# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Public workflow replacements must reject bad ports before any mutation."""

from copy import deepcopy
import json
from urllib.parse import urlsplit

import pytest
from ansible.module_utils import basic

from ansible_collections.cisco.nd.plugins.modules import nd_manage_networks
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


class ModuleFinished(BaseException):
    def __init__(self, result):
        self.result = result


class ArgumentModule(basic.AnsibleModule):
    def exit_json(self, **result):
        raise ModuleFinished(result)

    def fail_json(self, **result):
        raise ModuleFinished(dict(result, failed=True))


class Controller:
    def __init__(self, reject):
        self.reject = reject
        self.calls = []
        self.definitions = [
            {
                "fabricName": "MAIN",
                "networkName": name,
                "networkId": network_id,
                "networkMode": "layer2",
                "networkType": "vxlanIbgp",
                "vrfName": "NA",
                "vlanId": vlan,
                "networkStatus": "deployed",
                "displayName": name,
            }
            for name, network_id, vlan in (("BLUE", 20001, 101), ("SHARED", 20002, 102))
        ]
        self.attachments = [
            {
                "networkName": "BLUE",
                "switchId": "S1",
                "peerSwitchId": "S2",
                "attach": True,
                "vlanId": 101,
                "status": "inSync",
                "interfaces": [{"mode": "trunk", "interfaceRange": "Ethernet1/1"}],
            },
            {"networkName": "BLUE", "switchId": "S2", "peerSwitchId": "S1", "attach": True, "vlanId": 101, "status": "inSync", "interfaces": []},
            {"networkName": "SHARED", "switchId": "S1", "attach": True, "vlanId": 102, "status": "inSync", "interfaces": []},
        ]

    def dispatch(self, sender):
        method = sender.verb.value
        uri = urlsplit(sender.path).path
        body = deepcopy(sender.payload)
        self.calls.append({"method": method, "path": uri, "body": body})
        if method == "GET" and uri.endswith("/fabrics/MAIN"):
            data = {"name": "MAIN", "category": "fabric", "management": {"type": "vxlanIbgp"}}
        elif method == "GET" and uri.endswith("/fabrics"):
            data = {"fabrics": []}
        elif method == "GET" and uri.endswith("/switches"):
            data = {"switches": [{"switchId": serial, "fabricManagementIp": ip} for serial, ip in (("S1", "192.0.2.1"), ("S2", "192.0.2.2"))]}
        elif method == "GET" and uri.endswith("/networks"):
            data = {"networks": deepcopy(self.definitions), "meta": {"counts": {"remaining": 0, "total": len(self.definitions)}}}
        elif method == "POST" and uri.endswith("/networkAttachments/query"):
            rows = [row for row in self.attachments if row["networkName"] in body.get("networkNames", ["BLUE", "SHARED"])]
            data = {"attachments": deepcopy(rows), "meta": {"counts": {"remaining": 0, "total": len(rows)}}}
        elif method == "POST" and uri.endswith("/validateInterfaces"):
            data = {
                "results": [
                    {
                        "networkName": row["networkName"],
                        "switchId": row["switchId"],
                        "status": "failed" if self.reject else "success",
                        "message": "Replacement port is not eligible" if self.reject else "Validated",
                    }
                    for row in body["attachments"]
                ]
            }
        elif method == "POST" and uri.endswith("/networkAttachments"):
            for row in body["attachments"]:
                existing = next((r for r in self.attachments if (r["networkName"], r["switchId"]) == (row["networkName"], row["switchId"])), None)
                if existing is None:
                    self.attachments.append(deepcopy(row))
                else:
                    existing.update(deepcopy(row))
            data = {"results": [{"networkName": row["networkName"], "switchId": row["switchId"], "status": "success"} for row in body["attachments"]]}
        elif method == "POST" and uri.endswith("/networkActions/deploy"):
            data = {"status": "accepted"}
        elif method == "PUT" and "/networks/" in uri:
            data = {"results": [{"networkName": body["networkName"], "status": "success"}]}
        else:
            raise AssertionError(f"Unexpected controller request {method} {uri}")
        sender.response = {"RETURN_CODE": 200, "METHOD": method, "MESSAGE": "OK", "DATA": data}


def invoke(monkeypatch, state, *, reject=False, check=False, omit_shared=False):
    controller = Controller(reject)
    config = [
        {
            "network_name": "BLUE",
            "layer": "layer2",
            "network_id": 20001,
            "vlan_id": 101,
            "deploy": False,
            "attach": [
                {"ip_address": "192.0.2.1", "interfaces": [{"mode": "trunk", "interface_range": "Ethernet1/2"}]},
                {"ip_address": "192.0.2.2", "interfaces": []},
            ],
        }
    ]
    if not omit_shared:
        config.append(
            {
                "network_name": "SHARED",
                "layer": "layer2",
                "network_id": 20002,
                "vlan_id": 102,
                "deploy": False,
                "attach": [{"ip_address": "192.0.2.1", "interfaces": []}],
            }
        )
    args = {
        "host": "offline.invalid",
        "username": "fixture",
        "password": "fixture",
        "fabric_name": "MAIN",
        "state": state,
        "config": config,
        "_ansible_check_mode": check,
    }
    monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode())
    if hasattr(basic, "_ANSIBLE_PROFILE"):
        monkeypatch.setattr(basic, "_ANSIBLE_PROFILE", "legacy")
    monkeypatch.setattr(nd_manage_networks, "AnsibleModule", ArgumentModule)

    def commit(sender):
        return controller.dispatch(sender)

    monkeypatch.setattr(Sender, "commit", commit)
    monkeypatch.setattr(Sender, "get_version", lambda _self: "4.3.1.175")
    if hasattr(nd_manage_networks, "setup_logging"):
        monkeypatch.setattr(nd_manage_networks, "setup_logging", lambda *_args, **_kwargs: None)
    with pytest.raises(ModuleFinished) as finished:
        nd_manage_networks.main()
    return controller, finished.value.result


@pytest.mark.parametrize("state", ["staged", "replaced", "overridden"])
@pytest.mark.parametrize("check", [False, True])
def test_rejected_replacement_preserves_original_and_peer_before_any_write(monkeypatch, state, check):
    controller, result = invoke(monkeypatch, state, reject=True, check=check, omit_shared=True)
    assert result.get("failed") is True
    assert "Replacement port is not eligible" in result.get("msg", "")
    mutations = [call for call in controller.calls if call["method"] != "GET" and not call["path"].endswith(("/query", "/validateInterfaces"))]
    assert mutations == []
    assert all(row["attach"] is True for row in controller.attachments)
    assert controller.attachments[0]["interfaces"] == [{"mode": "trunk", "interfaceRange": "Ethernet1/1"}]


@pytest.mark.parametrize("state", ["staged", "replaced", "overridden"])
def test_valid_replacement_is_validated_before_detach_and_again_before_reattach(monkeypatch, state):
    controller, result = invoke(monkeypatch, state)
    assert not result.get("failed"), result.get("msg")
    paths = [call["path"].rsplit("/", 1)[-1] for call in controller.calls]
    validations = [i for i, path in enumerate(paths) if path == "validateInterfaces"]
    writes = [i for i, path in enumerate(paths) if path == "networkAttachments"]
    assert len(validations) == 2
    assert len(writes) == 2
    assert validations[0] < writes[0] < validations[1] < writes[1]
    deploys = [call["body"] for call in controller.calls if call["path"].endswith("/networkActions/deploy")]
    assert deploys == ([] if state == "staged" else [{"networkNames": ["BLUE"], "switchIds": ["S1"]}])
    assert controller.attachments[0]["interfaces"] == [{"mode": "trunk", "interfaceRange": "Ethernet1/2", "nativeVlan": False}]
    assert all(row["attach"] is True for row in controller.attachments)
