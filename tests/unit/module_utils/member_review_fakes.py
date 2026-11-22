# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Offline controller for public explicit-member workflow regressions.

Only the HTTP connection and Ansible's final exit methods are replaced. Argument
validation, planning, execution, REST handling and result contracts remain real.
"""

from copy import deepcopy
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
from ansible.module_utils import basic

from ansible_collections.cisco.nd.plugins.module_utils.rest import sender_nd
from ansible_collections.cisco.nd.plugins.modules import nd_interfaces_workflow


class ModuleResult(BaseException):
    """Model Ansible's SystemExit without being caught by product exceptions."""

    def __init__(self, failed, result):
        self.failed = failed
        self.result = result
        super().__init__(result.get("msg", ""))


def wire(name, policy_type, *, switch_id="S1", interface_type="ethernet", mode="trunk", **fields):
    return {
        "interfaceName": name,
        "interfaceType": interface_type,
        "switchId": switch_id,
        "configData": {"mode": mode, "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": policy_type, **fields}}},
        "operData": {"portChannelId": -1},
    }


def explicit_request(*, names=("Ethernet1/10",)):
    return {
        "fabric_name": "fab",
        "resources": [
            {
                "type": "ethernet_trunk_host",
                "state": "merged",
                "config": [
                    {
                        "switch_ip": "192.0.2.1",
                        "interface_names": list(names),
                        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkHost"}}},
                    }
                ],
            },
            {
                "type": "port_channel_trunk_host",
                "state": "merged",
                "config": [
                    {
                        "switch_ip": "192.0.2.1",
                        "interface_name": "port-channel10",
                        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkPoHost", "ports": list(names)}}},
                    }
                ],
            },
        ],
        "config_actions": {"deploy": False},
        "verify": {"enabled": True},
    }


class Controller:
    """Apply only shipping host/aggregate policies to deterministic inventories."""

    def __init__(self, *, paired=False, version="4.3.1.175"):
        self.rows = {"S1": {}, "S2": {}}
        self.calls = []
        self.paired = paired
        self.version = version

    def get_version(self, *_args):
        return self.version

    def set_params(self, _params):
        """Accept the real sender's connection configuration."""

    @property
    def writes(self):
        return [call for call in self.calls if call["verb"] != "GET"]

    def _switches(self):
        return [
            {
                "switchId": switch_id,
                "fabricManagementIp": address,
                "fabricName": "fab",
                "vpcConfigured": self.paired,
                "vpcData": {"peerSwitchId": "S2" if switch_id == "S1" else "S1"} if self.paired else {},
                "additionalData": {"platformType": "nx-os", "systemMode": "normal"},
                "role": "leaf",
                "status": "ok",
            }
            for switch_id, address in (("S1", "192.0.2.1"), ("S2", "192.0.2.2"))
        ]

    @staticmethod
    def _summary(row):
        return {
            "interfaceName": row["interfaceName"],
            "interfaceType": row["interfaceType"],
            "policyType": row["configData"]["networkOS"]["policy"]["policyType"],
            "switchId": row["switchId"],
            **dict.fromkeys(("editAllowed", "rbacAccessible", "policyChangeSupported", "deletable"), True),
            **dict.fromkeys(("blockConfig", "markDeleted", "hasDeletedOverlay"), False),
        }

    def _write_interfaces(self, path, payload):
        entries = payload.get("interfaces") if isinstance(payload, dict) else payload
        entries = entries if isinstance(entries, list) else [payload]
        results = []
        for entry in entries:
            row = deepcopy(entry)
            switch_id = row.get("switchId") or (path.split("/switches/")[-1].split("/")[0] if "/switches/" in path else "S1")
            name = row["interfaceName"]
            row["switchId"] = switch_id
            row.setdefault("operData", {"portChannelId": -1})
            self.rows[switch_id][name.casefold()] = row
            policy = row["configData"]["networkOS"]["policy"]
            if row["interfaceType"] in ("portChannel", "port-channel"):
                member_policy = {"trunkPoHost": "poMember", "accessPoHost": "accessPoMember", "l3Po": "l3PoMember"}[policy["policyType"]]
                for member_name in policy.get("ports", ()):
                    member = self.rows[switch_id].get(member_name.casefold())
                    if member is None:
                        continue
                    previous = member["configData"]["networkOS"]["policy"]
                    member["configData"]["networkOS"]["policy"] = {
                        "policyType": member_policy,
                        "portChannelId": "".join(character for character in name if character.isdigit()),
                        **{key: value for key, value in previous.items() if key in ("description", "adminState", "extraConfig")},
                    }
            results.append({"switchId": switch_id, "interfaceName": name, "status": "success"})
        return {"results": results}

    def send_request(self, verb, path, body=None):
        payload = json.loads(body) if body is not None else None
        url = urlsplit(path)
        query, route = parse_qs(url.query), unquote(url.path)
        self.calls.append({"verb": verb, "path": path, "payload": deepcopy(payload)})
        code = 200
        if verb == "GET" and route.endswith("/summary"):
            data = {"local": True, "fabricStatus": "default", "fabricType": "vxlanIbgp", "type": "vxlanIbgp", "freezeMode": False}
        elif verb == "GET" and route.endswith("/switches"):
            data = {"switches": self._switches()}
        elif verb == "GET" and (route.endswith("/vpcPair") or "/vpcPairs/" in route):
            switch_id = route.split("/switches/")[-1].split("/")[0] if "/switches/" in route else route.rsplit("/", 1)[1]
            data = {"switchId": switch_id, "peerSwitchId": "S2" if switch_id == "S1" else "S1"} if self.paired else {}
            code = 200 if self.paired else 404
        elif verb == "GET" and route.endswith("/vpcPairs"):
            data = {"vpcPairs": [{"switchId": "S1", "peerSwitchId": "S2"}, {"switchId": "S2", "peerSwitchId": "S1"}] if self.paired else []}
        elif verb == "GET" and route.endswith("/capableSwitches"):
            data = {"switches": [{"switchId": "S1"}, {"switchId": "S2"}]}
        elif verb == "GET" and route.endswith("/links"):
            data = {"links": []}
        elif verb == "GET" and route.endswith("/interfacesSummary"):
            switch_id = query.get("switchId", ["S1"])[0]
            data = {"interfaces": [self._summary(row) for row in self.rows[switch_id].values()]}
        elif verb == "GET" and route.endswith("/interfaces"):
            switch_id = route.split("/switches/")[-1].split("/")[0] if "/switches/" in route else query.get("switchId", ["S1"])[0]
            records = list(deepcopy(self.rows[switch_id]).values())
            offset, maximum = int(query.get("offset", [0])[0]), int(query.get("max", [500])[0])
            page = records[offset : offset + maximum]
            data = {"interfaces": page, "meta": {"counts": {"total": len(records), "remaining": max(0, len(records) - offset - len(page))}}}
        elif verb in ("POST", "PUT") and "/interfaces" in route:
            data = self._write_interfaces(route, payload)
        else:
            raise AssertionError(f"Unmodelled offline request {verb} {path}")
        return {"RETURN_CODE": code, "METHOD": verb, "REQUEST_PATH": path, "MESSAGE": "OK" if code == 200 else "not found", "DATA": deepcopy(data)}


def run_module(monkeypatch, params, controller):
    """Invoke the public module with real parsing and a non-network transport."""
    monkeypatch.delenv("ND_LOGGING_CONFIG", raising=False)
    monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": params}).encode())
    monkeypatch.setattr(sender_nd, "Connection", lambda *_args, **_kwargs: controller)

    def finish(_module, **result):
        raise ModuleResult(False, result)

    def fail(_module, **result):
        raise ModuleResult(True, result)

    monkeypatch.setattr(basic.AnsibleModule, "exit_json", finish)
    monkeypatch.setattr(basic.AnsibleModule, "fail_json", fail)
    with pytest.raises(ModuleResult) as captured:
        nd_interfaces_workflow.main()
    return captured.value
