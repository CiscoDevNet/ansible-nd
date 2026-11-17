# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Release validation through public VRF arguments and the real workflow.

Only topology discovery, the Sender boundary, and module exit/logging are
replaced. All mutations are recorded; sockets are forbidden.
"""

from copy import deepcopy
import json
import socket
from urllib.parse import urlsplit

import pytest
from ansible.module_utils import basic

from ansible_collections.cisco.nd.plugins.modules import nd_manage_vrfs
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import MulticlusterParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import MultisiteParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import VrfFabricResolver
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


class _Finished(BaseException):
    def __init__(self, result):
        self.result = result


class _ArgumentModule(basic.AnsibleModule):
    def exit_json(self, **result):
        raise _Finished(result)

    def fail_json(self, **result):
        raise _Finished(dict(result, failed=True))


class _Controller:
    def __init__(self, strategy, attached=True):
        self.calls = []
        self.version_reads = 0
        self.rows = {
            strategy.fabric_name: [
                {"fabricName": strategy.fabric_name, "vrfName": "OLD", "vrfId": 30211, "vlanId": 211, "vrfType": "vxlanIbgp", "vrfStatus": "notApplicable"}
            ]
        }
        self.attachments = (
            [{"vrfName": "OLD", "switchId": "SERIAL1", "ipAddress": "192.0.2.50", "vlanId": 211, "attach": True, "status": "inSync"}] if attached else []
        )

    @property
    def mutations(self):
        return [call for call in self.calls if call[0] != "GET" and not call[1].endswith("/query")]

    def dispatch(self, sender):
        method, path, body = sender.verb.value, urlsplit(sender.path).path, deepcopy(sender.payload)
        self.calls.append((method, path, body))
        fabric = path.split("/fabrics/", 1)[1].split("/", 1)[0]
        if method == "GET" and path.endswith("/vrfs"):
            rows = deepcopy(self.rows.get(fabric, []))
            data = {"vrfs": rows, "metadata": {"counts": {"total": len(rows), "remaining": 0}}}
        elif method == "GET" and path.endswith("/switches"):
            data = {"switches": [{"switchId": "SERIAL1", "ipAddress": "192.0.2.50"}]}
        elif method == "GET" and path.endswith("/networks"):
            data = {"networks": []}
        elif method == "POST" and path.endswith("/vrfAttachments/query"):
            rows = [deepcopy(row) for row in self.attachments if row["vrfName"] in body["vrfNames"]]
            data = {"attachments": rows, "metadata": {"counts": {"total": len(rows), "remaining": 0}}}
        elif method == "POST" and path.endswith("/vrfAttachments"):
            for update in body["attachments"]:
                row = next(row for row in self.attachments if row["vrfName"] == update["vrfName"])
                row.update(deepcopy(update))
            data = {"results": [{"vrfName": row["vrfName"], "switchId": row["switchId"], "status": "success"} for row in body["attachments"]]}
        elif method == "POST" and path.endswith("/vrfs"):
            self.rows.setdefault(fabric, []).extend(deepcopy(body["vrfs"]))
            data = {"results": [{"vrfName": row["vrfName"], "status": "success"} for row in body["vrfs"]]}
        elif method == "PUT" and "/vrfs/" in path:
            self.rows[fabric] = [row for row in self.rows.get(fabric, []) if row["vrfName"] != body["vrfName"]] + [body]
            data = {"results": [{"vrfName": body["vrfName"], "status": "success"}]}
        elif method == "POST" and path.endswith("/vrfActions/remove"):
            self.rows[fabric] = [row for row in self.rows.get(fabric, []) if row["vrfName"] not in body["vrfNames"]]
            data = {"results": [{"vrfName": name, "status": "success"} for name in body["vrfNames"]]}
        else:
            raise AssertionError(f"Unexpected offline request: {self.calls[-1]}")
        sender.response = {"RETURN_CODE": 200, "METHOD": method, "MESSAGE": "OK", "DATA": data}


@pytest.fixture
def invoke(monkeypatch):
    def deny_network(*_args, **_kwargs):
        raise AssertionError("Real networking is forbidden in VRF preflight regressions")

    monkeypatch.setattr(socket.socket, "connect", deny_network)
    monkeypatch.setattr(socket.socket, "connect_ex", deny_network)
    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    monkeypatch.setattr(nd_manage_vrfs, "AnsibleModule", _ArgumentModule)
    monkeypatch.setattr(nd_manage_vrfs, "setup_logging", lambda *_args: None)

    def run(config, *, state="staged", check=False, version="4.2.1.10", strategy=None, controller=None):
        strategy = strategy or StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
        controller = controller or _Controller(strategy)
        monkeypatch.setattr(VrfFabricResolver, "resolve", lambda _self: strategy)

        def commit(sender):
            return controller.dispatch(sender)

        monkeypatch.setattr(Sender, "commit", commit)

        def get_version(_self):
            controller.version_reads += 1
            return version

        monkeypatch.setattr(Sender, "get_version", get_version)
        args = {
            "host": "offline.invalid",
            "username": "fixture",
            "password": "fixture",
            "fabric_name": strategy.fabric_name,
            "state": state,
            "config": deepcopy(config),
            "output_level": "normal",
            "_ansible_check_mode": check,
        }
        monkeypatch.setattr(basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode())
        if hasattr(basic, "_ANSIBLE_PROFILE"):
            monkeypatch.setattr(basic, "_ANSIBLE_PROFILE", "legacy")
        with pytest.raises(_Finished) as finished:
            nd_manage_vrfs.main()
        return finished.value.result, controller

    return run


def _new(key_type="type6", **kwargs):
    return {"vrf_name": "NEW", "vrf_id": 30212, "vlan_id": 212, "bgp_password": "aabbccdd", "bgp_passwd_encrypt": key_type, "deploy": False, **kwargs}


def _assert_rejected(result, controller):
    assert result.get("failed"), result
    assert "bgp_passwd_encrypt 'type6' is not supported by the ND 4.2 Manage API" in result["msg"]
    assert controller.mutations == []
    assert controller.attachments[0]["attach"] is True
    assert controller.version_reads == 1


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_type6_rejected_before_any_omission_detach_or_crud(invoke, state, check):
    result, controller = invoke([_new()], state=state, check=check)
    _assert_rejected(result, controller)
    assert sum(method == "GET" and path.endswith("/vrfs") for method, path, _payload in controller.calls) == 1
    assert [row["vrfName"] for row in controller.rows["FAB"]] == ["OLD"]


def test_staged_apply_and_check_report_the_same_release_error(invoke):
    apply_result, apply_controller = invoke([_new()])
    check_result, check_controller = invoke([_new()], check=True)
    _assert_rejected(apply_result, apply_controller)
    _assert_rejected(check_result, check_controller)
    assert apply_result["msg"] == check_result["msg"]


@pytest.mark.parametrize("state", ["replaced", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_type6_rejected_before_explicit_detach_of_another_vrf(invoke, state, check):
    old = {"vrf_name": "OLD", "deploy": False, "attach": []}
    result, controller = invoke([old, _new()], state=state, check=check)
    _assert_rejected(result, controller)


@pytest.mark.parametrize(
    "version,key_type,wire_type",
    [
        ("4.2.1.10", "3des", 3),
        ("4.2.1.10", "type7", 7),
        ("4.3.1.175", "3des", "3des"),
        ("4.3.1.175", "type7", "type7"),
        ("4.3.1.175", "type6", "type6"),
    ],
)
@pytest.mark.parametrize("check", [False, True])
def test_supported_choices_preserve_staged_workflow_and_wire_encoding(invoke, version, key_type, wire_type, check):
    result, controller = invoke([_new(key_type)], version=version, check=check)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.version_reads == 1
    assert sum(method == "GET" and path.endswith("/vrfs") for method, path, _payload in controller.calls) == 1
    if check:
        assert controller.mutations == []
        assert controller.attachments[0]["attach"] is True
    else:
        assert len(controller.mutations) == 2
        assert controller.mutations[0][1].endswith("/vrfAttachments")
        assert controller.attachments[0]["attach"] is False
        payload = controller.mutations[1][2]["vrfs"][0]
        assert payload["fabricData"]["bgpPasswordKeyType"] == wire_type
        assert {row["vrfName"] for row in controller.rows["FAB"]} == {"OLD", "NEW"}


@pytest.mark.parametrize("check", [False, True])
def test_merged_update_validates_inherited_type6_in_effective_payload(invoke, check):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
    controller = _Controller(strategy)
    controller.rows["FAB"][0]["fabricData"] = {"bgpPassword": "aabbccdd", "bgpPasswordKeyType": "type6"}
    result, controller = invoke(
        [{"vrf_name": "OLD", "vrf_description": "changed", "deploy": False}], state="merged", check=check, strategy=strategy, controller=controller
    )
    _assert_rejected(result, controller)


@pytest.mark.parametrize("check", [False, True])
def test_unchanged_type6_is_not_a_definition_write(invoke, check):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
    controller = _Controller(strategy)
    controller.rows["FAB"][0]["fabricData"] = {"bgpPassword": "aabbccdd", "bgpPasswordKeyType": "type6"}
    result, controller = invoke([{"vrf_name": "OLD", "deploy": False}], state="merged", check=check, strategy=strategy, controller=controller)
    assert not result.get("failed"), result
    assert result["changed"] is False
    assert controller.mutations == []


@pytest.mark.parametrize("state", ["gathered", "deleted", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_existing_type6_does_not_block_reads_deletes_or_unrelated_writes(invoke, state, check):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
    controller = _Controller(strategy, attached=state == "staged")
    controller.rows["FAB"][0]["fabricData"] = {"bgpPassword": "aabbccdd", "bgpPasswordKeyType": "type6"}
    config = [_new("type7")] if state == "staged" else [{"vrf_name": "OLD"}]
    result, controller = invoke(config, state=state, check=check, strategy=strategy, controller=controller)
    assert not result.get("failed"), result
    if check or state == "gathered":
        assert controller.mutations == []
    elif state == "staged":
        assert controller.attachments[0]["attach"] is False
        assert controller.rows["FAB"][0]["fabricData"]["bgpPasswordKeyType"] == "type6"
    else:
        assert controller.rows["FAB"] == []


def _parent(strategy_cls):
    multicluster = strategy_cls is MulticlusterParentVrfStrategy
    member = {"fabricName": "CHILD", "fabric_type": "multicluster_child" if multicluster else "multisite_child", "managementType": "vxlanIbgp"}
    if multicluster:
        member["clusterName"] = "REMOTE"
    return strategy_cls(fabric_name="PARENT", fabric_data={"managementType": "vxlanIbgp", "members": [member]})


@pytest.mark.parametrize("strategy_cls", [MultisiteParentVrfStrategy, MulticlusterParentVrfStrategy])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("inherited", [False, True])
def test_child_type6_preflight_precedes_all_parent_writes(invoke, strategy_cls, state, check, inherited):
    strategy = _parent(strategy_cls)
    controller = _Controller(strategy)
    child = {"fabric_name": "CHILD"}
    if inherited:
        controller.rows["CHILD"] = [
            {
                "fabricName": "CHILD",
                "vrfName": "NEW",
                "vrfId": 30212,
                "vrfType": "vxlanIbgp",
                "fabricData": {"bgpPassword": "aabbccdd", "bgpPasswordKeyType": "type6"},
            }
        ]
        child["bgp_log_neighbor_change"] = True
    else:
        child.update(bgp_password="aabbccdd", bgp_passwd_encrypt="type6")
    config = [{"vrf_name": "NEW", "vrf_id": 30212, "vlan_id": 212, "deploy": False, "child_fabric_config": [child]}]
    result, controller = invoke(config, state=state, check=check, strategy=strategy, controller=controller)
    _assert_rejected(result, controller)
    assert all("/fabrics/CHILD/vrfs" in path for method, path, _payload in controller.calls if method == "GET")
    assert [row["vrfName"] for row in controller.rows["PARENT"]] == ["OLD"]


@pytest.mark.parametrize("strategy_cls", [MultisiteParentVrfStrategy, MulticlusterParentVrfStrategy])
@pytest.mark.parametrize(
    "version,key_type,wire_type",
    [
        ("4.2.1.10", "3des", 3),
        ("4.2.1.10", "type7", 7),
        ("4.3.1.175", "type6", "type6"),
    ],
)
@pytest.mark.parametrize("check", [False, True])
def test_supported_child_payloads_keep_parent_and_child_serialization(invoke, strategy_cls, version, key_type, wire_type, check):
    strategy = _parent(strategy_cls)
    child = {"fabric_name": "CHILD", "bgp_password": "aabbccdd", "bgp_passwd_encrypt": key_type}
    config = [{"vrf_name": "NEW", "vrf_id": 30212, "vlan_id": 212, "deploy": False, "child_fabric_config": [child]}]
    result, controller = invoke(config, strategy=strategy, check=check, version=version)
    assert not result.get("failed"), result
    assert result["changed"] is True
    assert controller.version_reads == 1
    if check:
        assert controller.mutations == []
        return
    assert len(controller.mutations) == 3
    detach, parent_write, child_write = controller.mutations
    assert detach[1].endswith("/PARENT/vrfAttachments")
    assert parent_write[0] == "POST" and parent_write[1].endswith("/PARENT/vrfs")
    parent_payload = parent_write[2]["vrfs"][0]
    assert not parent_payload.get("fabricData")
    if strategy.is_multicluster:
        assert "vlanId" not in parent_payload
        assert "/oneManage/manage/" in parent_write[1]
        assert parent_payload["coreData"]["routeTargetImport"] == []
    else:
        assert parent_payload["vlanId"] == 212
    assert child_write[0] == "PUT" and child_write[1].endswith("/CHILD/vrfs/NEW")
    assert child_write[2]["fabricData"]["bgpPasswordKeyType"] == wire_type
    assert "coreData" not in child_write[2] and "vlanId" not in child_write[2]


@pytest.mark.parametrize("check", [False, True])
def test_replacement_of_existing_type6_does_not_validate_discarded_key_type(invoke, check):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
    controller = _Controller(strategy)
    controller.rows["FAB"][0]["fabricData"] = {"bgpPassword": "aabbccdd", "bgpPasswordKeyType": "type6"}
    result, controller = invoke([{"vrf_name": "OLD", "deploy": False}], strategy=strategy, controller=controller, check=check)
    assert not result.get("failed"), result
    assert result["changed"] is True
    if check:
        assert controller.mutations == []
    else:
        assert len(controller.mutations) == 2
        assert controller.mutations[0][1].endswith("/vrfAttachments")
        assert controller.mutations[1][0] == "PUT"
        assert not {"bgpPassword", "bgpPasswordKeyType"}.intersection(controller.mutations[1][2].get("fabricData", {}))


@pytest.mark.parametrize("check", [False, True])
def test_later_child_rejection_precedes_earlier_child_and_parent_writes(invoke, check):
    strategy = _parent(MultisiteParentVrfStrategy)
    strategy.fabric_data["members"].append({"fabricName": "CHILD2", "fabric_type": "multisite_child", "managementType": "vxlanIbgp"})
    children = [
        {"fabric_name": "CHILD", "bgp_password": "aabbccdd", "bgp_passwd_encrypt": "type7"},
        {"fabric_name": "CHILD2", "bgp_password": "aabbccdd", "bgp_passwd_encrypt": "type6"},
    ]
    config = [{"vrf_name": "NEW", "deploy": False, "child_fabric_config": children}]
    result, controller = invoke(config, strategy=strategy, check=check)
    _assert_rejected(result, controller)
    assert [path.split("/fabrics/")[1].split("/")[0] for method, path, _payload in controller.calls if method == "GET"] == ["CHILD", "CHILD2"]


@pytest.mark.parametrize("check", [False, True])
def test_no_vlan_type6_still_fails_before_omission_detach(invoke, check):
    config = _new(l3vni_wo_vlan=True)
    config.pop("vlan_id")
    result, controller = invoke([config], check=check)
    _assert_rejected(result, controller)
