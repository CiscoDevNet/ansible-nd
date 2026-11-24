# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone port-channel/vPC dot1q contracts and version-compatible writes."""

from __future__ import annotations

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest
from ansible.module_utils import basic as ansible_basic
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_dot1q_tunnel_host_interface import (
    PortChannelDot1qTunnelHostInterfaceModel,
    PortChannelDot1qTunnelHostPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_dot1q_tunnel_interface import (
    VpcDot1qTunnelInterfaceModel,
    VpcDot1qTunnelPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_dot1q_tunnel_host_interface import (
    PortChannelDot1qTunnelHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_dot1q_tunnel_interface import (
    VpcDot1qTunnelInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import VpcInterfaceBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.modules import nd_interface_port_channel_dot1q_tunnel_host as pc_module
from ansible_collections.cisco.nd.plugins.modules import nd_interface_vpc_dot1q_tunnel as vpc_module

FAMILIES = [
    (PortChannelDot1qTunnelHostInterfaceModel, PortChannelDot1qTunnelHostPolicyModel, "port-channel261", "portChannel", "dot1qTunnelPoHost"),
    (VpcDot1qTunnelInterfaceModel, VpcDot1qTunnelPolicyModel, "vpc262", "vpc", "dot1qTunnelVpc"),
]


@pytest.mark.parametrize("model,policy,name,interface_type,policy_type", FAMILIES)
def test_dot1q_parent_envelope_and_round_trip(model, policy, name, interface_type, policy_type):
    instance = model.from_config({"switch_ip": "192.0.2.11", "interface_name": name, "config_data": {"network_os": {"policy": {"access_vlan": 2301}}}})
    payload = instance.to_payload()
    assert payload["interfaceName"] == name
    assert payload["interfaceType"] == interface_type
    assert "switchIp" not in payload
    assert payload["configData"]["mode"] == "dot1qTunnel"
    assert payload["configData"]["networkOS"]["networkOSType"] == "nx-os"
    assert payload["configData"]["networkOS"]["policy"]["policyType"] == policy_type
    assert payload["configData"]["networkOS"]["policy"]["accessVlan"] == 2301
    existing = model.from_response({**payload, "switchIp": "192.0.2.11"})
    assert existing.to_payload() == payload
    assert policy.from_response({"policyType": policy_type, "bpduFilter": "enable"}).to_reverse_diff_dict().get("bpduFilter") is None


@pytest.mark.parametrize("model,policy,name,interface_type,policy_type", FAMILIES)
def test_identifier_only_delete_and_supported_states(model, policy, name, interface_type, policy_type):
    instance = model.from_config({"switch_ip": "192.0.2.11", "interface_name": name})
    assert "configData" not in instance.to_payload()
    assert model.get_argument_spec()["state"]["choices"] == ["merged", "replaced", "overridden", "deleted", "gathered"]


@pytest.mark.parametrize("model,policy,name,interface_type,policy_type", FAMILIES)
@pytest.mark.parametrize("wrong", [{"monitor": True}, {"mtu": "1500"}, {"access_vlan": 0}, {"access_vlan": 4095}, {"policy_type": "accessPoHost"}])
def test_wrong_family_or_unsupported_fields_fail(model, policy, name, interface_type, policy_type, wrong):
    with pytest.raises(ValidationError):
        policy.from_config(wrong)


@pytest.mark.parametrize("model,policy,name,interface_type,policy_type", FAMILIES)
def test_ios_xe_is_rejected(model, policy, name, interface_type, policy_type):
    with pytest.raises(ValidationError):
        model.from_config({"switch_ip": "192.0.2.11", "interface_name": name, "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {}}}})


def test_pc_canonical_names_and_member_names():
    instance = PortChannelDot1qTunnelHostInterfaceModel.from_config(
        {"switch_ip": "192.0.2.11", "interface_name": "261", "config_data": {"network_os": {"policy": {"ports": ["e1/48", "eth1/49"]}}}}
    )
    assert instance.interface_name == "port-channel261"
    assert instance.config_data.network_os.policy.ports == ["Ethernet1/48", "Ethernet1/49"]


def test_vpc_peer_member_names_and_strict_field_scope():
    policy = VpcDot1qTunnelPolicyModel.from_config({"peer1_member_ports": ["e1/46"], "peer2_member_ports": ["eth1/47"]})
    assert policy.peer1_member_ports == ["Ethernet1/46"]
    assert policy.peer2_member_ports == ["Ethernet1/47"]
    for unsupported in ("orphan_port", "description", "extra_config", "ports"):
        with pytest.raises(ValidationError):
            VpcDot1qTunnelPolicyModel.from_config({unsupported: True})


@pytest.mark.parametrize("policy", [PortChannelDot1qTunnelHostPolicyModel, VpcDot1qTunnelPolicyModel])
def test_storm_control_and_atomic_netflow_merge(policy):
    with pytest.raises(ValidationError, match="broadcast"):
        policy.from_config({"storm_control_broadcast_level": 10, "storm_control_broadcast_level_pps": 1000})
    with pytest.raises(ValidationError, match="netflow_monitor"):
        policy.from_config({"netflow": True})
    current = policy.from_response({"netflow": False})
    current.merge(policy.from_config({"netflow": True, "netflow_monitor": "MONITOR"}))
    assert current.netflow is True and current.netflow_monitor == "MONITOR"


@pytest.mark.parametrize(
    "legacy",
    [
        {"peer1AccessVlan": 2301, "peer2AccessVlan": 2302},
        {"peer1AccessVlan": 2301},
        {"accessVlan": 2302, "peer1AccessVlan": 2301, "peer2AccessVlan": 2301},
    ],
)
def test_vpc_different_legacy_peer_vlans_are_never_silently_collapsed(legacy):
    with pytest.raises(ValidationError, match="VLAN"):
        VpcDot1qTunnelPolicyModel.from_response(legacy)


def test_vpc_equal_legacy_peer_vlan_normalizes_to_canonical_model():
    policy = VpcDot1qTunnelPolicyModel.from_response({"peer1AccessVlan": 2301, "peer2AccessVlan": 2301})
    assert policy.access_vlan == 2301
    assert policy.to_payload()["accessVlan"] == 2301
    assert "peer1AccessVlan" not in policy.to_payload()


@pytest.mark.parametrize("version", ["4.2.1", "4.2.1.10", "4.3.1", "4.3.1.175"])
@pytest.mark.parametrize("wrapped", [False, True])
def test_vpc_write_shape_matches_exact_controller_version(version, wrapped):
    rest = RestSend({"fabric_name": "fabric1", "state": "merged", "config": []})
    rest.controller_version = version
    orchestrator = VpcDot1qTunnelInterfaceOrchestrator(rest_send=rest)
    body = {"interfaceName": "vpc262", "configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelVpc", "accessVlan": 2301}}}}
    body = {"interfaces": [body]} if wrapped else body
    saved = deepcopy(body)
    output = orchestrator._dot1q_write_payload(body)
    item = output["interfaces"][0] if wrapped else output
    policy = item["configData"]["networkOS"]["policy"]
    if version.startswith("4.2.1"):
        assert "accessVlan" not in policy
        assert policy["peer1AccessVlan"] == policy["peer2AccessVlan"] == 2301
    else:
        assert policy["accessVlan"] == 2301
        assert "peer1AccessVlan" not in policy
    assert body == saved


@pytest.mark.parametrize("version", [None, "4.2.2", "4.4.1", "not-a-version"])
def test_unknown_controller_version_fails_before_vpc_vlan_write(version):
    rest = RestSend({"fabric_name": "fabric1", "state": "merged", "config": []})
    rest.controller_version = version
    orchestrator = VpcDot1qTunnelInterfaceOrchestrator(rest_send=rest)
    with pytest.raises(ValueError, match="Cannot select"):
        orchestrator._dot1q_write_payload({"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelVpc", "accessVlan": 2301}}}})


def test_vpc_request_adapts_only_writes_and_retains_shared_transport(monkeypatch):
    rest = RestSend({"fabric_name": "fabric1", "state": "merged", "config": []})
    rest.controller_version = "4.2.1.10"
    orchestrator = VpcDot1qTunnelInterfaceOrchestrator(rest_send=rest)
    calls = []
    monkeypatch.setattr(VpcInterfaceBaseOrchestrator, "_request", lambda self, path, verb, data, not_found_ok, operation_type: calls.append((verb, data)))
    body = {"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelVpc", "accessVlan": 2301}}}}
    orchestrator._request("/interfaces", HttpVerbEnum.PUT, body)
    orchestrator._request("/interfaces", HttpVerbEnum.GET, body)
    assert calls[0][1]["configData"]["networkOS"]["policy"]["peer1AccessVlan"] == 2301
    assert calls[1][1] is body


def test_orchestrators_keep_narrow_scope_and_bulk_safeguards():
    assert PortChannelDot1qTunnelHostInterfaceOrchestrator._managed_policy_types(None) == {"dot1qTunnelPoHost"}
    assert VpcDot1qTunnelInterfaceOrchestrator._managed_policy_types(None) == {"dot1qTunnelVpc"}
    assert PortChannelDot1qTunnelHostInterfaceOrchestrator.supports_bulk_create
    assert PortChannelDot1qTunnelHostInterfaceOrchestrator.supports_bulk_full_modify
    assert VpcDot1qTunnelInterfaceOrchestrator.supports_bulk_create
    assert VpcDot1qTunnelInterfaceOrchestrator.supports_bulk_full_modify
    # The shared vPC base intentionally uses exact singular DELETE requests.
    assert not VpcDot1qTunnelInterfaceOrchestrator.supports_bulk_delete


@pytest.mark.parametrize("module", [pc_module, vpc_module])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "deleted"])
def test_standalone_modules_retain_state_machine_and_check_mode_hooks(monkeypatch, module, check_mode, state):
    calls = []

    class StubModule:
        def __init__(self):
            self.check_mode = check_mode
            self.params = {"fabric_name": "fabric1", "config": [], "state": state, "config_actions": {"deploy": False}}

        def exit_json(self, **kwargs):
            calls.append("exit")

    class StubOrchestrator:
        def apply_config_actions(self, params):
            assert params["config_actions"] == {"deploy": False}
            calls.append("actions")
            return False

        def remove_pending(self):
            calls.append("remove")

        def deploy_pending(self):
            calls.append("deploy")

    class StubStateMachine:
        def __init__(self, module, model_orchestrator):
            self.model_orchestrator = StubOrchestrator()
            self.output = self

        def manage_state(self):
            calls.append(state)

        def format(self):
            return {"changed": not check_mode}

    monkeypatch.setattr(module, "AnsibleModule", lambda **kwargs: StubModule())
    monkeypatch.setattr(module, "NDBaseInterfaceOrchestrator", StubOrchestrator)
    monkeypatch.setattr(module, "NDStateMachine", StubStateMachine)
    monkeypatch.setattr(module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(module, "setup_logging", lambda value: None)
    module.main()
    assert calls == ["actions", state] + ([] if check_mode else ["remove", "deploy"]) + ["exit"]


@pytest.mark.parametrize("clear_peers", [(1,), (2,), (1, 2)])
@pytest.mark.parametrize("merged", [False, True])
def test_vpc_explicit_peer_description_clear_is_detected_and_then_idempotent(clear_peers, merged):
    policy = {"access_vlan": 2302, "peer1_port_channel_description": "peer1 current", "peer2_port_channel_description": "peer2 current"}
    base = {"switch_ip": "192.0.2.11", "interface_name": "vpc262", "config_data": {"network_os": {"policy": policy}}}
    current = VpcDot1qTunnelInterfaceModel.from_config(base)
    desired_config = deepcopy(base)
    for peer in clear_peers:
        desired_config["config_data"]["network_os"]["policy"][f"peer{peer}_port_channel_description"] = ""
    desired = VpcDot1qTunnelInterfaceModel.from_config(desired_config)
    assert not current.get_diff(desired, exclude_unset=merged)
    if merged:
        current.merge(desired)
        assert all(getattr(current.config_data.network_os.policy, f"peer{peer}_port_channel_description") == "" for peer in clear_peers)
    wire = VpcDot1qTunnelInterfaceOrchestrator._without_empty_peer_descriptions(desired.to_payload())
    after = VpcDot1qTunnelInterfaceModel.from_response({**wire, "switchIp": "192.0.2.11"})
    assert after.get_diff(desired, exclude_unset=merged)
    for peer in (1, 2):
        value = getattr(after.config_data.network_os.policy, f"peer{peer}_port_channel_description")
        assert value is None if peer in clear_peers else value == f"peer{peer} current"


@pytest.mark.parametrize("wrapped", [False, True])
def test_vpc_peer_description_omission_is_exact_and_keeps_nonempty_fields(wrapped):
    row = {
        "configData": {
            "networkOS": {
                "policy": {"policyType": "dot1qTunnelVpc", "peer1PortChannelDescription": "", "peer2PortChannelDescription": "keep peer2", "accessVlan": 2302}
            }
        }
    }
    foreign = {"configData": {"networkOS": {"policy": {"policyType": "accessVpcHost", "peer1PortChannelDescription": ""}}}}
    body = {"interfaces": [row, foreign]} if wrapped else row
    original = deepcopy(body)
    result = VpcDot1qTunnelInterfaceOrchestrator._without_empty_peer_descriptions(body)
    policy = (result["interfaces"][0] if wrapped else result)["configData"]["networkOS"]["policy"]
    assert "peer1PortChannelDescription" not in policy
    assert policy["peer2PortChannelDescription"] == "keep peer2"
    assert policy["accessVlan"] == 2302
    if wrapped:
        assert result["interfaces"][1] == foreign
    assert body == original


def test_nonempty_vpc_descriptions_need_no_payload_copy():
    body = {"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelVpc", "peer1PortChannelDescription": "keep"}}}}
    assert VpcDot1qTunnelInterfaceOrchestrator._without_empty_peer_descriptions(body) is body


@pytest.mark.parametrize("verb", [HttpVerbEnum.POST, HttpVerbEnum.PUT])
def test_vpc_write_omits_empty_peer_descriptions_without_a_failed_first_request(monkeypatch, verb):
    rest = RestSend({"fabric_name": "fabric1", "state": "merged", "config": []})
    rest.controller_version = "4.3.1.175"
    orchestrator = VpcDot1qTunnelInterfaceOrchestrator(rest_send=rest)
    body = {"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelVpc", "accessVlan": 2302, "peer1PortChannelDescription": ""}}}}
    calls = []
    monkeypatch.setattr(VpcInterfaceBaseOrchestrator, "_request", lambda self, path, verb, data, not_found_ok, operation_type: calls.append(data))
    orchestrator._request("/interfaces", verb, body)
    assert len(calls) == 1
    assert "peer1PortChannelDescription" not in calls[0]["configData"]["networkOS"]["policy"]
    assert body["configData"]["networkOS"]["policy"]["peer1PortChannelDescription"] == ""


def test_vpc_description_clear_keeps_singular_put_and_nonempty_uses_shared_guard(monkeypatch):
    rest = RestSend({"fabric_name": "fabric1", "state": "merged", "config": []})
    orchestrator = VpcDot1qTunnelInterfaceOrchestrator(rest_send=rest)
    calls = []
    monkeypatch.setattr(VpcInterfaceBaseOrchestrator, "_bulk_full_modify_guard", lambda self, model, current: calls.append(model) or True)
    base = {"switch_ip": "192.0.2.11", "interface_name": "vpc262", "config_data": {"network_os": {"policy": {"peer1_port_channel_description": ""}}}}
    assert not orchestrator._bulk_full_modify_guard(VpcDot1qTunnelInterfaceModel.from_config(base), {})
    assert calls == []
    base["config_data"]["network_os"]["policy"]["peer1_port_channel_description"] = "keep"
    assert orchestrator._bulk_full_modify_guard(VpcDot1qTunnelInterfaceModel.from_config(base), {})
    assert len(calls) == 1


def _dot1q_inventory_row(name, interface_type, policy_type, *, peer=None, vlan=2301, admin_state=True, legacy=False):
    """Build one controller response using only documented writable policy fields."""
    policy = {"policyType": policy_type, "adminState": admin_state}
    if legacy:
        policy.update(peer1AccessVlan=vlan, peer2AccessVlan=vlan)
    else:
        policy["accessVlan"] = vlan
    if peer is not None:
        policy.update(peerSwitchId=peer, peer1MemberPorts=["Ethernet1/46"], peer2MemberPorts=["Ethernet1/47"])
    return {
        "interfaceName": name,
        "interfaceType": interface_type,
        "configData": {"mode": "dot1qTunnel", "networkOS": {"networkOSType": "nx-os", "policy": policy}},
    }


def _gather_dot1q(monkeypatch, orchestrator_type, inventory, *, config=None, check_mode=False):
    """Exercise real query, model and state handling with a local inventory only."""
    params = {"fabric_name": "fabric1", "state": "gathered", "config": config, "config_actions": {"deploy": True}}
    rest = RestSend(params)
    orchestrator = orchestrator_type(rest_send=rest)
    context = FabricContext(rest_send=rest, fabric_name="fabric1")
    context._fabric_summary = {"fabricName": "fabric1", "local": True, "fabricStatus": "deploymentFreeze"}
    context._switch_map = {f"192.0.2.{11 + index}": switch_id for index, switch_id in enumerate(inventory)}
    context._switch_map_by_id = {switch_id: ip for ip, switch_id in context._switch_map.items()}
    orchestrator._fabric_context = context
    reads = []

    def read_inventory(self, switch_id):
        reads.append(switch_id)
        return {row["interfaceName"].lower(): deepcopy(row) for row in inventory[switch_id]}

    monkeypatch.setattr(NDBaseInterfaceOrchestrator, "_switch_interfaces", read_inventory)
    monkeypatch.setattr(RestSend, "commit", lambda self: pytest.fail("No real transport is permitted in this test"))
    monkeypatch.setattr(FabricContext, "fabric_is_deployment_frozen", lambda self: pytest.fail("Gathered must not check deployment freeze"))
    module = SimpleNamespace(params=params, check_mode=check_mode)
    machine = NDStateMachine(module=module, model_orchestrator=orchestrator)
    orchestrator.apply_config_actions(params)
    machine.manage_state()
    return machine.output.format(), reads


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("config", [None, []])
@pytest.mark.parametrize(
    "orchestrator_type,interface_type,policy_type,name",
    [
        (PortChannelDot1qTunnelHostInterfaceOrchestrator, "portChannel", "dot1qTunnelPoHost", "port-channel261"),
        (VpcDot1qTunnelInterfaceOrchestrator, "vpc", "dot1qTunnelVpc", "vpc262"),
    ],
)
def test_gathered_reads_all_switches_without_config_and_preserves_names(monkeypatch, check_mode, config, orchestrator_type, interface_type, policy_type, name):
    is_vpc = interface_type == "vpc"
    inventory = {
        "A": [_dot1q_inventory_row(name, interface_type, policy_type, peer="B" if is_vpc else None)],
        "B": [_dot1q_inventory_row(name, interface_type, policy_type, peer="A" if is_vpc else None)],
    }
    result, reads = _gather_dot1q(monkeypatch, orchestrator_type, inventory, config=config, check_mode=check_mode)
    assert reads == ["A", "B"]
    assert result["changed"] is False
    assert result["before"] == result["after"] == []
    assert len(result["gathered"]) == (1 if is_vpc else 2)
    model = VpcDot1qTunnelInterfaceModel if is_vpc else PortChannelDot1qTunnelHostInterfaceModel
    for item in result["gathered"]:
        assert item["interface_name"] == name
        assert item["config_data"]["network_os"]["policy"]["access_vlan"] == 2301
        assert "peer_switch_id" not in item["config_data"]["network_os"]["policy"]
        assert model.from_config(item).interface_name == name


@pytest.mark.parametrize("orchestrator_type", [PortChannelDot1qTunnelHostInterfaceOrchestrator, VpcDot1qTunnelInterfaceOrchestrator])
def test_gathered_returns_an_empty_list_without_inventory(monkeypatch, orchestrator_type):
    result, reads = _gather_dot1q(monkeypatch, orchestrator_type, {"A": [], "B": []})
    assert result["gathered"] == []
    assert result["changed"] is False
    assert reads == ["A", "B"]


def test_gathered_pc_excludes_other_families_and_generated_vpc_children(monkeypatch):
    rows = [
        _dot1q_inventory_row("port-channel261", "portChannel", "dot1qTunnelPoHost"),
        _dot1q_inventory_row("port-channel262", "portChannel", "dot1qTunnelVpcMember"),
        _dot1q_inventory_row("port-channel263", "portChannel", "accessPoHost"),
        _dot1q_inventory_row("Ethernet1/46", "ethernet", "dot1qTunnelPoMember"),
    ]
    result, reads = _gather_dot1q(monkeypatch, PortChannelDot1qTunnelHostInterfaceOrchestrator, {"A": rows})
    assert [item["interface_name"] for item in result["gathered"]] == ["port-channel261"]
    assert reads == ["A"]


@pytest.mark.parametrize("legacy", [False, True])
def test_gathered_vpc_keeps_same_name_on_different_pairs_and_normalizes_vlan(monkeypatch, legacy):
    inventory = {
        switch: [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer=peer, legacy=legacy)]
        for switch, peer in [("B", "A"), ("A", "B"), ("D", "C"), ("C", "D")]
    }
    result, reads = _gather_dot1q(monkeypatch, VpcDot1qTunnelInterfaceOrchestrator, inventory)
    assert len(reads) == 4
    assert len(result["gathered"]) == 2
    assert {item["switch_ip"] for item in result["gathered"]} == {"192.0.2.12", "192.0.2.14"}
    assert {item["interface_name"] for item in result["gathered"]} == {"vpc262"}
    assert all(item["config_data"]["network_os"]["policy"]["access_vlan"] == 2301 for item in result["gathered"])


def test_gathered_vpc_filters_before_dedup_so_a_matching_peer_is_retained(monkeypatch):
    inventory = {
        "A": [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer="B")],
        "B": [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer="A")],
    }
    filters = [
        {"switch_ip": "192.0.2.11", "config_data": {"network_os": {"policy": {"access_vlan": 2302}}}},
        {"switch_ip": "192.0.2.12", "interface_name": "VPC262", "config_data": {"network_os": {"policy": {"access_vlan": 2301}}}},
    ]
    result, reads = _gather_dot1q(monkeypatch, VpcDot1qTunnelInterfaceOrchestrator, inventory, config=filters)
    assert reads == ["A", "B"]
    assert len(result["gathered"]) == 1
    assert result["gathered"][0]["switch_ip"] == "192.0.2.12"


@pytest.mark.parametrize(
    "filters,expected_reads",
    [
        ([{"switch_ip": "192.0.2.12"}], ["B"]),
        ([{"switch_ip": "192.0.2.12"}, {"interface_name": "vpc262"}], ["A", "B"]),
        ([{"config_data": {"network_os": {"policy": {"admin_state": False}}}}], ["A", "B"]),
    ],
)
def test_gathered_vpc_scopes_queries_without_narrowing_unscoped_or_filters(monkeypatch, filters, expected_reads):
    inventory = {
        "A": [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer="B", admin_state=False)],
        "B": [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer="A", admin_state=False)],
    }
    result, reads = _gather_dot1q(monkeypatch, VpcDot1qTunnelInterfaceOrchestrator, inventory, config=filters)
    assert reads == expected_reads
    assert len(result["gathered"]) == 1


@pytest.mark.parametrize("include_unscoped_filter", [False, True])
def test_gathered_vpc_rejects_unknown_switch_before_interface_queries(monkeypatch, include_unscoped_filter):
    filters = [{"switch_ip": "192.0.2.99"}]
    if include_unscoped_filter:
        filters.append({"interface_name": "vpc262"})
    rest = RestSend({"fabric_name": "fabric1", "state": "gathered", "config": filters})
    orchestrator = VpcDot1qTunnelInterfaceOrchestrator(rest_send=rest)
    context = FabricContext(rest_send=rest, fabric_name="fabric1")
    context._fabric_summary = {"fabricName": "fabric1", "local": True}
    context._switch_map = {"192.0.2.11": "A", "192.0.2.12": "B"}
    orchestrator._fabric_context = context
    monkeypatch.setattr(
        NDBaseInterfaceOrchestrator,
        "_switch_interfaces",
        lambda self, switch_id: pytest.fail("Unknown switch criteria must fail before reading any interface inventory"),
    )
    monkeypatch.setattr(RestSend, "commit", lambda self: pytest.fail("No real transport is permitted in this test"))
    with pytest.raises(RuntimeError, match="192.0.2.99.*does not exist in fabric 'fabric1'"):
        orchestrator.query_all()


@pytest.mark.parametrize("policy_filter", [{"access_vlan": 2301}, {"admin_state": False}])
def test_gathered_vpc_policy_filters_accept_actual_ansible_parser_defaults(monkeypatch, policy_filter):
    config = [{"config_data": {"network_os": {"policy": policy_filter}}}]
    args = {"fabric_name": "fabric1", "state": "gathered", "config": config}
    monkeypatch.setattr(ansible_basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode())
    monkeypatch.setattr(ansible_basic, "_ANSIBLE_PROFILE", "legacy", raising=False)
    argument_spec = vpc_module.nd_argument_spec()
    argument_spec.update(VpcDot1qTunnelInterfaceModel.get_argument_spec())
    parsed = ansible_basic.AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    parsed_policy = parsed.params["config"][0]["config_data"]["network_os"]["policy"]
    assert parsed_policy["bandwidth"] is None
    assert parsed_policy["peer1_member_ports"] is None
    inventory = {
        "A": [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer="B", admin_state=False)],
        "B": [_dot1q_inventory_row("vpc262", "vpc", "dot1qTunnelVpc", peer="A", admin_state=False)],
    }
    result, reads = _gather_dot1q(monkeypatch, VpcDot1qTunnelInterfaceOrchestrator, inventory, config=parsed.params["config"])
    assert reads == ["A", "B"]
    assert len(result["gathered"]) == 1
    assert result["gathered"][0]["config_data"]["network_os"]["policy"]["admin_state"] is False


@pytest.mark.parametrize(
    "criterion",
    [
        {},
        {"switch_ip": " "},
        {"interface_name": ""},
        {"switch_ip": "192.0.2.11", "interface_name": ""},
        {"config_data": {"network_os": {"policy": {"access_vlan": 4095}}}},
        {"config_data": {"network_os": {"policy": {"admin_state": "invalid"}}}},
        {"config_data": {"network_os": {"policy": {"peer1_port_channel_description": "unsupported"}}}},
    ],
)
def test_gathered_vpc_rejects_invalid_filters_before_reading_inventory(monkeypatch, criterion):
    monkeypatch.setattr(VpcDot1qTunnelInterfaceOrchestrator, "query_all", lambda self, **kwargs: pytest.fail("Invalid filters must fail before queries"))
    module = SimpleNamespace(params={"fabric_name": "fabric1", "state": "gathered", "config": [criterion]}, check_mode=False)
    with pytest.raises(ValueError):
        NDStateMachine(module=module, model_orchestrator=VpcDot1qTunnelInterfaceOrchestrator)


@pytest.mark.parametrize("module", [pc_module, vpc_module])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("config", [None, []])
def test_gathered_public_wrappers_never_run_cleanup_or_deployment(monkeypatch, module, check_mode, config):
    calls = []

    class StubModule:
        def __init__(self):
            self.params = {"fabric_name": "fabric1", "state": "gathered", "config": config, "config_actions": {"deploy": True}}
            self.check_mode = check_mode

        def exit_json(self, **kwargs):
            assert kwargs == {"changed": False, "gathered": []}
            calls.append("exit")

    class StubOrchestrator:
        def apply_config_actions(self, params):
            assert params["config_actions"]["deploy"] is True
            calls.append("actions")

        def remove_pending(self):
            pytest.fail("Gathered must not attempt pending removal")

        def deploy_pending(self):
            pytest.fail("Gathered must not attempt deployment")

    class StubStateMachine:
        def __init__(self, **kwargs):
            self.model_orchestrator = StubOrchestrator()
            self.output = SimpleNamespace(format=lambda: {"changed": False, "gathered": []})

        def manage_state(self):
            calls.append("gathered")

    monkeypatch.setattr(module, "AnsibleModule", lambda **kwargs: StubModule())
    monkeypatch.setattr(module, "NDBaseInterfaceOrchestrator", StubOrchestrator)
    monkeypatch.setattr(module, "NDStateMachine", StubStateMachine)
    monkeypatch.setattr(module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(module, "setup_logging", lambda value: None)
    module.main()
    assert calls == ["actions", "gathered", "exit"]


def test_gathered_pc_rejects_nonempty_configuration_before_queries(monkeypatch):
    class InvalidGatheredFilter(ValueError):
        """Stop at the module's explicit unsupported-filter rejection."""

    module = SimpleNamespace(params={"fabric_name": "fabric1", "state": "gathered", "config": [{"switch_ip": "192.0.2.11"}]}, check_mode=False)

    def reject(**kwargs):
        raise InvalidGatheredFilter(kwargs["msg"])

    module.fail_json = reject
    monkeypatch.setattr(pc_module, "AnsibleModule", lambda **kwargs: module)
    monkeypatch.setattr(pc_module, "require_pydantic", lambda value: None)
    monkeypatch.setattr(pc_module, "setup_logging", lambda value: None)
    monkeypatch.setattr(pc_module, "NDStateMachine", lambda **kwargs: pytest.fail("Unsupported PC filters must fail before querying"))
    with pytest.raises(InvalidGatheredFilter, match="filtering is not supported"):
        pc_module.main()


@pytest.mark.parametrize("module", [pc_module, vpc_module])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "deleted"])
def test_mutation_states_still_require_configuration_at_the_public_entrypoint(monkeypatch, module, state):
    class MissingConfig(BaseException):
        """Stop module parsing without allowing its broad runtime handler to retry."""

    def reject(self, **kwargs):
        raise MissingConfig(kwargs["msg"])

    args = {"fabric_name": "fabric1", "state": state}
    monkeypatch.setattr(ansible_basic, "_ANSIBLE_ARGS", json.dumps({"ANSIBLE_MODULE_ARGS": args}).encode())
    monkeypatch.setattr(ansible_basic, "_ANSIBLE_PROFILE", "legacy", raising=False)
    monkeypatch.setattr(ansible_basic.AnsibleModule, "fail_json", reject)
    monkeypatch.setattr(module, "require_pydantic", lambda value: pytest.fail("Missing write config must fail during argument parsing"))
    monkeypatch.setattr(module, "NDStateMachine", lambda **kwargs: pytest.fail("Missing write config must fail before querying"))
    with pytest.raises(MissingConfig, match="config"):
        module.main()


@pytest.mark.parametrize("model,policy,name,interface_type,policy_type", FAMILIES)
@pytest.mark.parametrize("missing", ["switch_ip", "interface_name"])
def test_partial_gathered_criteria_do_not_relax_writable_model_identifiers(model, policy, name, interface_type, policy_type, missing):
    config = {"switch_ip": "192.0.2.11", "interface_name": name}
    config.pop(missing)
    with pytest.raises(ValidationError):
        model.from_config(config)
