# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone port-channel/vPC dot1q contracts and version-compatible writes."""

from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
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
    assert model.get_argument_spec()["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]


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
