# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Scope and protected-member tests for the dot1q-tunnel host orchestrator."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import BulkCreateGroupKey, BulkCreateItem
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import EthernetBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _orchestrator(state: str = "merged", config: list | None = None) -> EthernetDot1qTunnelHostInterfaceOrchestrator:
    rest_send = RestSend({"fabric_name": "test_fabric", "state": state, "config": config or []})
    return EthernetDot1qTunnelHostInterfaceOrchestrator(rest_send=rest_send)


def _wire(name: str, policy_type: str, *, mode: str = "dot1qTunnel") -> dict:
    return {
        "interfaceName": name,
        "switchId": "SERIAL11",
        "interfaceType": "ethernet",
        "configData": {
            "mode": mode,
            "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": policy_type, "description": name}},
        },
    }


def test_query_all_selects_only_dot1q_host_policy(monkeypatch) -> None:
    """Overridden inventory must never claim access/trunk or dot1q members."""
    orchestrator = _orchestrator("overridden")
    inventory = {
        "ethernet1/40": _wire("Ethernet1/40", "dot1qTunnelHost"),
        "ethernet1/41": _wire("Ethernet1/41", "dot1qTunnelPoMember"),
        "ethernet1/42": _wire("Ethernet1/42", "accessHost", mode="access"),
    }
    monkeypatch.setattr(EthernetDot1qTunnelHostInterfaceOrchestrator, "validate_prerequisites", lambda self: None)
    monkeypatch.setattr(EthernetDot1qTunnelHostInterfaceOrchestrator, "_switches_to_query", lambda self: {"192.0.2.11": "SERIAL11"})
    monkeypatch.setattr(EthernetDot1qTunnelHostInterfaceOrchestrator, "_switch_interfaces", lambda self, _switch_id: deepcopy(inventory))
    result = orchestrator.query_all()
    assert [(item["switchIp"], item["interfaceName"]) for item in result] == [("192.0.2.11", "Ethernet1/40")]


@pytest.mark.parametrize("policy_type", ["dot1qTunnelPoMember", "dot1qTunnelVpcMember", "dot1qTunnelVpcPoMember"])
def test_existing_dot1q_members_fail_host_preflight(policy_type: str) -> None:
    """Existing dot1q members remain protected even when explicitly named."""
    orchestrator = _orchestrator("merged")
    proposed = EthernetDot1qTunnelHostInterfaceModel.from_config(
        {"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/41", "config_data": {"network_os": {"policy": {"description": "new"}}}}
    )
    with pytest.raises(RuntimeError, match="does not manage port-channel members"):
        orchestrator._prepare_member_intent(proposed, _wire("Ethernet1/41", policy_type))


def test_existing_fabric_owned_policy_cannot_be_reassigned() -> None:
    orchestrator = _orchestrator("merged")
    proposed = EthernetDot1qTunnelHostInterfaceModel.from_config(
        {"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/1", "config_data": {"network_os": {"policy": {"access_vlan": 150}}}}
    )
    with pytest.raises(RuntimeError, match="owned by the fabric"):
        orchestrator._check_fabric_ownership(proposed, _wire("Ethernet1/1", "numbered", mode="routed"))


@pytest.mark.parametrize("verb", [HttpVerbEnum.POST, HttpVerbEnum.PUT])
def test_empty_description_fallback_only_removes_the_exact_dot1q_field(monkeypatch, verb) -> None:
    orchestrator = _orchestrator()
    body = {
        "interfaces": [
            {"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelHost", "description": ""}}}},
            {"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelHost", "description": "kept"}}}},
        ]
    }
    calls = []

    def fake_request(_self, _path, _verb, data=None, _not_found_ok=False, _operation_type=None):
        calls.append(deepcopy(data))
        if len(calls) == 1:
            raise RuntimeError("ND HTTP 400")
        return {"ok": True}

    monkeypatch.setattr(EthernetBaseOrchestrator, "_request", fake_request)
    monkeypatch.setattr(orchestrator, "_rejected_empty_description", lambda _count: True)
    assert orchestrator._request("/exact", verb, body) == {"ok": True}
    assert calls[0]["interfaces"][0]["configData"]["networkOS"]["policy"]["description"] == ""
    assert "description" not in calls[1]["interfaces"][0]["configData"]["networkOS"]["policy"]
    assert calls[1]["interfaces"][1]["configData"]["networkOS"]["policy"]["description"] == "kept"
    assert body["interfaces"][0]["configData"]["networkOS"]["policy"]["description"] == ""


def test_empty_description_does_not_retry_unrelated_failure(monkeypatch) -> None:
    orchestrator = _orchestrator()
    calls = []

    def fake_request(_self, _path, _verb, data=None, _not_found_ok=False, _operation_type=None):
        calls.append(data)
        raise RuntimeError("transport failure")

    monkeypatch.setattr(EthernetBaseOrchestrator, "_request", fake_request)
    monkeypatch.setattr(orchestrator, "_rejected_empty_description", lambda _count: False)
    body = {"configData": {"networkOS": {"policy": {"policyType": "dot1qTunnelHost", "description": ""}}}}
    with pytest.raises(RuntimeError, match="transport failure"):
        orchestrator._request("/exact", HttpVerbEnum.PUT, body)
    assert len(calls) == 1


def test_dot1q_partial_create_queues_only_exact_accepted_interface(monkeypatch) -> None:
    orchestrator = _orchestrator()

    def partial_create(path, verb, data=None, **_kwargs):
        assert verb == HttpVerbEnum.POST
        assert [row["interfaceName"] for row in data["interfaces"]] == ["Ethernet1/40", "Ethernet1/41"]
        response = {
            "RETURN_CODE": 207,
            "METHOD": "POST",
            "REQUEST_PATH": path,
            "MESSAGE": "Multi-Status",
            "DATA": {
                "results": [
                    {"name": "Ethernet1/40", "status": "success"},
                    {"name": "Ethernet1/41", "status": "failed"},
                ]
            },
        }
        orchestrator.rest_send.response_current = response
        orchestrator.rest_send.add_response(response)
        raise RuntimeError("mixed create result")

    monkeypatch.setattr(orchestrator, "_request", partial_create)
    group = BulkCreateGroupKey(switch_id="SERIAL11", policy_type="dot1qTunnelHost")
    items = [BulkCreateItem(interface_name=name, payload={"interfaceName": name, "switchId": "SERIAL11"}) for name in ("Ethernet1/40", "Ethernet1/41")]
    with pytest.raises(RuntimeError, match=r"accepted \['Ethernet1/40'\] from the same request"):
        orchestrator._post_bulk_create_group(group, items)
    assert orchestrator._pending_deploys == [("Ethernet1/40", "SERIAL11")]


def test_dot1q_deploy_pending_uses_only_queued_exact_target(monkeypatch) -> None:
    orchestrator = _orchestrator()
    orchestrator.apply_config_actions({"config_actions": {"deploy": True}})
    orchestrator._pending_deploys = [("Ethernet1/40", "SERIAL11")]
    requests = []
    monkeypatch.setattr(orchestrator, "_deploy_interfaces", lambda pairs: requests.append(pairs) or {"ok": True})
    assert orchestrator.deploy_pending() == {"ok": True}
    assert requests == [[("Ethernet1/40", "SERIAL11")]]
    assert orchestrator._pending_deploys == []


@pytest.mark.parametrize("description", ["new description", ""])
def test_description_updates_decline_raw_inventory_bulk_without_state_reads(monkeypatch, description) -> None:
    orchestrator = _orchestrator()
    model = EthernetDot1qTunnelHostInterfaceModel.from_config(
        {"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/40", "config_data": {"network_os": {"policy": {"description": description}}}}
    )
    monkeypatch.setattr(
        orchestrator,
        "_resolve_switch_id",
        lambda *_args: pytest.fail("Declining raw-inventory dot1q batching must not add discovery reads"),
    )
    assert orchestrator.prepare_bulk_description_update(model, model) is None


def _dot1q_model(name: str = "Ethernet1/40", **policy) -> EthernetDot1qTunnelHostInterfaceModel:
    return EthernetDot1qTunnelHostInterfaceModel.from_config(
        {"switch_ip": "192.0.2.11", "interface_name": name, "config_data": {"network_os": {"policy": policy}}}
    )


def _bulk_orchestrator(version: str = "4.3.1.175") -> EthernetDot1qTunnelHostInterfaceOrchestrator:
    """Use a complete shared snapshot and fail on any unexpected inventory read."""
    rest_send = RestSend({"fabric_name": "test_fabric", "state": "replaced", "check_mode": False})
    rest_send.controller_version = version
    context = FabricContext(rest_send=rest_send, fabric_name="test_fabric")
    context._switch_map = {"192.0.2.11": "SERIAL11"}
    context._switch_map_by_id = {"SERIAL11": "192.0.2.11"}
    snapshot = InterfaceStateSnapshot(fabric_name="test_fabric", fabric_context=context, request=lambda **_kwargs: pytest.fail("Unexpected inventory read"))
    snapshot._interfaces_by_switch["SERIAL11"] = {}
    for name in ("Ethernet1/40", "Ethernet1/41"):
        current = _dot1q_model(name, description="before", access_vlan=150).to_payload()
        current["switchId"] = "SERIAL11"
        current["configData"]["networkOS"]["policy"]["ptp"] = False
        snapshot._interfaces_by_switch["SERIAL11"][name.casefold()] = current
    return EthernetDot1qTunnelHostInterfaceOrchestrator(rest_send=rest_send, interface_state_snapshot=snapshot)


@pytest.mark.parametrize("version", ["4.3.1.175", "4.3.2.1"])
def test_full_bulk_update_uses_typed_body_without_replaying_readonly_ptp(version) -> None:
    """A VLAN and description update must omit fields only echoed by ND."""
    orchestrator = _bulk_orchestrator(version)
    previous = _dot1q_model(description="before", access_vlan=150)
    desired = _dot1q_model(description="after", access_vlan=151)
    current = orchestrator.state_snapshot.cached_interface("SERIAL11", desired.interface_name)
    original = deepcopy(current)
    payload = orchestrator.prepare_bulk_full_update(desired, previous)
    assert payload == {**desired.to_payload(), "switchId": "SERIAL11"}
    assert payload["configData"]["networkOS"]["policy"]["accessVlan"] == 151
    assert "ptp" not in payload["configData"]["networkOS"]["policy"]
    assert orchestrator.state_snapshot.cached_interface("SERIAL11", desired.interface_name) == original


@pytest.mark.parametrize("policy", [{}, {"description": None}, {"description": ""}])
def test_full_bulk_update_keeps_empty_or_missing_description_on_singular_put(policy) -> None:
    orchestrator = _bulk_orchestrator()
    previous = _dot1q_model(description="before", access_vlan=150)
    desired = _dot1q_model(access_vlan=151, **policy)
    assert orchestrator.prepare_bulk_full_update(desired, previous) is None


def test_full_bulk_update_guard_rejects_identifier_only_model() -> None:
    orchestrator = _bulk_orchestrator()
    desired = EthernetDot1qTunnelHostInterfaceModel.from_config({"switch_ip": "192.0.2.11", "interface_name": "Ethernet1/40"})
    assert orchestrator._bulk_full_modify_guard(desired, {}) is False


def test_full_bulk_update_preserves_parent_family_guard(monkeypatch) -> None:
    orchestrator = _bulk_orchestrator()
    monkeypatch.setattr(EthernetBaseOrchestrator, "_bulk_full_modify_guard", lambda *_args: False)
    model = _dot1q_model(description="after", access_vlan=151)
    assert orchestrator.prepare_bulk_full_update(model, model) is None


@pytest.mark.parametrize("version", ["4.2.1.10", "4.3.0.99", "", "invalid"])
def test_full_bulk_update_requires_qualified_controller_version(version) -> None:
    orchestrator = _bulk_orchestrator(version)
    model = _dot1q_model(description="after", access_vlan=151)
    assert orchestrator.prepare_bulk_full_update(model, model) is None


def test_full_bulk_update_requires_previous_model() -> None:
    orchestrator = _bulk_orchestrator()
    model = _dot1q_model(description="after", access_vlan=151)
    assert orchestrator.prepare_bulk_full_update(model) is None


@pytest.mark.parametrize("mismatch", ["absent", "switch", "name", "family", "policy", "member", "network_os"])
def test_full_bulk_update_requires_exact_owned_nxos_dot1q_identity(mismatch) -> None:
    orchestrator = _bulk_orchestrator()
    inventory = orchestrator.state_snapshot._interfaces_by_switch["SERIAL11"]
    current = inventory["ethernet1/40"]
    if mismatch == "absent":
        inventory.pop("ethernet1/40")
    elif mismatch == "switch":
        current["switchId"] = "OTHER"
    elif mismatch == "name":
        current["interfaceName"] = "Ethernet1/99"
    elif mismatch == "family":
        current["interfaceType"] = "portChannel"
    elif mismatch == "policy":
        current["configData"]["networkOS"]["policy"]["policyType"] = "numbered"
    elif mismatch == "member":
        current["configData"]["networkOS"]["policy"]["policyType"] = "dot1qTunnelPoMember"
    else:
        current["configData"]["networkOS"]["networkOSType"] = "ios-xe"
    model = _dot1q_model(description="after", access_vlan=151)
    assert orchestrator.prepare_bulk_full_update(model, model) is None


@pytest.mark.parametrize("guard", ["_check_fabric_ownership", "_check_port_channel_restrictions"])
def test_full_bulk_sender_rechecks_ethernet_write_guards(monkeypatch, guard) -> None:
    """Batching must retain the same ownership and membership checks as PUT."""
    orchestrator = _bulk_orchestrator()
    models = [_dot1q_model(name, description="after", access_vlan=151) for name in ("Ethernet1/40", "Ethernet1/41")]
    payloads = [orchestrator.prepare_bulk_full_update(model, model) for model in models]

    def reject(*_args):
        raise RuntimeError("guard rejected write")

    monkeypatch.setattr(orchestrator, guard, reject)
    monkeypatch.setattr(orchestrator, "_request", lambda **_kwargs: pytest.fail("Rejected batch must not reach transport"))
    with pytest.raises(RuntimeError, match="guard rejected write"):
        orchestrator.modify_bulk_prepared(payloads, payload_orchestrators=[orchestrator] * 2, payload_models=models, payload_modes=["full"] * 2)
    assert orchestrator.pending_deploys == ()
