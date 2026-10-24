# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Scope and protected-member tests for the dot1q-tunnel host orchestrator."""

from __future__ import annotations

from copy import deepcopy

import pytest

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


def test_empty_description_fallback_only_removes_the_exact_dot1q_field(monkeypatch) -> None:
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
    assert orchestrator._request("/exact", HttpVerbEnum.POST, body) == {"ok": True}
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
