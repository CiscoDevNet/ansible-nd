# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Scope and protected-member tests for the dot1q-tunnel host orchestrator."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
)
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
