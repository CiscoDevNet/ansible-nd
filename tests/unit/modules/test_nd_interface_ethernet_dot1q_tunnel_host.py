# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone dot1q-tunnel module grouping and ownership-contract tests."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.modules.nd_interface_ethernet_dot1q_tunnel_host import expand_ethernet_config


def test_orchestrator_has_narrow_host_policy_scope() -> None:
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.model_class is EthernetDot1qTunnelHostInterfaceModel
    assert EthernetDot1qTunnelHostInterfaceOrchestrator._managed_policy_types(None) == {"dot1qTunnelHost"}
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.MEMBER_FAMILY == ""
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_create is True
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_delete is True
    assert EthernetDot1qTunnelHostInterfaceOrchestrator.supports_bulk_full_modify is False


def test_grouped_config_expands_once_per_switch_interface() -> None:
    grouped = [
        {"switch_ip": "192.0.2.11", "interface_names": ["Ethernet1/40", "Ethernet1/41"], "config_data": {"network_os": {"policy": {"access_vlan": 150}}}},
        {"switch_ip": "192.0.2.12", "interface_names": ["Ethernet1/40"], "config_data": {"network_os": {"policy": {"access_vlan": 151}}}},
    ]
    expanded = expand_ethernet_config(grouped)
    assert [(item["switch_ip"], item["interface_name"]) for item in expanded] == [
        ("192.0.2.11", "Ethernet1/40"),
        ("192.0.2.11", "Ethernet1/41"),
        ("192.0.2.12", "Ethernet1/40"),
    ]
    assert all("interface_names" not in item for item in expanded)


def test_grouped_config_rejects_duplicate_exact_target() -> None:
    grouped = [
        {"switch_ip": "192.0.2.11", "interface_names": ["Ethernet1/40"]},
        {"switch_ip": "192.0.2.11", "interface_names": ["ethernet1/40"]},
    ]
    with pytest.raises(ValueError, match="multiple config items"):
        expand_ethernet_config(grouped)
