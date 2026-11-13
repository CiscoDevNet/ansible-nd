# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Regression tests for empty port-channel membership normalization."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessPolicyModel,
    XePortChannelAccessPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_routed_interface import (
    PortChannelRoutedPolicyModel,
    XePortChannelRoutedPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostPolicyModel,
    XePortChannelTrunkHostPolicyModel,
)

POLICY_CASES = [
    (PortChannelAccessPolicyModel, "Ethernet1/41"),
    (XePortChannelAccessPolicyModel, "GigabitEthernet1/0/41"),
    (PortChannelTrunkHostPolicyModel, "Ethernet1/43"),
    (XePortChannelTrunkHostPolicyModel, "GigabitEthernet1/0/43"),
    (PortChannelRoutedPolicyModel, "Ethernet1/45"),
    (XePortChannelRoutedPolicyModel, "GigabitEthernet1/0/45"),
]
POLICY_CLASSES = [policy_class for policy_class, _member in POLICY_CASES]


@pytest.mark.parametrize("policy_class", POLICY_CLASSES)
def test_port_channel_empty_ports_normalize_missing_and_null(policy_class):
    """A missing or null controller member list has the canonical value ``[]``."""
    omitted = policy_class()
    null_value = policy_class.model_validate({"ports": None})
    explicit = policy_class(ports=[])

    assert omitted.ports == []
    assert null_value.ports == []
    assert explicit.ports == []
    assert "ports" not in omitted.model_fields_set
    assert "ports" in null_value.model_fields_set
    assert "ports" in explicit.model_fields_set


@pytest.mark.parametrize("policy_class,member", POLICY_CASES)
def test_port_channel_empty_ports_merged_semantics(policy_class, member):
    """Merged state distinguishes omitted membership from an explicit empty list."""
    current_empty = policy_class()
    current_with_member = policy_class(ports=[member])
    proposed_omitted = policy_class()
    proposed_empty = policy_class(ports=[])

    assert current_empty.get_diff(proposed_empty, exclude_unset=True) is True
    assert current_with_member.get_diff(proposed_omitted, exclude_unset=True) is True
    assert current_with_member.get_diff(proposed_empty, exclude_unset=True) is False


@pytest.mark.parametrize("policy_class,member", POLICY_CASES)
def test_port_channel_empty_ports_full_state_semantics(policy_class, member):
    """Replaced and overridden comparisons treat omitted membership as empty."""
    current_with_member = policy_class(ports=[member])
    proposed_omitted = policy_class()

    assert current_with_member.get_diff(proposed_omitted, exclude_unset=False) is False
    assert proposed_omitted.to_payload()["ports"] == []
