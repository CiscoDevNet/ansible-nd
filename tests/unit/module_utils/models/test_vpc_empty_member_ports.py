# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Regression tests for empty per-peer vPC membership normalization."""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
    AccessVpcHostPolicyModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_trunk_host_interface import (
    TrunkVpcHostPolicyModel,
)

POLICY_CLASSES = [AccessVpcHostPolicyModel, TrunkVpcHostPolicyModel]
PEER_CASES = [
    (AccessVpcHostPolicyModel, "peer1_member_ports", "peer1MemberPorts", "Ethernet1/42"),
    (AccessVpcHostPolicyModel, "peer2_member_ports", "peer2MemberPorts", "Ethernet1/42"),
    (TrunkVpcHostPolicyModel, "peer1_member_ports", "peer1MemberPorts", "Ethernet1/44"),
    (TrunkVpcHostPolicyModel, "peer2_member_ports", "peer2MemberPorts", "Ethernet1/44"),
]


@pytest.mark.parametrize("policy_class", POLICY_CLASSES)
def test_vpc_empty_member_ports_default_both_peers(policy_class):
    """Missing peer lists have canonical empty values without becoming explicitly set."""
    omitted = policy_class()

    assert omitted.peer1_member_ports == []
    assert omitted.peer2_member_ports == []
    assert "peer1_member_ports" not in omitted.model_fields_set
    assert "peer2_member_ports" not in omitted.model_fields_set


@pytest.mark.parametrize("policy_class,field_name,wire_name,member", PEER_CASES)
def test_vpc_empty_member_ports_normalize_null_and_explicit(policy_class, field_name, wire_name, member):
    """Null and explicit empty peer lists normalize to the same value."""
    del member
    null_value = policy_class.model_validate({field_name: None})
    explicit = policy_class(**{field_name: []})

    assert getattr(null_value, field_name) == []
    assert getattr(explicit, field_name) == []
    assert field_name in null_value.model_fields_set
    assert field_name in explicit.model_fields_set
    assert explicit.to_payload()[wire_name] == []


@pytest.mark.parametrize("policy_class,field_name,wire_name,member", PEER_CASES)
def test_vpc_empty_member_ports_merged_semantics(policy_class, field_name, wire_name, member):
    """Merged state preserves omitted peer membership and clears only an explicitly empty peer list."""
    del wire_name
    current_empty = policy_class()
    current_with_member = policy_class(**{field_name: [member]})
    proposed_omitted = policy_class()
    proposed_empty = policy_class(**{field_name: []})

    assert current_empty.get_diff(proposed_empty, exclude_unset=True) is True
    assert current_with_member.get_diff(proposed_omitted, exclude_unset=True) is True
    assert current_with_member.get_diff(proposed_empty, exclude_unset=True) is False


@pytest.mark.parametrize("policy_class,field_name,wire_name,member", PEER_CASES)
def test_vpc_empty_member_ports_full_state_semantics(policy_class, field_name, wire_name, member):
    """Replaced and overridden comparisons reset an omitted peer membership list to empty."""
    current_with_member = policy_class(**{field_name: [member]})
    proposed_omitted = policy_class()

    assert current_with_member.get_diff(proposed_omitted, exclude_unset=False) is False
    assert proposed_omitted.to_payload()[wire_name] == []
