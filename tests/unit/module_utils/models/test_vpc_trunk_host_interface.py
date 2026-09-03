# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for vpc_trunk_host_interface.py

Tests the vPC trunkVpcHost Interface Pydantic model classes.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_trunk_host_interface import (
    TrunkVpcHostConfigDataModel,
    TrunkVpcHostInterfaceModel,
    TrunkVpcHostNetworkOSModel,
    TrunkVpcHostPolicyModel,
    TrunkVpcHostVlanMappingEntryModel,
)
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_API_RESPONSE = {
    "switchIp": "192.168.1.1",
    "interfaceName": "vpc500",
    "interfaceType": "vpc",
    "configData": {
        "mode": "trunk",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "trunkVpcHost",
                "peerSwitchId": "FDOPEER0001",
                "adminState": True,
                "allowedVlans": "100-200",
                "nativeVlan": 99,
                "peer1PortChannelId": 500,
                "peer1MemberPorts": ["Ethernet1/1"],
                "peer2PortChannelId": 500,
                "peer2MemberPorts": ["Ethernet1/2"],
                "portChannelMode": "active",
                "lacpRate": "fast",
                "mtu": "jumbo",
            },
        },
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "vpc500",
    "config_data": {
        "network_os": {
            "policy": {
                "admin_state": True,
                "allowed_vlans": "100-200",
                "native_vlan": 99,
                "peer1_port_channel_id": 500,
                "peer1_member_ports": ["Ethernet1/1"],
                "peer2_port_channel_id": 500,
                "peer2_member_ports": ["Ethernet1/2"],
                "port_channel_mode": "active",
                "lacp_rate": "fast",
                "mtu": "jumbo",
            },
        },
    },
}


# =============================================================================
# Test: TrunkVpcHostPolicyModel — initialization
# =============================================================================


def test_vpc_trunk_host_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None except the frozen policy_type.

    ## Test

    - Instantiate with no arguments
    - Every per-peer and shared field is None
    - policy_type defaults to "trunkVpcHost"

    ## Classes and Methods

    - TrunkVpcHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = TrunkVpcHostPolicyModel()
    assert instance.policy_type == "trunkVpcHost"
    assert instance.peer_switch_id is None
    # Trunk-specific single-valued fields
    assert instance.allowed_vlans is None
    assert instance.native_vlan is None
    # Per-peer
    assert instance.peer1_member_ports is None
    assert instance.peer1_port_channel_configuration is None
    assert instance.peer1_port_channel_description is None
    assert instance.peer1_port_channel_id is None
    assert instance.peer2_member_ports is None
    assert instance.peer2_port_channel_configuration is None
    assert instance.peer2_port_channel_description is None
    assert instance.peer2_port_channel_id is None
    # VLAN mapping
    assert instance.vlan_mapping is None
    assert instance.vlan_mapping_entries is None
    # Shared
    assert instance.admin_state is None
    assert instance.bandwidth is None
    assert instance.bpdu_filter is None
    assert instance.bpdu_guard is None
    assert instance.cdp is None
    assert instance.copy_description is None
    assert instance.duplex_mode is None
    assert instance.inherit_bandwidth is None
    assert instance.lacp_port_priority is None
    assert instance.lacp_rate is None
    assert instance.lacp_suspend is None
    assert instance.lacp_vpc_convergence is None
    assert instance.link_type is None
    assert instance.mirror_config is None
    assert instance.mtu is None
    assert instance.negotiate_auto is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None
    assert instance.netflow_sampler is None
    assert instance.pfc is None
    assert instance.port_channel_mode is None
    assert instance.port_type_edge_trunk is None
    assert instance.qos is None
    assert instance.qos_policy is None
    assert instance.queuing_policy is None
    assert instance.speed is None
    assert instance.storm_control is None
    assert instance.storm_control_action is None


def test_vpc_trunk_host_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible via Python attributes

    ## Classes and Methods

    - TrunkVpcHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = TrunkVpcHostPolicyModel(
            admin_state=True,
            allowed_vlans="100-200,300",
            native_vlan=99,
            peer1_port_channel_id=500,
            peer1_member_ports=["Ethernet1/1"],
            peer2_port_channel_id=500,
            peer2_member_ports=["Ethernet1/2"],
            port_channel_mode="active",
            lacp_rate="fast",
        )
    assert instance.admin_state is True
    assert instance.allowed_vlans == "100-200,300"
    assert instance.native_vlan == 99
    assert instance.peer1_port_channel_id == 500
    assert instance.peer1_member_ports == ["Ethernet1/1"]
    assert instance.peer2_port_channel_id == 500
    assert instance.peer2_member_ports == ["Ethernet1/2"]
    assert instance.port_channel_mode == "active"
    assert instance.lacp_rate == "fast"
    assert instance.policy_type == "trunkVpcHost"


def test_vpc_trunk_host_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - TrunkVpcHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = TrunkVpcHostPolicyModel(
            adminState=True,
            allowedVlans="all",
            nativeVlan=1,
            peer1PortChannelId=600,
            peer1MemberPorts=["Ethernet1/5"],
            peer2PortChannelId=600,
            peer2MemberPorts=["Ethernet1/6"],
            portChannelMode="passive",
            policyType="trunkVpcHost",
            peerSwitchId="FDOPEER0001",
        )
    assert instance.admin_state is True
    assert instance.allowed_vlans == "all"
    assert instance.native_vlan == 1
    assert instance.peer1_port_channel_id == 600
    assert instance.peer1_member_ports == ["Ethernet1/5"]
    assert instance.peer2_port_channel_id == 600
    assert instance.peer2_member_ports == ["Ethernet1/6"]
    assert instance.port_channel_mode == "passive"
    assert instance.policy_type == "trunkVpcHost"
    assert instance.peer_switch_id == "FDOPEER0001"


# =============================================================================
# Test: TrunkVpcHostPolicyModel — allowed_vlans validator
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("none", "none"),
        ("all", "all"),
        ("100", "100"),
        ("100-200", "100-200"),
        ("100,200,300", "100,200,300"),
        ("1-200,500-2000,3000", "1-200,500-2000,3000"),
        (250, "250"),  # int -> str coercion (per ND wire echo)
        (None, None),
        ("", ""),
    ],
    ids=[
        "none_keyword",
        "all_keyword",
        "single_vlan",
        "single_range",
        "comma_list",
        "comma_with_ranges",
        "int_coerced_to_str",
        "none_passthrough",
        "empty_str_passthrough",
    ],
)
def test_vpc_trunk_host_interface_00150_allowed_vlans_accepts(value, expected):
    """
    # Summary

    Verify `allowed_vlans` validator accepts valid shapes and coerces ND's int echo to str.

    ## Test

    - "none" / "all" / single id / range / comma-list pass through unchanged
    - An int value is coerced to a string for idempotency stability

    ## Classes and Methods

    - TrunkVpcHostPolicyModel._validate_allowed_vlans()
    """
    with does_not_raise():
        instance = TrunkVpcHostPolicyModel(allowed_vlans=value)
    assert instance.allowed_vlans == expected


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "100-",
        "-100",
        "100,abc",
        "200-100",  # reversed range
        "100-5000",  # out of bounds high
        "0-100",  # out of bounds low
        "0",
        "4095",
        "100--200",
    ],
    ids=[
        "non_numeric",
        "trailing_dash",
        "leading_dash",
        "mixed_garbage",
        "reversed_range",
        "high_out_of_bounds",
        "low_out_of_bounds",
        "zero",
        "above_4094",
        "double_dash",
    ],
)
def test_vpc_trunk_host_interface_00155_allowed_vlans_rejects(value):
    """
    # Summary

    Verify `allowed_vlans` validator rejects invalid shapes and out-of-bounds values.

    ## Test

    - Garbage strings raise ValueError
    - Reversed ranges raise ValueError
    - VLAN ids outside 1..4094 raise ValueError

    ## Classes and Methods

    - TrunkVpcHostPolicyModel._validate_allowed_vlans()
    """
    with pytest.raises(ValidationError):
        TrunkVpcHostPolicyModel(allowed_vlans=value)


# =============================================================================
# Test: TrunkVpcHostPolicyModel — member_ports normalizer
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        (["ethernet1/1", "ethernet1/2"], ["Ethernet1/1", "Ethernet1/2"]),
        (["Ethernet1/1"], ["Ethernet1/1"]),
        # NX-OS abbreviations expand to the canonical Ethernet form so they match the wire key (idempotency).
        (["e1/1"], ["Ethernet1/1"]),
        (["eth1/1", "et1/1"], ["Ethernet1/1", "Ethernet1/1"]),
        # Any casing of the full prefix canonicalizes to "Ethernet".
        (["ETHERNET1/2", "etHernet1/3"], ["Ethernet1/2", "Ethernet1/3"]),
        ([], []),
        (None, None),
        (["ethernet1/1/1"], ["Ethernet1/1/1"]),
    ],
    ids=[
        "lowercase_to_canonical",
        "already_canonical_passthrough",
        "single_letter_expanded",
        "abbreviations_expanded",
        "any_casing_canonicalized",
        "empty_list",
        "none_passthrough",
        "breakout_preserved",
    ],
)
def test_vpc_trunk_host_interface_00180_peer1(value, expected):
    """
    # Summary

    Verify `normalize_member_ports` expands each peer1 member name to ND's canonical `Ethernet` form.

    ## Test

    - Lowercase and abbreviated member names (`e1/1`, `eth1/1`, `et1/1`) expand to `Ethernet...`
    - Any casing of the full prefix canonicalizes to `Ethernet`
    - Already-canonical values pass through; empty list and None pass through; breakout suffixes are preserved

    ## Classes and Methods

    - TrunkVpcHostPolicyModel.normalize_member_ports()
    - TrunkVpcHostPolicyModel._normalize_member_name()
    """
    with does_not_raise():
        instance = TrunkVpcHostPolicyModel(peer1_member_ports=value)
    assert instance.peer1_member_ports == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (["ethernet1/1", "ethernet1/2"], ["Ethernet1/1", "Ethernet1/2"]),
        (["Ethernet1/1"], ["Ethernet1/1"]),
        (["eth1/1"], ["Ethernet1/1"]),
        (None, None),
    ],
    ids=["lowercase_to_canonical", "already_canonical_passthrough", "abbreviation_expanded", "none_passthrough"],
)
def test_vpc_trunk_host_interface_00185_peer2(value, expected):
    """
    # Summary

    Verify `normalize_member_ports` also applies to peer2_member_ports.

    ## Test

    - Same normalization rules as peer1

    ## Classes and Methods

    - TrunkVpcHostPolicyModel.normalize_member_ports()
    - TrunkVpcHostPolicyModel._normalize_member_name()
    """
    with does_not_raise():
        instance = TrunkVpcHostPolicyModel(peer2_member_ports=value)
    assert instance.peer2_member_ports == expected


# =============================================================================
# Test: TrunkVpcHostPolicyModel — bounds + frozen
# =============================================================================


@pytest.mark.parametrize(
    "field,value",
    [
        ("native_vlan", 0),
        ("native_vlan", 4095),
        ("peer1_port_channel_id", 0),
        ("peer1_port_channel_id", 4097),
        ("peer2_port_channel_id", 0),
        ("peer2_port_channel_id", 4097),
    ],
    ids=[
        "native_vlan_below_min",
        "native_vlan_above_max",
        "peer1_pc_id_below_min",
        "peer1_pc_id_above_max",
        "peer2_pc_id_below_min",
        "peer2_pc_id_above_max",
    ],
)
def test_vpc_trunk_host_interface_00200_range(field, value):
    """
    # Summary

    Verify VLAN (1-4094) and port-channel-id (1-4096) range validation.

    ## Test

    - Values outside the valid range raise ValidationError

    ## Classes and Methods

    - TrunkVpcHostPolicyModel (Pydantic Field constraints)
    """
    with pytest.raises(ValidationError):
        TrunkVpcHostPolicyModel(**{field: value})


def test_vpc_trunk_host_interface_00210_policy_type_frozen():
    """
    # Summary

    Verify `policy_type` cannot be reassigned to a different value (frozen=True).

    ## Test

    - Construct with default policy_type
    - Attempt to assign a different value raises ValidationError

    ## Classes and Methods

    - TrunkVpcHostPolicyModel (frozen Field)
    """
    instance = TrunkVpcHostPolicyModel()
    with pytest.raises(ValidationError):
        instance.policy_type = "accessVpcHost"


# =============================================================================
# Test: TrunkVpcHostVlanMappingEntryModel
# =============================================================================


def test_vpc_trunk_host_interface_00250_vlan_mapping_entry_construction():
    """
    # Summary

    Verify VLAN mapping entry accepts customer/provider ids with valid shape.

    ## Test

    - Construction with mixed scalar / range customer ids
    - Optional dot1q_tunnel and customer_inner_vlan_id

    ## Classes and Methods

    - TrunkVpcHostVlanMappingEntryModel.__init__()
    """
    entry = TrunkVpcHostVlanMappingEntryModel(
        customer_vlan_id=["100", "200-300"],
        provider_vlan_id=1000,
        dot1q_tunnel=True,
        customer_inner_vlan_id=510,
    )
    assert entry.customer_vlan_id == ["100", "200-300"]
    assert entry.provider_vlan_id == 1000
    assert entry.dot1q_tunnel is True
    assert entry.customer_inner_vlan_id == 510


@pytest.mark.parametrize(
    "value",
    [
        ["abc"],
        ["100", ""],
        [""],
        ["200-100"],
        ["0"],
        ["5000"],
    ],
    ids=["non_numeric", "empty_token", "single_empty", "reversed_range", "low_oob", "high_oob"],
)
def test_vpc_trunk_host_interface_00255_customer_vlan_id_rejects(value):
    """
    # Summary

    Verify customer_vlan_id list validator rejects invalid entries.

    ## Test

    - Non-string / empty / out-of-bounds / reversed-range entries raise ValueError

    ## Classes and Methods

    - TrunkVpcHostPolicyModel._validate_customer_vlan_id_list()
    """
    with pytest.raises(ValidationError):
        TrunkVpcHostVlanMappingEntryModel(customer_vlan_id=value)


# =============================================================================
# Test: TrunkVpcHostInterfaceModel — identifier behavior
# =============================================================================


def test_vpc_trunk_host_interface_00300_identifier():
    """
    # Summary

    Verify the identifier is `interface_name` only (single strategy). A vPC interface is one fabric-level resource;
    ND echoes it from both peers but it must collapse to one identity for diff/override-deletion correctness.

    ## Test

    - Identifier is `["interface_name"]`
    - Identifier strategy is `"single"`
    - get_identifier_value returns the interface name string
    - `switch_ip` is excluded from the diff dict (routing-only field)

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.get_identifier_value()
    - TrunkVpcHostInterfaceModel.to_diff_dict()
    """
    instance = TrunkVpcHostInterfaceModel(switch_ip="192.168.1.1", interface_name="vpc500")
    assert instance.identifiers == ["interface_name"]
    assert instance.identifier_strategy == "single"
    assert instance.get_identifier_value() == "vpc500"
    # switch_ip is for routing only; it must not appear in the diff dict so two peers' echoes diff-equal.
    assert "switchIp" not in instance.to_diff_dict()


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Vpc500", "vpc500"),
        ("VPC500", "vpc500"),
        ("vpc500", "vpc500"),
        ("vPC500", "vpc500"),
    ],
    ids=["title_case", "upper_case", "lower_case_passthrough", "mixed_case"],
)
def test_vpc_trunk_host_interface_00310_normalize_name(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` lowercases interface names.

    ## Test

    - Various casings are normalized to lowercase

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.normalize_interface_name()
    """
    instance = TrunkVpcHostInterfaceModel(switch_ip="192.168.1.1", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: TrunkVpcHostInterfaceModel — round-trip
# =============================================================================


def test_vpc_trunk_host_interface_00400_round_trip_from_api():
    """
    # Summary

    Verify the model accepts the camelCase API response shape and exposes values via Python attributes.

    ## Test

    - Construct from SAMPLE_API_RESPONSE
    - Nested values accessible
    - peerSwitchId reads through

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.__init__()
    """
    instance = TrunkVpcHostInterfaceModel(**SAMPLE_API_RESPONSE)
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "vpc500"
    assert instance.interface_type == "vpc"
    policy = instance.config_data.network_os.policy
    assert policy.policy_type == "trunkVpcHost"
    assert policy.peer_switch_id == "FDOPEER0001"
    assert policy.allowed_vlans == "100-200"
    assert policy.native_vlan == 99
    assert policy.peer1_member_ports == ["Ethernet1/1"]
    assert policy.peer2_member_ports == ["Ethernet1/2"]
    assert policy.admin_state is True


def test_vpc_trunk_host_interface_00410_round_trip_from_ansible():
    """
    # Summary

    Verify the model accepts the snake_case Ansible config shape.

    ## Test

    - Construct from SAMPLE_ANSIBLE_CONFIG
    - Nested values accessible

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.__init__()
    """
    instance = TrunkVpcHostInterfaceModel(**copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.switch_ip == "192.168.1.1"
    policy = instance.config_data.network_os.policy
    assert policy.peer1_port_channel_id == 500
    assert policy.peer2_port_channel_id == 500
    assert policy.allowed_vlans == "100-200"
    assert policy.native_vlan == 99
    assert policy.policy_type == "trunkVpcHost"


def test_vpc_trunk_host_interface_00420_to_payload():
    """
    # Summary

    Verify `to_payload()` serializes the model back to camelCase, drops the `switch_ip` identifier, and splits the
    user-facing single `allowed_vlans` and `native_vlan` into the per-peer write keys that ND's create schema requires.

    ## Test

    - to_payload() returns wire-shaped dict
    - switchIp is excluded (Ansible-facing only)
    - interfaceType is present
    - Nested policy aliases are camelCase
    - allowedVlans and nativeVlan are absent from the payload (split into per-peer keys)
    - peer1/peer2 AllowedVlans + NativeVlan are present with the same value

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.to_payload()
    - TrunkVpcHostPolicyModel.expand_per_peer_fields()
    """
    instance = TrunkVpcHostInterfaceModel(**SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert "switchIp" not in payload
    assert payload["interfaceName"] == "vpc500"
    assert payload["interfaceType"] == "vpc"
    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == "trunkVpcHost"
    assert policy["peer1MemberPorts"] == ["Ethernet1/1"]
    assert policy["peer2MemberPorts"] == ["Ethernet1/2"]
    assert policy["peer1PortChannelId"] == 500
    assert policy["peer2PortChannelId"] == 500
    # allowed_vlans split to both per-peer keys; the single-valued allowedVlans key is removed on payload.
    assert "allowedVlans" not in policy
    assert policy["peer1AllowedVlans"] == "100-200"
    assert policy["peer2AllowedVlans"] == "100-200"
    # native_vlan split as well.
    assert "nativeVlan" not in policy
    assert policy["peer1NativeVlan"] == 99
    assert policy["peer2NativeVlan"] == 99


def test_vpc_trunk_host_interface_00425_to_config_keeps_single_vlan():
    """
    # Summary

    Verify `to_config()` keeps `allowed_vlans` and `native_vlan` as single fields (does NOT expand to per-peer) and
    drops the frozen, argspec-excluded `policy_type` so it does not leak into before/after/gathered output.
    The expansion only happens for payload mode; config / diff modes use the wire-echo (single) shape so idempotency works.

    ## Test

    - to_config() returns the snake_case fields `allowed_vlans` and `native_vlan`
    - `peer1_allowed_vlans` / `peer2_allowed_vlans` / `peer1_native_vlan` / `peer2_native_vlan` are NOT in the config
    - `policy_type` / `policyType` are NOT in the config (frozen scaffolding suppressed)

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.to_config()
    - TrunkVpcHostPolicyModel.expand_per_peer_fields()
    """
    instance = TrunkVpcHostInterfaceModel(**SAMPLE_API_RESPONSE)
    config = instance.to_config()
    policy = config["config_data"]["network_os"]["policy"]
    assert policy["allowed_vlans"] == "100-200"
    assert policy["native_vlan"] == 99
    assert "peer1_allowed_vlans" not in policy
    assert "peer2_allowed_vlans" not in policy
    assert "peer1_native_vlan" not in policy
    assert "peer2_native_vlan" not in policy
    assert "policy_type" not in policy
    assert "policyType" not in policy


def test_vpc_trunk_host_interface_00430_payload_with_vlan_mapping():
    """
    # Summary

    Verify VLAN mapping entries serialize through `to_payload()` with their camelCase aliases intact.

    ## Test

    - vlan_mapping=True and a single entry are present in the payload
    - Entry keys are camelCase (customerVlanId, providerVlanId, etc.)

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.to_payload()
    - TrunkVpcHostVlanMappingEntryModel
    """
    cfg = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    cfg["config_data"]["network_os"]["policy"]["vlan_mapping"] = True
    cfg["config_data"]["network_os"]["policy"]["vlan_mapping_entries"] = [
        {
            "customer_vlan_id": ["100", "200-300"],
            "provider_vlan_id": 1000,
            "dot1q_tunnel": False,
        },
    ]
    instance = TrunkVpcHostInterfaceModel(**cfg)
    payload = instance.to_payload()
    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["vlanMapping"] is True
    assert len(policy["vlanMappingEntries"]) == 1
    entry = policy["vlanMappingEntries"][0]
    assert entry["customerVlanId"] == ["100", "200-300"]
    assert entry["providerVlanId"] == 1000
    assert entry["dot1qTunnel"] is False


# =============================================================================
# Test: Argument spec exposure
# =============================================================================


def test_vpc_trunk_host_interface_00500_argument_spec_shape():
    """
    # Summary

    Verify the argument spec exposes the right shape: fabric_name, config list, state choices.

    ## Test

    - top-level keys: fabric_name, config, state
    - state choices contain merged/replaced/overridden/deleted
    - config has nested policy options including peer1_/peer2_ fields and trunk-specific fields
    - Frozen scaffolding (interface_type, mode, network_os_type, policy_type) is NOT exposed
    - peer_switch_id (orchestrator-injected) is NOT exposed
    - Per-peer AllowedVlans / NativeVlan are NOT exposed (ND collapses to single fields on read)

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.get_argument_spec()
    """
    spec = TrunkVpcHostInterfaceModel.get_argument_spec()
    assert set(spec) == {"fabric_name", "config", "state"}
    assert spec["fabric_name"]["required"] is True
    assert set(spec["state"]["choices"]) == {"merged", "replaced", "overridden", "deleted", "gathered"}

    config_options = spec["config"]["options"]
    assert "switch_ip" in config_options
    assert "interface_name" in config_options
    assert "config_data" in config_options

    policy_options = config_options["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    # Trunk-specific single fields
    assert "allowed_vlans" in policy_options
    assert "native_vlan" in policy_options
    assert "vlan_mapping" in policy_options
    assert "vlan_mapping_entries" in policy_options
    # Per-peer presence
    assert "peer1_port_channel_id" in policy_options
    assert "peer1_member_ports" in policy_options
    assert "peer2_port_channel_id" in policy_options
    assert "peer2_member_ports" in policy_options
    # Shared field samples
    assert "admin_state" in policy_options
    assert "lacp_rate" in policy_options
    assert "port_channel_mode" in policy_options
    assert "port_type_edge_trunk" in policy_options
    # Frozen/injected exclusions
    assert "interface_type" not in config_options
    assert "policy_type" not in policy_options
    assert "mode" not in policy_options
    assert "network_os_type" not in policy_options
    assert "peer_switch_id" not in policy_options
    # Per-peer VLAN/Native explicitly NOT exposed (ND collapses on read; user sets single fields).
    assert "peer1_allowed_vlans" not in policy_options
    assert "peer2_allowed_vlans" not in policy_options
    assert "peer1_native_vlan" not in policy_options
    assert "peer2_native_vlan" not in policy_options


def test_vpc_trunk_host_interface_00510_argument_spec_vlan_mapping_entries_shape():
    """
    # Summary

    Verify `vlan_mapping_entries` argspec exposes the four nested options.

    ## Test

    - vlan_mapping_entries is a list of dicts with options: customer_vlan_id, customer_inner_vlan_id, dot1q_tunnel, provider_vlan_id

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.get_argument_spec()
    """
    spec = TrunkVpcHostInterfaceModel.get_argument_spec()
    policy_options = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    entries = policy_options["vlan_mapping_entries"]
    assert entries["type"] == "list"
    assert entries["elements"] == "dict"
    assert set(entries["options"]) == {"customer_vlan_id", "customer_inner_vlan_id", "dot1q_tunnel", "provider_vlan_id"}


# =============================================================================
# Test: Nested-model sanity (Config / NetworkOS)
# =============================================================================


def test_vpc_trunk_host_interface_00600_nested_defaults():
    """
    # Summary

    Verify ConfigData and NetworkOS containers default their frozen discriminators.

    ## Test

    - TrunkVpcHostConfigDataModel.mode defaults to "trunk"
    - TrunkVpcHostNetworkOSModel.network_os_type defaults to "nx-os"

    ## Classes and Methods

    - TrunkVpcHostConfigDataModel
    - TrunkVpcHostNetworkOSModel
    """
    network_os = TrunkVpcHostNetworkOSModel(policy=TrunkVpcHostPolicyModel())
    config = TrunkVpcHostConfigDataModel(network_os=network_os)
    assert config.mode == "trunk"
    assert config.network_os.network_os_type == "nx-os"


# =============================================================================
# Gathered state and filtering tests
# =============================================================================


def test_vpc_trunk_host_interface_00700_gathered_state_in_choices():
    """
    # Summary

    Verify state choices include ``gathered`` and default is ``merged``.

    ## Test

    - state choices: ["merged", "replaced", "overridden", "deleted", "gathered"]
    - state default: "merged"

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.get_argument_spec()
    """
    spec = TrunkVpcHostInterfaceModel.get_argument_spec()
    state_spec = spec["state"]
    assert state_spec["choices"] == [
        "merged",
        "replaced",
        "overridden",
        "deleted",
        "gathered",
    ]
    assert state_spec["default"] == "merged"


def test_vpc_trunk_host_interface_00710_config_optional_for_gathered():
    """
    # Summary

    Verify ``config`` is optional so ``state=gathered`` can run without input.

    ## Test

    - config required is False

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.get_argument_spec()
    """
    spec = TrunkVpcHostInterfaceModel.get_argument_spec()
    assert spec["config"].get("required", False) is False


def test_vpc_trunk_host_interface_00720_identifiers_optional_for_gathered():
    """
    # Summary

    Verify gathered filters may omit both identifiers (``switch_ip``, ``interface_name``).

    ## Test

    - switch_ip required is False
    - interface_name required is False

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.get_argument_spec()
    """
    config_options = TrunkVpcHostInterfaceModel.get_argument_spec()["config"]["options"]
    assert config_options["switch_ip"].get("required", False) is False
    assert config_options["interface_name"].get("required", False) is False


def test_vpc_trunk_host_interface_00730_supports_gathered_filtering():
    """
    # Summary

    Verify ``supports_gathered_filtering`` is ``True`` on ``TrunkVpcHostInterfaceModel``
    and ``False`` on the base ``NDBaseModel``.

    ## Test

    - NDBaseModel.supports_gathered_filtering is False
    - TrunkVpcHostInterfaceModel.supports_gathered_filtering is True

    ## Classes and Methods

    - NDBaseModel.supports_gathered_filtering
    - TrunkVpcHostInterfaceModel.supports_gathered_filtering
    """
    from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

    assert NDBaseModel.supports_gathered_filtering is False
    assert TrunkVpcHostInterfaceModel.supports_gathered_filtering is True


def test_vpc_trunk_host_interface_00740_gathered_filter_properties():
    """
    # Summary

    Verify ``gathered_filter_properties`` contains the expected 7 properties.

    ## Test

    - gathered_filter_properties tuple has exactly 7 entries
    - Each entry matches the expected dot-path

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.gathered_filter_properties
    """
    assert TrunkVpcHostInterfaceModel.gathered_filter_properties == (
        "switch_ip",
        "interface_name",
        "config_data.network_os.policy.admin_state",
        "config_data.network_os.policy.allowed_vlans",
        "config_data.network_os.policy.native_vlan",
        "config_data.network_os.policy.peer1_port_channel_id",
        "config_data.network_os.policy.peer2_port_channel_id",
    )


def test_vpc_trunk_host_interface_00750_normalize_gathered_filter_lowercase():
    """
    # Summary

    Verify ``normalize_gathered_filter`` lowercases vPC interface names
    (matching the Pydantic ``normalize_interface_name`` validator).

    ## Test

    - ``Vpc500`` normalizes to ``vpc500``
    - ``VPC600`` normalizes to ``vpc600``
    - ``vpc700`` is idempotent

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.normalize_gathered_filter()
    """
    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"interface_name": "Vpc500"}) == {"interface_name": "vpc500"}

    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"interface_name": "VPC600"}) == {"interface_name": "vpc600"}

    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"interface_name": "vpc700"}) == {"interface_name": "vpc700"}


def test_vpc_trunk_host_interface_00760_normalize_gathered_filter_passthrough():
    """
    # Summary

    Verify ``normalize_gathered_filter`` passes through filters without ``interface_name``
    unchanged.

    ## Test

    - Filter with only switch_ip is returned unchanged
    - Filter with only policy fields is returned unchanged
    - Empty filter is returned unchanged

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.normalize_gathered_filter()
    """
    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"switch_ip": "10.1.1.1"}) == {"switch_ip": "10.1.1.1"}

    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"config_data": {"network_os": {"policy": {"allowed_vlans": "100-200"}}}}) == {
        "config_data": {"network_os": {"policy": {"allowed_vlans": "100-200"}}}
    }

    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({}) == {}


def test_vpc_trunk_host_interface_00770_normalize_gathered_filter_edge_cases():
    """
    # Summary

    Verify ``normalize_gathered_filter`` handles edge cases for ``interface_name``:
    ``None``, empty string, and non-string values.

    ## Test

    - interface_name=None is passed through
    - interface_name="" is passed through
    - interface_name=123 is passed through

    ## Classes and Methods

    - TrunkVpcHostInterfaceModel.normalize_gathered_filter()
    """
    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"interface_name": None}) == {"interface_name": None}

    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"interface_name": ""}) == {"interface_name": ""}

    assert TrunkVpcHostInterfaceModel.normalize_gathered_filter({"interface_name": 123}) == {"interface_name": 123}
