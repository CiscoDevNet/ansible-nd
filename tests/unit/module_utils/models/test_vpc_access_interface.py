# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for vpc_access_interface.py

Tests the vPC accessVpcHost Interface Pydantic model classes.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
    AccessVpcHostConfigDataModel,
    AccessVpcHostInterfaceModel,
    AccessVpcHostNetworkOSModel,
    AccessVpcHostPolicyModel,
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
    "interfaceName": "vpc100",
    "interfaceType": "vpc",
    "configData": {
        "mode": "access",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "accessVpcHost",
                "peerSwitchId": "FDOPEER0001",
                "adminState": True,
                "accessVlan": 10,
                "peer1PortChannelId": 100,
                "peer1MemberPorts": ["Ethernet1/1"],
                "peer2PortChannelId": 100,
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
    "interface_name": "vpc100",
    "config_data": {
        "network_os": {
            "policy": {
                "admin_state": True,
                "access_vlan": 10,
                "peer1_port_channel_id": 100,
                "peer1_member_ports": ["Ethernet1/1"],
                "peer2_port_channel_id": 100,
                "peer2_member_ports": ["Ethernet1/2"],
                "port_channel_mode": "active",
                "lacp_rate": "fast",
                "mtu": "jumbo",
            },
        },
    },
}


# =============================================================================
# Test: AccessVpcHostPolicyModel — initialization
# =============================================================================


def test_vpc_access_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None except the frozen policy_type.

    ## Test

    - Instantiate with no arguments
    - Every per-peer and shared field is None
    - policy_type defaults to "accessVpcHost"

    ## Classes and Methods

    - AccessVpcHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = AccessVpcHostPolicyModel()
    assert instance.policy_type == "accessVpcHost"
    assert instance.peer_switch_id is None
    # Shared access VLAN
    assert instance.access_vlan is None
    # Per-peer
    assert instance.peer1_member_ports is None
    assert instance.peer1_port_channel_configuration is None
    assert instance.peer1_port_channel_description is None
    assert instance.peer1_port_channel_id is None
    assert instance.peer2_member_ports is None
    assert instance.peer2_port_channel_configuration is None
    assert instance.peer2_port_channel_description is None
    assert instance.peer2_port_channel_id is None
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


def test_vpc_access_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible via Python attributes

    ## Classes and Methods

    - AccessVpcHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = AccessVpcHostPolicyModel(
            admin_state=True,
            access_vlan=10,
            peer1_port_channel_id=100,
            peer1_member_ports=["Ethernet1/1"],
            peer2_port_channel_id=100,
            peer2_member_ports=["Ethernet1/2"],
            port_channel_mode="active",
            lacp_rate="fast",
        )
    assert instance.admin_state is True
    assert instance.access_vlan == 10
    assert instance.peer1_port_channel_id == 100
    assert instance.peer1_member_ports == ["Ethernet1/1"]
    assert instance.peer2_port_channel_id == 100
    assert instance.peer2_member_ports == ["Ethernet1/2"]
    assert instance.port_channel_mode == "active"
    assert instance.lacp_rate == "fast"
    assert instance.policy_type == "accessVpcHost"


def test_vpc_access_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - AccessVpcHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = AccessVpcHostPolicyModel(
            adminState=True,
            accessVlan=20,
            peer1PortChannelId=200,
            peer1MemberPorts=["Ethernet1/5"],
            peer2PortChannelId=200,
            peer2MemberPorts=["Ethernet1/6"],
            portChannelMode="passive",
            policyType="accessVpcHost",
            peerSwitchId="FDOPEER0001",
        )
    assert instance.admin_state is True
    assert instance.access_vlan == 20
    assert instance.peer1_port_channel_id == 200
    assert instance.peer1_member_ports == ["Ethernet1/5"]
    assert instance.peer2_port_channel_id == 200
    assert instance.peer2_member_ports == ["Ethernet1/6"]
    assert instance.port_channel_mode == "passive"
    assert instance.policy_type == "accessVpcHost"
    assert instance.peer_switch_id == "FDOPEER0001"


# =============================================================================
# Test: AccessVpcHostPolicyModel — validators
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        (["ethernet1/1", "ethernet1/2"], ["Ethernet1/1", "Ethernet1/2"]),
        (["Ethernet1/1"], ["Ethernet1/1"]),
        (["e1/1"], ["E1/1"]),
        ([], []),
        (None, None),
        (["ethernet1/1/1", "ETHERNET1/2"], ["Ethernet1/1/1", "ETHERNET1/2"]),
    ],
    ids=[
        "lowercase_to_capitalized",
        "already_capitalized_passthrough",
        "single_letter",
        "empty_list",
        "none_passthrough",
        "mixed_breakout",
    ],
)
def test_vpc_access_interface_00180_peer1(value, expected):
    """
    # Summary

    Verify `normalize_member_ports` capitalizes the first character of each peer1 member name.

    ## Test

    - Lowercase member names are capitalized
    - Already-capitalized values pass through
    - Empty list and None pass through

    ## Classes and Methods

    - AccessVpcHostPolicyModel.normalize_member_ports()
    """
    with does_not_raise():
        instance = AccessVpcHostPolicyModel(peer1_member_ports=value)
    assert instance.peer1_member_ports == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (["ethernet1/1", "ethernet1/2"], ["Ethernet1/1", "Ethernet1/2"]),
        (["Ethernet1/1"], ["Ethernet1/1"]),
        (None, None),
    ],
    ids=["lowercase_to_capitalized", "already_capitalized_passthrough", "none_passthrough"],
)
def test_vpc_access_interface_00185_peer2(value, expected):
    """
    # Summary

    Verify `normalize_member_ports` also applies to peer2_member_ports.

    ## Test

    - Same normalization rules as peer1

    ## Classes and Methods

    - AccessVpcHostPolicyModel.normalize_member_ports()
    """
    with does_not_raise():
        instance = AccessVpcHostPolicyModel(peer2_member_ports=value)
    assert instance.peer2_member_ports == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("access_vlan", 0),
        ("access_vlan", 4095),
        ("peer1_port_channel_id", 0),
        ("peer1_port_channel_id", 4097),
        ("peer2_port_channel_id", 0),
        ("peer2_port_channel_id", 4097),
    ],
    ids=[
        "vlan_below_min",
        "vlan_above_max",
        "peer1_pc_id_below_min",
        "peer1_pc_id_above_max",
        "peer2_pc_id_below_min",
        "peer2_pc_id_above_max",
    ],
)
def test_vpc_access_interface_00200_range(field, value):
    """
    # Summary

    Verify VLAN (1-4094) and port-channel-id (1-4096) range validation.

    ## Test

    - Values outside the valid range raise ValidationError

    ## Classes and Methods

    - AccessVpcHostPolicyModel (Pydantic Field constraints)
    """
    with pytest.raises(ValidationError):
        AccessVpcHostPolicyModel(**{field: value})


def test_vpc_access_interface_00210_policy_type_frozen():
    """
    # Summary

    Verify `policy_type` cannot be reassigned to a different value (frozen=True).

    ## Test

    - Construct with default policy_type
    - Attempt to assign a different value raises ValidationError

    ## Classes and Methods

    - AccessVpcHostPolicyModel (frozen Field)
    """
    instance = AccessVpcHostPolicyModel()
    with pytest.raises(ValidationError):
        instance.policy_type = "trunkVpcHost"


# =============================================================================
# Test: AccessVpcHostInterfaceModel — identifier behavior
# =============================================================================


def test_vpc_access_interface_00300_identifier():
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

    - AccessVpcHostInterfaceModel.get_identifier_value()
    - AccessVpcHostInterfaceModel.to_diff_dict()
    """
    instance = AccessVpcHostInterfaceModel(switch_ip="192.168.1.1", interface_name="vpc100")
    assert instance.identifiers == ["interface_name"]
    assert instance.identifier_strategy == "single"
    assert instance.get_identifier_value() == "vpc100"
    # switch_ip is for routing only; it must not appear in the diff dict so two peers' echoes diff-equal.
    assert "switchIp" not in instance.to_diff_dict()


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Vpc100", "vpc100"),
        ("VPC100", "vpc100"),
        ("vpc100", "vpc100"),
        ("vPC100", "vpc100"),
    ],
    ids=["title_case", "upper_case", "lower_case_passthrough", "mixed_case"],
)
def test_vpc_access_interface_00310_normalize_name(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` lowercases interface names.

    ## Test

    - Various casings are normalized to lowercase

    ## Classes and Methods

    - AccessVpcHostInterfaceModel.normalize_interface_name()
    """
    instance = AccessVpcHostInterfaceModel(switch_ip="192.168.1.1", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: AccessVpcHostInterfaceModel — round-trip
# =============================================================================


def test_vpc_access_interface_00400_round_trip_from_api():
    """
    # Summary

    Verify the model accepts the camelCase API response shape and exposes values via Python attributes.

    ## Test

    - Construct from SAMPLE_API_RESPONSE
    - Nested values accessible
    - peerSwitchId reads through

    ## Classes and Methods

    - AccessVpcHostInterfaceModel.__init__()
    """
    instance = AccessVpcHostInterfaceModel(**SAMPLE_API_RESPONSE)
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "vpc100"
    assert instance.interface_type == "vpc"
    policy = instance.config_data.network_os.policy
    assert policy.policy_type == "accessVpcHost"
    assert policy.peer_switch_id == "FDOPEER0001"
    assert policy.access_vlan == 10
    assert policy.peer1_member_ports == ["Ethernet1/1"]
    assert policy.peer2_member_ports == ["Ethernet1/2"]
    assert policy.admin_state is True


def test_vpc_access_interface_00410_round_trip_from_ansible():
    """
    # Summary

    Verify the model accepts the snake_case Ansible config shape.

    ## Test

    - Construct from SAMPLE_ANSIBLE_CONFIG
    - Nested values accessible

    ## Classes and Methods

    - AccessVpcHostInterfaceModel.__init__()
    """
    instance = AccessVpcHostInterfaceModel(**copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.switch_ip == "192.168.1.1"
    policy = instance.config_data.network_os.policy
    assert policy.peer1_port_channel_id == 100
    assert policy.peer2_port_channel_id == 100
    assert policy.access_vlan == 10
    assert policy.policy_type == "accessVpcHost"


def test_vpc_access_interface_00420_to_payload():
    """
    # Summary

    Verify `to_payload()` serializes the model back to camelCase, drops the `switch_ip` identifier, and splits the
    user-facing single `access_vlan` into the per-peer write keys (`peer1AccessVlan` + `peer2AccessVlan`) that ND's
    create schema requires.

    ## Test

    - to_payload() returns wire-shaped dict
    - switchIp is excluded (Ansible-facing only)
    - interfaceType is present
    - Nested policy aliases are camelCase
    - accessVlan is absent from the payload (split into per-peer keys)
    - peer1AccessVlan and peer2AccessVlan are both present with the same value

    ## Classes and Methods

    - AccessVpcHostInterfaceModel.to_payload()
    - AccessVpcHostPolicyModel.expand_per_peer_fields()
    """
    instance = AccessVpcHostInterfaceModel(**SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert "switchIp" not in payload
    assert payload["interfaceName"] == "vpc100"
    assert payload["interfaceType"] == "vpc"
    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == "accessVpcHost"
    assert policy["peer1MemberPorts"] == ["Ethernet1/1"]
    assert policy["peer2MemberPorts"] == ["Ethernet1/2"]
    assert policy["peer1PortChannelId"] == 100
    assert policy["peer2PortChannelId"] == 100
    # access_vlan split to both per-peer keys; the single-valued accessVlan key is removed on payload.
    assert "accessVlan" not in policy
    assert policy["peer1AccessVlan"] == 10
    assert policy["peer2AccessVlan"] == 10


def test_vpc_access_interface_00425_to_config_keeps_single_vlan():
    """
    # Summary

    Verify `to_config()` keeps `access_vlan` as a single field (does NOT expand to per-peer). The expansion only
    happens for payload mode; config / diff modes use the wire-echo (single) shape so idempotency works.

    ## Test

    - to_config() returns the snake_case field `access_vlan`
    - `peer1_access_vlan` and `peer2_access_vlan` are NOT in the config

    ## Classes and Methods

    - AccessVpcHostInterfaceModel.to_config()
    - AccessVpcHostPolicyModel.expand_per_peer_fields()
    """
    instance = AccessVpcHostInterfaceModel(**SAMPLE_API_RESPONSE)
    config = instance.to_config()
    policy = config["config_data"]["network_os"]["policy"]
    assert policy["access_vlan"] == 10
    assert "peer1_access_vlan" not in policy
    assert "peer2_access_vlan" not in policy


# =============================================================================
# Test: Argument spec exposure
# =============================================================================


def test_vpc_access_interface_00500_argument_spec_shape():
    """
    # Summary

    Verify the argument spec exposes the right shape: fabric_name, config list, state choices.

    ## Test

    - top-level keys: fabric_name, config, state
    - state choices contain merged/replaced/overridden/deleted
    - config has nested policy options including peer1_/peer2_ fields
    - Frozen scaffolding (interface_type, mode, network_os_type, policy_type) is NOT exposed
    - peer_switch_id (orchestrator-injected) is NOT exposed

    ## Classes and Methods

    - AccessVpcHostInterfaceModel.get_argument_spec()
    """
    spec = AccessVpcHostInterfaceModel.get_argument_spec()
    assert set(spec) == {"fabric_name", "config", "state"}
    assert spec["fabric_name"]["required"] is True
    assert set(spec["state"]["choices"]) == {"merged", "replaced", "overridden", "deleted"}

    config_options = spec["config"]["options"]
    assert "switch_ip" in config_options
    assert "interface_name" in config_options
    assert "config_data" in config_options

    policy_options = config_options["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    # Shared access VLAN (collapsed by ND on read; single field on the user side)
    assert "access_vlan" in policy_options
    # Per-peer presence
    assert "peer1_port_channel_id" in policy_options
    assert "peer1_member_ports" in policy_options
    assert "peer2_port_channel_id" in policy_options
    assert "peer2_member_ports" in policy_options
    # Shared field samples
    assert "admin_state" in policy_options
    assert "lacp_rate" in policy_options
    assert "port_channel_mode" in policy_options
    # Frozen/injected exclusions
    assert "interface_type" not in config_options
    assert "policy_type" not in policy_options
    assert "mode" not in policy_options
    assert "network_os_type" not in policy_options
    assert "peer_switch_id" not in policy_options
    # Per-peer access VLANs are explicitly NOT exposed (ND collapses to single accessVlan on read).
    assert "peer1_access_vlan" not in policy_options
    assert "peer2_access_vlan" not in policy_options


# =============================================================================
# Test: Nested-model sanity (Config / NetworkOS)
# =============================================================================


def test_vpc_access_interface_00600_nested_defaults():
    """
    # Summary

    Verify ConfigData and NetworkOS containers default their frozen discriminators.

    ## Test

    - AccessVpcHostConfigDataModel.mode defaults to "access"
    - AccessVpcHostNetworkOSModel.network_os_type defaults to "nx-os"

    ## Classes and Methods

    - AccessVpcHostConfigDataModel
    - AccessVpcHostNetworkOSModel
    """
    network_os = AccessVpcHostNetworkOSModel(policy=AccessVpcHostPolicyModel())
    config = AccessVpcHostConfigDataModel(network_os=network_os)
    assert config.mode == "access"
    assert config.network_os.network_os_type == "nx-os"
