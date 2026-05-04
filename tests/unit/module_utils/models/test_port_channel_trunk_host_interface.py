# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_trunk_host_interface.py

Tests the Port-channel trunkPoHost Interface Pydantic model classes.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    BpduFilterEnum,
    BpduGuardEnum,
    DuplexModeEnum,
    LacpRateEnum,
    LinkTypeEnum,
    MtuEnum,
    PortChannelModeEnum,
    SpeedEnum,
    StormControlActionEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostConfigDataModel,
    PortChannelTrunkHostInterfaceModel,
    PortChannelTrunkHostNetworkOSModel,
    PortChannelTrunkHostPolicyModel,
    PortChannelTrunkHostVlanMappingEntryModel,
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
    "interfaceName": "port-channel501",
    "interfaceType": "portChannel",
    "configData": {
        "mode": "trunk",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "adminState": True,
                "allowedVlans": "100-200,300",
                "nativeVlan": 99,
                "ports": ["Ethernet1/1", "Ethernet1/2"],
                "portChannelMode": "active",
                "lacpRate": "fast",
                "lacpPortPriority": 32768,
                "bpduGuard": "enable",
                "bpduFilter": "disable",
                "linkType": "auto",
                "description": "trunk to host",
                "policyType": "trunkPoHost",
                "speed": "10Gb",
                "duplexMode": "auto",
                "mtu": "jumbo",
                "copyDescription": True,
                "portTypeEdgeTrunk": True,
                "negotiateAuto": True,
                "vlanMapping": False,
            },
        },
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "port-channel501",
    "interface_type": "portChannel",
    "config_data": {
        "mode": "trunk",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "admin_state": True,
                "allowed_vlans": "100-200,300",
                "native_vlan": 99,
                "ports": ["Ethernet1/1", "Ethernet1/2"],
                "port_channel_mode": "active",
                "lacp_rate": "fast",
                "lacp_port_priority": 32768,
                "bpdu_guard": "enable",
                "bpdu_filter": "disable",
                "link_type": "auto",
                "description": "trunk to host",
                "policy_type": "trunkPoHost",
                "speed": "10Gb",
                "duplex_mode": "auto",
                "mtu": "jumbo",
                "copy_description": True,
                "port_type_edge_trunk": True,
                "negotiate_auto": True,
                "vlan_mapping": False,
            },
        },
    },
}


# =============================================================================
# Test: PortChannelTrunkHostPolicyModel — initialization
# =============================================================================


def test_port_channel_trunk_host_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None (except hardcoded `policy_type`).

    ## Test

    - Instantiate with no arguments
    - Every field is None except `policy_type` which is "trunkPoHost"

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel()
    assert instance.admin_state is None
    assert instance.allowed_vlans is None
    assert instance.bandwidth is None
    assert instance.bpdu_filter is None
    assert instance.bpdu_guard is None
    assert instance.cdp is None
    assert instance.copy_description is None
    assert instance.description is None
    assert instance.duplex_mode is None
    assert instance.extra_config is None
    assert instance.inherit_bandwidth is None
    assert instance.lacp_port_priority is None
    assert instance.lacp_rate is None
    assert instance.lacp_suspend is None
    assert instance.link_type is None
    assert instance.monitor is None
    assert instance.mtu is None
    assert instance.native_vlan is None
    assert instance.negotiate_auto is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None
    assert instance.netflow_sampler is None
    assert instance.orphan_port is None
    assert instance.pfc is None
    assert instance.policy_type == "trunkPoHost"
    assert instance.port_channel_id is None
    assert instance.port_channel_mode is None
    assert instance.port_type_edge_trunk is None
    assert instance.ports is None
    assert instance.ptp is None
    assert instance.qos is None
    assert instance.qos_policy is None
    assert instance.queuing_policy is None
    assert instance.speed is None
    assert instance.storm_control is None
    assert instance.storm_control_action is None
    assert instance.storm_control_broadcast_level is None
    assert instance.storm_control_broadcast_level_pps is None
    assert instance.storm_control_multicast_level is None
    assert instance.storm_control_multicast_level_pps is None
    assert instance.storm_control_unicast_level is None
    assert instance.storm_control_unicast_level_pps is None
    assert instance.vlan_mapping is None
    assert instance.vlan_mapping_entries is None


def test_port_channel_trunk_host_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(
            admin_state=True,
            allowed_vlans="100-200",
            native_vlan=99,
            ports=["Ethernet1/1"],
            port_channel_mode="active",
            lacp_rate="fast",
            description="test",
            speed="10Gb",
            link_type="auto",
        )
    assert instance.admin_state is True
    assert instance.allowed_vlans == "100-200"
    assert instance.native_vlan == 99
    assert instance.ports == ["Ethernet1/1"]
    assert instance.port_channel_mode == "active"
    assert instance.lacp_rate == "fast"
    assert instance.description == "test"
    # Hardcoded model default; user no longer supplies this field.
    assert instance.policy_type == "trunkPoHost"
    assert instance.speed == "10Gb"
    assert instance.link_type == "auto"


def test_port_channel_trunk_host_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(
            adminState=True,
            allowedVlans="all",
            nativeVlan=200,
            ports=["Ethernet1/3", "Ethernet1/4"],
            portChannelMode="passive",
            policyType="trunkPoHost",
            bpduGuard="enable",
            duplexMode="full",
            copyDescription=True,
            portTypeEdgeTrunk=True,
            negotiateAuto=False,
        )
    assert instance.admin_state is True
    assert instance.allowed_vlans == "all"
    assert instance.native_vlan == 200
    assert instance.ports == ["Ethernet1/3", "Ethernet1/4"]
    assert instance.port_channel_mode == "passive"
    assert instance.policy_type == "trunkPoHost"
    assert instance.bpdu_guard == "enable"
    assert instance.duplex_mode == "full"
    assert instance.copy_description is True
    assert instance.port_type_edge_trunk is True
    assert instance.negotiate_auto is False


# =============================================================================
# Test: PortChannelTrunkHostPolicyModel — validators
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        (["ethernet1/1", "ethernet1/2"], ["Ethernet1/1", "Ethernet1/2"]),
        (["Ethernet1/1"], ["Ethernet1/1"]),
        (["e1/1"], ["E1/1"]),
        ([], []),
        (None, None),
        # Mixed and breakout-style names preserve everything after the first character.
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
def test_port_channel_trunk_host_interface_00180(value, expected):
    """
    # Summary

    Verify `normalize_ports` capitalizes the first character of each member interface name.

    ## Test

    - Lowercase member names are capitalized
    - Already-capitalized values pass through
    - Empty list and None pass through

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.normalize_ports()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(ports=value)
    assert instance.ports == expected


def test_port_channel_trunk_host_interface_00190():
    """
    # Summary

    Verify `normalize_ports` passes a non-list, non-None value through to fail Pydantic type validation
    rather than coercing it. This keeps misconfigured input surfaced as a `ValidationError`.

    ## Test

    - A scalar string for `ports` raises ValidationError

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.normalize_ports()
    """
    with pytest.raises(ValidationError):
        PortChannelTrunkHostPolicyModel(ports="Ethernet1/1")


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("none", False),
        ("all", False),
        ("100", False),
        ("100-200", False),
        ("1-200,500-2000,3000", False),
        ("1,2,3,4-10", False),
        ("", False),
        (None, False),
        ("abc", True),
        ("1-", True),
        ("100-200,", True),
        ("None", True),  # case-sensitive
        ("ALL", True),
    ],
    ids=[
        "none_keyword",
        "all_keyword",
        "single_id",
        "single_range",
        "multiple_ranges",
        "mixed_ids_ranges",
        "empty_passthrough",
        "none_passthrough",
        "non_numeric_rejected",
        "trailing_dash_rejected",
        "trailing_comma_rejected",
        "case_none_rejected",
        "case_all_rejected",
    ],
)
def test_port_channel_trunk_host_interface_00200(value, should_raise):
    """
    # Summary

    Verify `allowed_vlans` regex validator accepts `none`, `all`, or comma-separated VLAN ids/ranges and
    rejects malformed input.

    ## Test

    - Valid forms are accepted
    - Invalid strings raise ValidationError

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.validate_allowed_vlans()
    """
    if should_raise:
        with pytest.raises(ValidationError, match=r"allowed_vlans"):
            PortChannelTrunkHostPolicyModel(allowed_vlans=value)
    else:
        with does_not_raise():
            instance = PortChannelTrunkHostPolicyModel(allowed_vlans=value)
        assert instance.allowed_vlans == value


@pytest.mark.parametrize(
    "value,expected",
    [
        (250, "250"),
        (1, "1"),
        (4094, "4094"),
    ],
    ids=["single_vlan_int", "min_vlan_int", "max_vlan_int"],
)
def test_port_channel_trunk_host_interface_00205(value, expected):
    """
    # Summary

    Verify `allowed_vlans` coerces JSON int responses to str. ND returns single-id values as JSON ints
    (e.g. `250` instead of `"250"`) when the field is set to a single VLAN with no commas/dashes. The model
    normalizes to str so round-trips and idempotency comparisons stay stable.

    ## Test

    - JSON int 250 is coerced to "250"

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.validate_allowed_vlans()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(allowed_vlans=value)
    assert instance.allowed_vlans == expected
    assert isinstance(instance.allowed_vlans, str)


# =============================================================================
# Test: PortChannelTrunkHostPolicyModel — range and enum validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("native_vlan", 1, False),
        ("native_vlan", 4094, False),
        ("native_vlan", 0, True),
        ("native_vlan", 4095, True),
        ("bandwidth", 1, False),
        ("bandwidth", 100000000, False),
        ("bandwidth", 0, True),
        ("bandwidth", 100000001, True),
        ("inherit_bandwidth", 1, False),
        ("inherit_bandwidth", 100000000, False),
        ("inherit_bandwidth", 0, True),
        ("inherit_bandwidth", 100000001, True),
        ("lacp_port_priority", 1, False),
        ("lacp_port_priority", 65535, False),
        ("lacp_port_priority", 0, True),
        ("lacp_port_priority", 65536, True),
        ("storm_control_broadcast_level_pps", 0, False),
        ("storm_control_broadcast_level_pps", 200000000, False),
        ("storm_control_broadcast_level_pps", -1, True),
        ("storm_control_broadcast_level_pps", 200000001, True),
        ("storm_control_multicast_level_pps", 0, False),
        ("storm_control_multicast_level_pps", 200000000, False),
        ("storm_control_multicast_level_pps", -1, True),
        ("storm_control_multicast_level_pps", 200000001, True),
        ("storm_control_unicast_level_pps", 0, False),
        ("storm_control_unicast_level_pps", 200000000, False),
        ("storm_control_unicast_level_pps", -1, True),
        ("storm_control_unicast_level_pps", 200000001, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_port_channel_trunk_host_interface_00220(field, value, should_raise):
    """
    # Summary

    Verify ge/le constraints on every numeric policy field.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected with ValidationError

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelTrunkHostPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = PortChannelTrunkHostPolicyModel(**{field: value})
        assert getattr(instance, field) == value


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("storm_control_broadcast_level", 0.0, False),
        ("storm_control_broadcast_level", 100.0, False),
        ("storm_control_broadcast_level", -0.1, True),
        ("storm_control_broadcast_level", 100.01, True),
        ("storm_control_multicast_level", 0.0, False),
        ("storm_control_multicast_level", 100.0, False),
        ("storm_control_multicast_level", -0.1, True),
        ("storm_control_multicast_level", 100.01, True),
        ("storm_control_unicast_level", 0.0, False),
        ("storm_control_unicast_level", 100.0, False),
        ("storm_control_unicast_level", -0.1, True),
        ("storm_control_unicast_level", 100.01, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_port_channel_trunk_host_interface_00225(field, value, should_raise):
    """
    # Summary

    Verify storm-control percentage fields enforce the 0.0-100.0 range.

    ## Test

    - 0.0 and 100.0 accepted
    - -0.1 and 100.01 rejected

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelTrunkHostPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = PortChannelTrunkHostPolicyModel(**{field: value})
        assert getattr(instance, field) == value


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("storm_control_broadcast_level", "50.5", 50.5),
        ("storm_control_multicast_level", "75.25", 75.25),
        ("storm_control_unicast_level", "0.0", 0.0),
    ],
    ids=["broadcast_str_to_float", "multicast_str_to_float", "unicast_str_to_float"],
)
def test_port_channel_trunk_host_interface_00227(field, value, expected):
    """
    # Summary

    Verify Pydantic coerces JSON-string storm-control levels to float. ND returns these fields as quoted
    strings on the wire even though they are typed as `float | None` in the model.

    ## Test

    - String "50.5" parses to float 50.5

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(**{field: value})
    assert getattr(instance, field) == expected
    assert isinstance(getattr(instance, field), float)


def test_port_channel_trunk_host_interface_00230():
    """
    # Summary

    Verify `description` max_length=254.

    ## Test

    - 254-char description accepted
    - 255-char description rejected with ValidationError

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    at_limit = "a" * 254
    over_limit = "a" * 255
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(description=at_limit)
    assert instance.description == at_limit

    with pytest.raises(ValidationError):
        PortChannelTrunkHostPolicyModel(description=over_limit)


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("plain ASCII", False),
        ("with-hyphen and 123", False),
        ("em — dash", True),
        ("smart “quotes”", True),
        ("emoji \U0001f600", True),
        ("latin-1 \xe9", True),
    ],
    ids=[
        "ascii_ok",
        "ascii_punct_digits",
        "em_dash_rejected",
        "smart_quotes_rejected",
        "emoji_rejected",
        "latin1_rejected",
    ],
)
def test_port_channel_trunk_host_interface_00235(value, should_raise):
    """
    # Summary

    Verify `description` (typed `AsciiDescription`) rejects any non-ASCII character.

    Cisco backend pipes interface descriptions through CLI generators that 500 on UTF-8. Catching this client-side
    gives users a clear error instead of a generic "unexpected error during policy execution" 500.

    ## Test

    - ASCII strings accepted
    - Non-ASCII characters (em-dash, smart quotes, emoji, latin-1) raise

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    - models.types.ascii_only()
    """
    if should_raise:
        with pytest.raises(ValidationError, match="description must contain only ASCII"):
            PortChannelTrunkHostPolicyModel(description=value)
    else:
        instance = PortChannelTrunkHostPolicyModel(description=value)
        assert instance.description == value


@pytest.mark.parametrize(
    "field,enum_cls",
    [
        ("speed", SpeedEnum),
        ("duplex_mode", DuplexModeEnum),
        ("bpdu_guard", BpduGuardEnum),
        ("bpdu_filter", BpduFilterEnum),
        ("mtu", MtuEnum),
        ("storm_control_action", StormControlActionEnum),
        ("port_channel_mode", PortChannelModeEnum),
        ("lacp_rate", LacpRateEnum),
        ("link_type", LinkTypeEnum),
    ],
    ids=["speed", "duplex_mode", "bpdu_guard", "bpdu_filter", "mtu", "storm_control_action", "port_channel_mode", "lacp_rate", "link_type"],
)
def test_port_channel_trunk_host_interface_00240(field, enum_cls):
    """
    # Summary

    Verify enum-constrained fields accept any valid enum value and reject invalid strings.

    ## Test

    - Valid enum value sets the stored value
    - Invalid value raises ValidationError

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    valid_value = next(iter(enum_cls)).value
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(**{field: valid_value})
    assert getattr(instance, field) == valid_value

    with pytest.raises(ValidationError):
        PortChannelTrunkHostPolicyModel(**{field: "not_a_real_value"})


# =============================================================================
# Test: PortChannelTrunkHostVlanMappingEntryModel
# =============================================================================


def test_port_channel_trunk_host_interface_00300():
    """
    # Summary

    Verify VLAN mapping entry construction with all fields.

    ## Test

    - All fields accessible
    - camelCase aliases populate snake_case fields

    ## Classes and Methods

    - PortChannelTrunkHostVlanMappingEntryModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostVlanMappingEntryModel(
            customer_inner_vlan_id=10,
            customer_vlan_id=["100", "200"],
            dot1q_tunnel=True,
            provider_vlan_id=1000,
        )
    assert instance.customer_inner_vlan_id == 10
    assert instance.customer_vlan_id == ["100", "200"]
    assert instance.dot1q_tunnel is True
    assert instance.provider_vlan_id == 1000


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("customer_inner_vlan_id", 1, False),
        ("customer_inner_vlan_id", 4094, False),
        ("customer_inner_vlan_id", 0, True),
        ("customer_inner_vlan_id", 4095, True),
        ("provider_vlan_id", 1, False),
        ("provider_vlan_id", 4094, False),
        ("provider_vlan_id", 0, True),
        ("provider_vlan_id", 4095, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_port_channel_trunk_host_interface_00310(field, value, should_raise):
    """
    # Summary

    Verify VLAN mapping entry id range constraints.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected

    ## Classes and Methods

    - PortChannelTrunkHostVlanMappingEntryModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelTrunkHostVlanMappingEntryModel(**{field: value})
    else:
        with does_not_raise():
            instance = PortChannelTrunkHostVlanMappingEntryModel(**{field: value})
        assert getattr(instance, field) == value


def test_port_channel_trunk_host_interface_00320():
    """
    # Summary

    Verify policy accepts a list of VLAN mapping entries via dict input.

    ## Test

    - vlan_mapping_entries accepts a list of dicts
    - Each dict is coerced to PortChannelTrunkHostVlanMappingEntryModel

    ## Classes and Methods

    - PortChannelTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostPolicyModel(
            vlan_mapping=True,
            vlan_mapping_entries=[
                {"customer_vlan_id": ["100"], "provider_vlan_id": 200, "dot1q_tunnel": True},
                {"customer_vlan_id": ["300"], "provider_vlan_id": 400},
            ],
        )
    assert instance.vlan_mapping is True
    assert len(instance.vlan_mapping_entries) == 2
    assert isinstance(instance.vlan_mapping_entries[0], PortChannelTrunkHostVlanMappingEntryModel)
    assert instance.vlan_mapping_entries[0].provider_vlan_id == 200
    assert instance.vlan_mapping_entries[0].dot1q_tunnel is True
    assert instance.vlan_mapping_entries[1].dot1q_tunnel is None


# =============================================================================
# Test: PortChannelTrunkHostNetworkOSModel
# =============================================================================


def test_port_channel_trunk_host_interface_00400():
    """
    # Summary

    Verify `network_os_type` defaults to "nx-os".

    ## Test

    - Instantiate without args
    - network_os_type is "nx-os"
    - policy is None

    ## Classes and Methods

    - PortChannelTrunkHostNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert instance.policy is None


def test_port_channel_trunk_host_interface_00410():
    """
    # Summary

    Verify nested `policy` assignment accepts a dict and coerces to PortChannelTrunkHostPolicyModel.

    ## Test

    - Construct with policy as dict
    - policy is a PortChannelTrunkHostPolicyModel instance

    ## Classes and Methods

    - PortChannelTrunkHostNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostNetworkOSModel(policy={"admin_state": True, "allowed_vlans": "100-200"})
    assert isinstance(instance.policy, PortChannelTrunkHostPolicyModel)
    assert instance.policy.admin_state is True
    assert instance.policy.allowed_vlans == "100-200"


def test_port_channel_trunk_host_interface_00420():
    """
    # Summary

    Verify camelCase alias `networkOSType` populates network_os_type.

    ## Test

    - Construct with camelCase alias
    - Python field accessible

    ## Classes and Methods

    - PortChannelTrunkHostNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostNetworkOSModel(networkOSType="ios-xe")
    assert instance.network_os_type == "ios-xe"


# =============================================================================
# Test: PortChannelTrunkHostConfigDataModel
# =============================================================================


def test_port_channel_trunk_host_interface_00450():
    """
    # Summary

    Verify `mode` defaults to "trunk".

    ## Test

    - Construct with only network_os
    - mode is "trunk"

    ## Classes and Methods

    - PortChannelTrunkHostConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostConfigDataModel(network_os=PortChannelTrunkHostNetworkOSModel())
    assert instance.mode == "trunk"


def test_port_channel_trunk_host_interface_00460():
    """
    # Summary

    Verify camelCase alias `networkOS` populates network_os.

    ## Test

    - Construct with camelCase alias
    - Python field accessible

    ## Classes and Methods

    - PortChannelTrunkHostConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostConfigDataModel(networkOS={"networkOSType": "nx-os"})
    assert isinstance(instance.network_os, PortChannelTrunkHostNetworkOSModel)
    assert instance.network_os.network_os_type == "nx-os"


def test_port_channel_trunk_host_interface_00470():
    """
    # Summary

    Verify `network_os` is a required field.

    ## Test

    - Construct without network_os
    - ValidationError raised

    ## Classes and Methods

    - PortChannelTrunkHostConfigDataModel.__init__()
    """
    with pytest.raises(ValidationError, match=r"network_os|networkOS"):
        PortChannelTrunkHostConfigDataModel()


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — initialization and ClassVars
# =============================================================================


def test_port_channel_trunk_host_interface_00500():
    """
    # Summary

    Verify ClassVar `identifiers` and `identifier_strategy`.

    ## Test

    - identifiers == ["switch_ip", "interface_name"]
    - identifier_strategy == "composite"

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel
    """
    assert PortChannelTrunkHostInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    assert PortChannelTrunkHostInterfaceModel.identifier_strategy == "composite"


def test_port_channel_trunk_host_interface_00510():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip`.

    ## Test

    - payload_exclude_fields == {"switch_ip"}

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel
    """
    assert PortChannelTrunkHostInterfaceModel.payload_exclude_fields == {"switch_ip"}


def test_port_channel_trunk_host_interface_00520():
    """
    # Summary

    Verify `switch_ip` and `interface_name` are required.

    ## Test

    - Missing switch_ip raises ValidationError
    - Missing interface_name raises ValidationError

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.__init__()
    """
    with pytest.raises(ValidationError, match=r"switch_ip|switchIp"):
        PortChannelTrunkHostInterfaceModel(interface_name="port-channel501")

    with pytest.raises(ValidationError, match=r"interface_name|interfaceName"):
        PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1")


def test_port_channel_trunk_host_interface_00530():
    """
    # Summary

    Verify `interface_type` defaults to "portChannel" and `config_data` defaults to None.

    ## Test

    - Minimal construction
    - Defaults applied

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "port-channel501"
    assert instance.interface_type == "portChannel"
    assert instance.config_data is None


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — normalize_interface_name
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("port-channel501", "port-channel501"),
        ("Port-Channel501", "port-channel501"),
        ("PORT-CHANNEL501", "port-channel501"),
        ("Port-channel1", "port-channel1"),
        ("", ""),
    ],
    ids=["already_lower", "title_case", "upper", "mixed_case", "empty_passthrough"],
)
def test_port_channel_trunk_host_interface_00550(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` lowercases the entire interface name (port-channel convention).

    ## Test

    - Mixed-case inputs normalized to lowercase
    - Already-lowercase input unchanged

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.normalize_interface_name()
    """
    instance = PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — to_payload
# =============================================================================


def test_port_channel_trunk_host_interface_00600():
    """
    # Summary

    Verify `to_payload` emits camelCase keys and excludes `switch_ip`.

    ## Test

    - Top-level keys are camelCase
    - switchIp / switch_ip not present

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_payload()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert "interfaceName" in result
    assert "interfaceType" in result
    assert "configData" in result
    assert "switchIp" not in result
    assert "switch_ip" not in result


def test_port_channel_trunk_host_interface_00610():
    """
    # Summary

    Verify deeply nested structure preserves camelCase aliases throughout.

    ## Test

    - configData.networkOS.policy has camelCase keys

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_payload()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    policy = result["configData"]["networkOS"]["policy"]
    assert "adminState" in policy
    assert "allowedVlans" in policy
    assert "nativeVlan" in policy
    assert "ports" in policy
    assert "portChannelMode" in policy
    assert "lacpRate" in policy
    assert "lacpPortPriority" in policy
    assert "policyType" in policy
    assert "bpduGuard" in policy
    assert "copyDescription" in policy
    assert "linkType" in policy
    assert "portTypeEdgeTrunk" in policy
    assert "negotiateAuto" in policy


def test_port_channel_trunk_host_interface_00620():
    """
    # Summary

    Verify `policyType` is the API camelCase value in payload mode.

    ## Test

    - Hardcoded model default for `policy_type` serializes as `"trunkPoHost"` under the `policyType` alias.

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_payload()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "trunkPoHost"


def test_port_channel_trunk_host_interface_00630():
    """
    # Summary

    Verify member ports list survives serialization with normalized names.

    ## Test

    - ports list survives in payload as a list of capitalized member names

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_payload()
    - PortChannelTrunkHostPolicyModel.normalize_ports()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["config_data"]["network_os"]["policy"]["ports"] = ["ethernet1/5", "ethernet1/6"]
    instance = PortChannelTrunkHostInterfaceModel.from_config(config)
    result = instance.to_payload()
    assert result["configData"]["networkOS"]["policy"]["ports"] == ["Ethernet1/5", "Ethernet1/6"]


def test_port_channel_trunk_host_interface_00640():
    """
    # Summary

    Verify None-valued fields are excluded from payload output.

    ## Test

    - Minimal model with config_data=None
    - configData not present in payload

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_payload()
    """
    instance = PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    result = instance.to_payload()
    assert "configData" not in result
    assert "interfaceName" in result


def test_port_channel_trunk_host_interface_00650():
    """
    # Summary

    Verify VLAN mapping entries survive serialization.

    ## Test

    - vlan_mapping_entries is preserved in payload as a list of camelCase dicts

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_payload()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["config_data"]["network_os"]["policy"]["vlan_mapping"] = True
    config["config_data"]["network_os"]["policy"]["vlan_mapping_entries"] = [
        {"customer_vlan_id": ["100"], "provider_vlan_id": 200, "dot1q_tunnel": True},
    ]
    instance = PortChannelTrunkHostInterfaceModel.from_config(config)
    result = instance.to_payload()
    entries = result["configData"]["networkOS"]["policy"]["vlanMappingEntries"]
    assert len(entries) == 1
    assert entries[0]["customerVlanId"] == ["100"]
    assert entries[0]["providerVlanId"] == 200
    assert entries[0]["dot1qTunnel"] is True


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — to_config
# =============================================================================


def test_port_channel_trunk_host_interface_00700():
    """
    # Summary

    Verify `to_config` emits snake_case keys throughout.

    ## Test

    - Top-level keys are snake_case
    - Nested keys are snake_case

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_config()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert "interface_name" in result
    assert "interface_type" in result
    assert "config_data" in result
    policy = result["config_data"]["network_os"]["policy"]
    assert "admin_state" in policy
    assert "allowed_vlans" in policy
    assert "native_vlan" in policy
    assert "ports" in policy
    assert "port_channel_mode" in policy
    assert "lacp_rate" in policy
    assert "copy_description" in policy
    assert "link_type" in policy


def test_port_channel_trunk_host_interface_00710():
    """
    # Summary

    Verify `policy_type` round-trips as the API value in config output.

    ## Test

    - Stored "trunkPoHost" -> output "trunkPoHost" (no Ansible<->API translation; field is hardcoded by the model)

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_config()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    result = instance.to_config()
    assert result["config_data"]["network_os"]["policy"]["policy_type"] == "trunkPoHost"


def test_port_channel_trunk_host_interface_00720():
    """
    # Summary

    Verify `switch_ip` is included in config output (differs from payload).

    ## Test

    - switch_ip present at top level of config

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.to_config()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert result["switch_ip"] == "192.168.1.1"


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — from_response
# =============================================================================


def test_port_channel_trunk_host_interface_00800():
    """
    # Summary

    Verify `from_response` constructs a model from the ND API response.

    ## Test

    - All fields accessible by Python names
    - Nested structure populated

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "port-channel501"
    assert instance.interface_type == "portChannel"
    assert instance.config_data.mode == "trunk"
    assert instance.config_data.network_os.policy.admin_state is True
    assert instance.config_data.network_os.policy.allowed_vlans == "100-200,300"
    assert instance.config_data.network_os.policy.native_vlan == 99
    assert instance.config_data.network_os.policy.ports == ["Ethernet1/1", "Ethernet1/2"]
    assert instance.config_data.network_os.policy.port_channel_mode == "active"
    assert instance.config_data.network_os.policy.policy_type == "trunkPoHost"


def test_port_channel_trunk_host_interface_00810():
    """
    # Summary

    Verify `from_response` re-serialized via `to_payload` yields an equivalent dict (minus switchIp).

    ## Test

    - API response -> model -> payload matches original (except switchIp which is excluded)

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_response()
    - PortChannelTrunkHostInterfaceModel.to_payload()
    """
    original = copy.deepcopy(SAMPLE_API_RESPONSE)
    instance = PortChannelTrunkHostInterfaceModel.from_response(original)
    result = instance.to_payload()
    expected = {k: v for k, v in original.items() if k != "switchIp"}
    assert result == expected


def test_port_channel_trunk_host_interface_00820():
    """
    # Summary

    Verify `from_response` tolerates missing `configData`.

    ## Test

    - Response with only switchIp + interfaceName constructs valid model
    - config_data is None

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel.from_response({"switchIp": "192.168.1.1", "interfaceName": "port-channel501"})
    assert instance.config_data is None


def test_port_channel_trunk_host_interface_00830():
    """
    # Summary

    Verify `from_response` ignores unknown top-level and nested keys (extra="ignore").

    ## Test

    - Response with extra keys constructs valid model

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["unknownField"] = "ignored"
    response["configData"]["somethingExtra"] = "also_ignored"
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel.from_response(response)
    assert instance.interface_name == "port-channel501"


def test_port_channel_trunk_host_interface_00840():
    """
    # Summary

    Verify `from_response` accepts the wire-format response shape with `portChannelId` and `ptp` fields that
    ND auto-fills. These fields are present in actual API responses but not always in the OpenAPI spec.

    ## Test

    - Response with portChannelId and ptp fields constructs valid model
    - portChannelId stored as response-only echo of interface_name

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["portChannelId"] = "port-channel501"
    response["configData"]["networkOS"]["policy"]["ptp"] = False
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel.from_response(response)
    assert instance.config_data.network_os.policy.port_channel_id == "port-channel501"
    assert instance.config_data.network_os.policy.ptp is False


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — from_config
# =============================================================================


def test_port_channel_trunk_host_interface_00900():
    """
    # Summary

    Verify `from_config` constructs a model from an Ansible snake_case config.

    ## Test

    - All fields accessible

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "port-channel501"
    assert instance.config_data.network_os.policy.allowed_vlans == "100-200,300"
    assert instance.config_data.network_os.policy.native_vlan == 99
    assert instance.config_data.network_os.policy.description == "trunk to host"
    assert instance.config_data.network_os.policy.ports == ["Ethernet1/1", "Ethernet1/2"]


def test_port_channel_trunk_host_interface_00910():
    """
    # Summary

    Verify model hardcodes the `trunkPoHost` policy type regardless of input.

    ## Test

    - After from_config (no policy_type in input), stored policy_type is the API value "trunkPoHost"

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_config()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.config_data.network_os.policy.policy_type == "trunkPoHost"


def test_port_channel_trunk_host_interface_00920():
    """
    # Summary

    Verify `from_config` -> `to_config` round-trip preserves original data.

    ## Test

    - Input config equals to_config() output

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_config()
    - PortChannelTrunkHostInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = PortChannelTrunkHostInterfaceModel.from_config(original)
    result = instance.to_config()
    assert result == original


def test_port_channel_trunk_host_interface_00930():
    """
    # Summary

    Verify `from_config` accepts a minimal config with just identifiers.

    ## Test

    - Construct with switch_ip + interface_name only
    - config_data is None

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = PortChannelTrunkHostInterfaceModel.from_config({"switch_ip": "192.168.1.1", "interface_name": "port-channel501"})
    assert instance.switch_ip == "192.168.1.1"
    assert instance.config_data is None


def test_port_channel_trunk_host_interface_00940():
    """
    # Summary

    Verify full round-trip through all serialization methods.

    ## Test

    - config -> from_config -> to_payload -> from_response (with switchIp injected) -> to_config
      matches original config

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.from_config()
    - PortChannelTrunkHostInterfaceModel.to_payload()
    - PortChannelTrunkHostInterfaceModel.from_response()
    - PortChannelTrunkHostInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = PortChannelTrunkHostInterfaceModel.from_config(original)
    payload = instance.to_payload()
    payload["switchIp"] = original["switch_ip"]
    instance2 = PortChannelTrunkHostInterfaceModel.from_response(payload)
    result = instance2.to_config()
    assert result == original


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — identifier, diff, merge
# =============================================================================


def test_port_channel_trunk_host_interface_01000():
    """
    # Summary

    Verify `get_identifier_value` returns the composite `(switch_ip, interface_name)` tuple.

    ## Test

    - Composite tuple returned

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_identifier_value()
    """
    instance = PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    assert instance.get_identifier_value() == ("192.168.1.1", "port-channel501")


def test_port_channel_trunk_host_interface_01010():
    """
    # Summary

    Verify `get_diff` returns True when two models are identical.

    ## Test

    - Two identical models
    - get_diff returns True

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_diff()
    """
    instance1 = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    instance2 = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance1.get_diff(instance2) is True


def test_port_channel_trunk_host_interface_01020():
    """
    # Summary

    Verify `get_diff` returns False when a nested field differs.

    ## Test

    - Allowed VLANs differ between two models
    - get_diff returns False

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_diff()
    """
    config1 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2["config_data"]["network_os"]["policy"]["allowed_vlans"] = "999"
    instance1 = PortChannelTrunkHostInterfaceModel.from_config(config1)
    instance2 = PortChannelTrunkHostInterfaceModel.from_config(config2)
    assert instance1.get_diff(instance2) is False


def test_port_channel_trunk_host_interface_01030():
    """
    # Summary

    Verify `merge` applies non-None values from `other` into `self`.

    ## Test

    - Other sets a field self did not have
    - After merge, self has the field

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.merge()
    """
    base = {
        "switch_ip": "192.168.1.1",
        "interface_name": "port-channel501",
        "config_data": {
            "network_os": {
                "policy": {"admin_state": True},
            },
        },
    }
    other = {
        "switch_ip": "192.168.1.1",
        "interface_name": "port-channel501",
        "config_data": {
            "network_os": {
                "policy": {"allowed_vlans": "100-200"},
            },
        },
    }
    instance = PortChannelTrunkHostInterfaceModel.from_config(base)
    instance.merge(PortChannelTrunkHostInterfaceModel.from_config(other))
    assert instance.config_data.network_os.policy.admin_state is True
    assert instance.config_data.network_os.policy.allowed_vlans == "100-200"


def test_port_channel_trunk_host_interface_01040():
    """
    # Summary

    Verify `merge` preserves existing values when `other` has unset fields (model_fields_set semantics).

    ## Test

    - Self has a value, other does not mention that field
    - After merge, self still has the original value

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.merge()
    """
    instance = PortChannelTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    other = PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    instance.merge(other)
    assert instance.config_data.network_os.policy.allowed_vlans == "100-200,300"


def test_port_channel_trunk_host_interface_01050():
    """
    # Summary

    Verify `merge` raises TypeError when given a model of the wrong type.

    ## Test

    - Passing a policy model to the interface model merge raises TypeError

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.merge()
    """
    instance = PortChannelTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    with pytest.raises(TypeError, match=r"Cannot merge"):
        instance.merge(PortChannelTrunkHostPolicyModel())


# =============================================================================
# Test: PortChannelTrunkHostInterfaceModel — get_argument_spec
# =============================================================================


def test_port_channel_trunk_host_interface_01100():
    """
    # Summary

    Verify top-level structural layout of the Ansible argument spec.

    ## Test

    - fabric_name, config, state keys present
    - switch_ip is under config.options, not top-level
    - config.type == "list", elements == "dict"
    - state choices and default
    - policy_type is not exposed in the argspec (hardcoded by the model)

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = PortChannelTrunkHostInterfaceModel.get_argument_spec()
    assert "fabric_name" in spec
    assert "config" in spec
    assert "state" in spec
    assert "switch_ip" not in spec
    assert "switch_ip" in spec["config"]["options"]
    assert spec["config"]["type"] == "list"
    assert spec["config"]["elements"] == "dict"
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert spec["state"]["default"] == "merged"
    policy_spec = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    assert "policy_type" not in policy_spec


def test_port_channel_trunk_host_interface_01110():
    """
    # Summary

    Verify `interface_type` default is "portChannel" in the argument spec.

    ## Test

    - config.options.interface_type.default == "portChannel"

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = PortChannelTrunkHostInterfaceModel.get_argument_spec()
    assert spec["config"]["options"]["interface_type"]["default"] == "portChannel"


def test_port_channel_trunk_host_interface_01115():
    """
    # Summary

    Verify the `mode` default in the argument spec is "trunk" (distinct from access PC).

    ## Test

    - config.options.config_data.options.mode.default == "trunk"

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = PortChannelTrunkHostInterfaceModel.get_argument_spec()
    assert spec["config"]["options"]["config_data"]["options"]["mode"]["default"] == "trunk"


@pytest.mark.parametrize(
    "field,enum_cls",
    [
        ("bpdu_filter", BpduFilterEnum),
        ("bpdu_guard", BpduGuardEnum),
        ("duplex_mode", DuplexModeEnum),
        ("lacp_rate", LacpRateEnum),
        ("link_type", LinkTypeEnum),
        ("mtu", MtuEnum),
        ("port_channel_mode", PortChannelModeEnum),
        ("speed", SpeedEnum),
        ("storm_control_action", StormControlActionEnum),
    ],
    ids=[
        "bpdu_filter",
        "bpdu_guard",
        "duplex_mode",
        "lacp_rate",
        "link_type",
        "mtu",
        "port_channel_mode",
        "speed",
        "storm_control_action",
    ],
)
def test_port_channel_trunk_host_interface_01120(field, enum_cls):
    """
    # Summary

    Verify enum-constrained policy fields expose correct `choices` in the argument spec.

    ## Test

    - Each enum field's choices list exactly matches the enum values

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = PortChannelTrunkHostInterfaceModel.get_argument_spec()
    policy_spec = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    expected = [e.value for e in enum_cls]
    assert policy_spec[field]["choices"] == expected


def test_port_channel_trunk_host_interface_01130():
    """
    # Summary

    Verify `vlan_mapping_entries` in argspec is a list of dicts with the expected suboptions.

    ## Test

    - vlan_mapping_entries.type == "list"
    - vlan_mapping_entries.elements == "dict"
    - All four entry suboptions present

    ## Classes and Methods

    - PortChannelTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = PortChannelTrunkHostInterfaceModel.get_argument_spec()
    policy_spec = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    entries_spec = policy_spec["vlan_mapping_entries"]
    assert entries_spec["type"] == "list"
    assert entries_spec["elements"] == "dict"
    assert "customer_inner_vlan_id" in entries_spec["options"]
    assert "customer_vlan_id" in entries_spec["options"]
    assert "dot1q_tunnel" in entries_spec["options"]
    assert "provider_vlan_id" in entries_spec["options"]
