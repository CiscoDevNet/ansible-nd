# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ethernet_trunk_host_interface.py

Tests the Ethernet trunkHost Interface Pydantic model classes.
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
    FecEnum,
    LinkTypeEnum,
    MtuEnum,
    SpeedEnum,
    StormControlActionEnum,
    TrunkHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_trunk_host_interface import (
    EthernetTrunkHostConfigDataModel,
    EthernetTrunkHostInterfaceModel,
    EthernetTrunkHostNetworkOSModel,
    EthernetTrunkHostPolicyModel,
    EthernetTrunkHostVlanMappingEntryModel,
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
    "interfaceName": "Ethernet1/1",
    "interfaceType": "ethernet",
    "configData": {
        "mode": "trunk",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "adminState": True,
                "allowedVlans": "1-100",
                "nativeVlan": 10,
                "description": "uplink to spine",
                "policyType": "trunkHost",
                "speed": "10Gb",
                "duplexMode": "auto",
                "mtu": "jumbo",
                "bpduGuard": "enable",
                "bpduFilter": "disable",
                "vlanMapping": True,
                "vlanMappingEntries": [
                    {
                        "customerInnerVlanId": 100,
                        "customerVlanId": ["10", "20-30"],
                        "dot1qTunnel": True,
                        "providerVlanId": 200,
                    },
                ],
            },
        },
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "Ethernet1/1",
    "interface_type": "ethernet",
    "config_data": {
        "mode": "trunk",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "admin_state": True,
                "allowed_vlans": "1-100",
                "native_vlan": 10,
                "description": "uplink to spine",
                "policy_type": "trunk_host",
                "speed": "10Gb",
                "duplex_mode": "auto",
                "mtu": "jumbo",
                "bpdu_guard": "enable",
                "bpdu_filter": "disable",
                "vlan_mapping": True,
                "vlan_mapping_entries": [
                    {
                        "customer_inner_vlan_id": 100,
                        "customer_vlan_id": ["10", "20-30"],
                        "dot1q_tunnel": True,
                        "provider_vlan_id": 200,
                    },
                ],
            },
        },
    },
}


# =============================================================================
# Test: EthernetTrunkHostVlanMappingEntryModel
# =============================================================================


def test_ethernet_trunk_host_interface_00010():
    """
    # Summary

    Verify all VLAN mapping entry fields default to None.

    ## Test

    - Instantiate with no arguments
    - All fields are None

    ## Classes and Methods

    - EthernetTrunkHostVlanMappingEntryModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostVlanMappingEntryModel()
    assert instance.customer_inner_vlan_id is None
    assert instance.customer_vlan_id is None
    assert instance.dot1q_tunnel is None
    assert instance.provider_vlan_id is None


def test_ethernet_trunk_host_interface_00020():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - All values accessible

    ## Classes and Methods

    - EthernetTrunkHostVlanMappingEntryModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostVlanMappingEntryModel(
            customer_inner_vlan_id=100,
            customer_vlan_id=["10", "20-30"],
            dot1q_tunnel=True,
            provider_vlan_id=200,
        )
    assert instance.customer_inner_vlan_id == 100
    assert instance.customer_vlan_id == ["10", "20-30"]
    assert instance.dot1q_tunnel is True
    assert instance.provider_vlan_id == 200


def test_ethernet_trunk_host_interface_00030():
    """
    # Summary

    Verify construction with camelCase aliases (populate_by_name=True).

    ## Test

    - Construct with API alias names
    - All values accessible by Python names

    ## Classes and Methods

    - EthernetTrunkHostVlanMappingEntryModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostVlanMappingEntryModel(
            customerInnerVlanId=100,
            customerVlanId=["10"],
            dot1qTunnel=False,
            providerVlanId=200,
        )
    assert instance.customer_inner_vlan_id == 100
    assert instance.customer_vlan_id == ["10"]
    assert instance.dot1q_tunnel is False
    assert instance.provider_vlan_id == 200


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
    ids=[
        "cust_inner_min",
        "cust_inner_max",
        "cust_inner_below",
        "cust_inner_above",
        "prov_min",
        "prov_max",
        "prov_below",
        "prov_above",
    ],
)
def test_ethernet_trunk_host_interface_00040(field, value, should_raise):
    """
    # Summary

    Verify `customer_inner_vlan_id` and `provider_vlan_id` range validation (ge=1, le=4094).

    ## Test

    - Valid values at boundary accepted
    - Invalid values at boundary rejected with ValidationError

    ## Classes and Methods

    - EthernetTrunkHostVlanMappingEntryModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            EthernetTrunkHostVlanMappingEntryModel(**{field: value})
    else:
        with does_not_raise():
            instance = EthernetTrunkHostVlanMappingEntryModel(**{field: value})
        assert getattr(instance, field) == value


# =============================================================================
# Test: EthernetTrunkHostPolicyModel — initialization
# =============================================================================


def test_ethernet_trunk_host_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None.

    ## Test

    - Instantiate with no arguments
    - Every field is None

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel()
    assert instance.admin_state is None
    assert instance.allowed_vlans is None
    assert instance.bandwidth is None
    assert instance.bpdu_filter is None
    assert instance.bpdu_guard is None
    assert instance.cdp is None
    assert instance.debounce_timer is None
    assert instance.debounce_linkup_timer is None
    assert instance.description is None
    assert instance.duplex_mode is None
    assert instance.error_detection_acl is None
    assert instance.extra_config is None
    assert instance.fec is None
    assert instance.inherit_bandwidth is None
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
    assert instance.policy_type is None
    assert instance.port_type_edge_trunk is None
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


def test_ethernet_trunk_host_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel(
            admin_state=True,
            allowed_vlans="1-100",
            native_vlan=10,
            description="test",
            policy_type="trunk_host",
            speed="10Gb",
        )
    assert instance.admin_state is True
    assert instance.allowed_vlans == "1-100"
    assert instance.native_vlan == 10
    assert instance.description == "test"
    # After normalize + use_enum_values the stored value is the API string.
    assert instance.policy_type == "trunkHost"
    assert instance.speed == "10Gb"


def test_ethernet_trunk_host_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel(
            adminState=True,
            allowedVlans="all",
            nativeVlan=1,
            policyType="trunkHost",
            bpduGuard="enable",
            duplexMode="full",
            portTypeEdgeTrunk=True,
        )
    assert instance.admin_state is True
    assert instance.allowed_vlans == "all"
    assert instance.native_vlan == 1
    assert instance.policy_type == "trunkHost"
    assert instance.bpdu_guard == "enable"
    assert instance.duplex_mode == "full"
    assert instance.port_type_edge_trunk is True


def test_ethernet_trunk_host_interface_00130():
    """
    # Summary

    Verify nested `vlan_mapping_entries` list is coerced to `EthernetTrunkHostVlanMappingEntryModel` instances.

    ## Test

    - Construct with a list of dicts under vlan_mapping_entries
    - Each entry is an EthernetTrunkHostVlanMappingEntryModel

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel(
            vlan_mapping=True,
            vlan_mapping_entries=[
                {"customer_inner_vlan_id": 100, "provider_vlan_id": 200},
                {"customer_inner_vlan_id": 101, "provider_vlan_id": 201},
            ],
        )
    assert instance.vlan_mapping is True
    assert len(instance.vlan_mapping_entries) == 2
    assert isinstance(instance.vlan_mapping_entries[0], EthernetTrunkHostVlanMappingEntryModel)
    assert instance.vlan_mapping_entries[0].customer_inner_vlan_id == 100
    assert instance.vlan_mapping_entries[1].provider_vlan_id == 201


# =============================================================================
# Test: EthernetTrunkHostPolicyModel — validators
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("none", "none"),
        ("all", "all"),
        ("1", "1"),
        ("1-100", "1-100"),
        ("1-200,500-2000,3000", "1-200,500-2000,3000"),
        (42, "42"),
        (None, None),
    ],
    ids=[
        "none",
        "all",
        "single",
        "single_range",
        "multi_range",
        "int_coerced_to_str",
        "none_passthrough",
    ],
)
def test_ethernet_trunk_host_interface_00150(value, expected):
    """
    # Summary

    Verify `validate_allowed_vlans` accepts valid values and coerces integers to strings.

    ## Test

    - Valid values pass through or are coerced
    - Stored value equals expected

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.validate_allowed_vlans()
    """
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel(allowed_vlans=value)
    assert instance.allowed_vlans == expected


@pytest.mark.parametrize(
    "value",
    [
        "abc",
        "1-",
        ",1",
        "1,,2",
        "-1",
        [1, 2],
    ],
    ids=[
        "letters",
        "dangling_hyphen",
        "leading_comma",
        "double_comma",
        "negative",
        "wrong_type_list",
    ],
)
def test_ethernet_trunk_host_interface_00160(value):
    """
    # Summary

    Verify `validate_allowed_vlans` rejects malformed values.

    ## Test

    - Invalid values raise ValidationError

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.validate_allowed_vlans()
    """
    with pytest.raises(ValidationError, match=r"allowed_vlans must be 'none', 'all'"):
        EthernetTrunkHostPolicyModel(allowed_vlans=value)


@pytest.mark.parametrize(
    "value,expected,raises",
    [
        ("trunk_host", "trunkHost", False),
        ("trunkHost", "trunkHost", False),
        (None, None, False),
        ("unknown_value", None, True),
    ],
    ids=[
        "ansible_name",
        "api_value_passthrough",
        "none_passthrough",
        "unknown_rejected_by_enum",
    ],
)
def test_ethernet_trunk_host_interface_00170(value, expected, raises):
    """
    # Summary

    Verify `normalize_policy_type` maps Ansible names to API values and passes through API values unchanged.

    ## Test

    - "trunk_host" normalizes to "trunkHost"
    - "trunkHost" passes through
    - None passes through
    - Unknown values fail enum validation

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.normalize_policy_type()
    """
    if raises:
        with pytest.raises(ValidationError):
            EthernetTrunkHostPolicyModel(policy_type=value)
    else:
        with does_not_raise():
            instance = EthernetTrunkHostPolicyModel(policy_type=value)
        assert instance.policy_type == expected


# =============================================================================
# Test: EthernetTrunkHostPolicyModel — range and enum validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("bandwidth", 1, False),
        ("bandwidth", 100000000, False),
        ("bandwidth", 0, True),
        ("bandwidth", 100000001, True),
        ("debounce_timer", 0, False),
        ("debounce_timer", 20000, False),
        ("debounce_timer", -1, True),
        ("debounce_timer", 20001, True),
        ("debounce_linkup_timer", 1000, False),
        ("debounce_linkup_timer", 10000, False),
        ("debounce_linkup_timer", 999, True),
        ("debounce_linkup_timer", 10001, True),
        ("inherit_bandwidth", 1, False),
        ("inherit_bandwidth", 100000000, False),
        ("inherit_bandwidth", 0, True),
        ("inherit_bandwidth", 100000001, True),
        ("native_vlan", 1, False),
        ("native_vlan", 4094, False),
        ("native_vlan", 0, True),
        ("native_vlan", 4095, True),
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
def test_ethernet_trunk_host_interface_00220(field, value, should_raise):
    """
    # Summary

    Verify ge/le constraints on every numeric policy field.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected with ValidationError

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            EthernetTrunkHostPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = EthernetTrunkHostPolicyModel(**{field: value})
        assert getattr(instance, field) == value


def test_ethernet_trunk_host_interface_00230():
    """
    # Summary

    Verify `description` max_length=254.

    ## Test

    - 254-char description accepted
    - 255-char description rejected with ValidationError

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    at_limit = "a" * 254
    over_limit = "a" * 255
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel(description=at_limit)
    assert instance.description == at_limit

    with pytest.raises(ValidationError):
        EthernetTrunkHostPolicyModel(description=over_limit)


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("plain ASCII", False),
        ("with-hyphen and 123", False),
        ("em — dash", True),
        ("smart “quotes”", True),
        ("emoji \U0001F600", True),
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
def test_ethernet_trunk_host_interface_00235(value, should_raise):
    """
    # Summary

    Verify `description` (typed `AsciiDescription`) rejects any non-ASCII character.

    Cisco backend pipes interface descriptions through CLI generators that 500 on UTF-8. Catching this client-side
    gives users a clear error instead of a generic "unexpected error during policy execution" 500.

    ## Test

    - ASCII strings accepted
    - Non-ASCII characters (em-dash, smart quotes, emoji, latin-1) raise

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    - models.types.ascii_only()
    """
    if should_raise:
        with pytest.raises(ValidationError, match="description must contain only ASCII"):
            EthernetTrunkHostPolicyModel(description=value)
    else:
        instance = EthernetTrunkHostPolicyModel(description=value)
        assert instance.description == value


@pytest.mark.parametrize(
    "field,enum_cls",
    [
        ("speed", SpeedEnum),
        ("duplex_mode", DuplexModeEnum),
        ("fec", FecEnum),
        ("bpdu_guard", BpduGuardEnum),
        ("bpdu_filter", BpduFilterEnum),
        ("link_type", LinkTypeEnum),
        ("mtu", MtuEnum),
        ("storm_control_action", StormControlActionEnum),
    ],
    ids=["speed", "duplex_mode", "fec", "bpdu_guard", "bpdu_filter", "link_type", "mtu", "storm_control_action"],
)
def test_ethernet_trunk_host_interface_00240(field, enum_cls):
    """
    # Summary

    Verify enum-constrained fields accept any valid enum value and reject invalid strings.

    ## Test

    - Valid enum value sets the stored value (enum `.value` due to use_enum_values=True)
    - Invalid value raises ValidationError

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.__init__()
    """
    valid_value = next(iter(enum_cls)).value
    with does_not_raise():
        instance = EthernetTrunkHostPolicyModel(**{field: valid_value})
    assert getattr(instance, field) == valid_value

    with pytest.raises(ValidationError):
        EthernetTrunkHostPolicyModel(**{field: "not_a_real_value"})


# =============================================================================
# Test: EthernetTrunkHostPolicyModel — serializer
# =============================================================================


@pytest.mark.parametrize(
    "stored_value,mode,expected",
    [
        ("trunkHost", "payload", "trunkHost"),
        ("trunkHost", "config", "trunk_host"),
        (None, "payload", None),
        (None, "config", None),
    ],
    ids=["payload_known", "config_known", "payload_none", "config_none"],
)
def test_ethernet_trunk_host_interface_00300(stored_value, mode, expected):
    """
    # Summary

    Verify `serialize_policy_type` emits API value in payload mode and Ansible name in config mode.

    ## Test

    - model_dump with context={"mode": "payload"} returns camelCase API value
    - model_dump with context={"mode": "config"} returns Ansible-friendly snake_case

    ## Classes and Methods

    - EthernetTrunkHostPolicyModel.serialize_policy_type()
    """
    instance = EthernetTrunkHostPolicyModel(policy_type=stored_value) if stored_value is not None else EthernetTrunkHostPolicyModel()
    dumped = instance.model_dump(context={"mode": mode}, exclude_none=False)
    assert dumped["policy_type"] == expected


# =============================================================================
# Test: EthernetTrunkHostNetworkOSModel
# =============================================================================


def test_ethernet_trunk_host_interface_00400():
    """
    # Summary

    Verify `network_os_type` defaults to "nx-os".

    ## Test

    - Instantiate without args
    - network_os_type is "nx-os"
    - policy is None

    ## Classes and Methods

    - EthernetTrunkHostNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert instance.policy is None


def test_ethernet_trunk_host_interface_00410():
    """
    # Summary

    Verify nested `policy` assignment accepts a dict and coerces to EthernetTrunkHostPolicyModel.

    ## Test

    - Construct with policy as dict
    - policy is an EthernetTrunkHostPolicyModel instance

    ## Classes and Methods

    - EthernetTrunkHostNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostNetworkOSModel(policy={"admin_state": True, "allowed_vlans": "all"})
    assert isinstance(instance.policy, EthernetTrunkHostPolicyModel)
    assert instance.policy.admin_state is True
    assert instance.policy.allowed_vlans == "all"


def test_ethernet_trunk_host_interface_00420():
    """
    # Summary

    Verify camelCase alias `networkOSType` populates network_os_type.

    ## Test

    - Construct with camelCase alias
    - Python field accessible

    ## Classes and Methods

    - EthernetTrunkHostNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostNetworkOSModel(networkOSType="ios-xe")
    assert instance.network_os_type == "ios-xe"


# =============================================================================
# Test: EthernetTrunkHostConfigDataModel
# =============================================================================


def test_ethernet_trunk_host_interface_00450():
    """
    # Summary

    Verify `mode` defaults to "trunk".

    ## Test

    - Construct with only network_os
    - mode is "trunk"

    ## Classes and Methods

    - EthernetTrunkHostConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostConfigDataModel(network_os=EthernetTrunkHostNetworkOSModel())
    assert instance.mode == "trunk"


def test_ethernet_trunk_host_interface_00460():
    """
    # Summary

    Verify camelCase alias `networkOS` populates network_os.

    ## Test

    - Construct with camelCase alias
    - Python field accessible

    ## Classes and Methods

    - EthernetTrunkHostConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostConfigDataModel(networkOS={"networkOSType": "nx-os"})
    assert isinstance(instance.network_os, EthernetTrunkHostNetworkOSModel)
    assert instance.network_os.network_os_type == "nx-os"


def test_ethernet_trunk_host_interface_00470():
    """
    # Summary

    Verify `network_os` is a required field.

    ## Test

    - Construct without network_os
    - ValidationError raised

    ## Classes and Methods

    - EthernetTrunkHostConfigDataModel.__init__()
    """
    with pytest.raises(ValidationError, match=r"network_os|networkOS"):
        EthernetTrunkHostConfigDataModel()


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — initialization and ClassVars
# =============================================================================


def test_ethernet_trunk_host_interface_00500():
    """
    # Summary

    Verify ClassVar `identifiers` and `identifier_strategy`.

    ## Test

    - identifiers == ["switch_ip", "interface_name"]
    - identifier_strategy == "composite"

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel
    """
    assert EthernetTrunkHostInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    assert EthernetTrunkHostInterfaceModel.identifier_strategy == "composite"


def test_ethernet_trunk_host_interface_00510():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip`.

    ## Test

    - payload_exclude_fields == {"switch_ip"}

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel
    """
    assert EthernetTrunkHostInterfaceModel.payload_exclude_fields == {"switch_ip"}


def test_ethernet_trunk_host_interface_00520():
    """
    # Summary

    Verify `switch_ip` and `interface_name` are required.

    ## Test

    - Missing switch_ip raises ValidationError
    - Missing interface_name raises ValidationError

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.__init__()
    """
    with pytest.raises(ValidationError, match=r"switch_ip|switchIp"):
        EthernetTrunkHostInterfaceModel(interface_name="Ethernet1/1")

    with pytest.raises(ValidationError, match=r"interface_name|interfaceName"):
        EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1")


def test_ethernet_trunk_host_interface_00530():
    """
    # Summary

    Verify `interface_type` defaults to "ethernet" and `config_data` defaults to None.

    ## Test

    - Minimal construction
    - Defaults applied

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.__init__()
    """
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="Ethernet1/1")
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "Ethernet1/1"
    assert instance.interface_type == "ethernet"
    assert instance.config_data is None


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — normalize_interface_name
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("ethernet1/1", "Ethernet1/1"),
        ("Ethernet1/1", "Ethernet1/1"),
        ("e1/1", "E1/1"),
        ("eth1/1/1", "Eth1/1/1"),
        ("", ""),
    ],
    ids=["lowercase_full", "already_cap", "single_letter", "breakout", "empty_passthrough"],
)
def test_ethernet_trunk_host_interface_00550(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` capitalizes the first character.

    ## Test

    - Lowercase input capitalized
    - Already-capitalized input unchanged

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.normalize_interface_name()
    """
    instance = EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — to_payload
# =============================================================================


def test_ethernet_trunk_host_interface_00600():
    """
    # Summary

    Verify `to_payload` emits camelCase keys and excludes `switch_ip`.

    ## Test

    - Top-level keys are camelCase
    - switchIp / switch_ip not present

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_payload()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert "interfaceName" in result
    assert "interfaceType" in result
    assert "configData" in result
    assert "switchIp" not in result
    assert "switch_ip" not in result


def test_ethernet_trunk_host_interface_00610():
    """
    # Summary

    Verify deeply nested structure preserves camelCase aliases throughout.

    ## Test

    - configData.networkOS.policy has camelCase keys

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_payload()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    policy = result["configData"]["networkOS"]["policy"]
    assert "adminState" in policy
    assert "allowedVlans" in policy
    assert "nativeVlan" in policy
    assert "policyType" in policy
    assert "bpduGuard" in policy
    assert "vlanMapping" in policy
    assert "vlanMappingEntries" in policy


def test_ethernet_trunk_host_interface_00620():
    """
    # Summary

    Verify `policyType` is the API camelCase value in payload mode.

    ## Test

    - policy_type="trunk_host" in config -> "trunkHost" in payload

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_payload()
    - EthernetTrunkHostPolicyModel.serialize_policy_type()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "trunkHost"


def test_ethernet_trunk_host_interface_00630():
    """
    # Summary

    Verify `vlanMappingEntries` list is serialized with camelCase inside each entry.

    ## Test

    - vlanMappingEntries elements use customerInnerVlanId, providerVlanId aliases

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_payload()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    entries = result["configData"]["networkOS"]["policy"]["vlanMappingEntries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["customerInnerVlanId"] == 100
    assert entry["customerVlanId"] == ["10", "20-30"]
    assert entry["dot1qTunnel"] is True
    assert entry["providerVlanId"] == 200


def test_ethernet_trunk_host_interface_00640():
    """
    # Summary

    Verify None-valued fields are excluded from payload output.

    ## Test

    - Minimal model with config_data=None
    - configData not present in payload

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_payload()
    """
    instance = EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="Ethernet1/1")
    result = instance.to_payload()
    assert "configData" not in result
    assert "interfaceName" in result


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — to_config
# =============================================================================


def test_ethernet_trunk_host_interface_00700():
    """
    # Summary

    Verify `to_config` emits snake_case keys throughout.

    ## Test

    - Top-level keys are snake_case
    - Nested keys are snake_case

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_config()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert "interface_name" in result
    assert "interface_type" in result
    assert "config_data" in result
    policy = result["config_data"]["network_os"]["policy"]
    assert "admin_state" in policy
    assert "allowed_vlans" in policy
    assert "native_vlan" in policy
    assert "vlan_mapping_entries" in policy


def test_ethernet_trunk_host_interface_00710():
    """
    # Summary

    Verify `policy_type` is normalized back to the Ansible-friendly name in config mode.

    ## Test

    - Stored "trunkHost" -> output "trunk_host"

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_config()
    - EthernetTrunkHostPolicyModel.serialize_policy_type()
    """
    instance = EthernetTrunkHostInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    result = instance.to_config()
    assert result["config_data"]["network_os"]["policy"]["policy_type"] == "trunk_host"


def test_ethernet_trunk_host_interface_00720():
    """
    # Summary

    Verify `switch_ip` is included in config output (differs from payload).

    ## Test

    - switch_ip present at top level of config

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.to_config()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert result["switch_ip"] == "192.168.1.1"


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — from_response
# =============================================================================


def test_ethernet_trunk_host_interface_00800():
    """
    # Summary

    Verify `from_response` constructs a model from the ND API response.

    ## Test

    - All fields accessible by Python names
    - Nested structure populated

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "Ethernet1/1"
    assert instance.interface_type == "ethernet"
    assert instance.config_data.mode == "trunk"
    assert instance.config_data.network_os.policy.admin_state is True
    assert instance.config_data.network_os.policy.allowed_vlans == "1-100"
    assert instance.config_data.network_os.policy.native_vlan == 10
    # policyType "trunkHost" from API is stored as "trunkHost" after normalization (already API form).
    assert instance.config_data.network_os.policy.policy_type == "trunkHost"


def test_ethernet_trunk_host_interface_00810():
    """
    # Summary

    Verify `from_response` re-serialized via `to_payload` yields an equivalent dict (minus switchIp).

    ## Test

    - API response -> model -> payload matches original (except switchIp which is excluded)

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_response()
    - EthernetTrunkHostInterfaceModel.to_payload()
    """
    original = copy.deepcopy(SAMPLE_API_RESPONSE)
    instance = EthernetTrunkHostInterfaceModel.from_response(original)
    result = instance.to_payload()
    expected = {k: v for k, v in original.items() if k != "switchIp"}
    assert result == expected


def test_ethernet_trunk_host_interface_00820():
    """
    # Summary

    Verify `from_response` tolerates missing `configData`.

    ## Test

    - Response with only switchIp + interfaceName constructs valid model
    - config_data is None

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel.from_response({"switchIp": "192.168.1.1", "interfaceName": "Ethernet1/1"})
    assert instance.config_data is None


def test_ethernet_trunk_host_interface_00830():
    """
    # Summary

    Verify `from_response` ignores unknown top-level and nested keys (extra="ignore").

    ## Test

    - Response with extra keys constructs valid model

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["unknownField"] = "ignored"
    response["configData"]["somethingExtra"] = "also_ignored"
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel.from_response(response)
    assert instance.interface_name == "Ethernet1/1"


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — from_config
# =============================================================================


def test_ethernet_trunk_host_interface_00900():
    """
    # Summary

    Verify `from_config` constructs a model from an Ansible snake_case config.

    ## Test

    - All fields accessible

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "Ethernet1/1"
    assert instance.config_data.network_os.policy.native_vlan == 10
    assert instance.config_data.network_os.policy.description == "uplink to spine"


def test_ethernet_trunk_host_interface_00910():
    """
    # Summary

    Verify Ansible `policy_type: "trunk_host"` is normalized to API value internally.

    ## Test

    - After from_config, stored policy_type is the API value "trunkHost"

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_config()
    - EthernetTrunkHostPolicyModel.normalize_policy_type()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.config_data.network_os.policy.policy_type == "trunkHost"


def test_ethernet_trunk_host_interface_00920():
    """
    # Summary

    Verify `from_config` -> `to_config` round-trip preserves original data.

    ## Test

    - Input config equals to_config() output

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_config()
    - EthernetTrunkHostInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = EthernetTrunkHostInterfaceModel.from_config(original)
    result = instance.to_config()
    assert result == original


def test_ethernet_trunk_host_interface_00930():
    """
    # Summary

    Verify `from_config` accepts a minimal config with just identifiers.

    ## Test

    - Construct with switch_ip + interface_name only
    - config_data is None

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = EthernetTrunkHostInterfaceModel.from_config({"switch_ip": "192.168.1.1", "interface_name": "Ethernet1/1"})
    assert instance.switch_ip == "192.168.1.1"
    assert instance.config_data is None


def test_ethernet_trunk_host_interface_00940():
    """
    # Summary

    Verify full round-trip through all serialization methods.

    ## Test

    - config -> from_config -> to_payload -> from_response (with switchIp injected) -> to_config
      matches original config

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.from_config()
    - EthernetTrunkHostInterfaceModel.to_payload()
    - EthernetTrunkHostInterfaceModel.from_response()
    - EthernetTrunkHostInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = EthernetTrunkHostInterfaceModel.from_config(original)
    payload = instance.to_payload()
    payload["switchIp"] = original["switch_ip"]
    instance2 = EthernetTrunkHostInterfaceModel.from_response(payload)
    result = instance2.to_config()
    assert result == original


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — identifier, diff, merge
# =============================================================================


def test_ethernet_trunk_host_interface_01000():
    """
    # Summary

    Verify `get_identifier_value` returns the composite `(switch_ip, interface_name)` tuple.

    ## Test

    - Composite tuple returned

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.get_identifier_value()
    """
    instance = EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="Ethernet1/1")
    assert instance.get_identifier_value() == ("192.168.1.1", "Ethernet1/1")


def test_ethernet_trunk_host_interface_01010():
    """
    # Summary

    Verify `get_diff` returns True when two models are identical.

    ## Test

    - Two identical models
    - get_diff returns True

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.get_diff()
    """
    instance1 = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    instance2 = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance1.get_diff(instance2) is True


def test_ethernet_trunk_host_interface_01020():
    """
    # Summary

    Verify `get_diff` returns False when a nested field differs.

    ## Test

    - Native VLAN differs between two models
    - get_diff returns False

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.get_diff()
    """
    config1 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2["config_data"]["network_os"]["policy"]["native_vlan"] = 99
    instance1 = EthernetTrunkHostInterfaceModel.from_config(config1)
    instance2 = EthernetTrunkHostInterfaceModel.from_config(config2)
    assert instance1.get_diff(instance2) is False


def test_ethernet_trunk_host_interface_01030():
    """
    # Summary

    Verify `merge` applies non-None values from `other` into `self`.

    ## Test

    - Other sets a field self did not have
    - After merge, self has the field

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.merge()
    """
    base = {
        "switch_ip": "192.168.1.1",
        "interface_name": "Ethernet1/1",
        "config_data": {
            "network_os": {
                "policy": {"admin_state": True},
            },
        },
    }
    other = {
        "switch_ip": "192.168.1.1",
        "interface_name": "Ethernet1/1",
        "config_data": {
            "network_os": {
                "policy": {"allowed_vlans": "1-100"},
            },
        },
    }
    instance = EthernetTrunkHostInterfaceModel.from_config(base)
    instance.merge(EthernetTrunkHostInterfaceModel.from_config(other))
    assert instance.config_data.network_os.policy.admin_state is True
    assert instance.config_data.network_os.policy.allowed_vlans == "1-100"


def test_ethernet_trunk_host_interface_01040():
    """
    # Summary

    Verify `merge` preserves existing values when `other` has unset fields (model_fields_set semantics).

    ## Test

    - Self has a value, other does not mention that field
    - After merge, self still has the original value

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.merge()
    """
    instance = EthernetTrunkHostInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    other = EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="Ethernet1/1")
    instance.merge(other)
    assert instance.config_data.network_os.policy.native_vlan == 10


def test_ethernet_trunk_host_interface_01050():
    """
    # Summary

    Verify `merge` raises TypeError when given a model of the wrong type.

    ## Test

    - Passing a policy model to the interface model merge raises TypeError

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.merge()
    """
    instance = EthernetTrunkHostInterfaceModel(switch_ip="192.168.1.1", interface_name="Ethernet1/1")
    with pytest.raises(TypeError, match=r"Cannot merge"):
        instance.merge(EthernetTrunkHostPolicyModel())


# =============================================================================
# Test: EthernetTrunkHostInterfaceModel — get_argument_spec
# =============================================================================


def test_ethernet_trunk_host_interface_01100():
    """
    # Summary

    Verify top-level structural layout of the Ansible argument spec.

    ## Test

    - fabric_name, config, state keys present
    - switch_ip is under config.options, not top-level
    - config.type == "list", elements == "dict"
    - state choices and default
    - policy_type default is "trunk_host"

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = EthernetTrunkHostInterfaceModel.get_argument_spec()
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
    assert policy_spec["policy_type"]["default"] == "trunk_host"


@pytest.mark.parametrize(
    "field,enum_cls,key",
    [
        ("bpdu_filter", BpduFilterEnum, "value"),
        ("bpdu_guard", BpduGuardEnum, "value"),
        ("duplex_mode", DuplexModeEnum, "value"),
        ("fec", FecEnum, "value"),
        ("link_type", LinkTypeEnum, "value"),
        ("mtu", MtuEnum, "value"),
        ("speed", SpeedEnum, "value"),
        ("storm_control_action", StormControlActionEnum, "value"),
        ("policy_type", TrunkHostPolicyTypeEnum, "name"),
    ],
    ids=[
        "bpdu_filter",
        "bpdu_guard",
        "duplex_mode",
        "fec",
        "link_type",
        "mtu",
        "speed",
        "storm_control_action",
        "policy_type",
    ],
)
def test_ethernet_trunk_host_interface_01120(field, enum_cls, key):
    """
    # Summary

    Verify enum-constrained policy fields expose correct `choices` in the argument spec.

    ## Test

    - Each enum field's choices list exactly matches the enum values (or Ansible names for policy_type)

    ## Classes and Methods

    - EthernetTrunkHostInterfaceModel.get_argument_spec()
    """
    spec = EthernetTrunkHostInterfaceModel.get_argument_spec()
    policy_spec = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    if key == "name":
        expected = [e.name.lower() for e in enum_cls]
    else:
        expected = [e.value for e in enum_cls]
    assert policy_spec[field]["choices"] == expected
