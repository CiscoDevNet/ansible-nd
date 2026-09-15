# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_access_interface.py

Tests the Port-channel accessPoHost Interface Pydantic model classes.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy

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
    XeAccessPoHostPolicyTypeEnum,
    XePortChannelModeEnum,
    XeTrunkPoHostPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessConfigDataModel,
    PortChannelAccessInterfaceModel,
    PortChannelAccessNetworkOSModel,
    PortChannelAccessPolicyModel,
    XePortChannelAccessNetworkOSModel,
    XePortChannelAccessPolicyModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from pydantic import ValidationError

# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_API_RESPONSE = {
    "switchIp": "192.168.1.1",
    "interfaceName": "port-channel501",
    "interfaceType": "portChannel",
    "configData": {
        "mode": "access",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "adminState": True,
                "accessVlan": 100,
                "ports": ["Ethernet1/1", "Ethernet1/2"],
                "portChannelMode": "active",
                "lacpRate": "fast",
                "lacpPortPriority": 32768,
                "bpduGuard": "enable",
                "bpduFilter": "disable",
                "description": "uplink to host",
                "policyType": "accessPoHost",
                "speed": "10Gb",
                "duplexMode": "auto",
                "mtu": "jumbo",
                "copyDescription": True,
            },
        },
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "port-channel501",
    "interface_type": "portChannel",
    "config_data": {
        "mode": "access",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "admin_state": True,
                "access_vlan": 100,
                "ports": ["Ethernet1/1", "Ethernet1/2"],
                "port_channel_mode": "active",
                "lacp_rate": "fast",
                "lacp_port_priority": 32768,
                "bpdu_guard": "enable",
                "bpdu_filter": "disable",
                "description": "uplink to host",
                # The branch discriminator is injected when omitted and is now surfaced in `to_config()` output,
                # so the round-trip samples carry it explicitly (issue #536).
                "policy_type": "accessPoHost",
                "speed": "10Gb",
                "duplex_mode": "auto",
                "mtu": "jumbo",
                "copy_description": True,
            },
        },
    },
}


# =============================================================================
# Test: PortChannelAccessPolicyModel — initialization
# =============================================================================


def test_port_channel_access_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None.

    ## Test

    - Instantiate with no arguments
    - Every field is None

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessPolicyModel()
    assert instance.admin_state is None
    assert instance.access_vlan is None
    assert instance.bpdu_filter is None
    assert instance.bpdu_guard is None
    assert instance.cdp is None
    assert instance.copy_description is None
    assert instance.description is None
    assert instance.duplex_mode is None
    assert instance.extra_config is None
    assert instance.lacp_port_priority is None
    assert instance.lacp_rate is None
    assert instance.lacp_suspend is None
    assert instance.monitor is None
    assert instance.mtu is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None
    assert instance.netflow_sampler is None
    assert instance.policy_type == "accessPoHost"
    assert instance.port_channel_mode is None
    assert instance.ports is None
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


def test_port_channel_access_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessPolicyModel(
            admin_state=True,
            access_vlan=100,
            ports=["Ethernet1/1"],
            port_channel_mode="active",
            lacp_rate="fast",
            description="test",
            speed="10Gb",
        )
    assert instance.admin_state is True
    assert instance.access_vlan == 100
    assert instance.ports == ["Ethernet1/1"]
    assert instance.port_channel_mode == "active"
    assert instance.lacp_rate == "fast"
    assert instance.description == "test"
    # Hardcoded model default; user no longer supplies this field.
    assert instance.policy_type == "accessPoHost"
    assert instance.speed == "10Gb"


def test_port_channel_access_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessPolicyModel(
            adminState=True,
            accessVlan=200,
            ports=["Ethernet1/3", "Ethernet1/4"],
            portChannelMode="passive",
            policyType="accessPoHost",
            bpduGuard="enable",
            duplexMode="full",
            copyDescription=True,
        )
    assert instance.admin_state is True
    assert instance.access_vlan == 200
    assert instance.ports == ["Ethernet1/3", "Ethernet1/4"]
    assert instance.port_channel_mode == "passive"
    assert instance.policy_type == "accessPoHost"
    assert instance.bpdu_guard == "enable"
    assert instance.duplex_mode == "full"
    assert instance.copy_description is True


# =============================================================================
# Test: PortChannelAccessPolicyModel — validators
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
        # Digits and separators after the alphabetic prefix are preserved (breakout/subinterface forms).
        (["ethernet1/1/1"], ["Ethernet1/1/1"]),
    ],
    ids=[
        "lowercase_to_canonical",
        "already_canonical_passthrough",
        "single_letter_abbreviation",
        "eth_and_et_abbreviations",
        "uppercase_canonicalized",
        "empty_list",
        "none_passthrough",
        "breakout_separators_preserved",
    ],
)
def test_port_channel_access_interface_00180(value, expected):
    """
    # Summary

    Verify `normalize_ports` normalizes each member name through the shared cross-OS helper
    (`ethernet_common.normalize_ethernet_interface_name`, via `normalize_member_interface_names`): a prefix that matches
    exactly one canonical family (`Ethernet`, `GigabitEthernet`) expands to it, and anything else passes through verbatim.

    ## Test

    - Abbreviated member names (`e1/1`, `eth1/1`, `et1/1`) expand to `Ethernet...`
    - Any casing of the full prefix canonicalizes to `Ethernet`
    - Already-canonical values pass through unchanged
    - Digits/separators after the prefix are preserved
    - Empty list and None pass through
    - An unlisted family passes through verbatim (covered by `test_port_channel_access_interface_02120`)

    ## Classes and Methods

    - PortChannelAccessPolicyModel.normalize_ports()
    - ethernet_common.normalize_member_interface_names()
    """
    with does_not_raise():
        instance = PortChannelAccessPolicyModel(ports=value)
    assert instance.ports == expected


def test_port_channel_access_interface_00190():
    """
    # Summary

    Verify `normalize_ports` passes a non-list, non-None value straight through to fail Pydantic type validation
    rather than coercing it. This keeps misconfigured input surfaced as a `ValidationError` instead of silently
    succeeding.

    ## Test

    - A scalar string for `ports` raises ValidationError

    ## Classes and Methods

    - PortChannelAccessPolicyModel.normalize_ports()
    """
    with pytest.raises(ValidationError):
        PortChannelAccessPolicyModel(ports="Ethernet1/1")


# =============================================================================
# Test: PortChannelAccessPolicyModel — range and enum validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("access_vlan", 1, False),
        ("access_vlan", 4094, False),
        ("access_vlan", 0, True),
        ("access_vlan", 4095, True),
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
def test_port_channel_access_interface_00220(field, value, should_raise):
    """
    # Summary

    Verify ge/le constraints on every numeric policy field.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected with ValidationError

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelAccessPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = PortChannelAccessPolicyModel(**{field: value})
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
def test_port_channel_access_interface_00225(field, value, should_raise):
    """
    # Summary

    Verify storm-control percentage fields enforce the 0.0-100.0 range.

    ## Test

    - 0.0 and 100.0 accepted
    - -0.1 and 100.01 rejected

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelAccessPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = PortChannelAccessPolicyModel(**{field: value})
        assert getattr(instance, field) == value


def test_port_channel_access_interface_00230():
    """
    # Summary

    Verify `description` max_length=254.

    ## Test

    - 254-char description accepted
    - 255-char description rejected with ValidationError

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    at_limit = "a" * 254
    over_limit = "a" * 255
    with does_not_raise():
        instance = PortChannelAccessPolicyModel(description=at_limit)
    assert instance.description == at_limit

    with pytest.raises(ValidationError):
        PortChannelAccessPolicyModel(description=over_limit)


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("plain ASCII", False),
        ("with-hyphen and 123", False),
        ("em — dash", True),
        ("smart \u201cquotes\u201d", True),
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
def test_port_channel_access_interface_00235(value, should_raise):
    """
    # Summary

    Verify `description` (typed `AsciiDescription`) rejects any non-ASCII character.

    Cisco backend pipes interface descriptions through CLI generators that 500 on UTF-8. Catching this client-side
    gives users a clear error instead of a generic "unexpected error during policy execution" 500.

    ## Test

    - ASCII strings accepted
    - Non-ASCII characters (em-dash, smart quotes, emoji, latin-1) raise

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    - models.types.ascii_only()
    """
    if should_raise:
        with pytest.raises(ValidationError, match="description must contain only ASCII"):
            PortChannelAccessPolicyModel(description=value)
    else:
        instance = PortChannelAccessPolicyModel(description=value)
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
    ],
    ids=["speed", "duplex_mode", "bpdu_guard", "bpdu_filter", "mtu", "storm_control_action", "port_channel_mode", "lacp_rate"],
)
def test_port_channel_access_interface_00240(field, enum_cls):
    """
    # Summary

    Verify enum-constrained fields accept any valid enum value and reject invalid strings.

    ## Test

    - Valid enum value sets the stored value (enum `.value` due to use_enum_values=True)
    - Invalid value raises ValidationError

    ## Classes and Methods

    - PortChannelAccessPolicyModel.__init__()
    """
    valid_value = next(iter(enum_cls)).value
    with does_not_raise():
        instance = PortChannelAccessPolicyModel(**{field: valid_value})
    assert getattr(instance, field) == valid_value

    with pytest.raises(ValidationError):
        PortChannelAccessPolicyModel(**{field: "not_a_real_value"})


# =============================================================================
# Test: PortChannelAccessNetworkOSModel
# =============================================================================


def test_port_channel_access_interface_00400():
    """
    # Summary

    Verify `network_os_type` defaults to "nx-os".

    ## Test

    - Instantiate without args
    - network_os_type is "nx-os"
    - policy is None

    ## Classes and Methods

    - PortChannelAccessNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert instance.policy is None


def test_port_channel_access_interface_00410():
    """
    # Summary

    Verify nested `policy` assignment accepts a dict and coerces to PortChannelAccessPolicyModel.

    ## Test

    - Construct with policy as dict
    - policy is a PortChannelAccessPolicyModel instance

    ## Classes and Methods

    - PortChannelAccessNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessNetworkOSModel(policy={"admin_state": True, "access_vlan": 100})
    assert isinstance(instance.policy, PortChannelAccessPolicyModel)
    assert instance.policy.admin_state is True
    assert instance.policy.access_vlan == 100


def test_port_channel_access_interface_00420():
    """
    # Summary

    Verify camelCase alias `networkOSType` populates network_os_type, and that the field is locked to `nx-os`.

    ## Test

    - Construct with camelCase alias and the only valid value
    - Construct with a non-nx-os value raises ValidationError (Literal lock)

    ## Classes and Methods

    - PortChannelAccessNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessNetworkOSModel(networkOSType="nx-os")
    assert instance.network_os_type == "nx-os"

    with pytest.raises(ValidationError, match="Input should be 'nx-os'"):
        PortChannelAccessNetworkOSModel(networkOSType="ios-xe")


# =============================================================================
# Test: PortChannelAccessConfigDataModel
# =============================================================================


def test_port_channel_access_interface_00450():
    """
    # Summary

    Verify `mode` defaults to "access".

    ## Test

    - Construct with only network_os
    - mode is "access"

    ## Classes and Methods

    - PortChannelAccessConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessConfigDataModel(network_os=PortChannelAccessNetworkOSModel())
    assert instance.mode == "access"


def test_port_channel_access_interface_00460():
    """
    # Summary

    Verify camelCase alias `networkOS` populates network_os.

    ## Test

    - Construct with camelCase alias
    - Python field accessible

    ## Classes and Methods

    - PortChannelAccessConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessConfigDataModel(networkOS={"networkOSType": "nx-os"})
    assert isinstance(instance.network_os, PortChannelAccessNetworkOSModel)
    assert instance.network_os.network_os_type == "nx-os"


def test_port_channel_access_interface_00470():
    """
    # Summary

    Verify `network_os` defaults to an empty `PortChannelAccessNetworkOSModel` when omitted, so constructing
    `config_data` without an explicit `network_os` does not raise a raw `ValidationError`.

    ## Test

    - Construct without network_os
    - config_data.network_os is a PortChannelAccessNetworkOSModel with a None policy

    ## Classes and Methods

    - PortChannelAccessConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessConfigDataModel()
    assert isinstance(instance.network_os, PortChannelAccessNetworkOSModel)
    assert instance.network_os.policy is None


# =============================================================================
# Test: PortChannelAccessInterfaceModel — initialization and ClassVars
# =============================================================================


def test_port_channel_access_interface_00500():
    """
    # Summary

    Verify ClassVar `identifiers` and `identifier_strategy`.

    ## Test

    - identifiers == ["switch_ip", "interface_name"]
    - identifier_strategy == "composite"

    ## Classes and Methods

    - PortChannelAccessInterfaceModel
    """
    assert PortChannelAccessInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    assert PortChannelAccessInterfaceModel.identifier_strategy == "composite"


def test_port_channel_access_interface_00510():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip`.

    ## Test

    - payload_exclude_fields == {"switch_ip"}

    ## Classes and Methods

    - PortChannelAccessInterfaceModel
    """
    assert PortChannelAccessInterfaceModel.payload_exclude_fields == {"switch_ip"}


def test_port_channel_access_interface_00520():
    """
    # Summary

    Verify `switch_ip` and `interface_name` are required.

    ## Test

    - Missing switch_ip raises ValidationError
    - Missing interface_name raises ValidationError

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.__init__()
    """
    with pytest.raises(ValidationError, match=r"switch_ip|switchIp"):
        PortChannelAccessInterfaceModel(interface_name="port-channel501")

    with pytest.raises(ValidationError, match=r"interface_name|interfaceName"):
        PortChannelAccessInterfaceModel(switch_ip="192.168.1.1")


def test_port_channel_access_interface_00530():
    """
    # Summary

    Verify `interface_type` defaults to "portChannel" and `config_data` defaults to None.

    ## Test

    - Minimal construction
    - Defaults applied

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.__init__()
    """
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "port-channel501"
    assert instance.interface_type == "portChannel"
    assert instance.config_data is None


# =============================================================================
# Test: PortChannelAccessInterfaceModel — normalize_interface_name
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
def test_port_channel_access_interface_00550(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` lowercases the entire interface name (port-channel convention).

    ## Test

    - Mixed-case inputs normalized to lowercase
    - Already-lowercase input unchanged

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.normalize_interface_name()
    """
    instance = PortChannelAccessInterfaceModel(switch_ip="192.168.1.1", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: PortChannelAccessInterfaceModel — to_payload
# =============================================================================


def test_port_channel_access_interface_00600():
    """
    # Summary

    Verify `to_payload` emits camelCase keys and excludes `switch_ip`.

    ## Test

    - Top-level keys are camelCase
    - switchIp / switch_ip not present

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_payload()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert "interfaceName" in result
    assert "interfaceType" in result
    assert "configData" in result
    assert "switchIp" not in result
    assert "switch_ip" not in result


def test_port_channel_access_interface_00610():
    """
    # Summary

    Verify deeply nested structure preserves camelCase aliases throughout.

    ## Test

    - configData.networkOS.policy has camelCase keys

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_payload()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    policy = result["configData"]["networkOS"]["policy"]
    assert "adminState" in policy
    assert "accessVlan" in policy
    assert "ports" in policy
    assert "portChannelMode" in policy
    assert "lacpRate" in policy
    assert "lacpPortPriority" in policy
    assert "policyType" in policy
    assert "bpduGuard" in policy
    assert "copyDescription" in policy


def test_port_channel_access_interface_00620():
    """
    # Summary

    Verify `policyType` is the API camelCase value in payload mode.

    ## Test

    - Hardcoded model default for `policy_type` serializes as `"accessPoHost"` under the `policyType` alias.

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_payload()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "accessPoHost"


def test_port_channel_access_interface_00630():
    """
    # Summary

    Verify member ports list survives serialization with normalized names.

    ## Test

    - ports list survives in payload as a list of capitalized member names

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_payload()
    - PortChannelAccessPolicyModel.normalize_ports()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["config_data"]["network_os"]["policy"]["ports"] = ["ethernet1/5", "ethernet1/6"]
    instance = PortChannelAccessInterfaceModel.from_config(config)
    result = instance.to_payload()
    assert result["configData"]["networkOS"]["policy"]["ports"] == ["Ethernet1/5", "Ethernet1/6"]


def test_port_channel_access_interface_00640():
    """
    # Summary

    Verify None-valued fields are excluded from payload output.

    ## Test

    - Minimal model with config_data=None
    - configData not present in payload

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_payload()
    """
    instance = PortChannelAccessInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    result = instance.to_payload()
    assert "configData" not in result
    assert "interfaceName" in result


# =============================================================================
# Test: PortChannelAccessInterfaceModel — to_config
# =============================================================================


def test_port_channel_access_interface_00700():
    """
    # Summary

    Verify `to_config` emits snake_case keys throughout.

    ## Test

    - Top-level keys are snake_case
    - Nested keys are snake_case

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_config()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert "interface_name" in result
    assert "interface_type" in result
    assert "config_data" in result
    policy = result["config_data"]["network_os"]["policy"]
    assert "admin_state" in policy
    assert "access_vlan" in policy
    assert "ports" in policy
    assert "port_channel_mode" in policy
    assert "lacp_rate" in policy
    assert "copy_description" in policy


def test_port_channel_access_interface_00710():
    """
    # Summary

    Verify `policy_type` IS surfaced in `to_config()` output. The field is now the per-network-OS branch discriminator
    (`accessPoHost` / `iosXeAccessPoHost`) and is exposed in the argspec, so `before`/`after`/`gathered` output must show
    which policy template the item resolved to rather than hiding it.

    ## Test

    - From a full API response, to_config() DOES include `policy_type` in the policy dict, as the wire value
    - All other policy fields ARE present

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_config()
    - PortChannelAccessPolicyModel.default_policy_type()
    """
    instance = PortChannelAccessInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    result = instance.to_config()
    policy = result["config_data"]["network_os"]["policy"]
    assert policy["policy_type"] == "accessPoHost"
    assert policy["admin_state"] is True
    assert policy["access_vlan"] == 100


def test_port_channel_access_interface_00720():
    """
    # Summary

    Verify `switch_ip` is included in config output (differs from payload).

    ## Test

    - switch_ip present at top level of config

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.to_config()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert result["switch_ip"] == "192.168.1.1"


# =============================================================================
# Test: PortChannelAccessInterfaceModel — from_response
# =============================================================================


def test_port_channel_access_interface_00800():
    """
    # Summary

    Verify `from_response` constructs a model from the ND API response.

    ## Test

    - All fields accessible by Python names
    - Nested structure populated

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "port-channel501"
    assert instance.interface_type == "portChannel"
    assert instance.config_data.mode == "access"
    assert instance.config_data.network_os.policy.admin_state is True
    assert instance.config_data.network_os.policy.access_vlan == 100
    assert instance.config_data.network_os.policy.ports == ["Ethernet1/1", "Ethernet1/2"]
    assert instance.config_data.network_os.policy.port_channel_mode == "active"
    # policyType "accessPoHost" from API is stored as "accessPoHost" after normalization (already API form).
    assert instance.config_data.network_os.policy.policy_type == "accessPoHost"


def test_port_channel_access_interface_00810():
    """
    # Summary

    Verify `from_response` re-serialized via `to_payload` yields an equivalent dict (minus switchIp).

    ## Test

    - API response -> model -> payload matches original (except switchIp which is excluded)

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_response()
    - PortChannelAccessInterfaceModel.to_payload()
    """
    original = copy.deepcopy(SAMPLE_API_RESPONSE)
    instance = PortChannelAccessInterfaceModel.from_response(original)
    result = instance.to_payload()
    expected = {k: v for k, v in original.items() if k != "switchIp"}
    assert result == expected


def test_port_channel_access_interface_00820():
    """
    # Summary

    Verify `from_response` tolerates missing `configData`.

    ## Test

    - Response with only switchIp + interfaceName constructs valid model
    - config_data is None

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel.from_response({"switchIp": "192.168.1.1", "interfaceName": "port-channel501"})
    assert instance.config_data is None


def test_port_channel_access_interface_00830():
    """
    # Summary

    Verify `from_response` ignores unknown top-level and nested keys (extra="ignore").

    ## Test

    - Response with extra keys constructs valid model

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["unknownField"] = "ignored"
    response["configData"]["somethingExtra"] = "also_ignored"
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel.from_response(response)
    assert instance.interface_name == "port-channel501"


# =============================================================================
# Test: PortChannelAccessInterfaceModel — from_config
# =============================================================================


def test_port_channel_access_interface_00900():
    """
    # Summary

    Verify `from_config` constructs a model from an Ansible snake_case config.

    ## Test

    - All fields accessible

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.switch_ip == "192.168.1.1"
    assert instance.interface_name == "port-channel501"
    assert instance.config_data.network_os.policy.access_vlan == 100
    assert instance.config_data.network_os.policy.description == "uplink to host"
    assert instance.config_data.network_os.policy.ports == ["Ethernet1/1", "Ethernet1/2"]


def test_port_channel_access_interface_00910():
    """
    # Summary

    Verify model hardcodes the `accessPoHost` policy type regardless of input.

    ## Test

    - After from_config (no policy_type in input), stored policy_type is the API value "accessPoHost"

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_config()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.config_data.network_os.policy.policy_type == "accessPoHost"


def test_port_channel_access_interface_00920():
    """
    # Summary

    Verify `from_config` -> `to_config` round-trip preserves original data.

    ## Test

    - Input config equals to_config() output

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_config()
    - PortChannelAccessInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = PortChannelAccessInterfaceModel.from_config(original)
    result = instance.to_config()
    assert result == original


def test_port_channel_access_interface_00930():
    """
    # Summary

    Verify `from_config` accepts a minimal config with just identifiers.

    ## Test

    - Construct with switch_ip + interface_name only
    - config_data is None

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel.from_config({"switch_ip": "192.168.1.1", "interface_name": "port-channel501"})
    assert instance.switch_ip == "192.168.1.1"
    assert instance.config_data is None


def test_port_channel_access_interface_00940():
    """
    # Summary

    Verify full round-trip through all serialization methods.

    ## Test

    - config -> from_config -> to_payload -> from_response (with switchIp injected) -> to_config
      matches original config

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.from_config()
    - PortChannelAccessInterfaceModel.to_payload()
    - PortChannelAccessInterfaceModel.from_response()
    - PortChannelAccessInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = PortChannelAccessInterfaceModel.from_config(original)
    payload = instance.to_payload()
    payload["switchIp"] = original["switch_ip"]
    instance2 = PortChannelAccessInterfaceModel.from_response(payload)
    result = instance2.to_config()
    assert result == original


# =============================================================================
# Test: PortChannelAccessInterfaceModel — identifier, diff, merge
# =============================================================================


def test_port_channel_access_interface_01000():
    """
    # Summary

    Verify `get_identifier_value` returns the composite `(switch_ip, interface_name)` tuple.

    ## Test

    - Composite tuple returned

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.get_identifier_value()
    """
    instance = PortChannelAccessInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    assert instance.get_identifier_value() == ("192.168.1.1", "port-channel501")


def test_port_channel_access_interface_01010():
    """
    # Summary

    Verify `get_diff` returns True when two models are identical.

    ## Test

    - Two identical models
    - get_diff returns True

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.get_diff()
    """
    instance1 = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    instance2 = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance1.get_diff(instance2) is True


def test_port_channel_access_interface_01020():
    """
    # Summary

    Verify `get_diff` returns False when a nested field differs.

    ## Test

    - Access VLAN differs between two models
    - get_diff returns False

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.get_diff()
    """
    config1 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2["config_data"]["network_os"]["policy"]["access_vlan"] = 999
    instance1 = PortChannelAccessInterfaceModel.from_config(config1)
    instance2 = PortChannelAccessInterfaceModel.from_config(config2)
    assert instance1.get_diff(instance2) is False


def test_port_channel_access_interface_01030():
    """
    # Summary

    Verify `merge` applies non-None values from `other` into `self`.

    ## Test

    - Other sets a field self did not have
    - After merge, self has the field

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.merge()
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
                "policy": {"access_vlan": 100},
            },
        },
    }
    instance = PortChannelAccessInterfaceModel.from_config(base)
    instance.merge(PortChannelAccessInterfaceModel.from_config(other))
    assert instance.config_data.network_os.policy.admin_state is True
    assert instance.config_data.network_os.policy.access_vlan == 100


def test_port_channel_access_interface_01040():
    """
    # Summary

    Verify `merge` preserves existing values when `other` has unset fields (model_fields_set semantics).

    ## Test

    - Self has a value, other does not mention that field
    - After merge, self still has the original value

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.merge()
    """
    instance = PortChannelAccessInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    other = PortChannelAccessInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    instance.merge(other)
    assert instance.config_data.network_os.policy.access_vlan == 100


def test_port_channel_access_interface_01050():
    """
    # Summary

    Verify `merge` raises TypeError when given a model of the wrong type.

    ## Test

    - Passing a policy model to the interface model merge raises TypeError

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.merge()
    """
    instance = PortChannelAccessInterfaceModel(switch_ip="192.168.1.1", interface_name="port-channel501")
    with pytest.raises(TypeError, match=r"Cannot merge"):
        instance.merge(PortChannelAccessPolicyModel())


# =============================================================================
# Test: PortChannelAccessInterfaceModel — get_argument_spec
# =============================================================================


def test_port_channel_access_interface_01100():
    """
    # Summary

    Verify top-level structural layout of the Ansible argument spec.

    ## Test

    - fabric_name, config, state keys present
    - switch_ip is under config.options, not top-level
    - config.type == "list", elements == "dict"
    - state choices and default
    - network_os_type is exposed with the `nx-os` default, and policy_type with both branch choices

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.get_argument_spec()
    """
    spec = PortChannelAccessInterfaceModel.get_argument_spec()
    assert "fabric_name" in spec
    assert "config" in spec
    assert "state" in spec
    assert "switch_ip" not in spec
    assert "switch_ip" in spec["config"]["options"]
    assert spec["config"]["type"] == "list"
    assert spec["config"]["elements"] == "dict"
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert spec["state"]["default"] == "merged"
    # interface_type and mode are hardcoded in the Pydantic model and intentionally absent from the
    # user-facing argument spec. network_os_type and policy_type select the IOS-XE / NX-OS branch and are exposed.
    config_options = spec["config"]["options"]
    assert "interface_type" not in config_options
    config_data_spec = config_options["config_data"]["options"]
    assert "mode" not in config_data_spec
    network_os_spec = config_data_spec["network_os"]["options"]
    assert network_os_spec["network_os_type"]["default"] == "nx-os"
    assert network_os_spec["network_os_type"]["choices"] == ["nx-os", "ios-xe"]
    policy_spec = network_os_spec["policy"]["options"]
    assert policy_spec["policy_type"]["choices"] == ["accessPoHost", "iosXeAccessPoHost"]


def test_port_channel_access_interface_01110():
    """
    # Summary

    Verify `interface_type` is hardcoded on the Pydantic model and absent from the user-facing argument spec.

    ## Test

    - Model field default is "portChannel"
    - argument spec does not expose interface_type as a user option

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.get_argument_spec()
    """
    spec = PortChannelAccessInterfaceModel.get_argument_spec()
    assert "interface_type" not in spec["config"]["options"]
    instance = PortChannelAccessInterfaceModel(switch_ip="1.2.3.4", interface_name="port-channel501")
    assert instance.interface_type == "portChannel"


@pytest.mark.parametrize(
    "field,enum_cls,key",
    [
        ("bpdu_filter", BpduFilterEnum, "value"),
        ("bpdu_guard", BpduGuardEnum, "value"),
        ("duplex_mode", DuplexModeEnum, "value"),
        ("lacp_rate", LacpRateEnum, "value"),
        ("link_type", LinkTypeEnum, "value"),
        ("port_channel_mode", XePortChannelModeEnum, "value"),
        ("speed", SpeedEnum, "value"),
        ("storm_control_action", StormControlActionEnum, "value"),
    ],
    ids=[
        "bpdu_filter",
        "bpdu_guard",
        "duplex_mode",
        "lacp_rate",
        "link_type",
        "port_channel_mode",
        "speed",
        "storm_control_action",
    ],
)
def test_port_channel_access_interface_01120(field, enum_cls, key):
    """
    # Summary

    Verify enum-constrained policy fields expose correct `choices` in the argument spec.

    `port_channel_mode` carries the IOS-XE superset (`XePortChannelModeEnum`, which adds the PAgP `auto` / `desirable`
    values); the per-branch subset is enforced by the Pydantic branch models. `mtu` is now an unconstrained `str` option
    because the NX-OS branch takes the `default` / `jumbo` enum while the IOS-XE branch takes an integer.

    ## Test

    - Each enum field's choices list exactly matches the enum values
    - `mtu` is `type: str` with no `choices`

    ## Classes and Methods

    - PortChannelAccessInterfaceModel.get_argument_spec()
    """
    spec = PortChannelAccessInterfaceModel.get_argument_spec()
    policy_spec = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    if key == "name":
        expected = [e.name.lower() for e in enum_cls]
    else:
        expected = [e.value for e in enum_cls]
    assert policy_spec[field]["choices"] == expected
    assert policy_spec["mtu"]["type"] == "str"
    assert "choices" not in policy_spec["mtu"]


def test_port_channel_access_interface_01130():
    """
    # Summary

    Verify `_validate_netflow_monitor_present`: `netflow_monitor` is required when `netflow` is true.

    ## Test

    - `netflow=True` without `netflow_monitor` is rejected
    - `netflow=True` with `netflow_monitor` is accepted
    - `netflow=False` (or unset) without `netflow_monitor` is accepted

    ## Classes and Methods

    - PortChannelAccessPolicyModel._validate_netflow_monitor_present()
    """
    with pytest.raises(ValidationError, match="netflow_monitor must be provided when netflow is true"):
        PortChannelAccessPolicyModel(netflow=True)
    with does_not_raise():
        PortChannelAccessPolicyModel(netflow=True, netflow_monitor="MONITOR-1")
        PortChannelAccessPolicyModel(netflow=False)
        PortChannelAccessPolicyModel()


# =============================================================================
# Test: IOS-XE enums (issues #536 / #537)
# =============================================================================


def test_port_channel_access_interface_02000():
    """
    # Summary

    Verify the IOS-XE port-channel enums carry exactly the create-side wire values.

    ## Test

    - `XeAccessPoHostPolicyTypeEnum` / `XeTrunkPoHostPolicyTypeEnum` each have the single managed member
    - `XePortChannelModeEnum` is the template enum (`on`, `active`, `passive`, `auto`, `desirable`)

    ## Classes and Methods

    - XeAccessPoHostPolicyTypeEnum
    - XeTrunkPoHostPolicyTypeEnum
    - XePortChannelModeEnum
    """
    assert [e.value for e in XeAccessPoHostPolicyTypeEnum] == ["iosXeAccessPoHost"]
    assert [e.value for e in XeTrunkPoHostPolicyTypeEnum] == ["iosXeTrunkPoHost"]
    assert [e.value for e in XePortChannelModeEnum] == ["on", "active", "passive", "auto", "desirable"]


# =============================================================================
# Test: IOS-XE branch, union, #381 fields, member normalizer, create-name rewrite
# =============================================================================


XE_ACCESS_PO_RESPONSE = {
    "switchIp": "192.168.12.181",
    "interfaceName": "port-channel101",
    "interfaceType": "portChannel",
    "configData": {
        "mode": "access",
        "networkOS": {
            "networkOSType": "ios-xe",
            "policy": {
                "accessVlan": 100,
                "adminState": True,
                "bpduGuard": "default",
                "description": "xe po",
                "policyType": "iosXeAccessPoHost",
                "portChannelId": "Port-channel101",
                "portChannelMode": "active",
                "ports": ["GigabitEthernet1/0/2", "GigabitEthernet1/0/3"],
            },
        },
    },
}


def test_port_channel_access_interface_02010():
    """
    # Summary

    Verify `network_os_type: ios-xe` selects the IOS-XE branch and `policy_type` is injected as `iosXeAccessPoHost` when omitted.

    ## Test

    - from_config with `network_os_type: ios-xe` and no `policy_type`
    - `config_data.network_os` is `XePortChannelAccessNetworkOSModel`, policy is `XePortChannelAccessPolicyModel`
    - `instance.policy_type == "iosXeAccessPoHost"`; `policy_type` is in `model_fields_set`

    ## Classes and Methods

    - PortChannelAccessConfigDataModel.default_network_os_type()
    - XePortChannelAccessPolicyModel.default_policy_type()
    - PortChannelAccessInterfaceModel.policy_type
    """
    with does_not_raise():
        instance = PortChannelAccessInterfaceModel.from_config(
            {
                "switch_ip": "192.168.12.181",
                "interface_name": "port-channel101",
                "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"policy_type": None, "access_vlan": 100, "ports": ["gi1/0/2"]}}},
            }
        )
    assert isinstance(instance.config_data.network_os, XePortChannelAccessNetworkOSModel)
    assert isinstance(instance.config_data.network_os.policy, XePortChannelAccessPolicyModel)
    assert instance.policy_type == "iosXeAccessPoHost"
    assert "policy_type" in instance.config_data.network_os.policy.model_fields_set
    assert instance.config_data.network_os.policy.ports == ["GigabitEthernet1/0/2"]


def test_port_channel_access_interface_02020():
    """
    # Summary

    Verify an omitted `network_os_type` still selects the NX-OS branch with `policy_type` injected as `accessPoHost`, and that
    `policy_type` is now visible in `to_config()` output for both branches.

    ## Test

    - from_config without `network_os` discriminator -> `PortChannelAccessNetworkOSModel`, `accessPoHost`
    - `to_config()["config_data"]["network_os"]["policy"]["policy_type"] == "accessPoHost"`
    - XE response -> `to_config()` policy carries `policy_type == "iosXeAccessPoHost"` and `network_os_type == "ios-xe"`

    ## Classes and Methods

    - PortChannelAccessPolicyModel.default_policy_type()
    - PortChannelAccessInterfaceModel.to_config()
    """
    nx = PortChannelAccessInterfaceModel.from_config(
        {
            "switch_ip": "192.168.1.1",
            "interface_name": "port-channel501",
            "config_data": {"network_os": {"policy": {"access_vlan": 10, "ports": ["Ethernet1/1"]}}},
        }
    )
    assert isinstance(nx.config_data.network_os, PortChannelAccessNetworkOSModel)
    assert nx.to_config()["config_data"]["network_os"]["policy"]["policy_type"] == "accessPoHost"
    xe = PortChannelAccessInterfaceModel.from_response(copy.deepcopy(XE_ACCESS_PO_RESPONSE))
    config = xe.to_config()["config_data"]["network_os"]
    assert config["network_os_type"] == "ios-xe"
    assert config["policy"]["policy_type"] == "iosXeAccessPoHost"
    assert "port_channel_id" not in config["policy"] and "portChannelId" not in config["policy"]


@pytest.mark.parametrize(
    "policy, match",
    [
        ({"policy_type": "accessPoHost"}, r"policy_type"),
        ({"lacp_rate": "fast"}, r"lacp_rate|Extra inputs"),
        ({"port_channel_mode": "desirable", "policy_type": None}, r"port_channel_mode"),
    ],
)
def test_port_channel_access_interface_02030(policy, match):
    """
    # Summary

    Verify the IOS-XE branch is write-strict: a wrong-branch discriminator, an NX-OS-only field, and an NX-OS-only mode value are rejected.
    (The third case is the NX-OS branch rejecting the PAgP `desirable` mode.)

    ## Test

    - Each policy input raises `ValidationError` matching `match`

    ## Classes and Methods

    - XePortChannelAccessPolicyModel (extra="forbid")
    - PortChannelAccessPolicyModel.port_channel_mode
    """
    os_type = "nx-os" if policy.get("port_channel_mode") == "desirable" else "ios-xe"
    with pytest.raises(ValidationError, match=match):
        PortChannelAccessInterfaceModel.from_config(
            {"switch_ip": "192.168.12.181", "interface_name": "port-channel101", "config_data": {"network_os": {"network_os_type": os_type, "policy": policy}}}
        )


@pytest.mark.parametrize(
    "value, expected, should_raise", [("8000", 8000, False), (9198, 9198, False), ("1499", None, True), ("jumbo", None, True), (9199, None, True)]
)
def test_port_channel_access_interface_02040(value, expected, should_raise):
    """
    # Summary

    Verify the IOS-XE `mtu` coerces numeric strings (the shared `str` argspec) and enforces 1500-9198.

    ## Test

    - Valid values parse to int; out-of-range or non-numeric values raise

    ## Classes and Methods

    - XePortChannelAccessPolicyModel.coerce_mtu()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            XePortChannelAccessPolicyModel(mtu=value)
    else:
        assert XePortChannelAccessPolicyModel(mtu=value).mtu == expected


def test_port_channel_access_interface_02050():
    """
    # Summary

    Verify the create-name rewrite: `to_payload()` emits `Port-channel<N>` for the IOS-XE branch only; `to_config()` and the diff dump
    keep the lowercase identifier, and the NX-OS branch is untouched in every mode.

    # workaround: xe-port-channel-create-requires-canonical-name

    ## Test

    - XE model built from `Port-Channel101` normalizes `interface_name` to `port-channel101`
    - `to_payload()["interfaceName"] == "Port-channel101"`; `to_config()["interface_name"] == "port-channel101"`
    - `get_diff` against an identical copy reports no difference (the identifier is unaffected)
    - NX model `to_payload()["interfaceName"] == "port-channel501"`

    ## Classes and Methods

    - PortChannelAccessInterfaceModel._canonical_xe_create_name()
    """
    xe = PortChannelAccessInterfaceModel.from_config(
        {
            "switch_ip": "192.168.12.181",
            "interface_name": "Port-Channel101",
            "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"access_vlan": 100}}},
        }
    )
    assert xe.interface_name == "port-channel101"
    assert xe.to_payload()["interfaceName"] == "Port-channel101"
    assert xe.to_config()["interface_name"] == "port-channel101"
    assert xe.to_diff_dict()["interfaceName"] == "port-channel101"
    # `get_diff` returns True when `other` is a subset of `self` with no removals, i.e. no difference.
    assert xe.get_diff(copy.deepcopy(xe)) is True
    nx = PortChannelAccessInterfaceModel.from_config(
        {"switch_ip": "192.168.1.1", "interface_name": "port-channel501", "config_data": {"network_os": {"policy": {"access_vlan": 100}}}}
    )
    assert nx.to_payload()["interfaceName"] == "port-channel501"


def test_port_channel_access_interface_02060():
    """
    # Summary

    Verify the IOS-XE `reverse_diff_defaults` scrub: an ND echo carrying only template defaults reads back as no user configuration,
    while a non-default value survives.

    ## Test

    - Echo `{adminState true, bpduGuard default, portChannelMode active, policyType}` -> `to_reverse_diff_dict()` has no keys beyond `policyType`
    - Echo with `bpduGuard: enable` keeps `bpduGuard`

    ## Classes and Methods

    - XePortChannelAccessPolicyModel.reverse_diff_defaults
    """
    defaults = XePortChannelAccessPolicyModel.from_response(
        {"adminState": True, "bpduGuard": "default", "portChannelMode": "active", "policyType": "iosXeAccessPoHost", "portChannelId": "Port-channel101"}
    )
    assert set(defaults.to_reverse_diff_dict()) <= {"policyType"}
    custom = XePortChannelAccessPolicyModel.from_response(
        {"adminState": True, "bpduGuard": "enable", "portChannelMode": "active", "policyType": "iosXeAccessPoHost"}
    )
    assert custom.to_reverse_diff_dict()["bpduGuard"] == "enable"


@pytest.mark.parametrize(
    "field, value, should_raise",
    [
        ("bandwidth", 1, False),
        ("bandwidth", 100000000, False),
        ("bandwidth", 0, True),
        ("bandwidth", 100000001, True),
        ("inherit_bandwidth", 5000, False),
        ("inherit_bandwidth", 0, True),
        ("link_type", "pointToPoint", False),
        ("link_type", "bogus", True),
        ("negotiate_auto", False, False),
        ("orphan_port", True, False),
        ("pfc", True, False),
        ("port_type_edge_trunk", False, False),
    ],
)
def test_port_channel_access_interface_02100(field, value, should_raise):
    """
    # Summary

    Verify the seven `accessPoHost` fields added for issue #381 with the `intPortChannelAccessHostTemplate` ranges.

    ## Test

    - In-range values are accepted and round-trip to their wire alias; out-of-range values raise

    ## Classes and Methods

    - PortChannelAccessPolicyModel
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelAccessPolicyModel(**{field: value})
        return
    instance = PortChannelAccessPolicyModel(**{field: value})
    assert getattr(instance, field) == value or getattr(instance, field).value == value
    alias = PortChannelAccessPolicyModel.model_fields[field].alias
    assert instance.to_payload()[alias] == value


def test_port_channel_access_interface_02110():
    """
    # Summary

    Verify the #381 defaults are scrubbed by `reverse_diff_defaults` (`linkType auto`, `negotiateAuto true`, `orphanPort false`,
    `pfc false`, `portTypeEdgeTrunk true`).

    ## Test

    - A response echoing exactly those defaults yields a reverse-diff dict without them

    ## Classes and Methods

    - PortChannelAccessPolicyModel.reverse_diff_defaults
    """
    echo = {"policyType": "accessPoHost", "linkType": "auto", "negotiateAuto": True, "orphanPort": False, "pfc": False, "portTypeEdgeTrunk": True}
    result = PortChannelAccessPolicyModel.from_response(echo).to_reverse_diff_dict()
    assert not {"linkType", "negotiateAuto", "orphanPort", "pfc", "portTypeEdgeTrunk"} & set(result)


@pytest.mark.parametrize(
    "value, expected",
    [
        (["gi1/0/2"], ["GigabitEthernet1/0/2"]),
        (["e1/1", "ETH1/2"], ["Ethernet1/1", "Ethernet1/2"]),
        (["TenGigabitEthernet1/1/1"], ["TenGigabitEthernet1/1/1"]),
    ],
)
def test_port_channel_access_interface_02120(value, expected):
    """
    # Summary

    Verify member names normalize through the shared cross-OS helper on both branches.

    ## Test

    - `gi...` expands to `GigabitEthernet`, `e...`/`eth...` to `Ethernet`, an unlisted family passes through verbatim

    ## Classes and Methods

    - PortChannelAccessPolicyModel.normalize_ports()
    - XePortChannelAccessPolicyModel.normalize_ports()
    """
    assert PortChannelAccessPolicyModel(ports=value).ports == expected
    assert XePortChannelAccessPolicyModel(ports=value).ports == expected
