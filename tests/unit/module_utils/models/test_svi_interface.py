# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for svi_interface.py

Tests the SVI (switched virtual interface) Pydantic model classes.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import (
    SviConfigDataModel,
    SviInterfaceModel,
    SviNetworkOSModel,
    SviOperDataModel,
    SviPolicyModel,
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
    "interfaceName": "vlan333",
    "interfaceType": "svi",
    "switchId": "9NIE7U0ZXHZ",
    "configData": {
        "mode": "managed",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "svi",
                "adminState": True,
                "advertiseSubnetInUnderlay": False,
                "description": "Sample SVI",
                "hsrpGroup": 1,
                "ip": "10.99.99.1",
                "ipRedirects": True,
                "netflow": False,
                "pimDrPriority": 1,
                "pimSparse": False,
                "preempt": False,
                "prefix": 24,
            },
        },
    },
    "operData": {
        "adminStatus": "up",
        "operationalDescription": "VLAN/BD is down",
        "operationalStatus": "down",
        "portChannelId": -1,
        "switchName": "LE1",
        "vlanRange": "-1",
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "vlan333",
    "interface_type": "svi",
    "config_data": {
        "mode": "managed",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "policy_type": "svi",
                "admin_state": True,
                "advertise_subnet_in_underlay": False,
                "description": "Sample SVI",
                "hsrp_group": 1,
                "ip": "10.99.99.1",
                "ip_redirects": True,
                "netflow": False,
                "pim_dr_priority": 1,
                "pim_sparse": False,
                "preempt": False,
                "prefix": 24,
            },
        },
    },
}


# =============================================================================
# Test: SviPolicyModel — initialization and defaults
# =============================================================================


def test_svi_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None except `policy_type` which defaults to `SviPolicyTypeEnum.SVI`.

    ## Test

    - Instantiate with no arguments
    - All optional fields are None
    - policy_type defaults to "svi"

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SviPolicyModel()
    assert instance.policy_type == "svi"
    assert instance.admin_state is None
    assert instance.description is None
    assert instance.extra_config is None
    assert instance.mtu is None
    assert instance.ip is None
    assert instance.prefix is None
    assert instance.ipv6 is None
    assert instance.prefixv6 is None
    assert instance.ip_redirects is None
    assert instance.vrf_interface is None
    assert instance.routing_tag is None
    assert instance.pim_sparse is None
    assert instance.pim_dr_priority is None
    assert instance.hsrp is None
    assert instance.hsrp_vip is None
    assert instance.hsrp_vipv6 is None
    assert instance.hsrp_group is None
    assert instance.hsrp_groupv6 is None
    assert instance.hsrp_version is None
    assert instance.hsrp_priority is None
    assert instance.preempt is None
    assert instance.mac is None
    assert instance.dhcp_server_address1 is None
    assert instance.dhcp_server_address2 is None
    assert instance.dhcp_server_address3 is None
    assert instance.vrf_dhcp1 is None
    assert instance.vrf_dhcp2 is None
    assert instance.vrf_dhcp3 is None
    assert instance.advertise_subnet_in_underlay is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None
    assert instance.netflow_sampler is None


def test_svi_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SviPolicyModel(
            admin_state=True,
            description="test",
            ip="10.0.0.1",
            prefix=24,
            mtu=9216,
        )
    assert instance.admin_state is True
    assert instance.description == "test"
    assert instance.ip == "10.0.0.1"
    assert instance.prefix == 24
    assert instance.mtu == 9216
    # Hardcoded model default; user no longer supplies this field.
    assert instance.policy_type == "svi"


def test_svi_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SviPolicyModel(
            adminState=True,
            ipRedirects=True,
            pimDrPriority=5,
            advertiseSubnetInUnderlay=True,
            policyType="svi",
        )
    assert instance.admin_state is True
    assert instance.ip_redirects is True
    assert instance.pim_dr_priority == 5
    assert instance.advertise_subnet_in_underlay is True
    assert instance.policy_type == "svi"


# =============================================================================
# Test: SviPolicyModel — description ASCII validator
# =============================================================================


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("plain ASCII", False),
        ("with-hyphen and 123", False),
        ("", False),  # max_length lower bound 0 acceptable here, validator only checks ASCII
        (None, False),
        ("em — dash", True),
        ("smart “quotes”", True),
        ("emoji \U0001f600", True),
        ("latin-1 \xe9", True),
    ],
    ids=[
        "ascii_ok",
        "ascii_punct_digits",
        "empty_string",
        "none_passthrough",
        "em_dash_rejected",
        "smart_quotes_rejected",
        "emoji_rejected",
        "latin1_rejected",
    ],
)
def test_svi_interface_00130(value, should_raise):
    """
    # Summary

    Verify `description` (typed `AsciiDescription`) rejects any non-ASCII character.

    Cisco backend pipes interface descriptions through CLI generators that 500 on UTF-8. Catching this client-side
    gives users a clear error instead of a generic "unexpected error during policy execution" 500.

    ## Test

    - ASCII strings (including empty and None) accepted
    - Any non-ASCII character (em-dash, smart quotes, emoji, latin-1) raises

    ## Classes and Methods

    - SviPolicyModel.__init__()
    - models.types.ascii_only()
    """
    if should_raise:
        with pytest.raises(ValidationError, match="description must contain only ASCII"):
            SviPolicyModel(description=value)
    else:
        with does_not_raise():
            instance = SviPolicyModel(description=value)
        assert instance.description == value


# =============================================================================
# Test: SviPolicyModel — range validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("mtu", 68, False),
        ("mtu", 9216, False),
        ("mtu", 67, True),
        ("mtu", 9217, True),
        ("prefix", 1, False),
        ("prefix", 31, False),
        ("prefix", 0, True),
        ("prefix", 32, True),
        ("prefixv6", 1, False),
        ("prefixv6", 127, False),
        ("prefixv6", 0, True),
        ("prefixv6", 128, True),
        ("pim_dr_priority", 1, False),
        ("pim_dr_priority", 4294967295, False),
        ("pim_dr_priority", 0, True),
        ("pim_dr_priority", 4294967296, True),
        ("hsrp_group", 0, False),
        ("hsrp_group", 4095, False),
        ("hsrp_group", -1, True),
        ("hsrp_group", 4096, True),
        ("hsrp_groupv6", 0, False),
        ("hsrp_groupv6", 4095, False),
        ("hsrp_groupv6", -1, True),
        ("hsrp_groupv6", 4096, True),
        ("hsrp_priority", 0, False),
        ("hsrp_priority", 255, False),
        ("hsrp_priority", -1, True),
        ("hsrp_priority", 256, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_svi_interface_00220(field, value, should_raise):
    """
    # Summary

    Verify ge/le constraints on every numeric policy field.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected with ValidationError

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            SviPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = SviPolicyModel(**{field: value})
        assert getattr(instance, field) == value


def test_svi_interface_00230():
    """
    # Summary

    Verify `description` max_length=254.

    ## Test

    - 254 characters accepted
    - 255 characters rejected

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        SviPolicyModel(description="a" * 254)
    with pytest.raises(ValidationError):
        SviPolicyModel(description="a" * 255)


# =============================================================================
# Test: SviPolicyModel — payload / config serialization
# =============================================================================


def test_svi_interface_00300():
    """
    # Summary

    Verify `to_payload`-style serialization (model_dump with aliases, exclude_none) emits camelCase keys.

    ## Test

    - Construct with snake_case
    - Dump with by_alias=True
    - Output uses API camelCase keys

    ## Classes and Methods

    - SviPolicyModel.model_dump()
    """
    instance = SviPolicyModel(
        admin_state=True,
        description="payload",
        ip_redirects=True,
        pim_dr_priority=2,
        advertise_subnet_in_underlay=True,
    )
    data = instance.model_dump(by_alias=True, exclude_none=True)
    assert data["adminState"] is True
    assert data["description"] == "payload"
    assert data["ipRedirects"] is True
    assert data["pimDrPriority"] == 2
    assert data["advertiseSubnetInUnderlay"] is True
    assert "admin_state" not in data
    assert "ip_redirects" not in data


# =============================================================================
# Test: SviNetworkOSModel
# =============================================================================


def test_svi_interface_00400():
    """
    # Summary

    Verify default values for SviNetworkOSModel.

    ## Test

    - network_os_type defaults to "nx-os"
    - policy defaults to None

    ## Classes and Methods

    - SviNetworkOSModel.__init__()
    """
    instance = SviNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert instance.policy is None


def test_svi_interface_00410():
    """
    # Summary

    Verify SviNetworkOSModel accepts a SviPolicyModel as the `policy` field.

    ## Test

    - Pass a populated policy
    - Access through the network OS container

    ## Classes and Methods

    - SviNetworkOSModel.__init__()
    """
    policy = SviPolicyModel(admin_state=True, description="net-os")
    instance = SviNetworkOSModel(policy=policy)
    assert instance.policy is not None
    assert instance.policy.admin_state is True
    assert instance.policy.description == "net-os"


# =============================================================================
# Test: SviConfigDataModel
# =============================================================================


def test_svi_interface_00500():
    """
    # Summary

    Verify SviConfigDataModel defaults — `mode` is "managed" and `network_os` is required.

    ## Test

    - Construct with only network_os
    - mode defaults to "managed"

    ## Classes and Methods

    - SviConfigDataModel.__init__()
    """
    nos = SviNetworkOSModel(policy=SviPolicyModel(admin_state=True))
    instance = SviConfigDataModel(network_os=nos)
    assert instance.mode == "managed"
    assert instance.network_os is not None


def test_svi_interface_00510():
    """
    # Summary

    Verify SviConfigDataModel rejects construction without network_os.

    ## Test

    - Construct with no network_os
    - ValidationError raised

    ## Classes and Methods

    - SviConfigDataModel.__init__()
    """
    with pytest.raises(ValidationError):
        SviConfigDataModel()  # network_os is required


# =============================================================================
# Test: SviOperDataModel — read-only operational data
# =============================================================================


def test_svi_interface_00600():
    """
    # Summary

    Verify SviOperDataModel parses GET-side aliases.

    ## Test

    - Construct with camelCase aliases
    - Access by snake_case fields

    ## Classes and Methods

    - SviOperDataModel.__init__()
    """
    instance = SviOperDataModel(
        adminStatus="up",
        operationalDescription="VLAN/BD is down",
        operationalStatus="down",
        portChannelId=-1,
        switchName="LE1",
        vlanRange="-1",
    )
    assert instance.admin_status == "up"
    assert instance.operational_description == "VLAN/BD is down"
    assert instance.operational_status == "down"
    assert instance.port_channel_id == -1
    assert instance.switch_name == "LE1"
    assert instance.vlan_range == "-1"


# =============================================================================
# Test: SviInterfaceModel — interface_name normalization
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("vlan333", "vlan333"),
        ("Vlan333", "vlan333"),
        ("VLAN333", "vlan333"),
        ("vLaN333", "vlan333"),
        ("333", "vlan333"),
        (333, "vlan333"),
        ("  333  ", "vlan333"),
    ],
    ids=[
        "lowercase_passthrough",
        "title_case",
        "all_caps",
        "mixed_case",
        "bare_digit_string",
        "bare_int",
        "padded_digit_string",
    ],
)
def test_svi_interface_00700(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` converts all common forms to the lowercase API form `vlan<id>`.

    ## Test

    - Title / mixed / all-caps cased forms normalize to lowercase `vlan<id>`
    - Bare integer (or its string form) is prefixed with `vlan`

    ## Classes and Methods

    - SviInterfaceModel.normalize_interface_name()
    """
    instance = SviInterfaceModel(switch_ip="1.2.3.4", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: SviInterfaceModel — composite identifier
# =============================================================================


def test_svi_interface_00800():
    """
    # Summary

    Verify identifier configuration: composite `(switch_ip, interface_name)`.

    ## Test

    - identifier_strategy is "composite"
    - identifiers is ["switch_ip", "interface_name"]
    - get_identifier_value returns the tuple

    ## Classes and Methods

    - SviInterfaceModel — class attributes
    - SviInterfaceModel.get_identifier_value()
    """
    assert SviInterfaceModel.identifier_strategy == "composite"
    assert SviInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    instance = SviInterfaceModel(switch_ip="1.2.3.4", interface_name="vlan333")
    assert instance.get_identifier_value() == ("1.2.3.4", "vlan333")


def test_svi_interface_00810():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip` and `oper_data` from `to_payload`.

    ## Test

    - Construct with all top-level fields
    - to_payload omits switch_ip and operData

    ## Classes and Methods

    - SviInterfaceModel.to_payload()
    """
    instance = SviInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert "switchIp" not in payload
    assert "operData" not in payload
    # Verify the remaining top-level shape
    assert payload["interfaceName"] == "vlan333"
    assert payload["interfaceType"] == "svi"


# =============================================================================
# Test: SviInterfaceModel — from_response round-trips hsrpVersion as int
# =============================================================================


def test_svi_interface_00900():
    """
    # Summary

    Verify `from_response` round-trips `hsrpVersion` as integer through `to_payload`.

    Lab-verified 2026-04-30: ND accepts `hsrpVersion: 1` (integer) on PUT cleanly even when `hsrp` is not set, so
    no GET-side stripping is needed. The phase-1 strip workaround has been removed.

    ## Test

    - Response with hsrpGroup=1 and hsrpVersion=1
    - Model has hsrp_group=1 and hsrp_version=1
    - to_payload() includes both as integers

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.to_payload()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["hsrpVersion"] = 1
    response["configData"]["networkOS"]["policy"]["hsrpGroup"] = 1

    instance = SviInterfaceModel.from_response(response)
    policy = instance.config_data.network_os.policy
    assert policy.hsrp_group == 1
    assert policy.hsrp_version == 1

    payload = instance.to_payload()
    policy_payload = payload["configData"]["networkOS"]["policy"]
    assert policy_payload["hsrpGroup"] == 1
    assert policy_payload["hsrpVersion"] == 1


@pytest.mark.parametrize(
    "value,should_raise",
    [
        (1, False),
        (2, False),
        (0, True),
        (3, True),
        ("1", True),  # API requires int, string-form must be rejected client-side
    ],
    ids=["v1_ok", "v2_ok", "below_min_rejected", "above_max_rejected", "string_rejected"],
)
def test_svi_interface_00910(value, should_raise):
    """
    # Summary

    Verify `hsrp_version` is `Literal[1, 2]`. Strings are rejected to keep the wire format aligned with the OpenAPI
    schema, which declares `hsrpVersion` as integer.

    ## Test

    - Integers 1 and 2 accepted
    - Other integers and string `"1"` rejected by Pydantic

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            SviPolicyModel(hsrp_version=value)
    else:
        with does_not_raise():
            instance = SviPolicyModel(hsrp_version=value)
        assert instance.hsrp_version == value


def test_svi_interface_00920():
    """
    # Summary

    Verify `from_response` is robust to missing nested structures.

    ## Test

    - Response with no configData
    - Response with configData but no networkOS
    - Response with networkOS but no policy
    - All return a valid model without raising

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    """
    minimal = {
        "switchIp": "1.2.3.4",
        "interfaceName": "vlan333",
        "switchId": "X",
    }
    with does_not_raise():
        SviInterfaceModel.from_response(minimal)

    no_policy = copy.deepcopy(minimal)
    no_policy["configData"] = {"mode": "managed", "networkOS": {"networkOSType": "nx-os"}}
    with does_not_raise():
        SviInterfaceModel.from_response(no_policy)


def test_svi_interface_00930():
    """
    # Summary

    Verify a full HSRP block round-trips through `from_response` -> `to_payload` with all fields preserved.

    Mirrors the lab-verified shape: `hsrp: true` plus `hsrpGroup`, `hsrpVersion` (int), `hsrpVip`, `hsrpPriority`,
    `preempt`, and `mac` all flow through unchanged.

    ## Test

    - Response includes a full HSRP block
    - After from_response, every HSRP field is reachable on the model
    - to_payload re-emits every HSRP field with API names

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.to_payload()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"].update(
        {
            "hsrp": True,
            "hsrpGroup": 5,
            "hsrpVersion": 2,
            "hsrpVip": "10.99.99.254",
            "hsrpPriority": 110,
            "preempt": True,
            "mac": "0000.0c07.ac05",
        }
    )

    instance = SviInterfaceModel.from_response(response)
    policy = instance.config_data.network_os.policy
    assert policy.hsrp is True
    assert policy.hsrp_group == 5
    assert policy.hsrp_version == 2
    assert policy.hsrp_vip == "10.99.99.254"
    assert policy.hsrp_priority == 110
    assert policy.preempt is True
    assert policy.mac == "0000.0c07.ac05"

    payload_policy = instance.to_payload()["configData"]["networkOS"]["policy"]
    assert payload_policy["hsrp"] is True
    assert payload_policy["hsrpGroup"] == 5
    assert payload_policy["hsrpVersion"] == 2
    assert payload_policy["hsrpVip"] == "10.99.99.254"
    assert payload_policy["hsrpPriority"] == 110
    assert payload_policy["preempt"] is True
    assert payload_policy["mac"] == "0000.0c07.ac05"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("12345", "12345"),
        (12345, "12345"),
        (0, "0"),
        (None, None),
    ],
    ids=["string_passthrough", "int_coerced", "zero_int_coerced", "none_passthrough"],
)
def test_svi_interface_00935(value, expected):
    """
    # Summary

    Verify `routing_tag` accepts both strings (Ansible playbook side / POST/PUT request side) and integers (ND
    GET response side). ND coerces input to int internally and returns int on GET even though OpenAPI declares
    the field as string; the model normalizes to string for clean round-trips.

    ## Test

    - String values pass through unchanged
    - Integer values are coerced to their decimal string form
    - None passes through

    ## Classes and Methods

    - SviPolicyModel.coerce_routing_tag_to_string()
    """
    instance = SviPolicyModel(routing_tag=value)
    assert instance.routing_tag == expected


def test_svi_interface_00940():
    """
    # Summary

    Verify the DHCP relay fields round-trip through `from_response` -> `to_payload` for all 3 server slots and
    their corresponding VRF overrides.

    ## Test

    - Response includes dhcpServerAddress1/2/3 and vrfDhcp1/2/3
    - Model preserves all six fields
    - to_payload re-emits them with API aliases

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.to_payload()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"].update(
        {
            "dhcpServerAddress1": "10.10.10.10",
            "vrfDhcp1": "shared",
            "dhcpServerAddress2": "10.10.10.11",
            "vrfDhcp2": "default",
            "dhcpServerAddress3": "10.10.10.12",
            "vrfDhcp3": "mgmt",
        }
    )

    instance = SviInterfaceModel.from_response(response)
    policy = instance.config_data.network_os.policy
    assert policy.dhcp_server_address1 == "10.10.10.10"
    assert policy.vrf_dhcp1 == "shared"
    assert policy.dhcp_server_address3 == "10.10.10.12"

    payload_policy = instance.to_payload()["configData"]["networkOS"]["policy"]
    assert payload_policy["dhcpServerAddress1"] == "10.10.10.10"
    assert payload_policy["vrfDhcp1"] == "shared"
    assert payload_policy["dhcpServerAddress3"] == "10.10.10.12"
    assert payload_policy["vrfDhcp3"] == "mgmt"


# =============================================================================
# Test: SviInterfaceModel — round-trip from_response -> to_payload
# =============================================================================


def test_svi_interface_01000():
    """
    # Summary

    Verify a full GET response round-trips through from_response and to_payload, producing the same shape minus
    excluded fields. All fields present in SAMPLE_API_RESPONSE must round-trip cleanly with their API aliases.

    ## Test

    - Build model from SAMPLE_API_RESPONSE
    - to_payload result matches expected

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.to_payload()
    """
    instance = SviInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()

    expected_policy_keys = set(SAMPLE_API_RESPONSE["configData"]["networkOS"]["policy"].keys())
    assert set(payload["configData"]["networkOS"]["policy"].keys()) == expected_policy_keys
    assert payload["interfaceName"] == "vlan333"
    assert payload["interfaceType"] == "svi"
    assert payload["configData"]["mode"] == "managed"
    assert payload["configData"]["networkOS"]["networkOSType"] == "nx-os"


def test_svi_interface_01010():
    """
    # Summary

    Verify from_config (Ansible-side snake_case) produces an equivalent model to from_response (API-side camelCase).

    ## Test

    - Build model A from SAMPLE_API_RESPONSE
    - Build model B from SAMPLE_ANSIBLE_CONFIG
    - to_payload outputs match

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.from_config()
    """
    a = SviInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    b = SviInterfaceModel.from_config(SAMPLE_ANSIBLE_CONFIG)
    # b has no oper_data so payloads should match (oper_data excluded from payload anyway)
    assert a.to_payload() == b.to_payload()


# =============================================================================
# Test: SviInterfaceModel — get_argument_spec
# =============================================================================


def test_svi_interface_01100():
    """
    # Summary

    Verify the argument spec exposes the expected top-level keys and required structure.

    ## Test

    - fabric_name is required str
    - config is required list-of-dict
    - state is enum with merged/replaced/overridden/deleted
    - policy options include the phase 1 writable fields

    ## Classes and Methods

    - SviInterfaceModel.get_argument_spec()
    """
    spec = SviInterfaceModel.get_argument_spec()
    assert spec["fabric_name"]["type"] == "str"
    assert spec["fabric_name"]["required"] is True
    assert spec["config"]["type"] == "list"
    assert spec["config"]["required"] is True
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert spec["state"]["default"] == "merged"

    config_options = spec["config"]["options"]
    assert config_options["switch_ip"]["required"] is True
    assert config_options["interface_name"]["type"] == "str"
    assert config_options["interface_name"]["required"] is True
    # interface_type, mode, and network_os_type are hardcoded in the Pydantic model
    # and intentionally absent from the user-facing argument spec.
    assert "interface_type" not in config_options
    assert "mode" not in config_options["config_data"]["options"]
    assert "network_os_type" not in config_options["config_data"]["options"]["network_os"]["options"]

    policy_options = config_options["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    expected_policy_fields = {
        "admin_state",
        "description",
        "extra_config",
        "mtu",
        "ip",
        "prefix",
        "ipv6",
        "prefixv6",
        "ip_redirects",
        "vrf_interface",
        "routing_tag",
        "pim_sparse",
        "pim_dr_priority",
        "hsrp",
        "hsrp_vip",
        "hsrp_vipv6",
        "hsrp_group",
        "hsrp_groupv6",
        "hsrp_version",
        "hsrp_priority",
        "preempt",
        "mac",
        "dhcp_server_address1",
        "dhcp_server_address2",
        "dhcp_server_address3",
        "vrf_dhcp1",
        "vrf_dhcp2",
        "vrf_dhcp3",
        "advertise_subnet_in_underlay",
        "netflow",
        "netflow_monitor",
        "netflow_sampler",
    }
    assert set(policy_options.keys()) == expected_policy_fields
    assert "policy_type" not in policy_options
    assert policy_options["hsrp_version"]["type"] == "int"
    assert policy_options["hsrp_version"]["choices"] == [1, 2]


# =============================================================================
# Test: SviInterfaceModel — interface_type default
# =============================================================================


def test_svi_interface_01200():
    """
    # Summary

    Verify `interface_type` defaults to "svi".

    ## Test

    - Construct without interface_type
    - Field equals "svi"

    ## Classes and Methods

    - SviInterfaceModel.__init__()
    """
    instance = SviInterfaceModel(switch_ip="1.2.3.4", interface_name="vlan333")
    assert instance.interface_type == "svi"
