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
import json
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SviPolicyTypeEnum, XeSviPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import (
    SviConfigDataModel,
    SviInterfaceModel,
    SviNetworkOSModel,
    SviOperDataModel,
    SviPolicyModel,
    XeSviDhcpServerModel,
    XeSviNetworkOSModel,
    XeSviPolicyModel,
    XeSviShutNoShutPolicyModel,
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
        ("smart \u201cquotes\u201d", True),
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
    # `prefix`/`prefixv6` are required-together with `ip`/`ipv6` (see `_validate_ip_prefix_paired`), so supply
    # the paired address when range-testing the mask length in isolation.
    kwargs = {field: value}
    if field == "prefix":
        kwargs.setdefault("ip", "10.1.1.1")
    elif field == "prefixv6":
        kwargs.setdefault("ipv6", "2001:db8::1")
    if should_raise:
        with pytest.raises(ValidationError):
            SviPolicyModel(**kwargs)
    else:
        with does_not_raise():
            instance = SviPolicyModel(**kwargs)
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


def test_svi_interface_00240():
    """
    # Summary

    Verify `_validate_netflow_monitor_present`: `netflow_monitor` is required when `netflow` is true.

    ## Test

    - `netflow=True` without `netflow_monitor` is rejected
    - `netflow=True` with `netflow_monitor` is accepted
    - `netflow=False` (or unset) without `netflow_monitor` is accepted

    ## Classes and Methods

    - SviPolicyModel._validate_netflow_monitor_present()
    """
    with pytest.raises(ValidationError, match="netflow_monitor must be provided when netflow is true"):
        SviPolicyModel(netflow=True)
    with does_not_raise():
        SviPolicyModel(netflow=True, netflow_monitor="MONITOR-1")
        SviPolicyModel(netflow=False)
        SviPolicyModel()


def test_svi_interface_00250():
    """
    # Summary

    Verify `_validate_ip_prefix_paired`: `ip`/`prefix` (and `ipv6`/`prefixv6`) are required together.

    ## Test

    - `ip` without `prefix` is rejected; `prefix` without `ip` is rejected
    - `ipv6` without `prefixv6` is rejected; `prefixv6` without `ipv6` is rejected
    - Both halves of a pair, or neither, is accepted

    ## Classes and Methods

    - SviPolicyModel._validate_ip_prefix_paired()
    """
    with pytest.raises(ValidationError, match="ip and prefix are required together"):
        SviPolicyModel(ip="10.1.1.1")
    with pytest.raises(ValidationError, match="ip and prefix are required together"):
        SviPolicyModel(prefix=24)
    with pytest.raises(ValidationError, match="ipv6 and prefixv6 are required together"):
        SviPolicyModel(ipv6="2001:db8::1")
    with pytest.raises(ValidationError, match="ipv6 and prefixv6 are required together"):
        SviPolicyModel(prefixv6=64)
    with does_not_raise():
        SviPolicyModel(ip="10.1.1.1", prefix=24)
        SviPolicyModel(ipv6="2001:db8::1", prefixv6=64)
        SviPolicyModel()


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

    Verify SviConfigDataModel defaults `network_os` to the NX-OS branch when it is omitted, so playbooks written before the IOS-XE
    branch existed (issue #540) keep selecting `SviNetworkOSModel`.

    ## Test

    - Construct with no network_os
    - `network_os` is an `SviNetworkOSModel` with `network_os_type == "nx-os"` and no policy

    ## Classes and Methods

    - SviConfigDataModel.__init__()
    """
    instance = SviConfigDataModel()
    assert isinstance(instance.network_os, SviNetworkOSModel)
    assert instance.network_os.network_os_type == "nx-os"
    assert instance.network_os.policy is None


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


@pytest.mark.parametrize(
    "value",
    [0, 4095, "0", "9999", "vlan0", "vlan4095", "VLAN9999"],
    ids=["int_zero", "int_above_max", "str_zero", "str_above_max", "prefixed_zero", "prefixed_above_max", "caps_above_max"],
)
def test_svi_interface_00710(value):
    """
    # Summary

    Verify `normalize_interface_name` rejects a VLAN ID outside the controller-supported range 1-4094.

    ## Test

    - An extractable VLAN ID below 1 or above 4094 raises ValidationError

    ## Classes and Methods

    - SviInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match=r"SVI VLAN ID must be in the range 1-4094"):
        SviInterfaceModel(switch_ip="1.2.3.4", interface_name=value)


@pytest.mark.parametrize(
    "value,expected",
    [(1, "vlan1"), (4094, "vlan4094"), ("vlan4094", "vlan4094")],
    ids=["min_boundary", "max_boundary", "prefixed_max_boundary"],
)
def test_svi_interface_00711(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` accepts the VLAN ID range boundaries 1 and 4094.

    ## Test

    - VLAN IDs 1 and 4094 are accepted and normalized to `vlan<id>`

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
        ("x", True),  # non-numeric strings are still rejected; numeric strings are coerced (test 02080, issue #380)
    ],
    ids=["v1_ok", "v2_ok", "below_min_rejected", "above_max_rejected", "non_numeric_string_rejected"],
)
def test_svi_interface_00910(value, should_raise):
    """
    # Summary

    Verify `hsrp_version` is `Literal[1, 2]`: the wire format stays aligned with the OpenAPI schema, which declares `hsrpVersion` as an
    integer. A numeric string is coerced to the integer (the ND 4.3.1 echo, see test 02080); anything else is rejected.

    ## Test

    - Integers 1 and 2 accepted
    - Other integers and the non-numeric string `"x"` rejected by Pydantic

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
    # interface_type and mode are hardcoded in the Pydantic model and intentionally absent from the user-facing argument spec;
    # network_os_type and policy_type are the platform / template discriminators (issue #540).
    assert "interface_type" not in config_options
    assert "mode" not in config_options["config_data"]["options"]
    network_os_options = config_options["config_data"]["options"]["network_os"]["options"]
    assert network_os_options["network_os_type"]["default"] == "nx-os"
    assert network_os_options["network_os_type"]["choices"] == ["nx-os", "ios-xe"]

    policy_options = network_os_options["policy"]["options"]
    expected_policy_fields = {
        "policy_type",
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
        "vlan_name",
        "dhcp_servers",
    }
    assert set(policy_options.keys()) == expected_policy_fields
    assert "required" not in policy_options["policy_type"]
    assert policy_options["policy_type"]["choices"] == ["svi", "iosXeSvi", "iosXeSviShutNoShut"]
    assert policy_options["hsrp_version"]["type"] == "int"
    assert policy_options["hsrp_version"]["choices"] == [1, 2]
    assert policy_options["dhcp_servers"]["type"] == "list"
    assert policy_options["dhcp_servers"]["elements"] == "dict"
    assert policy_options["dhcp_servers"]["options"]["server_ip_address"]["required"] is True
    assert policy_options["dhcp_servers"]["options"]["server_vrf"]["required"] is True


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


# =============================================================================
# Test: IOS-XE branch (issue #540) — enums, union selection, write-strictness, DHCP relay list, hsrpVersion coercion
# =============================================================================


XE_SVI_RESPONSE_421 = {
    "switchIp": "192.168.12.181",
    "interfaceName": "vlan990",
    "interfaceType": "svi",
    "switchId": "CAT9KV1701",
    "configData": {
        "mode": "managed",
        "networkOS": {
            "networkOSType": "ios-xe",
            "policy": {
                "adminState": True,
                "description": "probe-xe-full",
                "dhcpServers": [{"srvrAddr": "10.10.10.10", "srvrVrf": "default"}, {"srvrAddr": "10.10.10.11", "srvrVrf": "global"}],
                "extraConfig": "no shutdown",
                "ip": "10.99.93.1",
                "ipRedirects": False,
                "ipv6": "2001:db8:93::1",
                "ipv6Prefix": 64,
                "policyType": "iosXeSvi",
                "prefix": 24,
                "vlanName": "probe93",
                "vrfInterface": "default",
            },
        },
    },
    "operData": {
        "adminStatus": "unknown",
        "operationalDescription": "Not discovered",
        "operationalStatus": "unknown",
        "portChannelId": -1,
        "switchName": "C1_LE1",
        "vlanRange": "0",
    },
}


def test_svi_interface_02000():
    """
    # Summary

    Verify the SVI policy-type enums carry exactly the create-side wire values on both network OS types.

    ## Test

    - `SviPolicyTypeEnum` has the single NX-OS member `svi`
    - `XeSviPolicyTypeEnum` has `iosXeSvi` and `iosXeSviShutNoShut` (the `iosXeIntVlanTemplate` discriminator minus `userDefined`)

    ## Classes and Methods

    - SviPolicyTypeEnum
    - XeSviPolicyTypeEnum
    """
    assert [e.value for e in SviPolicyTypeEnum] == ["svi"]
    assert [e.value for e in XeSviPolicyTypeEnum] == ["iosXeSvi", "iosXeSviShutNoShut"]


def test_svi_interface_02010():
    """
    # Summary

    Verify `network_os_type: ios-xe` selects the IOS-XE branch and `policy_type` is injected as `iosXeSvi` when omitted (the argspec
    passes an omitted suboption as `None`).

    ## Test

    - from_config with `network_os_type: ios-xe` and `policy_type: None`
    - `config_data.network_os` is `XeSviNetworkOSModel`, policy is `XeSviPolicyModel`
    - `instance.policy_type == "iosXeSvi"`; `policy_type` is in `model_fields_set`
    - `prefixv6` (the shared option name) is stored on the XE branch and serialized as the wire key `ipv6Prefix`

    ## Classes and Methods

    - SviConfigDataModel.default_network_os_type()
    - XeSviNetworkOSModel.default_policy_type()
    - SviInterfaceModel.policy_type
    """
    with does_not_raise():
        instance = SviInterfaceModel.from_config(
            {
                "switch_ip": "192.168.12.181",
                "interface_name": "Vlan990",
                "config_data": {
                    "network_os": {
                        "network_os_type": "ios-xe",
                        "policy": {
                            "policy_type": None,
                            "admin_state": True,
                            "ip": "10.99.90.1",
                            "prefix": 24,
                            "ipv6": "2001:db8:90::1",
                            "prefixv6": 64,
                            "vlan_name": "probe",
                        },
                    }
                },
            }
        )
    assert instance.interface_name == "vlan990"
    assert isinstance(instance.config_data.network_os, XeSviNetworkOSModel)
    assert isinstance(instance.config_data.network_os.policy, XeSviPolicyModel)
    assert instance.policy_type == "iosXeSvi"
    assert "policy_type" in instance.config_data.network_os.policy.model_fields_set
    payload = instance.to_payload()["configData"]["networkOS"]
    assert payload["networkOSType"] == "ios-xe"
    assert payload["policy"]["policyType"] == "iosXeSvi"
    assert payload["policy"]["ipv6Prefix"] == 64
    assert "prefixv6" not in payload["policy"]
    assert payload["policy"]["vlanName"] == "probe"
    assert instance.to_config()["config_data"]["network_os"]["policy"]["prefixv6"] == 64


def test_svi_interface_02020():
    """
    # Summary

    Verify an omitted `network_os_type` still selects the NX-OS branch with `policy_type` injected as `svi`, that `policy_type` is
    visible in `to_config()` output for both branches, and that an IOS-XE response reads back onto the XE branch.

    ## Test

    - from_config without the `network_os` discriminator -> `SviNetworkOSModel`, `svi`
    - `to_config()["config_data"]["network_os"]["policy"]["policy_type"] == "svi"`
    - XE response -> `to_config()` carries `network_os_type == "ios-xe"` and `policy_type == "iosXeSvi"`

    ## Classes and Methods

    - SviPolicyModel.default_policy_type()
    - SviInterfaceModel.to_config()
    - SviInterfaceModel.from_response()
    """
    nx = SviInterfaceModel.from_config(
        {
            "switch_ip": "192.168.1.1",
            "interface_name": "vlan333",
            "config_data": {"network_os": {"policy": {"admin_state": True, "ip": "10.99.99.1", "prefix": 24}}},
        }
    )
    assert isinstance(nx.config_data.network_os, SviNetworkOSModel)
    assert isinstance(nx.config_data.network_os.policy, SviPolicyModel)
    assert nx.policy_type == "svi"
    assert nx.to_config()["config_data"]["network_os"]["policy"]["policy_type"] == "svi"
    assert nx.to_config()["config_data"]["network_os"]["network_os_type"] == "nx-os"
    xe = SviInterfaceModel.from_response(copy.deepcopy(XE_SVI_RESPONSE_421))
    assert isinstance(xe.config_data.network_os, XeSviNetworkOSModel)
    config = xe.to_config()["config_data"]["network_os"]
    assert config["network_os_type"] == "ios-xe"
    assert config["policy"]["policy_type"] == "iosXeSvi"
    assert config["policy"]["prefixv6"] == 64
    assert config["policy"]["vlan_name"] == "probe93"


@pytest.mark.parametrize(
    "os_type, policy, match",
    [
        ("ios-xe", {"policy_type": "svi"}, r"policy_type|policyType"),
        ("nx-os", {"policy_type": "iosXeSvi"}, r"policy_type|policyType"),
        ("ios-xe", {"hsrp": True, "hsrp_vip": "10.0.0.254"}, r"hsrp|Extra inputs"),
        ("ios-xe", {"mtu": 9000}, r"mtu|Extra inputs"),
        ("ios-xe", {"dhcp_server_address1": "10.10.10.10"}, r"dhcp_server_address1|Extra inputs"),
        ("nx-os", {"vlan_name": "x"}, r"vlan_name|Extra inputs"),
        ("nx-os", {"dhcp_servers": [{"server_ip_address": "10.10.10.10", "server_vrf": "default"}]}, r"dhcp_servers|Extra inputs"),
        ("ios-xe", {"policy_type": "iosXeSviShutNoShut", "ip": "10.99.90.1", "prefix": 24}, r"ip|Extra inputs"),
    ],
)
def test_svi_interface_02030(os_type, policy, match):
    """
    # Summary

    Verify both branches are write-strict: a wrong-branch discriminator, an NX-OS-only field on the IOS-XE branch (HSRP, mtu, flat DHCP
    relay), an IOS-XE-only field on the NX-OS branch (`vlan_name`, `dhcp_servers`), and an L3 field on the admin-state-only
    `iosXeSviShutNoShut` template are all rejected before any controller call.

    ## Test

    - Each policy input raises `ValidationError` matching `match`

    ## Classes and Methods

    - SviPolicyModel (extra="forbid")
    - XeSviPolicyModel (extra="forbid")
    - XeSviShutNoShutPolicyModel (extra="forbid")
    """
    with pytest.raises(ValidationError, match=match):
        SviInterfaceModel.from_config(
            {"switch_ip": "192.168.12.181", "interface_name": "vlan990", "config_data": {"network_os": {"network_os_type": os_type, "policy": policy}}}
        )


def test_svi_interface_02040():
    """
    # Summary

    Verify the admin-state-only `iosXeSviShutNoShut` branch: an explicit `policy_type` selects `XeSviShutNoShutPolicyModel`, the payload
    carries only the discriminator and `adminState`, and a controller echo reads back onto the same branch.

    ## Test

    - from_config with `policy_type: iosXeSviShutNoShut`, `admin_state: false`
    - `to_payload()` policy == `{"policyType": "iosXeSviShutNoShut", "adminState": False}`
    - from_response of the echo -> `XeSviShutNoShutPolicyModel`

    ## Classes and Methods

    - XeSviShutNoShutPolicyModel
    - XeSviNetworkOSModel.policy (discriminated on `policy_type`)
    """
    instance = SviInterfaceModel.from_config(
        {
            "switch_ip": "192.168.12.181",
            "interface_name": "vlan991",
            "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"policy_type": "iosXeSviShutNoShut", "admin_state": False}}},
        }
    )
    assert isinstance(instance.config_data.network_os.policy, XeSviShutNoShutPolicyModel)
    assert instance.policy_type == "iosXeSviShutNoShut"
    assert instance.to_payload()["configData"]["networkOS"]["policy"] == {"policyType": "iosXeSviShutNoShut", "adminState": False}
    echo = SviInterfaceModel.from_response(
        {
            "interfaceName": "Vlan991",
            "interfaceType": "svi",
            "switchIp": "192.168.12.181",
            "configData": {"mode": "managed", "networkOS": {"networkOSType": "ios-xe", "policy": {"adminState": False, "policyType": "iosXeSviShutNoShut"}}},
        }
    )
    assert isinstance(echo.config_data.network_os.policy, XeSviShutNoShutPolicyModel)
    assert echo.interface_name == "vlan991"


def test_svi_interface_02050():
    """
    # Summary

    Verify the IOS-XE DHCP relay list: the ND 4.2.1 echo keys `srvrAddr` / `srvrVrf` are read onto the spec fields, config and
    payload dumps carry only the spec spellings (`server_ip_address` / `serverIpAddress`, `server_vrf` / `serverVrf`), and an item without
    a `server_vrf` is rejected.

    # workaround: xe-svi-dhcpservers-echo-keys
    # workaround: xe-svi-dhcpservers-servervrf-required

    ## Test

    - from_response of the 4.2.1 echo -> two `XeSviDhcpServerModel` items with the spec field names populated
    - `to_payload()` emits `serverIpAddress` / `serverVrf` and never `srvrAddr` / `srvrVrf`
    - `to_config()` emits `server_ip_address` / `server_vrf`
    - the 4.3.1 echo (spec keys) reads identically
    - `XeSviDhcpServerModel` without `server_vrf`, or with an empty one, raises `ValidationError`

    ## Classes and Methods

    - XeSviDhcpServerModel.accept_echo_keys()
    - XeSviPolicyModel.dhcp_servers
    """
    xe = SviInterfaceModel.from_response(copy.deepcopy(XE_SVI_RESPONSE_421))
    servers = xe.config_data.network_os.policy.dhcp_servers
    assert [(s.server_ip_address, s.server_vrf) for s in servers] == [("10.10.10.10", "default"), ("10.10.10.11", "global")]
    wire = xe.to_payload()["configData"]["networkOS"]["policy"]["dhcpServers"]
    assert wire == [{"serverIpAddress": "10.10.10.10", "serverVrf": "default"}, {"serverIpAddress": "10.10.10.11", "serverVrf": "global"}]
    assert "srvrAddr" not in json.dumps(xe.to_payload()) and "srvrVrf" not in json.dumps(xe.to_config())
    config = xe.to_config()["config_data"]["network_os"]["policy"]["dhcp_servers"]
    assert config == [{"server_ip_address": "10.10.10.10", "server_vrf": "default"}, {"server_ip_address": "10.10.10.11", "server_vrf": "global"}]
    echo_431 = copy.deepcopy(XE_SVI_RESPONSE_421)
    echo_431["configData"]["networkOS"]["policy"]["dhcpServers"] = wire
    assert SviInterfaceModel.from_response(echo_431).to_config() == xe.to_config()
    with pytest.raises(ValidationError, match=r"server_vrf|serverVrf"):
        XeSviDhcpServerModel(server_ip_address="10.10.10.10")
    with pytest.raises(ValidationError, match=r"server_vrf|serverVrf"):
        XeSviDhcpServerModel(server_ip_address="10.10.10.10", server_vrf="")


def test_svi_interface_02060():
    """
    # Summary

    Verify the IOS-XE `reverse_diff_defaults` scrub: the two defaults ND injects on an `iosXeSvi` echo for fields the user never set
    (`adminState: true`, `ipRedirects: true`, lab-verified on 4.2.1.10 and 4.3.1.175) read back as no user configuration, while a
    non-default value survives. The NX-OS table is unchanged.

    ## Test

    - Echo `{adminState true, ipRedirects true, policyType}` -> `to_reverse_diff_dict()` has no keys beyond `policyType`
    - Echo with `ipRedirects: false` keeps it
    - `SviPolicyModel.reverse_diff_defaults` still carries the NX-OS `int_vlan` defaults

    ## Classes and Methods

    - XeSviPolicyModel.reverse_diff_defaults
    - SviPolicyModel.reverse_diff_defaults
    """
    defaults = XeSviPolicyModel.from_response({"adminState": True, "ipRedirects": True, "policyType": "iosXeSvi"})
    assert set(defaults.to_reverse_diff_dict()) <= {"policyType"}
    custom = XeSviPolicyModel.from_response({"adminState": True, "ipRedirects": False, "policyType": "iosXeSvi"})
    assert custom.to_reverse_diff_dict()["ipRedirects"] is False
    assert XeSviPolicyModel.reverse_diff_defaults == {"adminState": True, "ipRedirects": True}
    assert SviPolicyModel.reverse_diff_defaults["hsrpVersion"] == 1
    assert SviPolicyModel.reverse_diff_defaults["adminState"] is True


def test_svi_interface_02070():
    """
    # Summary

    Verify diff and merge behave across the DHCP relay list: an identical XE model reports no difference, a changed server list is
    a difference, and `merge()` replaces the list wholesale (a merged update that names one server drops the others, matching the
    controller's full-replace PUT semantics).

    ## Test

    - `get_diff` against a deep copy is True (no difference)
    - `get_diff` against a copy with a different `dhcp_servers` list is False
    - `merge()` of a proposed single-server list onto the two-server existing model leaves one server

    ## Classes and Methods

    - SviInterfaceModel.get_diff()
    - SviInterfaceModel.merge()
    """
    existing = SviInterfaceModel.from_response(copy.deepcopy(XE_SVI_RESPONSE_421))
    assert existing.get_diff(copy.deepcopy(existing)) is True
    proposed = SviInterfaceModel.from_config(
        {
            "switch_ip": "192.168.12.181",
            "interface_name": "vlan990",
            "config_data": {
                "network_os": {"network_os_type": "ios-xe", "policy": {"dhcp_servers": [{"server_ip_address": "10.10.10.12", "server_vrf": "default"}]}}
            },
        }
    )
    assert existing.get_diff(proposed, exclude_unset=True) is False
    merged = copy.deepcopy(existing)
    merged.merge(proposed)
    assert [s.server_ip_address for s in merged.config_data.network_os.policy.dhcp_servers] == ["10.10.10.12"]
    assert merged.config_data.network_os.policy.vlan_name == "probe93"


@pytest.mark.parametrize(
    "value, expected, should_raise", [(1, 1, False), (2, 2, False), ("1", 1, False), ("2", 2, False), ("3", None, True), (3, None, True), ("x", None, True)]
)
def test_svi_interface_02080(value, expected, should_raise):
    """
    # Summary

    Verify `hsrp_version` coerces the string ND 4.3.1 echoes (`"1"`) to the integer the spec and the PUT gateway require, and still
    rejects values outside 1-2. Issue #380.

    # workaround: svi-hsrpversion-string-echo-431

    ## Test

    - `1`, `2`, `"1"`, `"2"` parse to the int; `3`, `"3"`, `"x"` raise
    - A 4.3.1-shaped response echo (`hsrpVersion: "1"`) reads and serializes as int `1`

    ## Classes and Methods

    - SviPolicyModel.coerce_hsrp_version_to_int()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            SviPolicyModel(hsrp_version=value)
        return
    assert SviPolicyModel(hsrp_version=value).hsrp_version == expected
    echo = SviPolicyModel.from_response({"policyType": "svi", "adminState": True, "hsrpVersion": str(value)})
    assert echo.hsrp_version == expected
    assert echo.to_payload()["hsrpVersion"] == expected


def test_svi_interface_02090():
    """
    # Summary

    Verify a ND 4.3.1-shaped NX-OS SVI echo (`hsrpVersion: "1"`, no `hsrpGroup` / `pimDrPriority`) reads back onto the NX-OS branch and
    scrubs to no user configuration: the coerced `hsrpVersion: 1` matches the `reverse_diff_defaults` entry.

    # workaround: svi-hsrpversion-string-echo-431

    ## Test

    - from_response succeeds
    - `to_reverse_diff_dict()` of the policy carries nothing beyond `policyType` and the user-set `description` / `ip` / `prefix`

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviPolicyModel.reverse_diff_defaults
    """
    echo = {
        "interfaceName": "vlan990",
        "interfaceType": "svi",
        "switchIp": "192.168.14.131",
        "configData": {
            "mode": "managed",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "adminState": True,
                    "advertiseSubnetInUnderlay": False,
                    "description": "probe380",
                    "hsrpVersion": "1",
                    "ip": "10.99.90.1",
                    "ipRedirects": True,
                    "netflow": False,
                    "pimSparse": False,
                    "policyType": "svi",
                    "preempt": False,
                    "prefix": 24,
                },
            },
        },
    }
    instance = SviInterfaceModel.from_response(echo)
    assert instance.config_data.network_os.policy.hsrp_version == 1
    scrubbed = instance.config_data.network_os.policy.to_reverse_diff_dict()
    assert set(scrubbed) == {"policyType", "description", "ip", "prefix"}


@pytest.mark.parametrize(
    "os_type, length, should_raise",
    [("nx-os", 254, False), ("nx-os", 255, True), ("ios-xe", 200, False), ("ios-xe", 201, True), ("ios-xe", 0, True)],
)
def test_svi_interface_02100(os_type, length, should_raise):
    """
    # Summary

    Verify the per-template `description` limits: 254 on the NX-OS `int_vlan` template, 1-200 on the IOS-XE `ios_xe_int_vlan` template.

    ## Test

    - Boundary lengths are accepted; one past the limit (and the empty IOS-XE string) raise

    ## Classes and Methods

    - SviPolicyModel.description
    - XeSviPolicyModel.description
    """
    model_cls = SviPolicyModel if os_type == "nx-os" else XeSviPolicyModel
    if should_raise:
        with pytest.raises(ValidationError):
            model_cls(description="d" * length)
        return
    assert model_cls(description="d" * length).description == "d" * length


@pytest.mark.parametrize(
    "field, value, extra, should_raise",
    [
        ("ip", "10.99.90.1", {"prefix": 24}, False),
        ("ip", "not-an-ip", {"prefix": 24}, True),
        ("ip", "10.99.90.1/24", {"prefix": 24}, True),
        ("ip", "2001:db8::1", {"prefix": 24}, True),
        ("ipv6", "2001:db8:90::1", {"prefixv6": 64}, False),
        ("ipv6", "also-not-ipv6", {"prefixv6": 64}, True),
        ("ipv6", "2001:db8:90::1/64", {"prefixv6": 64}, True),
        ("ipv6", "10.99.90.1", {"prefixv6": 64}, True),
    ],
)
def test_svi_interface_02110(field, value, extra, should_raise):
    """
    # Summary

    Verify the IOS-XE `iosXeSvi` policy validates `ip` as a bare IPv4 address and `ipv6` as a bare IPv6 address before any controller
    call (PR #571 review). The mask length lives in the sibling `prefix` / `prefixv6` fields, so CIDR input is rejected rather than
    normalized, and the wire value stays the string the user gave.

    ## Test

    - A bare address of the right family is accepted and serialized unchanged
    - Free text, CIDR notation and the other address family raise `ValidationError`

    ## Classes and Methods

    - XeSviPolicyModel.ip
    - XeSviPolicyModel.ipv6
    """
    if should_raise:
        with pytest.raises(ValidationError):
            XeSviPolicyModel(**{field: value}, **extra)
        return
    model = XeSviPolicyModel(**{field: value}, **extra)
    assert getattr(model, field) == value
    assert model.model_dump(by_alias=True, exclude_none=True)[field] == value


@pytest.mark.parametrize(
    "value, should_raise",
    [
        ("10.99.0.10", False),
        ("bad", True),
        ("10.99.0.10/32", True),
        ("2001:db8::10", True),
    ],
)
def test_svi_interface_02120(value, should_raise):
    """
    # Summary

    Verify a `dhcp_servers` entry validates `server_ip_address` as a bare IPv4 address (PR #571 review), on the spec key and on the
    ND 4.2.1 echo key alike.

    ## Test

    - A bare IPv4 address is accepted through `serverIpAddress` and through the echoed `srvrAddr`
    - Free text, CIDR notation and an IPv6 address raise `ValidationError`

    ## Classes and Methods

    - XeSviDhcpServerModel.server_ip_address
    - XeSviDhcpServerModel.accept_echo_keys()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            XeSviDhcpServerModel(serverIpAddress=value, serverVrf="default")
        return
    assert XeSviDhcpServerModel(serverIpAddress=value, serverVrf="default").server_ip_address == value
    assert XeSviDhcpServerModel.model_validate({"srvrAddr": value, "srvrVrf": "default"}).server_ip_address == value
