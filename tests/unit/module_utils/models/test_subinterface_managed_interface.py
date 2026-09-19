# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for subinterface_managed_interface.py

Tests the managed L3 subinterface Pydantic model classes.
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
    SubinterfaceManagedPolicyTypeEnum,
    XeSubinterfacePolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import (
    SubinterfaceManagedConfigDataModel,
    SubinterfaceManagedInterfaceModel,
    SubinterfaceManagedNetworkOSModel,
    SubinterfaceManagedOperDataModel,
    SubinterfaceManagedPolicyModel,
    XeSubinterfaceNetworkOSModel,
    XeSubinterfacePolicyModel,
    XeSubinterfaceShutNoshutPolicyModel,
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
    "interfaceName": "Ethernet1/3.2",
    "interfaceType": "subInterface",
    "switchId": "FDO11111AAA",
    "configData": {
        "mode": "managed",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "subinterface",
                "adminState": True,
                "description": "Sample subinterface",
                "vlanId": 2,
                "ip": "10.20.30.40",
                "ipRedirects": True,
                "netflow": False,
                "pimDrPriority": 1,
                "pimSparse": False,
                "prefix": 24,
            },
        },
    },
    "operData": {
        "adminStatus": "up",
        "operationalDescription": "subinterface is down",
        "operationalStatus": "down",
        "switchName": "LE1",
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "Ethernet1/3.2",
    "interface_type": "subInterface",
    "config_data": {
        "mode": "managed",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "policy_type": "subinterface",
                "admin_state": True,
                "description": "Sample subinterface",
                "vlan_id": 2,
                "ip": "10.20.30.40",
                "ip_redirects": True,
                "netflow": False,
                "pim_dr_priority": 1,
                "pim_sparse": False,
                "prefix": 24,
            },
        },
    },
}


# =============================================================================
# Test: SubinterfaceManagedPolicyModel — initialization and defaults
# =============================================================================


def test_subinterface_managed_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None except `policy_type` which defaults to
    `SubinterfaceManagedPolicyTypeEnum.SUBINTERFACE`.

    ## Test

    - Instantiate with no arguments
    - All optional fields are None
    - policy_type defaults to "subinterface"

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SubinterfaceManagedPolicyModel()
    assert instance.policy_type == SubinterfaceManagedPolicyTypeEnum.SUBINTERFACE
    assert instance.policy_type == "subinterface"
    assert instance.admin_state is None
    assert instance.description is None
    assert instance.extra_config is None
    assert instance.mtu is None
    assert instance.vlan_id is None
    assert instance.vrf_interface is None
    assert instance.ip is None
    assert instance.prefix is None
    assert instance.ipv6 is None
    assert instance.ipv6_prefix is None
    assert instance.routing_tag is None
    assert instance.ip_redirects is None
    assert instance.pim_sparse is None
    assert instance.pim_dr_priority is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None
    assert instance.netflow_sampler is None


def test_subinterface_managed_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SubinterfaceManagedPolicyModel(
            admin_state=True,
            description="test",
            vlan_id=10,
            ip="10.0.0.1",
            prefix=24,
            mtu=9216,
        )
    assert instance.admin_state is True
    assert instance.description == "test"
    assert instance.vlan_id == 10
    assert instance.ip == "10.0.0.1"
    assert instance.prefix == 24
    assert instance.mtu == 9216
    # Hardcoded model default; user no longer supplies this field.
    assert instance.policy_type == "subinterface"


def test_subinterface_managed_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SubinterfaceManagedPolicyModel(
            adminState=True,
            ipRedirects=True,
            pimDrPriority=5,
            vlanId=20,
            policyType="subinterface",
        )
    assert instance.admin_state is True
    assert instance.ip_redirects is True
    assert instance.pim_dr_priority == 5
    assert instance.vlan_id == 20
    assert instance.policy_type == "subinterface"


# =============================================================================
# Test: SubinterfaceManagedPolicyModel — description ASCII validator
# =============================================================================


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("plain ASCII", False),
        ("with-hyphen and 123", False),
        ("", False),
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
def test_subinterface_managed_interface_00130(value, should_raise):
    """
    # Summary

    Verify `description` (typed `AsciiDescription`) rejects any non-ASCII character.

    Cisco backend pipes interface descriptions through CLI generators that 500 on UTF-8. Catching this client-side
    gives users a clear error instead of a generic "unexpected error during policy execution" 500.

    ## Test

    - ASCII strings (including empty and None) accepted
    - Any non-ASCII character (em-dash, smart quotes, emoji, latin-1) raises

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    - models.types.ascii_only()
    """
    if should_raise:
        with pytest.raises(ValidationError, match="description must contain only ASCII"):
            SubinterfaceManagedPolicyModel(description=value)
    else:
        with does_not_raise():
            instance = SubinterfaceManagedPolicyModel(description=value)
        assert instance.description == value


# =============================================================================
# Test: SubinterfaceManagedPolicyModel — range validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("mtu", 576, False),
        ("mtu", 9216, False),
        ("mtu", 575, True),
        ("mtu", 9217, True),
        ("vlan_id", 2, False),
        ("vlan_id", 4094, False),
        ("vlan_id", 1, True),
        ("vlan_id", 4095, True),
        ("prefix", 8, False),
        ("prefix", 31, False),
        ("prefix", 7, True),
        ("prefix", 32, True),
        ("ipv6_prefix", 1, False),
        ("ipv6_prefix", 127, False),
        ("ipv6_prefix", 0, True),
        ("ipv6_prefix", 128, True),
        ("pim_dr_priority", 1, False),
        ("pim_dr_priority", 4294967295, False),
        ("pim_dr_priority", 0, True),
        ("pim_dr_priority", 4294967296, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_subinterface_managed_interface_00220(field, value, should_raise):
    """
    # Summary

    Verify ge/le constraints on every numeric policy field.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected with ValidationError

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    """
    # `prefix`/`ipv6_prefix` are required-together with `ip`/`ipv6` (see `_validate_ip_prefix_paired`), so supply
    # the paired address when range-testing the mask length in isolation.
    kwargs = {field: value}
    if field == "prefix":
        kwargs.setdefault("ip", "10.1.1.1")
    elif field == "ipv6_prefix":
        kwargs.setdefault("ipv6", "2001:db8::1")
    if should_raise:
        with pytest.raises(ValidationError):
            SubinterfaceManagedPolicyModel(**kwargs)
    else:
        with does_not_raise():
            instance = SubinterfaceManagedPolicyModel(**kwargs)
        assert getattr(instance, field) == value


def test_subinterface_managed_interface_00230():
    """
    # Summary

    Verify `description` max_length=254.

    ## Test

    - 254 characters accepted
    - 255 characters rejected

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    """
    with does_not_raise():
        SubinterfaceManagedPolicyModel(description="a" * 254)
    with pytest.raises(ValidationError):
        SubinterfaceManagedPolicyModel(description="a" * 255)


def test_subinterface_managed_interface_00240():
    """
    # Summary

    Verify `vrf_interface` length constraints (min_length=1, max_length=32).

    ## Test

    - 1 and 32 character strings accepted
    - empty string and 33 character string rejected

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.__init__()
    """
    with does_not_raise():
        SubinterfaceManagedPolicyModel(vrf_interface="a")
        SubinterfaceManagedPolicyModel(vrf_interface="a" * 32)
    with pytest.raises(ValidationError):
        SubinterfaceManagedPolicyModel(vrf_interface="")
    with pytest.raises(ValidationError):
        SubinterfaceManagedPolicyModel(vrf_interface="a" * 33)


def test_subinterface_managed_interface_00250():
    """
    # Summary

    Verify `_validate_netflow_monitor_present`: `netflow_monitor` is required when `netflow` is true.

    ## Test

    - `netflow=True` without `netflow_monitor` is rejected
    - `netflow=True` with `netflow_monitor` is accepted
    - `netflow=False` (or unset) without `netflow_monitor` is accepted

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel._validate_netflow_monitor_present()
    """
    with pytest.raises(ValidationError, match="netflow_monitor must be provided when netflow is true"):
        SubinterfaceManagedPolicyModel(netflow=True)
    with does_not_raise():
        SubinterfaceManagedPolicyModel(netflow=True, netflow_monitor="MONITOR-1")
        SubinterfaceManagedPolicyModel(netflow=False)
        SubinterfaceManagedPolicyModel()


def test_subinterface_managed_interface_00260():
    """
    # Summary

    Verify `_validate_ip_prefix_paired`: `ip`/`prefix` (and `ipv6`/`ipv6_prefix`) are required together.

    ## Test

    - `ip` without `prefix` is rejected; `prefix` without `ip` is rejected
    - `ipv6` without `ipv6_prefix` is rejected; `ipv6_prefix` without `ipv6` is rejected
    - Both halves of a pair, or neither, is accepted

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel._validate_ip_prefix_paired()
    """
    with pytest.raises(ValidationError, match="ip and prefix are required together"):
        SubinterfaceManagedPolicyModel(ip="10.1.1.1")
    with pytest.raises(ValidationError, match="ip and prefix are required together"):
        SubinterfaceManagedPolicyModel(prefix=24)
    with pytest.raises(ValidationError, match="ipv6 and ipv6_prefix are required together"):
        SubinterfaceManagedPolicyModel(ipv6="2001:db8::1")
    with pytest.raises(ValidationError, match="ipv6 and ipv6_prefix are required together"):
        SubinterfaceManagedPolicyModel(ipv6_prefix=64)
    with does_not_raise():
        SubinterfaceManagedPolicyModel(ip="10.1.1.1", prefix=24)
        SubinterfaceManagedPolicyModel(ipv6="2001:db8::1", ipv6_prefix=64)
        SubinterfaceManagedPolicyModel()


# =============================================================================
# Test: SubinterfaceManagedPolicyModel — payload / config serialization
# =============================================================================


def test_subinterface_managed_interface_00300():
    """
    # Summary

    Verify `to_payload`-style serialization (model_dump with aliases, exclude_none) emits camelCase keys.

    ## Test

    - Construct with snake_case
    - Dump with by_alias=True
    - Output uses API camelCase keys

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.model_dump()
    """
    instance = SubinterfaceManagedPolicyModel(
        admin_state=True,
        description="payload",
        vlan_id=30,
        ip_redirects=True,
        pim_dr_priority=2,
    )
    data = instance.model_dump(by_alias=True, exclude_none=True)
    assert data["adminState"] is True
    assert data["description"] == "payload"
    assert data["vlanId"] == 30
    assert data["ipRedirects"] is True
    assert data["pimDrPriority"] == 2
    assert "admin_state" not in data
    assert "ip_redirects" not in data


# =============================================================================
# Test: SubinterfaceManagedPolicyModel — routing_tag int->str coercion
# =============================================================================


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
def test_subinterface_managed_interface_00310(value, expected):
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

    - SubinterfaceManagedPolicyModel.coerce_routing_tag_to_string()
    """
    instance = SubinterfaceManagedPolicyModel(routing_tag=value)
    assert instance.routing_tag == expected


# =============================================================================
# Test: SubinterfaceManagedNetworkOSModel
# =============================================================================


def test_subinterface_managed_interface_00400():
    """
    # Summary

    Verify default values for SubinterfaceManagedNetworkOSModel.

    ## Test

    - network_os_type defaults to "nx-os"
    - policy defaults to None

    ## Classes and Methods

    - SubinterfaceManagedNetworkOSModel.__init__()
    """
    instance = SubinterfaceManagedNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert instance.policy is None


def test_subinterface_managed_interface_00410():
    """
    # Summary

    Verify SubinterfaceManagedNetworkOSModel accepts a SubinterfaceManagedPolicyModel as the `policy` field.

    ## Test

    - Pass a populated policy
    - Access through the network OS container

    ## Classes and Methods

    - SubinterfaceManagedNetworkOSModel.__init__()
    """
    policy = SubinterfaceManagedPolicyModel(admin_state=True, description="net-os")
    instance = SubinterfaceManagedNetworkOSModel(policy=policy)
    assert instance.policy is not None
    assert instance.policy.admin_state is True
    assert instance.policy.description == "net-os"


# =============================================================================
# Test: SubinterfaceManagedConfigDataModel
# =============================================================================


def test_subinterface_managed_interface_00500():
    """
    # Summary

    Verify SubinterfaceManagedConfigDataModel defaults — `mode` is "managed" and `network_os` is required.

    ## Test

    - Construct with only network_os
    - mode defaults to "managed"

    ## Classes and Methods

    - SubinterfaceManagedConfigDataModel.__init__()
    """
    nos = SubinterfaceManagedNetworkOSModel(policy=SubinterfaceManagedPolicyModel(admin_state=True))
    instance = SubinterfaceManagedConfigDataModel(network_os=nos)
    assert instance.mode == "managed"
    assert instance.network_os is not None


def test_subinterface_managed_interface_00510():
    """
    # Summary

    Verify SubinterfaceManagedConfigDataModel rejects construction without network_os.

    ## Test

    - Construct with no network_os
    - ValidationError raised

    ## Classes and Methods

    - SubinterfaceManagedConfigDataModel.__init__()
    """
    with pytest.raises(ValidationError):
        SubinterfaceManagedConfigDataModel()  # network_os is required


# =============================================================================
# Test: SubinterfaceManagedOperDataModel — read-only operational data
# =============================================================================


def test_subinterface_managed_interface_00600():
    """
    # Summary

    Verify SubinterfaceManagedOperDataModel parses GET-side aliases.

    ## Test

    - Construct with camelCase aliases
    - Access by snake_case fields

    ## Classes and Methods

    - SubinterfaceManagedOperDataModel.__init__()
    """
    instance = SubinterfaceManagedOperDataModel(
        adminStatus="up",
        operationalDescription="subinterface is down",
        operationalStatus="down",
        switchName="LE1",
    )
    assert instance.admin_status == "up"
    assert instance.operational_description == "subinterface is down"
    assert instance.operational_status == "down"
    assert instance.switch_name == "LE1"


# =============================================================================
# Test: SubinterfaceManagedInterfaceModel — interface_name normalization
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Ethernet1/3.2", "Ethernet1/3.2"),
        ("ethernet1/3.2", "Ethernet1/3.2"),
        ("ETHERNET1/3.2", "Ethernet1/3.2"),
        ("eThErNeT1/3.2", "Ethernet1/3.2"),
        ("Port-channel10.5", "Port-channel10.5"),
        ("port-channel10.5", "Port-channel10.5"),
        ("PORT-CHANNEL10.5", "Port-channel10.5"),
        ("  Ethernet1/3.2  ", "Ethernet1/3.2"),
    ],
    ids=[
        "ethernet_canonical_passthrough",
        "ethernet_lowercase",
        "ethernet_uppercase",
        "ethernet_mixed_case",
        "portchannel_canonical_passthrough",
        "portchannel_lowercase",
        "portchannel_uppercase",
        "ethernet_padded",
    ],
)
def test_subinterface_managed_interface_00700(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` canonicalizes the parent prefix capitalization while preserving the
    dot-separated sub-id (e.g. `ethernet1/3.2` -> `Ethernet1/3.2`, `port-channel10.5` -> `Port-channel10.5`).

    ## Test

    - Any-cased Ethernet/Port-channel parents normalize to canonical capitalization
    - Surrounding whitespace is stripped
    - The `.<sub>` segment is preserved

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.normalize_interface_name()
    """
    instance = SubinterfaceManagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)
    assert instance.interface_name == expected


def test_subinterface_managed_interface_00710():
    """
    # Summary

    Verify `normalize_interface_name` rejects a name without a dot-separated sub-id.

    ## Test

    - A parent-only name (no `.<sub>`) raises ValidationError mentioning the dot-separated requirement

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match="must include a dot-separated subinterface id"):
        SubinterfaceManagedInterfaceModel(switch_ip="1.2.3.4", interface_name="Ethernet1/3")


@pytest.mark.parametrize(
    "value",
    ["Loopback0.1", "Vlan10.2", "mgmt0.3", "Tunnel1.4", "HundredGigE1/0/25.7"],
    ids=["loopback", "vlan", "mgmt", "tunnel", "hundredgig"],
)
def test_subinterface_managed_interface_00720(value):
    """
    # Summary

    Verify `normalize_interface_name` passes a parent that is not a case-insensitive prefix of exactly one canonical name
    (`Ethernet`, `GigabitEthernet`, `Port-channel`) through verbatim rather than re-casing or rejecting it, so correctly typed
    Catalyst families the canonical list does not know (e.g. `HundredGigE`) are never corrupted; ND validates the parent itself.

    ## Test

    - A dotted name on any other parent is stored unchanged

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.normalize_interface_name()
    """
    instance = SubinterfaceManagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)
    assert instance.interface_name == value


# =============================================================================
# Test: SubinterfaceManagedInterfaceModel — composite identifier
# =============================================================================


def test_subinterface_managed_interface_00800():
    """
    # Summary

    Verify identifier configuration: composite `(switch_ip, interface_name)`.

    ## Test

    - identifier_strategy is "composite"
    - identifiers is ["switch_ip", "interface_name"]
    - get_identifier_value returns the tuple

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel — class attributes
    - SubinterfaceManagedInterfaceModel.get_identifier_value()
    """
    assert SubinterfaceManagedInterfaceModel.identifier_strategy == "composite"
    assert SubinterfaceManagedInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    instance = SubinterfaceManagedInterfaceModel(switch_ip="1.2.3.4", interface_name="Ethernet1/3.2")
    assert instance.get_identifier_value() == ("1.2.3.4", "Ethernet1/3.2")


def test_subinterface_managed_interface_00810():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip` and `oper_data` from `to_payload`.

    ## Test

    - Construct from a full GET response
    - to_payload omits switchIp and operData

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.to_payload()
    """
    instance = SubinterfaceManagedInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert "switchIp" not in payload
    assert "operData" not in payload
    # Verify the remaining top-level shape
    assert payload["interfaceName"] == "Ethernet1/3.2"
    assert payload["interfaceType"] == "subInterface"


# =============================================================================
# Test: SubinterfaceManagedInterfaceModel — from_response robustness
# =============================================================================


def test_subinterface_managed_interface_00900():
    """
    # Summary

    Verify `from_response` is robust to missing nested structures.

    ## Test

    - Response with no configData
    - Response with configData but no policy
    - Both return a valid model without raising

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.from_response()
    """
    minimal = {
        "switchIp": "1.2.3.4",
        "interfaceName": "Ethernet1/3.2",
        "switchId": "X",
    }
    with does_not_raise():
        SubinterfaceManagedInterfaceModel.from_response(minimal)

    no_policy = copy.deepcopy(minimal)
    no_policy["configData"] = {"mode": "managed", "networkOS": {"networkOSType": "nx-os"}}
    with does_not_raise():
        SubinterfaceManagedInterfaceModel.from_response(no_policy)


def test_subinterface_managed_interface_00910():
    """
    # Summary

    Verify a populated policy round-trips through `from_response` -> `to_payload` with all fields preserved.

    ## Test

    - Response includes vlan_id, ip, prefix, PIM, netflow fields
    - After from_response, every field is reachable on the model
    - to_payload re-emits every field with API names

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.from_response()
    - SubinterfaceManagedInterfaceModel.to_payload()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"].update(
        {
            "mtu": 9216,
            "vrfInterface": "tenant_a",
            "ipv6": "2001:db8::1",
            "ipv6Prefix": 64,
            "routingTag": "12345",
            "netflow": True,
            "netflowMonitor": "MON1",
        }
    )

    instance = SubinterfaceManagedInterfaceModel.from_response(response)
    policy = instance.config_data.network_os.policy
    assert policy.mtu == 9216
    assert policy.vrf_interface == "tenant_a"
    assert policy.ipv6 == "2001:db8::1"
    assert policy.ipv6_prefix == 64
    assert policy.routing_tag == "12345"
    assert policy.netflow is True
    assert policy.netflow_monitor == "MON1"

    payload_policy = instance.to_payload()["configData"]["networkOS"]["policy"]
    assert payload_policy["mtu"] == 9216
    assert payload_policy["vrfInterface"] == "tenant_a"
    assert payload_policy["ipv6"] == "2001:db8::1"
    assert payload_policy["ipv6Prefix"] == 64
    assert payload_policy["routingTag"] == "12345"
    assert payload_policy["netflow"] is True
    assert payload_policy["netflowMonitor"] == "MON1"


# =============================================================================
# Test: SubinterfaceManagedInterfaceModel — round-trip from_response -> to_payload
# =============================================================================


def test_subinterface_managed_interface_01000():
    """
    # Summary

    Verify a full GET response round-trips through from_response and to_payload, producing the same shape minus
    excluded fields. All fields present in SAMPLE_API_RESPONSE must round-trip cleanly with their API aliases; the payload additionally
    carries the `mtu` template default the NX-OS branch always emits (`payload_defaults`).

    ## Test

    - Build model from SAMPLE_API_RESPONSE
    - to_payload result matches expected, plus `mtu: 9216`

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.from_response()
    - SubinterfaceManagedInterfaceModel.to_payload()
    """
    instance = SubinterfaceManagedInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()

    expected_policy_keys = set(SAMPLE_API_RESPONSE["configData"]["networkOS"]["policy"].keys()) | {"mtu"}
    assert set(payload["configData"]["networkOS"]["policy"].keys()) == expected_policy_keys
    assert payload["configData"]["networkOS"]["policy"]["mtu"] == 9216
    assert payload["interfaceName"] == "Ethernet1/3.2"
    assert payload["interfaceType"] == "subInterface"
    assert payload["configData"]["mode"] == "managed"
    assert payload["configData"]["networkOS"]["networkOSType"] == "nx-os"


def test_subinterface_managed_interface_01010():
    """
    # Summary

    Verify from_config (Ansible-side snake_case) produces an equivalent model to from_response (API-side camelCase).

    ## Test

    - Build model A from SAMPLE_API_RESPONSE
    - Build model B from SAMPLE_ANSIBLE_CONFIG
    - to_payload outputs match

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.from_response()
    - SubinterfaceManagedInterfaceModel.from_config()
    """
    a = SubinterfaceManagedInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    b = SubinterfaceManagedInterfaceModel.from_config(SAMPLE_ANSIBLE_CONFIG)
    # b has no oper_data so payloads should match (oper_data excluded from payload anyway)
    assert a.to_payload() == b.to_payload()


# =============================================================================
# Test: SubinterfaceManagedInterfaceModel — get_argument_spec
# =============================================================================


def test_subinterface_managed_interface_01100():
    """
    # Summary

    Verify the argument spec exposes the expected top-level keys and required structure.

    ## Test

    - fabric_name is required str
    - config is required list-of-dict
    - state is enum with merged/replaced/overridden/deleted
    - policy options include the writable fields and exclude the hardcoded discriminators

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.get_argument_spec()
    """
    spec = SubinterfaceManagedInterfaceModel.get_argument_spec()
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
    # interface_type and mode are hardcoded in the Pydantic model and intentionally absent from the user-facing
    # argument spec; network_os_type and policy_type are the platform / template discriminators (issue #541).
    assert "interface_type" not in config_options
    assert "mode" not in config_options["config_data"]["options"]
    network_os_options = config_options["config_data"]["options"]["network_os"]["options"]
    assert network_os_options["network_os_type"] == {"type": "str", "default": "nx-os", "choices": ["nx-os", "ios-xe"]}

    policy_options = network_os_options["policy"]["options"]
    expected_policy_fields = {
        "policy_type",
        "admin_state",
        "description",
        "extra_config",
        "mtu",
        "vlan_id",
        "vrf_interface",
        "ip",
        "prefix",
        "ipv6",
        "ipv6_prefix",
        "routing_tag",
        "ip_redirects",
        "pim_sparse",
        "pim_dr_priority",
        "netflow",
        "netflow_monitor",
        "netflow_sampler",
    }
    assert set(policy_options.keys()) == expected_policy_fields
    assert policy_options["policy_type"] == {"type": "str", "choices": ["subinterface", "iosXeSubinterface", "iosXeSubinterfaceShutNoshut"]}
    assert policy_options["vlan_id"]["type"] == "int"


# =============================================================================
# Test: SubinterfaceManagedInterfaceModel — interface_type default
# =============================================================================


def test_subinterface_managed_interface_01200():
    """
    # Summary

    Verify `interface_type` defaults to "subInterface".

    ## Test

    - Construct without interface_type
    - Field equals "subInterface"

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.__init__()
    """
    instance = SubinterfaceManagedInterfaceModel(switch_ip="1.2.3.4", interface_name="Ethernet1/3.2")
    assert instance.interface_type == "subInterface"


# =============================================================================
# Test: IOS-XE branch (issue #541) — enums, union dispatch, write-strictness, ranges, Catalyst parent names
# =============================================================================

XE_SUBIF_RESPONSE = {
    "interfaceName": "GigabitEthernet1/0/2.100",
    "interfaceType": "subInterface",
    "switchIp": "192.168.12.181",
    "switchId": "CAT9KV1701",
    "configData": {
        "mode": "managed",
        "networkOS": {
            "networkOSType": "ios-xe",
            "policy": {
                "policyType": "iosXeSubinterface",
                "adminState": True,
                "description": "probe100",
                "vlanId": 100,
                "ip": "10.99.100.1",
                "prefix": 24,
                "ipv6": "2001:db8:100::1",
                "ipv6Prefix": 64,
                "vrfInterface": "default",
            },
        },
    },
    "operData": {"adminStatus": "up", "operationalStatus": "up", "switchName": "C1_LE1"},
}


def test_subinterface_managed_interface_02000():
    """
    # Summary

    Verify the managed-subinterface policy-type enums carry exactly the create-side wire values on both network OS types.

    ## Test

    - `SubinterfaceManagedPolicyTypeEnum` has the single NX-OS member `subinterface`
    - `XeSubinterfacePolicyTypeEnum` has `iosXeSubinterface` and `iosXeSubinterfaceShutNoshut` (the
      `createInterfaceSubInterfaceManagedXeType` discriminator minus the ND-internal `iosXeInternalSubinterface` and `userDefined`)

    ## Classes and Methods

    - SubinterfaceManagedPolicyTypeEnum
    - XeSubinterfacePolicyTypeEnum
    """
    assert [e.value for e in SubinterfaceManagedPolicyTypeEnum] == ["subinterface"]
    assert [e.value for e in XeSubinterfacePolicyTypeEnum] == ["iosXeSubinterface", "iosXeSubinterfaceShutNoshut"]


def test_subinterface_managed_interface_02010():
    """
    # Summary

    Verify `network_os_type: ios-xe` selects the IOS-XE branch and `policy_type` is injected as `iosXeSubinterface` when omitted (the
    argspec passes an omitted suboption as `None`).

    ## Test

    - from_config with `network_os_type: ios-xe` and `policy_type: None`
    - `config_data.network_os` is `XeSubinterfaceNetworkOSModel`, policy is `XeSubinterfacePolicyModel`
    - `instance.policy_type == "iosXeSubinterface"`; `policy_type` is in `model_fields_set`
    - The payload carries `networkOSType: ios-xe`, the injected `policyType` and the wire key `ipv6Prefix`

    ## Classes and Methods

    - SubinterfaceManagedConfigDataModel.default_network_os_type()
    - XeSubinterfaceNetworkOSModel.default_policy_type()
    - SubinterfaceManagedInterfaceModel.policy_type
    """
    with does_not_raise():
        instance = SubinterfaceManagedInterfaceModel.from_config(
            {
                "switch_ip": "192.168.12.181",
                "interface_name": "GigabitEthernet1/0/2.100",
                "config_data": {
                    "network_os": {
                        "network_os_type": "ios-xe",
                        "policy": {
                            "policy_type": None,
                            "admin_state": True,
                            "vlan_id": 100,
                            "ip": "10.99.100.1",
                            "prefix": 24,
                            "ipv6": "2001:db8:100::1",
                            "ipv6_prefix": 64,
                            "vrf_interface": "default",
                        },
                    }
                },
            }
        )
    assert isinstance(instance.config_data.network_os, XeSubinterfaceNetworkOSModel)
    assert isinstance(instance.config_data.network_os.policy, XeSubinterfacePolicyModel)
    assert instance.policy_type == "iosXeSubinterface"
    assert "policy_type" in instance.config_data.network_os.policy.model_fields_set
    payload = instance.to_payload()["configData"]["networkOS"]
    assert payload["networkOSType"] == "ios-xe"
    assert payload["policy"]["policyType"] == "iosXeSubinterface"
    assert payload["policy"]["ipv6Prefix"] == 64
    assert payload["policy"]["vlanId"] == 100
    assert instance.to_config()["config_data"]["network_os"]["policy"]["ipv6_prefix"] == 64


def test_subinterface_managed_interface_02020():
    """
    # Summary

    Verify an omitted `network_os_type` still selects the NX-OS branch with `policy_type` injected as `subinterface`, that `policy_type`
    is visible in `to_config()` output for both branches, and that an IOS-XE response reads back onto the XE branch.

    ## Test

    - from_config without the `network_os` discriminator -> `SubinterfaceManagedNetworkOSModel`, `subinterface`
    - `to_config()["config_data"]["network_os"]["policy"]["policy_type"] == "subinterface"`
    - XE response -> `to_config()` carries `network_os_type == "ios-xe"` and `policy_type == "iosXeSubinterface"`

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.default_policy_type()
    - SubinterfaceManagedInterfaceModel.to_config()
    - SubinterfaceManagedInterfaceModel.from_response()
    """
    nx = SubinterfaceManagedInterfaceModel.from_config(
        {
            "switch_ip": "192.168.1.1",
            "interface_name": "Ethernet1/3.2",
            "config_data": {"network_os": {"policy": {"admin_state": True, "vlan_id": 2, "ip": "10.20.30.40", "prefix": 24}}},
        }
    )
    assert isinstance(nx.config_data.network_os, SubinterfaceManagedNetworkOSModel)
    assert isinstance(nx.config_data.network_os.policy, SubinterfaceManagedPolicyModel)
    assert nx.policy_type == "subinterface"
    assert nx.to_config()["config_data"]["network_os"]["policy"]["policy_type"] == "subinterface"
    assert nx.to_config()["config_data"]["network_os"]["network_os_type"] == "nx-os"
    xe = SubinterfaceManagedInterfaceModel.from_response(copy.deepcopy(XE_SUBIF_RESPONSE))
    assert isinstance(xe.config_data.network_os, XeSubinterfaceNetworkOSModel)
    assert xe.interface_name == "GigabitEthernet1/0/2.100"
    config = xe.to_config()["config_data"]["network_os"]
    assert config["network_os_type"] == "ios-xe"
    assert config["policy"]["policy_type"] == "iosXeSubinterface"
    assert config["policy"]["ipv6_prefix"] == 64
    assert config["policy"]["vlan_id"] == 100


@pytest.mark.parametrize(
    "os_type, policy, match",
    [
        ("ios-xe", {"policy_type": "subinterface"}, r"policy_type|policyType"),
        ("nx-os", {"policy_type": "iosXeSubinterface"}, r"policy_type|policyType"),
        ("ios-xe", {"mtu": 9000}, r"mtu|Extra inputs"),
        ("ios-xe", {"routing_tag": "100"}, r"routing_tag|Extra inputs"),
        ("ios-xe", {"ip_redirects": True}, r"ip_redirects|Extra inputs"),
        ("ios-xe", {"pim_sparse": True}, r"pim_sparse|Extra inputs"),
        ("ios-xe", {"pim_dr_priority": 5}, r"pim_dr_priority|Extra inputs"),
        ("ios-xe", {"netflow": True, "netflow_monitor": "m"}, r"netflow|Extra inputs"),
        ("ios-xe", {"policy_type": "iosXeSubinterfaceShutNoshut", "vlan_id": 100}, r"vlan_id|Extra inputs"),
        ("ios-xe", {"policy_type": "iosXeSubinterfaceShutNoshut", "ip": "10.99.100.1", "prefix": 24}, r"ip|Extra inputs"),
    ],
)
def test_subinterface_managed_interface_02030(os_type, policy, match):
    """
    # Summary

    Verify both branches are write-strict: a wrong-branch discriminator, an NX-OS-only field on the IOS-XE branch (mtu, routing tag,
    ip-redirects, PIM, Netflow), and an L3 field on the admin-state-only `iosXeSubinterfaceShutNoshut` template are all rejected
    before any controller call.

    ## Test

    - Each policy input raises `ValidationError` matching `match`

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel (extra="forbid")
    - XeSubinterfacePolicyModel (extra="forbid")
    - XeSubinterfaceShutNoshutPolicyModel (extra="forbid")
    """
    with pytest.raises(ValidationError, match=match):
        SubinterfaceManagedInterfaceModel.from_config(
            {
                "switch_ip": "192.168.12.181",
                "interface_name": "GigabitEthernet1/0/2.100",
                "config_data": {"network_os": {"network_os_type": os_type, "policy": policy}},
            }
        )


def test_subinterface_managed_interface_02040():
    """
    # Summary

    Verify the admin-state-only `iosXeSubinterfaceShutNoshut` branch: an explicit `policy_type` selects
    `XeSubinterfaceShutNoshutPolicyModel`, the payload carries only the discriminator and `adminState`, and a controller echo reads back
    onto the same branch.

    ## Test

    - from_config with `policy_type: iosXeSubinterfaceShutNoshut`, `admin_state: false`
    - `to_payload()` policy == `{"policyType": "iosXeSubinterfaceShutNoshut", "adminState": False}`
    - from_response of the echo -> `XeSubinterfaceShutNoshutPolicyModel`

    ## Classes and Methods

    - XeSubinterfaceShutNoshutPolicyModel
    - XeSubinterfaceNetworkOSModel.policy (discriminated on `policy_type`)
    """
    instance = SubinterfaceManagedInterfaceModel.from_config(
        {
            "switch_ip": "192.168.12.181",
            "interface_name": "GigabitEthernet1/0/2.101",
            "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"policy_type": "iosXeSubinterfaceShutNoshut", "admin_state": False}}},
        }
    )
    assert isinstance(instance.config_data.network_os.policy, XeSubinterfaceShutNoshutPolicyModel)
    assert instance.policy_type == "iosXeSubinterfaceShutNoshut"
    assert instance.to_payload()["configData"]["networkOS"]["policy"] == {"policyType": "iosXeSubinterfaceShutNoshut", "adminState": False}
    echo = SubinterfaceManagedInterfaceModel.from_response(
        {
            "interfaceName": "GigabitEthernet1/0/2.101",
            "interfaceType": "subInterface",
            "switchIp": "192.168.12.181",
            "configData": {
                "mode": "managed",
                "networkOS": {"networkOSType": "ios-xe", "policy": {"adminState": False, "policyType": "iosXeSubinterfaceShutNoshut"}},
            },
        }
    )
    assert isinstance(echo.config_data.network_os.policy, XeSubinterfaceShutNoshutPolicyModel)
    assert echo.policy_type == "iosXeSubinterfaceShutNoshut"


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("vlan_id", 1, False),
        ("vlan_id", 4094, False),
        ("vlan_id", 0, True),
        ("vlan_id", 4095, True),
        ("ipv6_prefix", 64, False),
        ("ipv6_prefix", 127, False),
        ("ipv6_prefix", 63, True),
        ("ipv6_prefix", 128, True),
        ("prefix", 8, False),
        ("prefix", 31, False),
        ("prefix", 7, True),
        ("prefix", 32, True),
        ("description", "d" * 200, False),
        ("description", "d" * 201, True),
        ("vrf_interface", "v" * 32, False),
        ("vrf_interface", "v" * 33, True),
    ],
    ids=lambda v: str(v)[:12] if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_subinterface_managed_interface_02050(field, value, should_raise):
    """
    # Summary

    Verify the IOS-XE `iosXeSubinterface` branch enforces the `ios_xe_int_subintf` template ranges, which differ from the NX-OS
    `int_subif` template: `vlanId` 1-4094 (NX-OS 2-4094), `ipv6Prefix` 64-127 (NX-OS 1-127), `prefix` 8-31, `description` 1-200
    characters (NX-OS 254), `vrfInterface` 1-32 characters.

    ## Test

    - In-range values are accepted, out-of-range values raise `ValidationError`

    ## Classes and Methods

    - XeSubinterfacePolicyModel
    """
    kwargs = {field: value}
    if field == "prefix":
        kwargs["ip"] = "10.99.100.1"
    if field == "ipv6_prefix":
        kwargs["ipv6"] = "2001:db8:100::1"
    if should_raise:
        with pytest.raises(ValidationError):
            XeSubinterfacePolicyModel(**kwargs)
    else:
        with does_not_raise():
            instance = XeSubinterfacePolicyModel(**kwargs)
        assert getattr(instance, field) == value


@pytest.mark.parametrize(
    "value,expected",
    [
        ("GigabitEthernet1/0/2.100", "GigabitEthernet1/0/2.100"),
        ("gigabitethernet1/0/2.100", "GigabitEthernet1/0/2.100"),
        ("gi1/0/2.100", "GigabitEthernet1/0/2.100"),
        ("TenGigabitEthernet1/0/1.5", "TenGigabitEthernet1/0/1.5"),
        ("te1/0/1.5", "TenGigabitEthernet1/0/1.5"),
        ("twe1/0/1.5", "TwentyFiveGigE1/0/1.5"),
        ("fo1/0/1.2", "FortyGigabitEthernet1/0/1.2"),
        ("hu1/0/25.7", "HundredGigE1/0/25.7"),
        ("t1/0/1.5", "t1/0/1.5"),
        ("eth1/3.2", "Ethernet1/3.2"),
        ("po10.5", "Port-channel10.5"),
    ],
    ids=[
        "gig_canonical",
        "gig_lowercase",
        "gig_short",
        "tengig_canonical",
        "tengig_short",
        "twentyfivegig_short",
        "fortygig_short",
        "hundredgig_short",
        "ambiguous_t_verbatim",
        "eth_short",
        "po_short",
    ],
)
def test_subinterface_managed_interface_02060(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` accepts the Catalyst IOS-XE parent families: a prefix that is a case-insensitive prefix of exactly
    one canonical name (`Ethernet`, `Port-channel` and the Catalyst `...GigabitEthernet` / `...GigE` families) is expanded to it, an
    ambiguous abbreviation (`t` matches several) passes through verbatim, and the dot-separated sub-id is preserved. ND removes an
    IOS-XE subinterface from the switch only under its canonical spelling (lab 2026-09-16), so the expansion is what makes delete work.

    ## Test

    - Each input normalizes to `expected`

    ## Classes and Methods

    - SubinterfaceManagedInterfaceModel.normalize_interface_name()
    """
    instance = SubinterfaceManagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)
    assert instance.interface_name == expected


def test_subinterface_managed_interface_02070():
    """
    # Summary

    Verify the IOS-XE branch's `_validate_ip_prefix_paired` rejects a half-supplied address pair on either family, matching the NX-OS
    branch.

    ## Test

    - `ip` without `prefix` raises; `ipv6_prefix` without `ipv6` raises

    ## Classes and Methods

    - XeSubinterfacePolicyModel._validate_ip_prefix_paired()
    """
    with pytest.raises(ValidationError, match="ip and prefix are required together"):
        XeSubinterfacePolicyModel(ip="10.99.100.1")
    with pytest.raises(ValidationError, match="ipv6 and ipv6_prefix are required together"):
        XeSubinterfacePolicyModel(ipv6_prefix=64)


def test_subinterface_managed_interface_02080():
    """
    # Summary

    Verify the NX-OS `subinterface` branch always emits the `int_subif` template default `mtu: 9216` on the wire when the user did not set
    it (ND 4.3.1 rejects a create that omits `mtu`, "Validation failed for following fields: [mtu]"; 4.2.1 stored 9216 either way), while
    an explicit `mtu` is sent as given and the IOS-XE branch, whose template has no `mtu`, is unaffected.

    ## Test

    - NX-OS policy without `mtu` -> payload carries `mtu == 9216`, `to_config()` does not (payload-only default)
    - NX-OS policy with `mtu: 1500` -> payload carries 1500
    - IOS-XE policy -> payload carries no `mtu`

    ## Classes and Methods

    - SubinterfaceManagedPolicyModel.payload_defaults
    - NDBaseModel.to_payload()
    """
    nx = SubinterfaceManagedInterfaceModel.from_config(
        {
            "switch_ip": "192.168.1.1",
            "interface_name": "Ethernet1/3.2",
            "config_data": {"network_os": {"policy": {"vlan_id": 2, "ip": "10.20.30.40", "prefix": 24}}},
        }
    )
    assert nx.to_payload()["configData"]["networkOS"]["policy"]["mtu"] == 9216
    assert "mtu" not in nx.to_config()["config_data"]["network_os"]["policy"]
    nx_explicit = SubinterfaceManagedInterfaceModel.from_config(
        {"switch_ip": "192.168.1.1", "interface_name": "Ethernet1/3.2", "config_data": {"network_os": {"policy": {"vlan_id": 2, "mtu": 1500}}}}
    )
    assert nx_explicit.to_payload()["configData"]["networkOS"]["policy"]["mtu"] == 1500
    xe = SubinterfaceManagedInterfaceModel.from_config(
        {
            "switch_ip": "192.168.12.181",
            "interface_name": "GigabitEthernet1/0/2.100",
            "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": {"vlan_id": 100, "ip": "10.99.100.1", "prefix": 24}}},
        }
    )
    assert "mtu" not in xe.to_payload()["configData"]["networkOS"]["policy"]


@pytest.mark.parametrize(
    "field, value, extra, should_raise",
    [
        ("ip", "10.99.100.1", {"prefix": 24}, False),
        ("ip", "not-an-ip", {"prefix": 24}, True),
        ("ip", "10.99.100.1/24", {"prefix": 24}, True),
        ("ip", "2001:db8::1", {"prefix": 24}, True),
        ("ipv6", "2001:db8:100::1", {"ipv6_prefix": 64}, False),
        ("ipv6", "also-not-ipv6", {"ipv6_prefix": 64}, True),
        ("ipv6", "2001:db8:100::1/64", {"ipv6_prefix": 64}, True),
        ("ipv6", "10.99.100.1", {"ipv6_prefix": 64}, True),
    ],
)
def test_subinterface_managed_interface_02090(field, value, extra, should_raise):
    """
    # Summary

    Verify the IOS-XE `iosXeSubinterface` policy validates `ip` as a bare IPv4 address and `ipv6` as a bare IPv6 address before any
    controller call. The mask length lives in the sibling `prefix` / `ipv6_prefix` fields, so CIDR input is rejected rather than
    normalized, and the wire value stays the string the user gave.

    ## Test

    - A bare address of the right family is accepted and serialized unchanged
    - Free text, CIDR notation and the other address family raise `ValidationError`

    ## Classes and Methods

    - XeSubinterfacePolicyModel.ip
    - XeSubinterfacePolicyModel.ipv6
    """
    if should_raise:
        with pytest.raises(ValidationError):
            XeSubinterfacePolicyModel(vlan_id=100, **{field: value}, **extra)
        return
    model = XeSubinterfacePolicyModel(vlan_id=100, **{field: value}, **extra)
    assert getattr(model, field) == value
    assert model.model_dump(by_alias=True, exclude_none=True)[field] == value
