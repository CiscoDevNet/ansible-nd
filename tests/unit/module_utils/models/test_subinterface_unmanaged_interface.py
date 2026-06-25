# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for subinterface_unmanaged_interface.py

Tests the unmanaged (monitor-mode) L3 subinterface Pydantic model classes. The unmanaged variant carries only the
`policyType` discriminator in its policy body; no L3 fields are configurable, so the focus here is the
`interface_name` normalizer, the hardcoded scaffolding fields, and `extra="ignore"` tolerance on read.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import SubinterfaceUnmanagedPolicyTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_unmanaged_interface import (
    SubinterfaceUnmanagedConfigDataModel,
    SubinterfaceUnmanagedInterfaceModel,
    SubinterfaceUnmanagedNetworkOSModel,
    SubinterfaceUnmanagedOperDataModel,
    SubinterfaceUnmanagedPolicyModel,
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
    "interfaceName": "Ethernet1/3.20",
    "interfaceType": "subInterface",
    "switchId": "FDO11111AAA",
    "configData": {
        "mode": "unmanaged",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "monitorSubinterface",
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
    "interface_name": "Ethernet1/3.20",
}


# =============================================================================
# Test: SubinterfaceUnmanagedPolicyModel — initialization and defaults
# =============================================================================


def test_subinterface_unmanaged_interface_00100():
    """
    # Summary

    Verify the unmanaged policy body carries only the `policy_type` discriminator, defaulting to
    `SubinterfaceUnmanagedPolicyTypeEnum.MONITOR_SUBINTERFACE`.

    ## Test

    - Instantiate with no arguments
    - policy_type defaults to "monitorSubinterface"

    ## Classes and Methods

    - SubinterfaceUnmanagedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SubinterfaceUnmanagedPolicyModel()
    assert instance.policy_type == SubinterfaceUnmanagedPolicyTypeEnum.MONITOR_SUBINTERFACE
    assert instance.policy_type == "monitorSubinterface"


def test_subinterface_unmanaged_interface_00110():
    """
    # Summary

    Verify `extra="ignore"` silently discards fields ND returns on GET that are not part of the unmanaged policy
    body (e.g. the `userDefined` discriminator branch's `templateName` / `templateConfig`).

    ## Test

    - Construct with unknown extra keys plus the policy_type alias
    - Construction succeeds and the extras are not attached to the model

    ## Classes and Methods

    - SubinterfaceUnmanagedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SubinterfaceUnmanagedPolicyModel(
            policyType="monitorSubinterface",
            templateName="int_subif_unmanaged",
            templateConfig={"foo": "bar"},
        )
    assert instance.policy_type == "monitorSubinterface"
    assert not hasattr(instance, "templateName")
    assert not hasattr(instance, "templateConfig")


# =============================================================================
# Test: SubinterfaceUnmanagedNetworkOSModel
# =============================================================================


def test_subinterface_unmanaged_interface_00400():
    """
    # Summary

    Verify default values for SubinterfaceUnmanagedNetworkOSModel — `network_os_type` is "nx-os" and `policy` is
    populated via default_factory (never None).

    ## Test

    - Construct with no arguments
    - network_os_type defaults to "nx-os"
    - policy is a SubinterfaceUnmanagedPolicyModel with the monitor discriminator

    ## Classes and Methods

    - SubinterfaceUnmanagedNetworkOSModel.__init__()
    """
    instance = SubinterfaceUnmanagedNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert isinstance(instance.policy, SubinterfaceUnmanagedPolicyModel)
    assert instance.policy.policy_type == "monitorSubinterface"


# =============================================================================
# Test: SubinterfaceUnmanagedConfigDataModel
# =============================================================================


def test_subinterface_unmanaged_interface_00500():
    """
    # Summary

    Verify SubinterfaceUnmanagedConfigDataModel defaults — `mode` is "unmanaged" and `network_os` is populated via
    default_factory, so the container constructs with no arguments (unlike the managed variant, where network_os is
    required).

    ## Test

    - Construct with no arguments
    - mode defaults to "unmanaged"
    - network_os is present

    ## Classes and Methods

    - SubinterfaceUnmanagedConfigDataModel.__init__()
    """
    instance = SubinterfaceUnmanagedConfigDataModel()
    assert instance.mode == "unmanaged"
    assert isinstance(instance.network_os, SubinterfaceUnmanagedNetworkOSModel)


# =============================================================================
# Test: SubinterfaceUnmanagedOperDataModel — read-only operational data
# =============================================================================


def test_subinterface_unmanaged_interface_00600():
    """
    # Summary

    Verify SubinterfaceUnmanagedOperDataModel parses GET-side aliases.

    ## Test

    - Construct with camelCase aliases
    - Access by snake_case fields

    ## Classes and Methods

    - SubinterfaceUnmanagedOperDataModel.__init__()
    """
    instance = SubinterfaceUnmanagedOperDataModel(
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
# Test: SubinterfaceUnmanagedInterfaceModel — interface_name normalization
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Ethernet1/3.20", "Ethernet1/3.20"),
        ("ethernet1/3.20", "Ethernet1/3.20"),
        ("ETHERNET1/3.20", "Ethernet1/3.20"),
        ("eThErNeT1/3.20", "Ethernet1/3.20"),
        ("Port-channel10.20", "Port-channel10.20"),
        ("port-channel10.20", "Port-channel10.20"),
        ("PORT-CHANNEL10.20", "Port-channel10.20"),
        ("  Ethernet1/3.20  ", "Ethernet1/3.20"),
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
def test_subinterface_unmanaged_interface_00700(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` canonicalizes the parent prefix capitalization while preserving the
    dot-separated sub-id (e.g. `ethernet1/3.20` -> `Ethernet1/3.20`, `port-channel10.20` -> `Port-channel10.20`).
    This is the same lowercase-on-GET normalization needed for idempotency.

    ## Test

    - Any-cased Ethernet/Port-channel parents normalize to canonical capitalization
    - Surrounding whitespace is stripped
    - The `.<sub>` segment is preserved

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    instance = SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)
    assert instance.interface_name == expected


def test_subinterface_unmanaged_interface_00710():
    """
    # Summary

    Verify `normalize_interface_name` rejects a name without a dot-separated sub-id.

    ## Test

    - A parent-only name (no `.<sub>`) raises ValidationError mentioning the dot-separated requirement

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match="must include a dot-separated subinterface id"):
        SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name="Ethernet1/3")


@pytest.mark.parametrize(
    "value",
    ["Loopback0.1", "Vlan10.2", "mgmt0.3", "Tunnel1.4"],
    ids=["loopback", "vlan", "mgmt", "tunnel"],
)
def test_subinterface_unmanaged_interface_00720(value):
    """
    # Summary

    Verify `normalize_interface_name` rejects parents that are neither Ethernet nor Port-channel.

    ## Test

    - A dotted name on a non-Ethernet/Port-channel parent raises ValidationError mentioning the allowed parents

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match="parent must be 'Ethernet...' or 'Port-channel...'"):
        SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)


def test_subinterface_unmanaged_interface_00730():
    """
    # Summary

    Verify `normalize_interface_name` passes an empty string through its guard unchanged (no normalization, no
    "missing dot" ValueError) — the `not value` guard defers to the field's own type handling.

    ## Test

    - An empty `interface_name` constructs without raising and is preserved as ""

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with does_not_raise():
        instance = SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name="")
    assert instance.interface_name == ""


def test_subinterface_unmanaged_interface_00740():
    """
    # Summary

    Verify a non-string `interface_name` is passed through the normalizer's guard unchanged (it does not raise the
    validator's own ValueError) and is then rejected by the field's `str` type validation.

    ## Test

    - A None `interface_name` raises ValidationError, but not the normalizer's dot/parent messages

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError) as exc_info:
        SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name=None)
    message = str(exc_info.value)
    assert "must include a dot-separated subinterface id" not in message
    assert "parent must be" not in message


@pytest.mark.parametrize(
    "value",
    ["Ethernet1/3.", "Port-channel10."],
    ids=["ethernet_trailing_dot", "portchannel_trailing_dot"],
)
def test_subinterface_unmanaged_interface_00750(value):
    """
    # Summary

    Verify `normalize_interface_name` rejects a trailing-dot name with an empty sub-id (e.g. `Ethernet1/3.`).

    ## Test

    - A name whose `.<sub>` segment is empty raises ValidationError mentioning the numeric sub-id requirement

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match="subinterface id .* must be a number"):
        SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)


@pytest.mark.parametrize(
    "value",
    ["Ethernet1/3.abc", "Port-channel10.2a"],
    ids=["ethernet_alpha_sub", "portchannel_alphanumeric_sub"],
)
def test_subinterface_unmanaged_interface_00760(value):
    """
    # Summary

    Verify `normalize_interface_name` rejects a non-numeric sub-id (e.g. `Ethernet1/3.abc`).

    ## Test

    - A name whose `.<sub>` segment is not all-digits raises ValidationError mentioning the numeric sub-id requirement

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match="subinterface id .* must be a number"):
        SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)


@pytest.mark.parametrize(
    "value",
    ["ethernetfoo.1", "port-channelbar.2"],
    ids=["ethernet_no_port", "portchannel_no_number"],
)
def test_subinterface_unmanaged_interface_00770(value):
    """
    # Summary

    Verify `normalize_interface_name` rejects a parent that carries the right prefix but no port/channel number
    after it (e.g. `ethernetfoo.1`), rather than silently canonicalizing the malformed parent.

    ## Test

    - A name whose parent has a non-numeric first character after the `Ethernet`/`Port-channel` prefix raises
      ValidationError mentioning the malformed parent

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.normalize_interface_name()
    """
    with pytest.raises(ValidationError, match="is malformed"):
        SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name=value)


# =============================================================================
# Test: SubinterfaceUnmanagedInterfaceModel — composite identifier
# =============================================================================


def test_subinterface_unmanaged_interface_00800():
    """
    # Summary

    Verify identifier configuration: composite `(switch_ip, interface_name)`.

    ## Test

    - identifier_strategy is "composite"
    - identifiers is ["switch_ip", "interface_name"]
    - get_identifier_value returns the tuple

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel — class attributes
    - SubinterfaceUnmanagedInterfaceModel.get_identifier_value()
    """
    assert SubinterfaceUnmanagedInterfaceModel.identifier_strategy == "composite"
    assert SubinterfaceUnmanagedInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    instance = SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name="Ethernet1/3.20")
    assert instance.get_identifier_value() == ("1.2.3.4", "Ethernet1/3.20")


def test_subinterface_unmanaged_interface_00810():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip` and `oper_data` from `to_payload`.

    ## Test

    - Construct from a full GET response
    - to_payload omits switchIp and operData
    - to_payload retains the hardcoded interfaceName / interfaceType

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.to_payload()
    """
    instance = SubinterfaceUnmanagedInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert "switchIp" not in payload
    assert "operData" not in payload
    assert payload["interfaceName"] == "Ethernet1/3.20"
    assert payload["interfaceType"] == "subInterface"


# =============================================================================
# Test: SubinterfaceUnmanagedInterfaceModel — from_response robustness
# =============================================================================


def test_subinterface_unmanaged_interface_00900():
    """
    # Summary

    Verify `from_response` is robust to missing nested structures and to extra policy fields ND may return.

    ## Test

    - Response with no configData constructs without raising (scaffolding defaults fill in)
    - Response whose policy carries unexpected extra keys is accepted (extra="ignore")

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.from_response()
    """
    minimal = {
        "switchIp": "1.2.3.4",
        "interfaceName": "Ethernet1/3.20",
        "switchId": "X",
    }
    with does_not_raise():
        SubinterfaceUnmanagedInterfaceModel.from_response(minimal)

    extra_policy = copy.deepcopy(SAMPLE_API_RESPONSE)
    extra_policy["configData"]["networkOS"]["policy"]["templateName"] = "int_subif_unmanaged"
    with does_not_raise():
        instance = SubinterfaceUnmanagedInterfaceModel.from_response(extra_policy)
    assert instance.config_data.network_os.policy.policy_type == "monitorSubinterface"


# =============================================================================
# Test: SubinterfaceUnmanagedInterfaceModel — round-trip + fixed hidden fields
# =============================================================================


def test_subinterface_unmanaged_interface_01000():
    """
    # Summary

    Verify a full GET response round-trips through from_response and to_payload, re-emitting every hardcoded
    scaffolding field with its API alias: interfaceType, mode, networkOSType, and policyType.

    ## Test

    - Build model from SAMPLE_API_RESPONSE
    - to_payload re-emits the fixed discriminator fields

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.from_response()
    - SubinterfaceUnmanagedInterfaceModel.to_payload()
    """
    instance = SubinterfaceUnmanagedInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert payload["interfaceName"] == "Ethernet1/3.20"
    assert payload["interfaceType"] == "subInterface"
    assert payload["configData"]["mode"] == "unmanaged"
    assert payload["configData"]["networkOS"]["networkOSType"] == "nx-os"
    assert payload["configData"]["networkOS"]["policy"]["policyType"] == "monitorSubinterface"


def test_subinterface_unmanaged_interface_01010():
    """
    # Summary

    Verify from_config (Ansible-side, only switch_ip + interface_name) produces a model whose payload matches the
    one built from a full API response — the hardcoded scaffolding is filled in identically either way.

    ## Test

    - Build model A from SAMPLE_API_RESPONSE
    - Build model B from SAMPLE_ANSIBLE_CONFIG
    - to_payload outputs match

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.from_response()
    - SubinterfaceUnmanagedInterfaceModel.from_config()
    """
    a = SubinterfaceUnmanagedInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    b = SubinterfaceUnmanagedInterfaceModel.from_config(SAMPLE_ANSIBLE_CONFIG)
    assert a.to_payload() == b.to_payload()


# =============================================================================
# Test: SubinterfaceUnmanagedInterfaceModel — get_argument_spec
# =============================================================================


def test_subinterface_unmanaged_interface_01100():
    """
    # Summary

    Verify the argument spec exposes only `switch_ip` and `interface_name` per config item — every config_data
    field is hardcoded scaffolding and intentionally hidden.

    ## Test

    - fabric_name is required str
    - config is required list-of-dict with only switch_ip and interface_name options
    - config_data is absent from the config options
    - state is enum with merged/replaced/overridden/deleted

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.get_argument_spec()
    """
    spec = SubinterfaceUnmanagedInterfaceModel.get_argument_spec()
    assert spec["fabric_name"]["type"] == "str"
    assert spec["fabric_name"]["required"] is True
    assert spec["config"]["type"] == "list"
    assert spec["config"]["required"] is True
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert spec["state"]["default"] == "merged"

    config_options = spec["config"]["options"]
    assert set(config_options.keys()) == {"switch_ip", "interface_name"}
    assert config_options["switch_ip"]["required"] is True
    assert config_options["interface_name"]["type"] == "str"
    assert config_options["interface_name"]["required"] is True
    # Every config_data field (interface_type, mode, network_os_type, policy_type) is hardcoded in the
    # Pydantic model and intentionally absent from the user-facing argument spec.
    assert "config_data" not in config_options
    assert "interface_type" not in config_options


# =============================================================================
# Test: SubinterfaceUnmanagedInterfaceModel — interface_type default
# =============================================================================


def test_subinterface_unmanaged_interface_01200():
    """
    # Summary

    Verify `interface_type` defaults to "subInterface".

    ## Test

    - Construct without interface_type
    - Field equals "subInterface"

    ## Classes and Methods

    - SubinterfaceUnmanagedInterfaceModel.__init__()
    """
    instance = SubinterfaceUnmanagedInterfaceModel(switch_ip="1.2.3.4", interface_name="Ethernet1/3.20")
    assert instance.interface_type == "subInterface"
