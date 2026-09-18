# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_routed_interface.py

Tests the routed (L3) port-channel Interface Pydantic model classes (NX-OS `l3Po`, IOS-XE `iosXeL3PortChannel`; issue #549).
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name

from __future__ import annotations

import copy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    PortChannelRoutedPolicyTypeEnum,
    XePortChannelRoutedPolicyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_routed_interface import (
    PortChannelRoutedInterfaceModel,
    PortChannelRoutedPolicyModel,
    XePortChannelRoutedPolicyModel,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from pydantic import ValidationError

# =============================================================================
# Test data constants
# =============================================================================

# The `l3Po` echo read from S1_TOR1 port-channel10 on ND 4.2.1.10 (2026-09-18), plus a `switchIp`. Every policy key except
# `description`, `ports` and `policyType` is an ND-echoed template default; `portChannelId` is undeclared in the template.
NX_L3PO_RESPONSE = {
    "switchIp": "192.168.12.161",
    "interfaceName": "port-channel10",
    "interfaceType": "portChannel",
    "configData": {
        "mode": "routed",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "adminState": True,
                "copyDescription": False,
                "description": "subinterface test parent",
                "ipRedirects": False,
                "mtu": 9216,
                "netflow": False,
                "pfc": False,
                "pimDrPriority": 1,
                "pimSparse": False,
                "policyType": "l3Po",
                "portChannelId": "Port-channel10",
                "portChannelMode": "active",
                "ports": ["Ethernet1/62"],
                "qos": False,
                "speed": "auto",
            },
        },
    },
}

# The `iosXeL3PortChannel` echo read from C1_LE1 Port-channel120 on ND 4.2.1.10 (2026-09-18, identical on 4.3.1.175).
XE_L3PO_RESPONSE = {
    "switchIp": "192.168.12.181",
    "interfaceName": "port-channel120",
    "interfaceType": "portChannel",
    "configData": {
        "mode": "routed",
        "networkOS": {
            "networkOSType": "ios-xe",
            "policy": {
                "adminState": True,
                "description": "probe-549",
                "ip": "10.49.0.1",
                "policyType": "iosXeL3PortChannel",
                "portChannelId": "Port-channel120",
                "portChannelMode": "active",
                "ports": ["GigabitEthernet1/0/22"],
                "prefix": 30,
            },
        },
    },
}


def nx_config(**policy) -> dict:
    """Return an NX-OS playbook config item whose policy is `policy`."""
    return {
        "switch_ip": "192.168.12.161",
        "interface_name": "port-channel20",
        "config_data": {"network_os": {"network_os_type": "nx-os", "policy": policy}},
    }


def xe_config(**policy) -> dict:
    """Return an IOS-XE playbook config item whose policy is `policy`."""
    return {
        "switch_ip": "192.168.12.181",
        "interface_name": "port-channel120",
        "config_data": {"network_os": {"network_os_type": "ios-xe", "policy": policy}},
    }


# =============================================================================
# Test: enums
# =============================================================================


def test_port_channel_routed_interface_00000():
    """
    # Summary

    Verify the routed port-channel policy-type enums carry exactly the managed create-side wire values.

    ## Test

    - `PortChannelRoutedPolicyTypeEnum` is `l3Po` only (`l3PoInternal`, `mplsUplinkPo`, `freeform`, `userDefined` are not managed)
    - `XePortChannelRoutedPolicyTypeEnum` is `iosXeL3PortChannel` only

    ## Classes and Methods

    - PortChannelRoutedPolicyTypeEnum
    - XePortChannelRoutedPolicyTypeEnum
    """
    assert [e.value for e in PortChannelRoutedPolicyTypeEnum] == ["l3Po"]
    assert [e.value for e in XePortChannelRoutedPolicyTypeEnum] == ["iosXeL3PortChannel"]


# =============================================================================
# Test: read side
# =============================================================================


def test_port_channel_routed_interface_00100():
    """
    # Summary

    Verify the NX-OS `l3Po` echo parses, including the undeclared ND-injected `portChannelId`, which is dropped.

    ## Test

    - `from_response` on the lab echo does not raise
    - identifier, frozen `interface_type` / `mode`, `policy_type` property and member list read back
    - `portChannelId` never reaches a payload

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.from_response()
    - PortChannelRoutedInterfaceModel.policy_type
    """
    with does_not_raise():
        instance = PortChannelRoutedInterfaceModel.from_response(copy.deepcopy(NX_L3PO_RESPONSE))
    assert instance.switch_ip == "192.168.12.161"
    assert instance.interface_name == "port-channel10"
    assert instance.interface_type == "portChannel"
    assert instance.config_data.mode == "routed"
    assert instance.policy_type == "l3Po"
    assert instance.config_data.network_os.policy.ports == ["Ethernet1/62"]
    assert "portChannelId" not in instance.to_payload()["configData"]["networkOS"]["policy"]


def test_port_channel_routed_interface_00110():
    """
    # Summary

    Verify the IOS-XE `iosXeL3PortChannel` echo parses and selects the IOS-XE branch of the union.

    ## Test

    - `from_response` on the lab echo does not raise
    - `policy_type` is `iosXeL3PortChannel`; `ip` / `prefix` read back
    - `portChannelId` never reaches a payload

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = PortChannelRoutedInterfaceModel.from_response(copy.deepcopy(XE_L3PO_RESPONSE))
    policy = instance.config_data.network_os.policy
    assert isinstance(policy, XePortChannelRoutedPolicyModel)
    assert instance.policy_type == "iosXeL3PortChannel"
    assert (policy.ip, policy.prefix) == ("10.49.0.1", 30)
    assert "portChannelId" not in instance.to_payload()["configData"]["networkOS"]["policy"]


def test_port_channel_routed_interface_00120():
    """
    # Summary

    Verify the `reverse_diff_defaults` scrub on both branches: an echo carrying only ND template defaults reads back as no user
    configuration, while a non-default value survives.

    ## Test

    - The NX-OS lab echo keeps only `description`, `ports` and `policyType` in `to_reverse_diff_dict()`
    - An NX-OS echo with `mtu: 1500` keeps `mtu`
    - The IOS-XE defaults (`adminState`, `portChannelMode: active`) are scrubbed

    ## Classes and Methods

    - PortChannelRoutedPolicyModel.reverse_diff_defaults
    - XePortChannelRoutedPolicyModel.reverse_diff_defaults
    """
    nx_policy = copy.deepcopy(NX_L3PO_RESPONSE["configData"]["networkOS"]["policy"])
    assert set(PortChannelRoutedPolicyModel.from_response(nx_policy).to_reverse_diff_dict()) == {"description", "ports", "policyType"}
    nx_policy["mtu"] = 1500
    assert PortChannelRoutedPolicyModel.from_response(nx_policy).to_reverse_diff_dict()["mtu"] == 1500
    xe_defaults = XePortChannelRoutedPolicyModel.from_response(
        {"adminState": True, "portChannelMode": "active", "policyType": "iosXeL3PortChannel", "portChannelId": "Port-channel120"}
    )
    assert set(xe_defaults.to_reverse_diff_dict()) <= {"policyType"}


def test_port_channel_routed_interface_00130():
    """
    # Summary

    Verify `routing_tag` is coerced to a string on read (ND echoes the routed templates' `routingTag` as an integer).

    ## Test

    - `routingTag: 12345` in a response reads back as `"12345"`

    ## Classes and Methods

    - PortChannelRoutedPolicyModel.coerce_routing_tag()
    """
    policy = PortChannelRoutedPolicyModel.from_response({"policyType": "l3Po", "routingTag": 12345})
    assert policy.routing_tag == "12345"


# =============================================================================
# Test: write side
# =============================================================================


def test_port_channel_routed_interface_00200():
    """
    # Summary

    Verify `policy_type` is injected from `network_os_type` when the playbook omits it, on both branches.

    ## Test

    - `nx-os` with no `policy_type` -> `l3Po`
    - `ios-xe` with no `policy_type` -> `iosXeL3PortChannel`

    ## Classes and Methods

    - PortChannelRoutedPolicyModel.default_policy_type()
    - XePortChannelRoutedPolicyModel.default_policy_type()
    """
    assert PortChannelRoutedInterfaceModel.from_config(nx_config(ip="10.1.1.1", prefix=30)).policy_type == "l3Po"
    assert PortChannelRoutedInterfaceModel.from_config(xe_config(ip="10.1.1.1", prefix=30)).policy_type == "iosXeL3PortChannel"


def test_port_channel_routed_interface_00210():
    """
    # Summary

    Verify `network_os_type` is required: this is a new module with no legacy playbooks to default for.

    ## Test

    - A `network_os` without `network_os_type` raises `ValidationError`

    ## Classes and Methods

    - PortChannelRoutedConfigDataModel
    """
    config = nx_config(ip="10.1.1.1", prefix=30)
    del config["config_data"]["network_os"]["network_os_type"]
    with pytest.raises(ValidationError):
        PortChannelRoutedInterfaceModel.from_config(config)


@pytest.mark.parametrize(
    "config",
    [
        nx_config(policy_type="iosXeL3PortChannel"),
        xe_config(policy_type="l3Po"),
        nx_config(policy_type="mplsUplinkPo"),
        xe_config(ipv6="2001:db8::1", ipv6_prefix=64),
        xe_config(pim_sparse=True),
        xe_config(speed="auto"),
    ],
    ids=["nx_with_xe_policy", "xe_with_nx_policy", "unmanaged_nx_policy", "xe_ipv6", "xe_pim", "xe_speed"],
)
def test_port_channel_routed_interface_00220(config):
    """
    # Summary

    Verify the write side is strict: a cross-OS or unmanaged `policy_type`, or an NX-OS-only field on the IOS-XE branch (the IOS-XE
    template is IPv4-only with no PIM, QoS, netflow or speed), is rejected before any controller request.

    ## Test

    - Each parametrized config raises `ValidationError` from `from_config`

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.from_config()
    """
    with pytest.raises(ValidationError):
        PortChannelRoutedInterfaceModel.from_config(config)


@pytest.mark.parametrize(
    "policy, should_raise",
    [
        ({"mtu": 575}, True),
        ({"mtu": 576}, False),
        ({"mtu": 9217}, True),
        ({"prefix": 0}, True),
        ({"prefix": 31}, False),
        ({"prefix": 32}, True),
        ({"ipv6_prefix": 0}, True),
        ({"ipv6_prefix": 127}, False),
        ({"ipv6_prefix": 128}, True),
        ({"pim_dr_priority": 0}, True),
        ({"pim_dr_priority": 4294967295}, False),
        ({"description": "d" * 254}, False),
        ({"description": "d" * 255}, True),
        ({"vrf": "v" * 33}, True),
        ({"port_channel_mode": "passive"}, False),
        ({"port_channel_mode": "desirable"}, True),
    ],
)
def test_port_channel_routed_interface_00230(policy, should_raise):
    """
    # Summary

    Verify the NX-OS `l3Po` field ranges match `intL3PortChannelTemplate` (identical on ND 4.2.1 and 4.3.1), including the rejection
    of the PAgP-only port-channel modes.

    ## Test

    - Each parametrized policy is accepted or rejected per the template bounds

    ## Classes and Methods

    - PortChannelRoutedPolicyModel
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelRoutedInterfaceModel.from_config(nx_config(**policy))
    else:
        with does_not_raise():
            PortChannelRoutedInterfaceModel.from_config(nx_config(**policy))


@pytest.mark.parametrize(
    "policy, should_raise",
    [
        ({"mtu": 1499}, True),
        ({"mtu": 1500}, False),
        ({"mtu": 9216}, False),
        ({"mtu": 9217}, True),
        ({"prefix": 7}, True),
        ({"prefix": 8}, False),
        ({"prefix": 31}, False),
        ({"prefix": 32}, True),
        ({"description": "d" * 200}, False),
        ({"description": "d" * 201}, True),
        ({"port_channel_mode": "desirable"}, False),
        ({"port_channel_mode": "auto"}, False),
    ],
)
def test_port_channel_routed_interface_00240(policy, should_raise):
    """
    # Summary

    Verify the IOS-XE `iosXeL3PortChannel` field ranges match `iosXeIntL3PortChannelTemplate` (identical on ND 4.2.1 and 4.3.1): `mtu`
    1500-9216, `prefix` 8-31, `description` up to 200, and the PAgP `auto` / `desirable` modes.

    ## Test

    - Each parametrized policy is accepted or rejected per the template bounds

    ## Classes and Methods

    - XePortChannelRoutedPolicyModel
    """
    if should_raise:
        with pytest.raises(ValidationError):
            PortChannelRoutedInterfaceModel.from_config(xe_config(**policy))
    else:
        with does_not_raise():
            PortChannelRoutedInterfaceModel.from_config(xe_config(**policy))


def test_port_channel_routed_interface_00250():
    """
    # Summary

    Verify the NX-OS payload shape: wire aliases, frozen `mode: routed` / `interfaceType: portChannel`, no `switchIp`, the CIDR `ip`
    normalized to its bare host form, and the lowercase name left as typed.

    ## Test

    - `to_payload()` of a full NX-OS item matches the expected wire body

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.to_payload()
    """
    instance = PortChannelRoutedInterfaceModel.from_config(
        nx_config(ip="10.1.1.1/30", prefix=30, ipv6="2001:db8::1", ipv6_prefix=64, vrf="blue", ports=["Ethernet1/10"], routing_tag="100")
    )
    assert instance.to_payload() == {
        "interfaceName": "port-channel20",
        "interfaceType": "portChannel",
        "configData": {
            "mode": "routed",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "l3Po",
                    "ip": "10.1.1.1",
                    "prefix": 30,
                    "ipv6": "2001:db8::1",
                    "ipv6Prefix": 64,
                    "vrfInterface": "blue",
                    "ports": ["Ethernet1/10"],
                    "routingTag": "100",
                },
            },
        },
    }


def test_port_channel_routed_interface_00260():
    """
    # Summary

    Verify the create-name rewrite: `to_payload()` emits `Port-channel<N>` for the IOS-XE branch only; `to_config()` and the diff dump
    keep the lowercase identifier, and the NX-OS branch is untouched.

    # workaround: xe-port-channel-create-requires-canonical-name

    ## Test

    - XE model built from `Port-Channel120` normalizes `interface_name` to `port-channel120`
    - `to_payload()["interfaceName"] == "Port-channel120"`; `to_config()` and `to_diff_dict()` keep `port-channel120`
    - `get_diff` against an identical copy reports no difference
    - NX model built from `Port-Channel20` emits `port-channel20` on the wire

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.normalize_interface_name()
    - PortChannelInterfaceBaseModel._canonical_xe_create_name()
    """
    config = xe_config(ip="10.49.0.1", prefix=30)
    config["interface_name"] = "Port-Channel120"
    xe = PortChannelRoutedInterfaceModel.from_config(config)
    assert xe.interface_name == "port-channel120"
    assert xe.to_payload()["interfaceName"] == "Port-channel120"
    assert xe.to_config()["interface_name"] == "port-channel120"
    assert xe.to_diff_dict()["interfaceName"] == "port-channel120"
    # `get_diff` returns True when `other` is a subset of `self` with no removals, i.e. no difference.
    assert xe.get_diff(copy.deepcopy(xe)) is True
    config = nx_config(ip="10.1.1.1", prefix=30)
    config["interface_name"] = "Port-Channel20"
    assert PortChannelRoutedInterfaceModel.from_config(config).to_payload()["interfaceName"] == "port-channel20"


@pytest.mark.parametrize(
    "config, expected",
    [
        (nx_config(ports=["e1/10", "eth1/11", "Ethernet1/12"]), ["Ethernet1/10", "Ethernet1/11", "Ethernet1/12"]),
        (xe_config(ports=["gi1/0/2", "GigabitEthernet1/0/3"]), ["GigabitEthernet1/0/2", "GigabitEthernet1/0/3"]),
    ],
    ids=["nx", "xe"],
)
def test_port_channel_routed_interface_00270(config, expected):
    """
    # Summary

    Verify member names are normalized to their wire-canonical prefix on both branches so they match ND's echo (idempotency).

    ## Test

    - Abbreviated members expand; canonical members pass through

    ## Classes and Methods

    - PortChannelRoutedPolicyModel.normalize_ports()
    - XePortChannelRoutedPolicyModel.normalize_ports()
    """
    assert PortChannelRoutedInterfaceModel.from_config(config).config_data.network_os.policy.ports == expected


def test_port_channel_routed_interface_00280():
    """
    # Summary

    Verify a playbook item that spells out only ND's template defaults is idempotent against the lab echo, and that a changed field is
    reported as a difference.

    ## Test

    - Proposed `{description, ports, mtu: 9216, port_channel_mode: active}` vs the NX-OS lab echo -> no difference
    - Proposed `mtu: 1500` vs the same echo -> difference

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.get_diff()
    """
    existing = PortChannelRoutedInterfaceModel.from_response(copy.deepcopy(NX_L3PO_RESPONSE))
    config = nx_config(description="subinterface test parent", ports=["Ethernet1/62"], mtu=9216, port_channel_mode="active")
    config["interface_name"] = "port-channel10"
    assert existing.get_diff(PortChannelRoutedInterfaceModel.from_config(config)) is True
    config["config_data"]["network_os"]["policy"]["mtu"] = 1500
    assert existing.get_diff(PortChannelRoutedInterfaceModel.from_config(config)) is False


# =============================================================================
# Test: argument spec
# =============================================================================


def test_port_channel_routed_interface_00300():
    """
    # Summary

    Verify the argument spec: `network_os_type` is required with both choices, `policy_type` offers both managed types, the port-channel
    mode choices are the IOS-XE superset, every model field has an option, and the four write states are offered.

    ## Test

    - Inspect `get_argument_spec()`

    ## Classes and Methods

    - PortChannelRoutedInterfaceModel.get_argument_spec()
    """
    spec = PortChannelRoutedInterfaceModel.get_argument_spec()
    network_os = spec["config"]["options"]["config_data"]["options"]["network_os"]
    assert network_os["options"]["network_os_type"] == {"type": "str", "required": True, "choices": ["nx-os", "ios-xe"]}
    policy = network_os["options"]["policy"]["options"]
    assert policy["policy_type"]["choices"] == ["l3Po", "iosXeL3PortChannel"]
    assert policy["port_channel_mode"]["choices"] == ["on", "active", "passive", "auto", "desirable"]
    assert policy["mtu"] == {"type": "int"}
    model_fields = set(PortChannelRoutedPolicyModel.model_fields) | set(XePortChannelRoutedPolicyModel.model_fields)
    assert set(policy) == model_fields
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
