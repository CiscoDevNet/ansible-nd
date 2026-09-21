# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ethernet_routed_interface.py

Tests the Ethernet Routed Interface Pydantic model classes (issue #447).
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.enums import (
    EthernetRoutedPolicyTypeEnum,
    FecEnum,
    SpeedEnum,
    XeEthernetRoutedPolicyTypeEnum,
    XeEthernetSpeedEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import (
    EthernetRoutedInterfaceModel,
    NexusEthernetRoutedNetworkOSModel,
    NexusEthernetRoutedPolicyModel,
    XeEthernetRoutedNetworkOSModel,
    XeEthernetRoutedPolicyModel,
)
from pydantic import ValidationError

# pylint: disable=unused-variable


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_NX_API_RESPONSE = {
    "switchIp": "192.168.12.151",
    "interfaceName": "Ethernet1/7",
    "interfaceType": "ethernet",
    "configData": {
        "mode": "routed",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "routedHost",
                "adminState": True,
                "ip": "10.99.99.1",
                "prefix": 30,
                "mtu": 9216,
                "description": "routed uplink",
            },
        },
    },
}

SAMPLE_XE_API_RESPONSE = {
    "switchIp": "192.168.12.112",
    "interfaceName": "GigabitEthernet3",
    "interfaceType": "ethernet",
    "configData": {
        "mode": "routed",
        "networkOS": {
            "networkOSType": "ios-xe",
            "policy": {
                "policyType": "iosXeRoutedHost",
                "adminState": True,
                "ip": "10.99.99.9",
                "prefix": 30,
                "mtu": 1500,
                "description": "xe routed",
            },
        },
    },
}


# =============================================================================
# Test: enums
# =============================================================================


def test_ethernet_routed_interface_00010():
    """
    # Summary

    Verify the managed policy-type enums carry exactly the wire discriminator values for the initial branches.

    ## Test

    - `EthernetRoutedPolicyTypeEnum` has the single member `routedHost`
    - `XeEthernetRoutedPolicyTypeEnum` has the single member `iosXeRoutedHost`

    ## Classes and Methods

    - EthernetRoutedPolicyTypeEnum
    - XeEthernetRoutedPolicyTypeEnum
    """
    assert [e.value for e in EthernetRoutedPolicyTypeEnum] == ["routedHost"]
    assert [e.value for e in XeEthernetRoutedPolicyTypeEnum] == ["iosXeRoutedHost"]


# =============================================================================
# Test: NexusEthernetRoutedPolicyModel
# =============================================================================


def test_ethernet_routed_interface_00020():
    """
    # Summary

    Verify field defaults: user-facing fields default to None; an explicit `policy_type` is accepted verbatim.

    ## Test

    - Instantiate with only `policy_type`
    - User-facing fields are None
    - `policy_type` is "routedHost"

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = NexusEthernetRoutedPolicyModel(policy_type="routedHost")
    assert instance.admin_state is None
    assert instance.description is None
    assert instance.extra_config is None
    assert instance.fec is None
    assert instance.ip is None
    assert instance.ip_redirects is None
    assert instance.mtu is None
    assert instance.netflow is None
    assert instance.netflow_monitor is None
    assert instance.netflow_sampler is None
    assert instance.pfc is None
    assert instance.pim_dr_priority is None
    assert instance.pim_sparse is None
    assert instance.prefix is None
    assert instance.qos is None
    assert instance.qos_policy is None
    assert instance.queuing_policy is None
    assert instance.routing_tag is None
    assert instance.speed is None
    assert instance.vrf is None
    assert instance.policy_type == "routedHost"


def test_ethernet_routed_interface_00030():
    """
    # Summary

    Verify an omitted `policy_type` discriminator is injected as `routedHost` — the only NX-OS routed policy type the module manages,
    so the user need not repeat what `network_os_type` already implies (PR #550 review) — and that the injected value is SET, so it
    reaches the wire payload and the merge/diff paths exactly like an explicit value.

    ## Test

    - Instantiate with no `policy_type`, with `policy_type=None` (how the argspec passes an omitted suboption), and from a wire dict
      lacking `policyType`
    - `policy_type` is "routedHost" in every case and is reported by `model_fields_set`
    - `to_payload()` carries `policyType: routedHost`

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.default_policy_type()
    - _default_policy_type()
    """
    with does_not_raise():
        omitted = NexusEthernetRoutedPolicyModel()
        none_valued = NexusEthernetRoutedPolicyModel(policy_type=None, ip="10.1.1.1")
        wire = NexusEthernetRoutedPolicyModel.model_validate({"ip": "10.1.1.1", "prefix": 30})
    for instance in (omitted, none_valued, wire):
        assert instance.policy_type == "routedHost"
        assert "policy_type" in instance.model_fields_set
        assert instance.to_payload()["policyType"] == "routedHost"
    assert wire.ip == "10.1.1.1"


def test_ethernet_routed_interface_00031():
    """
    # Summary

    Verify an explicit `policy_type` is never overridden by the injection, and a wrong explicit value is still rejected.

    ## Test

    - `policy_type="routedHost"` stays "routedHost"
    - `policy_type="iosXeRoutedHost"` on the NX-OS model raises `ValidationError`

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.default_policy_type()
    """
    with does_not_raise():
        instance = NexusEthernetRoutedPolicyModel(policy_type="routedHost")
    assert instance.policy_type == "routedHost"
    with pytest.raises(ValidationError, match=r"policy_type\n  Input should be 'routedHost'"):
        result = NexusEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost")


def test_ethernet_routed_interface_00040():
    """
    # Summary

    Verify construction from wire-form (alias) keys.

    ## Test

    - `model_validate` a wire-form policy dict
    - Snake_case attributes carry the values

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.model_validate()
    """
    with does_not_raise():
        instance = NexusEthernetRoutedPolicyModel.model_validate(
            {
                "policyType": "routedHost",
                "adminState": True,
                "ip": "10.99.99.1",
                "prefix": 30,
                "ipRedirects": False,
                "pimSparse": True,
                "pimDrPriority": 10,
                "vrfInterface": "blue",
                "routingTag": "54321",
            }
        )
    assert instance.admin_state is True
    assert instance.ip == "10.99.99.1"
    assert instance.prefix == 30
    assert instance.ip_redirects is False
    assert instance.pim_sparse is True
    assert instance.pim_dr_priority == 10
    assert instance.vrf == "blue"
    assert instance.routing_tag == "54321"


def test_ethernet_routed_interface_00050():
    """
    # Summary

    Verify CIDR `ip` input is normalized to bare IPv4 host form (issue #401 behavior via `IPv4Host`).

    ## Test

    - Construct with `ip="10.99.99.1/30"`
    - `ip` is stored as "10.99.99.1"

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = NexusEthernetRoutedPolicyModel(policy_type="routedHost", ip="10.99.99.1/30")
    assert instance.ip == "10.99.99.1"


def test_ethernet_routed_interface_00060():
    """
    # Summary

    Verify NX-OS field constraints: `mtu` floor 576, `prefix` range 1-31, `pim_dr_priority` floor 1.

    ## Test

    - `mtu=575` raises; `mtu=576` accepted
    - `prefix=32` raises
    - `pim_dr_priority=0` raises

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.__init__()
    """
    with pytest.raises(ValidationError, match="mtu"):
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", mtu=575)
    with does_not_raise():
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", mtu=576)
    with pytest.raises(ValidationError, match="prefix"):
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", prefix=32)
    with pytest.raises(ValidationError, match="pim_dr_priority"):
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", pim_dr_priority=0)


def test_ethernet_routed_interface_00070():
    """
    # Summary

    Verify NX-OS speed accepts high-end Nexus values and rejects the XE-only `noNegotiate`.

    ## Test

    - `speed="800Gb"` accepted
    - `speed="noNegotiate"` raises

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.__init__()
    """
    with does_not_raise():
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", speed="800Gb")
    with pytest.raises(ValidationError, match="speed"):
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", speed="noNegotiate")


# =============================================================================
# Test: XeEthernetRoutedPolicyModel
# =============================================================================


def test_ethernet_routed_interface_00080():
    """
    # Summary

    Verify field defaults: user-facing fields default to None; an explicit `policy_type` is accepted verbatim.

    ## Test

    - Instantiate with only `policy_type`
    - User-facing fields are None
    - `policy_type` is "iosXeRoutedHost"

    ## Classes and Methods

    - XeEthernetRoutedPolicyModel.__init__()
    """
    with does_not_raise():
        instance = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost")
    assert instance.admin_state is None
    assert instance.description is None
    assert instance.extra_config is None
    assert instance.ip is None
    assert instance.mtu is None
    assert instance.prefix is None
    assert instance.speed is None
    assert instance.vrf is None
    assert instance.policy_type == "iosXeRoutedHost"


def test_ethernet_routed_interface_00081():
    """
    # Summary

    Verify an omitted `policy_type` on the IOS-XE model is injected as `iosXeRoutedHost` and reaches the wire payload.

    ## Test

    - Instantiate with no `policy_type`, with `policy_type=None`, and from a wire dict lacking `policyType`
    - `policy_type` is "iosXeRoutedHost" in every case and `to_payload()` carries it
    - An explicit NX-OS value on the XE model raises `ValidationError`

    ## Classes and Methods

    - XeEthernetRoutedPolicyModel.default_policy_type()
    - _default_policy_type()
    """
    with does_not_raise():
        omitted = XeEthernetRoutedPolicyModel()
        none_valued = XeEthernetRoutedPolicyModel(policy_type=None, ip="10.1.1.1")
        wire = XeEthernetRoutedPolicyModel.model_validate({"ip": "10.1.1.1", "prefix": 30})
    for instance in (omitted, none_valued, wire):
        assert instance.policy_type == "iosXeRoutedHost"
        assert instance.to_payload()["policyType"] == "iosXeRoutedHost"
    with pytest.raises(ValidationError, match=r"policy_type\n  Input should be 'iosXeRoutedHost'"):
        result = XeEthernetRoutedPolicyModel(policy_type="routedHost")


def test_ethernet_routed_interface_00090():
    """
    # Summary

    Verify IOS-XE field constraints diverge from NX-OS: `mtu` floor 1500, `description` max length 200, `speed` accepts
    `noNegotiate` and rejects Nexus-only 800Gb.

    ## Test

    - `mtu=1499` raises; `mtu=1500` accepted
    - 201-char `description` raises; 200-char accepted
    - `speed="noNegotiate"` accepted; `speed="800Gb"` raises

    ## Classes and Methods

    - XeEthernetRoutedPolicyModel.__init__()
    """
    with pytest.raises(ValidationError, match="mtu"):
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", mtu=1499)
    with does_not_raise():
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", mtu=1500)
    with pytest.raises(ValidationError, match="description"):
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", description="x" * 201)
    with does_not_raise():
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", description="x" * 200)
    with does_not_raise():
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", speed="noNegotiate")
    with pytest.raises(ValidationError, match="speed"):
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", speed="800Gb")


def test_ethernet_routed_interface_00100():
    """
    # Summary

    Verify write-strict behavior: an NX-only field with a real value is rejected on the XE branch (`extra="forbid"`),
    while the same field explicitly set to None is stripped and accepted (flat-argspec compatibility).

    ## Test

    - `fec="auto"` on the XE branch raises
    - `fec=None` on the XE branch is accepted

    ## Classes and Methods

    - XeEthernetRoutedPolicyModel.__init__()
    - InterfacePolicyStrictBase.strip_none_valued_keys()
    """
    with pytest.raises(ValidationError, match="fec"):
        result = XeEthernetRoutedPolicyModel(policy_type="iosXeRoutedHost", fec="auto")
    with does_not_raise():
        instance = XeEthernetRoutedPolicyModel.model_validate({"policyType": "iosXeRoutedHost", "fec": None})
    assert instance.policy_type == "iosXeRoutedHost"


# =============================================================================
# Test: discriminated unions + top-level model
# =============================================================================


def test_ethernet_routed_interface_00110():
    """
    # Summary

    Verify the outer `network_os_type` union selects the NX-OS branch from a wire-form response and round-trips to an
    identical payload with `switch_ip` excluded.

    ## Test

    - `from_response(SAMPLE_NX_API_RESPONSE)` selects `NexusEthernetRoutedNetworkOSModel` / `NexusEthernetRoutedPolicyModel`
    - `to_payload()` equals the wire dict minus `switchIp`

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.from_response()
    - EthernetRoutedInterfaceModel.to_payload()
    """
    with does_not_raise():
        instance = EthernetRoutedInterfaceModel.from_response(SAMPLE_NX_API_RESPONSE)
    assert isinstance(instance.config_data.network_os, NexusEthernetRoutedNetworkOSModel)
    assert isinstance(instance.config_data.network_os.policy, NexusEthernetRoutedPolicyModel)
    assert instance.policy_type == "routedHost"
    expected = {key: value for key, value in SAMPLE_NX_API_RESPONSE.items() if key != "switchIp"}
    assert instance.to_payload() == expected


def test_ethernet_routed_interface_00120():
    """
    # Summary

    Verify the outer `network_os_type` union selects the IOS-XE branch from a wire-form response.

    ## Test

    - `from_response(SAMPLE_XE_API_RESPONSE)` selects `XeEthernetRoutedNetworkOSModel` / `XeEthernetRoutedPolicyModel`
    - `policy_type` property reports "iosXeRoutedHost"

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.from_response()
    - EthernetRoutedInterfaceModel.policy_type
    """
    with does_not_raise():
        instance = EthernetRoutedInterfaceModel.from_response(SAMPLE_XE_API_RESPONSE)
    assert isinstance(instance.config_data.network_os, XeEthernetRoutedNetworkOSModel)
    assert isinstance(instance.config_data.network_os.policy, XeEthernetRoutedPolicyModel)
    assert instance.policy_type == "iosXeRoutedHost"


def test_ethernet_routed_interface_00130():
    """
    # Summary

    Verify read-tolerance: the ND-injected `ptp` key (absent from `intRoutedHostTemplate`; lab-verified 2026-07-27) is
    stripped on the read path and does NOT survive into the payload (retained extras would count as removals in the
    reverse diff pass).

    ## Test

    - `from_response` with `ptp: false` in the policy does not raise
    - The model has no `ptp` attribute value and `to_payload()` output contains no `ptp` key

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.from_response()
    - InterfacePolicyStrictBase.strip_none_valued_keys()
    """
    import copy  # pylint: disable=import-outside-toplevel

    response = copy.deepcopy(SAMPLE_NX_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["ptp"] = False
    with does_not_raise():
        instance = EthernetRoutedInterfaceModel.from_response(response)
    assert "ptp" not in instance.to_payload()["configData"]["networkOS"]["policy"]


def test_ethernet_routed_interface_00140():
    """
    # Summary

    Verify write-side strictness at the top level: the same `ptp` key that reads tolerate is rejected as user input.

    ## Test

    - `model_validate` (write path, no read context) with `ptp` in the policy raises

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.model_validate()
    """
    import copy  # pylint: disable=import-outside-toplevel

    config = copy.deepcopy(SAMPLE_NX_API_RESPONSE)
    config["configData"]["networkOS"]["policy"]["ptp"] = False
    with pytest.raises(ValidationError, match="ptp"):
        result = EthernetRoutedInterfaceModel.model_validate(config, by_alias=True)


def test_ethernet_routed_interface_00150():
    """
    # Summary

    Verify top-level model shape: composite identifiers, frozen `interface_type` of "ethernet", frozen `mode` of "routed",
    and wire-canonical interface-name normalization for BOTH network OS families. The ND wire echoes `Ethernet1/7` (NX-OS)
    and `GigabitEthernet3` (IOS-XE) - lab-verified 2026-07-27 - so lowercased or abbreviated user input must normalize to
    those forms or idempotency silently breaks, while an unrecognized prefix must pass through verbatim (never title-cased,
    which would corrupt correct input like `TenGigabitEthernet1/1`).

    ## Test

    - `identifiers` == ["switch_ip", "interface_name"]; strategy "composite"; `switch_ip` payload-excluded
    - `interface_type` defaults to "ethernet"; `config_data.mode` defaults to "routed"
    - NX: "ethernet1/7", "ETHERNET1/7", "eth1/7", "e1/7" all normalize to "Ethernet1/7"; "Ethernet1/7" is idempotent
    - XE: "gigabitethernet3", "gi3" normalize to "GigabitEthernet3"; "GigabitEthernet3" is idempotent
    - Unrecognized/ambiguous prefixes pass through verbatim: "TenGigabitEthernet1/1", "t1/1"
    - Digits and separators preserved: "ethernet1/1.10" -> "Ethernet1/1.10"

    ## Classes and Methods

    - EthernetRoutedInterfaceModel
    - EthernetRoutedInterfaceModel.normalize_interface_name()
    """
    assert EthernetRoutedInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    assert EthernetRoutedInterfaceModel.identifier_strategy == "composite"
    assert EthernetRoutedInterfaceModel.payload_exclude_fields == {"switch_ip"}
    with does_not_raise():
        instance = EthernetRoutedInterfaceModel.from_response(SAMPLE_NX_API_RESPONSE)
    assert instance.interface_type == "ethernet"
    assert instance.config_data.mode == "routed"
    cases = {
        "ethernet1/7": "Ethernet1/7",
        "ETHERNET1/7": "Ethernet1/7",
        "eth1/7": "Ethernet1/7",
        "e1/7": "Ethernet1/7",
        "Ethernet1/7": "Ethernet1/7",
        "ethernet1/1.10": "Ethernet1/1.10",
        "gigabitethernet3": "GigabitEthernet3",
        "gi3": "GigabitEthernet3",
        "GigabitEthernet3": "GigabitEthernet3",
        "TenGigabitEthernet1/1": "TenGigabitEthernet1/1",
        "t1/1": "t1/1",
    }
    for supplied, expected in cases.items():
        named = EthernetRoutedInterfaceModel(switch_ip="192.168.12.151", interface_name=supplied)
        assert named.interface_name == expected, f"{supplied!r} normalized to {named.interface_name!r}, expected {expected!r}"


def test_ethernet_routed_interface_00155():
    """
    # Summary

    Verify merging a newly-set field onto an existing model whose corresponding field is unset (None). Regression test for
    the `strip_none_valued_keys` x `validate_assignment=True` interaction: the first `setattr` inside `merge()` re-runs the
    before-validator over the model's entire `__dict__`; a validator that drops ALL None-valued keys (declared ones
    included) leaves `__dict__` missing those fields, so the next `getattr` raises `AttributeError` mid-merge. Declared
    fields must survive the strip even when None - only undeclared keys may be dropped. Found by the first live
    integration run (2026-07-27, MERGED UPDATE adding routing_tag/description to an existing defaults-only routedHost).

    ## Test

    - `existing` built from a wire response whose policy sets only adminState/mtu (description, routing_tag, ip unset)
    - `proposed` sets description, routing_tag, ip, prefix
    - `merge()` succeeds; the new fields land; the wire-present fields are retained

    ## Classes and Methods

    - NDBaseModel.merge()
    - InterfacePolicyStrictBase.strip_none_valued_keys()
    """
    existing = EthernetRoutedInterfaceModel.from_response(
        {
            "switchIp": "192.168.12.131",
            "interfaceName": "Ethernet1/31",
            "interfaceType": "ethernet",
            "configData": {
                "mode": "routed",
                "networkOS": {"networkOSType": "nx-os", "policy": {"policyType": "routedHost", "adminState": True, "mtu": 9216}},
            },
        }
    )
    proposed = EthernetRoutedInterfaceModel.model_validate(
        {
            "switch_ip": "192.168.12.131",
            "interface_name": "Ethernet1/31",
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {"policy_type": "routedHost", "ip": "10.99.31.5", "prefix": 30, "description": "Updated", "routing_tag": "54321"},
                }
            },
        }
    )
    with does_not_raise():
        existing.merge(proposed)
    policy = existing.config_data.network_os.policy
    assert policy.ip == "10.99.31.5"
    assert policy.prefix == 30
    assert policy.description == "Updated"
    assert policy.routing_tag == "54321"
    assert policy.admin_state is True
    assert policy.mtu == 9216


def test_ethernet_routed_interface_00156():
    """
    # Summary

    Verify `routing_tag` is coerced to a string when ND's GET echoes it as an integer. ND 4.2.1 retypes `routingTag`
    (string in, int out) on interface GETs (vault: interface-get-field-normalization) - without coercion,
    `from_response` hard-fails on any existing routedHost carrying a routing tag. Same drift class as loopback
    `route_map_tag`; keep the validators in sync. Found by the first live integration run (2026-07-27, MERGED UPDATE
    idempotency re-query after writing routing_tag "54321").

    ## Test

    - `from_response` with integer `routingTag` does not raise; value is the string form
    - String input passes through unchanged

    ## Classes and Methods

    - NexusEthernetRoutedPolicyModel.coerce_routing_tag()
    """
    import copy  # pylint: disable=import-outside-toplevel

    response = copy.deepcopy(SAMPLE_NX_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["routingTag"] = 54321
    with does_not_raise():
        instance = EthernetRoutedInterfaceModel.from_response(response)
    assert instance.config_data.network_os.policy.routing_tag == "54321"
    with does_not_raise():
        result = NexusEthernetRoutedPolicyModel(policy_type="routedHost", routing_tag="100")
    assert result.routing_tag == "100"


def test_ethernet_routed_interface_00160():
    """
    # Summary

    Verify a wrong-OS policy under a network-OS branch raises: an XE `policy_type` under `networkOSType: nx-os` is rejected.

    ## Test

    - NX network-OS dict with `policyType: iosXeRoutedHost` raises

    ## Classes and Methods

    - NexusEthernetRoutedNetworkOSModel.model_validate()
    """
    with pytest.raises(ValidationError):
        result = NexusEthernetRoutedNetworkOSModel.model_validate({"networkOSType": "nx-os", "policy": {"policyType": "iosXeRoutedHost", "ip": "10.1.1.1"}})


def test_ethernet_routed_interface_00165():
    """
    # Summary

    Verify the full interface model derives `policy_type` from `network_os_type` end to end: a user config that omits `policy_type`
    (argspec shape, with the omitted suboption present as `None`) selects the right network-OS branch, injects the matching
    discriminator, and produces a wire payload / config view identical to the explicit form. Covers Mike's PR #550 example
    (IOS-XE `GigabitEthernet3` without `policy_type`).

    ## Test

    - NX-OS config without `policy_type` -> `policy_type == "routedHost"`, `to_payload()` carries `policyType: routedHost`
    - IOS-XE config without `policy_type` -> `policy_type == "iosXeRoutedHost"`, `to_payload()` carries `policyType: iosXeRoutedHost`
    - The omitted form is equal to the explicit form (same `to_payload()` and `to_config()`)

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.model_validate()
    - NexusEthernetRoutedPolicyModel.default_policy_type()
    - XeEthernetRoutedPolicyModel.default_policy_type()
    """
    cases = (
        ("nx-os", "routedHost", {"ip": "10.99.99.1", "prefix": 30, "description": "L3 uplink"}),
        ("ios-xe", "iosXeRoutedHost", {"admin_state": True, "ip": "10.200.3.1", "prefix": 30, "description": "XE routed link"}),
    )
    for os_type, expected, policy in cases:
        omitted = EthernetRoutedInterfaceModel.model_validate(
            {
                "switch_ip": "192.168.2.1",
                "interface_name": "GigabitEthernet3",
                "config_data": {"network_os": {"network_os_type": os_type, "policy": {"policy_type": None, **policy}}},
            }
        )
        explicit = EthernetRoutedInterfaceModel.model_validate(
            {
                "switch_ip": "192.168.2.1",
                "interface_name": "GigabitEthernet3",
                "config_data": {"network_os": {"network_os_type": os_type, "policy": {"policy_type": expected, **policy}}},
            }
        )
        assert omitted.policy_type == expected
        assert omitted.to_payload()["configData"]["networkOS"]["policy"]["policyType"] == expected
        assert omitted.to_payload() == explicit.to_payload()
        assert omitted.to_config() == explicit.to_config()


def test_ethernet_routed_interface_00170():
    """
    # Summary

    Verify `get_argument_spec` exposes the required discriminators and the union of both branches' fields.

    ## Test

    - `network_os_type` required with choices ["nx-os", "ios-xe"]
    - `policy_type` OPTIONAL (derived from `network_os_type` when omitted) with choices ["routedHost", "iosXeRoutedHost"]
    - NX-only options (e.g. `fec`, `pim_sparse`) and shared options (`ip`, `prefix`, `vrf`) present

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.get_argument_spec()
    """
    spec = EthernetRoutedInterfaceModel.get_argument_spec()
    network_os = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]
    assert network_os["network_os_type"]["required"] is True
    assert network_os["network_os_type"]["choices"] == ["nx-os", "ios-xe"]
    policy = network_os["policy"]["options"]
    assert policy["policy_type"].get("required") is not True
    assert policy["policy_type"]["choices"] == ["routedHost", "iosXeRoutedHost"]
    for option in ("ip", "prefix", "vrf", "fec", "pim_sparse", "speed", "mtu"):
        assert option in policy


# =============================================================================
# Test: reverse_diff_defaults per routed policy_type (issue #410)
# =============================================================================

# ND 4.2.1 template-default echoes per routed `policyType`, restricted to the fields each policy model declares (the
# ND-injected `ptp` key is undeclared and dropped on read). Values are in WIRE form, sourced from the ND 4.2.1 OpenAPI
# template schemas `intRoutedHostTemplate` and `iosXeIntRoutedHostTemplate`. Held literally (not derived from the
# models' tables) so a wrong or missing table entry fails here.
ROUTED_TEMPLATE_DEFAULT_ECHOES: dict[str, tuple[type[NexusEthernetRoutedPolicyModel | XeEthernetRoutedPolicyModel], dict[str, Any]]] = {
    "routedHost": (
        NexusEthernetRoutedPolicyModel,
        {
            "adminState": True,
            "fec": "auto",
            "ipRedirects": False,
            "mtu": 9216,
            "netflow": False,
            "pfc": False,
            "pimDrPriority": 1,
            "pimSparse": False,
            "qos": False,
            "speed": "auto",
        },
    ),
    "iosXeRoutedHost": (XeEthernetRoutedPolicyModel, {"adminState": True, "mtu": 1500, "speed": "auto"}),
}

# One declared, non-default existing-side value per policy type that an admin_state-only proposed config must be seen
# to remove. `routingTag` is held as the wire integer ND 4.2.1 echoes (string in, int out).
ROUTED_NON_DEFAULT_OVERRIDES: dict[str, dict[str, Any]] = {
    "routedHost": {"routingTag": 54321},
    "iosXeRoutedHost": {"mtu": 9000},
}


@pytest.mark.parametrize("policy_type", sorted(ROUTED_TEMPLATE_DEFAULT_ECHOES))
def test_ethernet_routed_interface_00180(policy_type: str) -> None:
    """
    # Summary

    Every routed policy model normalizes its ND 4.2.1 template-default echo to absent on the reverse pass of `get_diff`,
    so a replaced/overridden run against an interface the user never customized is idempotent (issue #410), and an
    ND-injected undeclared key (`ptp`) is never counted as a pending removal.

    ## Test

    - An existing policy model built via `from_response` from the schema-sourced default echo plus the undeclared `ptp` key
    - A proposed model carrying only `policy_type` and `admin_state`
    - `to_reverse_diff_dict()` retains only `policyType`; `get_diff(proposed, exclude_unset=False)` reports no difference

    ## Classes and Methods

    - InterfacePolicyStrictBase.reverse_diff_defaults (and per-policy overrides)
    - NDBaseModel.to_reverse_diff_dict()
    - NDBaseModel.get_diff()
    """
    policy_cls, echo = ROUTED_TEMPLATE_DEFAULT_ECHOES[policy_type]
    existing = policy_cls.from_response({"policyType": policy_type, **echo, "ptp": False})
    proposed = policy_cls.from_config({"policy_type": policy_type, "admin_state": True})
    assert existing.to_reverse_diff_dict() == {"policyType": policy_type}
    assert existing.get_diff(proposed, exclude_unset=False) is True


@pytest.mark.parametrize("policy_type", sorted(ROUTED_NON_DEFAULT_OVERRIDES))
def test_ethernet_routed_interface_00190(policy_type: str) -> None:
    """
    # Summary

    Default normalization does not mask real removals: for every routed policy model, an existing-side value that
    differs from the template default is still reported as a difference against an admin_state-only proposed config
    on the replaced/overridden path.

    ## Test

    - An existing policy model built from the default echo with one declared field set to a non-default value
    - A proposed model carrying only `policy_type` and `admin_state`
    - `get_diff(proposed, exclude_unset=False)` reports a difference

    ## Classes and Methods

    - NDBaseModel.get_diff()
    """
    policy_cls, echo = ROUTED_TEMPLATE_DEFAULT_ECHOES[policy_type]
    existing = policy_cls.from_response({"policyType": policy_type, **echo, **ROUTED_NON_DEFAULT_OVERRIDES[policy_type]})
    proposed = policy_cls.from_config({"policy_type": policy_type, "admin_state": True})
    assert existing.get_diff(proposed, exclude_unset=False) is False


def test_ethernet_routed_interface_00200() -> None:
    """
    # Summary

    The reverse pass recurses through the outer `network_os_type` union into the NX-OS policy model, so a full
    `EthernetRoutedInterfaceModel` pair (ND response vs Ansible config) is replaced-idempotent when the response carries
    the user's `ip`/`prefix` plus template defaults and the ND-injected `ptp` key.

    ## Test

    - `EthernetRoutedInterfaceModel.from_response()` on an `nx-os` / `routedHost` response echoing every template default
      plus `ptp`
    - `EthernetRoutedInterfaceModel.from_config()` on the matching config that sets only `ip` and `prefix`
    - `get_diff(proposed, exclude_unset=False)` reports no difference

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.from_response()
    - EthernetRoutedInterfaceModel.from_config()
    - NDBaseModel.get_diff()
    """
    policy_cls, echo = ROUTED_TEMPLATE_DEFAULT_ECHOES["routedHost"]
    existing = EthernetRoutedInterfaceModel.from_response(
        {
            "switchIp": "192.168.12.131",
            "interfaceName": "Ethernet1/31",
            "interfaceType": "ethernet",
            "configData": {
                "mode": "routed",
                "networkOS": {
                    "networkOSType": "nx-os",
                    "policy": {"policyType": "routedHost", **echo, "ip": "10.99.31.1", "prefix": 30, "ptp": False},
                },
            },
        }
    )
    proposed = EthernetRoutedInterfaceModel.from_config(
        {
            "switch_ip": "192.168.12.131",
            "interface_name": "Ethernet1/31",
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {"policy_type": "routedHost", "ip": "10.99.31.1", "prefix": 30},
                }
            },
        }
    )
    assert isinstance(existing.config_data.network_os.policy, policy_cls)
    assert existing.get_diff(proposed, exclude_unset=False) is True


def test_ethernet_routed_interface_00210() -> None:
    """
    # Summary

    Contract test: the public argspec `choices` for `fec` and `speed` stay synchronized with the runtime enums, so ansible-doc and
    schema consumers see exactly the values the Pydantic branch models accept (PR #550 review). `speed` is the union of the NX-OS
    and IOS-XE enums (the argspec cannot express the per-`policy_type` subset; the branch models still enforce it).

    ## Test

    - `fec` choices equal the `FecEnum` values
    - `speed` choices equal the union of `SpeedEnum` and `XeEthernetSpeedEnum` values, with no duplicates
    - An IOS-XE-only speed (`noNegotiate`) is still rejected by the NX-OS branch model

    ## Classes and Methods

    - EthernetRoutedInterfaceModel.get_argument_spec()
    - NexusEthernetRoutedPolicyModel
    """
    policy_spec = EthernetRoutedInterfaceModel.get_argument_spec()["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    assert set(policy_spec["fec"]["choices"]) == {e.value for e in FecEnum}
    speed_choices = policy_spec["speed"]["choices"]
    assert set(speed_choices) == {e.value for e in SpeedEnum} | {e.value for e in XeEthernetSpeedEnum}
    assert len(speed_choices) == len(set(speed_choices))
    with pytest.raises(ValidationError):
        NexusEthernetRoutedPolicyModel(policy_type="routedHost", speed="noNegotiate")
