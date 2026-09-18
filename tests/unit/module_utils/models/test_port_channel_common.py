# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for port_channel_common.py

Tests the port-channel interface-name normalizer shared by the access, trunk-host and routed port-channel models (issue #378), and that
each concrete model inherits it through `PortChannelInterfaceBaseModel`.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import PortChannelAccessInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_common import normalize_port_channel_interface_name
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_routed_interface import PortChannelRoutedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import PortChannelTrunkHostInterfaceModel
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from pydantic import ValidationError

# One minimal, valid playbook item per concrete model, keyed by a readable id. `interface_name` is filled in by each test.
MODEL_CONFIGS = {
    "access": (PortChannelAccessInterfaceModel, {"network_os": {"policy": {"access_vlan": 100}}}),
    "trunk_host": (PortChannelTrunkHostInterfaceModel, {"network_os": {"policy": {"allowed_vlans": "none"}}}),
    "routed": (PortChannelRoutedInterfaceModel, {"network_os": {"network_os_type": "nx-os", "policy": {"ip": "10.1.1.1", "prefix": 30}}}),
}


def build(model_key: str, interface_name, network_os_type: str | None = None):
    """Build the concrete model named by `model_key` with `interface_name`, optionally forcing `network_os_type`."""
    model_class, config_data = MODEL_CONFIGS[model_key]
    network_os = dict(config_data["network_os"])
    if network_os_type is not None:
        network_os["network_os_type"] = network_os_type
    return model_class.from_config({"switch_ip": "192.168.1.1", "interface_name": interface_name, "config_data": {"network_os": network_os}})


# =============================================================================
# Test: normalize_port_channel_interface_name
# =============================================================================


@pytest.mark.parametrize(
    "value, expected",
    [
        (501, "port-channel501"),
        ("501", "port-channel501"),
        (" 501 ", "port-channel501"),
        (1, "port-channel1"),
        (4096, "port-channel4096"),
        ("port-channel501", "port-channel501"),
        ("Port-Channel501", "port-channel501"),
        ("PORT-CHANNEL501", "port-channel501"),
        ("Port-channel1", "port-channel1"),
        ("port-channel4096", "port-channel4096"),
    ],
)
def test_port_channel_common_00000(value, expected):
    """
    # Summary

    Verify a bare port-channel ID is accepted and prefixed, and that any casing of the canonical `port-channel` prefix is lowercased, with
    the boundary IDs 1 and 4096 accepted.

    ## Test

    - Bare `int`, bare numeric `str` (with surrounding whitespace) -> `port-channel<N>`
    - Case variants of `port-channel<N>` -> lowercase

    ## Classes and Methods

    - normalize_port_channel_interface_name()
    """
    with does_not_raise():
        assert normalize_port_channel_interface_name(value) == expected


@pytest.mark.parametrize("value", [0, 4097, "0", "5000", "port-channel0", "Port-Channel4097", "port-channel5000"])
def test_port_channel_common_00010(value):
    """
    # Summary

    Verify an extractable port-channel ID outside 1-4096 fails early with a clear error instead of being rejected by the controller.

    ## Test

    - Bare and prefixed IDs of 0, 4097 and 5000 raise `ValueError` naming the range and the offending ID

    ## Classes and Methods

    - normalize_port_channel_interface_name()
    """
    with pytest.raises(ValueError, match=r"Port-channel ID must be in the range 1-4096, got \d+\."):
        normalize_port_channel_interface_name(value)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("po501", "po501"),
        ("Po501", "po501"),
        ("port-channel 501", "port-channel 501"),
        ("port-channel", "port-channel"),
        ("port-channel501.5", "port-channel501.5"),
        ("Ethernet1/1", "ethernet1/1"),
        ("", ""),
    ],
)
def test_port_channel_common_00020(value, expected):
    """
    # Summary

    Verify an input with no extractable port-channel ID passes through lowercased, exactly as before issue #378: no abbreviation expansion
    (parity with the SVI normalizer) and no range check.

    ## Test

    - `po501`, a spaced name, a bare prefix, a subinterface-style name, another family and the empty string are only lowercased

    ## Classes and Methods

    - normalize_port_channel_interface_name()
    """
    with does_not_raise():
        assert normalize_port_channel_interface_name(value) == expected


@pytest.mark.parametrize("value", [True, False, None, 5.0, ["port-channel501"]])
def test_port_channel_common_00030(value):
    """
    # Summary

    Verify non-string, non-integer input is returned untouched so Pydantic reports the type error. `bool` is an `int` subclass and must
    not be read as port-channel ID 1 or 0.

    ## Test

    - `True`, `False`, `None`, a float and a list are returned as-is

    ## Classes and Methods

    - normalize_port_channel_interface_name()
    """
    assert normalize_port_channel_interface_name(value) is value


# =============================================================================
# Test: every concrete port-channel model inherits the normalizer
# =============================================================================


@pytest.mark.parametrize("model_key", list(MODEL_CONFIGS))
def test_port_channel_common_00100(model_key):
    """
    # Summary

    Verify the access, trunk-host and routed models all accept a bare ID and reject an out-of-range one through the shared base, so the
    logic lives in one place.

    ## Test

    - `interface_name: "501"` -> `port-channel501` in the model, the config dump and the payload
    - `interface_name: "port-channel5000"` raises `ValidationError` naming the range

    ## Classes and Methods

    - PortChannelInterfaceBaseModel.normalize_interface_name()
    """
    instance = build(model_key, "501")
    assert instance.interface_name == "port-channel501"
    assert instance.to_config()["interface_name"] == "port-channel501"
    assert instance.to_payload()["interfaceName"] == "port-channel501"
    with pytest.raises(ValidationError, match=r"Port-channel ID must be in the range 1-4096, got 5000\."):
        build(model_key, "port-channel5000")


@pytest.mark.parametrize("model_key", list(MODEL_CONFIGS))
def test_port_channel_common_00110(model_key):
    """
    # Summary

    Verify a bare ID composes with the IOS-XE create-name rewrite: the identifier stays lowercase while the create body carries the
    switch-canonical `Port-channel<N>`.

    # workaround: xe-port-channel-create-requires-canonical-name

    ## Test

    - IOS-XE item with `interface_name: "101"` -> `interface_name == "port-channel101"`, payload `interfaceName == "Port-channel101"`

    ## Classes and Methods

    - PortChannelInterfaceBaseModel.normalize_interface_name()
    - PortChannelInterfaceBaseModel._canonical_xe_create_name()
    """
    instance = build(model_key, "101", network_os_type="ios-xe")
    assert instance.interface_name == "port-channel101"
    assert instance.to_payload()["interfaceName"] == "Port-channel101"
