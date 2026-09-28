# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for interface_default_config.py

Tests the `int_trunk_host` default-config model that builds the `interfaceActions/normalize` body and the per-interface
PUT-as-replace reset body used by the ethernet interface orchestrators' delete path.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import (
    InterfaceDefaultConfig,
    InterfaceDefaultPolicyModel,
)


def test_interface_default_config_00000() -> None:
    """
    # Summary

    Verify the `int_trunk_host` policy defaults, in particular that `description` defaults to the template's empty string, which is
    what ND 4.2.1 needs to clear a description (it leaves an omitted field untouched).

    ## Test

    - Instantiate `InterfaceDefaultPolicyModel` with no arguments
    - `policy_type` is `trunkHost`, `mode` is `trunk`, `mtu` is `jumbo`
    - `description` is `""`

    ## Classes and Methods

    - InterfaceDefaultPolicyModel.__init__()
    """
    instance = InterfaceDefaultPolicyModel()
    assert instance.policy_type == "trunkHost"
    assert instance.mode == "trunk"
    assert instance.mtu == "jumbo"
    assert instance.description == ""


def test_interface_default_config_00100() -> None:
    """
    # Summary

    Verify `to_normalize_payload` builds the full `int_trunk_host` template body, with `description: ""` by default and without the
    key under `omit_description=True`.

    The spec types the ethernet policy `description` as `interfaceDescription` (`minLength: 1`) on both ND 4.2.1 and 4.3.1.
    ND 4.2.1 accepts the empty string and needs it to clear a description (an omitted field is left untouched); ND 4.3.1 rejects
    it with HTTP 400 `minimum string length is 1` but resets an omitted field. The orchestrator picks the variant per run.

    ## Test

    - Build the payload for two `(interface_name, switch_id)` pairs
    - Top-level `interfaceType` is `ethernet`; `switchInterfaces` carries both pairs in order
    - `configData.mode` is `trunk`; the policy carries `policyType: trunkHost`, the template fields, and `description: ""`
    - With `omit_description=True` the policy has no `description` key and is otherwise identical
    - Other empty-string template fields (`extraConfig`) are sent in both variants; only `description` carries `minLength: 1`

    ## Classes and Methods

    - InterfaceDefaultConfig.to_normalize_payload()
    """
    payload = InterfaceDefaultConfig.to_normalize_payload([("Ethernet1/48", "FDO11111AAA"), ("Ethernet1/49", "FDO22222BBB")])

    assert payload["interfaceType"] == "ethernet"
    assert payload["switchInterfaces"] == [
        {"interfaceName": "Ethernet1/48", "switchId": "FDO11111AAA"},
        {"interfaceName": "Ethernet1/49", "switchId": "FDO22222BBB"},
    ]
    assert payload["configData"]["mode"] == "trunk"
    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == "trunkHost"
    assert policy["mtu"] == "jumbo"
    assert policy["allowedVlans"] == "none"
    assert policy["nativeVlan"] == 1
    assert policy["adminState"] is True
    assert policy["description"] == ""
    assert policy["extraConfig"] == ""

    omitted = InterfaceDefaultConfig.to_normalize_payload([("Ethernet1/48", "FDO11111AAA"), ("Ethernet1/49", "FDO22222BBB")], omit_description=True)
    omitted_policy = omitted["configData"]["networkOS"]["policy"]
    assert "description" not in omitted_policy
    assert omitted_policy["extraConfig"] == ""
    assert {k: v for k, v in policy.items() if k != "description"} == omitted_policy
    assert omitted["switchInterfaces"] == payload["switchInterfaces"]


def test_interface_default_config_00110() -> None:
    """
    # Summary

    Verify `to_reset_payload` builds the minimal per-interface PUT-as-replace body and never carries a `description`.

    ## Test

    - Build the reset body for one interface
    - `interfaceName`, `switchId`, `interfaceType: ethernet` are set at the top level
    - The policy is exactly `{"adminState": True, "policyType": "trunkHost"}`

    ## Classes and Methods

    - InterfaceDefaultConfig.to_reset_payload()
    """
    payload = InterfaceDefaultConfig.to_reset_payload("Ethernet1/48", "FDO11111AAA")

    assert payload["interfaceName"] == "Ethernet1/48"
    assert payload["switchId"] == "FDO11111AAA"
    assert payload["interfaceType"] == "ethernet"
    assert payload["configData"]["mode"] == "trunk"
    assert payload["configData"]["networkOS"]["networkOSType"] == "nx-os"
    assert payload["configData"]["networkOS"]["policy"] == {"adminState": True, "policyType": "trunkHost"}
