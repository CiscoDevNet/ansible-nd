# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Helpers shared by the ethernet interface models (`nd_interface_ethernet_*`) that carry both an NX-OS and an IOS-XE branch.

Promoted from `ethernet_routed_interface.py` (issue #447) when the access and trunk-host models grew their IOS-XE branches
(issues #534 / #535) so the discriminator injection and the cross-OS interface-name normalization have one implementation.

TODO: issue #353 consolidates per-model interface-name normalization into shared helpers; `normalize_ethernet_interface_name`
is the cross-OS seed for that helper.
"""

from __future__ import annotations

import re
from typing import Any

# Leading alphabetic prefix + the remainder (digits, /, ., -) of an interface name.
_INTERFACE_NAME_PREFIX_RE = re.compile(r"^([A-Za-z]+)(.*)$")

# Wire-canonical interface-name prefixes the ethernet modules manage (lab-verified 2026-07-27: ND echoes
# `Ethernet1/7` on NX-OS and `GigabitEthernet3` on IOS-XE). A user-supplied prefix that is a
# case-insensitive prefix of exactly ONE canonical name is expanded to it (e.g. `e1/7`, `eth1/7`,
# `gi3`); anything else passes through verbatim so correctly-typed names of other XE interface
# families (e.g. `TenGigabitEthernet1/1`, `TwentyFiveGigE1/0/1`) are never corrupted.
_CANONICAL_INTERFACE_PREFIXES = ("Ethernet", "GigabitEthernet")


def normalize_ethernet_interface_name(value):
    """
    # Summary

    Normalize the leading alphabetic prefix of an interface name to its wire-canonical form. A prefix matching
    (case-insensitively) exactly one of `_CANONICAL_INTERFACE_PREFIXES` is expanded to it; an ambiguous or unrecognized
    prefix passes through verbatim - never re-cased. Digits and separators are preserved. Examples:

    - `ethernet1/7`, `ETHERNET1/7`, `eth1/7`, `e1/7` -> `Ethernet1/7`
    - `gigabitethernet3`, `gi3` -> `GigabitEthernet3`
    - `Ethernet1/1.10` -> `Ethernet1/1.10` (idempotent)
    - `TenGigabitEthernet1/1`, `t1/1` -> unchanged

    Shared between the models' `interface_name` field validators and the orchestrators' config-name matching so both sides
    canonicalize identically.

    ## Raises

    None
    """
    if not isinstance(value, str) or not value:
        return value
    match = _INTERFACE_NAME_PREFIX_RE.match(value)
    if not match:
        return value
    prefix, rest = match.groups()
    expansions = [canonical for canonical in _CANONICAL_INTERFACE_PREFIXES if canonical.lower().startswith(prefix.lower())]
    if len(expansions) == 1:
        return expansions[0] + rest
    return value


def default_policy_type(data: Any, policy_type: str) -> Any:
    """
    # Summary

    Inject the `policyType` discriminator into a policy input dict when the caller did not supply it (key absent, or present with
    `None`, which is how the Ansible argspec passes an omitted suboption). Each ethernet module manages exactly one host-facing
    policy type per network OS today, so `policy_type` is fully determined by `network_os_type` and the user need not repeat it
    (PR #550 review). An explicit value is left untouched, which keeps the input forward-compatible with feature-gated follow-on
    branches: when a branch becomes a `policy_type` discriminated union, this same injection supplies the discriminator Pydantic
    needs for an omitted value. Injecting on the input (rather than a field default) makes the field explicitly SET, so `merge()`
    / `get_diff(exclude_unset=True)` treat it exactly like a typed value.

    ## Raises

    None
    """
    if not isinstance(data, dict):
        return data
    if data.get("policyType") is not None or data.get("policy_type") is not None:
        return data
    return {**{key: value for key, value in data.items() if key not in ("policyType", "policy_type")}, "policyType": policy_type}


def default_network_os_type(data: Any, network_os_type: str = "nx-os") -> Any:
    """
    # Summary

    Inject the `networkOSType` discriminator into a network-OS input dict when the caller did not supply it (key absent, or present
    with `None`). Pydantic resolves a discriminated union from the INPUT, not from a field default, so a module whose pre-IOS-XE
    argspec never exposed `network_os_type` needs this to keep existing playbooks selecting the NX-OS branch unchanged. An explicit
    value is left untouched.

    ## Raises

    None
    """
    if not isinstance(data, dict):
        return data
    if data.get("networkOSType") is not None or data.get("network_os_type") is not None:
        return data
    return {**{key: value for key, value in data.items() if key not in ("networkOSType", "network_os_type")}, "networkOSType": network_os_type}
