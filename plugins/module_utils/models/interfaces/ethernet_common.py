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

import ipaddress
import re
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationInfo
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.policy_base import InterfacePolicyStrictBase

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


def normalize_member_interface_names(value):
    """
    # Summary

    Normalize every member interface name in a port-channel `ports` list through `normalize_ethernet_interface_name` (see it for the
    expansion rules). Normalize `None` to `[]` because ND can omit an empty member list or return it as null; both wire shapes mean
    that the port-channel has no members. Any other non-list value is returned unchanged so the field's own type validation reports it.

    ## Raises

    None
    """
    if value is None:
        return []
    if not isinstance(value, list):
        return value
    return [normalize_ethernet_interface_name(name) for name in value]


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


def _normalize_prefix_length(value: Any) -> int | None:
    """
    # Summary

    Normalize an explicit prefix-length input to `int` using the same lax rules pydantic applies to an `int` field: an `int`, a `float`
    with no fractional part, or a string holding either (whitespace tolerated). Return `None` for anything else, including `bool`,
    which pydantic also rejects for an `int` field.

    ## Raises

    None
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            try:
                value = float(value)
            except ValueError:
                return None
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def reconcile_cidr_prefix(data: Any, address_key: str, prefix_keys: tuple[str, ...], family: int) -> Any:
    """
    # Summary

    Reconcile CIDR input with a sibling prefix field, for a `mode="before"` model validator. When `data[address_key]` is written in
    CIDR notation (`10.1.1.1/24`), the address is rewritten to its bare host form and the mask is never lost: it fills the prefix
    field when that field is absent or `None`, and must agree with it when it is set. `prefix_keys` are the names the prefix may
    arrive under (field name first, then the wire alias); `family` is 4 or 6. Input that is not a dict, an address without a `/`,
    and an address that does not parse (left for the field validator to report) are returned unchanged.

    The explicit prefix is normalized with the same lax integer rules pydantic applies to the field before the comparison, so a quoted
    decimal such as `"24.0"` cannot hide a conflicting mask (PR #636 review). A prefix that is not an integer under those rules is rejected
    here, while the mask is still on the address, instead of being left for the field validator after the mask has been stripped.

    ## Raises

    ### ValueError

    - If the CIDR mask and the explicit prefix disagree.
    - If the explicit prefix is not an integer.
    """
    if not isinstance(data, dict):
        return data
    address = data.get(address_key)
    if not isinstance(address, str) or "/" not in address:
        return data
    try:
        parsed = ipaddress.IPv4Interface(address.strip()) if family == 4 else ipaddress.IPv6Interface(address.strip())
    except ValueError:
        return data
    derived = parsed.network.prefixlen
    explicit_key = next((key for key in prefix_keys if data.get(key) is not None), None)
    if explicit_key is not None:
        explicit = _normalize_prefix_length(data[explicit_key])
        if explicit is None:
            raise ValueError(f"{prefix_keys[0]} {data[explicit_key]!r} is not an integer; {address_key} '{address}' carries the mask /{derived}.")
        if explicit != derived:
            raise ValueError(f"{address_key} '{address}' carries the mask /{derived} but {prefix_keys[0]} is {explicit}; remove one or make them agree.")
    reconciled = {key: value for key, value in data.items() if key not in prefix_keys or value is not None}
    reconciled[address_key] = str(parsed.ip)
    reconciled[explicit_key if explicit_key is not None else prefix_keys[0]] = derived
    return reconciled


def require_address_prefix_pair(address: Any, prefix: Any, address_name: str, prefix_name: str, info: ValidationInfo | None = None) -> None:
    """
    # Summary

    Reject half of an address / prefix pair, for a `mode="after"` model validator: an address without its prefix length, or a prefix
    length without its address, is never serialized into a payload the controller would reject or apply ambiguously.

    The check runs only while validating config input (`info.context["mode"] == "config"`, set by `NDBaseModel.from_config`), which is the
    path every module and the interfaces workflow adapter use, and the only one that can introduce a user-authored half pair. It is skipped:

    - on `mode="response"`, so a prefix-only policy ND silently stored (issue #584) is read truthfully instead of failing the query;
    - on assignment, which carries no context: `NDBaseModel.merge()` assigns one field at a time under `validate_assignment`, so adding a
      pair to a policy that had neither passes through a transient half pair, and any field declared between the two is assigned while
      the pair is still half. The merged result is re-checked by `AddressPrefixPairMixin.merge`, because the existing side of a merge was
      read tolerantly and may itself carry a half pair the controller stored.

    `info.field_name` cannot be used to detect assignment: pydantic also sets it (to the parent field, `policy`) while validating this
    model nested inside its interface model, which would silence the check on every real path (PR #636 review).

    ## Raises

    ### ValueError

    - If exactly one of `address` / `prefix` is set on config input.
    """
    if (getattr(info, "context", None) or {}).get("mode") != "config":
        return
    if (address is None) != (prefix is None):
        raise ValueError(f"{address_name} and {prefix_name} are required together; set both or neither.")


class AddressPrefixPairMixin(InterfacePolicyStrictBase):
    """
    # Summary

    Policy-model base that re-checks every address / prefix pair in `address_prefix_pairs` on the result of `NDBaseModel.merge()`.

    `require_address_prefix_pair` guards config input only, so a half pair the controller already stores (ND accepts and echoes a `prefix`
    without `ip`, issue #584) is read tolerantly and would otherwise ride along unchanged into a merged update that touches an unrelated field,
    such as a description (PR #636 review). The merge is the only path that can produce such a policy for a write: `replaced` and create
    candidates are validated whole from config. Checking the merged result here covers `NDStateMachine`, `NDStatePlanner` (the interfaces
    workflow) and `NDConfigCollection.merge` without a second controller read, and still lets the task that supplies both halves repair the
    stored state.

    Subclasses list their pairs as `(address_field, prefix_field)` tuples in `address_prefix_pairs`.

    ## Raises

    None
    """

    address_prefix_pairs: ClassVar[tuple[tuple[str, str], ...]] = ()

    def merge(self, other: NDBaseModel) -> NDBaseModel:
        """
        # Summary

        Merge `other` into `self` (see `NDBaseModel.merge`), then reject a merged policy that still holds half of any pair in
        `address_prefix_pairs`.

        ## Raises

        ### ValueError

        - If the merged policy has exactly one of a pair's address / prefix set. The message names the half that is present, the half that is
          missing, and the remedy (set both in the task, or use `state: replaced`).
        """
        merged = super().merge(other)
        for address_name, prefix_name in self.address_prefix_pairs:
            address = getattr(merged, address_name, None)
            prefix = getattr(merged, prefix_name, None)
            if (address is None) == (prefix is None):
                continue
            present, missing = (address_name, prefix_name) if address is not None else (prefix_name, address_name)
            raise ValueError(
                f"{address_name} and {prefix_name} are required together, but the merged policy has {present} without {missing} "
                f"(the controller already stores this half pair). Set {address_name} and {prefix_name} together in the task, or use state: replaced."
            )
        return merged
