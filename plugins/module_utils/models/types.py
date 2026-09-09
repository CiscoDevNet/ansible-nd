# Copyright: (c) 2026, Allen Robel (@allenrobel)
# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared Pydantic Annotated types for ND model fields.

These types layer custom validators on top of standard Pydantic types so that cross-cutting input rules can be
applied consistently across model files (e.g. all `description` fields share the same ASCII-only constraint).

## Available types

- `AsciiDescription` — `str | None` that rejects any non-ASCII character. Use for interface `description` fields
  on any policy model that maps to an ND CLI-generated config line. The Cisco backend pipes these descriptions
  through CLI generators that fail with a generic 500 ("unexpected error during policy execution") when given
  UTF-8 input. Catching this client-side gives users a clear error instead of a confusing server fault.
- `IPv4CIDR` — `str | None` validated as an IPv4 interface address in CIDR notation (e.g. `10.1.1.1/32`).
- `IPv6CIDR` — `str | None` validated as an IPv6 interface address in CIDR notation (e.g. `2001:db8::1/128`).
- `IPv4Host` — `str | None` that accepts bare (`10.1.1.1`) or CIDR (`10.1.1.1/32`) input and normalizes to the bare
  host address. Use where ND rejects CIDR notation on the wire (e.g. the loopback `ip` field).
- `IPv6Host` — `str | None` that accepts bare (`2001:db8::1`) or CIDR (`2001:db8::1/128`) input and normalizes to the bare
  host address. Use where ND validates the field as a bare IPv6 address and applies the prefix length itself (e.g. the
  loopback `ipv6` field, rendered as `/128` by the ND template).
- `IPv4HostStrict` — `str | None` that accepts only a bare IPv4 address and rejects CIDR input. Use where the mask
  length lives in a separate sibling field (e.g. the IPFM `secondaryIpList` item's `prefix`), so CIDR input would be
  ambiguous and silently normalizing it could contradict the sibling field.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated, Optional  # Optional required here; see AsciiDescription comment below

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import AfterValidator, BeforeValidator, Field


def ascii_only(value: str | None) -> str | None:
    """
    # Summary

    Validate that `value` contains only ASCII characters. Returns the value unchanged if it passes, or raises
    `ValueError` with a position indicator on the first non-ASCII character.

    Used as the `AfterValidator` payload for the `AsciiDescription` Annotated type.

    ## Raises

    ### ValueError

    - If `value` contains any non-ASCII character.
    """
    if value is None:
        return value
    try:
        value.encode("ascii")
    except UnicodeEncodeError as e:
        raise ValueError(
            f"description must contain only ASCII characters; got non-ASCII at position {e.start}: {value[e.start]!r}. "
            "The ND backend currently returns a generic 500 for non-ASCII descriptions."
        ) from None
    return value


# NOTE: Optional[str] is intentional here. `str | None` is preferred elsewhere in this project, but
# Annotated[...] is a runtime expression — `from __future__ import annotations` does not protect it.
# ansible-test's pylint (running without a py-version hint) flags `str | None` in runtime position as
# `unsupported-binary-operation`. Optional[str] avoids the | operator at runtime without changing semantics.
AsciiDescription = Annotated[Optional[str], AfterValidator(ascii_only)]
"""ASCII-only `str | None`. Layer with `Field(...)` for `max_length` / `min_length` / aliases as usual."""


def validate_ipv4_cidr(value: str | None) -> str | None:
    """
    # Summary

    Validate that `value` is an IPv4 interface address in CIDR notation. Returns the value unchanged on success.

    Used as the `BeforeValidator` payload for the `IPv4CIDR` Annotated type.

    ## Raises

    ### ValueError

    - If `value` is not a valid IPv4 interface address in CIDR notation.
    """
    if value is None:
        return value
    try:
        ipaddress.IPv4Interface(value)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
        raise ValueError(f"Invalid IPv4 address: {value!r}. Expected CIDR notation (e.g. '10.1.1.1/32').") from err
    return value


def validate_ipv6_cidr(value: str | None) -> str | None:
    """
    # Summary

    Validate that `value` is an IPv6 interface address in CIDR notation. Returns the value unchanged on success.

    Used as the `BeforeValidator` payload for the `IPv6CIDR` Annotated type.

    ## Raises

    ### ValueError

    - If `value` is not a valid IPv6 interface address in CIDR notation.
    """
    if value is None:
        return value
    try:
        ipaddress.IPv6Interface(value)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
        raise ValueError(f"Invalid IPv6 address: {value!r}. Expected CIDR notation (e.g. '2001:db8::1/128').") from err
    return value


# See AsciiDescription comment above for why Optional[str] is used at runtime instead of `str | None`.
IPv4CIDR = Annotated[Optional[str], BeforeValidator(validate_ipv4_cidr)]
"""IPv4 interface address in CIDR notation (`str | None`). Layer with `Field(...)` for alias/description as usual."""

IPv6CIDR = Annotated[Optional[str], BeforeValidator(validate_ipv6_cidr)]
"""IPv6 interface address in CIDR notation (`str | None`). Layer with `Field(...)` for alias/description as usual."""


def validate_ipv4_host(value: str | None) -> str | None:
    """
    # Summary

    Normalize an IPv4 interface address to its bare host form (strip any prefix). Accepts bare (`10.1.1.1`) or CIDR
    (`10.1.1.1/32`) and returns the bare address, because ND's loopback `ip` field rejects CIDR notation.

    ## Raises

    ### ValueError

    - If `value` is not a valid IPv4 address or interface.
    """
    if value is None:
        return value
    try:
        return str(ipaddress.IPv4Interface(value).ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
        raise ValueError(f"'{value}' is not a valid IPv4 address") from err


# See AsciiDescription comment above for why Optional[str] is used at runtime instead of `str | None`.
IPv4Host = Annotated[Optional[str], BeforeValidator(validate_ipv4_host)]
"""IPv4 host address (`str | None`). Accepts bare or CIDR input; normalizes to the bare host form (no prefix).
Layer with `Field(...)` for alias/description as usual."""


def validate_ipv6_host(value: str | None) -> str | None:
    """
    # Summary

    Normalize an IPv6 interface address to its bare host form (strip any prefix). Accepts bare (`2001:db8::1`) or CIDR
    (`2001:db8::1/128`) and returns the bare address, because ND validates the loopback `ipv6` field as a bare IPv6 address
    and applies the `/128` prefix length itself (lab-verified on ND 4.2.1: CIDR input is rejected with HTTP 400).

    ## Raises

    ### ValueError

    - If `value` is not a valid IPv6 address or interface.
    """
    if value is None:
        return value
    try:
        return str(ipaddress.IPv6Interface(value).ip)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as err:
        raise ValueError(f"'{value}' is not a valid IPv6 address") from err


# See AsciiDescription comment above for why Optional[str] is used at runtime instead of `str | None`.
IPv6Host = Annotated[Optional[str], BeforeValidator(validate_ipv6_host)]
"""IPv6 host address (`str | None`). Accepts bare or CIDR input; normalizes to the bare host form (no prefix).
Layer with `Field(...)` for alias/description as usual."""


def validate_ipv4_host_strict(value: str | None) -> str | None:
    """
    # Summary

    Validate that `value` is a bare IPv4 host address (no prefix). Unlike `validate_ipv4_host`, CIDR input is
    rejected rather than normalized — use where the mask length lives in a separate sibling field, so a prefix
    embedded in the address could silently contradict it.

    ## Raises

    ### ValueError

    - If `value` is not a valid bare IPv4 address (including any CIDR form).
    """
    if value is None:
        return value
    try:
        ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, ValueError) as err:
        raise ValueError(f"'{value}' is not a valid bare IPv4 address (CIDR notation is not accepted)") from err
    return value


# See AsciiDescription comment above for why Optional[str] is used at runtime instead of `str | None`.
IPv4HostStrict = Annotated[Optional[str], BeforeValidator(validate_ipv4_host_strict)]
"""Bare IPv4 host address (`str | None`); CIDR input is rejected, not normalized.
Layer with `Field(...)` for alias/description as usual."""

# Fabric name rules (verified against ND 4.2.x GUI):
#   - Allowed chars: a-z, A-Z, 0-9, _, -
#   - Must start AND end with an alphanumeric (no leading/trailing _ or -)
#   - Numbers alone are not allowed (must contain at least one letter)
#   - Length 1-64 (enforced by the regex itself)
_FABRIC_NAME_RE = re.compile(
    r"^(?=.*[A-Za-z])"  # at least one letter (rejects all-digit)
    r"[A-Za-z0-9]"  # start: alphanumeric
    r"(?:[A-Za-z0-9_-]{0,62}"  # middle: up to 62 inner chars
    r"[A-Za-z0-9])?$"  # end: alphanumeric (skipped if length is 1)
)


def _validate_fabric_name(value: str) -> str:
    """Validate that a fabric name matches ND's naming constraints."""
    if not _FABRIC_NAME_RE.match(value):
        raise ValueError(
            f"Invalid fabric name {value!r}. Allowed chars: a-z, A-Z, 0-9, _, -. "
            "Must start and end with an alphanumeric character, must contain at "
            "least one letter, and must be 1-64 characters."
        )
    return value


NdFabricName = Annotated[
    str,
    Field(alias="name", min_length=1, max_length=64, description="Fabric name"),
    AfterValidator(_validate_fabric_name),
]
