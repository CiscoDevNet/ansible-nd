# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Generic validators for common network and system fields.

These validators are reusable across different models and modules.
They follow a consistent pattern:
- Accept str | None or other types
- Return None when input is None or empty after stripping
- Raise ValueError with descriptive messages on validation failure
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Callable

# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


def _normalize_optional_string(v: str | None) -> str | None:
    """Normalize an optional string value.

    Converts the value to string, strips whitespace, and returns ``None``
    if the value is ``None`` or empty after stripping.

    This is a common preprocessing step for string-based validators.

    Args:
        v: Raw value that may be ``None``, empty, or contain whitespace.

    Returns:
        Stripped non-empty string, or ``None``.
    """
    if v is None:
        return None
    v = str(v).strip()
    if not v:
        return None
    return v


def _require_field(
    v: str,
    validator_func: Callable[[str | None], str | None],
    field_name: str,
) -> str:
    """Validate and require a non-empty field value.

    Generic wrapper that calls a nullable validator and raises
    ``ValueError`` when the result is ``None`` (empty after stripping).

    Args:
        v: Raw field value from Pydantic.
        validator_func: Validator function that accepts optional string.
        field_name: Field name used in the error message.

    Returns:
        Validated non-empty string.

    Raises:
        ValueError: When the value is empty or fails validation.
    """
    result = validator_func(v)
    if result is None:
        raise ValueError(f"{field_name} cannot be empty")
    return result


# ------------------------------------------------------------------
# IP Address and Network Validators
# ------------------------------------------------------------------


def validate_ip_address(v: str | None) -> str | None:
    """Validate IPv4 or IPv6 address.

    Args:
        v: Raw IP address value.

    Returns:
        Validated IP address string, or ``None`` if input is None/empty.

    Raises:
        ValueError: When the value is not a valid IPv4/v6 address.
    """
    v = _normalize_optional_string(v)
    if v is None:
        return None
    try:
        ip_address(v)
        return v
    except ValueError:
        raise ValueError(f"Invalid IP address format: {v}")


def validate_cidr(v: str | None) -> str | None:
    """Validate CIDR notation (IP/mask).

    Args:
        v: Raw CIDR value.

    Returns:
        Validated CIDR string, or ``None`` if input is None/empty.

    Raises:
        ValueError: When the value is not valid CIDR notation.
    """
    v = _normalize_optional_string(v)
    if v is None:
        return None
    if "/" not in v:
        raise ValueError(f"CIDR notation required (IP/mask format): {v}")
    try:
        ip_network(v, strict=False)
        return v
    except ValueError:
        raise ValueError(f"Invalid CIDR format: {v}")


def validate_ip_or_cidr_as_cidr(v: str | None) -> str | None:
    """Validate IP or CIDR and normalize to CIDR notation.

    Accepts either a plain IP address or CIDR notation.
    Plain IPs are normalized to /32 (IPv4) or /128 (IPv6).

    Args:
        v: Raw IP or CIDR value.

    Returns:
        Normalized CIDR string (e.g., "10.1.1.1/32"), or ``None``.

    Raises:
        ValueError: When the value is not a valid IP or CIDR.
    """
    v = _normalize_optional_string(v)
    if v is None:
        return None

    # If already in CIDR notation, validate it
    if "/" in v:
        try:
            network = ip_network(v, strict=False)
            return str(network)
        except ValueError:
            raise ValueError(f"Invalid CIDR format: {v}")

    # Plain IP - validate and append appropriate mask
    try:
        ip_obj = ip_address(v)
        # IPv4 gets /32, IPv6 gets /128
        prefix_len = 32 if ip_obj.version == 4 else 128
        return f"{v}/{prefix_len}"
    except ValueError:
        raise ValueError(f"Invalid IP address format: {v}")


def require_ip_address(v: str) -> str:
    """Validate and require a non-empty IP address.

    Args:
        v: Raw IP address value.

    Returns:
        Validated IP address string.

    Raises:
        ValueError: When the value is empty or not a valid IPv4/v6 address.
    """
    return _require_field(v, validate_ip_address, "IP address")


def require_ip_or_cidr_as_cidr(v: str) -> str:
    """Validate and require a non-empty IP or CIDR, normalized to CIDR.

    Args:
        v: Raw IP or CIDR value.

    Returns:
        Validated CIDR string (plain IPs converted to /32 or /128).

    Raises:
        ValueError: When the value is empty or not a valid IP/CIDR.
    """
    return _require_field(v, validate_ip_or_cidr_as_cidr, "IP or CIDR")


def validate_cidr_optional(v: str | None) -> str | None:
    """Validate an optional CIDR string; pass through ``None`` unchanged.

    Args:
        v: Raw CIDR value or ``None``.

    Returns:
        Validated CIDR string, or ``None``.

    Raises:
        ValueError: When the value is present but not valid CIDR notation.
    """
    if v is None:
        return None
    return _require_field(v, validate_cidr, "CIDR")


# ------------------------------------------------------------------
# Hostname and MAC Address Validators
# ------------------------------------------------------------------


def validate_hostname(v: str | None) -> str | None:
    """Validate hostname format (RFC 1123).

    Args:
        v: Raw hostname value.

    Returns:
        Validated hostname string, or ``None`` if input is None/empty.

    Raises:
        ValueError: When the value fails RFC 1123 checks.
    """
    v = _normalize_optional_string(v)
    if v is None:
        return None
    # RFC 1123 hostname validation
    if len(v) > 255:
        raise ValueError("Hostname cannot exceed 255 characters")
    # Allow alphanumeric, dots, hyphens, underscores
    # Must start with alphanumeric, cannot end with dot or contain consecutive dots
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", v):
        raise ValueError(f"Invalid hostname format. Must start with alphanumeric and contain only alphanumeric, dots, hyphens, underscores: {v}")
    if v.endswith(".") or ".." in v:
        raise ValueError(f"Invalid hostname format. Cannot end with dot or contain consecutive dots: {v}")
    return v


def require_hostname(v: str) -> str:
    """Validate and require a non-empty hostname.

    Args:
        v: Raw hostname value.

    Returns:
        Validated hostname string.

    Raises:
        ValueError: When the value is empty or fails RFC 1123 checks.
    """
    return _require_field(v, validate_hostname, "hostname")


def validate_mac_address(v: str | None) -> str | None:
    """Validate MAC address format and normalize.

    Accepts multiple common MAC address formats:
    - Colon-separated: AA:BB:CC:DD:EE:FF
    - Hyphen-separated: AA-BB-CC-DD-EE-FF
    - Cisco dot-notation: aabb.ccdd.eeff
    - Bare hex: aabbccddeeff

    Returns normalized uppercase colon-separated format: AA:BB:CC:DD:EE:FF

    Args:
        v: Raw MAC address value.

    Returns:
        Normalized MAC address (AA:BB:CC:DD:EE:FF), or ``None`` if input is None/empty.

    Raises:
        ValueError: When the value is not a valid MAC address.
    """
    v = _normalize_optional_string(v)
    if v is None:
        return None

    # Remove common separators and convert to lowercase
    clean_mac = v.lower().replace(":", "").replace("-", "").replace(".", "")

    # Validate it's exactly 12 hex characters
    if not re.match(r"^[0-9a-f]{12}$", clean_mac):
        raise ValueError(
            f"Invalid MAC address format: {v}. "
            f"Expected 12 hex digits in formats like AA:BB:CC:DD:EE:FF, "
            f"AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff, or aabbccddeeff"
        )

    # Normalize to colon-separated format (AA:BB:CC:DD:EE:FF)
    normalized = ":".join(clean_mac[i : i + 2] for i in range(0, 12, 2))
    return normalized.upper()


def require_mac_address(v: str) -> str:
    """Validate and require a non-empty MAC address.

    Args:
        v: Raw MAC address value.

    Returns:
        Normalized MAC address string (AA:BB:CC:DD:EE:FF).

    Raises:
        ValueError: When the value is empty or not a valid MAC address.
    """
    return _require_field(v, validate_mac_address, "MAC address")


# ------------------------------------------------------------------
# Credential Pair Validators
# ------------------------------------------------------------------


def check_credentials_pair(
    username: str | None,
    password: str | None,
    username_field: str = "username",
    password_field: str = "password",
) -> None:
    """Enforce mutual-presence of credential pairs.

    Both username and password must either be absent together or present together.

    Args:
        username: Username value (may be ``None``).
        password: Password value (may be ``None``).
        username_field: Field name for username (for error messages).
        password_field: Field name for password (for error messages).

    Raises:
        ValueError: When exactly one of the two is provided.
    """
    has_user = bool(username)
    has_pass = bool(password)
    if has_user and not has_pass:
        raise ValueError(f"{password_field} must be set when {username_field} is specified")
    if has_pass and not has_user:
        raise ValueError(f"{username_field} must be set when {password_field} is specified")


__all__ = [
    "validate_ip_address",
    "validate_cidr",
    "validate_ip_or_cidr_as_cidr",
    "validate_hostname",
    "validate_mac_address",
    "require_ip_address",
    "require_ip_or_cidr_as_cidr",
    "require_hostname",
    "require_mac_address",
    "validate_cidr_optional",
    "check_credentials_pair",
]
