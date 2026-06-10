# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Common validators for switch-related fields."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from ipaddress import ip_address, ip_network
from typing import Optional


class SwitchValidators:
    """
    Common validators for switch-related fields.

    The ``validate_*`` static methods are safe to call from Pydantic
    ``@field_validator`` bodies.  They return ``None`` when the value is
    absent and raise ``ValueError`` on bad input.

    The ``require_*`` helpers are convenience wrappers that additionally
    raise ``ValueError`` when the result is ``None`` (i.e. the field was
    empty after stripping).  Use them in place of the repetitive
    ``result = …; if result is None: raise …`` pattern.

    ``check_discovery_credentials_pair`` is a shared ``@model_validator``
    helper that enforces the mutual-presence rule for discovery credentials.
    """

    # ------------------------------------------------------------------
    # Low-level nullable validators (return None when absent)
    # ------------------------------------------------------------------

    @staticmethod
    def validate_ip_address(v: Optional[str]) -> Optional[str]:
        """Validate IPv4 or IPv6 address."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        try:
            ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

    @staticmethod
    def validate_cidr(v: Optional[str]) -> Optional[str]:
        """Validate CIDR notation (IP/mask)."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if "/" not in v:
            raise ValueError(f"CIDR notation required (IP/mask format): {v}")
        try:
            ip_network(v, strict=False)
            return v
        except ValueError:
            raise ValueError(f"Invalid CIDR format: {v}")

    @staticmethod
    def validate_serial_number(v: Optional[str]) -> Optional[str]:
        """Validate switch serial number format."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        # Serial numbers are typically alphanumeric with optional hyphens
        if not re.match(r"^[A-Za-z0-9_-]+$", v):
            raise ValueError(f"Serial number must be alphanumeric with optional hyphens/underscores: {v}")
        return v

    @staticmethod
    def validate_hostname(v: Optional[str]) -> Optional[str]:
        """Validate hostname format."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        # RFC 1123 hostname validation
        if len(v) > 255:
            raise ValueError("Hostname cannot exceed 255 characters")
        # Allow alphanumeric, dots, hyphens, underscores
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$", v):
            raise ValueError(f"Invalid hostname format. Must start with alphanumeric and " f"contain only alphanumeric, dots, hyphens, underscores: {v}")
        if v.startswith(".") or v.endswith(".") or ".." in v:
            raise ValueError(f"Invalid hostname format (dots): {v}")
        return v

    @staticmethod
    def validate_mac_address(v: Optional[str]) -> Optional[str]:
        """Validate MAC address format."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        # Accept colon or hyphen separated MAC addresses
        mac_pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        if not re.match(mac_pattern, v):
            raise ValueError(f"Invalid MAC address format: {v}")
        return v

    @staticmethod
    def validate_vpc_domain(v: Optional[int]) -> Optional[int]:
        """Validate VPC domain ID (1-1000)."""
        if v is None:
            return None
        if not 1 <= v <= 1000:
            raise ValueError(f"VPC domain must be between 1 and 1000: {v}")
        return v

    # ------------------------------------------------------------------
    # Required-field helpers (raise ValueError when value is absent)
    # ------------------------------------------------------------------

    @staticmethod
    def require_serial_number(v: str, field_name: str = "serial_number") -> str:
        """Validate and require a non-empty serial number.

        Delegates to ``validate_serial_number`` and raises ``ValueError``
        when the result is ``None`` (empty after stripping).

        Args:
            v: Raw serial number value from Pydantic.
            field_name: Field name used in the error message.

        Returns:
            Validated serial number string.

        Raises:
            ValueError: When the value is empty or contains invalid characters.
        """
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError(f"{field_name} cannot be empty")
        return result

    @staticmethod
    def require_hostname(v: str) -> str:
        """Validate and require a non-empty hostname.

        Args:
            v: Raw hostname value from Pydantic.

        Returns:
            Validated hostname string.

        Raises:
            ValueError: When the value is empty or fails RFC 1123 checks.
        """
        result = SwitchValidators.validate_hostname(v)
        if result is None:
            raise ValueError("hostname cannot be empty")
        return result

    @staticmethod
    def require_ip_address(v: str) -> str:
        """Validate and require a non-empty IP address.

        Args:
            v: Raw IP address value from Pydantic.

        Returns:
            Validated IP address string.

        Raises:
            ValueError: When the value is empty or not a valid IPv4/v6 address.
        """
        result = SwitchValidators.validate_ip_address(v)
        if result is None:
            raise ValueError(f"Invalid IP address: {v}")
        return result

    @staticmethod
    def validate_cidr_optional(v: Optional[str]) -> Optional[str]:
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
        result = SwitchValidators.validate_cidr(v)
        if result is None:
            raise ValueError(f"Invalid CIDR notation: {v}")
        return result

    @staticmethod
    def check_discovery_credentials_pair(username: Optional[str], password: Optional[str]) -> None:
        """Enforce mutual-presence of discovery credentials.

        Both ``discovery_username`` and ``discovery_password`` must either be
        absent together or present together.  Call from a ``@model_validator``
        body to avoid duplicating the same four-line check across every model.

        Args:
            username: discovery_username value (may be ``None``).
            password: discovery_password value (may be ``None``).

        Raises:
            ValueError: When exactly one of the two is provided.
        """
        has_user = bool(username)
        has_pass = bool(password)
        if has_user and not has_pass:
            raise ValueError("discovery_password must be set when discovery_username is specified")
        if has_pass and not has_user:
            raise ValueError("discovery_username must be set when discovery_password is specified")


__all__ = [
    "SwitchValidators",
]
