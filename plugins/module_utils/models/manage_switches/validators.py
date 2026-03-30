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
    """

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
            raise ValueError(
                f"Serial number must be alphanumeric with optional hyphens/underscores: {v}"
            )
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
            raise ValueError(
                f"Invalid hostname format. Must start with alphanumeric and "
                f"contain only alphanumeric, dots, hyphens, underscores: {v}"
            )
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


__all__ = [
    "SwitchValidators",
]
