# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ResourceValidators - Common validators for resource-related fields.

Standalone utility class (no instance required).
"""

from ipaddress import ip_address, ip_network
from typing import Optional


class ResourceValidators:
    """
    Common validators for resource-related fields.
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
    def validate_pool_range(v: Optional[str]) -> Optional[str]:
        """Validate pool range format (e.g., '2300-2600' or '10.1.1.0/24')."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        # Check if it's a CIDR notation
        if "/" in v:
            return ResourceValidators.validate_cidr(v)
        # Check if it's a range (e.g., '2300-2600')
        if "-" in v:
            parts = v.split("-")
            if len(parts) == 2:
                try:
                    start = int(parts[0].strip())
                    end = int(parts[1].strip())
                    if start >= end:
                        raise ValueError(f"Invalid range: start ({start}) must be less than end ({end})")
                    return v
                except ValueError as e:
                    raise ValueError(f"Invalid range format: {v}. Error: {str(e)}")
        return v
