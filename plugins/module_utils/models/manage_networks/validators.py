# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Common validators for network-related fields."""

from __future__ import annotations
from ipaddress import ip_address, ip_network


class NetworkValidators:
    """
    Common validators for network-related fields.

    The ``validate_*`` helpers return ``None`` for absent/blank nullable
    values and raise ``ValueError`` for invalid user-provided values.
    """

    @staticmethod
    def validate_ip_address(v: str | None) -> str | None:
        """Validate IPv4 or IPv6 address."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        try:
            ip_address(v)
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IP address format: {v}") from exc

    @staticmethod
    def validate_ipv4_address(v: str | None) -> str | None:
        """Validate IPv4 address."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        try:
            addr = ip_address(v)
            if addr.version != 4:
                raise ValueError(f"Expected IPv4 address, got IPv6: {v}")
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 address format: {v}") from exc

    @staticmethod
    def validate_ipv6_address(v: str | None) -> str | None:
        """Validate IPv6 address."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        try:
            addr = ip_address(v)
            if addr.version != 6:
                raise ValueError(f"Expected IPv6 address, got IPv4: {v}")
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 address format: {v}") from exc

    @staticmethod
    def validate_cidrv4(v: str | None) -> str | None:
        """Validate IPv4 CIDR notation."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if "/" not in v:
            raise ValueError(f"CIDR notation required (IPv4/mask format): {v}")
        try:
            net = ip_network(v, strict=False)
            if net.version != 4:
                raise ValueError(f"Expected IPv4 CIDR, got IPv6: {v}")
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 CIDR format: {v}") from exc

    @staticmethod
    def validate_cidrv6(v: str | None) -> str | None:
        """Validate IPv6 CIDR notation."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if "/" not in v:
            raise ValueError(f"CIDR notation required (IPv6/prefix-length format): {v}")
        try:
            net = ip_network(v, strict=False)
            if net.version != 6:
                raise ValueError(f"Expected IPv6 CIDR, got IPv4: {v}")
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IPv6 CIDR format: {v}") from exc

    @staticmethod
    def validate_multicast_ipv4(v: str | None) -> str | None:
        """Validate an IPv4 address in the 224.0.0.0/4 multicast range."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        try:
            addr = ip_address(v)
            if addr.version != 4:
                raise ValueError(f"Expected IPv4 multicast address, got IPv6: {v}")
            if addr not in ip_network("224.0.0.0/4"):
                raise ValueError(f"Address must be in 224.0.0.0/4 multicast range: {v}")
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 multicast address: {v}") from exc

    @staticmethod
    def validate_network_name(v: str | None) -> str | None:
        """Validate network name length and non-blank content."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if len(v) > 128:
            raise ValueError(f"Network name must not exceed 128 characters: {v}")
        return v

    @staticmethod
    def validate_vlan_id(v: int | None) -> int | None:
        """Validate VLAN ID range."""
        if v is None:
            return None
        if not (2 <= v <= 4094):
            raise ValueError(f"VLAN ID must be between 2 and 4094, got: {v}")
        return v

    @staticmethod
    def validate_network_id(v: int | None) -> int | None:
        """Validate network ID range."""
        if v is None:
            return None
        if not (1 <= v <= 16777214):
            raise ValueError(f"Network ID must be between 1 and 16777214, got: {v}")
        return v

    @staticmethod
    def validate_mtu(v: int | None) -> int | None:
        """Validate interface MTU range."""
        if v is None:
            return None
        if not (68 <= v <= 9216):
            raise ValueError(f"MTU must be between 68 and 9216, got: {v}")
        return v

    @staticmethod
    def validate_igmp_version(v: int | None) -> int | None:
        """Validate IGMP version."""
        if v is None:
            return None
        if v not in (1, 2, 3):
            raise ValueError(f"IGMP version must be 1, 2, or 3, got: {v}")
        return v

    @staticmethod
    def validate_interface_range(v: str | None) -> str | None:
        """Validate a non-empty interface or interface range string."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        return v
