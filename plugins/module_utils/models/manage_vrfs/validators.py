# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Common validators for VRF-related fields."""

import re
from ipaddress import ip_address, ip_network


class VrfValidators:
    """
    Common validators for VRF-related fields.

    The ``validate_*`` static methods are safe to call from Pydantic
    ``@field_validator`` bodies.  They return ``None`` when the value is
    absent and raise ``ValueError`` on bad input.

    The ``require_*`` helpers additionally raise ``ValueError`` when the
    result is ``None``.
    """

    # ------------------------------------------------------------------
    # Nullable validators
    # ------------------------------------------------------------------

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
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")

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
    def validate_cidrv4(v: str | None) -> str | None:
        """Validate IPv4 CIDR notation (IP/mask)."""
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if "/" not in v:
            raise ValueError(f"CIDR notation required (IPv4/mask format): {v}")
        try:
            ip_network(v, strict=False)
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 CIDR format: {v}") from exc

    @staticmethod
    def validate_cidrv6(v: str | None) -> str | None:
        """Validate IPv6 CIDR notation (IPv6/prefix-length)."""
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
    def validate_route_target(v: str | None) -> str | None:
        """
        Validate a single route target string.

        Based on: components/schemas/vrfAttachmentInstanceValues
        Pattern: ``^((\\d{1,5}:\\d{1,9})|(\\d{1,10}:\\d{1,9})|
                 ((25[0-5]|2[0-4]\\d|1\\d{2}|\\d{1,2})\\.(...):<ip>:\\d{1,9}))$``
        """
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        pattern = (
            r"^((\d{1,5}:\d{1,9})|(\d{1,10}:\d{1,9})"
            r"|((25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})"
            r"\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})"
            r"\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})"
            r"\.(25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}):\d{1,9}))$"
        )
        if not re.match(pattern, v):
            raise ValueError(f"Invalid route target format: {v}. " "Expected AS:NN, IP:NN, or large-community format.")
        return v

    @staticmethod
    def validate_vrf_name(v: str | None) -> str | None:
        """
        Validate VRF name.

        Based on: components/schemas/vrfName
        maxLength: 94. For multi-tenant: tenantName~vrfName.
        """
        if v is None:
            return None
        v = str(v).strip()
        if not v:
            return None
        if len(v) > 94:
            raise ValueError(f"VRF name must not exceed 94 characters: {v}")
        return v

    @staticmethod
    def validate_vlan_id(v: int | None) -> int | None:
        """
        Validate VLAN ID.

        Based on: components/schemas/vlanId
        minimum: 2, maximum: 4094
        """
        if v is None:
            return None
        if not (2 <= v <= 4094):
            raise ValueError(f"VLAN ID must be between 2 and 4094, got: {v}")
        return v

    @staticmethod
    def validate_loopback_id(v: int | None) -> int | None:
        """
        Validate loopback interface ID.

        Based on: components/schemas/vrfAttachmentInstanceValues (loopbackId)
        minimum: 0, maximum: 1023
        """
        if v is None:
            return None
        if not (0 <= v <= 1023):
            raise ValueError(f"Loopback ID must be between 0 and 1023, got: {v}")
        return v

    @staticmethod
    def validate_mtu(v: int | None) -> int | None:
        """
        Validate interface MTU.

        Based on: components/schemas/interfaceMtuInteger
        minimum: 68, maximum: 9216
        """
        if v is None:
            return None
        if not (68 <= v <= 9216):
            raise ValueError(f"MTU must be between 68 and 9216, got: {v}")
        return v

    @staticmethod
    def validate_dot1q_id(v: int | None) -> int | None:
        """
        Validate 802.1Q VLAN tag ID.

        Based on: components/schemas/vrfExtensionCommon (dot1qId)
        minimum: 2, maximum: 4094
        """
        if v is None:
            return None
        if not (2 <= v <= 4094):
            raise ValueError(f"dot1qId must be between 2 and 4094, got: {v}")
        return v

    @staticmethod
    def validate_vrf_vlan_name(v: str | None) -> str | None:
        """
        Validate VLAN name used in VRF attachment instance values.

        Based on: components/schemas/vrfAttachmentInstanceValues (vrfVlanName)
        pattern: ``^[^\\?,\\\\,\\s]*$``, maxLength: 128
        """
        if v is None:
            return None
        v = str(v).strip()
        if len(v) > 128:
            raise ValueError(f"vrfVlanName must not exceed 128 characters: {v}")
        if re.search(r"[\?,\\\s]", v):
            raise ValueError(f"vrfVlanName must not contain '?', '\\', or whitespace: {v}")
        return v

    @staticmethod
    def validate_overlay_mcast_group(v: str | None) -> str | None:
        """
        Validate that an IPv4 address is in the 224.0.0.0/4 multicast range.

        Used for the ``overlay_mcast_group`` (TRM) field.
        """
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
                raise ValueError(f"overlay_mcast_group must be in the 224.0.0.0/4 " f"multicast range, got: {v}")
            return v
        except ValueError as exc:
            raise ValueError(f"Invalid overlay multicast group address: {v}") from exc

    @staticmethod
    def validate_bgp_passwd_encrypt(v: int | None) -> int | None:
        """
        Validate BGP password key type.

        Accepted values: 3 (3DES) or 7 (Cisco Type-7).
        """
        if v is None:
            return None
        if v not in (3, 7):
            raise ValueError(f"bgp_passwd_encrypt must be 3 (3DES) or 7 (Cisco Type-7), got: {v}")
        return v

    @staticmethod
    def normalize_route_targets(v: str | list[str] | None) -> list[str] | None:
        """
        Normalise a route-target value to a validated list.

        Accepts:
        - ``None``                    → ``None``
        - ``""``                      → ``None``
        - ``"65001:100"``             → ``["65001:100"]``
        - ``"65001:100, 65001:200"``  → ``["65001:100", "65001:200"]``
        - ``["65001:100", "65001:200"]`` → ``["65001:100", "65001:200"]``

        Each entry is validated with ``validate_route_target``.
        """
        if v is None:
            return None
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
            entries = [rt.strip() for rt in v.split(",")]
        else:
            entries = [str(rt).strip() for rt in v]
        result = []
        for rt in entries:
            if not rt:
                continue
            validated = VrfValidators.validate_route_target(rt)
            if validated is not None:
                result.append(validated)
        return result if result else None

    # ------------------------------------------------------------------
    # Require wrappers
    # ------------------------------------------------------------------

    @classmethod
    def require_vrf_name(cls, v: str | None, field: str = "vrf_name") -> str:
        """Validate and require a non-empty VRF name."""
        result = cls.validate_vrf_name(v)
        if result is None:
            raise ValueError(f"{field} cannot be empty")
        return result
