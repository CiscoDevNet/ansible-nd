# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Shared constants for manage_fabric models.

Constants
---------
FABRIC_SUPPORTED_POOLS
    Maps each FabricTypeEnum to the frozenset of standard (exact-match) pool
    names supported by that fabric type.

FABRIC_DYNAMIC_POOL_PATTERNS
    Maps each FabricTypeEnum to a tuple of compiled regex patterns that match
    dynamically-named pools (e.g. user-supplied IPv4/IPv6 CIDR pool names).
    Only FabricTypeEnum.VXLAN_EBGP currently has dynamic pool patterns.

FABRIC_TYPE_STRING_MAP
    Maps string fabric type values ("routed", "vxlanEbgp", etc.) to their
    corresponding FabricTypeEnum. Supports both old ("vxlanEbgp") and new
    ("routed") string representations for VXLAN_EBGP.

Usage
-----
To check whether *pool_name* is supported for *fabric_type* (enum or string)::

    # Option 1: Using enum directly
    fabric_type = FabricTypeEnum.VXLAN_EBGP
    exact   = pool_name in FABRIC_SUPPORTED_POOLS.get(fabric_type, frozenset())
    dynamic = any(p.match(pool_name) for p in FABRIC_DYNAMIC_POOL_PATTERNS.get(fabric_type, ()))
    is_supported = exact or dynamic

    # Option 2: Using string value (auto-converts to enum)
    fabric_type_str = "routed"  # or "vxlanEbgp" - both supported
    ft_enum = FABRIC_TYPE_STRING_MAP.get(fabric_type_str)
    if ft_enum:
        exact   = pool_name in FABRIC_SUPPORTED_POOLS.get(ft_enum, frozenset())
        dynamic = any(p.match(pool_name) for p in FABRIC_DYNAMIC_POOL_PATTERNS.get(ft_enum, ()))
        is_supported = exact or dynamic

    # Option 3: Using helper functions (most convenient)
    is_supported = is_pool_supported("routed", pool_name)
"""

from __future__ import annotations

__metaclass__ = type

import re

from .enums import FabricTypeEnum

__all__ = [
    "FABRIC_SUPPORTED_POOLS",
    "FABRIC_DYNAMIC_POOL_PATTERNS",
    "FABRIC_TYPE_STRING_MAP",
    "is_pool_supported",
    "get_supported_pools",
    "get_dynamic_patterns",
]

# =============================================================================
# FABRIC_SUPPORTED_POOLS
# Maps each FabricTypeEnum to the frozenset of standard named pools supported
# by that fabric type. Pool names that are raw IP/CIDR notation (user-defined
# dynamic pools) are intentionally excluded here; use FABRIC_DYNAMIC_POOL_PATTERNS
# for those.
# Source: iBGPFabricPools.json, eBGPFabricPools.json, ExternalFabricPools.json
# =============================================================================
FABRIC_SUPPORTED_POOLS: dict[FabricTypeEnum, frozenset[str]] = {
    FabricTypeEnum.VXLAN_IBGP: frozenset(
        {
            "ANYCAST_RP_IP_POOL",
            "BGP_ASN_ID",
            "DCI subnet pool",
            "FEX_ID",
            "IPv6 DCI subnet pool",
            "L2_VNI",
            "L3_VNI",
            "LOOPBACK0_IP_POOL",
            "LOOPBACK1_IP_POOL",
            "LOOPBACK_ID",
            "MCAST_IP_POOL",
            "MPLS_LOOPBACK_IP_POOL",
            "OBJECT_TRACKING_NUMBER_POOL",
            "PORT_CHANNEL_ID",
            "ROUTE_MAP_SEQUENCE_NUMBER_POOL",
            "SERVICE_NETWORK_VLAN",
            "SLA_ID",
            "SUBNET",
            "TOP_DOWN_L3_DOT1Q",
            "TOP_DOWN_NETWORK_VLAN",
            "TOP_DOWN_VRF_VLAN",
            "VPC_DOMAIN_ID",
            "VPC_ID",
            "VPC_PEER_LINK_VLAN",
        }
    ),
    FabricTypeEnum.VXLAN_EBGP: frozenset(
        {
            "DCI subnet pool",
            "DEVICE_BGP_ASN",
            "FEX_ID",
            "IPv6 DCI subnet pool",
            "L2_VNI",
            "LOOPBACK0_IP_POOL",
            "LOOPBACK_ID",
            "PORT_CHANNEL_ID",
            "ROUTE_MAP_SEQUENCE_NUMBER_POOL",
            "ROUTER_ID_POOL",
            "SUBNET",
            "TOP_DOWN_L3_DOT1Q",
            "TOP_DOWN_NETWORK_VLAN",
            "VPC_DOMAIN_ID",
            "VPC_ID",
            "VPC_PEER_LINK_VLAN",
            "default_SUBNET_POOL_IPV4",
        }
    ),
    FabricTypeEnum.EXTERNAL_CONNECTIVITY: frozenset(
        {
            "DCI subnet pool",
            "FEX_ID",
            "INSTANCE_ID",
            "IPv6 DCI subnet pool",
            "L2_VNI",
            "L3_VNI",
            "LOOPBACK0_IP_POOL",
            "LOOPBACK_ID",
            "LOOPBACK_IPV6_POOL",
            "PORT_CHANNEL_ID",
            "PORT_CHANNEL_ID_IOS_XE",
            "ROUTE_MAP_SEQUENCE_NUMBER_POOL",
            "TOP_DOWN_L3_DOT1Q",
            "TOP_DOWN_NETWORK_VLAN",
            "TUNNEL_ID_IOS_XE",
            "VPC_DOMAIN_ID",
            "VPC_ID",
        }
    ),
}

# =============================================================================
# FABRIC_DYNAMIC_POOL_PATTERNS
# Maps each FabricTypeEnum to a tuple of compiled regex patterns matching
# dynamically-named (user-supplied) pool names such as bare IPv4/IPv6 CIDR
# blocks. Only FabricTypeEnum.VXLAN_EBGP has dynamic pool patterns; all other
# fabric types return an empty tuple.
#
# Patterns:
#   _IPV4_CIDR_RE  - Matches IPv4 CIDR notation, e.g. "10.4.0.0/30"
#   _IPV6_CIDR_RE  - Matches IPv6 / link-local CIDR notation, e.g. "fe:80:505::5/64"
# =============================================================================
_IPV4_CIDR_RE: re.Pattern[str] = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$"
)

_IPV6_CIDR_RE: re.Pattern[str] = re.compile(
    r"^([0-9a-fA-F]*:)+[0-9a-fA-F]*\/\d{1,3}$"
)

FABRIC_DYNAMIC_POOL_PATTERNS: dict[FabricTypeEnum, tuple[re.Pattern[str], ...]] = {
    FabricTypeEnum.VXLAN_IBGP: (),
    FabricTypeEnum.VXLAN_EBGP: (
        _IPV4_CIDR_RE,
        _IPV6_CIDR_RE,
    ),
    FabricTypeEnum.EXTERNAL_CONNECTIVITY: (),
}

# =============================================================================
# FABRIC_TYPE_STRING_MAP
# Maps string fabric type values to their corresponding FabricTypeEnum.
# Supports both old ("vxlanEbgp") and new ("routed") representations for
# VXLAN_EBGP fabrics, enabling backward compatibility and flexible lookups.
# =============================================================================
FABRIC_TYPE_STRING_MAP: dict[str, FabricTypeEnum] = {
    "vxlanIbgp": FabricTypeEnum.VXLAN_IBGP,
    "vxlanEbgp": FabricTypeEnum.VXLAN_EBGP,
    "routed": FabricTypeEnum.VXLAN_EBGP,  # Alternative name for VXLAN_EBGP
    "externalConnectivity": FabricTypeEnum.EXTERNAL_CONNECTIVITY,
}


# =============================================================================
# Helper Functions
# =============================================================================
def get_supported_pools(
    fabric_type: FabricTypeEnum | str,
) -> frozenset[str]:
    """
    Get the frozenset of standard (exact-match) pool names for a fabric type.

    Args:
        fabric_type: FabricTypeEnum or string value ("vxlanIbgp", "vxlanEbgp",
            "routed", "externalConnectivity").

    Returns:
        frozenset of pool names, or empty frozenset if fabric_type not recognized.
    """
    if isinstance(fabric_type, str):
        fabric_type = FABRIC_TYPE_STRING_MAP.get(fabric_type)
        if fabric_type is None:
            return frozenset()

    return FABRIC_SUPPORTED_POOLS.get(fabric_type, frozenset())


def get_dynamic_patterns(
    fabric_type: FabricTypeEnum | str,
) -> tuple[re.Pattern[str], ...]:
    """
    Get the tuple of regex patterns for dynamic pool names in a fabric type.

    Args:
        fabric_type: FabricTypeEnum or string value ("vxlanIbgp", "vxlanEbgp",
            "routed", "externalConnectivity").

    Returns:
        tuple of compiled regex patterns, or empty tuple if fabric_type not
        recognized or has no dynamic patterns.
    """
    if isinstance(fabric_type, str):
        fabric_type = FABRIC_TYPE_STRING_MAP.get(fabric_type)
        if fabric_type is None:
            return ()

    return FABRIC_DYNAMIC_POOL_PATTERNS.get(fabric_type, ())


def is_pool_supported(
    fabric_type: FabricTypeEnum | str,
    pool_name: str,
) -> bool:
    """
    Check whether a pool name is supported for a given fabric type.

    Supports both exact-match (standard named pools) and regex-match (dynamic
    IP-address pools) for the given fabric_type.

    Args:
        fabric_type: FabricTypeEnum or string value ("vxlanIbgp", "vxlanEbgp",
            "routed", "externalConnectivity").
        pool_name: The pool name to check.

    Returns:
        True if pool_name is supported (exact or dynamic match), False otherwise.
    """
    exact = pool_name in get_supported_pools(fabric_type)
    dynamic = any(p.match(pool_name) for p in get_dynamic_patterns(fabric_type))
    return exact or dynamic

