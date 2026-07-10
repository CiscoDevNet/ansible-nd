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
    Maps string fabric type values ("vxlanIbgp", "vxlanEbgp", etc.) to their
    corresponding FabricTypeEnum.

Usage
-----
To check whether *pool_name* is supported for *fabric_type* (enum or string)::

    # Option 1: Using enum directly
    fabric_type = FabricTypeEnum.VXLAN_EBGP
    exact   = pool_name in FABRIC_SUPPORTED_POOLS.get(fabric_type, frozenset())
    dynamic = any(p.match(pool_name) for p in FABRIC_DYNAMIC_POOL_PATTERNS.get(fabric_type, ()))
    is_supported = exact or dynamic

    # Option 2: Using string value (auto-converts to enum)
    fabric_type_str = "vxlanEbgp"
    ft_enum = FABRIC_TYPE_STRING_MAP.get(fabric_type_str)
    if ft_enum:
        exact   = pool_name in FABRIC_SUPPORTED_POOLS.get(ft_enum, frozenset())
        dynamic = any(p.match(pool_name) for p in FABRIC_DYNAMIC_POOL_PATTERNS.get(ft_enum, ()))
        is_supported = exact or dynamic

    # Option 3: Using helper functions (most convenient)
    is_supported = is_pool_supported("vxlanEbgp", pool_name)
"""

from __future__ import annotations

__metaclass__ = type

import re
import logging

from .enums import FabricTypeEnum

LOGGER = logging.getLogger(__name__)

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
            "VPC_PEER_LINK_VLAN",
            "LOOPBACK_ID",
            "TOP_DOWN_L3_DOT1Q",
            "L2_VNI",
            "VPC_ID",
            "L3_VNI",
            "VPC_DOMAIN_ID",
            "TOP_DOWN_NETWORK_VLAN",
            "TOP_DOWN_VRF_VLAN",
            "OBJECT_TRACKING_NUMBER_POOL",
            "ROUTE_MAP_SEQUENCE_NUMBER_POOL",
            "SLA_ID",
            "PORT_CHANNEL_ID",
            "FEX_ID",
            "SERVICE_NETWORK_VLAN",
            "SUBNET",
            "LOOPBACK0_IP_POOL",
            "LOOPBACK1_IP_POOL",
            "ANYCAST_RP_IP_POOL",
            "MPLS_LOOPBACK_IP_POOL",
            "DCI subnet pool",
            "IPv6 DCI subnet pool",
            "BGP_ASN_ID",
            "MCAST_IP_POOL",
        }
    ),
    FabricTypeEnum.VXLAN_EBGP: frozenset(
        {
            "VPC_PEER_LINK_VLAN",
            "L3_VNI",
            "VPC_ID",
            "L2_VNI",
            "TOP_DOWN_VRF_VLAN",
            "ROUTE_MAP_SEQUENCE_NUMBER_POOL",
            "VPC_DOMAIN_ID",
            "FEX_ID",
            "TOP_DOWN_NETWORK_VLAN",
            "PORT_CHANNEL_ID",
            "LOOPBACK_ID",
            "TOP_DOWN_L3_DOT1Q",
            "LOOPBACK0_IP_POOL",
            "LOOPBACK1_IP_POOL",
            "ANYCAST_RP_IP_POOL",
            "DCI subnet pool",
            "IPv6 DCI subnet pool",
            "DEVICE_BGP_ASN",
            "MCAST_IP_POOL",
            "ROUTER_ID_POOL",
            "SUBNET",
        }
    ),
    FabricTypeEnum.EXTERNAL_CONNECTIVITY: frozenset(
        {
            "TOP_DOWN_L3_DOT1Q",
            "VPC_ID",
            "ROUTE_MAP_SEQUENCE_NUMBER_POOL",
            "VPC_DOMAIN_ID",
            "TUNNEL_ID_IOS_XE",
            "INSTANCE_ID",
            "PORT_CHANNEL_ID_IOS_XE",
            "TOP_DOWN_NETWORK_VLAN",
            "LOOPBACK_ID",
            "L2_VNI",
            "L3_VNI",
            "FEX_ID",
            "PORT_CHANNEL_ID",
            "LOOPBACK0_IP_POOL",
            "LOOPBACK_IPV6_POOL",
            "DCI subnet pool",
            "IPv6 DCI subnet pool",
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
_IPV4_CIDR_RE: re.Pattern[str] = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$")
_IPV6_CIDR_RE: re.Pattern[str] = re.compile(r"^([0-9a-fA-F]*:)+[0-9a-fA-F]*\/\d{1,3}$")

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
# Supports string representations used by NDFC fabric management responses.
# =============================================================================
FABRIC_TYPE_STRING_MAP: dict[str, FabricTypeEnum] = {
    "vxlanIbgp": FabricTypeEnum.VXLAN_IBGP,
    "vxlanEbgp": FabricTypeEnum.VXLAN_EBGP,
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
            "externalConnectivity").

    Returns:
        frozenset of pool names, or empty frozenset if fabric_type not recognized.
    """
    LOGGER.debug("get_supported_pools: input fabric_type=%s", fabric_type)
    if isinstance(fabric_type, str):
        fabric_type = FABRIC_TYPE_STRING_MAP.get(fabric_type)
        if fabric_type is None:
            LOGGER.debug("get_supported_pools: unknown fabric_type string, returning empty set")
            return frozenset()

    pools = FABRIC_SUPPORTED_POOLS.get(fabric_type, frozenset())
    LOGGER.debug("get_supported_pools: resolved fabric_type=%s, pool_count=%s", fabric_type, len(pools))
    return pools


def get_dynamic_patterns(
    fabric_type: FabricTypeEnum | str,
) -> tuple[re.Pattern[str], ...]:
    """
    Get the tuple of regex patterns for dynamic pool names in a fabric type.

    Args:
        fabric_type: FabricTypeEnum or string value ("vxlanIbgp", "vxlanEbgp",
            "externalConnectivity").

    Returns:
        tuple of compiled regex patterns, or empty tuple if fabric_type not
        recognized or has no dynamic patterns.
    """
    LOGGER.debug("get_dynamic_patterns: input fabric_type=%s", fabric_type)
    if isinstance(fabric_type, str):
        fabric_type = FABRIC_TYPE_STRING_MAP.get(fabric_type)
        if fabric_type is None:
            LOGGER.debug("get_dynamic_patterns: unknown fabric_type string, returning empty tuple")
            return ()

    patterns = FABRIC_DYNAMIC_POOL_PATTERNS.get(fabric_type, ())
    LOGGER.debug("get_dynamic_patterns: resolved fabric_type=%s, pattern_count=%s", fabric_type, len(patterns))
    return patterns


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
            "externalConnectivity").
        pool_name: The pool name to check.

    Returns:
        True if pool_name is supported (exact or dynamic match), False otherwise.
    """
    LOGGER.debug("is_pool_supported: checking pool_name=%s for fabric_type=%s", pool_name, fabric_type)
    exact = pool_name in get_supported_pools(fabric_type)
    if exact:
        LOGGER.debug("is_pool_supported: exact match found for pool_name=%s", pool_name)
        return True

    patterns = get_dynamic_patterns(fabric_type)
    dynamic = any(p.match(pool_name) for p in patterns)
    LOGGER.debug(
        "is_pool_supported: dynamic_match=%s for pool_name=%s using pattern_count=%s",
        dynamic,
        pool_name,
        len(patterns),
    )
    return dynamic
