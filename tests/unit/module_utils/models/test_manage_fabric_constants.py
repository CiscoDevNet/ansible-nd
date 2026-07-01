# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric constants module.

Verifies that fabric type -> supported pool name mappings work correctly,
including exact-match pools and dynamic regex pattern matching for IP/IPv6
CIDR pool names. Tests both enum and string-based lookups.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import unittest

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.constants import (
    FABRIC_DYNAMIC_POOL_PATTERNS,
    FABRIC_SUPPORTED_POOLS,
    FABRIC_TYPE_STRING_MAP,
    get_dynamic_patterns,
    get_supported_pools,
    is_pool_supported,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
)


class TestFabricTypeStringMap(unittest.TestCase):
    """Tests for FABRIC_TYPE_STRING_MAP constant."""

    def test_fabric_type_string_map_vxlan_ibgp(self):
        """Test FABRIC_TYPE_STRING_MAP maps 'vxlanIbgp' to VXLAN_IBGP enum."""
        assert FABRIC_TYPE_STRING_MAP["vxlanIbgp"] == FabricTypeEnum.VXLAN_IBGP

    def test_fabric_type_string_map_vxlan_ebgp_old(self):
        """Test FABRIC_TYPE_STRING_MAP maps 'vxlanEbgp' (old) to VXLAN_EBGP enum."""
        assert FABRIC_TYPE_STRING_MAP["vxlanEbgp"] == FabricTypeEnum.VXLAN_EBGP

    def test_fabric_type_string_map_external(self):
        """Test FABRIC_TYPE_STRING_MAP maps 'externalConnectivity' to EXTERNAL_CONNECTIVITY enum."""
        assert FABRIC_TYPE_STRING_MAP["externalConnectivity"] == FabricTypeEnum.EXTERNAL_CONNECTIVITY


class TestFabricSupportedPools(unittest.TestCase):
    """Tests for FABRIC_SUPPORTED_POOLS constant."""

    def test_vxlan_ibgp_pool_count(self):
        """Test VXLAN_IBGP has 24 supported pools."""
        assert len(FABRIC_SUPPORTED_POOLS[FabricTypeEnum.VXLAN_IBGP]) == 24

    def test_vxlan_ebgp_pool_count(self):
        """Test VXLAN_EBGP has 21 supported pools."""
        assert len(FABRIC_SUPPORTED_POOLS[FabricTypeEnum.VXLAN_EBGP]) == 21

    def test_external_connectivity_pool_count(self):
        """Test EXTERNAL_CONNECTIVITY has 17 supported pools."""
        assert len(FABRIC_SUPPORTED_POOLS[FabricTypeEnum.EXTERNAL_CONNECTIVITY]) == 17

    def test_vxlan_ibgp_contains_expected_pools(self):
        """Test VXLAN_IBGP contains expected pool names."""
        pools = FABRIC_SUPPORTED_POOLS[FabricTypeEnum.VXLAN_IBGP]
        expected = {
            "LOOPBACK_ID",
            "LOOPBACK0_IP_POOL",
            "L2_VNI",
            "L3_VNI",
            "VPC_ID",
            "VPC_DOMAIN_ID",
            "VPC_PEER_LINK_VLAN",
            "PORT_CHANNEL_ID",
            "FEX_ID",
            "TOP_DOWN_L3_DOT1Q",
            "TOP_DOWN_NETWORK_VLAN",
            "TOP_DOWN_VRF_VLAN",
            "BGP_ASN_ID",
            "MCAST_IP_POOL",
        }
        assert expected.issubset(pools)

    def test_vxlan_ebgp_contains_expected_pools(self):
        """Test VXLAN_EBGP contains expected pool names."""
        pools = FABRIC_SUPPORTED_POOLS[FabricTypeEnum.VXLAN_EBGP]
        expected = {
            "LOOPBACK_ID",
            "LOOPBACK0_IP_POOL",
            "L2_VNI",
            "VPC_ID",
            "VPC_DOMAIN_ID",
            "VPC_PEER_LINK_VLAN",
            "PORT_CHANNEL_ID",
            "FEX_ID",
            "TOP_DOWN_L3_DOT1Q",
            "TOP_DOWN_NETWORK_VLAN",
            "DEVICE_BGP_ASN",
            "ROUTER_ID_POOL",
        }
        assert expected.issubset(pools)

    def test_external_connectivity_contains_expected_pools(self):
        """Test EXTERNAL_CONNECTIVITY contains expected pool names."""
        pools = FABRIC_SUPPORTED_POOLS[FabricTypeEnum.EXTERNAL_CONNECTIVITY]
        expected = {
            "LOOPBACK_ID",
            "LOOPBACK0_IP_POOL",
            "L2_VNI",
            "L3_VNI",
            "VPC_ID",
            "VPC_DOMAIN_ID",
            "PORT_CHANNEL_ID",
            "FEX_ID",
            "TOP_DOWN_L3_DOT1Q",
            "TOP_DOWN_NETWORK_VLAN",
            "TUNNEL_ID_IOS_XE",
            "PORT_CHANNEL_ID_IOS_XE",
            "INSTANCE_ID",
        }
        assert expected.issubset(pools)

    def test_supported_pools_are_frozensets(self):
        """Test all supported pools are immutable frozensets."""
        for fabric_type, pools in FABRIC_SUPPORTED_POOLS.items():
            assert isinstance(pools, frozenset), f"{fabric_type} pools not frozenset"


class TestFabricDynamicPoolPatterns(unittest.TestCase):
    """Tests for FABRIC_DYNAMIC_POOL_PATTERNS constant."""

    def test_vxlan_ibgp_has_no_dynamic_patterns(self):
        """Test VXLAN_IBGP has no dynamic pool patterns."""
        assert FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.VXLAN_IBGP] == ()

    def test_vxlan_ebgp_has_two_patterns(self):
        """Test VXLAN_EBGP has 2 dynamic pool patterns (IPv4 and IPv6)."""
        assert len(FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.VXLAN_EBGP]) == 2

    def test_external_connectivity_has_no_dynamic_patterns(self):
        """Test EXTERNAL_CONNECTIVITY has no dynamic pool patterns."""
        assert FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.EXTERNAL_CONNECTIVITY] == ()

    def test_vxlan_ebgp_ipv4_cidr_pattern_matches(self):
        """Test VXLAN_EBGP IPv4 CIDR pattern matches valid IPv4 CIDR."""
        patterns = FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.VXLAN_EBGP]
        ipv4_pattern = patterns[0]
        assert ipv4_pattern.match("10.4.0.0/30")
        assert ipv4_pattern.match("192.168.1.0/24")
        assert ipv4_pattern.match("0.0.0.0/0")

    def test_vxlan_ebgp_ipv4_cidr_pattern_rejects_invalid(self):
        """Test VXLAN_EBGP IPv4 CIDR pattern rejects non-CIDR strings."""
        patterns = FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.VXLAN_EBGP]
        ipv4_pattern = patterns[0]
        assert not ipv4_pattern.match("LOOPBACK_ID")
        assert not ipv4_pattern.match("DCI subnet pool")
        assert not ipv4_pattern.match("10.4.0.0")
        assert not ipv4_pattern.match("10.4.0.0/")

    def test_vxlan_ebgp_ipv6_cidr_pattern_matches(self):
        """Test VXLAN_EBGP IPv6 CIDR pattern matches valid IPv6 CIDR."""
        patterns = FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.VXLAN_EBGP]
        ipv6_pattern = patterns[1]
        assert ipv6_pattern.match("fe:80:505::5/64")
        assert ipv6_pattern.match("2001:db8::/32")
        assert ipv6_pattern.match("::1/128")

    def test_vxlan_ebgp_ipv6_cidr_pattern_rejects_invalid(self):
        """Test VXLAN_EBGP IPv6 CIDR pattern rejects non-IPv6 CIDR strings."""
        patterns = FABRIC_DYNAMIC_POOL_PATTERNS[FabricTypeEnum.VXLAN_EBGP]
        ipv6_pattern = patterns[1]
        assert not ipv6_pattern.match("LOOPBACK_ID")
        assert not ipv6_pattern.match("DCI subnet pool")
        assert not ipv6_pattern.match("IPv6 DCI subnet pool")


class TestGetSupportedPoolsFunction(unittest.TestCase):
    """Tests for get_supported_pools() helper function."""

    def test_get_supported_pools_with_enum_vxlan_ibgp(self):
        """Test get_supported_pools with FabricTypeEnum.VXLAN_IBGP."""
        pools = get_supported_pools(FabricTypeEnum.VXLAN_IBGP)
        assert len(pools) == 24
        assert "LOOPBACK_ID" in pools

    def test_get_supported_pools_with_enum_vxlan_ebgp(self):
        """Test get_supported_pools with FabricTypeEnum.VXLAN_EBGP."""
        pools = get_supported_pools(FabricTypeEnum.VXLAN_EBGP)
        assert len(pools) == 21
        assert "ROUTER_ID_POOL" in pools

    def test_get_supported_pools_with_enum_external(self):
        """Test get_supported_pools with FabricTypeEnum.EXTERNAL_CONNECTIVITY."""
        pools = get_supported_pools(FabricTypeEnum.EXTERNAL_CONNECTIVITY)
        assert len(pools) == 17
        assert "TUNNEL_ID_IOS_XE" in pools

    def test_get_supported_pools_with_string_vxlan_ibgp(self):
        """Test get_supported_pools with 'vxlanIbgp' string."""
        pools = get_supported_pools("vxlanIbgp")
        assert len(pools) == 24
        assert "LOOPBACK_ID" in pools

    def test_get_supported_pools_with_string_vxlan_ebgp_old(self):
        """Test get_supported_pools with 'vxlanEbgp' (old) string."""
        pools = get_supported_pools("vxlanEbgp")
        assert len(pools) == 21
        assert "ROUTER_ID_POOL" in pools

    def test_get_supported_pools_with_string_external(self):
        """Test get_supported_pools with 'externalConnectivity' string."""
        pools = get_supported_pools("externalConnectivity")
        assert len(pools) == 17
        assert "TUNNEL_ID_IOS_XE" in pools

    def test_get_supported_pools_with_invalid_string(self):
        """Test get_supported_pools with invalid string returns empty frozenset."""
        pools = get_supported_pools("invalid_fabric_type")
        assert pools == frozenset()

    def test_get_supported_pools_returns_frozenset(self):
        """Test get_supported_pools always returns frozenset."""
        pools = get_supported_pools(FabricTypeEnum.VXLAN_IBGP)
        assert isinstance(pools, frozenset)


class TestGetDynamicPatternsFunction(unittest.TestCase):
    """Tests for get_dynamic_patterns() helper function."""

    def test_get_dynamic_patterns_with_enum_vxlan_ibgp(self):
        """Test get_dynamic_patterns with FabricTypeEnum.VXLAN_IBGP."""
        patterns = get_dynamic_patterns(FabricTypeEnum.VXLAN_IBGP)
        assert patterns == ()

    def test_get_dynamic_patterns_with_enum_vxlan_ebgp(self):
        """Test get_dynamic_patterns with FabricTypeEnum.VXLAN_EBGP."""
        patterns = get_dynamic_patterns(FabricTypeEnum.VXLAN_EBGP)
        assert len(patterns) == 2

    def test_get_dynamic_patterns_with_enum_external(self):
        """Test get_dynamic_patterns with FabricTypeEnum.EXTERNAL_CONNECTIVITY."""
        patterns = get_dynamic_patterns(FabricTypeEnum.EXTERNAL_CONNECTIVITY)
        assert patterns == ()

    def test_get_dynamic_patterns_with_string_vxlan_ebgp_old(self):
        """Test get_dynamic_patterns with 'vxlanEbgp' string."""
        patterns = get_dynamic_patterns("vxlanEbgp")
        assert len(patterns) == 2

    def test_get_dynamic_patterns_with_invalid_string(self):
        """Test get_dynamic_patterns with invalid string returns empty tuple."""
        patterns = get_dynamic_patterns("invalid_fabric_type")
        assert patterns == ()

    def test_get_dynamic_patterns_returns_tuple(self):
        """Test get_dynamic_patterns always returns tuple."""
        patterns = get_dynamic_patterns(FabricTypeEnum.VXLAN_EBGP)
        assert isinstance(patterns, tuple)


class TestIsPoolSupportedFunction(unittest.TestCase):
    """Tests for is_pool_supported() helper function."""

    # ========================================================================
    # Exact-match tests (standard named pools)
    # ========================================================================

    def test_is_pool_supported_exact_vxlan_ibgp_enum(self):
        """Test is_pool_supported with exact-match VXLAN_IBGP pool (enum)."""
        assert is_pool_supported(FabricTypeEnum.VXLAN_IBGP, "LOOPBACK_ID")
        assert is_pool_supported(FabricTypeEnum.VXLAN_IBGP, "L2_VNI")
        assert is_pool_supported(FabricTypeEnum.VXLAN_IBGP, "MCAST_IP_POOL")

    def test_is_pool_supported_exact_vxlan_ibgp_string(self):
        """Test is_pool_supported with exact-match VXLAN_IBGP pool (string)."""
        assert is_pool_supported("vxlanIbgp", "LOOPBACK_ID")
        assert is_pool_supported("vxlanIbgp", "L2_VNI")

    def test_is_pool_supported_exact_vxlan_ebgp_enum(self):
        """Test is_pool_supported with exact-match VXLAN_EBGP pool (enum)."""
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "LOOPBACK_ID")
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "ROUTER_ID_POOL")

    def test_is_pool_supported_exact_vxlan_ebgp_old_string(self):
        """Test is_pool_supported with exact-match VXLAN_EBGP pool ('vxlanEbgp')."""
        assert is_pool_supported("vxlanEbgp", "LOOPBACK_ID")
        assert is_pool_supported("vxlanEbgp", "ROUTER_ID_POOL")

    def test_is_pool_supported_exact_external_enum(self):
        """Test is_pool_supported with exact-match EXTERNAL_CONNECTIVITY pool (enum)."""
        assert is_pool_supported(FabricTypeEnum.EXTERNAL_CONNECTIVITY, "TUNNEL_ID_IOS_XE")
        assert is_pool_supported(FabricTypeEnum.EXTERNAL_CONNECTIVITY, "INSTANCE_ID")

    def test_is_pool_supported_exact_external_string(self):
        """Test is_pool_supported with exact-match EXTERNAL_CONNECTIVITY pool (string)."""
        assert is_pool_supported("externalConnectivity", "TUNNEL_ID_IOS_XE")
        assert is_pool_supported("externalConnectivity", "INSTANCE_ID")

    def test_is_pool_supported_subnet_not_for_external_connectivity_enum(self):
        """Test EXTERNAL_CONNECTIVITY does NOT support SUBNET pool (enum)."""
        assert not is_pool_supported(FabricTypeEnum.EXTERNAL_CONNECTIVITY, "SUBNET")

    def test_is_pool_supported_subnet_not_for_external_connectivity_string(self):
        """Test EXTERNAL_CONNECTIVITY does NOT support SUBNET pool (string)."""
        assert not is_pool_supported("externalConnectivity", "SUBNET")

    def test_is_pool_supported_subnet_supported_for_ibgp(self):
        """Test VXLAN_IBGP DOES support SUBNET pool."""
        assert is_pool_supported(FabricTypeEnum.VXLAN_IBGP, "SUBNET")
        assert is_pool_supported("vxlanIbgp", "SUBNET")

    def test_is_pool_supported_subnet_supported_for_ebgp(self):
        """Test VXLAN_EBGP DOES support SUBNET pool."""
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "SUBNET")
        assert is_pool_supported("vxlanEbgp", "SUBNET")

    def test_is_pool_supported_exact_not_supported(self):
        """Test is_pool_supported returns False for unsupported exact-match pool."""
        assert not is_pool_supported(FabricTypeEnum.VXLAN_IBGP, "INVALID_POOL")
        assert not is_pool_supported("vxlanEbgp", "INVALID_POOL")

    # ========================================================================
    # Dynamic pattern tests (IP/IPv6 CIDR pools)
    # ========================================================================

    def test_is_pool_supported_dynamic_ipv4_vxlan_ebgp_enum(self):
        """Test is_pool_supported with dynamic IPv4 CIDR for VXLAN_EBGP (enum)."""
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "10.4.0.0/30")
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "192.168.1.0/24")

    def test_is_pool_supported_dynamic_ipv4_vxlan_ebgp_old_string(self):
        """Test is_pool_supported with dynamic IPv4 CIDR for 'vxlanEbgp'."""
        assert is_pool_supported("vxlanEbgp", "10.4.0.0/30")
        assert is_pool_supported("vxlanEbgp", "192.168.1.0/24")

    def test_is_pool_supported_dynamic_ipv6_vxlan_ebgp_enum(self):
        """Test is_pool_supported with dynamic IPv6 CIDR for VXLAN_EBGP (enum)."""
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "fe:80:505::5/64")
        assert is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "2001:db8::/32")

    def test_is_pool_supported_dynamic_ipv6_vxlan_ebgp_old_string(self):
        """Test is_pool_supported with dynamic IPv6 CIDR for 'vxlanEbgp'."""
        assert is_pool_supported("vxlanEbgp", "fe:80:505::5/64")
        assert is_pool_supported("vxlanEbgp", "2001:db8::/32")

    def test_is_pool_supported_dynamic_not_for_other_types(self):
        """Test is_pool_supported rejects dynamic pools for non-EBGP fabric types."""
        assert not is_pool_supported(FabricTypeEnum.VXLAN_IBGP, "10.4.0.0/30")
        assert not is_pool_supported(FabricTypeEnum.EXTERNAL_CONNECTIVITY, "10.4.0.0/30")
        assert not is_pool_supported("vxlanIbgp", "fe:80:505::5/64")
        assert not is_pool_supported("externalConnectivity", "fe:80:505::5/64")

    # ========================================================================
    # Combination tests (exact + dynamic)
    # ========================================================================

    def test_is_pool_supported_combination_vxlan_ebgp(self):
        """Test is_pool_supported with mix of exact and dynamic pools for VXLAN_EBGP."""
        # Exact matches
        assert is_pool_supported("vxlanEbgp", "LOOPBACK_ID")
        assert is_pool_supported("vxlanEbgp", "DCI subnet pool")
        # Dynamic matches
        assert is_pool_supported("vxlanEbgp", "10.4.0.0/30")
        assert is_pool_supported("vxlanEbgp", "fe:80:505::5/64")
        # Unsupported
        assert not is_pool_supported("vxlanEbgp", "INVALID_POOL")
        assert not is_pool_supported("vxlanEbgp", "invalid_ip_range")

    def test_is_pool_supported_case_sensitive(self):
        """Test is_pool_supported is case-sensitive for pool names."""
        assert is_pool_supported("vxlanEbgp", "LOOPBACK_ID")
        assert not is_pool_supported("vxlanEbgp", "loopback_id")
        assert not is_pool_supported("vxlanEbgp", "Loopback_Id")

    def test_is_pool_supported_invalid_fabric_type(self):
        """Test is_pool_supported returns False for invalid fabric type."""
        assert not is_pool_supported("invalid_type", "LOOPBACK_ID")
        assert not is_pool_supported("invalid_type", "10.4.0.0/30")

    def test_is_pool_supported_empty_pool_name(self):
        """Test is_pool_supported with empty pool name."""
        assert not is_pool_supported("vxlanEbgp", "")
        assert not is_pool_supported(FabricTypeEnum.VXLAN_EBGP, "")


class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple functions."""

    def test_all_fabrics_have_supported_pools(self):
        """Test all fabric types have supported pools defined."""
        for fabric_type in FabricTypeEnum:
            pools = get_supported_pools(fabric_type)
            assert len(pools) > 0, f"{fabric_type} has no supported pools"

    def test_no_ip_address_pools_in_exact_matches(self):
        """Test exact-match pools don't contain raw IP/CIDR addresses."""
        # For VXLAN_EBGP, verify IP-address-style names are not in exact pools
        # (they're only matched via regex)
        ebgp_pools = get_supported_pools("vxlanEbgp")
        for pool in ebgp_pools:
            # Should not match IPv4 CIDR pattern
            patterns = get_dynamic_patterns("vxlanEbgp")
            assert not patterns[0].match(pool), f"IPv4 CIDR pool '{pool}' found in exact matches"
            # Should not match IPv6 CIDR pattern
            assert not patterns[1].match(pool), f"IPv6 CIDR pool '{pool}' found in exact matches"
