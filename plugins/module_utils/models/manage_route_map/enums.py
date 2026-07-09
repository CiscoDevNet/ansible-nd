# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Enumerations for Route Map management.
"""

from enum import Enum


class ActionEnum(str, Enum):
    """Action values for a route map entry."""

    PERMIT = "permit"
    DENY = "deny"


class RuleTypeEnum(str, Enum):
    """Rule type discriminator values for route map rule entries."""

    MATCH_IPV4_ACL = "matchIpv4Acl"
    MATCH_IPV6_ACL = "matchIpv6Acl"
    MATCH_IPV4_PREFIX_LIST = "matchIpv4PrefixList"
    MATCH_IPV6_PREFIX_LIST = "matchIpv6PrefixList"
    MATCH_COMMUNITY = "matchCommunity"
    MATCH_EXTENDED_COMMUNITY = "matchExtendedCommunity"
    MATCH_TAG = "matchTag"
    SET_COMMUNITY = "setCommunity"
    SET_EXTENDED_COMMUNITY_LIST = "setExtendedCommunityList"
    SET_LOCAL_PREFERENCE = "setLocalPreference"
    SET_IPV4_NEXT_HOP = "setIpv4NextHop"
    SET_IPV6_NEXT_HOP = "setIpv6NextHop"
