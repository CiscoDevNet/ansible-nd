# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Enum definitions for the nd_manage_extended_community_list module.
"""

from __future__ import annotations

from enum import Enum


class ExtendedCommunityListTypeEnum(str, Enum):
    """
    Enumeration of extended community list types.

    - STANDARD: Standard extended community list - matches extended communities
      using explicit route targets, router MACs, site-of-origin, or generic
      extended community values.
    - EXPANDED: Expanded extended community list - matches extended communities
      using a regular expression.
    """

    STANDARD = "standard"
    EXPANDED = "expanded"


class ExtendedCommunityListActionEnum(str, Enum):
    """
    Enumeration of permit/deny actions for extended community list entries.

    - PERMIT: Allow routes matching the entry.
    - DENY: Reject routes matching the entry.
    """

    PERMIT = "permit"
    DENY = "deny"
