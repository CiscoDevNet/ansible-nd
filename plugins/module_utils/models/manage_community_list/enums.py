# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Enum definitions for the nd_manage_community_list module.
"""

from __future__ import annotations

__metaclass__ = type

from enum import Enum


class CommunityListTypeEnum(str, Enum):
    """
    Enumeration of community list types.

    - STANDARD: Standard community list - matches well-known communities and/or
      ASN:NN community numbers.
    - EXPANDED: Expanded community list - matches communities using a regular
      expression on the community string.
    """

    STANDARD = "standard"
    EXPANDED = "expanded"


class CommunityListActionEnum(str, Enum):
    """
    Enumeration of permit/deny actions for community list entries.

    - PERMIT: Allow routes matching the entry.
    - DENY: Reject routes matching the entry.
    """

    PERMIT = "permit"
    DENY = "deny"
