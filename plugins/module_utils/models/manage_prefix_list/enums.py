# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
Enumerations for Prefix List management.
"""

from __future__ import annotations

from enum import Enum


class PrefixListActionEnum(str, Enum):
    """Permit/deny action for a prefix list entry."""

    PERMIT = "permit"
    DENY = "deny"


class IpVersionEnum(str, Enum):
    """IP version discriminator for a prefix list."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
