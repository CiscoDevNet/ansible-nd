# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
# pylint: disable=missing-module-docstring
# Copyright: (c) 2026, Matt Tarkington (@mtarking)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

Enum definitions for VXLAN Fabric Group (MSD) modules.

## Enums

- FabricGroupTypeEnum: Fabric group type discriminator.
- BgpAuthenticationKeyTypeEnum: BGP authentication key encryption types.
- MultisiteOverlayInterConnectTypeEnum: Multi-Site Overlay Interconnect type options.
- CloudSecAlgorithmEnum: CloudSec encryption algorithm options.
- CloudSecEnforcementEnum: CloudSec enforcement type options.
- SecurityGroupTagEnum: Security Group Tag enforcement options.
"""

from __future__ import annotations

__metaclass__ = type

from enum import Enum


class FabricGroupTypeEnum(str, Enum):
    """
    # Summary

    Enumeration of supported fabric group types for discriminated union.

    ## Values

    - `VXLAN` - VXLAN fabric group (MSD)
    """

    VXLAN = "vxlan"


class BgpAuthenticationKeyTypeEnum(str, Enum):
    """
    # Summary

    Enumeration for BGP authentication key encryption types.
    """

    THREE_DES = "3des"
    TYPE6 = "type6"
    TYPE7 = "type7"


class MultisiteOverlayInterConnectTypeEnum(str, Enum):
    """
    # Summary

    Enumeration for Multi-Site Overlay Interconnect type options.
    """

    MANUAL = "manual"
    ROUTE_SERVER = "routeServer"
    DIRECT_PEERING = "directPeering"


class CloudSecAlgorithmEnum(str, Enum):
    """
    # Summary

    Enumeration for CloudSec encryption algorithm options.
    """

    AES_128_CMAC = "AES_128_CMAC"
    AES_256_CMAC = "AES_256_CMAC"


class CloudSecEnforcementEnum(str, Enum):
    """
    # Summary

    Enumeration for CloudSec enforcement type options.
    """

    STRICT = "strict"
    LOOSE = "loose"


class SecurityGroupTagEnum(str, Enum):
    """
    # Summary

    Enumeration for Security Group Tag enforcement options (fabric group level).
    """

    OFF = "off"
    LOOSE = "loose"
    STRICT = "strict"
