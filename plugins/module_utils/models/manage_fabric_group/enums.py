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
- MultisiteOverlayInterConnectTypeEnum: Multi-Site Overlay Interconnect type options.
- CloudSecAlgorithmEnum: CloudSec encryption algorithm options.
- CloudSecEnforcementEnum: CloudSec enforcement type options.
- SecurityGroupTagEnum: Security Group Tag enforcement options.
- VxlanAciOverlayInterConnectTypeEnum: Overlay Interconnect type options for VXLAN-to-ACI fabric groups.
- VxlanAciSecurityGroupTagEnum: Security Group Tag enforcement options for VXLAN-to-ACI fabric groups.
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
    - `VXLAN_ACI` - VXLAN-to-ACI fabric group (contains both ACI and VXLAN EVPN fabrics)
    """

    VXLAN = "vxlan"
    VXLAN_ACI = "vxlanAci"


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


class VxlanAciOverlayInterConnectTypeEnum(str, Enum):
    """
    # Summary

    Multi-Site Overlay Interconnect type options for VXLAN-to-ACI fabric groups.

    Unlike the standard VXLAN fabric group, the VXLAN-to-ACI type does not
    support the ``routeServer`` interconnect option.
    """

    MANUAL = "manual"
    DIRECT_PEERING = "directPeering"


class VxlanAciSecurityGroupTagEnum(str, Enum):
    """
    # Summary

    Security Group Tag enforcement options for VXLAN-to-ACI fabric groups.

    The VXLAN-to-ACI type only supports ``loose`` and ``strict`` enforcement.
    """

    LOOSE = "loose"
    STRICT = "strict"
