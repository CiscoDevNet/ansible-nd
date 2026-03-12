# -*- coding: utf-8 -*-
# pylint: disable=wrong-import-position
# pylint: disable=missing-module-docstring
# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

Enum definitions for Nexus Dashboard Ansible modules.

## Enums

- HttpVerbEnum: Enum for HTTP verb values used in endpoints.
- OperationType: Enum for operation types used by Results to determine if changes have occurred.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from enum import Enum

class FabricTypeEnum(str, Enum):
    """
    # Summary

    Enumeration of supported fabric types for discriminated union.

    ## Values

    - `VXLAN_IBGP` - VXLAN fabric with iBGP overlay
    """

    VXLAN_IBGP = "vxlanIbgp"


class AlertSuspendEnum(str, Enum):
    """
    # Summary

    Enumeration for alert suspension states.

    ## Values

    - `ENABLED` - Alerts are enabled
    - `DISABLED` - Alerts are disabled
    """

    ENABLED = "enabled"
    DISABLED = "disabled"


class LicenseTierEnum(str, Enum):
    """
    # Summary

    Enumeration for license tier options.

    ## Values

    - `ESSENTIALS` - Essentials license tier
    - `PREMIER` - Premier license tier
    """

    ESSENTIALS = "essentials"
    PREMIER = "premier"


class ReplicationModeEnum(str, Enum):
    """
    # Summary

    Enumeration for replication modes.

    ## Values

    - `MULTICAST` - Multicast replication
    - `INGRESS` - Ingress replication
    """

    MULTICAST = "multicast"
    INGRESS = "ingress"


class OverlayModeEnum(str, Enum):
    """
    # Summary

    Enumeration for overlay modes.

    ## Values

    - `CLI` - CLI based configuration
    - `CONFIG_PROFILE` - Configuration profile based
    """

    CLI = "cli"
    CONFIG_PROFILE = "config-profile"


class LinkStateRoutingProtocolEnum(str, Enum):
    """
    # Summary

    Enumeration for underlay routing protocols.

    ## Values

    - `OSPF` - Open Shortest Path First
    - `ISIS` - Intermediate System to Intermediate System
    """

    OSPF = "ospf"
    ISIS = "isis"
