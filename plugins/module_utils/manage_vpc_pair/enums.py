# -*- coding: utf-8 -*-

# Copyright (c) 2026 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Enums for VPC pair management.

This module provides enumeration types used throughout the VPC pair
management implementation.

Note:
- This file does not define API paths.
- Endpoint path mappings are defined by path-based endpoint files under
  `plugins/module_utils/endpoints/v1/manage/`.
"""

from __future__ import absolute_import, division, print_function

__author__ = "Sivakami Sivaraman"

from enum import Enum

# Import HttpVerbEnum from top-level enums module (RestSend infrastructure)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# Backward compatibility alias - Use HttpVerbEnum directly in new code
VerbEnum = HttpVerbEnum


# ============================================================================
# VPC ACTION ENUMS
# ============================================================================


class VpcActionEnum(str, Enum):
    """
    VPC pair action types for discriminator pattern.

    Used in API payloads to distinguish between pair/unpair operations.
    Values must match OpenAPI discriminator mapping exactly:
    - "pair" (lowercase) for pairing operations
    - "unPair" (camelCase) for unpairing operations
    """

    PAIR = "pair"  # Create or update VPC pair (lowercase per OpenAPI spec)
    UNPAIR = "unPair"  # Delete VPC pair (camelCase per OpenAPI spec)


# ============================================================================
# TEMPLATE AND CONFIGURATION ENUMS
# ============================================================================


class VpcPairTypeEnum(str, Enum):
    """
    VPC pair template types.

    Discriminator for vpc_pair_details field.
    """

    DEFAULT = "default"  # Use default VPC pair template
    CUSTOM = "custom"  # Use custom VPC pair template


class KeepAliveVrfEnum(str, Enum):
    """
    VPC keep-alive VRF options.

    VRF used for vPC keep-alive link traffic.
    """

    DEFAULT = "default"  # Use default VRF
    MANAGEMENT = "management"  # Use management VRF


class PoModeEnum(str, Enum):
    """
    Port-channel mode options for vPC interfaces.

    Defines LACP behavior.
    """

    ON = "on"  # Static channel mode (no LACP)
    ACTIVE = "active"  # LACP active mode (initiates negotiation)
    PASSIVE = "passive"  # LACP passive mode (waits for negotiation)


class PortChannelDuplexEnum(str, Enum):
    """
    Port-channel duplex mode options.
    """

    HALF = "half"  # Half duplex mode
    FULL = "full"  # Full duplex mode


# ============================================================================
# VPC ROLE AND STATUS ENUMS
# ============================================================================


class VpcRoleEnum(str, Enum):
    """
    VPC role designation for switches in a vPC pair.
    """

    PRIMARY = "primary"  # Configured primary peer
    SECONDARY = "secondary"  # Configured secondary peer
    OPERATIONAL_PRIMARY = "operationalPrimary"  # Runtime primary role
    OPERATIONAL_SECONDARY = "operationalSecondary"  # Runtime secondary role


class MaintenanceModeEnum(str, Enum):
    """
    Switch maintenance mode status.
    """

    MAINTENANCE = "maintenance"  # Switch in maintenance mode
    NORMAL = "normal"  # Switch in normal operation


# ============================================================================
# QUERY AND VIEW ENUMS
# ============================================================================


class ComponentTypeOverviewEnum(str, Enum):
    """
    VPC pair overview component types.

    Used for filtering overview endpoint responses.
    """

    FULL = "full"  # Full overview with all components
    HEALTH = "health"  # Health status only
    MODULE = "module"  # Module information only
    VXLAN = "vxlan"  # VXLAN configuration only
    OVERLAY = "overlay"  # Overlay information only
    PAIRS_INFO = "pairsInfo"  # Pairs information only
    INVENTORY = "inventory"  # Inventory information only
    ANOMALIES = "anomalies"  # Anomalies information only


class ComponentTypeSupportEnum(str, Enum):
    """
    VPC pair support check types.

    Used for validation endpoints.
    """

    CHECK_PAIRING = "checkPairing"  # Check if pairing is allowed
    CHECK_FABRIC_PEERING_SUPPORT = "checkFabricPeeringSupport"  # Check fabric support


class VpcPairViewEnum(str, Enum):
    """
    VPC pairs list view options.

    Controls which VPC pairs are returned in queries.
    """

    INTENDED_PAIRS = "intendedPairs"  # Show intended VPC pairs
    DISCOVERED_PAIRS = "discoveredPairs"  # Show discovered VPC pairs (default)


# ============================================================================
# API FIELD NAME CONSTANTS (Not Enums - Used as Dict Keys)
# ============================================================================


class VpcFieldNames:
    """
    API field name constants for VPC pair operations.

    These are string constants, not enums, because they're used as
    dictionary keys in API payloads and responses.

    Centralized to:
    - Eliminate magic strings
    - Enable IDE autocomplete
    - Prevent typos
    - Easy refactoring
    """

    # VPC Action Discriminator Field
    VPC_ACTION = "vpcAction"

    # Primary Identifier Fields (API format)
    SWITCH_ID = "switchId"
    PEER_SWITCH_ID = "peerSwitchId"
    USE_VIRTUAL_PEER_LINK = "useVirtualPeerLink"

    # Ansible Playbook Fields (user input aliases)
    ANSIBLE_PEER1_SWITCH_ID = "peer1SwitchId"
    ANSIBLE_PEER2_SWITCH_ID = "peer2SwitchId"

    # Configuration Fields
    VPC_PAIR_DETAILS = "vpcPairDetails"
    DOMAIN_ID = "domainId"
    SWITCH_NAME = "switchName"
    PEER_SWITCH_NAME = "peerSwitchName"
    TEMPLATE_NAME = "templateName"
    TEMPLATE_TYPE = "type"

    # Status Fields (for query responses)
    VPC_CONFIGURED = "vpcConfigured"
    CONFIG_SYNC_STATUS = "configSyncStatus"
    CURRENT_PEER = "currentPeer"
    IS_CURRENT_PEER = "isCurrentPeer"
    IS_CONSISTENT = "isConsistent"
    IS_DISCOVERED = "isDiscovered"

    # Response Keys
    VPC_PAIRS = "vpcPairs"
    SWITCHES = "switches"
    DATA = "data"
    VPC_DATA = "vpcData"

    # Network Fields
    FABRIC_MGMT_IP = "fabricManagementIp"
    SERIAL_NUMBER = "serialNumber"
    IP_ADDRESS = "ipAddress"

    # Validation Fields (for pre-deletion checks)
    OVERLAY = "overlay"
    INVENTORY = "inventory"
    NETWORK_COUNT = "networkCount"
    VRF_COUNT = "vrfCount"
    VPC_INTERFACE_COUNT = "vpcInterfaceCount"

    # Template Detail Fields
    KEEP_ALIVE_VRF = "keepAliveVrf"
    PEER_KEEPALIVE_DEST = "peerKeepAliveDest"
    PEER_GATEWAY_ENABLE = "peerGatewayEnable"
    AUTO_RECOVERY_ENABLE = "autoRecoveryEnable"
    DELAY_RESTORE = "delayRestore"
    DELAY_RESTORE_TIME = "delayRestoreTime"

    # Port-Channel Fields
    PO_MODE = "poMode"
    PO_SPEED = "poSpeed"
    PO_DESCRIPTION = "poDescription"
    PO_DUPLEX = "poDuplex"
    PO_MTU = "poMtu"
