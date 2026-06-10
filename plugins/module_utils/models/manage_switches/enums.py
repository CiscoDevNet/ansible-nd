# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Enumerations for Switch and Inventory Operations.

Extracted from OpenAPI schema (manage.json) for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from enum import Enum
from typing import List

# =============================================================================
# ENUMS - Extracted from OpenAPI Schema components/schemas
# =============================================================================


class SwitchRole(str, Enum):
    """
    Switch role enumeration.

    Based on: components/schemas/switchRole
    Description: The role of the switch, meta is a read-only switch role
    """

    BORDER = "border"
    BORDER_GATEWAY = "borderGateway"
    BORDER_GATEWAY_SPINE = "borderGatewaySpine"
    BORDER_GATEWAY_SUPER_SPINE = "borderGatewaySuperSpine"
    BORDER_SPINE = "borderSpine"
    BORDER_SUPER_SPINE = "borderSuperSpine"
    LEAF = "leaf"
    SPINE = "spine"
    SUPER_SPINE = "superSpine"
    TIER2_LEAF = "tier2Leaf"
    TOR = "tor"
    ACCESS = "access"
    AGGREGATION = "aggregation"
    CORE_ROUTER = "coreRouter"
    EDGE_ROUTER = "edgeRouter"
    META = "meta"  # read-only
    NEIGHBOR = "neighbor"

    @classmethod
    def choices(cls) -> List[str]:
        """Return list of valid choices."""
        return [e.value for e in cls]


class SystemMode(str, Enum):
    """
    System mode enumeration.

    Based on: components/schemas/systemMode
    """

    NORMAL = "normal"
    MAINTENANCE = "maintenance"
    MIGRATION = "migration"
    INCONSISTENT = "inconsistent"
    WAITING = "waiting"
    NOT_APPLICABLE = "notApplicable"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class PlatformType(str, Enum):
    """
    Switch platform type enumeration.

    Used for POST /fabrics/{fabricName}/switches (AddSwitches).
    Includes all platform types supported by the add-switches endpoint.
    Based on: components/schemas
    """

    NX_OS = "nx-os"
    OTHER = "other"
    IOS_XE = "ios-xe"
    IOS_XR = "ios-xr"
    SONIC = "sonic"
    APIC = "apic"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class SnmpV3AuthProtocol(str, Enum):
    """
    SNMPv3 authentication protocols.

    Based on: components/schemas/snmpV3AuthProtocol and schemas-snmpV3AuthProtocol
    """

    MD5 = "md5"
    SHA = "sha"
    MD5_DES = "md5-des"
    MD5_AES = "md5-aes"
    SHA_AES = "sha-aes"
    SHA_DES = "sha-des"
    SHA_AES_256 = "sha-aes-256"
    SHA_224 = "sha-224"
    SHA_224_AES = "sha-224-aes"
    SHA_224_AES_256 = "sha-224-aes-256"
    SHA_256 = "sha-256"
    SHA_256_AES = "sha-256-aes"
    SHA_256_AES_256 = "sha-256-aes-256"
    SHA_384 = "sha-384"
    SHA_384_AES = "sha-384-aes"
    SHA_384_AES_256 = "sha-384-aes-256"
    SHA_512 = "sha-512"
    SHA_512_AES = "sha-512-aes"
    SHA_512_AES_256 = "sha-512-aes-256"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class DiscoveryStatus(str, Enum):
    """
    Switch discovery status.

    Based on: components/schemas/additionalSwitchData.discoveryStatus
    """

    OK = "ok"
    DISCOVERING = "discovering"
    REDISCOVERING = "rediscovering"
    DEVICE_SHUTTING_DOWN = "deviceShuttingDown"
    UNREACHABLE = "unreachable"
    IP_ADDRESS_CHANGE = "ipAddressChange"
    DISCOVERY_TIMEOUT = "discoveryTimeout"
    RETRYING = "retrying"
    SSH_SESSION_ERROR = "sshSessionError"
    TIMEOUT = "timeout"
    UNKNOWN_USER_PASSWORD = "unknownUserPassword"
    CONNECTION_ERROR = "connectionError"
    NOT_APPLICABLE = "notApplicable"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class ConfigSyncStatus(str, Enum):
    """
    Configuration sync status.

    Based on: components/schemas/switchConfigSyncStatus
    """

    DEPLOYED = "deployed"
    DEPLOYMENT_IN_PROGRESS = "deploymentInProgress"
    FAILED = "failed"
    IN_PROGRESS = "inProgress"
    IN_SYNC = "inSync"
    NOT_APPLICABLE = "notApplicable"
    OUT_OF_SYNC = "outOfSync"
    PENDING = "pending"
    PREVIEW_IN_PROGRESS = "previewInProgress"
    SUCCESS = "success"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class VpcRole(str, Enum):
    """
    VPC role enumeration.

    Based on: components/schemas/schemas-vpcRole
    """

    PRIMARY = "primary"
    SECONDARY = "secondary"
    OPERATIONAL_PRIMARY = "operationalPrimary"
    OPERATIONAL_SECONDARY = "operationalSecondary"
    NONE_ESTABLISHED = "noneEstablished"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class RemoteCredentialStore(str, Enum):
    """
    Remote credential store type.

    Based on: components/schemas/remoteCredentialStore
    """

    LOCAL = "local"
    CYBERARK = "cyberark"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class AnomalyLevel(str, Enum):
    """
    Anomaly level classification.

    Based on: components/schemas/anomalyLevel
    """

    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    WARNING = "warning"
    HEALTHY = "healthy"
    NOT_APPLICABLE = "notApplicable"
    UNKNOWN = "unknown"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


class AdvisoryLevel(str, Enum):
    """
    Advisory level classification.

    Based on: components/schemas/advisoryLevel
    """

    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    WARNING = "warning"
    HEALTHY = "healthy"
    NONE = "none"
    NOT_APPLICABLE = "notApplicable"

    @classmethod
    def choices(cls) -> List[str]:
        return [e.value for e in cls]


__all__ = [
    "SwitchRole",
    "SystemMode",
    "PlatformType",
    "SnmpV3AuthProtocol",
    "DiscoveryStatus",
    "ConfigSyncStatus",
    "VpcRole",
    "RemoteCredentialStore",
    "AnomalyLevel",
    "AdvisoryLevel",
]
