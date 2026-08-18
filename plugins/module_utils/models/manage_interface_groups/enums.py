# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Enumerations for Nexus Dashboard Manage Interface Groups APIs."""

from __future__ import annotations

from enum import Enum


class InterfaceGroupType(str, Enum):
    """Supported Interface Group discriminator values."""

    ANY = "any"
    ETHERNET_CUSTOM = "ethernetCustom"
    ETHERNET_WITH_POLICY = "ethernetWithPolicy"
    ETHERNET_WITHOUT_POLICY = "ethernetWithoutPolicy"
    PORT_CHANNEL = "portChannel"
    VPC = "vpc"

    @classmethod
    def choices(cls) -> list[str]:
        return [item.value for item in cls]


class InterfaceGroupConfigActionType(str, Enum):
    """Deployment scopes supported by the Interface Groups module."""

    RESOURCE = "resource"
    SWITCH = "switch"

    @classmethod
    def choices(cls) -> list[str]:
        return [item.value for item in cls]


class InterfaceGroupState(str, Enum):
    """Resource states supported by ``nd_manage_interface_group``."""

    MERGED = "merged"
    REPLACED = "replaced"
    OVERRIDDEN = "overridden"
    DELETED = "deleted"
    GATHERED = "gathered"

    @classmethod
    def choices(cls) -> list[str]:
        return [item.value for item in cls]


class InterfaceGroupOperationStatus(str, Enum):
    """Per-item status values returned in HTTP 207 responses."""

    SUCCESS = "success"
    FAILED = "failed"

    @classmethod
    def choices(cls) -> list[str]:
        return [item.value for item in cls]
