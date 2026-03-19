# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Switch discovery models for shallow discovery and fabric add operations.

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from pydantic import Field, field_validator
from typing import Any, Dict, List, Optional, ClassVar, Literal, Union
from typing_extensions import Self

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import (
    PlatformType,
    RemoteCredentialStore,
    ShallowDiscoveryPlatformType,
    SnmpV3AuthProtocol,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.validators import SwitchValidators


class ShallowDiscoveryRequestModel(NDBaseModel):
    """
    Initiates a shallow CDP/LLDP-based discovery from one or more seed IP addresses.

    Path: POST /fabrics/{fabricName}/actions/shallowDiscovery
    """
    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "singleton"
    exclude_from_diff: ClassVar[List[str]] = ["password"]
    seed_ip_collection: List[str] = Field(
        ...,
        alias="seedIpCollection",
        min_length=1,
        description="Seed switch IP collection"
    )
    max_hop: int = Field(
        default=2,
        alias="maxHop",
        ge=0,
        le=7,
        description="Max hop"
    )
    platform_type: ShallowDiscoveryPlatformType = Field(
        default=ShallowDiscoveryPlatformType.NX_OS,
        alias="platformType",
        description="Switch platform type (apic is not supported for shallow discovery)"
    )
    snmp_v3_auth_protocol: SnmpV3AuthProtocol = Field(
        default=SnmpV3AuthProtocol.MD5,
        alias="snmpV3AuthProtocol",
        description="SNMPv3 authentication protocols"
    )
    username: Optional[str] = Field(
        default=None,
        description="User name for switch login"
    )
    password: Optional[str] = Field(
        default=None,
        description="User password for switch login"
    )
    remote_credential_store: Optional[RemoteCredentialStore] = Field(
        default=None,
        alias="remoteCredentialStore",
        description="Type of credential store"
    )
    remote_credential_store_key: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key"
    )

    @field_validator('seed_ip_collection', mode='before')
    @classmethod
    def validate_seed_ips(cls, v: List[str]) -> List[str]:
        """Validate all seed IPs."""
        if not v:
            raise ValueError("At least one seed IP is required")
        validated = []
        for ip in v:
            result = SwitchValidators.validate_ip_address(ip)
            if result:
                validated.append(result)
        if not validated:
            raise ValueError("No valid seed IPs provided")
        return validated

    @field_validator('snmp_v3_auth_protocol', mode='before')
    @classmethod
    def normalize_snmp_auth(cls, v: Union[str, SnmpV3AuthProtocol, None]) -> SnmpV3AuthProtocol:
        """Normalize SNMP auth protocol (case-insensitive)."""
        return SnmpV3AuthProtocol.normalize(v)

    @field_validator('platform_type', mode='before')
    @classmethod
    def normalize_platform(cls, v: Union[str, ShallowDiscoveryPlatformType, None]) -> ShallowDiscoveryPlatformType:
        """Normalize platform type (case-insensitive)."""
        return ShallowDiscoveryPlatformType.normalize(v)


class SwitchDiscoveryModel(NDBaseModel):
    """
    Discovery data for a single switch returned by the shallow discovery API.

    For N7K user VDC deployments, the serial number format is serialNumber:vDCName.
    """
    identifiers: ClassVar[List[str]] = ["serial_number"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"
    hostname: str = Field(
        ...,
        description="Switch host name"
    )
    ip: str = Field(
        ...,
        description="Switch IPv4/v6 address"
    )
    serial_number: str = Field(
        ...,
        alias="serialNumber",
        description="Switch serial number"
    )
    model: str = Field(
        ...,
        description="Switch model"
    )
    software_version: Optional[str] = Field(
        default=None,
        alias="softwareVersion",
        description="Switch software version"
    )
    vdc_id: Optional[int] = Field(
        default=None,
        alias="vdcId",
        ge=0,
        description="N7K VDC ID. Mandatory for N7K switch discovery"
    )
    vdc_mac: Optional[str] = Field(
        default=None,
        alias="vdcMac",
        description="N7K VDC Mac address. Mandatory for N7K switch discovery"
    )
    switch_role: Optional[SwitchRole] = Field(
        default=None,
        alias="switchRole",
        description="Switch role"
    )

    @field_validator('hostname', mode='before')
    @classmethod
    def validate_host(cls, v: str) -> str:
        result = SwitchValidators.validate_hostname(v)
        if result is None:
            raise ValueError("hostname cannot be empty")
        return result

    @field_validator('ip', mode='before')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        result = SwitchValidators.validate_ip_address(v)
        if result is None:
            raise ValueError("ip cannot be empty")
        return result

    @field_validator('serial_number', mode='before')
    @classmethod
    def validate_serial(cls, v: str) -> str:
        result = SwitchValidators.validate_serial_number(v)
        if result is None:
            raise ValueError("serial_number cannot be empty")
        return result

    @field_validator('vdc_mac', mode='before')
    @classmethod
    def validate_mac(cls, v: Optional[str]) -> Optional[str]:
        return SwitchValidators.validate_mac_address(v)


class AddSwitchesRequestModel(NDBaseModel):
    """
    Imports one or more previously discovered switches into a fabric.

    Path: POST /fabrics/{fabricName}/switches
    """
    identifiers: ClassVar[List[str]] = []
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "singleton"
    exclude_from_diff: ClassVar[List[str]] = ["password"]
    switches: List[SwitchDiscoveryModel] = Field(
        ...,
        min_length=1,
        description="The list of switches to be imported"
    )
    platform_type: PlatformType = Field(
        default=PlatformType.NX_OS,
        alias="platformType",
        description="Switch platform type"
    )
    preserve_config: bool = Field(
        default=True,
        alias="preserveConfig",
        description="Flag to preserve the switch configuration after import"
    )
    snmp_v3_auth_protocol: SnmpV3AuthProtocol = Field(
        default=SnmpV3AuthProtocol.MD5,
        alias="snmpV3AuthProtocol",
        description="SNMPv3 authentication protocols"
    )
    use_credential_for_write: Optional[bool] = Field(
        default=None,
        alias="useCredentialForWrite",
        description="Flag to use the discovery credential as LAN credential"
    )
    username: Optional[str] = Field(
        default=None,
        description="User name for switch login"
    )
    password: Optional[str] = Field(
        default=None,
        description="User password for switch login"
    )
    remote_credential_store: Optional[RemoteCredentialStore] = Field(
        default=None,
        alias="remoteCredentialStore",
        description="Type of credential store"
    )
    remote_credential_store_key: Optional[str] = Field(
        default=None,
        alias="remoteCredentialStoreKey",
        description="Remote credential store key"
    )

    def to_payload(self) -> Dict[str, Any]:
        """Convert to API payload format."""
        payload = self.model_dump(by_alias=True, exclude_none=True)
        # Convert nested switches to payload format
        if 'switches' in payload:
            payload['switches'] = [
                s.to_payload() if hasattr(s, 'to_payload') else s
                for s in self.switches
            ]
        return payload

    @field_validator('snmp_v3_auth_protocol', mode='before')
    @classmethod
    def normalize_snmp_auth(cls, v: Union[str, SnmpV3AuthProtocol, None]) -> SnmpV3AuthProtocol:
        """Normalize SNMP auth protocol (case-insensitive: MD5, md5, etc.)."""
        return SnmpV3AuthProtocol.normalize(v)

    @field_validator('platform_type', mode='before')
    @classmethod
    def normalize_platform_type(cls, v: Union[str, PlatformType, None]) -> PlatformType:
        """Normalize platform type (case-insensitive: NX_OS, nx-os, etc.)."""
        return PlatformType.normalize(v)


__all__ = [
    "ShallowDiscoveryRequestModel",
    "SwitchDiscoveryModel",
    "AddSwitchesRequestModel",
]
