# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import re
from typing import List, Dict, Any, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_fabric.enums import (
    FabricTypeEnum,
    AlertSuspendEnum,
    LicenseTierEnum,
    CoppPolicyEnum,
    DhcpProtocolVersionEnum,
    PowerRedundancyModeEnum,
)
# Re-use shared nested models from the iBGP module
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_fabric.manage_fabric_ibgp import (
    LocationModel,
    NetflowSettingsModel,
    BootstrapSubnetModel,
    TelemetrySettingsModel,
    ExternalStreamingSettingsModel,
)


"""
# Comprehensive Pydantic models for External VXLAN fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
External VXLAN fabrics (border/edge router fabrics) through the Nexus Dashboard
Fabric Controller (NDFC) API.

## Models Overview

- `VxlanExternalManagementModel` - External VXLAN fabric-specific management settings
- `FabricExternalModel` - Complete fabric creation model for External fabrics
- `FabricExternalDeleteModel` - Fabric deletion model

## Usage

```python
# Create a new External VXLAN fabric
fabric_data = {
    "name": "MyExternalFabric",
    "management": {
        "type": "vxlanExternal",
        "bgpAsn": "65001",
    }
}
fabric = FabricExternalModel(**fabric_data)
```
"""

# Regex from OpenAPI schema: bgpAsn accepts plain integers (1-4294967295) and
# dotted four-byte ASN notation (1-65535).(0-65535)
_BGP_ASN_RE = re.compile(
    r"^(([1-9]{1}[0-9]{0,8}|[1-3]{1}[0-9]{1,9}|[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))?)$"
)


class VxlanExternalManagementModel(NDNestedModel):
    """
    # Summary

    Comprehensive External VXLAN fabric management configuration.

    This model contains all settings for External VXLAN fabric types, used for
    border/edge router fabrics that connect to external networks.

    ## Raises

    - `ValueError` - If BGP ASN or other field validations fail
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.VXLAN_EXTERNAL] = Field(
        description="Fabric management type",
        default=FabricTypeEnum.VXLAN_EXTERNAL
    )

    # Propagated from FabricExternalModel
    name: Optional[str] = Field(description="Fabric name", min_length=1, max_length=64, default="")

    # Core BGP Configuration
    bgp_asn: str = Field(
        alias="bgpAsn",
        description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]",
    )
    create_bgp_config: bool = Field(
        alias="createBgpConfig",
        description="Generate BGP configuration for core and edge routers",
        default=True
    )

    # Fabric Behavior
    monitored_mode: bool = Field(
        alias="monitoredMode",
        description="If enabled, fabric is only monitored. No configuration will be deployed",
        default=False
    )
    mpls_handoff: bool = Field(
        alias="mplsHandoff",
        description="Enable MPLS Handoff",
        default=False
    )
    mpls_loopback_identifier: Optional[int] = Field(
        alias="mplsLoopbackIdentifier",
        description="Underlay MPLS Loopback Identifier",
        default=None
    )
    mpls_loopback_ip_range: str = Field(
        alias="mplsLoopbackIpRange",
        description="MPLS Loopback IP Address Range",
        default="10.102.0.0/25"
    )
    sub_interface_dot1q_range: str = Field(
        alias="subInterfaceDot1qRange",
        description="Per aggregation dot1q range for VRF-Lite connectivity (minimum: 2, maximum: 4093)",
        default="2-511"
    )
    inband_management: bool = Field(
        alias="inbandManagement",
        description="Import switches with reachability over the switch front-panel ports",
        default=False
    )
    allow_same_loopback_ip_on_switches: bool = Field(
        alias="allowSameLoopbackIpOnSwitches",
        description="Allow the same loopback IP address to be configured on multiple switches",
        default=False
    )
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding",
        description="Enable onboarding of smart switches to Hypershield for firewall service",
        default=False
    )

    # Bootstrap / Day-0 / DHCP
    day0_bootstrap: bool = Field(
        alias="day0Bootstrap",
        description="Support day 0 touchless switch bringup",
        default=False
    )
    day0_plug_and_play: bool = Field(
        alias="day0PlugAndPlay",
        description="Enable Plug n Play for Catalyst 9000 switches",
        default=False
    )
    inband_day0_bootstrap: bool = Field(
        alias="inbandDay0Bootstrap",
        description="Support day 0 touchless switch bringup via inband management",
        default=False
    )
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="List of IPv4 or IPv6 subnets to be used for bootstrap",
        default_factory=list
    )
    local_dhcp_server: bool = Field(
        alias="localDhcpServer",
        description="Automatic IP Assignment For POAP from Local DHCP Server",
        default=False
    )
    dhcp_protocol_version: DhcpProtocolVersionEnum = Field(
        alias="dhcpProtocolVersion",
        description="IP protocol version for Local DHCP Server",
        default=DhcpProtocolVersionEnum.DHCPV4
    )
    dhcp_start_address: str = Field(
        alias="dhcpStartAddress",
        description="DHCP Scope Start Address For Switch POAP",
        default=""
    )
    dhcp_end_address: str = Field(
        alias="dhcpEndAddress",
        description="DHCP Scope End Address For Switch POAP",
        default=""
    )
    domain_name: str = Field(
        alias="domainName",
        description="Domain name for DHCP server PnP block",
        default=""
    )
    management_gateway: str = Field(
        alias="managementGateway",
        description="Default Gateway For Management VRF On The Switch",
        default=""
    )
    management_ipv4_prefix: int = Field(
        alias="managementIpv4Prefix",
        description="Switch Mgmt IP Subnet Prefix if ipv4",
        default=24
    )
    management_ipv6_prefix: int = Field(
        alias="managementIpv6Prefix",
        description="Switch Management IP Subnet Prefix if ipv6",
        default=64
    )

    # DNS Collections
    dns_collection: List[str] = Field(
        alias="dnsCollection",
        description="List of IPv4 and IPv6 DNS addresses",
        default_factory=list
    )
    dns_vrf_collection: List[str] = Field(
        alias="dnsVrfCollection",
        description="DNS Server VRFs. One VRF for all DNS servers or a list of VRFs, one per DNS server",
        default_factory=list
    )

    # Extra Configuration
    extra_config_aaa: str = Field(
        alias="extraConfigAaa",
        description="Additional CLIs for AAA Configuration",
        default=""
    )
    extra_config_fabric: str = Field(
        alias="extraConfigFabric",
        description="Additional CLIs for all switches",
        default=""
    )
    extra_config_nxos_bootstrap: str = Field(
        alias="extraConfigNxosBootstrap",
        description="Additional CLIs required during device bootup/login e.g. AAA/Radius (NX-OS)",
        default=""
    )
    extra_config_xe_bootstrap: str = Field(
        alias="extraConfigXeBootstrap",
        description="Additional CLIs required during device bootup/login e.g. AAA/Radius (IOS-XE)",
        default=""
    )

    # Management Protocol Settings
    nxapi: bool = Field(
        description="Enable NX-API over HTTPS",
        default=False
    )
    nxapi_http: bool = Field(
        alias="nxapiHttp",
        description="Enable NX-API over HTTP",
        default=False
    )
    nxapi_http_port: int = Field(
        alias="nxapiHttpPort",
        description="HTTP port for NX-API",
        default=80
    )
    nxapi_https_port: int = Field(
        alias="nxapiHttpsPort",
        description="HTTPS port for NX-API",
        default=443
    )
    cdp: bool = Field(
        description="Enable CDP on management interface",
        default=False
    )
    aaa: bool = Field(
        description="Include AAA configs from Advanced tab during device bootup",
        default=False
    )
    advanced_ssh_option: bool = Field(
        alias="advancedSshOption",
        description="Enable only, when IP Authorization is enabled in the AAA Server",
        default=False
    )
    snmp_trap: bool = Field(
        alias="snmpTrap",
        description="Configure Nexus Dashboard as a receiver for SNMP traps",
        default=True
    )
    copp_policy: CoppPolicyEnum = Field(
        alias="coppPolicy",
        description="Fabric wide CoPP policy. Customized CoPP policy should be provided when 'manual'",
        default=CoppPolicyEnum.MANUAL
    )
    power_redundancy_mode: PowerRedundancyModeEnum = Field(
        alias="powerRedundancyMode",
        description="Default Power Supply Mode for NX-OS Switches",
        default=PowerRedundancyModeEnum.REDUNDANT
    )
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval",
        description="Interface Statistics Load Interval Time in seconds",
        default=10
    )
    performance_monitoring: bool = Field(
        alias="performanceMonitoring",
        description="If enabled, switch metrics are collected through periodic SNMP polling",
        default=False
    )
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description="Enable Real Time Interface Statistics Collection. Valid for NX-OS only",
        default=False
    )

    # PTP Settings
    ptp: bool = Field(
        description="Enable Precision Time Protocol (PTP)",
        default=False
    )
    ptp_domain_id: int = Field(
        alias="ptpDomainId",
        description="Multiple Independent PTP Clocking Subdomains on a Single Network",
        default=0
    )
    ptp_loopback_id: int = Field(
        alias="ptpLoopbackId",
        description="Precision Time Protocol Source Loopback Id",
        default=0
    )

    # Netflow Settings
    netflow_settings: NetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Settings associated with netflow",
        default_factory=NetflowSettingsModel
    )

    # Backup / Restore
    real_time_backup: Optional[bool] = Field(
        alias="realTimeBackup",
        description="Hourly Fabric Backup only if there is any config deployment since last backup",
        default=None
    )
    scheduled_backup: Optional[bool] = Field(
        alias="scheduledBackup",
        description="Enable backup at the specified time daily",
        default=None
    )
    scheduled_backup_time: str = Field(
        alias="scheduledBackupTime",
        description="Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59)",
        default=""
    )

    # Hypershield / Connectivity
    connectivity_domain_name: Optional[str] = Field(
        alias="connectivityDomainName",
        description="Domain name to connect to Hypershield",
        default=None
    )
    hypershield_connectivity_proxy_server: Optional[str] = Field(
        alias="hypershieldConnectivityProxyServer",
        description="IPv4 address, IPv6 address, or DNS name of the proxy server for Hypershield communication",
        default=None
    )
    hypershield_connectivity_proxy_server_port: Optional[int] = Field(
        alias="hypershieldConnectivityProxyServerPort",
        description="Proxy port number for communication with Hypershield",
        default=None
    )
    hypershield_connectivity_source_intf: Optional[str] = Field(
        alias="hypershieldConnectivitySourceIntf",
        description="Loopback interface on smart switch for communication with Hypershield",
        default=None
    )

    @field_validator("bgp_asn")
    @classmethod
    def validate_bgp_asn(cls, value: str) -> str:
        """
        # Summary

        Validate BGP ASN format and range.

        ## Raises

        - `ValueError` - If value does not match the expected ASN format
        """
        if not _BGP_ASN_RE.match(value):
            raise ValueError(
                f"Invalid BGP ASN '{value}'. "
                "Expected a plain integer (1-4294967295) or dotted notation (1-65535.0-65535)."
            )
        return value


class FabricExternalModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a new External VXLAN fabric.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Properties
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    name: str = Field(description="Fabric name", min_length=1, max_length=64)
    location: Optional[LocationModel] = Field(description="Geographic location of the fabric", default=None)

    # License and Operations
    license_tier: LicenseTierEnum = Field(alias="licenseTier", description="License tier", default=LicenseTierEnum.PREMIER)
    alert_suspend: AlertSuspendEnum = Field(alias="alertSuspend", description="Alert suspension state", default=AlertSuspendEnum.DISABLED)
    telemetry_collection: bool = Field(alias="telemetryCollection", description="Enable telemetry collection", default=False)
    telemetry_collection_type: str = Field(alias="telemetryCollectionType", description="Telemetry collection type", default="outOfBand")
    telemetry_streaming_protocol: str = Field(alias="telemetryStreamingProtocol", description="Telemetry streaming protocol", default="ipv4")
    telemetry_source_interface: str = Field(alias="telemetrySourceInterface", description="Telemetry source interface", default="")
    telemetry_source_vrf: str = Field(alias="telemetrySourceVrf", description="Telemetry source VRF", default="")
    security_domain: str = Field(alias="securityDomain", description="Security domain", default="all")

    # Core Management Configuration
    management: Optional[VxlanExternalManagementModel] = Field(
        description="External VXLAN management configuration",
        default=None
    )

    # Optional Advanced Settings
    telemetry_settings: Optional[TelemetrySettingsModel] = Field(
        alias="telemetrySettings",
        description="Telemetry configuration",
        default=None
    )
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings",
        description="External streaming settings",
        default_factory=ExternalStreamingSettingsModel
    )

    @field_validator("name")
    @classmethod
    def validate_fabric_name(cls, value: str) -> str:
        """
        # Summary

        Validate fabric name format and characters.

        ## Raises

        - `ValueError` - If name contains invalid characters or format
        """
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            raise ValueError(f"Fabric name can only contain letters, numbers, underscores, and hyphens, got: {value}")
        return value

    @model_validator(mode='after')
    def validate_fabric_consistency(self) -> 'FabricExternalModel':
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        if self.management is not None and self.management.type != FabricTypeEnum.VXLAN_EXTERNAL:
            raise ValueError(f"Management type must be {FabricTypeEnum.VXLAN_EXTERNAL}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.name

        # Auto-create default telemetry settings if collection is enabled
        if self.telemetry_collection and self.telemetry_settings is None:
            self.telemetry_settings = TelemetrySettingsModel()

        return self

    @classmethod
    def get_argument_spec(cls) -> Dict:
        return dict(
            state={
                "type": "str",
                "default": "merged",
                "choices": ["merged", "replaced", "deleted", "overridden", "query"],
            },
            config={"required": False, "type": "list", "elements": "dict"},
        )


# Export all models for external use
__all__ = [
    "VxlanExternalManagementModel",
    "FabricExternalModel",
    "FabricExternalDeleteModel",
    "FabricTypeEnum",
    "AlertSuspendEnum",
    "LicenseTierEnum",
    "CoppPolicyEnum",
    "DhcpProtocolVersionEnum",
    "PowerRedundancyModeEnum",
]
