# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import List, Dict, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
    AlertSuspendEnum,
    LicenseTierEnum,
    CoppPolicyEnum,
    DhcpProtocolVersionEnum,
    PowerRedundancyModeEnum,
    TelemetryCollectionTypeEnum,
    TelemetryStreamingProtocolEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    BGP_ASN_RE,
    LocationModel,
    NetflowExporterModel,
    NetflowRecordModel,
    NetflowMonitorModel,
    NetflowSettingsModel,
    BootstrapSubnetModel,
    TelemetryFlowCollectionModel,
    TelemetryMicroburstModel,
    TelemetryAnalysisSettingsModel,
    TelemetryEnergyManagementModel,
    TelemetrySettingsModel,
    ExternalStreamingSettingsModel,
)

"""
# Comprehensive Pydantic models for External Connectivity fabric management via Nexus Dashboard

This module provides comprehensive Pydantic models for creating, updating, and deleting
External Connectivity fabrics through the Nexus Dashboard Fabric Controller (NDFC) API.

## Models Overview

- `ExternalConnectivityManagementModel` - External Connectivity specific management settings
- `FabricExternalConnectivityModel` - Complete fabric creation model

## Usage

```python
# Create a new External Connectivity fabric
fabric_data = {
    "name": "MyExtFabric",
    "location": {"latitude": 37.7749, "longitude": -122.4194},
    "management": {
        "type": "externalConnectivity",
        "bgp_asn": "65001",
    }
}
fabric = FabricExternalConnectivityModel(**fabric_data)
```
"""


class ExternalConnectivityManagementModel(NDNestedModel):
    """
    # Summary

    Comprehensive External Connectivity fabric management configuration.

    This model contains all settings specific to External Connectivity fabric types including
    BGP configuration, bootstrap settings, and advanced features.

    ## Raises

    - `ValueError` - If BGP ASN or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.EXTERNAL_CONNECTIVITY] = Field(description="Fabric management type", default=FabricTypeEnum.EXTERNAL_CONNECTIVITY)

    # Core Configuration
    bgp_asn: str = Field(
        alias="bgpAsn",
        description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]",
    )

    # Name under management section is optional for backward compatibility
    name: Optional[str] = Field(description="Fabric name", min_length=1, max_length=64, default="")

    # AAA
    aaa: bool = Field(
        description="Include AAA configs from Advanced tab during device bootup",
        default=False,
    )

    # SSH
    advanced_ssh_option: bool = Field(
        alias="advancedSshOption",
        description="Enable only, when IP Authorization is enabled in the AAA Server",
        default=False,
    )

    # Loopback
    allow_same_loopback_ip_on_switches: bool = Field(
        alias="allowSameLoopbackIpOnSwitches",
        description=("Allow the same loopback IP address to be configured on multiple" " switches (e.g. RP loopback IP)"),
        default=False,
    )

    # Smart Switch
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding",
        description=("Enable onboarding of smart switches to Hypershield" " for firewall service"),
        default=False,
    )

    # Bootstrap Subnet Collection
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="List of IPv4 or IPv6 subnets to be used for bootstrap",
        default_factory=list,
    )

    # CDP
    cdp: bool = Field(description="Enable CDP on management interface", default=False)

    # CoPP Policy
    copp_policy: CoppPolicyEnum = Field(
        alias="coppPolicy",
        description=("Fabric wide CoPP policy. Customized CoPP policy should be" " provided when 'manual' is selected."),
        default=CoppPolicyEnum.MANUAL,
    )

    # BGP Configuration
    create_bgp_config: bool = Field(
        alias="createBgpConfig",
        description="Generate BGP configuration for core and edge routers",
        default=True,
    )

    # Bootstrap Settings
    day0_bootstrap: bool = Field(
        alias="day0Bootstrap",
        description="Support day 0 touchless switch bringup",
        default=False,
    )
    day0_plug_and_play: bool = Field(
        alias="day0PlugAndPlay",
        description="Enable Plug n Play for Catalyst 9000 switches",
        default=False,
    )

    # DHCP
    dhcp_end_address: str = Field(
        alias="dhcpEndAddress",
        description="DHCP Scope End Address For Switch POAP",
        default="",
    )
    dhcp_protocol_version: DhcpProtocolVersionEnum = Field(
        alias="dhcpProtocolVersion",
        description="IP protocol version for Local DHCP Server",
        default=DhcpProtocolVersionEnum.DHCPV4,
    )
    dhcp_start_address: str = Field(
        alias="dhcpStartAddress",
        description="DHCP Scope Start Address For Switch POAP",
        default="",
    )

    # DNS
    dns_collection: List[str] = Field(
        alias="dnsCollection",
        description="List of IPv4 and IPv6 DNS addresses",
        default_factory=list,
    )
    dns_vrf_collection: List[str] = Field(
        alias="dnsVrfCollection",
        description=("DNS Server VRFs. One VRF for all DNS servers or a list of VRFs," " one per DNS server"),
        default_factory=list,
    )

    # Domain
    domain_name: str = Field(
        alias="domainName",
        description="Domain name for DHCP server PnP block",
        default="",
    )

    # DPU Pinning
    enable_dpu_pinning: bool = Field(
        alias="enableDpuPinning",
        description=("Enable pinning of VRFs and networks to specific DPUs" " on smart switches"),
        default=False,
    )

    # Extra Config
    extra_config_aaa: str = Field(
        alias="extraConfigAaa",
        description="Additional CLIs for AAA Configuration",
        default="",
    )
    extra_config_fabric: str = Field(
        alias="extraConfigFabric",
        description="Additional CLIs for all switches",
        default="",
    )
    extra_config_nxos_bootstrap: str = Field(
        alias="extraConfigNxosBootstrap",
        description=("Additional CLIs required during device bootup/login" " e.g. AAA/Radius (NX-OS)"),
        default="",
    )
    extra_config_xe_bootstrap: str = Field(
        alias="extraConfigXeBootstrap",
        description=("Additional CLIs required during device bootup/login" " e.g. AAA/Radius (IOS-XE)"),
        default="",
    )

    # Inband Management
    inband_day0_bootstrap: bool = Field(
        alias="inbandDay0Bootstrap",
        description="Support day 0 touchless switch bringup via inband management",
        default=False,
    )
    inband_management: bool = Field(
        alias="inbandManagement",
        description=("Import switches with reachability over the switch" " front-panel ports"),
        default=False,
    )

    # Interface Statistics
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval",
        description="Interface Statistics Load Interval Time in seconds",
        default=10,
    )

    # Local DHCP Server
    local_dhcp_server: bool = Field(
        alias="localDhcpServer",
        description="Automatic IP Assignment For POAP from Local DHCP Server",
        default=False,
    )

    # Management
    management_gateway: str = Field(
        alias="managementGateway",
        description="Default Gateway For Management VRF On The Switch",
        default="",
    )
    management_ipv4_prefix: int = Field(
        alias="managementIpv4Prefix",
        description="Switch Mgmt IP Subnet Prefix if ipv4",
        default=24,
    )
    management_ipv6_prefix: int = Field(
        alias="managementIpv6Prefix",
        description="Switch Management IP Subnet Prefix if ipv6",
        default=64,
    )

    # Monitored Mode
    monitored_mode: bool = Field(
        alias="monitoredMode",
        description=("If enabled, fabric is only monitored." " No configuration will be deployed"),
        default=False,
    )

    # MPLS Handoff
    mpls_handoff: bool = Field(
        alias="mplsHandoff",
        description="Enable MPLS Handoff",
        default=False,
    )
    mpls_loopback_identifier: Optional[int] = Field(
        alias="mplsLoopbackIdentifier",
        description="Underlay MPLS Loopback Identifier",
        default=None,
    )
    mpls_loopback_ip_range: str = Field(
        alias="mplsLoopbackIpRange",
        description="MPLS Loopback IP Address Range",
        default="10.102.0.0/25",
    )

    # Netflow Settings
    netflow_settings: NetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Settings associated with netflow",
        default_factory=NetflowSettingsModel,
    )

    # NX-API Settings
    nxapi: bool = Field(description="Enable NX-API over HTTPS", default=False)
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API over HTTP", default=False)
    nxapi_http_port: int = Field(alias="nxapiHttpPort", description="HTTP port for NX-API", ge=1, le=65535, default=80)
    nxapi_https_port: int = Field(alias="nxapiHttpsPort", description="HTTPS port for NX-API", ge=1, le=65535, default=443)

    # Performance Monitoring
    performance_monitoring: bool = Field(
        alias="performanceMonitoring",
        description=("If enabled, switch metrics are collected through periodic SNMP" " polling. Alternative to real-time telemetry"),
        default=False,
    )

    # Power Redundancy
    power_redundancy_mode: PowerRedundancyModeEnum = Field(
        alias="powerRedundancyMode",
        description="Default Power Supply Mode for NX-OS Switches",
        default=PowerRedundancyModeEnum.REDUNDANT,
    )

    # PTP
    ptp: bool = Field(description="Enable Precision Time Protocol (PTP)", default=False)
    ptp_domain_id: int = Field(
        alias="ptpDomainId",
        description=("Multiple Independent PTP Clocking Subdomains" " on a Single Network"),
        default=0,
    )
    ptp_loopback_id: int = Field(
        alias="ptpLoopbackId",
        description="Precision Time Protocol Source Loopback Id",
        default=0,
    )

    # Backup / Restore
    real_time_backup: Optional[bool] = Field(
        alias="realTimeBackup",
        description=("Hourly Fabric Backup only if there is any config deployment" " since last backup"),
        default=None,
    )

    # Interface Statistics Collection
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description=("Enable Real Time Interface Statistics Collection." " Valid for NX-OS only"),
        default=False,
    )

    # Scheduled Backup
    scheduled_backup: Optional[bool] = Field(
        alias="scheduledBackup",
        description="Enable backup at the specified time daily",
        default=None,
    )
    scheduled_backup_time: str = Field(
        alias="scheduledBackupTime",
        description=("Time (UTC) in 24 hour format to take a daily backup" " if enabled (00:00 to 23:59)"),
        default="",
    )

    # SNMP
    snmp_trap: bool = Field(
        alias="snmpTrap",
        description="Configure Nexus Dashboard as a receiver for SNMP traps",
        default=True,
    )

    # Sub-Interface
    sub_interface_dot1q_range: str = Field(
        alias="subInterfaceDot1qRange",
        description=("Per aggregation dot1q range for VRF-Lite connectivity" " (minimum: 2, maximum: 4093)"),
        default="2-511",
    )

    # Hypershield / Connectivity
    connectivity_domain_name: Optional[str] = Field(alias="connectivityDomainName", description="Domain name to connect to Hypershield", default=None)
    hypershield_connectivity_proxy_server: Optional[str] = Field(
        alias="hypershieldConnectivityProxyServer",
        description="IPv4 address, IPv6 address, or DNS name of the proxy server for Hypershield communication",
        default=None,
    )
    hypershield_connectivity_proxy_server_port: Optional[int] = Field(
        alias="hypershieldConnectivityProxyServerPort", description="Proxy port number for communication with Hypershield", default=None
    )
    hypershield_connectivity_source_intf: Optional[str] = Field(
        alias="hypershieldConnectivitySourceIntf", description="Loopback interface on smart switch for communication with Hypershield", default=None
    )

    @field_validator("bgp_asn")
    @classmethod
    def validate_bgp_asn(cls, value: str) -> str:
        """
        # Summary

        Validate BGP ASN format and range.

        ## Description

        Accepts either a plain integer ASN (1-4294967295) or dotted four-byte
        ASN notation in the form ``MMMM.NNNN`` where both parts are in the
        range 1-65535 / 0-65535 respectively.

        ## Raises

        - `ValueError` - If the value does not match the expected ASN format
        """
        if not BGP_ASN_RE.match(value):
            raise ValueError(f"Invalid BGP ASN '{value}'. " "Expected a plain integer (1-4294967295) or dotted notation (1-65535.0-65535).")
        return value


class FabricExternalConnectivityModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a new External Connectivity fabric.

    This model combines all necessary components for fabric creation including
    basic fabric properties, management settings, telemetry, and streaming configuration.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(
        str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow"  # Allow extra fields from API responses
    )

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Properties
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    fabric_name: str = Field(alias="name", description="Fabric name", min_length=1, max_length=64)
    location: Optional[LocationModel] = Field(description="Geographic location of the fabric", default=None)

    # License and Operations
    license_tier: LicenseTierEnum = Field(
        alias="licenseTier",
        description="License Tier value of a fabric.",
        default=LicenseTierEnum.PREMIER,
    )
    alert_suspend: AlertSuspendEnum = Field(
        alias="alertSuspend",
        description="Alert Suspend state configured on the fabric",
        default=AlertSuspendEnum.DISABLED,
    )
    telemetry_collection: bool = Field(alias="telemetryCollection", description="Enable telemetry collection", default=False)
    telemetry_collection_type: TelemetryCollectionTypeEnum = Field(
        alias="telemetryCollectionType",
        description="Telemetry collection method.",
        default=TelemetryCollectionTypeEnum.OUT_OF_BAND,
    )
    telemetry_streaming_protocol: TelemetryStreamingProtocolEnum = Field(
        alias="telemetryStreamingProtocol",
        description="Telemetry Streaming Protocol.",
        default=TelemetryStreamingProtocolEnum.IPV4,
    )
    telemetry_source_interface: str = Field(
        alias="telemetrySourceInterface",
        description=("Telemetry Source Interface (VLAN id or Loopback id) only valid" " if Telemetry Collection is set to inBand"),
        default="",
    )
    telemetry_source_vrf: str = Field(
        alias="telemetrySourceVrf",
        description=("VRF over which telemetry is streamed, valid only if telemetry" " collection is set to inband"),
        default="",
    )
    security_domain: str = Field(
        alias="securityDomain",
        description="Security Domain associated with the fabric",
        default="all",
    )

    # Core Management Configuration
    management: Optional[ExternalConnectivityManagementModel] = Field(description="External Connectivity management configuration", default=None)

    # Optional Advanced Settings
    telemetry_settings: Optional[TelemetrySettingsModel] = Field(alias="telemetrySettings", description="Telemetry configuration", default=None)
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings", description="External streaming settings", default_factory=ExternalStreamingSettingsModel
    )

    @field_validator("fabric_name")
    @classmethod
    def validate_fabric_name(cls, value: str) -> str:
        """
        # Summary

        Validate fabric name format and characters.

        ## Raises

        - `ValueError` - If name contains invalid characters or format
        """
        if not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise ValueError(f"Fabric name can only contain letters, numbers, underscores, and hyphens, got: {value}")

        return value

    @model_validator(mode="after")
    def validate_fabric_consistency(self) -> "FabricExternalConnectivityModel":
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        # Ensure management type matches model type
        if self.management is not None and self.management.type != FabricTypeEnum.EXTERNAL_CONNECTIVITY:
            raise ValueError(f"Management type must be {FabricTypeEnum.EXTERNAL_CONNECTIVITY}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.fabric_name

        # Validate telemetry consistency
        if self.telemetry_collection and self.telemetry_settings is None:
            # Auto-create default telemetry settings if collection is enabled
            self.telemetry_settings = TelemetrySettingsModel()

        return self

    # TODO: to generate from Fields (low priority)
    @classmethod
    def get_argument_spec(cls) -> Dict:
        return dict(
            state={
                "type": "str",
                "default": "merged",
                "choices": ["merged", "replaced", "deleted", "overridden"],
            },
            config={"required": False, "type": "list", "elements": "dict"},
        )


# Export all models for external use
__all__ = [
    "LocationModel",
    "NetflowExporterModel",
    "NetflowRecordModel",
    "NetflowMonitorModel",
    "NetflowSettingsModel",
    "BootstrapSubnetModel",
    "TelemetryFlowCollectionModel",
    "TelemetryMicroburstModel",
    "TelemetryAnalysisSettingsModel",
    "TelemetryEnergyManagementModel",
    "TelemetrySettingsModel",
    "ExternalStreamingSettingsModel",
    "ExternalConnectivityManagementModel",
    "FabricExternalConnectivityModel",
    "FabricTypeEnum",
    "AlertSuspendEnum",
    "LicenseTierEnum",
    "CoppPolicyEnum",
    "DhcpProtocolVersionEnum",
    "PowerRedundancyModeEnum",
]
