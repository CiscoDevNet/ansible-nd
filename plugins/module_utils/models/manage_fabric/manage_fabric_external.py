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


"""
# Comprehensive Pydantic models for External Connectivity fabric management via Nexus Dashboard

This module provides comprehensive Pydantic models for creating, updating, and deleting
External Connectivity fabrics through the Nexus Dashboard Fabric Controller (NDFC) API.

## Models Overview

- `LocationModel` - Geographic location coordinates
- `NetflowExporterModel` - Netflow exporter configuration
- `NetflowRecordModel` - Netflow record configuration
- `NetflowMonitorModel` - Netflow monitor configuration
- `NetflowSettingsModel` - Complete netflow settings
- `BootstrapSubnetModel` - Bootstrap subnet configuration
- `TelemetryFlowCollectionModel` - Telemetry flow collection settings
- `TelemetrySettingsModel` - Complete telemetry configuration
- `ExternalStreamingSettingsModel` - External streaming configuration
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

# Regex from OpenAPI schema: bgpAsn accepts plain integers (1-4294967295) and
# dotted four-byte ASN notation (1-65535).(0-65535)
_BGP_ASN_RE = re.compile(
    r"^(([1-9]{1}[0-9]{0,8}|[1-3]{1}[0-9]{1,9}|[4]{1}([0-1]{1}[0-9]{8}"
    r"|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}"
    r"|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}"
    r"|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))"
    r"|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])"
    r"(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))?)$"
)


class LocationModel(NDNestedModel):
    """
    # Summary

    Geographic location coordinates for the fabric.

    ## Raises

    - `ValueError` - If latitude or longitude are outside valid ranges
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    latitude: float = Field(
        description="Latitude coordinate (-90 to 90)",
        ge=-90.0,
        le=90.0
    )
    longitude: float = Field(
        description="Longitude coordinate (-180 to 180)",
        ge=-180.0,
        le=180.0
    )


class NetflowExporterModel(NDNestedModel):
    """
    # Summary

    Netflow exporter configuration for telemetry.

    ## Raises

    - `ValueError` - If UDP port is outside valid range or IP address is invalid
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    exporter_name: str = Field(alias="exporterName", description="Name of the netflow exporter")
    exporter_ip: str = Field(alias="exporterIp", description="IP address of the netflow collector")
    vrf: str = Field(description="VRF name for the exporter", default="management")
    source_interface_name: str = Field(alias="sourceInterfaceName", description="Source interface name")
    udp_port: int = Field(alias="udpPort", description="UDP port for netflow export", ge=1, le=65535)


class NetflowRecordModel(NDNestedModel):
    """
    # Summary

    Netflow record configuration defining flow record templates.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    record_name: str = Field(alias="recordName", description="Name of the netflow record")
    record_template: str = Field(alias="recordTemplate", description="Template type for the record")
    layer2_record: bool = Field(alias="layer2Record", description="Enable layer 2 record fields", default=False)


class NetflowMonitorModel(NDNestedModel):
    """
    # Summary

    Netflow monitor configuration linking records to exporters.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    monitor_name: str = Field(alias="monitorName", description="Name of the netflow monitor")
    record_name: str = Field(alias="recordName", description="Associated record name")
    exporter1_name: str = Field(alias="exporter1Name", description="Primary exporter name")
    exporter2_name: str = Field(alias="exporter2Name", description="Secondary exporter name", default="")


class NetflowSettingsModel(NDNestedModel):
    """
    # Summary

    Complete netflow configuration including exporters, records, and monitors.

    ## Raises

    - `ValueError` - If netflow lists are inconsistent with netflow enabled state
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    netflow: bool = Field(description="Enable netflow collection", default=False)
    netflow_exporter_collection: List[NetflowExporterModel] = Field(
        alias="netflowExporterCollection",
        description="List of netflow exporters",
        default_factory=list
    )
    netflow_record_collection: List[NetflowRecordModel] = Field(
        alias="netflowRecordCollection",
        description="List of netflow records",
        default_factory=list
    )
    netflow_monitor_collection: List[NetflowMonitorModel] = Field(
        alias="netflowMonitorCollection",
        description="List of netflow monitors",
        default_factory=list
    )


class BootstrapSubnetModel(NDNestedModel):
    """
    # Summary

    Bootstrap subnet configuration for fabric initialization.

    ## Raises

    - `ValueError` - If IP addresses or subnet prefix are invalid
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    start_ip: str = Field(alias="startIp", description="Starting IP address of the bootstrap range")
    end_ip: str = Field(alias="endIp", description="Ending IP address of the bootstrap range")
    default_gateway: str = Field(alias="defaultGateway", description="Default gateway for bootstrap subnet")
    subnet_prefix: int = Field(alias="subnetPrefix", description="Subnet prefix length", ge=8, le=30)


class TelemetryFlowCollectionModel(NDNestedModel):
    """
    # Summary

    Telemetry flow collection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    traffic_analytics: str = Field(alias="trafficAnalytics", description="Traffic analytics state", default="enabled")
    traffic_analytics_scope: str = Field(
        alias="trafficAnalyticsScope",
        description="Traffic analytics scope",
        default="intraFabric"
    )
    operating_mode: str = Field(alias="operatingMode", description="Operating mode", default="flowTelemetry")
    udp_categorization: str = Field(alias="udpCategorization", description="UDP categorization", default="enabled")


class TelemetryMicroburstModel(NDNestedModel):
    """
    # Summary

    Microburst detection configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    microburst: bool = Field(description="Enable microburst detection", default=False)
    sensitivity: str = Field(description="Microburst sensitivity level", default="low")


class TelemetryAnalysisSettingsModel(NDNestedModel):
    """
    # Summary

    Telemetry analysis configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    is_enabled: bool = Field(alias="isEnabled", description="Enable telemetry analysis", default=False)


class TelemetryEnergyManagementModel(NDNestedModel):
    """
    # Summary

    Energy management telemetry configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    cost: float = Field(description="Energy cost per unit", default=1.2)


class TelemetryNasExportSettingsModel(NDNestedModel):
    """
    # Summary

    NAS export settings for telemetry.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    export_type: str = Field(alias="exportType", description="Export type", default="full")
    export_format: str = Field(alias="exportFormat", description="Export format", default="json")


class TelemetryNasModel(NDNestedModel):
    """
    # Summary

    NAS (Network Attached Storage) telemetry configuration.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    server: str = Field(description="NAS server address", default="")
    export_settings: TelemetryNasExportSettingsModel = Field(
        alias="exportSettings",
        description="NAS export settings",
        default_factory=TelemetryNasExportSettingsModel
    )


class TelemetrySettingsModel(NDNestedModel):
    """
    # Summary

    Complete telemetry configuration for the fabric.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    flow_collection: TelemetryFlowCollectionModel = Field(
        alias="flowCollection",
        description="Flow collection settings",
        default_factory=TelemetryFlowCollectionModel
    )
    microburst: TelemetryMicroburstModel = Field(
        description="Microburst detection settings",
        default_factory=TelemetryMicroburstModel
    )
    analysis_settings: TelemetryAnalysisSettingsModel = Field(
        alias="analysisSettings",
        description="Analysis settings",
        default_factory=TelemetryAnalysisSettingsModel
    )
    nas: TelemetryNasModel = Field(
        description="NAS telemetry configuration",
        default_factory=TelemetryNasModel
    )
    energy_management: TelemetryEnergyManagementModel = Field(
        alias="energyManagement",
        description="Energy management settings",
        default_factory=TelemetryEnergyManagementModel
    )


class ExternalStreamingSettingsModel(NDNestedModel):
    """
    # Summary

    External streaming configuration for events and data export.

    ## Raises

    None
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    email: List[Dict[str, Any]] = Field(description="Email streaming configuration", default_factory=list)
    message_bus: List[Dict[str, Any]] = Field(alias="messageBus", description="Message bus configuration", default_factory=list)
    syslog: Dict[str, Any] = Field(
        description="Syslog streaming configuration",
        default_factory=lambda: {
            "collectionSettings": {"anomalies": []},
            "facility": "",
            "servers": []
        }
    )
    webhooks: List[Dict[str, Any]] = Field(description="Webhook configuration", default_factory=list)


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

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.EXTERNAL_CONNECTIVITY] = Field(
        description="Fabric management type",
        default=FabricTypeEnum.EXTERNAL_CONNECTIVITY
    )

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
        description=(
            "Allow the same loopback IP address to be configured on multiple"
            " switches (e.g. RP loopback IP)"
        ),
        default=False,
    )

    # Smart Switch
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding",
        description=(
            "Enable onboarding of smart switches to Hypershield"
            " for firewall service"
        ),
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
        description=(
            "Fabric wide CoPP policy. Customized CoPP policy should be"
            " provided when 'manual' is selected."
        ),
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
        description=(
            "DNS Server VRFs. One VRF for all DNS servers or a list of VRFs,"
            " one per DNS server"
        ),
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
        description=(
            "Enable pinning of VRFs and networks to specific DPUs"
            " on smart switches"
        ),
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
        description=(
            "Additional CLIs required during device bootup/login"
            " e.g. AAA/Radius (NX-OS)"
        ),
        default="",
    )
    extra_config_xe_bootstrap: str = Field(
        alias="extraConfigXeBootstrap",
        description=(
            "Additional CLIs required during device bootup/login"
            " e.g. AAA/Radius (IOS-XE)"
        ),
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
        description=(
            "Import switches with reachability over the switch"
            " front-panel ports"
        ),
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
        description=(
            "If enabled, fabric is only monitored."
            " No configuration will be deployed"
        ),
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
        description=(
            "If enabled, switch metrics are collected through periodic SNMP"
            " polling. Alternative to real-time telemetry"
        ),
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
        description=(
            "Multiple Independent PTP Clocking Subdomains"
            " on a Single Network"
        ),
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
        description=(
            "Hourly Fabric Backup only if there is any config deployment"
            " since last backup"
        ),
        default=None,
    )

    # Interface Statistics Collection
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description=(
            "Enable Real Time Interface Statistics Collection."
            " Valid for NX-OS only"
        ),
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
        description=(
            "Time (UTC) in 24 hour format to take a daily backup"
            " if enabled (00:00 to 23:59)"
        ),
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
        description=(
            "Per aggregation dot1q range for VRF-Lite connectivity"
            " (minimum: 2, maximum: 4093)"
        ),
        default="2-511",
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

        ## Description

        Accepts either a plain integer ASN (1-4294967295) or dotted four-byte
        ASN notation in the form ``MMMM.NNNN`` where both parts are in the
        range 1-65535 / 0-65535 respectively.

        ## Raises

        - `ValueError` - If the value does not match the expected ASN format
        """
        if not _BGP_ASN_RE.match(value):
            raise ValueError(
                f"Invalid BGP ASN '{value}'. "
                "Expected a plain integer (1-4294967295) or dotted notation (1-65535.0-65535)."
            )
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
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"  # Allow extra fields from API responses
    )

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Properties
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    name: str = Field(description="Fabric name", min_length=1, max_length=64)
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
        description=(
            "Telemetry Source Interface (VLAN id or Loopback id) only valid"
            " if Telemetry Collection is set to inBand"
        ),
        default="",
    )
    telemetry_source_vrf: str = Field(
        alias="telemetrySourceVrf",
        description=(
            "VRF over which telemetry is streamed, valid only if telemetry"
            " collection is set to inband"
        ),
        default="",
    )
    security_domain: str = Field(
        alias="securityDomain",
        description="Security Domain associated with the fabric",
        default="all",
    )

    # Core Management Configuration
    management: Optional[ExternalConnectivityManagementModel] = Field(
        description="External Connectivity management configuration",
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
    def validate_fabric_consistency(self) -> 'FabricExternalConnectivityModel':
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
            self.management.name = self.name

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
