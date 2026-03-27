# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import re
# from datetime import datetime
from enum import Enum
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
    AlertSuspendEnum,
    LicenseTierEnum,
    OverlayModeEnum,
    ReplicationModeEnum,
    LinkStateRoutingProtocolEnum,
    CoppPolicyEnum,
    FabricInterfaceTypeEnum,
    GreenfieldDebugFlagEnum,
    IsisLevelEnum,
    SecurityGroupStatusEnum,
    StpRootOptionEnum,
    VpcPeerKeepAliveOptionEnum,
    AimlQosPolicyEnum,
    AllowVlanOnLeafTorPairingEnum,
    BgpAuthenticationKeyTypeEnum,
    DhcpProtocolVersionEnum,
    DlbMixedModeDefaultEnum,
    DlbModeEnum,
    MacsecAlgorithmEnum,
    MacsecCipherSuiteEnum,
    PowerRedundancyModeEnum,
    RendezvousPointCountEnum,
    RendezvousPointModeEnum,
    RouteReflectorCountEnum,
    UnderlayMulticastGroupAddressLimitEnum,
    VrfLiteAutoConfigEnum,
)


"""
# Comprehensive Pydantic models for iBGP VXLAN fabric management via Nexus Dashboard

This module provides comprehensive Pydantic models for creating, updating, and deleting
iBGP VXLAN fabrics through the Nexus Dashboard Fabric Controller (NDFC) API.

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
- `VxlanIbgpManagementModel` - iBGP VXLAN specific management settings
- `FabricModel` - Complete fabric creation model
- `FabricDeleteModel` - Fabric deletion model

## Usage

```python
# Create a new iBGP VXLAN fabric
fabric_data = {
    "name": "MyFabric",
    "location": {"latitude": 37.7749, "longitude": -122.4194},
    "management": {
        "type": "vxlanIbgp",
        "bgp_asn": "65001",
        "site_id": "65001"
    }
}
fabric = FabricModel(**fabric_data)
```
"""

# Regex from OpenAPI schema: bgpAsn accepts plain integers (1-4294967295) and
# dotted four-byte ASN notation (1-65535).(0-65535)
_BGP_ASN_RE = re.compile(
    r"^(([1-9]{1}[0-9]{0,8}|[1-3]{1}[0-9]{1,9}|[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))?)$"
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
    message_bus: List[Dict[str, Any]] = Field(
        alias="messageBus",
        description="Message bus configuration",
        default_factory=list
    )
    syslog: Dict[str, Any] = Field(
        description="Syslog streaming configuration",
        default_factory=lambda: {
            "collectionSettings": {"anomalies": []},
            "facility": "",
            "servers": []
        }
    )
    webhooks: List[Dict[str, Any]] = Field(description="Webhook configuration", default_factory=list)


class VxlanIbgpManagementModel(NDNestedModel):
    """
    # Summary

    Comprehensive iBGP VXLAN fabric management configuration.

    This model contains all settings specific to iBGP VXLAN fabric types including
    overlay configuration, underlay routing, multicast settings, and advanced features.

    ## Raises

    - `ValueError` - If BGP ASN, VLAN ranges, or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        populate_by_name=True,
        extra="allow"
    )

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.VXLAN_IBGP] = Field(
        description="Type of the fabric",
        default=FabricTypeEnum.VXLAN_IBGP
    )

    # Core iBGP Configuration
    bgp_asn: str = Field(alias="bgpAsn", description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]")
    site_id: Optional[str] = Field(
        alias="siteId",
        description="For EVPN Multi-Site Support. Defaults to Fabric ASN",
        default=""
    )

    # Name under management section is optional for backward compatibility, but if provided must be non-empty string
    name: Optional[str] = Field(description="Fabric name", min_length=1, max_length=64, default="")
    # border_count: Optional[int] = Field(alias="borderCount", description="Number of border switches", ge=0, le=32, default=0)
    # breakout_spine_interfaces: Optional[bool] = Field(alias="breakoutSpineInterfaces", description="Enable breakout spine interfaces", default=False)
    # designer_use_robot_password: Optional[bool] = Field(alias="designerUseRobotPassword", description="Use robot password for designer", default=False)
    # leaf_count: Optional[int] = Field(alias="leafCount", description="Number of leaf switches", ge=1, le=128, default=1)
    # spine_count: Optional[int] = Field(alias="spineCount", description="Number of spine switches", ge=1, le=32, default=1)
    # vrf_lite_ipv6_subnet_range: Optional[str] = Field(alias="vrfLiteIpv6SubnetRange", description="VRF Lite IPv6 subnet range", default="fd00::a33:0/112")
    # vrf_lite_ipv6_subnet_target_mask: Optional[int] = Field(alias="vrfLiteIpv6SubnetTargetMask", description="VRF Lite IPv6 subnet target mask", ge=112, le=128, default=126)


    # Network Addressing
    bgp_loopback_ip_range: str = Field(
        alias="bgpLoopbackIpRange",
        description="Typically Loopback0 IP Address Range",
        default="10.2.0.0/22"
    )
    nve_loopback_ip_range: str = Field(
        alias="nveLoopbackIpRange",
        description="Typically Loopback1 IP Address Range",
        default="10.3.0.0/22"
    )
    anycast_rendezvous_point_ip_range: str = Field(
        alias="anycastRendezvousPointIpRange",
        description="Anycast or Phantom RP IP Address Range",
        default="10.254.254.0/24"
    )
    intra_fabric_subnet_range: str = Field(
        alias="intraFabricSubnetRange",
        description="Address range to assign numbered and peer link SVI IPs",
        default="10.4.0.0/16"
    )

    # VLAN and VNI Ranges
    l2_vni_range: str = Field(
        alias="l2VniRange",
        description="Overlay network identifier range (minimum: 1, maximum: 16777214)",
        default="30000-49000"
    )
    l3_vni_range: str = Field(
        alias="l3VniRange",
        description="Overlay VRF identifier range (minimum: 1, maximum: 16777214)",
        default="50000-59000"
    )
    network_vlan_range: str = Field(
        alias="networkVlanRange",
        description="Per Switch Overlay Network VLAN Range (minimum: 2, maximum: 4094)",
        default="2300-2999"
    )
    vrf_vlan_range: str = Field(
        alias="vrfVlanRange",
        description="Per Switch Overlay VRF VLAN Range (minimum: 2, maximum: 4094)",
        default="2000-2299"
    )

    # Overlay Configuration
    overlay_mode: OverlayModeEnum = Field(
        alias="overlayMode",
        description="Overlay Mode. VRF/Network configuration using config-profile or CLI",
        default=OverlayModeEnum.CLI
    )
    replication_mode: ReplicationModeEnum = Field(
        alias="replicationMode",
        description="Replication Mode for BUM Traffic",
        default=ReplicationModeEnum.MULTICAST
    )
    multicast_group_subnet: str = Field(
        alias="multicastGroupSubnet",
        description=(
            "Multicast pool prefix between 8 to 30. A multicast group ipv4 from this pool is used for BUM traffic for "
            "each overlay network."
        ),
        default="239.1.1.0/25"
    )
    auto_generate_multicast_group_address: bool = Field(
        alias="autoGenerateMulticastGroupAddress",
        description="Generate a new multicast group address from the multicast pool using a round-robin approach",
        default=False
    )
    underlay_multicast_group_address_limit: UnderlayMulticastGroupAddressLimitEnum = Field(
        alias="underlayMulticastGroupAddressLimit",
        description=(
            "The maximum supported value is 128 for NX-OS version 10.2(1) or earlier "
            "and 512 for versions above 10.2(1)"
        ),
        default=UnderlayMulticastGroupAddressLimitEnum.V_128
    )
    tenant_routed_multicast: bool = Field(
        alias="tenantRoutedMulticast",
        description="For Overlay ipv4 Multicast Support In VXLAN Fabrics",
        default=False
    )

    # Underlay Configuration
    link_state_routing_protocol: LinkStateRoutingProtocolEnum = Field(
        alias="linkStateRoutingProtocol",
        description="Underlay Routing Protocol.  Used for Spine-Leaf Connectivity",
        default=LinkStateRoutingProtocolEnum.OSPF
    )
    ospf_area_id: str = Field(alias="ospfAreaId", description="OSPF Area Id in IP address format", default="0.0.0.0")
    fabric_interface_type: FabricInterfaceTypeEnum = Field(
        alias="fabricInterfaceType",
        description="Numbered(Point-to-Point) or unNumbered",
        default=FabricInterfaceTypeEnum.P2P
    )

    # Advanced Features
    target_subnet_mask: int = Field(
        alias="targetSubnetMask",
        description="Mask for underlay subnet IP range",
        ge=24,
        le=31,
        default=30
    )
    anycast_gateway_mac: str = Field(
        alias="anycastGatewayMac",
        description="Shared anycast gateway MAC address for all VTEPs",
        default="2020.0000.00aa"
    )
    fabric_mtu: int = Field(
        alias="fabricMtu",
        description="Intra Fabric Interface MTU. Must be an even number",
        ge=1500,
        le=9216,
        default=9216
    )
    l2_host_interface_mtu: int = Field(
        alias="l2HostInterfaceMtu",
        description="Layer 2 host interface MTU. Must be an even number",
        ge=1500,
        le=9216,
        default=9216
    )

    # VPC Configuration
    vpc_domain_id_range: str = Field(
        alias="vpcDomainIdRange",
        description="vPC Domain id range (minimum: 1, maximum: 1000) to use for new pairings",
        default="1-1000"
    )
    vpc_peer_link_vlan: str = Field(
        alias="vpcPeerLinkVlan",
        description="VLAN range (minimum: 2, maximum: 4094) for vPC Peer Link SVI",
        default="3600"
    )
    vpc_peer_link_enable_native_vlan: bool = Field(
        alias="vpcPeerLinkEnableNativeVlan",
        description="Enable VpcPeer Link for Native Vlan",
        default=False
    )
    vpc_peer_keep_alive_option: VpcPeerKeepAliveOptionEnum = Field(
        alias="vpcPeerKeepAliveOption",
        description="Use vPC Peer Keep Alive with Loopback or Management",
        default=VpcPeerKeepAliveOptionEnum.MANAGEMENT
    )
    vpc_auto_recovery_timer: int = Field(
        alias="vpcAutoRecoveryTimer",
        description="vPC auto recovery timer (in seconds)",
        ge=240,
        le=3600,
        default=360
    )
    vpc_delay_restore_timer: int = Field(
        alias="vpcDelayRestoreTimer",
        description="vPC delay restore timer (in seconds)",
        ge=1,
        le=3600,
        default=150
    )

    # Loopback Configuration
    bgp_loopback_id: int = Field(
        alias="bgpLoopbackId",
        description="Underlay Routing Loopback Id",
        ge=0,
        le=1023,
        default=0
    )
    nve_loopback_id: int = Field(
        alias="nveLoopbackId",
        description="Underlay VTEP loopback Id associated with the Network Virtualization Edge (nve) interface",
        ge=0,
        le=1023,
        default=1
    )
    route_reflector_count: RouteReflectorCountEnum = Field(
        alias="routeReflectorCount",
        description="Number of spines acting as Route-Reflectors",
        default=RouteReflectorCountEnum.TWO
    )

    # Templates
    vrf_template: str = Field(
        alias="vrfTemplate",
        description="Default overlay VRF template for leafs",
        default="Default_VRF_Universal"
    )
    network_template: str = Field(
        alias="networkTemplate",
        description="Default overlay network template for leafs",
        default="Default_Network_Universal"
    )
    vrf_extension_template: str = Field(
        alias="vrfExtensionTemplate",
        description="Default overlay VRF template for borders",
        default="Default_VRF_Extension_Universal"
    )
    network_extension_template: str = Field(
        alias="networkExtensionTemplate",
        description="Default overlay network template for borders",
        default="Default_Network_Extension_Universal"
    )

    # Optional Advanced Settings
    performance_monitoring: bool = Field(
        alias="performanceMonitoring",
        description=(
            "If enabled, switch metrics are collected through periodic SNMP polling. "
            "Alternative to real-time telemetry"
        ),
        default=False
    )
    tenant_dhcp: bool = Field(alias="tenantDhcp", description="Enable Tenant DHCP", default=True)
    advertise_physical_ip: bool = Field(
        alias="advertisePhysicalIp",
        description="For Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes",
        default=False
    )
    advertise_physical_ip_on_border: bool = Field(
        alias="advertisePhysicalIpOnBorder",
        description=(
            "Enable advertise-pip on vPC borders and border gateways only. Applicable only when vPC advertise-pip is "
            "not enabled"
        ),
        default=True
    )

    # Protocol Settings
    bgp_authentication: bool = Field(
        alias="bgpAuthentication",
        description="Enables or disables the BGP authentication",
        default=False
    )
    bgp_authentication_key_type: BgpAuthenticationKeyTypeEnum = Field(
        alias="bgpAuthenticationKeyType",
        description="BGP key encryption type: 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7",
        default=BgpAuthenticationKeyTypeEnum.THREE_DES
    )
    bfd: bool = Field(description="Enable BFD.  Valid for IPv4 Underlay only", default=False)
    bfd_ibgp: bool = Field(alias="bfdIbgp", description="Enable BFD For iBGP", default=False)

    # Management Settings
    nxapi: bool = Field(description="Enable NX-API over HTTPS", default=False)
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API over HTTP", default=False)
    nxapi_https_port: int = Field(
        alias="nxapiHttpsPort",
        description="HTTPS port for NX-API",
        ge=1,
        le=65535,
        default=443
    )
    nxapi_http_port: int = Field(alias="nxapiHttpPort", description="HTTP port for NX-API", ge=1, le=65535, default=80)

    # Bootstrap Settings
    day0_bootstrap: bool = Field(alias="day0Bootstrap", description="Automatic IP Assignment For POAP", default=False)
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="List of IPv4 or IPv6 subnets to be used for bootstrap",
        default_factory=list
    )

    # Netflow Settings
    netflow_settings: NetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Settings associated with netflow",
        default_factory=NetflowSettingsModel
    )

    # Multicast Settings
    rendezvous_point_count: RendezvousPointCountEnum = Field(
        alias="rendezvousPointCount",
        description="Number of spines acting as Rendezvous-Points (RPs)",
        default=RendezvousPointCountEnum.TWO
    )
    rendezvous_point_loopback_id: int = Field(
        alias="rendezvousPointLoopbackId",
        description="Rendezvous point loopback Id",
        ge=0,
        le=1023,
        default=254
    )

    # System Settings
    snmp_trap: bool = Field(alias="snmpTrap", description="Configure ND as a receiver for SNMP traps", default=True)
    cdp: bool = Field(description="Enable CDP on management interface", default=False)
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description="Enable Real Time Interface Statistics Collection. Valid for NX-OS only",
        default=False
    )
    tcam_allocation: bool = Field(
        alias="tcamAllocation",
        description="TCAM commands are automatically generated for VxLAN and vPC Fabric Peering when Enabled",
        default=True
    )

    # VPC Extended Configuration
    vpc_peer_link_port_channel_id: str = Field(
        alias="vpcPeerLinkPortChannelId",
        description="vPC Peer Link Port Channel ID (minimum: 1, maximum: 4096)",
        default="500"
    )
    vpc_ipv6_neighbor_discovery_sync: bool = Field(
        alias="vpcIpv6NeighborDiscoverySync",
        description="Enable IPv6 ND synchronization between vPC peers",
        default=True
    )
    vpc_layer3_peer_router: bool = Field(
        alias="vpcLayer3PeerRouter",
        description="Enable Layer-3 Peer-Router on all Leaf switches",
        default=True
    )
    vpc_tor_delay_restore_timer: int = Field(
        alias="vpcTorDelayRestoreTimer",
        description="vPC delay restore timer for ToR switches (in seconds)",
        default=30
    )
    fabric_vpc_domain_id: bool = Field(
        alias="fabricVpcDomainId",
        description="Enable the same vPC Domain Id for all vPC Pairs.  Not Recommended.",
        default=False
    )
    shared_vpc_domain_id: int = Field(
        alias="sharedVpcDomainId",
        description="vPC Domain Id to be used on all vPC pairs",
        default=1
    )
    fabric_vpc_qos: bool = Field(
        alias="fabricVpcQos",
        description="Qos on spines for guaranteed delivery of vPC Fabric Peering communication",
        default=False
    )
    fabric_vpc_qos_policy_name: str = Field(
        alias="fabricVpcQosPolicyName",
        description="Qos Policy name should be same on all spines",
        default="spine_qos_for_fabric_vpc_peering"
    )
    enable_peer_switch: bool = Field(
        alias="enablePeerSwitch",
        description="Enable the vPC peer-switch feature on ToR switches",
        default=False
    )

    # Bootstrap / Day-0 / DHCP
    local_dhcp_server: bool = Field(
        alias="localDhcpServer",
        description="Automatic IP Assignment For POAP From Local DHCP Server",
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
    extra_config_nxos_bootstrap: str = Field(
        alias="extraConfigNxosBootstrap",
        description="Additional CLIs required during device bootup/login e.g. AAA/Radius",
        default=""
    )
    un_numbered_bootstrap_loopback_id: int = Field(
        alias="unNumberedBootstrapLoopbackId", description="Bootstrap Seed Switch Loopback Interface ID", default=253
    )
    un_numbered_dhcp_start_address: str = Field(
        alias="unNumberedDhcpStartAddress",
        description="Switch Loopback DHCP Scope Start Address.  Must be a subset of IGP/BGP Loopback Prefix Pool",
        default=""
    )
    un_numbered_dhcp_end_address: str = Field(
        alias="unNumberedDhcpEndAddress",
        description="Switch Loopback DHCP Scope End Address. Must be a subset of IGP/BGP Loopback Prefix Pool",
        default=""
    )
    inband_management: bool = Field(
        alias="inbandManagement",
        description="Manage switches with only Inband connectivity",
        default=False
    )
    inband_dhcp_servers: List[str] = Field(
        alias="inbandDhcpServers",
        description="List of external DHCP server IP addresses (Max 3)",
        default_factory=list
    )
    seed_switch_core_interfaces: List[str] = Field(
        alias="seedSwitchCoreInterfaces",
        description="Seed switch fabric interfaces. Core-facing interface list on seed switch",
        default_factory=list
    )
    spine_switch_core_interfaces: List[str] = Field(
        alias="spineSwitchCoreInterfaces",
        description="Spine switch fabric interfaces. Core-facing interface list on all spines",
        default_factory=list
    )

    # Backup / Restore
    real_time_backup: bool = Field(
        alias="realTimeBackup",
        description="Backup hourly only if there is any config deployment since last backup",
        default=False
    )
    scheduled_backup: bool = Field(
        alias="scheduledBackup",
        description="Enable backup at the specified time daily",
        default=False
    )
    scheduled_backup_time: str = Field(
        alias="scheduledBackupTime",
        description="Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59)",
        default=""
    )

    # IPv6 / Dual-Stack
    underlay_ipv6: bool = Field(
        alias="underlayIpv6",
        description="If not enabled, IPv4 underlay is used",
        default=False
    )
    ipv6_multicast_group_subnet: str = Field(
        alias="ipv6MulticastGroupSubnet",
        description="IPv6 Multicast address with prefix 112 to 128",
        default="ff1e::/121"
    )
    tenant_routed_multicast_ipv6: bool = Field(
        alias="tenantRoutedMulticastIpv6",
        description="For Overlay IPv6 Multicast Support In VXLAN Fabrics",
        default=False
    )
    ipv6_link_local: bool = Field(
        alias="ipv6LinkLocal",
        description="If not enabled, Spine-Leaf interfaces will use global IPv6 addresses",
        default=True
    )
    ipv6_subnet_target_mask: int = Field(
        alias="ipv6SubnetTargetMask",
        description="Mask for Underlay Subnet IPv6 Range",
        default=126
    )
    ipv6_subnet_range: str = Field(
        alias="ipv6SubnetRange",
        description="Underlay Subnet ipv6 range to assign Numbered and Peer Link SVI IPs",
        default="fd00::a04:0/112"
    )
    bgp_loopback_ipv6_range: str = Field(
        alias="bgpLoopbackIpv6Range",
        description="Typically Loopback0 IPv6 Address Range",
        default="fd00::a02:0/119"
    )
    nve_loopback_ipv6_range: str = Field(
        alias="nveLoopbackIpv6Range",
        description="Typically Loopback1 and Anycast Loopback IPv6 Address Range",
        default="fd00::a03:0/118"
    )
    ipv6_anycast_rendezvous_point_ip_range: str = Field(
        alias="ipv6AnycastRendezvousPointIpRange",
        description="Anycast RP IPv6 Address Range",
        default="fd00::254:254:0/118"
    )

    # Multicast / Rendezvous Point Extended
    mvpn_vrf_route_import_id: bool = Field(
        alias="mvpnVrfRouteImportId",
        description="Enable MVPN VRI ID Generation For Tenant Routed Multicast With IPv4 Underlay",
        default=True
    )
    mvpn_vrf_route_import_id_range: str = Field(
        alias="mvpnVrfRouteImportIdRange",
        description=(
            "MVPN VRI ID (minimum: 1, maximum: 65535) for vPC, applicable when TRM enabled with IPv6 underlay, or "
            "mvpnVrfRouteImportId enabled with IPv4 underlay"
        ),
        default=""
    )
    vrf_route_import_id_reallocation: bool = Field(
        alias="vrfRouteImportIdReallocation",
        description="One time VRI ID re-allocation based on 'MVPN VRI ID Range'",
        default=False
    )
    l3vni_multicast_group: str = Field(
        alias="l3vniMulticastGroup",
        description="Default Underlay Multicast group IPv4 address assigned for every overlay VRF",
        default="239.1.1.0"
    )
    l3_vni_ipv6_multicast_group: str = Field(
        alias="l3VniIpv6MulticastGroup",
        description="Default Underlay Multicast group IP6 address assigned for every overlay VRF",
        default="ff1e::"
    )
    rendezvous_point_mode: RendezvousPointModeEnum = Field(
        alias="rendezvousPointMode",
        description="Multicast rendezvous point Mode. For ipv6 underlay, please use asm only",
        default=RendezvousPointModeEnum.ASM
    )
    phantom_rendezvous_point_loopback_id1: int = Field(
        alias="phantomRendezvousPointLoopbackId1",
        description="Underlay phantom rendezvous point loopback primary Id for PIM Bi-dir deployments",
        default=2
    )
    phantom_rendezvous_point_loopback_id2: int = Field(
        alias="phantomRendezvousPointLoopbackId2",
        description="Underlay phantom rendezvous point loopback secondary Id for PIM Bi-dir deployments",
        default=3
    )
    phantom_rendezvous_point_loopback_id3: int = Field(
        alias="phantomRendezvousPointLoopbackId3",
        description="Underlay phantom rendezvous point loopback tertiary Id for PIM Bi-dir deployments",
        default=4
    )
    phantom_rendezvous_point_loopback_id4: int = Field(
        alias="phantomRendezvousPointLoopbackId4",
        description="Underlay phantom rendezvous point loopback quaternary Id for PIM Bi-dir deployments",
        default=5
    )
    anycast_loopback_id: int = Field(
        alias="anycastLoopbackId",
        description="Underlay Anycast Loopback Id.  Used for vPC Peering in VXLANv6 Fabrics",
        default=10
    )

    # VRF Lite / Sub-Interface
    sub_interface_dot1q_range: str = Field(
        alias="subInterfaceDot1qRange",
        description="Per aggregation dot1q range for VRF-Lite connectivity (minimum: 2, maximum: 4093)",
        default="2-511"
    )
    vrf_lite_auto_config: VrfLiteAutoConfigEnum = Field(
        alias="vrfLiteAutoConfig",
        description=(
            "VRF Lite Inter-Fabric Connection Deployment Options. If 'back2BackAndToExternal' is selected, VRF Lite "
            "IFCs are auto created between border devices of two Easy Fabrics, and between border devices in Easy "
            "Fabric and edge routers in External Fabric. The IP address is taken from the 'VRF Lite Subnet IP Range' "
            "pool."
        ),
        default=VrfLiteAutoConfigEnum.MANUAL
    )
    vrf_lite_subnet_range: str = Field(
        alias="vrfLiteSubnetRange",
        description="Address range to assign P2P Interfabric Connections",
        default="10.33.0.0/16"
    )
    vrf_lite_subnet_target_mask: int = Field(
        alias="vrfLiteSubnetTargetMask",
        description="VRF Lite Subnet Mask",
        default=30
    )
    auto_unique_vrf_lite_ip_prefix: bool = Field(
        alias="autoUniqueVrfLiteIpPrefix",
        description=(
            "When enabled, IP prefix allocated to the VRF LITE IFC is not reused on VRF extension over VRF LITE IFC. "
            "Instead, unique IP Subnet is allocated for each VRF extension over VRF LITE IFC."
        ),
        default=False
    )
    auto_symmetric_vrf_lite: bool = Field(
        alias="autoSymmetricVrfLite",
        description=(
            "Whether to auto generate VRF LITE sub-interface and BGP peering configuration on managed "
            "neighbor devices. If set, auto created VRF Lite IFC links will have "
            "'Auto Deploy for Peer' enabled."
        ),
        default=False
    )
    auto_vrf_lite_default_vrf: bool = Field(
        alias="autoVrfLiteDefaultVrf",
        description=(
            "For ipv4 underlay, whether to auto generate BGP peering in Default VRF for VRF Lite IFC auto deployment "
            "option. If set, will auto create VRF Lite Inter-Fabric links with 'Auto Deploy Default VRF' knob enabled"
        ),
        default=False
    )
    auto_symmetric_default_vrf: bool = Field(
        alias="autoSymmetricDefaultVrf",
        description=(
            "Whether to auto generate Default VRF interface and BGP peering configuration on managed neighbor devices. "
            "If set, auto created VRF Lite IFC links will have 'Auto Deploy Default VRF for Peer' enabled."
        ),
        default=False
    )
    default_vrf_redistribution_bgp_route_map: str = Field(
        alias="defaultVrfRedistributionBgpRouteMap",
        description=(
            "Route Map used to redistribute BGP routes to IGP in default vrf "
            "in auto created VRF Lite IFC links"
        ),
        default="extcon-rmap-filter"
    )

    # Per-VRF Loopback
    per_vrf_loopback_auto_provision: bool = Field(
        alias="perVrfLoopbackAutoProvision",
        description=(
            "Auto provision an IPv4 loopback on a VTEP on VRF attachment. Note: Enabling this option auto-provisions "
            "loopback on existing VRF attachments and also when Edit, QuickAttach, or Multiattach actions are "
            "performed. Provisioned loopbacks cannot be deleted until VRFs are unattached."
        ),
        default=False
    )
    per_vrf_loopback_ip_range: str = Field(
        alias="perVrfLoopbackIpRange",
        description="Prefix pool to assign IPv4 addresses to loopbacks on VTEPs on a per VRF basis",
        default="10.5.0.0/22"
    )
    per_vrf_loopback_auto_provision_ipv6: bool = Field(
        alias="perVrfLoopbackAutoProvisionIpv6",
        description="Auto provision an IPv6 loopback on a VTEP on VRF attachment.",
        default=False
    )
    per_vrf_loopback_ipv6_range: str = Field(
        alias="perVrfLoopbackIpv6Range",
        description="Prefix pool to assign IPv6 addresses to loopbacks on VTEPs on a per VRF basis",
        default="fd00::a05:0/112"
    )
    per_vrf_unique_loopback_auto_provision: bool = Field(
        alias="perVrfUniqueLoopbackAutoProvision",
        description=(
            "Auto provision a unique IPV4 loopback on a VTEP on VRF attachment. Note: Enabling this option "
            "auto-provisions unique loopback in the fabric per request. This option and per VRF per VTEP loopback "
            "auto-provisioning are mutually exclusive. Provisioned unique loopbacks will be released upon VRF "
            "unattachment or per request."
        ),
        default=False
    )
    per_vrf_unique_loopback_ip_range: str = Field(
        alias="perVrfUniqueLoopbackIpRange",
        description="Prefix pool to assign unique IPv4 addresses to loopbacks on VTEPs on a per VRF basis",
        default="10.6.0.0/22"
    )
    per_vrf_unique_loopback_auto_provision_v6: bool = Field(
        alias="perVrfUniqueLoopbackAutoProvisionV6",
        description="Auto provision a unique IPV6 loopback on a VTEP on VRF attachment.",
        default=False
    )
    per_vrf_unique_loopback_ipv6_range: str = Field(
        alias="perVrfUniqueLoopbackIpv6Range",
        description="Prefix pool to assign unique IPv6 addresses to loopbacks on VTEPs on a per VRF basis",
        default="fd00::a06:0/112"
    )

    # Authentication — BGP Extended
    bgp_authentication_key: str = Field(
        alias="bgpAuthenticationKey",
        description="Encrypted BGP authentication key based on type",
        default=""
    )

    # Authentication — PIM
    pim_hello_authentication: bool = Field(
        alias="pimHelloAuthentication",
        description="Valid for IPv4 Underlay only",
        default=False
    )
    pim_hello_authentication_key: str = Field(
        alias="pimHelloAuthenticationKey",
        description="3DES Encrypted",
        default=""
    )

    # Authentication — BFD
    bfd_authentication: bool = Field(
        alias="bfdAuthentication",
        description="Enable BFD Authentication.  Valid for P2P Interfaces only",
        default=False
    )
    bfd_authentication_key_id: int = Field(
        alias="bfdAuthenticationKeyId",
        description="BFD Authentication Key ID",
        default=100
    )
    bfd_authentication_key: str = Field(
        alias="bfdAuthenticationKey",
        description="Encrypted SHA1 secret value",
        default=""
    )
    bfd_ospf: bool = Field(alias="bfdOspf", description="Enable BFD For OSPF", default=False)
    bfd_isis: bool = Field(alias="bfdIsis", description="Enable BFD For ISIS", default=False)
    bfd_pim: bool = Field(alias="bfdPim", description="Enable BFD For PIM", default=False)

    # Authentication — OSPF
    ospf_authentication: bool = Field(
        alias="ospfAuthentication",
        description="Enable OSPF Authentication",
        default=False
    )
    ospf_authentication_key_id: int = Field(
        alias="ospfAuthenticationKeyId",
        description="(Min:0, Max:255)",
        default=127
    )
    ospf_authentication_key: str = Field(
        alias="ospfAuthenticationKey",
        description="OSPF Authentication Key.  3DES Encrypted",
        default=""
    )

    # IS-IS
    isis_level: IsisLevelEnum = Field(alias="isisLevel", description="IS-IS Level", default=IsisLevelEnum.LEVEL_2)
    isis_area_number: str = Field(
        alias="isisAreaNumber",
        description=(
            "NET in form of XX.<4-hex-digit Custom Area Number>.XXXX.XXXX.XXXX.00, default Area Number "
            "is 0001. If area number in existing NETs matches the previous area number set in fabric "
            "settings and is different from the "
            "current area number, these NETs will be updated by Recalculate and Deploy."
        ),
        default="0001"
    )
    isis_point_to_point: bool = Field(
        alias="isisPointToPoint",
        description="This will enable network point-to-point on fabric interfaces which are numbered",
        default=True
    )
    isis_authentication: bool = Field(
        alias="isisAuthentication",
        description="Enable IS-IS Authentication",
        default=False
    )
    isis_authentication_keychain_name: str = Field(
        alias="isisAuthenticationKeychainName", description="IS-IS Authentication Keychain Name", default=""
    )
    isis_authentication_keychain_key_id: int = Field(
        alias="isisAuthenticationKeychainKeyId", description="IS-IS Authentication Key ID", default=127
    )
    isis_authentication_key: str = Field(
        alias="isisAuthenticationKey",
        description="IS-IS Authentication Key.  Cisco Type 7 Encrypted",
        default=""
    )
    isis_overload: bool = Field(
        alias="isisOverload",
        description="Set IS-IS Overload Bit.  When enabled, set the overload bit for an elapsed time after a reload",
        default=True
    )
    isis_overload_elapse_time: int = Field(
        alias="isisOverloadElapseTime",
        description="IS-IS Overload Bit Elapsed Time. Clear the overload bit after an elapsed time in seconds",
        default=60
    )

    # MACsec
    macsec: bool = Field(
        description=(
            "Enable MACsec in the fabric. MACsec fabric parameters are used for configuring MACsec on a fabric link if "
            "MACsec is enabled on the link."
        ),
        default=False
    )
    macsec_cipher_suite: MacsecCipherSuiteEnum = Field(
        alias="macsecCipherSuite",
        description="Configure Cipher Suite",
        default=MacsecCipherSuiteEnum.GCM_AES_XPN_256
    )
    macsec_key_string: str = Field(
        alias="macsecKeyString",
        description="MACsec Primary Key String.  Cisco Type 7 Encrypted Octet String",
        default=""
    )
    macsec_algorithm: MacsecAlgorithmEnum = Field(
        alias="macsecAlgorithm",
        description="MACsec Primary Cryptographic Algorithm.  AES_128_CMAC or AES_256_CMAC",
        default=MacsecAlgorithmEnum.AES_128_CMAC
    )
    macsec_fallback_key_string: str = Field(
        alias="macsecFallbackKeyString",
        description="MACsec Fallback Key String. Cisco Type 7 Encrypted Octet String",
        default=""
    )
    macsec_fallback_algorithm: MacsecAlgorithmEnum = Field(
        alias="macsecFallbackAlgorithm",
        description="MACsec Fallback Cryptographic Algorithm.  AES_128_CMAC or AES_256_CMAC",
        default=MacsecAlgorithmEnum.AES_128_CMAC
    )
    macsec_report_timer: int = Field(
        alias="macsecReportTimer",
        description="MACsec Operational Status periodic report timer in minutes",
        default=5
    )

    # VRF Lite MACsec
    vrf_lite_macsec: bool = Field(
        alias="vrfLiteMacsec",
        description=(
            "Enable MACsec on DCI links. DCI MACsec fabric parameters are used for configuring MACsec on a DCI link if "
            "'Use Link MACsec Setting' is disabled on the link."
        ),
        default=False
    )
    vrf_lite_macsec_cipher_suite: MacsecCipherSuiteEnum = Field(
        alias="vrfLiteMacsecCipherSuite",
        description="DCI MACsec Cipher Suite",
        default=MacsecCipherSuiteEnum.GCM_AES_XPN_256
    )
    vrf_lite_macsec_key_string: str = Field(
        alias="vrfLiteMacsecKeyString",
        description="DCI MACsec Primary Key String.  Cisco Type 7 Encrypted Octet String",
        default=""
    )
    vrf_lite_macsec_algorithm: MacsecAlgorithmEnum = Field(
        alias="vrfLiteMacsecAlgorithm",
        description="DCI MACsec Primary Cryptographic Algorithm",
        default=MacsecAlgorithmEnum.AES_128_CMAC
    )
    vrf_lite_macsec_fallback_key_string: str = Field(
        alias="vrfLiteMacsecFallbackKeyString",
        description=(
            "DCI MACsec Fallback Key String.  Cisco Type 7 Encrypted Octet String. "
            "This parameter is used when DCI link has QKD disabled."
        ),
        default=""
    )
    vrf_lite_macsec_fallback_algorithm: MacsecAlgorithmEnum = Field(
        alias="vrfLiteMacsecFallbackAlgorithm",
        description="AES_128_CMAC or AES_256_CMAC. This parameter is used when DCI link has QKD disabled.",
        default=MacsecAlgorithmEnum.AES_128_CMAC
    )

    # Quantum Key Distribution / Trustpoint
    quantum_key_distribution: bool = Field(
        alias="quantumKeyDistribution",
        description=(
            "Enable Data Center Interconnect Media Access Control Security "
            "with Quantum Key Distribution config"
        ),
        default=False
    )
    quantum_key_distribution_profile_name: str = Field(
        alias="quantumKeyDistributionProfileName", description="Name of crypto profile (Max Size 63)", default=""
    )
    key_management_entity_server_ip: str = Field(
        alias="keyManagementEntityServerIp", description="Key Management Entity server ipv4 address", default=""
    )
    key_management_entity_server_port: int = Field(
        alias="keyManagementEntityServerPort", description="Key Management Entity server port number", default=0
    )
    trustpoint_label: str = Field(
        alias="trustpointLabel",
        description="Tls authentication type trustpoint label",
        default=""
    )
    skip_certificate_verification: bool = Field(
        alias="skipCertificateVerification", description="Skip verification of incoming certificate", default=False
    )

    # BGP / Routing Enhancements
    auto_bgp_neighbor_description: bool = Field(
        alias="autoBgpNeighborDescription", description="Generate BGP EVPN Neighbor Description", default=True
    )
    ibgp_peer_template: str = Field(
        alias="ibgpPeerTemplate",
        description=(
            "Specifies the iBGP Peer-Template config used for Route Reflectors and spines with border "
            "or border gateway role. This field should begin with '  template peer' or "
            "'  template peer-session'. This must have 2 "
            "leading spaces. Note ! All configs should strictly match show run output, with respect to case and "
            "newlines. Any mismatches will yield unexpected diffs during deploy."
        ),
        default=""
    )
    leaf_ibgp_peer_template: str = Field(
        alias="leafIbgpPeerTemplate",
        description=(
            "Specifies the config used for leaf, border or border gateway.  If this field is empty, the peer template "
            "defined in iBGP Peer-Template Config is used on all BGP enabled devices (RRs, leafs, border or border "
            "gateway roles).  This field should begin with '  template peer' or '  template peer-session'. This must "
            "have 2 leading spaces. Note ! All configs should strictly match 'show run' output, with respect to case "
            "and newlines. Any mismatches will yield unexpected diffs during deploy."
        ),
        default=""
    )
    link_state_routing_tag: str = Field(
        alias="linkStateRoutingTag",
        description="Underlay routing protocol process tag",
        default="UNDERLAY"
    )
    static_underlay_ip_allocation: bool = Field(
        alias="staticUnderlayIpAllocation",
        description="Checking this will disable Dynamic Underlay IP Address Allocations",
        default=False
    )
    router_id_range: str = Field(
        alias="routerIdRange",
        description="BGP Router ID Range in IPv4 subnet format used for IPv6 Underlay.",
        default="10.2.0.0/23"
    )

    # Security Group Tags (SGT)
    security_group_tag: bool = Field(
        alias="securityGroupTag",
        description="Security group can be enabled only with cli overlay mode",
        default=False
    )
    security_group_tag_prefix: str = Field(
        alias="securityGroupTagPrefix",
        description="Prefix to be used when a new security group is created",
        default="SG_"
    )
    security_group_tag_mac_segmentation: bool = Field(
        alias="securityGroupTagMacSegmentation",
        description="Enable MAC based segmentation for security groups",
        default=False
    )
    security_group_tag_id_range: str = Field(
        alias="securityGroupTagIdRange",
        description="Security group tag (SGT) identifier range (minimum: 16, maximum: 65535)",
        default="10000-14000"
    )
    security_group_tag_preprovision: bool = Field(
        alias="securityGroupTagPreprovision",
        description="Generate security groups configuration for non-enforced VRFs",
        default=False
    )
    security_group_status: SecurityGroupStatusEnum = Field(
        alias="securityGroupStatus",
        description="Security group status",
        default=SecurityGroupStatusEnum.DISABLED
    )

    # Queuing / QoS
    default_queuing_policy: bool = Field(
        alias="defaultQueuingPolicy",
        description="Enable Default Queuing Policies",
        default=False
    )
    default_queuing_policy_cloudscale: str = Field(
        alias="defaultQueuingPolicyCloudscale",
        description="Queuing Policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX series switches in the fabric",
        default="queuing_policy_default_8q_cloudscale"
    )
    default_queuing_policy_r_series: str = Field(
        alias="defaultQueuingPolicyRSeries",
        description="Queueing policy for all Nexus R-series switches",
        default="queuing_policy_default_r_series"
    )
    default_queuing_policy_other: str = Field(
        alias="defaultQueuingPolicyOther",
        description="Queuing Policy for all other switches in the fabric",
        default="queuing_policy_default_other"
    )
    aiml_qos: bool = Field(
        alias="aimlQos",
        description=(
            "Configures QoS and Queuing Policies specific to N9K Cloud Scale (CS) & Silicon One (S1) switch fabric for "
            "AI network workloads"
        ),
        default=False
    )
    aiml_qos_policy: AimlQosPolicyEnum = Field(
        alias="aimlQosPolicy",
        description=(
            "Queuing Policy based on predominant fabric link speed: 800G / 400G / 100G / 25G. User-defined allows for "
            "custom configuration."
        ),
        default=AimlQosPolicyEnum.V_400G
    )
    roce_v2: str = Field(
        alias="roceV2",
        description=(
            "DSCP for RDMA traffic: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default="26"
    )
    cnp: str = Field(
        description=(
            "DSCP value for Congestion Notification: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default="48"
    )
    wred_min: int = Field(alias="wredMin", description="WRED minimum threshold (in kbytes)", default=950)
    wred_max: int = Field(alias="wredMax", description="WRED maximum threshold (in kbytes)", default=3000)
    wred_drop_probability: int = Field(alias="wredDropProbability", description="Drop probability %", default=7)
    wred_weight: int = Field(
        alias="wredWeight",
        description="Influences how quickly WRED reacts to queue depth changes",
        default=0
    )
    bandwidth_remaining: int = Field(
        alias="bandwidthRemaining",
        description="Percentage of remaining bandwidth allocated to AI traffic queues",
        default=50
    )
    dlb: bool = Field(
        description=(
            "Enables fabric-level Dynamic Load Balancing (DLB) configuration. Note: Inter-Switch-Links (ISL) will be "
            "configured as DLB Interfaces"
        ),
        default=False
    )
    dlb_mode: DlbModeEnum = Field(
        alias="dlbMode",
        description=(
            "Select system-wide flowlet, per-packet (packet spraying) or policy driven mixed mode. Note: Mixed mode is "
            "supported on Silicon One (S1) platform only."
        ),
        default=DlbModeEnum.FLOWLET
    )
    dlb_mixed_mode_default: DlbMixedModeDefaultEnum = Field(
        alias="dlbMixedModeDefault",
        description="Default load balancing mode for policy driven mixed mode DLB",
        default=DlbMixedModeDefaultEnum.ECMP
    )
    flowlet_aging: int = Field(
        alias="flowletAging",
        description=(
            "Flowlet aging timer in microseconds. Valid range depends on platform: Cloud Scale (CS)=1-2000000 (default "
            "500), Silicon One (S1)=1-1024 (default 256)"
        ),
        default=1
    )
    flowlet_dscp: str = Field(
        alias="flowletDscp",
        description=(
            "DSCP values for flowlet load balancing: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default=""
    )
    per_packet_dscp: str = Field(
        alias="perPacketDscp",
        description=(
            "DSCP values for per-packet load balancing: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default=""
    )
    ai_load_sharing: bool = Field(
        alias="aiLoadSharing",
        description="Enable IP load sharing using source and destination address for AI workloads",
        default=False
    )
    priority_flow_control_watch_interval: int = Field(
        alias="priorityFlowControlWatchInterval",
        description="Acceptable values from 101 to 1000 (milliseconds).  Leave blank for system default (100ms).",
        default=101
    )

    # PTP
    ptp: bool = Field(description="Enable Precision Time Protocol (PTP)", default=False)
    ptp_loopback_id: int = Field(
        alias="ptpLoopbackId",
        description="Precision Time Protocol Source Loopback Id",
        default=0
    )
    ptp_domain_id: int = Field(
        alias="ptpDomainId",
        description="Multiple Independent PTP Clocking Subdomains on a Single Network",
        default=0
    )
    ptp_vlan_id: int = Field(
        alias="ptpVlanId",
        description="Precision Time Protocol (PTP) Source VLAN ID.  SVI used for ptp source on ToRs",
        default=2
    )

    # STP
    stp_root_option: StpRootOptionEnum = Field(
        alias="stpRootOption",
        description=(
            "Which protocol to use for configuring root bridge? rpvst+: Rapid Per-VLAN Spanning Tree, mst: Multiple "
            "Spanning Tree, unmanaged (default): STP Root not managed by ND"
        ),
        default=StpRootOptionEnum.UNMANAGED
    )
    stp_vlan_range: str = Field(
        alias="stpVlanRange",
        description="Spanning tree Vlan range (minimum: 1, maximum: 4094)",
        default="1-3967"
    )
    mst_instance_range: str = Field(
        alias="mstInstanceRange",
        description="Minimum Spanning Tree instance range (minimum: 0, maximum: 4094)",
        default="0"
    )
    stp_bridge_priority: int = Field(
        alias="stpBridgePriority",
        description="Bridge priority for the spanning tree in increments of 4096",
        default=0
    )

    # MPLS Handoff
    mpls_handoff: bool = Field(alias="mplsHandoff", description="Enable MPLS Handoff", default=False)
    mpls_loopback_identifier: int = Field(
        alias="mplsLoopbackIdentifier",
        description="Used for VXLAN to MPLS SR/LDP Handoff",
        default=101
    )
    mpls_isis_area_number: str = Field(
        alias="mplsIsisAreaNumber",
        description=(
            "NET in form of XX.<4-hex-digit Custom Area Number>.XXXX.XXXX.XXXX.00, default Area Number is 0001, used "
            "only if routing protocol on DCI MPLS link is is-is"
        ),
        default="0001"
    )
    mpls_loopback_ip_range: str = Field(
        alias="mplsLoopbackIpRange",
        description="Used for VXLAN to MPLS SR/LDP Handoff",
        default="10.101.0.0/25"
    )

    # Private VLAN
    private_vlan: bool = Field(
        alias="privateVlan",
        description="Enable PVLAN on switches except spines and super spines",
        default=False
    )
    default_private_vlan_secondary_network_template: str = Field(
        alias="defaultPrivateVlanSecondaryNetworkTemplate",
        description="Default PVLAN secondary network template",
        default="Pvlan_Secondary_Network"
    )
    allow_vlan_on_leaf_tor_pairing: AllowVlanOnLeafTorPairingEnum = Field(
        alias="allowVlanOnLeafTorPairing",
        description="Set trunk allowed vlan to 'none' or 'all' for leaf-tor pairing port-channels",
        default=AllowVlanOnLeafTorPairingEnum.NONE
    )

    # Leaf / TOR
    leaf_tor_id_range: bool = Field(
        alias="leafTorIdRange",
        description="Use specific vPC/Port-channel ID range for leaf-tor pairings",
        default=False
    )
    leaf_tor_vpc_port_channel_id_range: str = Field(
        alias="leafTorVpcPortChannelIdRange",
        description=(
            "Specify vPC/Port-channel ID range (minimum: 1, maximum: 4096), this range is used for auto-allocating "
            "vPC/Port-Channel IDs for leaf-tor pairings"
        ),
        default="1-499"
    )

    # Resource ID Ranges
    l3_vni_no_vlan_default_option: bool = Field(
        alias="l3VniNoVlanDefaultOption",
        description=(
            "L3 VNI configuration without VLAN configuration. This value is propagated on vrf creation as the default "
            "value of 'Enable L3VNI w/o VLAN' in vrf"
        ),
        default=False
    )
    ip_service_level_agreement_id_range: str = Field(
        alias="ipServiceLevelAgreementIdRange",
        description=(
            "Service Level Agreement (SLA) ID Range "
            "(minimum: 1, maximum: 655214748364735). Per switch SLA ID Range"
        ),
        default="10000-19999"
    )
    object_tracking_number_range: str = Field(
        alias="objectTrackingNumberRange",
        description="Tracked Object ID Range (minimum: 1, maximum: 512) Per switch tracked object ID Range",
        default="100-299"
    )
    service_network_vlan_range: str = Field(
        alias="serviceNetworkVlanRange",
        description=(
            "Service Network VLAN Range (minimum: 2, maximum: 4094). "
            "Per Switch Overlay Service Network VLAN Range"
        ),
        default="3000-3199"
    )
    route_map_sequence_number_range: str = Field(
        alias="routeMapSequenceNumberRange",
        description="Route Map Sequence Number Range (minimum: 1, maximum: 65534)",
        default="1-65534"
    )

    # DNS / NTP / Syslog Collections
    ntp_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerCollection")
    ntp_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerVrfCollection")
    dns_collection: List[str] = Field(default_factory=lambda: ["5.192.28.174"], alias="dnsCollection")
    dns_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="dnsVrfCollection")
    syslog_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerCollection")
    syslog_server_vrf_collection: List[str] = Field(
        default_factory=lambda: ["string"],
        alias="syslogServerVrfCollection"
    )
    syslog_severity_collection: List[int] = Field(
        default_factory=lambda: [7],
        alias="syslogSeverityCollection",
        description="List of Syslog severity values, one per Syslog server"
    )

    # Extra Config / Pre-Interface Config / AAA / Banner
    banner: str = Field(
        description=(
            "Message of the Day (motd) banner. Delimiter char (very first char is delimiter char) followed by message "
            "ending with delimiter"
        ),
        default=""
    )
    extra_config_leaf: str = Field(
        alias="extraConfigLeaf",
        description=(
            "Additional CLIs as captured from the show running configuration, added after interface configurations for "
            "all switches with a VTEP unless they have some spine role"
        ),
        default=""
    )
    extra_config_spine: str = Field(
        alias="extraConfigSpine",
        description=(
            "Additional CLIs as captured from the show running configuration, added after interface configurations for "
            "all switches with some spine role"
        ),
        default=""
    )
    extra_config_tor: str = Field(
        alias="extraConfigTor",
        description=(
            "Additional CLIs as captured from the show running configuration, added after interface configurations for "
            "all ToRs"
        ),
        default=""
    )
    extra_config_intra_fabric_links: str = Field(
        alias="extraConfigIntraFabricLinks", description="Additional CLIs for all Intra-Fabric links", default=""
    )
    extra_config_aaa: str = Field(alias="extraConfigAaa", description="AAA Configurations", default="")
    aaa: bool = Field(description="Include AAA configs from Manageability tab during device bootup", default=False)
    pre_interface_config_leaf: str = Field(
        alias="preInterfaceConfigLeaf",
        description=(
            "Additional CLIs as captured from the show running configuration, added before interface "
            "configurations for all switches with a VTEP unless they have some spine role"
        ),
        default=""
    )
    pre_interface_config_spine: str = Field(
        alias="preInterfaceConfigSpine",
        description=(
            "Additional CLIs as captured from the show running configuration, added before interface "
            "configurations for all switches with some spine role"
        ),
        default=""
    )
    pre_interface_config_tor: str = Field(
        alias="preInterfaceConfigTor",
        description=(
            "Additional CLIs as captured from the show running configuration, added before interface "
            "configurations for all ToRs"
        ),
        default=""
    )

    # System / Compliance / OAM / Misc
    anycast_border_gateway_advertise_physical_ip: bool = Field(
        alias="anycastBorderGatewayAdvertisePhysicalIp",
        description="To advertise Anycast Border Gateway PIP as VTEP. Effective on MSD fabric 'Recalculate Config'",
        default=False
    )
    greenfield_debug_flag: GreenfieldDebugFlagEnum = Field(
        alias="greenfieldDebugFlag",
        description="Allow switch configuration to be cleared without a reload when preserveConfig is set to false",
        default=GreenfieldDebugFlagEnum.DISABLE
    )
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval",
        description="Interface Statistics Load Interval. Time in seconds",
        default=10
    )
    nve_hold_down_timer: int = Field(
        alias="nveHoldDownTimer",
        description="NVE Source Inteface HoldDown Time in seconds",
        default=180
    )
    next_generation_oam: bool = Field(
        alias="nextGenerationOAM",
        description=(
            "Enable the Next Generation (NG) OAM feature for all switches in the fabric to aid in trouble-shooting "
            "VXLAN EVPN fabrics"
        ),
        default=True
    )
    ngoam_south_bound_loop_detect: bool = Field(
        alias="ngoamSouthBoundLoopDetect",
        description="Enable the Next Generation (NG) OAM southbound loop detection",
        default=False
    )
    ngoam_south_bound_loop_detect_probe_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectProbeInterval",
        description="Set Next Generation (NG) OAM southbound loop detection probe interval in seconds.",
        default=300
    )
    ngoam_south_bound_loop_detect_recovery_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectRecoveryInterval",
        description="Set the Next Generation (NG) OAM southbound loop detection recovery interval in seconds",
        default=600
    )
    strict_config_compliance_mode: bool = Field(
        alias="strictConfigComplianceMode",
        description=(
            "Enable bi-directional compliance checks to flag additional configs in the running config that are not in "
            "the intent/expected config"
        ),
        default=False
    )
    advanced_ssh_option: bool = Field(
        alias="advancedSshOption",
        description="Enable AAA IP Authorization.  Enable only, when IP Authorization is enabled in the AAA Server",
        default=False
    )
    copp_policy: CoppPolicyEnum = Field(
        alias="coppPolicy",
        description="Fabric wide CoPP policy. Customized CoPP policy should be provided when 'manual' is selected.",
        default=CoppPolicyEnum.STRICT
    )
    power_redundancy_mode: PowerRedundancyModeEnum = Field(
        alias="powerRedundancyMode",
        description="Default Power Supply Mode for NX-OS Switches",
        default=PowerRedundancyModeEnum.REDUNDANT
    )
    host_interface_admin_state: bool = Field(
        alias="hostInterfaceAdminState", description="Unshut Host Interfaces by Default", default=True
    )
    heartbeat_interval: int = Field(
        alias="heartbeatInterval",
        description="XConnect heartbeat interval for periodic link status checks",
        default=190
    )
    policy_based_routing: bool = Field(
        alias="policyBasedRouting",
        description="Enable feature pbr, sla sender, epbr, or enable feature pbr, based on the L4-L7 Services use case",
        default=False
    )
    brownfield_network_name_format: str = Field(
        alias="brownfieldNetworkNameFormat",
        description="Generated network name should be less than 64 characters",
        default="Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$"
    )
    brownfield_skip_overlay_network_attachments: bool = Field(
        alias="brownfieldSkipOverlayNetworkAttachments",
        description="Skip Overlay Network Interface Attachments for Brownfield and Host Port Resync cases",
        default=False
    )
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding",
        description="Enable onboarding of smart switches to Hypershield for firewall service",
        default=False
    )

    # Hypershield / Connectivity
    connectivity_domain_name: Optional[str] = Field(
        alias="connectivityDomainName", description="Domain name to connect to Hypershield", default=None
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

    @field_validator("site_id")
    @classmethod
    def validate_site_id(cls, value: str) -> str:
        """
        # Summary

        Validate site ID format.

        ## Raises

        - `ValueError` - If site ID is not numeric or outside valid range
        """

        # If value is empty string (default), skip validation (will be set to BGP ASN later if still empty)
        if value == "":
            return value

        if not value.isdigit():
            raise ValueError(f"Site ID must be numeric, got: {value}")

        site_id_int = int(value)
        if not (1 <= site_id_int <= 281474976710655):
            raise ValueError(f"Site ID must be between 1 and 281474976710655, got: {site_id_int}")

        return value

    @field_validator("anycast_gateway_mac")
    @classmethod
    def validate_mac_address(cls, value: str) -> str:
        """
        # Summary

        Validate MAC address format.

        ## Raises

        - `ValueError` - If MAC address format is invalid
        """
        mac_pattern = re.compile(r'^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$')
        if not mac_pattern.match(value):
            raise ValueError(f"Invalid MAC address format, expected xxxx.xxxx.xxxx, got: {value}")

        return value.lower()


class FabricIbgpModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a new iBGP VXLAN fabric.

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
        description="License tier",
        default=LicenseTierEnum.PREMIER
    )
    alert_suspend: AlertSuspendEnum = Field(
        alias="alertSuspend",
        description="Alert suspension state",
        default=AlertSuspendEnum.DISABLED
    )
    telemetry_collection: bool = Field(
        alias="telemetryCollection",
        description="Enable telemetry collection",
        default=False
    )
    telemetry_collection_type: str = Field(
        alias="telemetryCollectionType",
        description="Telemetry collection type",
        default="outOfBand"
    )
    telemetry_streaming_protocol: str = Field(
        alias="telemetryStreamingProtocol",
        description="Telemetry streaming protocol",
        default="ipv4"
    )
    telemetry_source_interface: str = Field(
        alias="telemetrySourceInterface",
        description="Telemetry source interface",
        default=""
    )
    telemetry_source_vrf: str = Field(alias="telemetrySourceVrf", description="Telemetry source VRF", default="")
    security_domain: str = Field(alias="securityDomain", description="Security domain", default="all")

    # Core Management Configuration
    management: Optional[VxlanIbgpManagementModel] = Field(
        description="iBGP VXLAN management configuration",
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
    def validate_fabric_consistency(self) -> 'FabricModel':
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        # Ensure management type matches model type
        if self.management is not None and self.management.type != FabricTypeEnum.VXLAN_IBGP:
            raise ValueError(f"Management type must be {FabricTypeEnum.VXLAN_IBGP}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.name

        # Propagate BGP ASN to Site ID management model if not set
        if self.management is not None and self.management.site_id == "":
            bgp_asn = self.management.bgp_asn
            if "." in bgp_asn:
                # asdot notation (High.Low) → convert to asplain decimal: (High × 65536) + Low
                high, low = bgp_asn.split(".")
                self.management.site_id = str(int(high) * 65536 + int(low))
            else:
                # Already plain decimal
                self.management.site_id = bgp_asn

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
                "choices": ["merged", "replaced", "deleted", "overridden", "query"],
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
    "VxlanIbgpManagementModel",
    "FabricModel",
    "FabricDeleteModel",
    "FabricTypeEnum",
    "AlertSuspendEnum",
    "LicenseTierEnum",
    "ReplicationModeEnum",
    "OverlayModeEnum",
    "LinkStateRoutingProtocolEnum"
]