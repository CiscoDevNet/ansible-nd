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
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_fabric.enums import (
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
    type: Literal[FabricTypeEnum.VXLAN_IBGP] = Field(description="Fabric management type", default=FabricTypeEnum.VXLAN_IBGP)

    # Core iBGP Configuration
    bgp_asn: str = Field(alias="bgpAsn", description="BGP Autonomous System Number 1-4294967295 | 1-65535[.0-65535]")
    site_id: Optional[str] = Field(alias="siteId", description="Site identifier for the fabric", default="")

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
        description="BGP loopback IP range",
        default="10.2.0.0/22"
    )
    nve_loopback_ip_range: str = Field(
        alias="nveLoopbackIpRange",
        description="NVE loopback IP range",
        default="10.3.0.0/22"
    )
    anycast_rendezvous_point_ip_range: str = Field(
        alias="anycastRendezvousPointIpRange",
        description="Anycast RP IP range",
        default="10.254.254.0/24"
    )
    intra_fabric_subnet_range: str = Field(
        alias="intraFabricSubnetRange",
        description="Intra-fabric subnet range",
        default="10.4.0.0/16"
    )

    # VLAN and VNI Ranges
    l2_vni_range: str = Field(alias="l2VniRange", description="Layer 2 VNI range", default="30000-49000")
    l3_vni_range: str = Field(alias="l3VniRange", description="Layer 3 VNI range", default="50000-59000")
    network_vlan_range: str = Field(alias="networkVlanRange", description="Network VLAN range", default="2300-2999")
    vrf_vlan_range: str = Field(alias="vrfVlanRange", description="VRF VLAN range", default="2000-2299")

    # Overlay Configuration
    overlay_mode: OverlayModeEnum = Field(alias="overlayMode", description="Overlay configuration mode", default=OverlayModeEnum.CLI)
    replication_mode: ReplicationModeEnum = Field(
        alias="replicationMode",
        description="Multicast replication mode",
        default=ReplicationModeEnum.MULTICAST
    )
    multicast_group_subnet: str = Field(
        alias="multicastGroupSubnet",
        description="Multicast group subnet",
        default="239.1.1.0/25"
    )
    auto_generate_multicast_group_address: bool = Field(
        alias="autoGenerateMulticastGroupAddress",
        description="Auto-generate multicast group addresses",
        default=False
    )
    underlay_multicast_group_address_limit: int = Field(
        alias="underlayMulticastGroupAddressLimit",
        description="Underlay multicast group address limit",
        ge=1,
        le=255,
        default=128
    )
    tenant_routed_multicast: bool = Field(
        alias="tenantRoutedMulticast",
        description="Enable tenant routed multicast",
        default=False
    )

    # Underlay Configuration
    link_state_routing_protocol: LinkStateRoutingProtocolEnum = Field(
        alias="linkStateRoutingProtocol",
        description="Underlay routing protocol",
        default=LinkStateRoutingProtocolEnum.OSPF
    )
    ospf_area_id: str = Field(alias="ospfAreaId", description="OSPF area ID", default="0.0.0.0")
    fabric_interface_type: FabricInterfaceTypeEnum = Field(alias="fabricInterfaceType", description="Fabric interface type", default=FabricInterfaceTypeEnum.P2P)

    # Advanced Features
    target_subnet_mask: int = Field(alias="targetSubnetMask", description="Target subnet mask", ge=24, le=31, default=30)
    anycast_gateway_mac: str = Field(
        alias="anycastGatewayMac",
        description="Anycast gateway MAC address",
        default="2020.0000.00aa"
    )
    fabric_mtu: int = Field(alias="fabricMtu", description="Fabric MTU size", ge=1500, le=9216, default=9216)
    l2_host_interface_mtu: int = Field(
        alias="l2HostInterfaceMtu",
        description="L2 host interface MTU",
        ge=1500,
        le=9216,
        default=9216
    )

    # VPC Configuration
    vpc_domain_id_range: str = Field(alias="vpcDomainIdRange", description="vPC domain ID range", default="1-1000")
    vpc_peer_link_vlan: str = Field(alias="vpcPeerLinkVlan", description="vPC peer link VLAN", default="3600")
    vpc_peer_link_enable_native_vlan: bool = Field(
        alias="vpcPeerLinkEnableNativeVlan",
        description="Enable native VLAN on vPC peer link",
        default=False
    )
    vpc_peer_keep_alive_option: VpcPeerKeepAliveOptionEnum = Field(
        alias="vpcPeerKeepAliveOption",
        description="vPC peer keep-alive option",
        default=VpcPeerKeepAliveOptionEnum.MANAGEMENT
    )
    vpc_auto_recovery_timer: int = Field(
        alias="vpcAutoRecoveryTimer",
        description="vPC auto recovery timer",
        ge=240,
        le=3600,
        default=360
    )
    vpc_delay_restore_timer: int = Field(
        alias="vpcDelayRestoreTimer",
        description="vPC delay restore timer",
        ge=1,
        le=3600,
        default=150
    )

    # Loopback Configuration
    bgp_loopback_id: int = Field(alias="bgpLoopbackId", description="BGP loopback interface ID", ge=0, le=1023, default=0)
    nve_loopback_id: int = Field(alias="nveLoopbackId", description="NVE loopback interface ID", ge=0, le=1023, default=1)
    route_reflector_count: int = Field(
        alias="routeReflectorCount",
        description="Number of route reflectors",
        ge=1,
        le=4,
        default=2
    )

    # Templates
    vrf_template: str = Field(alias="vrfTemplate", description="VRF template", default="Default_VRF_Universal")
    network_template: str = Field(alias="networkTemplate", description="Network template", default="Default_Network_Universal")
    vrf_extension_template: str = Field(
        alias="vrfExtensionTemplate",
        description="VRF extension template",
        default="Default_VRF_Extension_Universal"
    )
    network_extension_template: str = Field(
        alias="networkExtensionTemplate",
        description="Network extension template",
        default="Default_Network_Extension_Universal"
    )

    # Optional Advanced Settings
    performance_monitoring: bool = Field(alias="performanceMonitoring", description="Enable performance monitoring", default=False)
    tenant_dhcp: bool = Field(alias="tenantDhcp", description="Enable tenant DHCP", default=True)
    advertise_physical_ip: bool = Field(alias="advertisePhysicalIp", description="Advertise physical IP", default=False)
    advertise_physical_ip_on_border: bool = Field(
        alias="advertisePhysicalIpOnBorder",
        description="Advertise physical IP on border",
        default=True
    )

    # Protocol Settings
    bgp_authentication: bool = Field(alias="bgpAuthentication", description="Enable BGP authentication", default=False)
    bgp_authentication_key_type: str = Field(
        alias="bgpAuthenticationKeyType",
        description="BGP authentication key type",
        default="3des"
    )
    bfd: bool = Field(description="Enable BFD", default=False)
    bfd_ibgp: bool = Field(alias="bfdIbgp", description="Enable BFD for iBGP", default=False)

    # Management Settings
    nxapi: bool = Field(description="Enable NX-API", default=False)
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API HTTP", default=False)
    nxapi_https_port: int = Field(alias="nxapiHttpsPort", description="NX-API HTTPS port", ge=1, le=65535, default=443)
    nxapi_http_port: int = Field(alias="nxapiHttpPort", description="NX-API HTTP port", ge=1, le=65535, default=80)

    # Bootstrap Settings
    day0_bootstrap: bool = Field(alias="day0Bootstrap", description="Enable day-0 bootstrap", default=False)
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="Bootstrap subnet collection",
        default_factory=list
    )

    # Netflow Settings
    netflow_settings: NetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Netflow configuration",
        default_factory=NetflowSettingsModel
    )

    # Multicast Settings
    rendezvous_point_count: int = Field(
        alias="rendezvousPointCount",
        description="Number of rendezvous points",
        ge=1,
        le=4,
        default=2
    )
    rendezvous_point_loopback_id: int = Field(
        alias="rendezvousPointLoopbackId",
        description="RP loopback interface ID",
        ge=0,
        le=1023,
        default=254
    )

    # System Settings
    snmp_trap: bool = Field(alias="snmpTrap", description="Enable SNMP traps", default=True)
    cdp: bool = Field(description="Enable CDP", default=False)
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description="Enable real-time interface statistics",
        default=False
    )
    tcam_allocation: bool = Field(alias="tcamAllocation", description="Enable TCAM allocation", default=True)

    # VPC Extended Configuration
    vpc_peer_link_port_channel_id: str = Field(alias="vpcPeerLinkPortChannelId", description="vPC peer link port-channel ID", default="500")
    vpc_ipv6_neighbor_discovery_sync: bool = Field(
        alias="vpcIpv6NeighborDiscoverySync", description="Enable vPC IPv6 ND sync", default=True
    )
    vpc_layer3_peer_router: bool = Field(alias="vpcLayer3PeerRouter", description="Enable vPC layer-3 peer router", default=True)
    vpc_tor_delay_restore_timer: int = Field(alias="vpcTorDelayRestoreTimer", description="vPC TOR delay restore timer", default=30)
    fabric_vpc_domain_id: bool = Field(alias="fabricVpcDomainId", description="Enable fabric vPC domain ID", default=False)
    shared_vpc_domain_id: int = Field(alias="sharedVpcDomainId", description="Shared vPC domain ID", default=1)
    fabric_vpc_qos: bool = Field(alias="fabricVpcQos", description="Enable fabric vPC QoS", default=False)
    fabric_vpc_qos_policy_name: str = Field(
        alias="fabricVpcQosPolicyName", description="Fabric vPC QoS policy name", default="spine_qos_for_fabric_vpc_peering"
    )
    enable_peer_switch: bool = Field(alias="enablePeerSwitch", description="Enable peer switch", default=False)

    # Bootstrap / Day-0 / DHCP
    local_dhcp_server: bool = Field(alias="localDhcpServer", description="Enable local DHCP server", default=False)
    dhcp_protocol_version: str = Field(alias="dhcpProtocolVersion", description="DHCP protocol version", default="dhcpv4")
    dhcp_start_address: str = Field(alias="dhcpStartAddress", description="DHCP start address", default="")
    dhcp_end_address: str = Field(alias="dhcpEndAddress", description="DHCP end address", default="")
    management_gateway: str = Field(alias="managementGateway", description="Management gateway", default="")
    management_ipv4_prefix: int = Field(alias="managementIpv4Prefix", description="Management IPv4 prefix length", default=24)
    management_ipv6_prefix: int = Field(alias="managementIpv6Prefix", description="Management IPv6 prefix length", default=64)
    extra_config_nxos_bootstrap: str = Field(alias="extraConfigNxosBootstrap", description="Extra NX-OS bootstrap config", default="")
    un_numbered_bootstrap_loopback_id: int = Field(
        alias="unNumberedBootstrapLoopbackId", description="Unnumbered bootstrap loopback ID", default=253
    )
    un_numbered_dhcp_start_address: str = Field(alias="unNumberedDhcpStartAddress", description="Unnumbered DHCP start address", default="")
    un_numbered_dhcp_end_address: str = Field(alias="unNumberedDhcpEndAddress", description="Unnumbered DHCP end address", default="")
    inband_management: bool = Field(alias="inbandManagement", description="Enable in-band management", default=False)
    inband_dhcp_servers: List[str] = Field(alias="inbandDhcpServers", description="In-band DHCP servers", default_factory=list)
    seed_switch_core_interfaces: List[str] = Field(
        alias="seedSwitchCoreInterfaces", description="Seed switch core interfaces", default_factory=list
    )
    spine_switch_core_interfaces: List[str] = Field(
        alias="spineSwitchCoreInterfaces", description="Spine switch core interfaces", default_factory=list
    )

    # Backup / Restore
    real_time_backup: bool = Field(alias="realTimeBackup", description="Enable real-time backup", default=False)
    scheduled_backup: bool = Field(alias="scheduledBackup", description="Enable scheduled backup", default=False)
    scheduled_backup_time: str = Field(alias="scheduledBackupTime", description="Scheduled backup time", default="")

    # IPv6 / Dual-Stack
    underlay_ipv6: bool = Field(alias="underlayIpv6", description="Enable IPv6 underlay", default=False)
    ipv6_multicast_group_subnet: str = Field(
        alias="ipv6MulticastGroupSubnet", description="IPv6 multicast group subnet", default="ff1e::/121"
    )
    tenant_routed_multicast_ipv6: bool = Field(
        alias="tenantRoutedMulticastIpv6", description="Enable tenant routed multicast IPv6", default=False
    )
    ipv6_link_local: bool = Field(alias="ipv6LinkLocal", description="Enable IPv6 link-local", default=True)
    ipv6_subnet_target_mask: int = Field(alias="ipv6SubnetTargetMask", description="IPv6 subnet target mask", default=126)
    ipv6_subnet_range: str = Field(alias="ipv6SubnetRange", description="IPv6 subnet range", default="fd00::a04:0/112")
    bgp_loopback_ipv6_range: str = Field(alias="bgpLoopbackIpv6Range", description="BGP loopback IPv6 range", default="fd00::a02:0/119")
    nve_loopback_ipv6_range: str = Field(alias="nveLoopbackIpv6Range", description="NVE loopback IPv6 range", default="fd00::a03:0/118")
    ipv6_anycast_rendezvous_point_ip_range: str = Field(
        alias="ipv6AnycastRendezvousPointIpRange", description="IPv6 anycast RP IP range", default="fd00::254:254:0/118"
    )

    # Multicast / Rendezvous Point Extended
    mvpn_vrf_route_import_id: bool = Field(alias="mvpnVrfRouteImportId", description="Enable MVPN VRF route import ID", default=True)
    mvpn_vrf_route_import_id_range: str = Field(
        alias="mvpnVrfRouteImportIdRange", description="MVPN VRF route import ID range", default=""
    )
    vrf_route_import_id_reallocation: bool = Field(
        alias="vrfRouteImportIdReallocation", description="Enable VRF route import ID reallocation", default=False
    )
    l3vni_multicast_group: str = Field(alias="l3vniMulticastGroup", description="L3 VNI multicast group", default="239.1.1.0")
    l3_vni_ipv6_multicast_group: str = Field(alias="l3VniIpv6MulticastGroup", description="L3 VNI IPv6 multicast group", default="ff1e::")
    rendezvous_point_mode: str = Field(alias="rendezvousPointMode", description="Rendezvous point mode", default="asm")
    phantom_rendezvous_point_loopback_id1: int = Field(
        alias="phantomRendezvousPointLoopbackId1", description="Phantom RP loopback ID 1", default=2
    )
    phantom_rendezvous_point_loopback_id2: int = Field(
        alias="phantomRendezvousPointLoopbackId2", description="Phantom RP loopback ID 2", default=3
    )
    phantom_rendezvous_point_loopback_id3: int = Field(
        alias="phantomRendezvousPointLoopbackId3", description="Phantom RP loopback ID 3", default=4
    )
    phantom_rendezvous_point_loopback_id4: int = Field(
        alias="phantomRendezvousPointLoopbackId4", description="Phantom RP loopback ID 4", default=5
    )
    anycast_loopback_id: int = Field(alias="anycastLoopbackId", description="Anycast loopback ID", default=10)

    # VRF Lite / Sub-Interface
    sub_interface_dot1q_range: str = Field(alias="subInterfaceDot1qRange", description="Sub-interface 802.1q range", default="2-511")
    vrf_lite_auto_config: str = Field(alias="vrfLiteAutoConfig", description="VRF lite auto-config mode", default="manual")
    vrf_lite_subnet_range: str = Field(alias="vrfLiteSubnetRange", description="VRF lite subnet range", default="10.33.0.0/16")
    vrf_lite_subnet_target_mask: int = Field(alias="vrfLiteSubnetTargetMask", description="VRF lite subnet target mask", default=30)
    auto_unique_vrf_lite_ip_prefix: bool = Field(
        alias="autoUniqueVrfLiteIpPrefix", description="Auto unique VRF lite IP prefix", default=False
    )
    auto_symmetric_vrf_lite: bool = Field(alias="autoSymmetricVrfLite", description="Auto symmetric VRF lite", default=False)
    auto_vrf_lite_default_vrf: bool = Field(alias="autoVrfLiteDefaultVrf", description="Auto VRF lite default VRF", default=False)
    auto_symmetric_default_vrf: bool = Field(alias="autoSymmetricDefaultVrf", description="Auto symmetric default VRF", default=False)
    default_vrf_redistribution_bgp_route_map: str = Field(
        alias="defaultVrfRedistributionBgpRouteMap", description="Default VRF redistribution BGP route map", default="extcon-rmap-filter"
    )

    # Per-VRF Loopback
    per_vrf_loopback_auto_provision: bool = Field(
        alias="perVrfLoopbackAutoProvision", description="Per-VRF loopback auto-provision", default=False
    )
    per_vrf_loopback_ip_range: str = Field(
        alias="perVrfLoopbackIpRange", description="Per-VRF loopback IP range", default="10.5.0.0/22"
    )
    per_vrf_loopback_auto_provision_ipv6: bool = Field(
        alias="perVrfLoopbackAutoProvisionIpv6", description="Per-VRF loopback auto-provision IPv6", default=False
    )
    per_vrf_loopback_ipv6_range: str = Field(
        alias="perVrfLoopbackIpv6Range", description="Per-VRF loopback IPv6 range", default="fd00::a05:0/112"
    )
    per_vrf_unique_loopback_auto_provision: bool = Field(
        alias="perVrfUniqueLoopbackAutoProvision", description="Per-VRF unique loopback auto-provision", default=False
    )
    per_vrf_unique_loopback_ip_range: str = Field(
        alias="perVrfUniqueLoopbackIpRange", description="Per-VRF unique loopback IP range", default="10.6.0.0/22"
    )
    per_vrf_unique_loopback_auto_provision_v6: bool = Field(
        alias="perVrfUniqueLoopbackAutoProvisionV6", description="Per-VRF unique loopback auto-provision IPv6", default=False
    )
    per_vrf_unique_loopback_ipv6_range: str = Field(
        alias="perVrfUniqueLoopbackIpv6Range", description="Per-VRF unique loopback IPv6 range", default="fd00::a06:0/112"
    )

    # Authentication — BGP Extended
    bgp_authentication_key: str = Field(alias="bgpAuthenticationKey", description="BGP authentication key", default="")

    # Authentication — PIM
    pim_hello_authentication: bool = Field(alias="pimHelloAuthentication", description="Enable PIM hello authentication", default=False)
    pim_hello_authentication_key: str = Field(alias="pimHelloAuthenticationKey", description="PIM hello authentication key", default="")

    # Authentication — BFD
    bfd_authentication: bool = Field(alias="bfdAuthentication", description="Enable BFD authentication", default=False)
    bfd_authentication_key_id: int = Field(alias="bfdAuthenticationKeyId", description="BFD authentication key ID", default=100)
    bfd_authentication_key: str = Field(alias="bfdAuthenticationKey", description="BFD authentication key", default="")
    bfd_ospf: bool = Field(alias="bfdOspf", description="Enable BFD for OSPF", default=False)
    bfd_isis: bool = Field(alias="bfdIsis", description="Enable BFD for IS-IS", default=False)
    bfd_pim: bool = Field(alias="bfdPim", description="Enable BFD for PIM", default=False)

    # Authentication — OSPF
    ospf_authentication: bool = Field(alias="ospfAuthentication", description="Enable OSPF authentication", default=False)
    ospf_authentication_key_id: int = Field(alias="ospfAuthenticationKeyId", description="OSPF authentication key ID", default=127)
    ospf_authentication_key: str = Field(alias="ospfAuthenticationKey", description="OSPF authentication key", default="")

    # IS-IS
    isis_level: IsisLevelEnum = Field(alias="isisLevel", description="IS-IS level", default=IsisLevelEnum.LEVEL_2)
    isis_area_number: str = Field(alias="isisAreaNumber", description="IS-IS area number", default="0001")
    isis_point_to_point: bool = Field(alias="isisPointToPoint", description="IS-IS point-to-point", default=True)
    isis_authentication: bool = Field(alias="isisAuthentication", description="Enable IS-IS authentication", default=False)
    isis_authentication_keychain_name: str = Field(
        alias="isisAuthenticationKeychainName", description="IS-IS authentication keychain name", default=""
    )
    isis_authentication_keychain_key_id: int = Field(
        alias="isisAuthenticationKeychainKeyId", description="IS-IS authentication keychain key ID", default=127
    )
    isis_authentication_key: str = Field(alias="isisAuthenticationKey", description="IS-IS authentication key", default="")
    isis_overload: bool = Field(alias="isisOverload", description="Enable IS-IS overload bit", default=True)
    isis_overload_elapse_time: int = Field(alias="isisOverloadElapseTime", description="IS-IS overload elapse time", default=60)

    # MACsec
    macsec: bool = Field(description="Enable MACsec", default=False)
    macsec_cipher_suite: str = Field(alias="macsecCipherSuite", description="MACsec cipher suite", default="GCM-AES-XPN-256")
    macsec_key_string: str = Field(alias="macsecKeyString", description="MACsec key string", default="")
    macsec_algorithm: str = Field(alias="macsecAlgorithm", description="MACsec algorithm", default="AES_128_CMAC")
    macsec_fallback_key_string: str = Field(alias="macsecFallbackKeyString", description="MACsec fallback key string", default="")
    macsec_fallback_algorithm: str = Field(alias="macsecFallbackAlgorithm", description="MACsec fallback algorithm", default="AES_128_CMAC")
    macsec_report_timer: int = Field(alias="macsecReportTimer", description="MACsec report timer", default=5)

    # VRF Lite MACsec
    vrf_lite_macsec: bool = Field(alias="vrfLiteMacsec", description="Enable VRF lite MACsec", default=False)
    vrf_lite_macsec_cipher_suite: str = Field(
        alias="vrfLiteMacsecCipherSuite", description="VRF lite MACsec cipher suite", default="GCM-AES-XPN-256"
    )
    vrf_lite_macsec_key_string: str = Field(alias="vrfLiteMacsecKeyString", description="VRF lite MACsec key string", default="")
    vrf_lite_macsec_algorithm: str = Field(
        alias="vrfLiteMacsecAlgorithm", description="VRF lite MACsec algorithm", default="AES_128_CMAC"
    )
    vrf_lite_macsec_fallback_key_string: str = Field(
        alias="vrfLiteMacsecFallbackKeyString", description="VRF lite MACsec fallback key string", default=""
    )
    vrf_lite_macsec_fallback_algorithm: str = Field(
        alias="vrfLiteMacsecFallbackAlgorithm", description="VRF lite MACsec fallback algorithm", default="AES_128_CMAC"
    )

    # Quantum Key Distribution / Trustpoint
    quantum_key_distribution: bool = Field(alias="quantumKeyDistribution", description="Enable quantum key distribution", default=False)
    quantum_key_distribution_profile_name: str = Field(
        alias="quantumKeyDistributionProfileName", description="Quantum key distribution profile name", default=""
    )
    key_management_entity_server_ip: str = Field(
        alias="keyManagementEntityServerIp", description="Key management entity server IP", default=""
    )
    key_management_entity_server_port: int = Field(
        alias="keyManagementEntityServerPort", description="Key management entity server port", default=0
    )
    trustpoint_label: str = Field(alias="trustpointLabel", description="Trustpoint label", default="")
    skip_certificate_verification: bool = Field(
        alias="skipCertificateVerification", description="Skip certificate verification", default=False
    )

    # BGP / Routing Enhancements
    auto_bgp_neighbor_description: bool = Field(
        alias="autoBgpNeighborDescription", description="Auto BGP neighbor description", default=True
    )
    ibgp_peer_template: str = Field(alias="ibgpPeerTemplate", description="iBGP peer template", default="")
    leaf_ibgp_peer_template: str = Field(alias="leafIbgpPeerTemplate", description="Leaf iBGP peer template", default="")
    link_state_routing_tag: str = Field(alias="linkStateRoutingTag", description="Link state routing tag", default="UNDERLAY")
    static_underlay_ip_allocation: bool = Field(
        alias="staticUnderlayIpAllocation", description="Static underlay IP allocation", default=False
    )
    router_id_range: str = Field(alias="routerIdRange", description="Router ID range", default="10.2.0.0/23")

    # Security Group Tags (SGT)
    security_group_tag: bool = Field(alias="securityGroupTag", description="Enable security group tag", default=False)
    security_group_tag_prefix: str = Field(alias="securityGroupTagPrefix", description="SGT prefix", default="SG_")
    security_group_tag_mac_segmentation: bool = Field(
        alias="securityGroupTagMacSegmentation", description="Enable SGT MAC segmentation", default=False
    )
    security_group_tag_id_range: str = Field(
        alias="securityGroupTagIdRange", description="SGT ID range", default="10000-14000"
    )
    security_group_tag_preprovision: bool = Field(
        alias="securityGroupTagPreprovision", description="Enable SGT preprovision", default=False
    )
    security_group_status: SecurityGroupStatusEnum = Field(alias="securityGroupStatus", description="Security group status", default=SecurityGroupStatusEnum.DISABLED)

    # Queuing / QoS
    default_queuing_policy: bool = Field(alias="defaultQueuingPolicy", description="Enable default queuing policy", default=False)
    default_queuing_policy_cloudscale: str = Field(
        alias="defaultQueuingPolicyCloudscale", description="Default queuing policy cloudscale", default="queuing_policy_default_8q_cloudscale"
    )
    default_queuing_policy_r_series: str = Field(
        alias="defaultQueuingPolicyRSeries", description="Default queuing policy R-Series", default="queuing_policy_default_r_series"
    )
    default_queuing_policy_other: str = Field(
        alias="defaultQueuingPolicyOther", description="Default queuing policy other", default="queuing_policy_default_other"
    )
    aiml_qos: bool = Field(alias="aimlQos", description="Enable AI/ML QoS", default=False)
    aiml_qos_policy: str = Field(alias="aimlQosPolicy", description="AI/ML QoS policy", default="400G")
    roce_v2: str = Field(alias="roceV2", description="RoCEv2 DSCP value", default="26")
    cnp: str = Field(description="CNP value", default="48")
    wred_min: int = Field(alias="wredMin", description="WRED minimum threshold", default=950)
    wred_max: int = Field(alias="wredMax", description="WRED maximum threshold", default=3000)
    wred_drop_probability: int = Field(alias="wredDropProbability", description="WRED drop probability", default=7)
    wred_weight: int = Field(alias="wredWeight", description="WRED weight", default=0)
    bandwidth_remaining: int = Field(alias="bandwidthRemaining", description="Bandwidth remaining percentage", default=50)
    dlb: bool = Field(description="Enable dynamic load balancing", default=False)
    dlb_mode: str = Field(alias="dlbMode", description="DLB mode", default="flowlet")
    dlb_mixed_mode_default: str = Field(alias="dlbMixedModeDefault", description="DLB mixed mode default", default="ecmp")
    flowlet_aging: int = Field(alias="flowletAging", description="Flowlet aging interval", default=1)
    flowlet_dscp: str = Field(alias="flowletDscp", description="Flowlet DSCP value", default="")
    per_packet_dscp: str = Field(alias="perPacketDscp", description="Per-packet DSCP value", default="")
    ai_load_sharing: bool = Field(alias="aiLoadSharing", description="Enable AI load sharing", default=False)
    priority_flow_control_watch_interval: int = Field(
        alias="priorityFlowControlWatchInterval", description="Priority flow control watch interval", default=101
    )

    # PTP
    ptp: bool = Field(description="Enable PTP", default=False)
    ptp_loopback_id: int = Field(alias="ptpLoopbackId", description="PTP loopback ID", default=0)
    ptp_domain_id: int = Field(alias="ptpDomainId", description="PTP domain ID", default=0)
    ptp_vlan_id: int = Field(alias="ptpVlanId", description="PTP VLAN ID", default=2)

    # STP
    stp_root_option: StpRootOptionEnum = Field(alias="stpRootOption", description="STP root option", default=StpRootOptionEnum.UNMANAGED)
    stp_vlan_range: str = Field(alias="stpVlanRange", description="STP VLAN range", default="1-3967")
    mst_instance_range: str = Field(alias="mstInstanceRange", description="MST instance range", default="0")
    stp_bridge_priority: int = Field(alias="stpBridgePriority", description="STP bridge priority", default=0)

    # MPLS Handoff
    mpls_handoff: bool = Field(alias="mplsHandoff", description="Enable MPLS handoff", default=False)
    mpls_loopback_identifier: int = Field(alias="mplsLoopbackIdentifier", description="MPLS loopback identifier", default=101)
    mpls_isis_area_number: str = Field(alias="mplsIsisAreaNumber", description="MPLS IS-IS area number", default="0001")
    mpls_loopback_ip_range: str = Field(alias="mplsLoopbackIpRange", description="MPLS loopback IP range", default="10.101.0.0/25")

    # Private VLAN
    private_vlan: bool = Field(alias="privateVlan", description="Enable private VLAN", default=False)
    default_private_vlan_secondary_network_template: str = Field(
        alias="defaultPrivateVlanSecondaryNetworkTemplate",
        description="Default private VLAN secondary network template",
        default="Pvlan_Secondary_Network"
    )
    allow_vlan_on_leaf_tor_pairing: str = Field(
        alias="allowVlanOnLeafTorPairing", description="Allow VLAN on leaf/TOR pairing", default="none"
    )

    # Leaf / TOR
    leaf_tor_id_range: bool = Field(alias="leafTorIdRange", description="Enable leaf/TOR ID range", default=False)
    leaf_tor_vpc_port_channel_id_range: str = Field(
        alias="leafTorVpcPortChannelIdRange", description="Leaf/TOR vPC port-channel ID range", default="1-499"
    )

    # Resource ID Ranges
    l3_vni_no_vlan_default_option: bool = Field(
        alias="l3VniNoVlanDefaultOption", description="L3 VNI no-VLAN default option", default=False
    )
    ip_service_level_agreement_id_range: str = Field(
        alias="ipServiceLevelAgreementIdRange", description="IP SLA ID range", default="10000-19999"
    )
    object_tracking_number_range: str = Field(
        alias="objectTrackingNumberRange", description="Object tracking number range", default="100-299"
    )
    service_network_vlan_range: str = Field(
        alias="serviceNetworkVlanRange", description="Service network VLAN range", default="3000-3199"
    )
    route_map_sequence_number_range: str = Field(
        alias="routeMapSequenceNumberRange", description="Route map sequence number range", default="1-65534"
    )

    # DNS / NTP / Syslog Collections
    ntp_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerCollection")
    ntp_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerVrfCollection")
    dns_collection: List[str] = Field(default_factory=lambda: ["5.192.28.174"], alias="dnsCollection")
    dns_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="dnsVrfCollection")
    syslog_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerCollection")
    syslog_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerVrfCollection")
    syslog_severity_collection: List[int] = Field(default_factory=lambda: [7], alias="syslogSeverityCollection", description="Syslog severity levels (0-7)")

    # Extra Config / Pre-Interface Config / AAA / Banner
    banner: str = Field(description="Fabric banner text", default="")
    extra_config_leaf: str = Field(alias="extraConfigLeaf", description="Extra leaf config", default="")
    extra_config_spine: str = Field(alias="extraConfigSpine", description="Extra spine config", default="")
    extra_config_tor: str = Field(alias="extraConfigTor", description="Extra TOR config", default="")
    extra_config_intra_fabric_links: str = Field(
        alias="extraConfigIntraFabricLinks", description="Extra intra-fabric links config", default=""
    )
    extra_config_aaa: str = Field(alias="extraConfigAaa", description="Extra AAA config", default="")
    aaa: bool = Field(description="Enable AAA", default=False)
    pre_interface_config_leaf: str = Field(alias="preInterfaceConfigLeaf", description="Pre-interface leaf config", default="")
    pre_interface_config_spine: str = Field(alias="preInterfaceConfigSpine", description="Pre-interface spine config", default="")
    pre_interface_config_tor: str = Field(alias="preInterfaceConfigTor", description="Pre-interface TOR config", default="")

    # System / Compliance / OAM / Misc
    anycast_border_gateway_advertise_physical_ip: bool = Field(
        alias="anycastBorderGatewayAdvertisePhysicalIp", description="Anycast border gateway advertise physical IP", default=False
    )
    greenfield_debug_flag: GreenfieldDebugFlagEnum = Field(alias="greenfieldDebugFlag", description="Greenfield debug flag", default=GreenfieldDebugFlagEnum.DISABLE)
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval", description="Interface statistics load interval", default=10
    )
    nve_hold_down_timer: int = Field(alias="nveHoldDownTimer", description="NVE hold-down timer", default=180)
    next_generation_oam: bool = Field(alias="nextGenerationOAM", description="Enable next-generation OAM", default=True)
    ngoam_south_bound_loop_detect: bool = Field(
        alias="ngoamSouthBoundLoopDetect", description="Enable NGOAM south bound loop detect", default=False
    )
    ngoam_south_bound_loop_detect_probe_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectProbeInterval", description="NGOAM south bound loop detect probe interval", default=300
    )
    ngoam_south_bound_loop_detect_recovery_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectRecoveryInterval", description="NGOAM south bound loop detect recovery interval", default=600
    )
    strict_config_compliance_mode: bool = Field(
        alias="strictConfigComplianceMode", description="Enable strict config compliance mode", default=False
    )
    advanced_ssh_option: bool = Field(alias="advancedSshOption", description="Enable advanced SSH option", default=False)
    copp_policy: CoppPolicyEnum = Field(alias="coppPolicy", description="CoPP policy", default=CoppPolicyEnum.STRICT)
    power_redundancy_mode: str = Field(alias="powerRedundancyMode", description="Power redundancy mode", default="redundant")
    host_interface_admin_state: bool = Field(
        alias="hostInterfaceAdminState", description="Host interface admin state", default=True
    )
    heartbeat_interval: int = Field(alias="heartbeatInterval", description="Heartbeat interval", default=190)
    policy_based_routing: bool = Field(alias="policyBasedRouting", description="Enable policy-based routing", default=False)
    brownfield_network_name_format: str = Field(
        alias="brownfieldNetworkNameFormat", description="Brownfield network name format", default="Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$"
    )
    brownfield_skip_overlay_network_attachments: bool = Field(
        alias="brownfieldSkipOverlayNetworkAttachments", description="Skip brownfield overlay network attachments", default=False
    )
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding", description="Allow smart switch onboarding", default=False
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
    license_tier: LicenseTierEnum = Field(alias="licenseTier", description="License tier", default=LicenseTierEnum.PREMIER)
    alert_suspend: AlertSuspendEnum = Field(alias="alertSuspend", description="Alert suspension state", default=AlertSuspendEnum.DISABLED)
    telemetry_collection: bool = Field(alias="telemetryCollection", description="Enable telemetry collection", default=False)
    telemetry_collection_type: str = Field(alias="telemetryCollectionType", description="Telemetry collection type", default="outOfBand")
    telemetry_streaming_protocol: str = Field(alias="telemetryStreamingProtocol", description="Telemetry streaming protocol", default="ipv4")
    telemetry_source_interface: str = Field(alias="telemetrySourceInterface", description="Telemetry source interface", default="")
    telemetry_source_vrf: str = Field(alias="telemetrySourceVrf", description="Telemetry source VRF", default="")
    security_domain: str = Field(alias="securityDomain", description="Security domain", default="all")

    # Core Management Configuration
    management: Optional[VxlanIbgpManagementModel] = Field(description="iBGP VXLAN management configuration", default=None)

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