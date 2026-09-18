# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import List, Literal, Optional, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
    DhcpProtocolVersionEnum,
    GreenfieldDebugFlagEnum,
    ReplicationModeEnum,
    RendezvousPointCountEnum,
    RouteReflectorCountEnum,
    UnderlayMulticastGroupAddressLimitEnum,
    VpcPeerKeepAliveOptionEnum,
    VrfLiteAutoConfigEnum,
    VlanTrunkingProtocolModeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    BGP_ASN_RE,
    NetflowSettingsModel,
    BootstrapSubnetModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import FabricBaseModel

"""
# Comprehensive Pydantic models for VXLAN Campus fabric management via Nexus Dashboard

This module provides comprehensive Pydantic models for creating, updating, and deleting
VXLAN Campus fabrics through the Nexus Dashboard Fabric Controller (NDFC) API.

## Models Overview

- `CampusIbgpVxlanManagementModel` - Campus iBGP VXLAN specific management settings
- `FabricCampusIbgpVxlanModel` - Complete campus iBGP VXLAN fabric creation model

## Usage

```python
# Create a new VXLAN Campus fabric
fabric_data = {
    "name": "MyCampusFabric",
    "management": {
        "type": "vxlanCampus",
        "bgpAsn": "65001",
    }
}
fabric = FabricCampusIbgpVxlanModel(**fabric_data)
```
"""


class CampusIbgpVxlanManagementModel(NDNestedModel):
    """
    # Summary

    Comprehensive VXLAN Campus fabric management configuration.

    This model contains all settings specific to VXLAN Campus fabric types including
    VXLAN properties (shared), campus-specific properties, and netflow settings.

    ## Raises

    - `ValueError` - If BGP ASN or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # Fabric Type (required for discriminated union)
    type: Literal["vxlanCampus"] = Field(description="Fabric management type", default=FabricTypeEnum.CAMPUS_IBGP_VXLAN)

    # Core Configuration (from vxlanProperties)
    bgp_asn: str = Field(
        alias="bgpAsn",
        description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]",
    )

    # Name under management section is optional for backward compatibility
    name: Optional[str] = Field(description="Fabric name", min_length=1, max_length=64, default="")

    # --- vxlanProperties (shared VXLAN fields) ---

    # Underlay
    target_subnet_mask: int = Field(
        alias="targetSubnetMask",
        description="Mask for underlay subnet IP range",
        ge=30,
        le=31,
        default=30,
    )
    anycast_gateway_mac: str = Field(
        alias="anycastGatewayMac",
        description="Shared anycast gateway MAC address",
        default="2020.0000.00aa",
    )
    performance_monitoring: bool = Field(
        alias="performanceMonitoring",
        description="Enable switch metrics via periodic SNMP polling",
        default=False,
    )

    # Multicast / Replication
    replication_mode: ReplicationModeEnum = Field(
        alias="replicationMode",
        description="Replication Mode for BUM Traffic",
        default=ReplicationModeEnum.MULTICAST,
    )
    multicast_group_subnet: str = Field(
        alias="multicastGroupSubnet",
        description="Multicast pool prefix (8-30), CIDR v4 format",
        default="239.1.1.0/25",
    )
    auto_generate_multicast_group_address: bool = Field(
        alias="autoGenerateMulticastGroupAddress",
        description="Generate multicast group address from pool (round-robin)",
        default=False,
    )
    underlay_multicast_group_address_limit: UnderlayMulticastGroupAddressLimitEnum = Field(
        alias="underlayMulticastGroupAddressLimit",
        description="Max supported multicast group address value",
        default=UnderlayMulticastGroupAddressLimitEnum.V_128,
    )
    tenant_routed_multicast: bool = Field(
        alias="tenantRoutedMulticast",
        description="Overlay IPv4 multicast support in VXLAN fabrics",
        default=False,
    )
    rendezvous_point_count: RendezvousPointCountEnum = Field(
        alias="rendezvousPointCount",
        description="Number of spines acting as Rendezvous-Points",
        default=RendezvousPointCountEnum.TWO,
    )
    rendezvous_point_loopback_id: int = Field(
        alias="rendezvousPointLoopbackId",
        description="Rendezvous point loopback Id",
        ge=0,
        le=1023,
        default=254,
    )

    # vPC Settings
    vpc_peer_link_vlan: str = Field(
        alias="vpcPeerLinkVlan",
        description="VLAN range (2-4094) for vPC Peer Link SVI",
        default="3600",
    )
    vpc_peer_link_enable_native_vlan: bool = Field(
        alias="vpcPeerLinkEnableNativeVlan",
        description="Enable vPC Peer Link for Native VLAN",
        default=False,
    )
    vpc_peer_keep_alive_option: VpcPeerKeepAliveOptionEnum = Field(
        alias="vpcPeerKeepAliveOption",
        description="vPC Peer Keep Alive with Loopback or Management",
        default=VpcPeerKeepAliveOptionEnum.MANAGEMENT,
    )
    vpc_auto_recovery_timer: int = Field(
        alias="vpcAutoRecoveryTimer",
        description="vPC auto recovery timer in seconds",
        ge=240,
        le=3600,
        default=360,
    )
    vpc_delay_restore_timer: int = Field(
        alias="vpcDelayRestoreTimer",
        description="vPC delay restore timer in seconds",
        ge=1,
        le=3600,
        default=150,
    )
    vpc_peer_link_port_channel_id: str = Field(
        alias="vpcPeerLinkPortChannelId",
        description="vPC Peer Link Port Channel ID (1-4096)",
        default="500",
    )
    vpc_ipv6_neighbor_discovery_sync: bool = Field(
        alias="vpcIpv6NeighborDiscoverySync",
        description="Enable IPv6 ND sync between vPC peers",
        default=True,
    )
    advertise_physical_ip: bool = Field(
        alias="advertisePhysicalIp",
        description="Primary VTEP IP advertisement as next-hop of prefix routes",
        default=False,
    )
    vpc_domain_id_range: str = Field(
        alias="vpcDomainIdRange",
        description="vPC Domain Id range (1-1000)",
        default="1-1000",
    )

    # Loopback IDs
    bgp_loopback_id: int = Field(
        alias="bgpLoopbackId",
        description="Underlay Routing Loopback Id",
        ge=0,
        le=1023,
        default=0,
    )
    nve_loopback_id: int = Field(
        alias="nveLoopbackId",
        description="Underlay VTEP loopback Id (NVE interface)",
        ge=0,
        le=1023,
        default=1,
    )

    # Templates
    vrf_template: str = Field(
        alias="vrfTemplate",
        description="Default overlay VRF template for leafs",
        default="Default_VRF_Universal",
    )
    network_template: str = Field(
        alias="networkTemplate",
        description="Default overlay network template for leafs",
        default="Default_Network_Universal",
    )
    vrf_extension_template: str = Field(
        alias="vrfExtensionTemplate",
        description="Default overlay VRF template for borders",
        default="Default_VRF_Extension_Universal",
    )
    network_extension_template: str = Field(
        alias="networkExtensionTemplate",
        description="Default overlay network template for borders",
        default="Default_Network_Extension_Universal",
    )
    l3_vni_no_vlan_default_option: bool = Field(
        alias="l3VniNoVlanDefaultOption",
        description="L3 VNI config without VLAN; propagated on VRF creation",
        default=False,
    )

    # Site / MTU
    site_id: Optional[str] = Field(
        alias="siteId",
        description="EVPN Multi-Site Support. Defaults to Fabric ASN",
        default=None,
    )
    fabric_mtu: int = Field(
        alias="fabricMtu",
        description="Intra Fabric Interface MTU (must be even)",
        ge=576,
        le=9216,
        default=9216,
    )
    l2_host_interface_mtu: int = Field(
        alias="l2HostInterfaceMtu",
        description="Layer 2 host interface MTU (must be even)",
        ge=1500,
        le=9216,
        default=9216,
    )

    # Tenant / NX-API / SNMP
    tenant_dhcp: bool = Field(
        alias="tenantDhcp",
        description="Enable Tenant DHCP",
        default=True,
    )
    nxapi: bool = Field(description="Enable NX-API over HTTPS", default=False)
    nxapi_https_port: int = Field(
        alias="nxapiHttpsPort",
        description="HTTPS port for NX-API",
        ge=1,
        le=65535,
        default=443,
    )
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API over HTTP", default=False)
    nxapi_http_port: int = Field(
        alias="nxapiHttpPort",
        description="HTTP port for NX-API",
        ge=1,
        le=65535,
        default=80,
    )
    snmp_trap: bool = Field(
        alias="snmpTrap",
        description="Configure Nexus Dashboard as a receiver for SNMP traps",
        default=True,
    )
    anycast_border_gateway_advertise_physical_ip: bool = Field(
        alias="anycastBorderGatewayAdvertisePhysicalIp",
        description="Advertise Anycast Border Gateway PIP as VTEP",
        default=False,
    )

    # Debug / TCAM / Statistics
    greenfield_debug_flag: GreenfieldDebugFlagEnum = Field(
        alias="greenfieldDebugFlag",
        description="Allow switch config to be cleared without reload",
        default=GreenfieldDebugFlagEnum.DISABLE,
    )
    tcam_allocation: bool = Field(
        alias="tcamAllocation",
        description="TCAM commands auto-generated for VxLAN and vPC Fabric Peering",
        default=True,
    )
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description="Enable real-time interface statistics (NX-OS only)",
        default=False,
    )
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval",
        description="Interface Statistics Load Interval in seconds",
        ge=5,
        le=300,
        default=10,
    )

    # IP Ranges
    bgp_loopback_ip_range: str = Field(
        alias="bgpLoopbackIpRange",
        description="Typically Loopback0 IP Address Range",
        default="10.2.0.0/22",
    )
    nve_loopback_ip_range: str = Field(
        alias="nveLoopbackIpRange",
        description="Typically Loopback1 IP Address Range",
        default="10.3.0.0/22",
    )
    anycast_rendezvous_point_ip_range: str = Field(
        alias="anycastRendezvousPointIpRange",
        description="Anycast or Phantom RP IP Address Range",
        default="10.254.254.0/24",
    )
    intra_fabric_subnet_range: str = Field(
        alias="intraFabricSubnetRange",
        description="Address range for numbered and peer link SVI IPs",
        default="10.4.0.0/16",
    )

    # VNI / VLAN Ranges
    l2_vni_range: str = Field(
        alias="l2VniRange",
        description="Overlay network identifier range (1-16777214)",
        default="30000-49000",
    )
    l3_vni_range: str = Field(
        alias="l3VniRange",
        description="Overlay VRF identifier range (1-16777214)",
        default="50000-59000",
    )
    network_vlan_range: str = Field(
        alias="networkVlanRange",
        description="Per Switch Overlay Network VLAN Range (2-4094)",
        default="2300-2999",
    )
    vrf_vlan_range: str = Field(
        alias="vrfVlanRange",
        description="Per Switch Overlay VRF VLAN Range (2-4094)",
        default="2000-2299",
    )

    # VRF Lite
    sub_interface_dot1q_range: str = Field(
        alias="subInterfaceDot1qRange",
        description="Per aggregation dot1q range for VRF-Lite (2-4093)",
        default="2-511",
    )
    vrf_lite_auto_config: VrfLiteAutoConfigEnum = Field(
        alias="vrfLiteAutoConfig",
        description="VRF Lite Inter-Fabric Connection Deployment Options",
        default=VrfLiteAutoConfigEnum.MANUAL,
    )
    vrf_lite_subnet_range: str = Field(
        alias="vrfLiteSubnetRange",
        description="P2P Interfabric Connection address range (CIDR v4)",
        default="10.33.0.0/16",
    )
    vrf_lite_subnet_target_mask: int = Field(
        alias="vrfLiteSubnetTargetMask",
        description="VRF Lite Subnet Mask",
        ge=8,
        le=31,
        default=30,
    )
    auto_unique_vrf_lite_ip_prefix: bool = Field(
        alias="autoUniqueVrfLiteIpPrefix",
        description="Unique IP prefix per VRF extension over VRF LITE IFC",
        default=False,
    )

    # Per-VRF Loopback
    per_vrf_loopback_auto_provision: bool = Field(
        alias="perVrfLoopbackAutoProvision",
        description="Auto provision IPv4 loopback on VTEP on VRF attachment",
        default=False,
    )
    per_vrf_loopback_ip_range: str = Field(
        alias="perVrfLoopbackIpRange",
        description="Prefix pool for IPv4 loopback addresses on VTEPs per VRF",
        default="10.5.0.0/22",
    )
    per_vrf_loopback_auto_provision_ipv6: bool = Field(
        alias="perVrfLoopbackAutoProvisionIpv6",
        description="Auto provision IPv6 loopback on VTEP on VRF attachment",
        default=False,
    )
    per_vrf_loopback_ipv6_range: str = Field(
        alias="perVrfLoopbackIpv6Range",
        description="Prefix pool for IPv6 loopback addresses on VTEPs per VRF",
        default="fd00::a05:0/112",
    )

    # Banner
    banner: str = Field(
        description="MOTD banner (delimiter char + message + delimiter)",
        default="",
    )

    # Bootstrap
    day0_bootstrap: bool = Field(
        alias="day0Bootstrap",
        description="Automatic IP Assignment For POAP",
        default=False,
    )
    local_dhcp_server: bool = Field(
        alias="localDhcpServer",
        description="Automatic IP Assignment For POAP from Local DHCP Server",
        default=False,
    )
    dhcp_protocol_version: DhcpProtocolVersionEnum = Field(
        alias="dhcpProtocolVersion",
        description="IP protocol version for Local DHCP Server",
        default=DhcpProtocolVersionEnum.DHCPV4,
    )
    dhcp_start_address: str = Field(
        alias="dhcpStartAddress",
        description="DHCP Scope Start Address",
        default="",
    )
    dhcp_end_address: str = Field(
        alias="dhcpEndAddress",
        description="DHCP Scope End Address",
        default="",
    )
    management_gateway: str = Field(
        alias="managementGateway",
        description="Default Gateway For Management VRF",
        default="",
    )
    management_ipv4_prefix: int = Field(
        alias="managementIpv4Prefix",
        description="Switch Mgmt IP Subnet Prefix (IPv4)",
        ge=8,
        le=30,
        default=24,
    )
    management_ipv6_prefix: int = Field(
        alias="managementIpv6Prefix",
        description="Switch Mgmt IP Subnet Prefix (IPv6)",
        ge=64,
        le=126,
        default=64,
    )
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="List of IPv4/IPv6 subnets for bootstrap",
        default_factory=list,
    )

    # Backup
    real_time_backup: Optional[bool] = Field(
        alias="realTimeBackup",
        description="Backup hourly only if config deployed since last backup",
        default=None,
    )
    scheduled_backup: Optional[bool] = Field(
        alias="scheduledBackup",
        description="Enable daily backup at scheduled time",
        default=None,
    )
    scheduled_backup_time: str = Field(
        alias="scheduledBackupTime",
        description="Backup time (UTC) in 24 hour format HH:MM",
        default="",
    )

    # --- campusProperties (campus-specific fields) ---

    # Routing Protocol
    link_state_routing_protocol: str = Field(
        alias="linkStateRoutingProtocol",
        description="Link-State Routing Protocol. Supported: OSPF",
        default="ospf",
    )
    route_reflector_count: RouteReflectorCountEnum = Field(
        alias="routeReflectorCount",
        description="Number of spines acting as Route-Reflectors",
        default=RouteReflectorCountEnum.TWO,
    )
    bgp_ipv4_unicast_peering: bool = Field(
        alias="bgpIpv4UnicastPeering",
        description="Enable BGP IPv4 unicast session between RR and RR client",
        default=False,
    )
    auto_bgp_neighbor_description: bool = Field(
        alias="autoBgpNeighborDescription",
        description="Generate BGP EVPN Neighbor Description",
        default=True,
    )

    # OSPF
    ospf_process_id: int = Field(
        alias="ospfProcessId",
        description="OSPF Process Id (for Nexus: OSPF Process Tag)",
        ge=1,
        le=65535,
        default=1,
    )
    ospf_area_id: str = Field(
        alias="ospfAreaId",
        description="OSPF Area Id in IP address format",
        default="0.0.0.0",
    )

    # IOS-XE Specific
    system_mtu: int = Field(
        alias="systemMtu",
        description="IOS XE System MTU",
        ge=1500,
        le=9198,
        default=1500,
    )
    vlan_trunking_protocol_mode: VlanTrunkingProtocolModeEnum = Field(
        alias="vlanTrunkingProtocolMode",
        description="VLAN Trunking Protocol Mode",
        default=VlanTrunkingProtocolModeEnum.OFF,
    )
    overlay_conversion: bool = Field(
        alias="overlayConversion",
        description="One-time conversion of existing VRFs/networks from IOS_XE templates to Universal templates",
        default=False,
    )
    ssh_bulk_mode: bool = Field(
        alias="sshBulkMode",
        description="Enable optimizations for bulk data transfer (IOS XE only)",
        default=False,
    )
    ssh_window_size: int = Field(
        alias="sshWindowSize",
        description="SSH window size (IOS XE only)",
        ge=131072,
        le=1073741824,
        default=131072,
    )
    ios_xe_banner: str = Field(
        alias="iosXeBanner",
        description="MOTD banner for IOS XE (delimiter + message + delimiter)",
        default="",
    )

    # Extra Config (IOS-XE / NX-OS)
    ios_xe_leaf_freeform: str = Field(
        alias="iosXeLeafFreeform",
        description="Additional CLIs for all leafs (from show run)",
        default="",
    )
    extra_config_xe_spine: str = Field(
        alias="extraConfigXeSpine",
        description="Additional CLIs for all spines (from show run)",
        default="",
    )
    extra_config_xe_intra_fabric_links: str = Field(
        alias="extraConfigXeIntraFabricLinks",
        description="Additional CLIs for all intra-fabric links",
        default="",
    )

    # VRF Lite Auto
    auto_symmetric_vrf_lite: bool = Field(
        alias="autoSymmetricVrfLite",
        description="Auto-generate VRF LITE sub-interface and BGP peering on managed neighbor devices",
        default=False,
    )
    auto_vrf_lite_default_vrf: bool = Field(
        alias="autoVrfLiteDefaultVrf",
        description="Auto-generate Default VRF interface and BGP peering on VRF LITE IFC auto deployment",
        default=False,
    )
    auto_symmetric_default_vrf: bool = Field(
        alias="autoSymmetricDefaultVrf",
        description="Auto-generate Default VRF interface and BGP peering on managed neighbor devices",
        default=False,
    )
    default_vrf_redistribution_bgp_route_map: str = Field(
        alias="defaultVrfRedistributionBgpRouteMap",
        description="Route Map for redistributing BGP routes to IGP in default VRF",
        default="extcon-rmap-filter",
    )

    # Campus Misc
    domain_name: str = Field(
        alias="domainName",
        description="Domain name for DHCP server PnP block",
        default="",
    )
    inband_management: bool = Field(
        alias="inbandManagement",
        description="Manage switches with only Inband connectivity",
        default=False,
    )
    seed_switch_core_interfaces: List[str] = Field(
        alias="seedSwitchCoreInterfaces",
        description="Core-facing interface list on seed switch (N9K border gateway spine)",
        default_factory=list,
    )

    # Bootstrap Extra Config
    extra_config_xe_bootstrap: str = Field(
        alias="extraConfigXeBootstrap",
        description="Additional CLIs during device bootup/login (IOS-XE, e.g. AAA/Radius)",
        default="",
    )
    extra_config_bootstrap_nxos_border_gateway: str = Field(
        alias="extraConfigBootstrapNxosBorderGateway",
        description="Additional CLIs during device bootup/login for NX-OS border gateways",
        default="",
    )
    extra_config_nxos_border_gateway: str = Field(
        alias="extraConfigNxosBorderGateway",
        description="Additional CLIs for all Border Gateways (from show run)",
        default="",
    )
    extra_config_nxos_intra_fabric_links: str = Field(
        alias="extraConfigNxosIntraFabricLinks",
        description="Additional CLIs for all NX-OS intra-fabric links",
        default="",
    )

    # --- netflowProperties ---

    netflow_settings: NetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Settings associated with netflow",
        default_factory=NetflowSettingsModel,
    )

    @field_validator("bgp_asn")
    @classmethod
    def validate_bgp_asn(cls, value: str) -> str:
        """
        # Summary

        Validate BGP ASN format and range.

        ## Raises

        - `ValueError` - If the value does not match the expected ASN format
        """
        if not BGP_ASN_RE.match(value):
            raise ValueError(f"Invalid BGP ASN '{value}'. " "Expected a plain integer (1-4294967295) or dotted notation (1-65535.0-65535).")
        return value


class FabricCampusIbgpVxlanModel(FabricBaseModel):
    """
    # Summary

    Complete model for creating a new VXLAN Campus fabric.

    This model combines all necessary components for fabric creation including
    basic fabric properties, management settings, telemetry, and streaming configuration.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    _fabric_type: ClassVar[FabricTypeEnum] = FabricTypeEnum.CAMPUS_IBGP_VXLAN

    # Core Management Configuration
    management: Optional[CampusIbgpVxlanManagementModel] = Field(description="Campus iBGP VXLAN management configuration", default=None)
