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
    OverlayModeEnum,
    ReplicationModeEnum,
    CoppPolicyEnum,
    GreenfieldDebugFlagEnum,
    VpcPeerKeepAliveOptionEnum,
    BgpAsModeEnum,
    FirstHopRedundancyProtocolEnum,
)
# Re-use shared nested models from the iBGP module
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_fabric.manage_fabric_ibgp import (
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
    TelemetryNasExportSettingsModel,
    TelemetryNasModel,
    TelemetrySettingsModel,
    ExternalStreamingSettingsModel,
)


"""
# Comprehensive Pydantic models for eBGP VXLAN fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
eBGP VXLAN fabrics through the Nexus Dashboard Fabric Controller (NDFC) API.

## Models Overview

- `VxlanEbgpManagementModel` - eBGP VXLAN specific management settings
- `FabricEbgpModel` - Complete fabric creation model for eBGP fabrics
- `FabricEbgpDeleteModel` - Fabric deletion model

## Usage

```python
# Create a new eBGP VXLAN fabric
fabric_data = {
    "name": "MyEbgpFabric",
    "management": {
        "type": "vxlanEbgp",
        "bgpAsnAutoAllocation": True,
        "bgpAsnRange": "65000-65535"
    }
}
fabric = FabricEbgpModel(**fabric_data)
```
"""

# Regex from OpenAPI schema: bgpAsn accepts plain integers (1-4294967295) and
# dotted four-byte ASN notation (1-65535).(0-65535)
_BGP_ASN_RE = re.compile(
    r"^(([1-9]{1}[0-9]{0,8}|[1-3]{1}[0-9]{1,9}|[4]{1}([0-1]{1}[0-9]{8}|[2]{1}([0-8]{1}[0-9]{7}|[9]{1}([0-3]{1}[0-9]{6}|[4]{1}([0-8]{1}[0-9]{5}|[9]{1}([0-5]{1}[0-9]{4}|[6]{1}([0-6]{1}[0-9]{3}|[7]{1}([0-1]{1}[0-9]{2}|[2]{1}([0-8]{1}[0-9]{1}|[9]{1}[0-5]{1})))))))))|([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])(\.([1-5]\d{4}|[1-9]\d{0,3}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5]|0))?)$"
)


class VxlanEbgpManagementModel(NDNestedModel):
    """
    # Summary

    Comprehensive eBGP VXLAN fabric management configuration.

    This model contains all settings specific to eBGP VXLAN fabric types including
    overlay configuration, BGP AS allocation, multicast settings, and advanced features.

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
    type: Literal[FabricTypeEnum.VXLAN_EBGP] = Field(description="Fabric management type", default=FabricTypeEnum.VXLAN_EBGP)

    # Core eBGP Configuration
    bgp_asn: Optional[str] = Field(
        alias="bgpAsn",
        description="BGP Autonomous System Number 1-4294967295 | 1-65535[.0-65535]. Optional when bgpAsnAutoAllocation is True.",
        default=None
    )
    site_id: Optional[str] = Field(alias="siteId", description="Site identifier for the fabric. Defaults to Fabric ASN.", default="")
    bgp_as_mode: BgpAsModeEnum = Field(
        alias="bgpAsMode",
        description="BGP AS mode: multiAS assigns unique AS per leaf tier, sameTierAS assigns same AS within a tier",
        default=BgpAsModeEnum.MULTI_AS
    )
    bgp_asn_auto_allocation: bool = Field(
        alias="bgpAsnAutoAllocation",
        description="Enable automatic BGP ASN allocation from bgpAsnRange",
        default=True
    )
    bgp_asn_range: Optional[str] = Field(
        alias="bgpAsnRange",
        description="BGP ASN range for automatic allocation (e.g., '65000-65535')",
        default=None
    )
    bgp_allow_as_in_num: int = Field(
        alias="bgpAllowAsInNum",
        description="Number of times BGP allows AS-path that contains local AS",
        default=1
    )
    bgp_max_path: int = Field(alias="bgpMaxPath", description="Maximum number of BGP equal-cost paths", default=4)
    bgp_underlay_failure_protect: bool = Field(
        alias="bgpUnderlayFailureProtect",
        description="Enable BGP underlay failure protection",
        default=False
    )
    auto_configure_ebgp_evpn_peering: bool = Field(
        alias="autoConfigureEbgpEvpnPeering",
        description="Automatically configure eBGP EVPN peering between spine and leaf",
        default=True
    )
    allow_leaf_same_as: bool = Field(
        alias="allowLeafSameAs",
        description="Allow leaf switches to have the same BGP AS number",
        default=False
    )
    assign_ipv4_to_loopback0: bool = Field(
        alias="assignIpv4ToLoopback0",
        description="Assign IPv4 address to loopback0 interface",
        default=True
    )
    evpn: bool = Field(description="Enable EVPN control plane", default=True)
    route_map_tag: int = Field(alias="routeMapTag", description="Route map tag for redistribution", default=12345)
    disable_route_map_tag: bool = Field(
        alias="disableRouteMapTag",
        description="Disable route map tag usage",
        default=False
    )
    leaf_bgp_as: Optional[str] = Field(
        alias="leafBgpAs",
        description="BGP AS number for leaf switches (used with sameTierAS mode)",
        default=None
    )
    border_bgp_as: Optional[str] = Field(
        alias="borderBgpAs",
        description="BGP AS number for border switches",
        default=None
    )
    super_spine_bgp_as: Optional[str] = Field(
        alias="superSpineBgpAs",
        description="BGP AS number for super-spine switches",
        default=None
    )

    # Propagated from FabricEbgpModel
    name: Optional[str] = Field(description="Fabric name", min_length=1, max_length=64, default="")

    # Network Addressing
    bgp_loopback_id: int = Field(alias="bgpLoopbackId", description="BGP loopback interface ID", ge=0, le=1023, default=0)
    bgp_loopback_ip_range: str = Field(alias="bgpLoopbackIpRange", description="BGP loopback IP range", default="10.2.0.0/22")
    bgp_loopback_ipv6_range: str = Field(alias="bgpLoopbackIpv6Range", description="BGP loopback IPv6 range", default="fd00::a02:0/119")
    nve_loopback_id: int = Field(alias="nveLoopbackId", description="NVE loopback interface ID", ge=0, le=1023, default=1)
    nve_loopback_ip_range: str = Field(alias="nveLoopbackIpRange", description="NVE loopback IP range", default="10.3.0.0/22")
    nve_loopback_ipv6_range: str = Field(alias="nveLoopbackIpv6Range", description="NVE loopback IPv6 range", default="fd00::a03:0/118")
    anycast_loopback_id: int = Field(alias="anycastLoopbackId", description="Anycast loopback ID", default=10)
    anycast_rendezvous_point_ip_range: str = Field(
        alias="anycastRendezvousPointIpRange",
        description="Anycast RP IP range",
        default="10.254.254.0/24"
    )
    ipv6_anycast_rendezvous_point_ip_range: str = Field(
        alias="ipv6AnycastRendezvousPointIpRange",
        description="IPv6 anycast RP IP range",
        default="fd00::254:254:0/118"
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
    multicast_group_subnet: str = Field(alias="multicastGroupSubnet", description="Multicast group subnet", default="239.1.1.0/25")
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
    tenant_routed_multicast: bool = Field(alias="tenantRoutedMulticast", description="Enable tenant routed multicast", default=False)
    tenant_routed_multicast_ipv6: bool = Field(
        alias="tenantRoutedMulticastIpv6",
        description="Enable tenant routed multicast IPv6",
        default=False
    )
    first_hop_redundancy_protocol: FirstHopRedundancyProtocolEnum = Field(
        alias="firstHopRedundancyProtocol",
        description="First-hop redundancy protocol for tenant networks",
        default=FirstHopRedundancyProtocolEnum.HSRP
    )

    # Multicast / Rendezvous Point
    rendezvous_point_count: int = Field(
        alias="rendezvousPointCount",
        description="Number of spines acting as Rendezvous-Points",
        default=2
    )
    rendezvous_point_loopback_id: int = Field(alias="rendezvousPointLoopbackId", description="RP loopback ID", default=254)
    rendezvous_point_mode: str = Field(alias="rendezvousPointMode", description="Multicast RP mode", default="asm")
    phantom_rendezvous_point_loopback_id1: int = Field(alias="phantomRendezvousPointLoopbackId1", description="Phantom RP loopback ID 1", default=2)
    phantom_rendezvous_point_loopback_id2: int = Field(alias="phantomRendezvousPointLoopbackId2", description="Phantom RP loopback ID 2", default=3)
    phantom_rendezvous_point_loopback_id3: int = Field(alias="phantomRendezvousPointLoopbackId3", description="Phantom RP loopback ID 3", default=4)
    phantom_rendezvous_point_loopback_id4: int = Field(alias="phantomRendezvousPointLoopbackId4", description="Phantom RP loopback ID 4", default=5)
    l3vni_multicast_group: str = Field(alias="l3vniMulticastGroup", description="Default L3 VNI multicast group IPv4 address", default="239.1.1.0")
    l3_vni_ipv6_multicast_group: str = Field(alias="l3VniIpv6MulticastGroup", description="Default L3 VNI multicast group IPv6 address", default="ff1e::")
    ipv6_multicast_group_subnet: str = Field(alias="ipv6MulticastGroupSubnet", description="IPv6 multicast group subnet", default="ff1e::/121")
    mvpn_vrf_route_import_id: bool = Field(alias="mvpnVrfRouteImportId", description="Enable MVPN VRF route import ID", default=True)
    mvpn_vrf_route_import_id_range: Optional[str] = Field(
        alias="mvpnVrfRouteImportIdRange",
        description="MVPN VRF route import ID range",
        default=None
    )
    vrf_route_import_id_reallocation: bool = Field(
        alias="vrfRouteImportIdReallocation",
        description="Enable VRF route import ID reallocation",
        default=False
    )

    # Advanced Features
    anycast_gateway_mac: str = Field(
        alias="anycastGatewayMac",
        description="Anycast gateway MAC address",
        default="2020.0000.00aa"
    )
    target_subnet_mask: int = Field(alias="targetSubnetMask", description="Target subnet mask", ge=24, le=31, default=30)
    fabric_mtu: int = Field(alias="fabricMtu", description="Fabric MTU size", ge=1500, le=9216, default=9216)
    l2_host_interface_mtu: int = Field(alias="l2HostInterfaceMtu", description="L2 host interface MTU", ge=1500, le=9216, default=9216)
    l3_vni_no_vlan_default_option: bool = Field(
        alias="l3VniNoVlanDefaultOption",
        description="L3 VNI configuration without VLAN",
        default=False
    )
    underlay_ipv6: bool = Field(alias="underlayIpv6", description="Enable IPv6 underlay", default=False)
    static_underlay_ip_allocation: bool = Field(
        alias="staticUnderlayIpAllocation",
        description="Disable dynamic underlay IP address allocation",
        default=False
    )
    anycast_border_gateway_advertise_physical_ip: bool = Field(
        alias="anycastBorderGatewayAdvertisePhysicalIp",
        description="Advertise Anycast Border Gateway PIP as VTEP",
        default=False
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
    vpc_peer_link_port_channel_id: str = Field(alias="vpcPeerLinkPortChannelId", description="vPC peer link port-channel ID", default="500")
    vpc_ipv6_neighbor_discovery_sync: bool = Field(
        alias="vpcIpv6NeighborDiscoverySync",
        description="Enable vPC IPv6 ND sync",
        default=True
    )
    vpc_layer3_peer_router: bool = Field(alias="vpcLayer3PeerRouter", description="Enable vPC layer-3 peer router", default=True)
    vpc_tor_delay_restore_timer: int = Field(alias="vpcTorDelayRestoreTimer", description="vPC TOR delay restore timer", default=30)
    fabric_vpc_domain_id: bool = Field(alias="fabricVpcDomainId", description="Enable fabric vPC domain ID", default=False)
    shared_vpc_domain_id: int = Field(alias="sharedVpcDomainId", description="Shared vPC domain ID", default=1)
    fabric_vpc_qos: bool = Field(alias="fabricVpcQos", description="Enable fabric vPC QoS", default=False)
    fabric_vpc_qos_policy_name: str = Field(
        alias="fabricVpcQosPolicyName",
        description="Fabric vPC QoS policy name",
        default="spine_qos_for_fabric_vpc_peering"
    )
    enable_peer_switch: bool = Field(alias="enablePeerSwitch", description="Enable vPC peer-switch feature on ToR switches", default=False)

    # Per-VRF Loopback
    per_vrf_loopback_auto_provision: bool = Field(
        alias="perVrfLoopbackAutoProvision",
        description="Auto provision IPv4 loopback on VRF attachment",
        default=False
    )
    per_vrf_loopback_ip_range: str = Field(
        alias="perVrfLoopbackIpRange",
        description="Per-VRF loopback IPv4 prefix pool",
        default="10.5.0.0/22"
    )
    per_vrf_loopback_auto_provision_ipv6: bool = Field(
        alias="perVrfLoopbackAutoProvisionIpv6",
        description="Auto provision IPv6 loopback on VRF attachment",
        default=False
    )
    per_vrf_loopback_ipv6_range: str = Field(
        alias="perVrfLoopbackIpv6Range",
        description="Per-VRF loopback IPv6 prefix pool",
        default="fd00::a05:0/112"
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
    advertise_physical_ip: bool = Field(alias="advertisePhysicalIp", description="Advertise physical IP as VTEP", default=False)
    advertise_physical_ip_on_border: bool = Field(
        alias="advertisePhysicalIpOnBorder",
        description="Advertise physical IP on border switches only",
        default=True
    )

    # Protocol Settings — BGP
    bgp_authentication: bool = Field(alias="bgpAuthentication", description="Enable BGP authentication", default=False)
    bgp_authentication_key_type: str = Field(
        alias="bgpAuthenticationKeyType",
        description="BGP authentication key type",
        default="3des"
    )
    bgp_authentication_key: str = Field(alias="bgpAuthenticationKey", description="BGP authentication key", default="")

    # Protocol Settings — BFD
    bfd: bool = Field(description="Enable BFD", default=False)
    bfd_ibgp: bool = Field(alias="bfdIbgp", description="Enable BFD for iBGP", default=False)
    bfd_authentication: bool = Field(alias="bfdAuthentication", description="Enable BFD authentication", default=False)
    bfd_authentication_key_id: int = Field(alias="bfdAuthenticationKeyId", description="BFD authentication key ID", default=100)
    bfd_authentication_key: str = Field(alias="bfdAuthenticationKey", description="BFD authentication key", default="")

    # Protocol Settings — PIM
    pim_hello_authentication: bool = Field(alias="pimHelloAuthentication", description="Enable PIM hello authentication", default=False)
    pim_hello_authentication_key: str = Field(alias="pimHelloAuthenticationKey", description="PIM hello authentication key", default="")

    # Management Settings
    nxapi: bool = Field(description="Enable NX-API", default=False)
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API HTTP", default=False)
    nxapi_https_port: int = Field(alias="nxapiHttpsPort", description="NX-API HTTPS port", ge=1, le=65535, default=443)
    nxapi_http_port: int = Field(alias="nxapiHttpPort", description="NX-API HTTP port", ge=1, le=65535, default=80)

    # Bootstrap / Day-0 / DHCP
    day0_bootstrap: bool = Field(alias="day0Bootstrap", description="Enable day-0 bootstrap", default=False)
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection",
        description="Bootstrap subnet collection",
        default_factory=list
    )
    local_dhcp_server: bool = Field(alias="localDhcpServer", description="Enable local DHCP server", default=False)
    dhcp_protocol_version: str = Field(alias="dhcpProtocolVersion", description="DHCP protocol version", default="dhcpv4")
    dhcp_start_address: str = Field(alias="dhcpStartAddress", description="DHCP start address", default="")
    dhcp_end_address: str = Field(alias="dhcpEndAddress", description="DHCP end address", default="")
    management_gateway: str = Field(alias="managementGateway", description="Management gateway", default="")
    management_ipv4_prefix: int = Field(alias="managementIpv4Prefix", description="Management IPv4 prefix length", default=24)
    management_ipv6_prefix: int = Field(alias="managementIpv6Prefix", description="Management IPv6 prefix length", default=64)

    # Netflow Settings
    netflow_settings: NetflowSettingsModel = Field(
        alias="netflowSettings",
        description="Netflow configuration",
        default_factory=NetflowSettingsModel
    )

    # Backup / Restore
    real_time_backup: Optional[bool] = Field(alias="realTimeBackup", description="Enable real-time backup", default=None)
    scheduled_backup: Optional[bool] = Field(alias="scheduledBackup", description="Enable scheduled backup", default=None)
    scheduled_backup_time: str = Field(alias="scheduledBackupTime", description="Scheduled backup time", default="")

    # VRF Lite / Sub-Interface
    sub_interface_dot1q_range: str = Field(alias="subInterfaceDot1qRange", description="Sub-interface 802.1q range", default="2-511")
    vrf_lite_auto_config: str = Field(alias="vrfLiteAutoConfig", description="VRF lite auto-config mode", default="manual")
    vrf_lite_subnet_range: str = Field(alias="vrfLiteSubnetRange", description="VRF lite subnet range", default="10.33.0.0/16")
    vrf_lite_subnet_target_mask: int = Field(alias="vrfLiteSubnetTargetMask", description="VRF lite subnet target mask", default=30)
    auto_unique_vrf_lite_ip_prefix: bool = Field(
        alias="autoUniqueVrfLiteIpPrefix",
        description="Auto unique VRF lite IP prefix",
        default=False
    )

    # Leaf / TOR
    leaf_tor_id_range: bool = Field(alias="leafTorIdRange", description="Enable leaf/TOR ID range", default=False)
    leaf_tor_vpc_port_channel_id_range: str = Field(
        alias="leafTorVpcPortChannelIdRange",
        description="Leaf/TOR vPC port-channel ID range",
        default="1-499"
    )
    allow_vlan_on_leaf_tor_pairing: str = Field(
        alias="allowVlanOnLeafTorPairing",
        description="Set trunk allowed VLAN on leaf-TOR pairing port-channels",
        default="none"
    )

    # DNS / NTP / Syslog Collections
    ntp_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerCollection")
    ntp_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="ntpServerVrfCollection")
    dns_collection: List[str] = Field(default_factory=lambda: ["5.192.28.174"], alias="dnsCollection")
    dns_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="dnsVrfCollection")
    syslog_server_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerCollection")
    syslog_server_vrf_collection: List[str] = Field(default_factory=lambda: ["string"], alias="syslogServerVrfCollection")
    syslog_severity_collection: List[int] = Field(default_factory=lambda: [7], alias="syslogSeverityCollection")

    # Extra Config / Pre-Interface Config / AAA / Banner
    banner: str = Field(description="Fabric banner text", default="")
    extra_config_leaf: str = Field(alias="extraConfigLeaf", description="Extra leaf config", default="")
    extra_config_spine: str = Field(alias="extraConfigSpine", description="Extra spine config", default="")
    extra_config_tor: str = Field(alias="extraConfigTor", description="Extra TOR config", default="")
    extra_config_intra_fabric_links: str = Field(
        alias="extraConfigIntraFabricLinks",
        description="Extra intra-fabric links config",
        default=""
    )
    extra_config_aaa: str = Field(alias="extraConfigAaa", description="Extra AAA config", default="")
    extra_config_nxos_bootstrap: str = Field(alias="extraConfigNxosBootstrap", description="Extra NX-OS bootstrap config", default="")
    aaa: bool = Field(description="Enable AAA", default=False)
    pre_interface_config_leaf: str = Field(alias="preInterfaceConfigLeaf", description="Pre-interface leaf config", default="")
    pre_interface_config_spine: str = Field(alias="preInterfaceConfigSpine", description="Pre-interface spine config", default="")
    pre_interface_config_tor: str = Field(alias="preInterfaceConfigTor", description="Pre-interface TOR config", default="")

    # System / Compliance / OAM / Misc
    greenfield_debug_flag: GreenfieldDebugFlagEnum = Field(
        alias="greenfieldDebugFlag",
        description="Greenfield debug flag",
        default=GreenfieldDebugFlagEnum.DISABLE
    )
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval",
        description="Interface statistics load interval in seconds",
        default=10
    )
    nve_hold_down_timer: int = Field(alias="nveHoldDownTimer", description="NVE source interface hold-down timer in seconds", default=180)
    next_generation_oam: bool = Field(alias="nextGenerationOAM", description="Enable next-generation OAM", default=True)
    ngoam_south_bound_loop_detect: bool = Field(
        alias="ngoamSouthBoundLoopDetect",
        description="Enable NGOAM south bound loop detection",
        default=False
    )
    ngoam_south_bound_loop_detect_probe_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectProbeInterval",
        description="NGOAM south bound loop detect probe interval in seconds",
        default=300
    )
    ngoam_south_bound_loop_detect_recovery_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectRecoveryInterval",
        description="NGOAM south bound loop detect recovery interval in seconds",
        default=600
    )
    strict_config_compliance_mode: bool = Field(
        alias="strictConfigComplianceMode",
        description="Enable strict config compliance mode",
        default=False
    )
    advanced_ssh_option: bool = Field(alias="advancedSshOption", description="Enable advanced SSH option", default=False)
    copp_policy: CoppPolicyEnum = Field(alias="coppPolicy", description="CoPP policy", default=CoppPolicyEnum.STRICT)
    power_redundancy_mode: str = Field(alias="powerRedundancyMode", description="Power redundancy mode", default="redundant")
    heartbeat_interval: int = Field(alias="heartbeatInterval", description="XConnect heartbeat interval", default=190)
    snmp_trap: bool = Field(alias="snmpTrap", description="Enable SNMP traps", default=True)
    cdp: bool = Field(description="Enable CDP", default=False)
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection",
        description="Enable real-time interface statistics collection",
        default=False
    )
    tcam_allocation: bool = Field(alias="tcamAllocation", description="Enable TCAM allocation", default=True)
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding",
        description="Allow smart switch onboarding",
        default=False
    )

    # Queuing / QoS
    default_queuing_policy: bool = Field(alias="defaultQueuingPolicy", description="Enable default queuing policy", default=False)
    default_queuing_policy_cloudscale: str = Field(
        alias="defaultQueuingPolicyCloudscale",
        description="Default queuing policy for cloudscale switches",
        default="queuing_policy_default_8q_cloudscale"
    )
    default_queuing_policy_r_series: str = Field(
        alias="defaultQueuingPolicyRSeries",
        description="Default queuing policy for R-Series switches",
        default="queuing_policy_default_r_series"
    )
    default_queuing_policy_other: str = Field(
        alias="defaultQueuingPolicyOther",
        description="Default queuing policy for other switches",
        default="queuing_policy_default_other"
    )
    aiml_qos: bool = Field(alias="aimlQos", description="Enable AI/ML QoS", default=False)
    aiml_qos_policy: str = Field(alias="aimlQosPolicy", description="AI/ML QoS policy", default="400G")
    roce_v2: str = Field(alias="roceV2", description="RoCEv2 DSCP value", default="26")
    cnp: str = Field(description="CNP DSCP value", default="48")
    wred_min: int = Field(alias="wredMin", description="WRED minimum threshold in kbytes", default=950)
    wred_max: int = Field(alias="wredMax", description="WRED maximum threshold in kbytes", default=3000)
    wred_drop_probability: int = Field(alias="wredDropProbability", description="WRED drop probability %", default=7)
    wred_weight: int = Field(alias="wredWeight", description="WRED weight", default=0)
    bandwidth_remaining: int = Field(alias="bandwidthRemaining", description="Bandwidth remaining % for AI traffic queues", default=50)
    dlb: bool = Field(description="Enable dynamic load balancing", default=False)
    dlb_mode: str = Field(alias="dlbMode", description="DLB mode", default="flowlet")
    dlb_mixed_mode_default: str = Field(alias="dlbMixedModeDefault", description="DLB mixed mode default", default="ecmp")
    flowlet_aging: Optional[int] = Field(alias="flowletAging", description="Flowlet aging timer in microseconds", default=None)
    flowlet_dscp: str = Field(alias="flowletDscp", description="Flowlet DSCP value", default="")
    per_packet_dscp: str = Field(alias="perPacketDscp", description="Per-packet DSCP value", default="")
    ai_load_sharing: bool = Field(alias="aiLoadSharing", description="Enable AI load sharing", default=False)
    priority_flow_control_watch_interval: Optional[int] = Field(
        alias="priorityFlowControlWatchInterval",
        description="Priority flow control watch interval in milliseconds",
        default=None
    )

    # PTP
    ptp: bool = Field(description="Enable PTP", default=False)
    ptp_loopback_id: int = Field(alias="ptpLoopbackId", description="PTP loopback ID", default=0)
    ptp_domain_id: int = Field(alias="ptpDomainId", description="PTP domain ID", default=0)

    # Private VLAN
    private_vlan: bool = Field(alias="privateVlan", description="Enable private VLAN", default=False)
    default_private_vlan_secondary_network_template: str = Field(
        alias="defaultPrivateVlanSecondaryNetworkTemplate",
        description="Default private VLAN secondary network template",
        default="Pvlan_Secondary_Network"
    )

    # MACsec
    macsec: bool = Field(description="Enable MACsec", default=False)
    macsec_cipher_suite: str = Field(
        alias="macsecCipherSuite",
        description="MACsec cipher suite",
        default="GCM-AES-XPN-256"
    )
    macsec_key_string: str = Field(alias="macsecKeyString", description="MACsec primary key string", default="")
    macsec_algorithm: str = Field(alias="macsecAlgorithm", description="MACsec primary cryptographic algorithm", default="AES_128_CMAC")
    macsec_fallback_key_string: str = Field(alias="macsecFallbackKeyString", description="MACsec fallback key string", default="")
    macsec_fallback_algorithm: str = Field(
        alias="macsecFallbackAlgorithm",
        description="MACsec fallback cryptographic algorithm",
        default="AES_128_CMAC"
    )
    macsec_report_timer: int = Field(alias="macsecReportTimer", description="MACsec report timer in minutes", default=5)

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
    def validate_bgp_asn(cls, value: Optional[str]) -> Optional[str]:
        """
        # Summary

        Validate BGP ASN format and range when provided.

        ## Raises

        - `ValueError` - If value does not match the expected ASN format
        """
        if value is None:
            return value
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


class FabricEbgpModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a new eBGP VXLAN fabric.

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
    management: Optional[VxlanEbgpManagementModel] = Field(description="eBGP VXLAN management configuration", default=None)

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
    def validate_fabric_consistency(self) -> 'FabricEbgpModel':
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        if self.management is not None and self.management.type != FabricTypeEnum.VXLAN_EBGP:
            raise ValueError(f"Management type must be {FabricTypeEnum.VXLAN_EBGP}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.name

        # Propagate BGP ASN to site_id if both are set and site_id is empty
        if self.management is not None and self.management.site_id == "" and self.management.bgp_asn is not None:
            bgp_asn = self.management.bgp_asn
            if "." in bgp_asn:
                high, low = bgp_asn.split(".")
                self.management.site_id = str(int(high) * 65536 + int(low))
            else:
                self.management.site_id = bgp_asn

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
    "VxlanEbgpManagementModel",
    "FabricEbgpModel",
    "FabricEbgpDeleteModel",
    "FabricTypeEnum",
    "AlertSuspendEnum",
    "LicenseTierEnum",
    "ReplicationModeEnum",
    "OverlayModeEnum",
    "BgpAsModeEnum",
    "FirstHopRedundancyProtocolEnum",
    "VpcPeerKeepAliveOptionEnum",
    "CoppPolicyEnum",
    "GreenfieldDebugFlagEnum",
]
