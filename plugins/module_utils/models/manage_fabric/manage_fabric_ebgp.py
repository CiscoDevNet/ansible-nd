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
    OverlayModeEnum,
    ReplicationModeEnum,
    CoppPolicyEnum,
    GreenfieldDebugFlagEnum,
    VpcPeerKeepAliveOptionEnum,
    BgpAsModeEnum,
    FirstHopRedundancyProtocolEnum,
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
    UnderlayMulticastGroupAddressLimitEnum,
    VrfLiteAutoConfigEnum,
)

# Re-use shared nested models from the common module
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    BGP_ASN_RE,
    LocationModel,
    NetflowSettingsModel,
    BootstrapSubnetModel,
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

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.VXLAN_EBGP] = Field(description="Type of the fabric", default=FabricTypeEnum.VXLAN_EBGP)

    # Core eBGP Configuration
    bgp_asn: Optional[str] = Field(
        alias="bgpAsn", description="BGP Autonomous System Number 1-4294967295 | 1-65535[.0-65535]. Optional when bgpAsnAutoAllocation is True.", default=None
    )
    site_id: Optional[str] = Field(alias="siteId", description="For EVPN Multi-Site Support. Defaults to Fabric ASN", default="")
    bgp_as_mode: BgpAsModeEnum = Field(
        alias="bgpAsMode",
        description=(
            "Multi-AS Unique ASN per Leaf/Border/Border Gateway (Borders and border gateways are "
            "allowed to share ASN). Same-Tier-AS Leafs share one ASN, Borders/border gateways share one ASN"
        ),
        default=BgpAsModeEnum.MULTI_AS,
    )
    bgp_asn_auto_allocation: bool = Field(
        alias="bgpAsnAutoAllocation",
        description=("Automatically allocate and track BGP ASN for leafs, borders and border gateways " "in Multi-AS mode"),
        default=True,
    )
    bgp_asn_range: Optional[str] = Field(
        alias="bgpAsnRange", description=("BGP ASN range for auto-allocation " "(minimum: 1 or 1.0, maximum: 4294967295 or 65535.65535)"), default=None
    )
    bgp_allow_as_in_num: int = Field(alias="bgpAllowAsInNum", description="Number of occurrences of ASN allowed in the BGP AS-path", default=1)
    bgp_max_path: int = Field(alias="bgpMaxPath", description="BGP Maximum Paths", default=4)
    bgp_underlay_failure_protect: bool = Field(alias="bgpUnderlayFailureProtect", description="Enable BGP underlay failure protection", default=False)
    auto_configure_ebgp_evpn_peering: bool = Field(
        alias="autoConfigureEbgpEvpnPeering", description=("Automatically configure eBGP EVPN overlay peering between leaf and spine switches"), default=True
    )
    allow_leaf_same_as: bool = Field(alias="allowLeafSameAs", description="Leafs can have same BGP ASN even when AS mode is Multi-AS", default=False)
    assign_ipv4_to_loopback0: bool = Field(
        alias="assignIpv4ToLoopback0",
        description=(
            "In an IPv6 routed fabric or VXLAN EVPN fabric with IPv6 underlay, assign IPv4 address " "used for BGP Router ID to the routing loopback interface"
        ),
        default=True,
    )
    evpn: bool = Field(description=("Enable BGP EVPN as the control plane and VXLAN as the data plane for this fabric"), default=True)
    route_map_tag: int = Field(alias="routeMapTag", description="Tag for Route Map FABRIC-RMAP-REDIST-SUBNET. (Min:0, Max:4294967295)", default=12345)
    disable_route_map_tag: bool = Field(alias="disableRouteMapTag", description="No match tag for Route Map FABRIC-RMAP-REDIST-SUBNET", default=False)
    leaf_bgp_as: Optional[str] = Field(alias="leafBgpAs", description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]", default=None)
    border_bgp_as: Optional[str] = Field(alias="borderBgpAs", description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]", default=None)
    super_spine_bgp_as: Optional[str] = Field(alias="superSpineBgpAs", description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]", default=None)

    # Propagated from FabricEbgpModel
    name: Optional[str] = Field(description="Fabric name", min_length=1, max_length=64, default="")

    # Network Addressing
    bgp_loopback_id: int = Field(alias="bgpLoopbackId", description="Underlay Routing Loopback Id", ge=0, le=1023, default=0)
    bgp_loopback_ip_range: str = Field(alias="bgpLoopbackIpRange", description="Typically Loopback0 IP Address Range", default="10.2.0.0/22")
    bgp_loopback_ipv6_range: str = Field(alias="bgpLoopbackIpv6Range", description="Typically Loopback0 IPv6 Address Range", default="fd00::a02:0/119")
    nve_loopback_id: int = Field(
        alias="nveLoopbackId",
        description=("Underlay VTEP loopback Id associated with the Network Virtualization Edge (nve) interface"),
        ge=0,
        le=1023,
        default=1,
    )
    nve_loopback_ip_range: str = Field(alias="nveLoopbackIpRange", description="Typically Loopback1 IP Address Range", default="10.3.0.0/22")
    nve_loopback_ipv6_range: str = Field(
        alias="nveLoopbackIpv6Range", description="Typically Loopback1 and Anycast Loopback IPv6 Address Range", default="fd00::a03:0/118"
    )
    anycast_loopback_id: int = Field(
        alias="anycastLoopbackId", description="Underlay Anycast Loopback Id.  Used for vPC Peering in VXLANv6 Fabrics", default=10
    )
    anycast_rendezvous_point_ip_range: str = Field(
        alias="anycastRendezvousPointIpRange", description="Anycast or Phantom RP IP Address Range", default="10.254.254.0/24"
    )
    ipv6_anycast_rendezvous_point_ip_range: str = Field(
        alias="ipv6AnycastRendezvousPointIpRange", description="Anycast RP IPv6 Address Range", default="fd00::254:254:0/118"
    )
    intra_fabric_subnet_range: str = Field(
        alias="intraFabricSubnetRange", description="Address range to assign numbered and peer link SVI IPs", default="10.4.0.0/16"
    )

    # VLAN and VNI Ranges
    l2_vni_range: str = Field(alias="l2VniRange", description="Overlay network identifier range (minimum: 1, maximum: 16777214)", default="30000-49000")
    l3_vni_range: str = Field(alias="l3VniRange", description="Overlay VRF identifier range (minimum: 1, maximum: 16777214)", default="50000-59000")
    network_vlan_range: str = Field(
        alias="networkVlanRange", description="Per Switch Overlay Network VLAN Range (minimum: 2, maximum: 4094)", default="2300-2999"
    )
    vrf_vlan_range: str = Field(alias="vrfVlanRange", description="Per Switch Overlay VRF VLAN Range (minimum: 2, maximum: 4094)", default="2000-2299")

    # Overlay Configuration
    overlay_mode: OverlayModeEnum = Field(
        alias="overlayMode", description="Overlay Mode. VRF/Network configuration using config-profile or CLI", default=OverlayModeEnum.CLI
    )
    replication_mode: ReplicationModeEnum = Field(
        alias="replicationMode", description="Replication Mode for BUM Traffic", default=ReplicationModeEnum.MULTICAST
    )
    multicast_group_subnet: str = Field(
        alias="multicastGroupSubnet",
        description=("Multicast pool prefix between 8 to 30. A multicast group ipv4 from this pool " "is used for BUM traffic for each overlay network."),
        default="239.1.1.0/25",
    )
    auto_generate_multicast_group_address: bool = Field(
        alias="autoGenerateMulticastGroupAddress",
        description=("Generate a new multicast group address from the multicast pool using a round-robin approach"),
        default=False,
    )
    underlay_multicast_group_address_limit: UnderlayMulticastGroupAddressLimitEnum = Field(
        alias="underlayMulticastGroupAddressLimit",
        description=("The maximum supported value is 128 for NX-OS version 10.2(1) or earlier " "and 512 for versions above 10.2(1)"),
        default=UnderlayMulticastGroupAddressLimitEnum.V_128,
    )
    tenant_routed_multicast: bool = Field(alias="tenantRoutedMulticast", description="For Overlay ipv4 Multicast Support In VXLAN Fabrics", default=False)
    tenant_routed_multicast_ipv6: bool = Field(
        alias="tenantRoutedMulticastIpv6", description="For Overlay IPv6 Multicast Support In VXLAN Fabrics", default=False
    )
    first_hop_redundancy_protocol: FirstHopRedundancyProtocolEnum = Field(
        alias="firstHopRedundancyProtocol", description="First Hop Redundancy Protocol HSRP or VRRP", default=FirstHopRedundancyProtocolEnum.HSRP
    )

    # Multicast / Rendezvous Point
    rendezvous_point_count: RendezvousPointCountEnum = Field(
        alias="rendezvousPointCount", description="Number of spines acting as Rendezvous-Points (RPs)", default=RendezvousPointCountEnum.TWO
    )
    rendezvous_point_loopback_id: int = Field(alias="rendezvousPointLoopbackId", description="Rendezvous point loopback Id", default=254)
    rendezvous_point_mode: RendezvousPointModeEnum = Field(
        alias="rendezvousPointMode", description="Multicast rendezvous point Mode. For ipv6 underlay, please use asm only", default=RendezvousPointModeEnum.ASM
    )
    phantom_rendezvous_point_loopback_id1: int = Field(
        alias="phantomRendezvousPointLoopbackId1", description="Underlay phantom rendezvous point loopback primary Id for PIM Bi-dir deployments", default=2
    )
    phantom_rendezvous_point_loopback_id2: int = Field(
        alias="phantomRendezvousPointLoopbackId2", description="Underlay phantom rendezvous point loopback secondary Id for PIM Bi-dir deployments", default=3
    )
    phantom_rendezvous_point_loopback_id3: int = Field(
        alias="phantomRendezvousPointLoopbackId3", description="Underlay phantom rendezvous point loopback tertiary Id for PIM Bi-dir deployments", default=4
    )
    phantom_rendezvous_point_loopback_id4: int = Field(
        alias="phantomRendezvousPointLoopbackId4",
        description=("Underlay phantom rendezvous point loopback quaternary Id for PIM Bi-dir deployments"),
        default=5,
    )
    l3vni_multicast_group: str = Field(
        alias="l3vniMulticastGroup", description="Default Underlay Multicast group IPv4 address assigned for every overlay VRF", default="239.1.1.0"
    )
    l3_vni_ipv6_multicast_group: str = Field(
        alias="l3VniIpv6MulticastGroup", description="Default Underlay Multicast group IP6 address assigned for every overlay VRF", default="ff1e::"
    )
    ipv6_multicast_group_subnet: str = Field(
        alias="ipv6MulticastGroupSubnet", description="IPv6 Multicast address with prefix 112 to 128", default="ff1e::/121"
    )
    mvpn_vrf_route_import_id: bool = Field(
        alias="mvpnVrfRouteImportId", description="Enable MVPN VRI ID Generation For Tenant Routed Multicast With IPv4 Underlay", default=True
    )
    mvpn_vrf_route_import_id_range: Optional[str] = Field(
        alias="mvpnVrfRouteImportIdRange",
        description=(
            "MVPN VRI ID (minimum: 1, maximum: 65535) for vPC, applicable when TRM enabled "
            "with IPv6 underlay, or mvpnVrfRouteImportId enabled with IPv4 underlay"
        ),
        default=None,
    )
    vrf_route_import_id_reallocation: bool = Field(
        alias="vrfRouteImportIdReallocation", description="One time VRI ID re-allocation based on 'MVPN VRI ID Range'", default=False
    )

    # Advanced Features
    anycast_gateway_mac: str = Field(alias="anycastGatewayMac", description="Shared anycast gateway MAC address for all VTEPs", default="2020.0000.00aa")
    target_subnet_mask: int = Field(alias="targetSubnetMask", description="Mask for underlay subnet IP range", ge=24, le=31, default=30)
    fabric_mtu: int = Field(alias="fabricMtu", description="Intra Fabric Interface MTU. Must be an even number", ge=1500, le=9216, default=9216)
    l2_host_interface_mtu: int = Field(
        alias="l2HostInterfaceMtu", description="Layer 2 host interface MTU. Must be an even number", ge=1500, le=9216, default=9216
    )
    l3_vni_no_vlan_default_option: bool = Field(
        alias="l3VniNoVlanDefaultOption",
        description=(
            "L3 VNI configuration without VLAN configuration. This value is propagated on vrf "
            "creation as the default value of 'Enable L3VNI w/o VLAN' in vrf"
        ),
        default=False,
    )
    underlay_ipv6: bool = Field(alias="underlayIpv6", description="If not enabled, IPv4 underlay is used", default=False)
    static_underlay_ip_allocation: bool = Field(
        alias="staticUnderlayIpAllocation", description="Checking this will disable Dynamic Underlay IP Address Allocations", default=False
    )
    anycast_border_gateway_advertise_physical_ip: bool = Field(
        alias="anycastBorderGatewayAdvertisePhysicalIp",
        description=("To advertise Anycast Border Gateway PIP as VTEP. " "Effective on MSD fabric 'Recalculate Config'"),
        default=False,
    )

    # VPC Configuration
    vpc_domain_id_range: str = Field(
        alias="vpcDomainIdRange", description="vPC Domain id range (minimum: 1, maximum: 1000) to use for new pairings", default="1-1000"
    )
    vpc_peer_link_vlan: str = Field(alias="vpcPeerLinkVlan", description="VLAN range (minimum: 2, maximum: 4094) for vPC Peer Link SVI", default="3600")
    vpc_peer_link_enable_native_vlan: bool = Field(alias="vpcPeerLinkEnableNativeVlan", description="Enable VpcPeer Link for Native Vlan", default=False)
    vpc_peer_keep_alive_option: VpcPeerKeepAliveOptionEnum = Field(
        alias="vpcPeerKeepAliveOption", description="Use vPC Peer Keep Alive with Loopback or Management", default=VpcPeerKeepAliveOptionEnum.MANAGEMENT
    )
    vpc_auto_recovery_timer: int = Field(alias="vpcAutoRecoveryTimer", description="vPC auto recovery timer (in seconds)", ge=240, le=3600, default=360)
    vpc_delay_restore_timer: int = Field(alias="vpcDelayRestoreTimer", description="vPC delay restore timer (in seconds)", ge=1, le=3600, default=150)
    vpc_peer_link_port_channel_id: str = Field(
        alias="vpcPeerLinkPortChannelId", description="vPC Peer Link Port Channel ID (minimum: 1, maximum: 4096)", default="500"
    )
    vpc_ipv6_neighbor_discovery_sync: bool = Field(
        alias="vpcIpv6NeighborDiscoverySync", description="Enable IPv6 ND synchronization between vPC peers", default=True
    )
    vpc_layer3_peer_router: bool = Field(alias="vpcLayer3PeerRouter", description="Enable Layer-3 Peer-Router on all Leaf switches", default=True)
    vpc_tor_delay_restore_timer: int = Field(alias="vpcTorDelayRestoreTimer", description="vPC delay restore timer for ToR switches (in seconds)", default=30)
    fabric_vpc_domain_id: bool = Field(
        alias="fabricVpcDomainId", description="Enable the same vPC Domain Id for all vPC Pairs.  Not Recommended.", default=False
    )
    shared_vpc_domain_id: int = Field(alias="sharedVpcDomainId", description="vPC Domain Id to be used on all vPC pairs", default=1)
    fabric_vpc_qos: bool = Field(alias="fabricVpcQos", description="Qos on spines for guaranteed delivery of vPC Fabric Peering communication", default=False)
    fabric_vpc_qos_policy_name: str = Field(
        alias="fabricVpcQosPolicyName", description="Qos Policy name should be same on all spines", default="spine_qos_for_fabric_vpc_peering"
    )
    enable_peer_switch: bool = Field(alias="enablePeerSwitch", description="Enable the vPC peer-switch feature on ToR switches", default=False)

    # Per-VRF Loopback
    per_vrf_loopback_auto_provision: bool = Field(
        alias="perVrfLoopbackAutoProvision",
        description=(
            "Auto provision an IPv4 loopback on a VTEP on VRF attachment. Note: Enabling this option "
            "auto-provisions loopback on existing VRF attachments and also when Edit, QuickAttach, or "
            "Multiattach actions are performed. Provisioned loopbacks cannot be deleted until VRFs "
            "are unattached."
        ),
        default=False,
    )
    per_vrf_loopback_ip_range: str = Field(
        alias="perVrfLoopbackIpRange", description="Prefix pool to assign IPv4 addresses to loopbacks on VTEPs on a per VRF basis", default="10.5.0.0/22"
    )
    per_vrf_loopback_auto_provision_ipv6: bool = Field(
        alias="perVrfLoopbackAutoProvisionIpv6", description="Auto provision an IPv6 loopback on a VTEP on VRF attachment.", default=False
    )
    per_vrf_loopback_ipv6_range: str = Field(
        alias="perVrfLoopbackIpv6Range", description="Prefix pool to assign IPv6 addresses to loopbacks on VTEPs on a per VRF basis", default="fd00::a05:0/112"
    )

    # Templates
    vrf_template: str = Field(alias="vrfTemplate", description="Default overlay VRF template for leafs", default="Default_VRF_Universal")
    network_template: str = Field(alias="networkTemplate", description="Default overlay network template for leafs", default="Default_Network_Universal")
    vrf_extension_template: str = Field(
        alias="vrfExtensionTemplate", description="Default overlay VRF template for borders", default="Default_VRF_Extension_Universal"
    )
    network_extension_template: str = Field(
        alias="networkExtensionTemplate", description="Default overlay network template for borders", default="Default_Network_Extension_Universal"
    )

    # Optional Advanced Settings
    performance_monitoring: bool = Field(
        alias="performanceMonitoring",
        description=("If enabled, switch metrics are collected through periodic SNMP polling. " "Alternative to real-time telemetry"),
        default=False,
    )
    tenant_dhcp: bool = Field(alias="tenantDhcp", description="Enable tenant DHCP", default=True)
    advertise_physical_ip: bool = Field(
        alias="advertisePhysicalIp", description="For Primary VTEP IP Advertisement As Next-Hop Of Prefix Routes", default=False
    )
    advertise_physical_ip_on_border: bool = Field(
        alias="advertisePhysicalIpOnBorder",
        description=("Enable advertise-pip on vPC borders and border gateways only. " "Applicable only when vPC advertise-pip is not enabled"),
        default=True,
    )

    # Protocol Settings — BGP
    bgp_authentication: bool = Field(alias="bgpAuthentication", description="Enables or disables the BGP authentication", default=False)
    bgp_authentication_key_type: BgpAuthenticationKeyTypeEnum = Field(
        alias="bgpAuthenticationKeyType",
        description="BGP key encryption type: 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7",
        default=BgpAuthenticationKeyTypeEnum.THREE_DES,
    )
    bgp_authentication_key: str = Field(alias="bgpAuthenticationKey", description="Encrypted BGP authentication key based on type", default="")

    # Protocol Settings — BFD
    bfd: bool = Field(description="Enable BFD.  Valid for IPv4 Underlay only", default=False)
    bfd_ibgp: bool = Field(alias="bfdIbgp", description="Enable BFD For iBGP", default=False)
    bfd_authentication: bool = Field(alias="bfdAuthentication", description="Enable BFD Authentication.  Valid for P2P Interfaces only", default=False)
    bfd_authentication_key_id: int = Field(alias="bfdAuthenticationKeyId", description="BFD Authentication Key ID", default=100)
    bfd_authentication_key: str = Field(alias="bfdAuthenticationKey", description="Encrypted SHA1 secret value", default="")

    # Protocol Settings — PIM
    pim_hello_authentication: bool = Field(alias="pimHelloAuthentication", description="Valid for IPv4 Underlay only", default=False)
    pim_hello_authentication_key: str = Field(alias="pimHelloAuthenticationKey", description="3DES Encrypted", default="")

    # Management Settings
    nxapi: bool = Field(description="Enable NX-API over HTTPS", default=False)
    nxapi_http: bool = Field(alias="nxapiHttp", description="Enable NX-API over HTTP", default=False)
    nxapi_https_port: int = Field(alias="nxapiHttpsPort", description="HTTPS port for NX-API", ge=1, le=65535, default=443)
    nxapi_http_port: int = Field(alias="nxapiHttpPort", description="HTTP port for NX-API", ge=1, le=65535, default=80)

    # Bootstrap / Day-0 / DHCP
    day0_bootstrap: bool = Field(alias="day0Bootstrap", description="Automatic IP Assignment For POAP", default=False)
    bootstrap_subnet_collection: List[BootstrapSubnetModel] = Field(
        alias="bootstrapSubnetCollection", description="List of IPv4 or IPv6 subnets to be used for bootstrap", default_factory=list
    )
    local_dhcp_server: bool = Field(alias="localDhcpServer", description="Automatic IP Assignment For POAP From Local DHCP Server", default=False)
    dhcp_protocol_version: DhcpProtocolVersionEnum = Field(
        alias="dhcpProtocolVersion", description="IP protocol version for Local DHCP Server", default=DhcpProtocolVersionEnum.DHCPV4
    )
    dhcp_start_address: str = Field(alias="dhcpStartAddress", description="DHCP Scope Start Address For Switch POAP", default="")
    dhcp_end_address: str = Field(alias="dhcpEndAddress", description="DHCP Scope End Address For Switch POAP", default="")
    management_gateway: str = Field(alias="managementGateway", description="Default Gateway For Management VRF On The Switch", default="")
    management_ipv4_prefix: int = Field(alias="managementIpv4Prefix", description="Switch Mgmt IP Subnet Prefix if ipv4", default=24)
    management_ipv6_prefix: int = Field(alias="managementIpv6Prefix", description="Switch Management IP Subnet Prefix if ipv6", default=64)

    # Netflow Settings
    netflow_settings: NetflowSettingsModel = Field(alias="netflowSettings", description="Netflow configuration", default_factory=NetflowSettingsModel)

    # Backup / Restore
    real_time_backup: Optional[bool] = Field(
        alias="realTimeBackup", description=("Backup hourly only if there is any config deployment since last backup"), default=None
    )
    scheduled_backup: Optional[bool] = Field(alias="scheduledBackup", description="Enable backup at the specified time daily", default=None)
    scheduled_backup_time: str = Field(
        alias="scheduledBackupTime", description=("Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59)"), default=""
    )

    # VRF Lite / Sub-Interface
    sub_interface_dot1q_range: str = Field(
        alias="subInterfaceDot1qRange", description="Per aggregation dot1q range for VRF-Lite connectivity (minimum: 2, maximum: 4093)", default="2-511"
    )
    vrf_lite_auto_config: VrfLiteAutoConfigEnum = Field(
        alias="vrfLiteAutoConfig",
        description=(
            "VRF Lite Inter-Fabric Connection Deployment Options. If 'back2BackAndToExternal' is "
            "selected, VRF Lite IFCs are auto created between border devices of two Easy Fabrics, "
            "and between border devices in Easy Fabric and edge routers in External Fabric. "
            "The IP address is taken from the 'VRF Lite Subnet IP Range' pool."
        ),
        default=VrfLiteAutoConfigEnum.MANUAL,
    )
    vrf_lite_subnet_range: str = Field(alias="vrfLiteSubnetRange", description="Address range to assign P2P Interfabric Connections", default="10.33.0.0/16")
    vrf_lite_subnet_target_mask: int = Field(alias="vrfLiteSubnetTargetMask", description="VRF Lite Subnet Mask", default=30)
    auto_unique_vrf_lite_ip_prefix: bool = Field(
        alias="autoUniqueVrfLiteIpPrefix",
        description=(
            "When enabled, IP prefix allocated to the VRF LITE IFC is not reused on VRF extension "
            "over VRF LITE IFC. Instead, unique IP Subnet is allocated for each VRF extension "
            "over VRF LITE IFC."
        ),
        default=False,
    )

    # Leaf / TOR
    leaf_tor_id_range: bool = Field(alias="leafTorIdRange", description="Use specific vPC/Port-channel ID range for leaf-tor pairings", default=False)
    leaf_tor_vpc_port_channel_id_range: str = Field(
        alias="leafTorVpcPortChannelIdRange",
        description=(
            "Specify vPC/Port-channel ID range (minimum: 1, maximum: 4096), this range is used "
            "for auto-allocating vPC/Port-Channel IDs for leaf-tor pairings"
        ),
        default="1-499",
    )
    allow_vlan_on_leaf_tor_pairing: AllowVlanOnLeafTorPairingEnum = Field(
        alias="allowVlanOnLeafTorPairing",
        description="Set trunk allowed vlan to 'none' or 'all' for leaf-tor pairing port-channels",
        default=AllowVlanOnLeafTorPairingEnum.NONE,
    )

    # DNS / NTP / Syslog Collections
    ntp_server_collection: List[str] = Field(
        default_factory=lambda: ["string"], alias="ntpServerCollection", description="List of NTP server IPv4/IPv6 addresses and/or hostnames"
    )
    ntp_server_vrf_collection: List[str] = Field(
        default_factory=lambda: ["string"],
        alias="ntpServerVrfCollection",
        description=("NTP Server VRFs. One VRF for all NTP servers or a list of VRFs, one per NTP server"),
    )
    dns_collection: List[str] = Field(default_factory=lambda: ["5.192.28.174"], alias="dnsCollection", description="List of IPv4 and IPv6 DNS addresses")
    dns_vrf_collection: List[str] = Field(
        default_factory=lambda: ["string"],
        alias="dnsVrfCollection",
        description=("DNS Server VRFs. One VRF for all DNS servers or a list of VRFs, one per DNS server"),
    )
    syslog_server_collection: List[str] = Field(
        default_factory=lambda: ["string"], alias="syslogServerCollection", description="List of Syslog server IPv4/IPv6 addresses and/or hostnames"
    )
    syslog_server_vrf_collection: List[str] = Field(
        default_factory=lambda: ["string"],
        alias="syslogServerVrfCollection",
        description=("Syslog Server VRFs. One VRF for all Syslog servers or a list of VRFs, " "one per Syslog server"),
    )
    syslog_severity_collection: List[int] = Field(
        default_factory=lambda: [7], alias="syslogSeverityCollection", description="List of Syslog severity values, one per Syslog server"
    )

    # Extra Config / Pre-Interface Config / AAA / Banner
    banner: str = Field(
        description=("Message of the Day (motd) banner. Delimiter char (very first char is delimiter char) " "followed by message ending with delimiter"),
        default="",
    )
    extra_config_leaf: str = Field(
        alias="extraConfigLeaf",
        description=(
            "Additional CLIs as captured from the show running configuration, added after interface "
            "configurations for all switches with a VTEP unless they have some spine role"
        ),
        default="",
    )
    extra_config_spine: str = Field(
        alias="extraConfigSpine",
        description=(
            "Additional CLIs as captured from the show running configuration, added after interface " "configurations for all switches with some spine role"
        ),
        default="",
    )
    extra_config_tor: str = Field(
        alias="extraConfigTor",
        description=("Additional CLIs as captured from the show running configuration, added after interface " "configurations for all ToRs"),
        default="",
    )
    extra_config_intra_fabric_links: str = Field(alias="extraConfigIntraFabricLinks", description="Additional CLIs for all Intra-Fabric links", default="")
    extra_config_aaa: str = Field(alias="extraConfigAaa", description="AAA Configurations", default="")
    extra_config_nxos_bootstrap: str = Field(
        alias="extraConfigNxosBootstrap", description="Additional CLIs required during device bootup/login e.g. AAA/Radius", default=""
    )
    aaa: bool = Field(description="Include AAA configs from Manageability tab during device bootup", default=False)
    pre_interface_config_leaf: str = Field(
        alias="preInterfaceConfigLeaf",
        description=(
            "Additional CLIs as captured from the show running configuration, added before interface "
            "configurations for all switches with a VTEP unless they have some spine role"
        ),
        default="",
    )
    pre_interface_config_spine: str = Field(
        alias="preInterfaceConfigSpine",
        description=(
            "Additional CLIs as captured from the show running configuration, added before interface " "configurations for all switches with some spine role"
        ),
        default="",
    )
    pre_interface_config_tor: str = Field(
        alias="preInterfaceConfigTor",
        description=("Additional CLIs as captured from the show running configuration, added before interface " "configurations for all ToRs"),
        default="",
    )

    # System / Compliance / OAM / Misc
    greenfield_debug_flag: GreenfieldDebugFlagEnum = Field(
        alias="greenfieldDebugFlag",
        description=("Allow switch configuration to be cleared without a reload when " "preserveConfig is set to false"),
        default=GreenfieldDebugFlagEnum.DISABLE,
    )
    interface_statistics_load_interval: int = Field(
        alias="interfaceStatisticsLoadInterval", description="Interface Statistics Load Interval. Time in seconds", default=10
    )
    nve_hold_down_timer: int = Field(alias="nveHoldDownTimer", description="NVE Source Inteface HoldDown Time in seconds", default=180)
    next_generation_oam: bool = Field(
        alias="nextGenerationOAM",
        description=("Enable the Next Generation (NG) OAM feature for all switches in the fabric " "to aid in trouble-shooting VXLAN EVPN fabrics"),
        default=True,
    )
    ngoam_south_bound_loop_detect: bool = Field(
        alias="ngoamSouthBoundLoopDetect", description="Enable the Next Generation (NG) OAM southbound loop detection", default=False
    )
    ngoam_south_bound_loop_detect_probe_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectProbeInterval",
        description=("Set Next Generation (NG) OAM southbound loop detection probe interval in seconds."),
        default=300,
    )
    ngoam_south_bound_loop_detect_recovery_interval: int = Field(
        alias="ngoamSouthBoundLoopDetectRecoveryInterval",
        description=("Set the Next Generation (NG) OAM southbound loop detection recovery interval in seconds"),
        default=600,
    )
    strict_config_compliance_mode: bool = Field(
        alias="strictConfigComplianceMode",
        description=("Enable bi-directional compliance checks to flag additional configs in the running config " "that are not in the intent/expected config"),
        default=False,
    )
    advanced_ssh_option: bool = Field(
        alias="advancedSshOption",
        description=("Enable AAA IP Authorization.  Enable only, when IP Authorization is enabled " "in the AAA Server"),
        default=False,
    )
    copp_policy: CoppPolicyEnum = Field(
        alias="coppPolicy",
        description=("Fabric wide CoPP policy. Customized CoPP policy should be provided " "when 'manual' is selected."),
        default=CoppPolicyEnum.STRICT,
    )
    power_redundancy_mode: PowerRedundancyModeEnum = Field(
        alias="powerRedundancyMode", description="Default Power Supply Mode for NX-OS Switches", default=PowerRedundancyModeEnum.REDUNDANT
    )
    heartbeat_interval: int = Field(alias="heartbeatInterval", description="XConnect heartbeat interval for periodic link status checks", default=190)
    snmp_trap: bool = Field(alias="snmpTrap", description="Configure ND as a receiver for SNMP traps", default=True)
    cdp: bool = Field(description="Enable CDP on management interface", default=False)
    real_time_interface_statistics_collection: bool = Field(
        alias="realTimeInterfaceStatisticsCollection", description="Enable Real Time Interface Statistics Collection. Valid for NX-OS only", default=False
    )
    tcam_allocation: bool = Field(
        alias="tcamAllocation", description=("TCAM commands are automatically generated for VxLAN and vPC Fabric Peering when Enabled"), default=True
    )
    allow_smart_switch_onboarding: bool = Field(
        alias="allowSmartSwitchOnboarding", description="Enable onboarding of smart switches to Hypershield for firewall service", default=False
    )

    # Queuing / QoS
    default_queuing_policy: bool = Field(alias="defaultQueuingPolicy", description="Enable Default Queuing Policies", default=False)
    default_queuing_policy_cloudscale: str = Field(
        alias="defaultQueuingPolicyCloudscale",
        description=("Queuing Policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX series switches in the fabric"),
        default="queuing_policy_default_8q_cloudscale",
    )
    default_queuing_policy_r_series: str = Field(
        alias="defaultQueuingPolicyRSeries", description="Queueing policy for all Nexus R-series switches", default="queuing_policy_default_r_series"
    )
    default_queuing_policy_other: str = Field(
        alias="defaultQueuingPolicyOther", description="Queuing Policy for all other switches in the fabric", default="queuing_policy_default_other"
    )
    aiml_qos: bool = Field(
        alias="aimlQos",
        description=("Configures QoS and Queuing Policies specific to N9K Cloud Scale (CS) & Silicon One (S1) " "switch fabric for AI network workloads"),
        default=False,
    )
    aiml_qos_policy: AimlQosPolicyEnum = Field(
        alias="aimlQosPolicy",
        description=("Queuing Policy based on predominant fabric link speed: 800G / 400G / 100G / 25G. " "User-defined allows for custom configuration."),
        default=AimlQosPolicyEnum.V_400G,
    )
    roce_v2: str = Field(
        alias="roceV2",
        description=(
            "DSCP for RDMA traffic: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,"
            "cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default="26",
    )
    cnp: str = Field(
        description=(
            "DSCP value for Congestion Notification: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,"
            "cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default="48",
    )
    wred_min: int = Field(alias="wredMin", description="WRED minimum threshold (in kbytes)", default=950)
    wred_max: int = Field(alias="wredMax", description="WRED maximum threshold (in kbytes)", default=3000)
    wred_drop_probability: int = Field(alias="wredDropProbability", description="Drop probability %", default=7)
    wred_weight: int = Field(alias="wredWeight", description="Influences how quickly WRED reacts to queue depth changes", default=0)
    bandwidth_remaining: int = Field(alias="bandwidthRemaining", description="Percentage of remaining bandwidth allocated to AI traffic queues", default=50)
    dlb: bool = Field(
        description=(
            "Enables fabric-level Dynamic Load Balancing (DLB) configuration. " "Note: Inter-Switch-Links (ISL) will be configured as DLB Interfaces"
        ),
        default=False,
    )
    dlb_mode: DlbModeEnum = Field(
        alias="dlbMode",
        description=(
            "Select system-wide flowlet, per-packet (packet spraying) or policy driven mixed mode. "
            "Note: Mixed mode is supported on Silicon One (S1) platform only."
        ),
        default=DlbModeEnum.FLOWLET,
    )
    dlb_mixed_mode_default: DlbMixedModeDefaultEnum = Field(
        alias="dlbMixedModeDefault", description="Default load balancing mode for policy driven mixed mode DLB", default=DlbMixedModeDefaultEnum.ECMP
    )
    flowlet_aging: Optional[int] = Field(
        alias="flowletAging",
        description=(
            "Flowlet aging timer in microseconds. Valid range depends on platform: "
            "Cloud Scale (CS)=1-2000000 (default 500), Silicon One (S1)=1-1024 (default 256)"
        ),
        default=None,
    )
    flowlet_dscp: str = Field(
        alias="flowletDscp",
        description=(
            "DSCP values for flowlet load balancing: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,"
            "cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default="",
    )
    per_packet_dscp: str = Field(
        alias="perPacketDscp",
        description=(
            "DSCP values for per-packet load balancing: numeric (0-63) with ranges/comma, named values "
            "(af11,af12,af13,af21,af22,af23,af31,af32,af33,af41,af42,af43,"
            "cs1,cs2,cs3,cs4,cs5,cs6,cs7,default,ef)"
        ),
        default="",
    )
    ai_load_sharing: bool = Field(
        alias="aiLoadSharing", description=("Enable IP load sharing using source and destination address for AI workloads"), default=False
    )
    priority_flow_control_watch_interval: Optional[int] = Field(
        alias="priorityFlowControlWatchInterval",
        description=("Acceptable values from 101 to 1000 (milliseconds).  " "Leave blank for system default (100ms)."),
        default=None,
    )

    # PTP
    ptp: bool = Field(description="Enable Precision Time Protocol (PTP)", default=False)
    ptp_loopback_id: int = Field(alias="ptpLoopbackId", description="Precision Time Protocol Source Loopback Id", default=0)
    ptp_domain_id: int = Field(alias="ptpDomainId", description="Multiple Independent PTP Clocking Subdomains on a Single Network", default=0)

    # Private VLAN
    private_vlan: bool = Field(alias="privateVlan", description="Enable PVLAN on switches except spines and super spines", default=False)
    default_private_vlan_secondary_network_template: str = Field(
        alias="defaultPrivateVlanSecondaryNetworkTemplate", description="Default PVLAN secondary network template", default="Pvlan_Secondary_Network"
    )

    # MACsec
    macsec: bool = Field(
        description=(
            "Enable MACsec in the fabric. MACsec fabric parameters are used for configuring " "MACsec on a fabric link if MACsec is enabled on the link."
        ),
        default=False,
    )
    macsec_cipher_suite: MacsecCipherSuiteEnum = Field(
        alias="macsecCipherSuite", description="Configure Cipher Suite", default=MacsecCipherSuiteEnum.GCM_AES_XPN_256
    )
    macsec_key_string: str = Field(alias="macsecKeyString", description="MACsec Primary Key String.  Cisco Type 7 Encrypted Octet String", default="")
    macsec_algorithm: MacsecAlgorithmEnum = Field(
        alias="macsecAlgorithm", description="MACsec Primary Cryptographic Algorithm.  AES_128_CMAC or AES_256_CMAC", default=MacsecAlgorithmEnum.AES_128_CMAC
    )
    macsec_fallback_key_string: str = Field(
        alias="macsecFallbackKeyString", description="MACsec Fallback Key String. Cisco Type 7 Encrypted Octet String", default=""
    )
    macsec_fallback_algorithm: MacsecAlgorithmEnum = Field(
        alias="macsecFallbackAlgorithm",
        description="MACsec Fallback Cryptographic Algorithm.  AES_128_CMAC or AES_256_CMAC",
        default=MacsecAlgorithmEnum.AES_128_CMAC,
    )
    macsec_report_timer: int = Field(alias="macsecReportTimer", description="MACsec Operational Status periodic report timer in minutes", default=5)

    # Hypershield / Connectivity
    enable_dpu_pinning: bool = Field(
        alias="enableDpuPinning", description="Enable pinning of VRFs and networks to specific DPUs on smart switches", default=False
    )
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
    def validate_bgp_asn(cls, value: Optional[str]) -> Optional[str]:
        """
        # Summary

        Validate BGP ASN format and range when provided.

        ## Raises

        - `ValueError` - If value does not match the expected ASN format
        """
        if value is None:
            return value
        if not BGP_ASN_RE.match(value):
            raise ValueError(f"Invalid BGP ASN '{value}'. " "Expected a plain integer (1-4294967295) or dotted notation (1-65535.0-65535).")
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
        mac_pattern = re.compile(r"^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$")
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

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

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
    telemetry_settings: Optional[TelemetrySettingsModel] = Field(alias="telemetrySettings", description="Telemetry configuration", default=None)
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings", description="External streaming settings", default_factory=ExternalStreamingSettingsModel
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
        if not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise ValueError(f"Fabric name can only contain letters, numbers, underscores, and hyphens, got: {value}")
        return value

    @model_validator(mode="after")
    def validate_fabric_consistency(self) -> "FabricEbgpModel":
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

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, excluding fields that ND overrides for eBGP fabrics."""
        d = super().to_diff_dict(**kwargs)
        # ND always returns nxapiHttp=True for eBGP fabrics regardless of the configured value,
        # so exclude it from diff comparison to prevent a persistent false-positive diff.
        if "management" in d:
            d["management"].pop("nxapiHttp", None)
        return d

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
    "VxlanEbgpManagementModel",
    "FabricEbgpModel",
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
