#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2025 Cisco and/or its affiliates."
__author__ = "Mike Wiebe"

DOCUMENTATION = """

---
module: nd_manage_fabric
short_description: Manage fabrics in Cisco Nexus Dashboard.
version_added: "1.0.0"
author: Mike Wiebe (@mikewiebe)
description:
- Create, update, delete, override, and query fabrics in Cisco Nexus Dashboard.
- Supports Pydantic model validation for fabric configurations.
- Provides utility functions for merging models and handling default values.
- Uses state-based operations with intelligent diff calculation for optimal API calls.
options:
    state:
        choices:
        - merged
        - replaced
        - deleted
        - overridden
        - query
        default: merged
        description:
        - The state of the fabric configuration after module completion.
        type: str
    config:
        description:
        - A list of fabric configuration dictionaries.
        type: list
        elements: dict
        suboptions:
            name:
                description:
                - Name of the fabric. Must start with a letter and contain only alphanumeric characters, underscores, or hyphens.
                required: true
                type: str
            alert_suspend:
                description:
                - Alert suspension setting for the fabric.
                type: str
                default: disabled
            category:
                description:
                - Category of the fabric.
                type: str
                default: fabric
            security_domain:
                description:
                - Security domain for the fabric.
                type: str
                default: all
            location:
                description:
                - Geographic location settings for the fabric.
                type: dict
                suboptions:
                    latitude:
                        description:
                        - The latitude coordinate.
                        type: float
                        default: 0.0
                    longitude:
                        description:
                        - The longitude coordinate.
                        type: float
                        default: 0.0
            management:
                description:
                - Management configuration for the fabric.
                type: dict
                suboptions:
                    type:
                        description:
                        - Management type for the fabric.
                        type: str
                        choices:
                        - vxlanIbgp
                        - vxlanEbgp
                        - vxlanCampus
                        - aimlVxlanIbgp
                        - aimlVxlanEbgp
                        - aimlRouted
                        - routed
                        - classicLan
                        - classicLanEnhanced
                        - ipfm
                        - ipfmEnhanced
                        - externalConnectivity
                        - vxlanExternal
                        - aci
                        - meta
                        default: vxlanIbgp
                    bgp_asn:
                        description:
                        - BGP autonomous system number. Must be a valid ASN string (plain or dotted notation).
                        required: true
                        type: str
                    anycast_gateway_mac:
                        description:
                        - Anycast gateway MAC address in Cisco format (XXXX.XXXX.XXXX).
                        type: str
                        default: 2020.0000.00aa
                    replication_mode:
                        description:
                        - Replication mode for the fabric.
                        type: str
                        choices:
                        - multicast
                        - ingress
                        default: multicast
                    vrf_lite_auto_config:
                        description:
                        - VRF Lite Inter-Fabric Connection Deployment mode.
                        type: str
                        choices:
                        - manual
                        - back2Back&ToExternal
                        default: manual
                    bgp_authentication_key_type:
                        description:
                        - BGP Authentication Key Type for encryption.
                        type: str
                        choices:
                        - 3des
                        - type6
                        - type7
                        default: 3des
                    fabric_interface_type:
                        description:
                        - Fabric interface type for numbered (Point-to-Point) or unnumbered interfaces.
                        type: str
                        choices:
                        - p2p
                        - unNumbered
                        default: p2p
                    link_state_routing_protocol:
                        description:
                        - Underlay routing protocol for Spine-Leaf connectivity.
                        type: str
                        choices:
                        - ospf
                        - is-is
                        default: ospf
                    overlay_mode:
                        description:
                        - Overlay mode for VRF/Network configuration.
                        type: str
                        choices:
                        - configProfile
                        - cli
                        default: cli
                    power_redundancy_mode:
                        description:
                        - Default power supply mode for NX-OS switches.
                        type: str
                        choices:
                        - redundant
                        - combined
                        - inputSrcRedundant
                        default: redundant
                    rendezvous_point_mode:
                        description:
                        - Multicast rendezvous point mode. For IPv6 underlay, use ASM only.
                        type: str
                        choices:
                        - asm
                        - bidir
                        default: asm
                    isis_level:
                        description:
                        - IS-IS level configuration.
                        type: str
                        choices:
                        - level-1
                        - level-2
                        default: level-2
                    stp_root_option:
                        description:
                        - Protocol for configuring root bridge.
                        type: str
                        choices:
                        - rpvst+
                        - mst
                        - unmanaged
                        default: unmanaged
                    vpc_peer_keep_alive_option:
                        description:
                        - vPC peer keep alive option using loopback or management interfaces.
                        type: str
                        choices:
                        - loopback
                        - management
                        default: management
                    allow_vlan_on_leaf_tor_pairing:
                        description:
                        - Trunk allowed VLAN setting for leaf-tor pairing port-channels.
                        type: str
                        choices:
                        - none
                        - all
                        default: none
                    aiml_qos_policy:
                        description:
                        - Queuing policy based on predominant fabric link speed for AI/ML network loads.
                        type: str
                        choices:
                        - 800G
                        - 400G
                        - 100G
                        - 25G
                        default: 400G
                    greenfield_debug_flag:
                        description:
                        - Allow switch configuration to be cleared without a reload when preserveConfig is false.
                        type: str
                        choices:
                        - enable
                        - disable
                        default: disable
                    copp_policy:
                        description:
                        - Fabric wide CoPP (Control Plane Policing) policy. Customized CoPP policy should be provided when 'manual' is selected.
                        type: str
                        choices:
                        - dense
                        - lenient
                        - moderate
                        - strict
                        - manual
                        default: strict
                    # VPC and peering settings
                    vpc_layer3_peer_router:
                        description:
                        - Enable vPC layer 3 peer router functionality.
                        type: bool
                        default: true
                    vpc_peer_link_port_channel_id:
                        description:
                        - vPC peer link port channel ID.
                        type: str
                        default: "500"
                    vpc_peer_link_vlan:
                        description:
                        - vPC peer link VLAN.
                        type: str
                        default: "3600"
                    vpc_domain_id_range:
                        description:
                        - vPC domain ID range.
                        type: str
                        default: "1-1000"
                    vpc_delay_restore_timer:
                        description:
                        - vPC delay restore timer in seconds.
                        type: int
                        default: 150
                    vpc_auto_recovery_timer:
                        description:
                        - vPC auto recovery timer in seconds.
                        type: int
                        default: 360
                    vpc_tor_delay_restore_timer:
                        description:
                        - vPC ToR delay restore timer in seconds.
                        type: int
                        default: 30
                    vpc_ipv6_neighbor_discovery_sync:
                        description:
                        - Enable vPC IPv6 neighbor discovery sync.
                        type: bool
                        default: true
                    vpc_peer_link_enable_native_vlan:
                        description:
                        - Enable native VLAN on vPC peer link.
                        type: bool
                        default: false
                    fabric_vpc_qos:
                        description:
                        - Enable fabric vPC QoS.
                        type: bool
                        default: false
                    fabric_vpc_qos_policy_name:
                        description:
                        - Fabric vPC QoS policy name.
                        type: str
                        default: spine_qos_for_fabric_vpc_peering
                    fabric_vpc_domain_id:
                        description:
                        - Enable fabric vPC domain ID.
                        type: bool
                        default: false
                    # VNI and VLAN ranges
                    l3_vni_range:
                        description:
                        - Layer 3 VNI range.
                        type: str
                        default: "50000-59000"
                    l2_vni_range:
                        description:
                        - Layer 2 VNI range.
                        type: str
                        default: "30000-49000"
                    vrf_vlan_range:
                        description:
                        - VRF VLAN range.
                        type: str
                        default: "2000-2299"
                    network_vlan_range:
                        description:
                        - Network VLAN range.
                        type: str
                        default: "2300-2999"
                    service_network_vlan_range:
                        description:
                        - Service network VLAN range.
                        type: str
                        default: "3000-3199"
                    # BGP settings
                    bgp_loopback_id:
                        description:
                        - BGP loopback interface ID.
                        type: int
                        default: 0
                    bgp_loopback_ip_range:
                        description:
                        - BGP loopback IP range.
                        type: str
                        default: "10.2.0.0/22"
                    bgp_authentication:
                        description:
                        - Enable BGP authentication.
                        type: bool
                        default: false
                    auto_bgp_neighbor_description:
                        description:
                        - Enable automatic BGP neighbor description.
                        type: bool
                        default: true
                    # NVE settings
                    nve_loopback_id:
                        description:
                        - NVE loopback interface ID.
                        type: int
                        default: 1
                    nve_loopback_ip_range:
                        description:
                        - NVE loopback IP range.
                        type: str
                        default: "10.3.0.0/22"
                    nve_hold_down_timer:
                        description:
                        - NVE hold down timer in seconds.
                        type: int
                        default: 180
                    # IPv6 settings
                    underlay_ipv6:
                        description:
                        - Enable IPv6 underlay.
                        type: bool
                        default: false
                    ipv6_link_local:
                        description:
                        - Enable IPv6 link local addressing.
                        type: bool
                        default: true
                    ipv6_subnet_target_mask:
                        description:
                        - IPv6 subnet target mask length.
                        type: int
                        default: 126
                    # VRF settings
                    vrf_template:
                        description:
                        - VRF template name.
                        type: str
                        default: Default_VRF_Universal
                    vrf_extension_template:
                        description:
                        - VRF extension template name.
                        type: str
                        default: Default_VRF_Extension_Universal
                    vrf_lite_subnet_range:
                        description:
                        - VRF lite subnet range.
                        type: str
                        default: "10.33.0.0/16"
                    vrf_lite_subnet_target_mask:
                        description:
                        - VRF lite subnet target mask length.
                        type: int
                        default: 30
                    vrf_lite_ipv6_subnet_range:
                        description:
                        - VRF lite IPv6 subnet range.
                        type: str
                        default: "fd00::a33:0/112"
                    vrf_lite_ipv6_subnet_target_mask:
                        description:
                        - VRF lite IPv6 subnet target mask length.
                        type: int
                        default: 126
                    vrf_lite_macsec:
                        description:
                        - Enable VRF lite MACSec.
                        type: bool
                        default: false
                    auto_unique_vrf_lite_ip_prefix:
                        description:
                        - Enable automatic unique VRF lite IP prefix.
                        type: bool
                        default: false
                    auto_symmetric_vrf_lite:
                        description:
                        - Enable automatic symmetric VRF lite.
                        type: bool
                        default: false
                    auto_symmetric_default_vrf:
                        description:
                        - Enable automatic symmetric default VRF.
                        type: bool
                        default: false
                    auto_vrf_lite_default_vrf:
                        description:
                        - Enable automatic VRF lite default VRF.
                        type: bool
                        default: false
                    vrf_route_import_id_reallocation:
                        description:
                        - Enable VRF route import ID reallocation.
                        type: bool
                        default: false
                    per_vrf_loopback_auto_provision:
                        description:
                        - Enable per VRF loopback auto provision.
                        type: bool
                        default: false
                    per_vrf_loopback_auto_provision_ipv6:
                        description:
                        - Enable per VRF loopback auto provision for IPv6.
                        type: bool
                        default: false
                    # Network settings
                    network_template:
                        description:
                        - Network template name.
                        type: str
                        default: Default_Network_Universal
                    network_extension_template:
                        description:
                        - Network extension template name.
                        type: str
                        default: Default_Network_Extension_Universal
                    brownfield_network_name_format:
                        description:
                        - Brownfield network name format.
                        type: str
                        default: Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$
                    brownfield_skip_overlay_network_attachments:
                        description:
                        - Skip overlay network attachments in brownfield deployments.
                        type: bool
                        default: false
                    # Fabric interface and underlay settings
                    fabric_mtu:
                        description:
                        - Fabric MTU size.
                        type: int
                        default: 9216
                    l2_host_interface_mtu:
                        description:
                        - Layer 2 host interface MTU size.
                        type: int
                        default: 9216
                    target_subnet_mask:
                        description:
                        - Target subnet mask length.
                        type: int
                        default: 30
                    intra_fabric_subnet_range:
                        description:
                        - Intra-fabric subnet range.
                        type: str
                        default: "10.4.0.0/16"
                    static_underlay_ip_allocation:
                        description:
                        - Enable static underlay IP allocation.
                        type: bool
                        default: false
                    # OSPF settings
                    ospf_area_id:
                        description:
                        - OSPF area ID.
                        type: str
                        default: "0.0.0.0"
                    ospf_authentication:
                        description:
                        - Enable OSPF authentication.
                        type: bool
                        default: false
                    link_state_routing_tag:
                        description:
                        - Link state routing tag.
                        type: str
                        default: UNDERLAY
                    # ISIS settings
                    isis_area_number:
                        description:
                        - ISIS area number.
                        type: str
                        default: "0001"
                    isis_authentication:
                        description:
                        - Enable ISIS authentication.
                        type: bool
                        default: false
                    mpls_isis_area_number:
                        description:
                        - MPLS ISIS area number.
                        type: str
                        default: "0001"
                    # BFD settings
                    bfd:
                        description:
                        - Enable BFD (Bidirectional Forwarding Detection).
                        type: bool
                        default: false
                    bfd_pim:
                        description:
                        - Enable BFD for PIM.
                        type: bool
                        default: false
                    bfd_isis:
                        description:
                        - Enable BFD for ISIS.
                        type: bool
                        default: false
                    bfd_ospf:
                        description:
                        - Enable BFD for OSPF.
                        type: bool
                        default: false
                    bfd_ibgp:
                        description:
                        - Enable BFD for iBGP.
                        type: bool
                        default: false
                    bfd_authentication:
                        description:
                        - Enable BFD authentication.
                        type: bool
                        default: false
                    # Multicast settings
                    anycast_rendezvous_point_ip_range:
                        description:
                        - Anycast rendezvous point IP range.
                        type: str
                        default: "10.254.254.0/24"
                    rendezvous_point_count:
                        description:
                        - Number of rendezvous points.
                        type: int
                        default: 2
                    rendezvous_point_loopback_id:
                        description:
                        - Rendezvous point loopback interface ID.
                        type: int
                        default: 254
                    multicast_group_subnet:
                        description:
                        - Multicast group subnet.
                        type: str
                        default: "239.1.1.0/25"
                    auto_generate_multicast_group_address:
                        description:
                        - Enable automatic multicast group address generation.
                        type: bool
                        default: false
                    underlay_multicast_group_address_limit:
                        description:
                        - Underlay multicast group address limit.
                        type: int
                        default: 128
                    tenant_routed_multicast:
                        description:
                        - Enable tenant routed multicast.
                        type: bool
                        default: false
                    tenant_routed_multicast_ipv6:
                        description:
                        - Enable tenant routed multicast for IPv6.
                        type: bool
                        default: false
                    # Security and authentication
                    security_group_tag:
                        description:
                        - Enable security group tag.
                        type: bool
                        default: false
                    macsec:
                        description:
                        - Enable MACSec encryption.
                        type: bool
                        default: false
                    pim_hello_authentication:
                        description:
                        - Enable PIM hello authentication.
                        type: bool
                        default: false
                    # PTP and timing
                    ptp:
                        description:
                        - Enable PTP (Precision Time Protocol).
                        type: bool
                        default: false
                    # Management and monitoring
                    real_time_backup:
                        description:
                        - Enable real-time backup.
                        type: bool
                        default: true
                    scheduled_backup:
                        description:
                        - Enable scheduled backup.
                        type: bool
                        default: true
                    scheduled_backup_time:
                        description:
                        - Scheduled backup time in HH:MM format.
                        type: str
                        default: "21:38"
                    real_time_interface_statistics_collection:
                        description:
                        - Enable real-time interface statistics collection.
                        type: bool
                        default: false
                    performance_monitoring:
                        description:
                        - Enable performance monitoring.
                        type: bool
                        default: false
                    strict_config_compliance_mode:
                        description:
                        - Enable strict configuration compliance mode.
                        type: bool
                        default: false
                    # System settings
                    site_id:
                        description:
                        - Site ID for the fabric.
                        type: str
                        default: "4225625065"
                    heartbeat_interval:
                        description:
                        - Heartbeat interval in seconds.
                        type: int
                        default: 190
                    # QoS and queuing
                    default_queuing_policy:
                        description:
                        - Enable default queuing policy.
                        type: bool
                        default: false
                    default_queuing_policy_other:
                        description:
                        - Default queuing policy for other switch types.
                        type: str
                        default: queuing_policy_default_other
                    default_queuing_policy_cloudscale:
                        description:
                        - Default queuing policy for cloudscale switches.
                        type: str
                        default: queuing_policy_default_8q_cloudscale
                    default_queuing_policy_r_series:
                        description:
                        - Default queuing policy for R-series switches.
                        type: str
                        default: queuing_policy_default_r_series
                    aiml_qos:
                        description:
                        - Enable AI/ML QoS optimization.
                        type: bool
                        default: false
                    # DHCP and AAA
                    tenant_dhcp:
                        description:
                        - Enable tenant DHCP.
                        type: bool
                        default: true
                    local_dhcp_server:
                        description:
                        - Enable local DHCP server.
                        type: bool
                        default: false
                    aaa:
                        description:
                        - Enable AAA (Authentication, Authorization, and Accounting).
                        type: bool
                        default: false
                    # Protocol settings
                    cdp:
                        description:
                        - Enable CDP (Cisco Discovery Protocol).
                        type: bool
                        default: false
                    nxapi:
                        description:
                        - Enable NX-API.
                        type: bool
                        default: false
                    nxapi_http:
                        description:
                        - Enable NX-API HTTP.
                        type: bool
                        default: true
                    nxapi_http_port:
                        description:
                        - NX-API HTTP port number.
                        type: int
                        default: 80
                    nxapi_https_port:
                        description:
                        - NX-API HTTPS port number.
                        type: int
                        default: 443
                    snmp_trap:
                        description:
                        - Enable SNMP trap.
                        type: bool
                        default: true
                    # Overlay and EVPN settings
                    route_reflector_count:
                        description:
                        - Number of route reflectors.
                        type: int
                        default: 2
                    advertise_physical_ip:
                        description:
                        - Advertise physical IP addresses.
                        type: bool
                        default: false
                    advertise_physical_ip_on_border:
                        description:
                        - Advertise physical IP on border devices.
                        type: bool
                        default: true
                    anycast_border_gateway_advertise_physical_ip:
                        description:
                        - Advertise physical IP on anycast border gateway.
                        type: bool
                        default: false
                    # VLAN and interface ranges
                    sub_interface_dot1q_range:
                        description:
                        - Sub-interface dot1q range.
                        type: str
                        default: "2-511"
                    object_tracking_number_range:
                        description:
                        - Object tracking number range.
                        type: str
                        default: "100-299"
                    route_map_sequence_number_range:
                        description:
                        - Route map sequence number range.
                        type: str
                        default: "1-65534"
                    ip_service_level_agreement_id_range:
                        description:
                        - IP Service Level Agreement ID range.
                        type: str
                        default: "10000-19999"
                    # Private VLAN
                    private_vlan:
                        description:
                        - Enable private VLAN.
                        type: bool
                        default: false
                    # Advanced features
                    policy_based_routing:
                        description:
                        - Enable policy-based routing.
                        type: bool
                        default: false
                    tcam_allocation:
                        description:
                        - Enable TCAM allocation.
                        type: bool
                        default: true
                    l3_vni_no_vlan_default_option:
                        description:
                        - Enable L3 VNI no VLAN default option.
                        type: bool
                        default: false
                    host_interface_admin_state:
                        description:
                        - Host interface administrative state.
                        type: bool
                        default: true
                    # Routing and STP
                    leaf_to_r_id_range:
                        description:
                        - Enable leaf to router ID range.
                        type: bool
                        default: false
                    # Bootstrap and day0
                    day0_bootstrap:
                        description:
                        - Enable day 0 bootstrap.
                        type: bool
                        default: false
                    bootstrap_multi_subnet:
                        description:
                        - Bootstrap multi-subnet configuration.
                        type: str
                        default: "#Scope_Start_IP, Scope_End_IP, Scope_Default_Gateway, Scope_Subnet_Prefix"
                    # OAM and debugging
                    next_generation_oam:
                        description:
                        - Enable next generation OAM.
                        type: bool
                        default: true
                    ngoam_south_bound_loop_detect:
                        description:
                        - Enable NGOAM south bound loop detection.
                        type: bool
                        default: false
                    # MPLS
                    mpls_handoff:
                        description:
                        - Enable MPLS handoff.
                        type: bool
                        default: false
                    # In-band management
                    inband_management:
                        description:
                        - Enable in-band management.
                        type: bool
                        default: false
                    # SSH
                    advanced_ssh_option:
                        description:
                        - Enable advanced SSH options.
                        type: bool
                        default: false
                    # Server collections
                    ntp_server_collection:
                        description:
                        - List of NTP servers.
                        type: list
                        elements: str
                        default: ["string"]
                    ntp_server_vrf_collection:
                        description:
                        - List of NTP server VRFs.
                        type: list
                        elements: str
                        default: ["string"]
                    dns_collection:
                        description:
                        - List of DNS servers.
                        type: list
                        elements: str
                        default: ["5.192.28.174"]
                    dns_vrf_collection:
                        description:
                        - List of DNS server VRFs.
                        type: list
                        elements: str
                        default: ["string"]
                    syslog_server_collection:
                        description:
                        - List of syslog servers.
                        type: list
                        elements: str
                        default: ["string"]
                    syslog_server_vrf_collection:
                        description:
                        - List of syslog server VRFs.
                        type: list
                        elements: str
                        default: ["string"]
                    syslog_severity_collection:
                        description:
                        - List of syslog severity levels.
                        type: list
                        elements: str
                        default: ["7"]
                    # Extra configuration sections
                    extra_config_leaf:
                        description:
                        - Extra configuration for leaf switches.
                        type: str
                        default: string
                    extra_config_spine:
                        description:
                        - Extra configuration for spine switches.
                        type: str
                        default: string
                    extra_config_tor:
                        description:
                        - Extra configuration for ToR switches.
                        type: str
                        default: string
                    extra_config_aaa:
                        description:
                        - Extra AAA configuration.
                        type: str
                        default: string
                    extra_config_intra_fabric_links:
                        description:
                        - Extra configuration for intra-fabric links.
                        type: str
                        default: string
                    pre_interface_config_leaf:
                        description:
                        - Pre-interface configuration for leaf switches.
                        type: str
                        default: string
                    pre_interface_config_spine:
                        description:
                        - Pre-interface configuration for spine switches.
                        type: str
                        default: string
                    pre_interface_config_tor:
                        description:
                        - Pre-interface configuration for ToR switches.
                        type: str
                        default: string
                    # Netflow settings
                    netflow_settings:
                        description:
                        - Netflow monitoring configuration.
                        type: dict
"""

EXAMPLES = """
# Create a new fabric with basic VXLAN iBGP configuration
- name: Create basic VXLAN iBGP fabric
  cisco.nd.nd_manage_fabric:
    state: merged
    config:
      - name: example-fabric
        category: fabric
        security_domain: default
        management:
          type: vxlanIbgp
          bgp_asn: "65001"
          anycast_gateway_mac: "2020.0000.00aa"
          replication_mode: multicast

# Create a comprehensive fabric with advanced settings
- name: Create comprehensive fabric with advanced settings
  cisco.nd.nd_manage_fabric:
    state: merged
    config:
      - name: advanced-fabric
        category: fabric
        security_domain: all
        location:
          latitude: 37.7749
          longitude: -122.4194
        management:
          type: vxlanIbgp
          bgp_asn: "65001"
          anycast_gateway_mac: "2020.0000.00aa"
          replication_mode: multicast
          fabric_interface_type: p2p
          link_state_routing_protocol: ospf
          overlay_mode: cli
          power_redundancy_mode: redundant
          rendezvous_point_mode: asm
          isis_level: level-2
          stp_root_option: unmanaged
          vpc_peer_keep_alive_option: management
          allow_vlan_on_leaf_tor_pairing: none
          aiml_qos_policy: 400G
          greenfield_debug_flag: disable
          copp_policy: strict
          bgp_authentication: true
          bgp_authentication_key_type: 3des
          bfd: true
          bfd_ibgp: true
          macsec: false
          ptp: false
          real_time_backup: true
          performance_monitoring: true

# Create AI/ML optimized fabric
- name: Create AI/ML optimized fabric
  cisco.nd.nd_manage_fabric:
    state: merged
    config:
      - name: aiml-fabric
        category: fabric
        security_domain: all
        management:
          type: aimlVxlanIbgp
          bgp_asn: "65100"
          anycast_gateway_mac: "2020.0000.00ab"
          replication_mode: ingress
          aiml_qos: true
          aiml_qos_policy: 800G
          fabric_mtu: 9216
          l2_host_interface_mtu: 9216
          default_queuing_policy: true
          tenant_routed_multicast: true
          security_group_tag: true

# Replace existing fabric configuration
- name: Replace fabric configuration
  cisco.nd.nd_manage_fabric:
    state: replaced
    config:
      - name: example-fabric
        category: fabric
        security_domain: default
        management:
          type: vxlanEbgp
          bgp_asn: "65002"
          anycast_gateway_mac: "2020.0000.00ac"
          replication_mode: ingress
          fabric_interface_type: unNumbered
          link_state_routing_protocol: is-is
          isis_level: level-1

# Delete a fabric
- name: Delete fabric
  cisco.nd.nd_manage_fabric:
    state: deleted
    config:
      - name: example-fabric

# Query existing fabrics
- name: Query all fabrics
  cisco.nd.nd_manage_fabric:
    state: query

# Query specific fabric
- name: Query specific fabric
  cisco.nd.nd_manage_fabric:
    state: query
    config:
      - name: example-fabric

# Override fabric configurations (replace all with specified configs)
- name: Override all fabric configurations
  cisco.nd.nd_manage_fabric:
    state: overridden
    config:
      - name: production-fabric
        category: fabric
        security_domain: all
        management:
          type: vxlanIbgp
          bgp_asn: "65000"
          anycast_gateway_mac: "2020.0000.0001"
          replication_mode: multicast
          strict_config_compliance_mode: true
          real_time_backup: true
          scheduled_backup: true
          scheduled_backup_time: "02:00"
      - name: development-fabric
        category: fabric
        security_domain: dev
        management:
          type: vxlanEbgp
          bgp_asn: "65100"
          anycast_gateway_mac: "2020.0000.0002"
          replication_mode: ingress
          greenfield_debug_flag: enable
"""
import copy
import inspect
import logging
import re
import traceback
import sys
import json

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
from ansible.module_utils.basic import missing_required_lib

from ..module_utils.common.log import Log
from ..module_utils.common.models import merge_models, model_payload_with_defaults

from ansible_collections.cisco.nd.plugins.module_utils.manage.fabric.model_playbook_fabric import FabricModel

# try:
#     from pydantic import BaseModel
# except ImportError:
#     HAS_PYDANTIC = False
#     PYDANTIC_IMPORT_ERROR = traceback.format_exc()
# else:
#     HAS_PYDANTIC = True
#     PYDANTIC_IMPORT_ERROR = None

try:
    from deepdiff import DeepDiff
except ImportError:
    HAS_DEEPDIFF = False
    DEEPDIFF_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_DEEPDIFF = True
    DEEPDIFF_IMPORT_ERROR = None


class GetHave:
    """
    Class to retrieve and process fabric state information from Nexus Dashboard (ND).

    This class handles the retrieval of fabric state information from the Nexus Dashboard
    API and processes the response into a list of FabricModel objects.

    Attributes:
        class_name (str): Name of the class.
        log (Logger): Logger instance for this class.
        path (str): API endpoint path for fabric information.
        verb (str): HTTP method used for the request (GET).
        fabric_state (dict): Raw fabric state data retrieved from ND.
        have (list): List of processed FabricModel objects.
        nd: Nexus Dashboard instance for making API requests.

    Methods:
        refresh(): Fetches the current fabric state from Nexus Dashboard.
        validate_nd_state(): Processes the fabric state data into FabricModel objects.
    """

    def __init__(self, nd, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.path = "/api/v1/manage/fabrics"
        self.verb = "GET"
        self.fabric_state = {}
        self.have = []
        self.nd = nd

        msg = "ENTERED GetHave(): "
        self.log.debug(msg)

    def refresh(self):
        """
        Refreshes the fabric state by fetching the latest data from the ND API.

        This method updates the internal fabric_state attribute with fresh data
        retrieved from the network controller using the configured path and HTTP verb.

        Returns:
            None: Updates the self.fabric_state attribute directly.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        self.fabric_state = self.nd.request(self.path, method=self.verb)

    def validate_nd_state(self):
        """
        Validates the Nexus Dashboard (ND) state by extracting fabric information.

        This method processes the current fabric state data stored in self.fabric_state,
        extracts relevant attributes for each fabric, and converts them into FabricModel
        objects that are appended to the self.have list.

        The method logs its entry point for debugging purposes and creates a standardized
        representation of each fabric with the following attributes:
        - name
        - category
        - securityDomain
        - management information (type, bgpAsn, anycastGatewayMac, replicationMode)

        Returns:
            None
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.fabric_state.get("fabrics"):
            if not isinstance(fabric, dict):
                raise ValueError(f"Fabric data is not a dictionary: {fabric}")
            validated_fabric = FabricModel(**fabric)
            self.have.append(validated_fabric)
            # Sample Fabric Structure
            # fabric = {
            #     "name": f"{fabric['name']}",
            #     "category": f"{fabric['category']}",
            #     "securityDomain": f"{fabric['securityDomain']}",
            #     "management": {
            #         "type": f"{fabric['management']['type']}",
            #         "bgpAsn": f"{fabric['management']['bgpAsn']}",
            #         "anycastGatewayMac": f"{fabric['management']['anycastGatewayMac']}",
            #         "replicationMode": f"{fabric['management']['replicationMode']}",
            #     }
            # }


class Common:
    """
    Common utility class that provides shared functionality for all state operations in the Cisco ND fabric module.

    This class handles the core logic for processing fabric configurations across different operational states
    (merged, replaced, deleted, overridden, query) in Ansible tasks. It manages state comparison, parameter
    validation, and payload construction for ND API operations using Pydantic models and utility functions.

    The class leverages utility functions (merge_models, model_payload_with_defaults) to intelligently handle
    fabric configuration merging and default value application based on the operation state.

    Attributes:
        result (dict): Dictionary to store operation results including changed state, diffs, API responses and warnings.
        task_params (dict): Parameters provided from the Ansible task.
        state (str): The desired state operation (merged, replaced, deleted, overridden, or query).
        requests (dict): Container for API request requests.
        have (list): List of FabricModel objects representing the current state of fabrics.
        query (list): List for storing query results.
        validated (list): List of validated configuration items.
        want (list): List of FabricModel objects representing the desired state of fabrics.

    Methods:
        validate_task_params(): Validates the task parameters and builds the desired state using utility functions.
        fabric_in_have(fabric_name): Checks if a fabric with the given name exists in current state.
    """

    def __init__(self, task_params, have_state, logger=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.result = dict(changed=False, diff=[], response=[], warnings=[])
        self.task_params = task_params
        self.state = task_params["state"]
        self.requests = {}

        self.have = have_state
        self.query = []
        self.validated = []
        self.want = []

        self.validate_task_params()

        msg = "ENTERED Common(): "
        msg += f"state: {self.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def validate_task_params(self):
        """
        Validates and processes task parameters to create fabric model objects.

        This method iterates through each fabric configuration in the task parameters
        and converts them into FabricModel instances based on the current state and
        existing fabric configurations. The resulting models are stored in the want list
        for further processing.

        The method uses utility functions to handle different scenarios:
        - For 'merged' state with existing fabrics: Uses merge_models() to combine current and desired state
        - For other states or when fabrics don't exist: Uses model_payload_with_defaults() for complete configuration

        The method handles the following scenarios:
        - 'merged' state for new and existing fabrics
        - 'replaced', 'deleted', 'overridden', and 'query' states

        Returns:
            None: Updates self.want list with processed FabricModel objects
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.task_params.get("config"):
            have_fabric = self.fabric_in_have(fabric["name"])
            want_fabric = FabricModel(**fabric)
            if self.state == "merged" and have_fabric is not None:
                fabric_config_payload = merge_models(have_fabric, want_fabric)
            else:
                # This handles
                #  - Merged when the fabric does not yet exist
                #  - Replaced, Deleted, and Query states
                fabric_config_payload = model_payload_with_defaults(want_fabric)

            fabric = FabricModel(**fabric_config_payload)
            self.log.debug("Adding fabric to want list: %s", fabric.name)
            self.log.debug("Fabric model created: %s", fabric.model_dump(by_alias=True))
            # Add the fabric model to the want list
            self.want.append(fabric)

    def fabric_in_have(self, fabric_name):
        """
        Find a fabric by name in the current state.

        This method searches through the current state (`self.have`) for a fabric
        with the specified name and returns it if found.

        Args:
            fabric_name (str): The name of the fabric to find.

        Returns:
            object: The fabric object if found, None otherwise.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name} with fabric_name: {fabric_name}"
        self.log.debug(msg)

        # return any(fabric.name == fabric_name for fabric in self.have)
        have_fabric = next((h for h in self.have if h.name == fabric_name), None)
        return have_fabric


class Merged:
    """
    A class that implements the 'merged' state strategy for Cisco ND fabric configurations.

    This class compares the desired state ('want') with the current state ('have') of
    fabrics and generates the necessary API requests to bring the current state in line
    with the desired state. When using the 'merged' state, existing configurations are
    preserved and only the differences or additions are applied.

    The class calculates differences between configurations using DeepDiff and constructs
    appropriate REST API calls (POST for new fabrics, PUT for existing ones) with requests
    that reflect only the changes needed.

    Attributes:
        common (Common): Common utility instance for shared functionality
        verb (str): HTTP verb for the API call (POST or PUT)
        path (str): API endpoint path for the request

    Methods:
        build_request(): Analyzes desired state against current state and builds API requests
        update_payload_merged(have, want): Generates a merged request payload from current and desired states
        _parse_path(path): Parses DeepDiff paths into component parts
        _process_values_changed(diff, updated_payload): Updates changed values in the payload
        _process_dict_items_added(diff, updated_payload, want_dict): Adds new items to the payload
    """

    def __init__(self, task_params, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state)
        self.common.have = have_state

        self.verb = ""
        self.path = ""

        self.build_request()

        msg = "ENTERED Merged(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def build_request(self):
        """
        Build API request for creating or updating fabrics.

        This method compares the desired fabric configurations (want) with the current
        configurations (have) and prepares appropriate requests for API operations.
        For each fabric in the desired state:
        - If the fabric matches the current state, it is skipped
        - If the fabric doesn't exist in the current state, a POST payload is created
        - If the fabric exists but differs from desired state, a PUT payload is created

        The method populates self.common.requests with dictionaries containing:
        - verb: HTTP method (POST or PUT)
        - path: API endpoint path
        - payload: The data to be sent to the API

        No parameters are required as it uses instance attributes for processing.

        Returns:
            None: Updates self.common.requests with operation details
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.common.want:
            want_fabric = fabric
            have_fabric = self.common.fabric_in_have(want_fabric.name)

            if want_fabric == have_fabric:
                # want_fabric and have_fabric are the same, no action needed
                self.log.debug("Fabric %s is already in the desired state, skipping.", want_fabric.name)
                continue

            if not have_fabric:
                # If the fabric does not exist in the have state, we will create it
                self.log.debug("Fabric %s does not exist in the current state, creating it.", want_fabric.name)
                self.path = "/api/v1/manage/fabrics"
                self.verb = "POST"
                payload = copy.deepcopy(want_fabric.model_dump(by_alias=True))
            else:
                # If the fabric already exists in the have state, we will update it
                self.log.debug("Fabric %s exists in the current state, updating it.", want_fabric.name)
                self.path = "/api/v1/manage/fabrics" + f"/{want_fabric.name}"
                self.verb = "PUT"
                payload = self.update_payload_merged(have_fabric, want_fabric)

            self.common.requests[want_fabric.name] = {
                "verb": self.verb,
                "path": self.path,
                "payload": payload,
            }

    def _parse_path(self, path):
        """
        Parse a string path into a list of path segments.

        This method handles two different path format notations:
        1. Dot notation: "root.key1.key2"
        2. Bracket notation: "root['key1']['key2']"

        In both cases, if the path starts with "root", this prefix is removed from the result.

        Args:
            path (str): The path string to parse in either dot or bracket notation.

        Returns:
            list: A list of path segments/keys.

        Examples:
            >>> _parse_path("root.key1.key2")
            ['key1', 'key2']
            >>> _parse_path("root['key1']['key2']")
            ['key1', 'key2']
            >>> _parse_path("key1.key2")
            ['key1', 'key2']
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)
        # Handle paths like "root.key1.key2"
        if "." in path and "[" not in path:
            parts = path.split(".")
            if parts[0] == "root":
                parts = parts[1:]
            return parts

        # Handle paths like "root['key1']['key2']"
        parts = re.findall(r"'([^']*)'", path)
        return parts

    def _process_values_changed(self, diff, updated_payload):
        """
        Process values that have changed in the diff and update the payload accordingly.

        This method handles updating nested dictionary values based on the diff structure.
        It navigates through the payload using the path provided in the diff and updates
        the corresponding value with the new value from the diff.

        Args:
            diff (dict): Dictionary containing differences, with a 'values_changed' key
                         that maps to changes where keys are paths and values are dicts
                         with 'new_value' keys.
            updated_payload (dict): The payload to be updated with the new values.

        Returns:
            None: This method updates the updated_payload in-place.

        Notes:
            - Requires self._parse_path method to convert path strings to list of keys
            - Logs debug information using self.log
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if "values_changed" not in diff:
            return

        # Log the values changed for debugging
        self.log.debug("Values changed: %s", diff["values_changed"])

        for path, change in diff["values_changed"].items():
            parts = self._parse_path(path)

            # Navigate to the correct nested dictionary
            current = updated_payload
            for part in parts[:-1]:
                current = current[part]

            # Update the value
            current[parts[-1]] = change["new_value"]

    def _process_dict_items_added(self, diff, updated_payload, want_dict):
        """
        Process dictionary items that have been added according to the diff.

        This method updates the payload by adding items from the 'want' dictionary
        that are identified as newly added in the diff dictionary.

        Args:
            diff (dict): Dictionary containing differences between 'want' and 'have',
                         expected to have a 'dictionary_item_added' key if there are
                         items to add.
            updated_payload (dict): The payload dictionary to update with new items.
            want_dict (dict): The source dictionary containing the desired state with
                              items to be added.

        Returns:
            None: The method modifies the updated_payload dictionary in place.

        Note:
            The method uses _parse_path() to navigate the nested dictionary structure
            and properly place the new items at their correct locations.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        if "dictionary_item_added" not in diff:
            return

        # Log the dictionary items added for debugging
        self.log.debug("Dictionary items added: %s", diff["dictionary_item_added"])

        for path in diff["dictionary_item_added"]:
            parts = self._parse_path(path)

            # Navigate to the correct nested dictionary
            current = updated_payload
            for i, part in enumerate(parts[:-1]):
                if part not in current:
                    current[part] = {}
                current = current[part]

            # Get the value from want
            value = want_dict
            for part in parts:
                value = value[part]

            # Add the new item
            current[parts[-1]] = value

    def update_payload_merged(self, have, want):
        """
        Calculate the difference between the have and want states and generate an updated payload.

        This method computes what needs to be changed to transform the current state ('have')
        into the desired state ('want'). It uses DeepDiff to identify differences and applies
        a merge strategy, keeping existing values and updating only what's different or new.

        Parameters
        ----------
        have : object
            The current state of the object as a Pydantic model
        want : object
            The desired state of the object as a Pydantic model

        Returns
        -------
        dict
            Updated payload dictionary containing the merged state that reflects
            the differences between 'have' and 'want'

        Notes
        -----
        - Changed values are processed by _process_values_changed
        - New items are added via _process_dict_items_added
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        have = have.model_dump(by_alias=True)
        updated_payload = copy.deepcopy(have)  # Start with the current state

        want = want.model_dump(by_alias=True)

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        # Use DeepDiff to calculate the difference
        diff = DeepDiff(have, want, ignore_order=True)

        # If there are no differences, just return the original payload
        # NOTE: I don't think we will ever hit this condition
        if not diff:
            return updated_payload

        # Update changed values and add any new items
        self._process_values_changed(diff, updated_payload)
        self._process_dict_items_added(diff, updated_payload, want)

        return updated_payload


class Replaced:
    """
    A class for handling 'replaced' state operations on Cisco ND fabric resources.

    The Replaced class implements the logic for completely replacing existing fabric configurations
    with the desired configurations. When a fabric doesn't exist, it will be created; when it exists,
    it will be fully replaced with the specified configuration regardless of current settings.

    This differs from 'merged' state which would only update changed values and add new items.

    Parameters
    ----------
    task_params : dict
        The task_params containing the desired state ('want') for the fabrics
    have_state : dict
        The current state of fabrics in the system

    Attributes
    ----------
    common : Common
        Common utility instance for shared operations
    verb : str
        The HTTP verb (POST or PUT) for the API call
    path : str
        The API endpoint path for the operation

    Methods
    -------
    build_request()
        Processes each fabric in the desired state, compares with current state, and builds
        appropriate API requests for creation or replacement
    """

    def __init__(self, task_params, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state)
        self.common.have = have_state

        self.verb = ""
        self.path = ""

        self.build_request()

        msg = "ENTERED Replaced(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def build_request(self):
        """
        Build API requests for fabric management operations.

        This method processes the desired fabric configurations and generates
        appropriate API requests for creating or updating fabrics. It compares
        the desired state (want) with the current state (have) and determines
        the necessary actions.

        The method performs the following operations:
        - Iterates through all desired fabric configurations
        - Compares each desired fabric with its current state
        - Skips fabrics that are already in the desired state
        - Creates POST requests for new fabrics that don't exist
        - Creates PUT requests for existing fabrics that need updates
        - Uses the complete desired configuration for replaced operations

        The generated requests are stored in self.common.requests dictionary
        with the fabric name as the key and a dictionary containing the HTTP
        verb, API path, and payload data as the value.

        Note:
            This method implements a "replaced" strategy where the entire
            desired configuration is used, including default values, rather
            than calculating only the differences like in a "merged" strategy.
        """
        self.class_name = self.__class__.__name__
        method_name = inspect.stack()[0][3]  # pylint: disable=unused-variable

        msg = f"ENTERED: {self.class_name}.{method_name}"
        self.log.debug(msg)

        for fabric in self.common.want:
            want_fabric = fabric
            have_fabric = self.common.fabric_in_have(want_fabric.name)

            if want_fabric == have_fabric:
                # want_fabric and have_fabric are the same, no action needed
                self.log.debug("Fabric %s is already in the desired state, skipping.", want_fabric.name)
                continue

            if not have_fabric:
                # If the fabric does not exist in the have state, we will create it
                self.path = "/api/v1/manage/fabrics"
                self.verb = "POST"
            else:
                # If the fabric already exists in the have state, we will update it
                self.path = "/api/v1/manage/fabrics" + f"/{want_fabric.name}"
                self.verb = "PUT"

            # For replaced we just use the want payload "as is" including any default values
            # This is different from merged where we calculate the difference and only update
            # the changed values and add any new items
            payload = copy.deepcopy(want_fabric.model_dump(by_alias=True))
            self.common.requests[want_fabric.name] = {
                "verb": self.verb,
                "path": self.path,
                "payload": payload,
            }


class Deleted:
    """
    Handle deletion of fabric configurations.

    This class manages the deletion of fabrics by comparing the desired state (want)
    with the current state (have) and preparing DELETE operations for fabrics that
    exist in both lists.

    Args:
        task_params: The task_params configuration containing the desired state
        have_state: The current state of fabrics in the system

    Attributes:
        class_name (str): Name of the current class for logging purposes
        log (logging.Logger): Logger instance for this class
        common (Common): Common utilities and state management
        verb (str): HTTP verb for the operation ("DELETE")
        path (str): API endpoint template for fabric deletion
        delete_fabric_names (list): List of fabric names to be deleted

    The class identifies fabrics that exist in both the desired configuration
    and current system state, then prepares the necessary API calls to delete
    those fabrics by formatting the deletion path for each fabric and storing
    the operation details in the common requests dictionary.
    """

    def __init__(self, task_params, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric_name}"

        # Create a list of fabric names to be deleted that are in both self.common.want and self.have
        self.delete_fabric_names = [fabric.name for fabric in self.common.want if fabric.name in [h.name for h in self.common.have]]

        for fabric in self.delete_fabric_names:
            # Create a path for each fabric name to be deleted
            self.common.requests[fabric] = {
                "verb": self.verb,
                "path": self.path.format(fabric_name=fabric),
                "payload": "",
            }

        msg = "ENTERED Deleted(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)


class Overridden:
    """
    Handles the 'overridden' state for fabric management operations.

    This class manages the overridden state by deleting fabrics that exist in the current
    state but are not present in the desired state, and then creating or replacing fabrics
    that are specified in the desired state.

    The overridden operation is a combination of:
    1. Deleting fabrics that exist in 'have' but not in 'want'
    2. Creating or replacing fabrics specified in 'want'

    Args:
        task_params: The Ansible task_params context containing configuration data
        have_state: Current state of fabrics in the system
        logger (optional): Logger instance for debugging. Defaults to None
        common_util (optional): Common utility instance. Defaults to None
        replaced_task (optional): Replaced task instance. Defaults to None

    Attributes:
        class_name (str): Name of the current class
        log: Logger instance for debugging operations
        common: Common utility instance for shared operations
        verb (str): HTTP verb used for delete operations ('DELETE')
        path (str): API endpoint template for fabric deletion
        delete_fabric_names (list): List of fabric names to be deleted
    """

    def __init__(self, task_params, have_state, logger=None, common_util=None, replaced_task=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")

        self.common = common_util or Common(task_params, have_state)
        self.common.have = have_state
        self.verb = "DELETE"
        self.path = "/api/v1/manage/fabrics/{fabric_name}"

        # Use the Replaced() to create new fabrics or replace existing ones
        replaced_task = Replaced(task_params, have_state)

        # Create a list of fabric names to be deleted that are not in self.common.want but are in self.have
        self.delete_fabric_names = [fabric.name for fabric in self.common.have if fabric.name not in [w.name for w in self.common.want]]

        for fabric in self.delete_fabric_names:
            # Create a path for each fabric name to be deleted
            self.common.requests[fabric] = {
                "verb": self.verb,
                "path": self.path.format(fabric_name=fabric),
                "payload": "",
            }

        # Merge replace_task.common.requests into self.common.requests
        for fabric, request_data in replaced_task.common.requests.items():
            self.common.requests[fabric] = request_data

        msg = "ENTERED Overridden(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)


class Query:
    """
    Query class for managing fabric queries in Cisco ND.

    This class handles querying operations for fabric management in the Cisco Nexus Dashboard.
    It provides functionality to retrieve and return fabric state information.

    Args:
        task_params: The Ansible task_params context containing configuration parameters
        have_state: The current state of the fabric being queried

    Attributes:
        class_name (str): The name of the current class
        log (logging.Logger): Logger instance for the Query class
        common (Common): Common utility instance for shared operations
        have: The current have state of the fabric

    Note:
        This class is part of the Cisco ND Ansible collection for fabric management
        operations and follows the standard query pattern for state retrieval.
    """

    def __init__(self, task_params, have_state, logger=None, common_util=None):
        self.class_name = self.__class__.__name__
        self.log = logger or logging.getLogger(f"nd.{self.class_name}")
        self.common = common_util or Common(task_params, have_state)
        self.have = have_state

        msg = "ENTERED Query(): "
        msg += f"state: {self.common.state}, "
        # msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)


def main():
    argument_spec = {}
    argument_spec.update(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "query"],
        ),
        config=dict(required=False, type="list", elements="dict"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if sys.version_info < (3, 9):
        module.fail_json(msg="Python version 3.9 or higher is required for this module.")

    # if not HAS_PYDANTIC:
    #     module.fail_json(msg=missing_required_lib("pydantic"), exception=PYDANTIC_IMPORT_ERROR)
    if not HAS_DEEPDIFF:
        module.fail_json(msg=missing_required_lib("deepdiff"), exception=DEEPDIFF_IMPORT_ERROR)

    # Logging setup
    try:
        log = Log()
        log.commit()
        mainlog = logging.getLogger("nd.main")
    except ValueError as error:
        module.fail_json(str(error))

    mainlog.info("---------------------------------------------")
    mainlog.info("Starting cisco.nd.manage_fabric module")
    mainlog.info("---------------------------------------------\n")

    nd = NDModule(module)
    task_params = nd.params
    fabrics = GetHave(nd)
    fabrics.refresh()
    fabrics.validate_nd_state()

    try:
        task = None
        if task_params.get("state") == "merged":
            task = Merged(task_params, fabrics.have)
        elif task_params.get("state") == "replaced":
            task = Replaced(task_params, fabrics.have)
        elif task_params.get("state") == "deleted":
            task = Deleted(task_params, fabrics.have)
        elif task_params.get("state") == "overridden":
            task = Overridden(task_params, fabrics.have)
        elif task_params.get("state") == "query":
            task = Query(task_params, fabrics.have)
        if task is None:
            module.fail_json(f"Invalid state: {task_params['state']}")
    except ValueError as error:
        module.fail_json(f"{error}")

    # If the task is a query, we will just return the have state
    if isinstance(task, Query):
        for fabric in fabrics.have:
            task.common.query.append(fabric.model_dump(by_alias=True))
        task.common.result["query"] = task.common.query
        task.common.result["changed"] = False
        module.exit_json(**task.common.result)

    # Process all the requests from task.common.requests
    # Sample entry:
    #   {'fabric-ansible': {'verb': 'DELETE', 'path': '/api/v1/manage/fabrics/fabric-ansible', 'payload': ''}
    if task.common.requests:
        for fabric, request_data in task.common.requests.items():
            verb = request_data["verb"]
            path = request_data["path"]
            payload = request_data["payload"]

            # Pretty-print the payload for easier log reading
            pretty_payload = json.dumps(payload, indent=2, sort_keys=True)
            mainlog.info("Calling nd.request with path: %s, verb: %s, and payload:\n%s", path, verb, pretty_payload)
            # Make the API request
            response = nd.request(path, method=verb, data=payload if payload else None)
            task.common.result["response"].append(response)
            task.common.result["changed"] = True
    else:
        mainlog.info("No requests to process")

    # nd.exit_json()
    module.exit_json(**task.common.result)


if __name__ == "__main__":
    main()
