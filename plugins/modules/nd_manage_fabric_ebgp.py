#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_ebgp
version_added: "1.4.0"
short_description: Manage eBGP VXLAN fabrics on Cisco Nexus Dashboard
description:
- Manage eBGP VXLAN fabrics on Cisco Nexus Dashboard (ND).
- It supports creating, updating, replacing, and deleting eBGP VXLAN fabrics.
author:
- Mike Wiebe (@mwiebe)
options:
  config:
    description:
    - The list of eBGP VXLAN fabrics to configure.
    type: list
    elements: dict
    suboptions:
      fabric_name:
        description:
        - The name of the fabric.
        - Only letters, numbers, underscores, and hyphens are allowed.
        - The O(config.fabric_name) must be defined when creating, updating or deleting a fabric.
        type: str
        required: true
      category:
        description:
        - The resource category.
        type: str
        default: fabric
      location:
        description:
        - The geographic location of the fabric.
        type: dict
        suboptions:
          latitude:
            description:
            - Latitude coordinate of the fabric location (-90 to 90).
            type: float
            required: true
          longitude:
            description:
            - Longitude coordinate of the fabric location (-180 to 180).
            type: float
            required: true
      license_tier:
        description:
        - The license tier for the fabric.
        type: str
        default: premier
        choices: [ essentials, advantage, premier ]
      alert_suspend:
        description:
        - The alert suspension state for the fabric.
        type: str
        default: disabled
        choices: [ enabled, disabled ]
      telemetry_collection:
        description:
        - Enable telemetry collection for the fabric.
        type: bool
        default: false
      telemetry_collection_type:
        description:
        - The telemetry collection type.
        type: str
        default: outOfBand
      telemetry_streaming_protocol:
        description:
        - The telemetry streaming protocol.
        type: str
        default: ipv4
      telemetry_source_interface:
        description:
        - The telemetry source interface.
        type: str
        default: ""
      telemetry_source_vrf:
        description:
        - The telemetry source VRF.
        type: str
        default: ""
      security_domain:
        description:
        - The security domain associated with the fabric.
        type: str
        default: all
      management:
        description:
        - The eBGP VXLAN management configuration for the fabric.
        type: dict
        suboptions:
          type:
            description:
            - The fabric management type. Must be C(vxlanEbgp) for eBGP VXLAN fabrics.
            type: str
            default: vxlanEbgp
            choices: [ vxlanEbgp ]
          bgp_asn:
            description:
            - The BGP Autonomous System Number for the fabric.
            - Must be a numeric value between 1 and 4294967295, or dotted notation (1-65535.0-65535).
            - Optional when O(config.management.bgp_asn_auto_allocation) is C(true).
            type: str
          bgp_asn_auto_allocation:
            description:
            - Enable automatic BGP ASN allocation from the O(config.management.bgp_asn_range) pool.
            type: bool
            default: true
          bgp_asn_range:
            description:
            - The BGP ASN range to use for automatic ASN allocation (e.g. C(65000-65535)).
            - Required when O(config.management.bgp_asn_auto_allocation) is C(true).
            type: str
          bgp_as_mode:
            description:
            - The BGP AS mode for the fabric.
            - C(multiAS) assigns a unique AS number per leaf/border/border gateway (borders and border gateways may share ASN).
            - C(sameTierAS) assigns the same AS number within a tier (leafs share one ASN, borders/border gateways share one ASN).
            type: str
            default: multiAS
            choices: [ multiAS, sameTierAS ]
          bgp_allow_as_in_num:
            description:
            - The number of occurrences of the local AS number allowed in the BGP AS-path.
            type: int
            default: 1
          bgp_max_path:
            description:
            - The maximum number of BGP equal-cost paths.
            type: int
            default: 4
          bgp_underlay_failure_protect:
            description:
            - Enable BGP underlay failure protection.
            type: bool
            default: false
          auto_configure_ebgp_evpn_peering:
            description:
            - Automatically configure eBGP EVPN overlay peering between leaf and spine switches.
            type: bool
            default: true
          allow_leaf_same_as:
            description:
            - Allow leaf switches to have the same BGP ASN even when AS mode is Multi-AS.
            type: bool
            default: false
          assign_ipv4_to_loopback0:
            description:
            - In an IPv6 routed fabric or VXLAN EVPN fabric with IPv6 underlay, assign IPv4 address
              used for BGP Router ID to the routing loopback interface.
            type: bool
            default: true
          evpn:
            description:
            - Enable BGP EVPN as the control plane and VXLAN as the data plane for this fabric.
            type: bool
            default: true
          route_map_tag:
            description:
            - Tag for Route Map FABRIC-RMAP-REDIST-SUBNET. (Min 0, Max 4294967295).
            type: int
            default: 12345
          disable_route_map_tag:
            description:
            - Disable match tag for Route Map FABRIC-RMAP-REDIST-SUBNET.
            type: bool
            default: false
          leaf_bgp_as:
            description:
            - The BGP AS number for leaf switches.
            - Autonomous system number 1-4294967295 or dotted notation 1-65535.0-65535.
            type: str
          border_bgp_as:
            description:
            - The BGP AS number for border switches.
            - Autonomous system number 1-4294967295 or dotted notation 1-65535.0-65535.
            type: str
          super_spine_bgp_as:
            description:
            - The BGP AS number for super-spine switches.
            - Autonomous system number 1-4294967295 or dotted notation 1-65535.0-65535.
            type: str
          site_id:
            description:
            - The site identifier for EVPN Multi-Site support.
            - Defaults to the value of O(config.management.bgp_asn) if not provided.
            type: str
            default: ""
          bgp_loopback_id:
            description:
            - The underlay routing loopback interface ID (0-1023).
            type: int
            default: 0
          bgp_loopback_ip_range:
            description:
            - Typically Loopback0 IP address range.
            type: str
            default: "10.2.0.0/22"
          bgp_loopback_ipv6_range:
            description:
            - Typically Loopback0 IPv6 address range.
            type: str
            default: "fd00::a02:0/119"
          nve_loopback_id:
            description:
            - The underlay VTEP loopback ID associated with the NVE interface (0-1023).
            type: int
            default: 1
          nve_loopback_ip_range:
            description:
            - Typically Loopback1 IP address range.
            type: str
            default: "10.3.0.0/22"
          nve_loopback_ipv6_range:
            description:
            - Typically Loopback1 and Anycast Loopback IPv6 address range.
            type: str
            default: "fd00::a03:0/118"
          anycast_loopback_id:
            description:
            - Underlay anycast loopback ID. Used for vPC peering in VXLANv6 fabrics.
            type: int
            default: 10
          anycast_rendezvous_point_ip_range:
            description:
            - Anycast or Phantom RP IP address range.
            type: str
            default: "10.254.254.0/24"
          ipv6_anycast_rendezvous_point_ip_range:
            description:
            - Anycast RP IPv6 address range.
            type: str
            default: "fd00::254:254:0/118"
          intra_fabric_subnet_range:
            description:
            - Address range to assign numbered and peer link SVI IPs.
            type: str
            default: "10.4.0.0/16"
          l2_vni_range:
            description:
            - Overlay network identifier range (minimum 1, maximum 16777214).
            type: str
            default: "30000-49000"
          l3_vni_range:
            description:
            - Overlay VRF identifier range (minimum 1, maximum 16777214).
            type: str
            default: "50000-59000"
          network_vlan_range:
            description:
            - Per switch overlay network VLAN range (minimum 2, maximum 4094).
            type: str
            default: "2300-2999"
          vrf_vlan_range:
            description:
            - Per switch overlay VRF VLAN range (minimum 2, maximum 4094).
            type: str
            default: "2000-2299"
          overlay_mode:
            description:
            - Overlay mode. VRF/Network configuration using config-profile or CLI.
            type: str
            default: cli
            choices: [ cli, config-profile ]
          replication_mode:
            description:
            - Replication mode for BUM traffic.
            type: str
            default: multicast
            choices: [ multicast, ingress ]
          multicast_group_subnet:
            description:
            - Multicast pool prefix between 8 to 30. A multicast group IPv4 from this pool
              is used for BUM traffic for each overlay network.
            type: str
            default: "239.1.1.0/25"
          auto_generate_multicast_group_address:
            description:
            - Generate a new multicast group address from the multicast pool using a round-robin approach.
            type: bool
            default: false
          underlay_multicast_group_address_limit:
            description:
            - The maximum supported value is 128 for NX-OS version 10.2(1) or earlier
              and 512 for versions above 10.2(1).
            type: int
            default: 128
            choices: [ 128, 512 ]
          tenant_routed_multicast:
            description:
            - Enable overlay IPv4 multicast support in VXLAN fabrics.
            type: bool
            default: false
          tenant_routed_multicast_ipv6:
            description:
            - Enable overlay IPv6 multicast support in VXLAN fabrics.
            type: bool
            default: false
          first_hop_redundancy_protocol:
            description:
            - First hop redundancy protocol, HSRP or VRRP.
            type: str
            default: hsrp
            choices: [ hsrp, vrrp ]
          rendezvous_point_count:
            description:
            - Number of spines acting as Rendezvous-Points (RPs).
            type: int
            default: 2
            choices: [ 2, 4 ]
          rendezvous_point_loopback_id:
            description:
            - The rendezvous point loopback interface ID.
            type: int
            default: 254
          rendezvous_point_mode:
            description:
            - Multicast rendezvous point mode. For IPv6 underlay, use C(asm) only.
            type: str
            default: asm
            choices: [ asm, bidir ]
          phantom_rendezvous_point_loopback_id1:
            description:
            - Underlay phantom rendezvous point loopback primary ID for PIM Bi-dir deployments.
            type: int
            default: 2
          phantom_rendezvous_point_loopback_id2:
            description:
            - Underlay phantom rendezvous point loopback secondary ID for PIM Bi-dir deployments.
            type: int
            default: 3
          phantom_rendezvous_point_loopback_id3:
            description:
            - Underlay phantom rendezvous point loopback tertiary ID for PIM Bi-dir deployments.
            type: int
            default: 4
          phantom_rendezvous_point_loopback_id4:
            description:
            - Underlay phantom rendezvous point loopback quaternary ID for PIM Bi-dir deployments.
            type: int
            default: 5
          l3vni_multicast_group:
            description:
            - Default underlay multicast group IPv4 address assigned for every overlay VRF.
            type: str
            default: "239.1.1.0"
          l3_vni_ipv6_multicast_group:
            description:
            - Default underlay multicast group IPv6 address assigned for every overlay VRF.
            type: str
            default: "ff1e::"
          ipv6_multicast_group_subnet:
            description:
            - IPv6 multicast address with prefix 112 to 128.
            type: str
            default: "ff1e::/121"
          mvpn_vrf_route_import_id:
            description:
            - Enable MVPN VRI ID generation for tenant routed multicast with IPv4 underlay.
            type: bool
            default: true
          mvpn_vrf_route_import_id_range:
            description:
            - MVPN VRI ID range (minimum 1, maximum 65535) for vPC, applicable when TRM is enabled
              with IPv6 underlay, or O(config.management.mvpn_vrf_route_import_id) is enabled with IPv4 underlay.
            type: str
          vrf_route_import_id_reallocation:
            description:
            - One time VRI ID re-allocation based on MVPN VRI ID Range.
            type: bool
            default: false
          target_subnet_mask:
            description:
            - Mask for underlay subnet IP range (24-31).
            type: int
            default: 30
          anycast_gateway_mac:
            description:
            - Shared anycast gateway MAC address for all VTEPs in xxxx.xxxx.xxxx format.
            type: str
            default: 2020.0000.00aa
          fabric_mtu:
            description:
            - Intra fabric interface MTU. Must be an even number (1500-9216).
            type: int
            default: 9216
          l2_host_interface_mtu:
            description:
            - Layer 2 host interface MTU. Must be an even number (1500-9216).
            type: int
            default: 9216
          l3_vni_no_vlan_default_option:
            description:
            - L3 VNI configuration without VLAN configuration. This value is propagated on VRF
              creation as the default value of Enable L3VNI w/o VLAN in VRF.
            type: bool
            default: false
          underlay_ipv6:
            description:
            - Enable IPv6 underlay. If not enabled, IPv4 underlay is used.
            type: bool
            default: false
          static_underlay_ip_allocation:
            description:
            - Disable dynamic underlay IP address allocation.
            type: bool
            default: false
          anycast_border_gateway_advertise_physical_ip:
            description:
            - Advertise Anycast Border Gateway PIP as VTEP.
              Effective on MSD fabric Recalculate Config.
            type: bool
            default: false
          sub_interface_dot1q_range:
            description:
            - Per aggregation dot1q range for VRF-Lite connectivity (minimum 2, maximum 4093).
            type: str
            default: "2-511"
          vrf_lite_auto_config:
            description:
            - VRF Lite Inter-Fabric Connection Deployment Options.
            - If C(back2BackAndToExternal) is selected, VRF Lite IFCs are auto created between
              border devices of two Easy Fabrics, and between border devices in Easy Fabric and
              edge routers in External Fabric.
            type: str
            default: manual
            choices: [ manual, back2BackAndToExternal ]
          vrf_lite_subnet_range:
            description:
            - Address range to assign P2P interfabric connections.
            type: str
            default: "10.33.0.0/16"
          vrf_lite_subnet_target_mask:
            description:
            - VRF Lite subnet mask.
            type: int
            default: 30
          auto_unique_vrf_lite_ip_prefix:
            description:
            - When enabled, IP prefix allocated to the VRF LITE IFC is not reused on VRF extension
              over VRF LITE IFC. Instead, a unique IP subnet is allocated for each VRF extension.
            type: bool
            default: false
          vpc_domain_id_range:
            description:
            - vPC domain ID range (minimum 1, maximum 1000) to use for new pairings.
            type: str
            default: "1-1000"
          vpc_peer_link_vlan:
            description:
            - VLAN range (minimum 2, maximum 4094) for vPC Peer Link SVI.
            type: str
            default: "3600"
          vpc_peer_link_enable_native_vlan:
            description:
            - Enable vPC peer link for native VLAN.
            type: bool
            default: false
          vpc_peer_keep_alive_option:
            description:
            - Use vPC peer keep alive with loopback or management.
            type: str
            default: management
            choices: [ loopback, management ]
          vpc_auto_recovery_timer:
            description:
            - vPC auto recovery timer in seconds (240-3600).
            type: int
            default: 360
          vpc_delay_restore_timer:
            description:
            - vPC delay restore timer in seconds (1-3600).
            type: int
            default: 150
          vpc_peer_link_port_channel_id:
            description:
            - vPC peer link port channel ID (minimum 1, maximum 4096).
            type: str
            default: "500"
          vpc_ipv6_neighbor_discovery_sync:
            description:
            - Enable IPv6 ND synchronization between vPC peers.
            type: bool
            default: true
          vpc_layer3_peer_router:
            description:
            - Enable layer-3 peer-router on all leaf switches.
            type: bool
            default: true
          vpc_tor_delay_restore_timer:
            description:
            - vPC delay restore timer for ToR switches in seconds.
            type: int
            default: 30
          fabric_vpc_domain_id:
            description:
            - Enable the same vPC domain ID for all vPC pairs. Not recommended.
            type: bool
            default: false
          shared_vpc_domain_id:
            description:
            - vPC domain ID to be used on all vPC pairs.
            type: int
            default: 1
          fabric_vpc_qos:
            description:
            - QoS on spines for guaranteed delivery of vPC Fabric Peering communication.
            type: bool
            default: false
          fabric_vpc_qos_policy_name:
            description:
            - QoS policy name. Should be the same on all spines.
            type: str
            default: spine_qos_for_fabric_vpc_peering
          enable_peer_switch:
            description:
            - Enable the vPC peer-switch feature on ToR switches.
            type: bool
            default: false
          per_vrf_loopback_auto_provision:
            description:
            - Auto provision an IPv4 loopback on a VTEP on VRF attachment.
            - Enabling this option auto-provisions loopback on existing VRF attachments and also
              when Edit, QuickAttach, or Multiattach actions are performed.
            type: bool
            default: false
          per_vrf_loopback_ip_range:
            description:
            - Prefix pool to assign IPv4 addresses to loopbacks on VTEPs on a per VRF basis.
            type: str
            default: "10.5.0.0/22"
          per_vrf_loopback_auto_provision_ipv6:
            description:
            - Auto provision an IPv6 loopback on a VTEP on VRF attachment.
            type: bool
            default: false
          per_vrf_loopback_ipv6_range:
            description:
            - Prefix pool to assign IPv6 addresses to loopbacks on VTEPs on a per VRF basis.
            type: str
            default: "fd00::a05:0/112"
          vrf_template:
            description:
            - Default overlay VRF template for leafs.
            type: str
            default: Default_VRF_Universal
          network_template:
            description:
            - Default overlay network template for leafs.
            type: str
            default: Default_Network_Universal
          vrf_extension_template:
            description:
            - Default overlay VRF template for borders.
            type: str
            default: Default_VRF_Extension_Universal
          network_extension_template:
            description:
            - Default overlay network template for borders.
            type: str
            default: Default_Network_Extension_Universal
          performance_monitoring:
            description:
            - If enabled, switch metrics are collected through periodic SNMP polling.
              Alternative to real-time telemetry.
            type: bool
            default: false
          tenant_dhcp:
            description:
            - Enable tenant DHCP.
            type: bool
            default: true
          advertise_physical_ip:
            description:
            - For primary VTEP IP advertisement as next-hop of prefix routes.
            type: bool
            default: false
          advertise_physical_ip_on_border:
            description:
            - Enable advertise-pip on vPC borders and border gateways only.
              Applicable only when vPC advertise-pip is not enabled.
            type: bool
            default: true
          bgp_authentication:
            description:
            - Enable BGP authentication.
            type: bool
            default: false
          bgp_authentication_key_type:
            description:
            - BGP key encryption type. 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7.
            type: str
            default: 3des
            choices: [ 3des, type6, type7 ]
          bgp_authentication_key:
            description:
            - Encrypted BGP authentication key based on type.
            type: str
            default: ""
          bfd:
            description:
            - Enable BFD. Valid for IPv4 underlay only.
            type: bool
            default: false
          bfd_ibgp:
            description:
            - Enable BFD for iBGP.
            type: bool
            default: false
          bfd_authentication:
            description:
            - Enable BFD authentication. Valid for P2P interfaces only.
            type: bool
            default: false
          bfd_authentication_key_id:
            description:
            - BFD authentication key ID.
            type: int
            default: 100
          bfd_authentication_key:
            description:
            - Encrypted SHA1 secret value.
            type: str
            default: ""
          pim_hello_authentication:
            description:
            - Enable PIM hello authentication. Valid for IPv4 underlay only.
            type: bool
            default: false
          pim_hello_authentication_key:
            description:
            - PIM hello authentication key. 3DES encrypted.
            type: str
            default: ""
          nxapi:
            description:
            - Enable NX-API over HTTPS.
            type: bool
            default: false
          nxapi_http:
            description:
            - Enable NX-API over HTTP.
            type: bool
            default: false
          nxapi_https_port:
            description:
            - HTTPS port for NX-API (1-65535).
            type: int
            default: 443
          nxapi_http_port:
            description:
            - HTTP port for NX-API (1-65535).
            type: int
            default: 80
          day0_bootstrap:
            description:
            - Automatic IP assignment for POAP.
            type: bool
            default: false
          bootstrap_subnet_collection:
            description:
            - List of IPv4 or IPv6 subnets to be used for bootstrap.
            - When O(state=merged), omitting this option preserves the existing collection.
            - When O(state=merged), providing this option replaces the entire collection with the supplied list.
            - Under O(state=merged), entries in this list are not merged item-by-item.
            - Under O(state=merged), removing one entry from the playbook removes it from the fabric, and setting an empty list clears the collection.
            - When O(state=replaced), this option is also treated as the exact desired collection.
            - When O(state=replaced), omitting this option resets the collection to its default empty value.
            type: list
            elements: dict
            suboptions:
              start_ip:
                description:
                - Starting IP address of the bootstrap range.
                type: str
                required: true
              end_ip:
                description:
                - Ending IP address of the bootstrap range.
                type: str
                required: true
              default_gateway:
                description:
                - Default gateway for the bootstrap subnet.
                type: str
                required: true
              subnet_prefix:
                description:
                - Subnet prefix length (8-30).
                type: int
                required: true
          local_dhcp_server:
            description:
            - Automatic IP assignment for POAP from local DHCP server.
            type: bool
            default: false
          dhcp_protocol_version:
            description:
            - IP protocol version for local DHCP server.
            type: str
            default: dhcpv4
            choices: [ dhcpv4, dhcpv6 ]
          dhcp_start_address:
            description:
            - DHCP scope start address for switch POAP.
            type: str
            default: ""
          dhcp_end_address:
            description:
            - DHCP scope end address for switch POAP.
            type: str
            default: ""
          management_gateway:
            description:
            - Default gateway for management VRF on the switch.
            type: str
            default: ""
          management_ipv4_prefix:
            description:
            - Switch management IP subnet prefix for IPv4.
            type: int
            default: 24
          management_ipv6_prefix:
            description:
            - Switch management IP subnet prefix for IPv6.
            type: int
            default: 64
          netflow_settings:
            description:
            - Netflow configuration settings.
            type: dict
            suboptions:
              netflow:
                description:
                - Enable netflow collection.
                type: bool
                default: false
              netflow_exporter_collection:
                description:
                - List of netflow exporters.
                type: list
                elements: dict
                suboptions:
                  exporter_name:
                    description:
                    - Name of the netflow exporter.
                    type: str
                    required: true
                  exporter_ip:
                    description:
                    - IP address of the netflow collector.
                    type: str
                    required: true
                  vrf:
                    description:
                    - VRF name for the exporter.
                    type: str
                    default: management
                  source_interface_name:
                    description:
                    - Source interface name.
                    type: str
                    required: true
                  udp_port:
                    description:
                    - UDP port for netflow export (1-65535).
                    type: int
              netflow_record_collection:
                description:
                - List of netflow records.
                type: list
                elements: dict
                suboptions:
                  record_name:
                    description:
                    - Name of the netflow record.
                    type: str
                    required: true
                  record_template:
                    description:
                    - Template type for the record.
                    type: str
                    required: true
                  layer2_record:
                    description:
                    - Enable layer 2 record fields.
                    type: bool
                    default: false
              netflow_monitor_collection:
                description:
                - List of netflow monitors.
                type: list
                elements: dict
                suboptions:
                  monitor_name:
                    description:
                    - Name of the netflow monitor.
                    type: str
                    required: true
                  record_name:
                    description:
                    - Associated record name.
                    type: str
                    required: true
                  exporter1_name:
                    description:
                    - Primary exporter name.
                    type: str
                    required: true
                  exporter2_name:
                    description:
                    - Secondary exporter name.
                    type: str
                    default: ""
          real_time_backup:
            description:
            - Backup hourly only if there is any config deployment since last backup.
            type: bool
          scheduled_backup:
            description:
            - Enable backup at the specified time daily.
            type: bool
          scheduled_backup_time:
            description:
            - Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59).
            type: str
            default: ""
          leaf_tor_id_range:
            description:
            - Use specific vPC/Port-channel ID range for leaf-tor pairings.
            type: bool
            default: false
          leaf_tor_vpc_port_channel_id_range:
            description:
            - vPC/Port-channel ID range (minimum 1, maximum 4096), used for auto-allocating
              vPC/Port-Channel IDs for leaf-tor pairings.
            type: str
            default: "1-499"
          allow_vlan_on_leaf_tor_pairing:
            description:
            - Set trunk allowed VLAN to none or all for leaf-tor pairing port-channels.
            type: str
            default: none
            choices: [ none, all ]
          ntp_server_collection:
            description:
            - List of NTP server IPv4/IPv6 addresses and/or hostnames.
            type: list
            elements: str
          ntp_server_vrf_collection:
            description:
            - NTP Server VRFs. One VRF for all NTP servers or a list of VRFs, one per NTP server.
            type: list
            elements: str
          dns_collection:
            description:
            - List of IPv4 and IPv6 DNS addresses.
            type: list
            elements: str
          dns_vrf_collection:
            description:
            - DNS Server VRFs. One VRF for all DNS servers or a list of VRFs, one per DNS server.
            type: list
            elements: str
          syslog_server_collection:
            description:
            - List of syslog server IPv4/IPv6 addresses and/or hostnames.
            type: list
            elements: str
          syslog_server_vrf_collection:
            description:
            - Syslog Server VRFs. One VRF for all syslog servers or a list of VRFs, one per syslog server.
            type: list
            elements: str
          syslog_severity_collection:
            description:
            - List of syslog severity values, one per syslog server.
            type: list
            elements: int
          banner:
            description:
            - Message of the Day (motd) banner. Delimiter char (very first char is delimiter char)
              followed by message ending with delimiter.
            type: str
            default: ""
          extra_config_leaf:
            description:
            - Additional CLIs added after interface configurations for all switches with a VTEP
              unless they have some spine role.
            type: str
            default: ""
          extra_config_spine:
            description:
            - Additional CLIs added after interface configurations for all switches with some spine role.
            type: str
            default: ""
          extra_config_tor:
            description:
            - Additional CLIs added after interface configurations for all ToRs.
            type: str
            default: ""
          extra_config_intra_fabric_links:
            description:
            - Additional CLIs for all intra-fabric links.
            type: str
            default: ""
          extra_config_aaa:
            description:
            - AAA configurations.
            type: str
            default: ""
          extra_config_nxos_bootstrap:
            description:
            - Additional CLIs required during device bootup/login e.g. AAA/Radius.
            type: str
            default: ""
          aaa:
            description:
            - Include AAA configs from Manageability tab during device bootup.
            type: bool
            default: false
          pre_interface_config_leaf:
            description:
            - Additional CLIs added before interface configurations for all switches with a VTEP
              unless they have some spine role.
            type: str
            default: ""
          pre_interface_config_spine:
            description:
            - Additional CLIs added before interface configurations for all switches with some spine role.
            type: str
            default: ""
          pre_interface_config_tor:
            description:
            - Additional CLIs added before interface configurations for all ToRs.
            type: str
            default: ""
          greenfield_debug_flag:
            description:
            - Allow switch configuration to be cleared without a reload when preserveConfig is set to false.
            type: str
            default: disable
            choices: [ enable, disable ]
          interface_statistics_load_interval:
            description:
            - Interface statistics load interval in seconds.
            type: int
            default: 10
          nve_hold_down_timer:
            description:
            - NVE source interface hold-down time in seconds.
            type: int
            default: 180
          next_generation_oam:
            description:
            - Enable the Next Generation (NG) OAM feature for all switches in the fabric
              to aid in troubleshooting VXLAN EVPN fabrics.
            type: bool
            default: true
          ngoam_south_bound_loop_detect:
            description:
            - Enable the Next Generation (NG) OAM southbound loop detection.
            type: bool
            default: false
          ngoam_south_bound_loop_detect_probe_interval:
            description:
            - Next Generation (NG) OAM southbound loop detection probe interval in seconds.
            type: int
            default: 300
          ngoam_south_bound_loop_detect_recovery_interval:
            description:
            - Next Generation (NG) OAM southbound loop detection recovery interval in seconds.
            type: int
            default: 600
          strict_config_compliance_mode:
            description:
            - Enable bi-directional compliance checks to flag additional configs in the running
              config that are not in the intent/expected config.
            type: bool
            default: false
          advanced_ssh_option:
            description:
            - Enable AAA IP Authorization. Enable only when IP Authorization is enabled
              in the AAA Server.
            type: bool
            default: false
          copp_policy:
            description:
            - Fabric wide CoPP policy. Customized CoPP policy should be provided when C(manual) is selected.
            type: str
            default: strict
            choices: [ dense, lenient, moderate, strict, manual ]
          power_redundancy_mode:
            description:
            - Default power supply mode for NX-OS switches.
            type: str
            default: redundant
            choices: [ redundant, combined, inputSrcRedundant ]
          heartbeat_interval:
            description:
            - XConnect heartbeat interval for periodic link status checks.
            type: int
            default: 190
          snmp_trap:
            description:
            - Configure ND as a receiver for SNMP traps.
            type: bool
            default: true
          cdp:
            description:
            - Enable CDP on management interface.
            type: bool
            default: false
          real_time_interface_statistics_collection:
            description:
            - Enable real time interface statistics collection. Valid for NX-OS only.
            type: bool
            default: false
          tcam_allocation:
            description:
            - TCAM commands are automatically generated for VxLAN and vPC Fabric Peering when enabled.
            type: bool
            default: true
          allow_smart_switch_onboarding:
            description:
            - Enable onboarding of smart switches to Hypershield for firewall service.
            type: bool
            default: false
          default_queuing_policy:
            description:
            - Enable default queuing policies.
            type: bool
            default: false
          default_queuing_policy_cloudscale:
            description:
            - Queuing policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX series switches in the fabric.
            type: str
            default: queuing_policy_default_8q_cloudscale
          default_queuing_policy_r_series:
            description:
            - Queueing policy for all Nexus R-series switches.
            type: str
            default: queuing_policy_default_r_series
          default_queuing_policy_other:
            description:
            - Queuing policy for all other switches in the fabric.
            type: str
            default: queuing_policy_default_other
          aiml_qos:
            description:
            - Configures QoS and Queuing Policies specific to N9K Cloud Scale (CS) and
              Silicon One (S1) switch fabric for AI network workloads.
            type: bool
            default: false
          aiml_qos_policy:
            description:
            - Queuing policy based on predominant fabric link speed.
              C(User-defined) allows for custom configuration.
            type: str
            default: 400G
            choices: [ 800G, 400G, 100G, 25G, User-defined ]
          roce_v2:
            description:
            - DSCP for RDMA traffic. Numeric (0-63) with ranges/comma, or named values
              (af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43,
              cs1, cs2, cs3, cs4, cs5, cs6, cs7, default, ef).
            type: str
            default: "26"
          cnp:
            description:
            - DSCP value for Congestion Notification. Numeric (0-63) with ranges/comma, or named values
              (af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43,
              cs1, cs2, cs3, cs4, cs5, cs6, cs7, default, ef).
            type: str
            default: "48"
          wred_min:
            description:
            - WRED minimum threshold in kbytes.
            type: int
            default: 950
          wred_max:
            description:
            - WRED maximum threshold in kbytes.
            type: int
            default: 3000
          wred_drop_probability:
            description:
            - WRED drop probability percentage.
            type: int
            default: 7
          wred_weight:
            description:
            - Influences how quickly WRED reacts to queue depth changes.
            type: int
            default: 0
          bandwidth_remaining:
            description:
            - Percentage of remaining bandwidth allocated to AI traffic queues.
            type: int
            default: 50
          dlb:
            description:
            - Enables fabric-level Dynamic Load Balancing (DLB) configuration.
              Inter-Switch-Links (ISL) will be configured as DLB interfaces.
            type: bool
            default: false
          dlb_mode:
            description:
            - Select system-wide flowlet, per-packet (packet spraying) or policy driven mixed mode.
              Mixed mode is supported on Silicon One (S1) platform only.
            type: str
            default: flowlet
            choices: [ flowlet, per-packet, policy-driven-flowlet, policy-driven-per-packet, policy-driven-mixed-mode ]
          dlb_mixed_mode_default:
            description:
            - Default load balancing mode for policy driven mixed mode DLB.
            type: str
            default: ecmp
            choices: [ ecmp, flowlet, per-packet ]
          flowlet_aging:
            description:
            - Flowlet aging timer in microseconds. Valid range depends on platform.
              Cloud Scale (CS) 1-2000000 (default 500), Silicon One (S1) 1-1024 (default 256).
            type: int
          flowlet_dscp:
            description:
            - DSCP values for flowlet load balancing. Numeric (0-63) with ranges/comma, or named values
              (af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43,
              cs1, cs2, cs3, cs4, cs5, cs6, cs7, default, ef).
            type: str
            default: ""
          per_packet_dscp:
            description:
            - DSCP values for per-packet load balancing. Numeric (0-63) with ranges/comma, or named values
              (af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43,
              cs1, cs2, cs3, cs4, cs5, cs6, cs7, default, ef).
            type: str
            default: ""
          ai_load_sharing:
            description:
            - Enable IP load sharing using source and destination address for AI workloads.
            type: bool
            default: false
          priority_flow_control_watch_interval:
            description:
            - Acceptable values from 101 to 1000 (milliseconds).
              Leave blank for system default (100ms).
            type: int
          ptp:
            description:
            - Enable Precision Time Protocol (PTP).
            type: bool
            default: false
          ptp_loopback_id:
            description:
            - Precision Time Protocol source loopback ID.
            type: int
            default: 0
          ptp_domain_id:
            description:
            - Multiple independent PTP clocking subdomains on a single network.
            type: int
            default: 0
          private_vlan:
            description:
            - Enable PVLAN on switches except spines and super spines.
            type: bool
            default: false
          default_private_vlan_secondary_network_template:
            description:
            - Default PVLAN secondary network template.
            type: str
            default: Pvlan_Secondary_Network
          macsec:
            description:
            - Enable MACsec in the fabric. MACsec fabric parameters are used for configuring
              MACsec on a fabric link if MACsec is enabled on the link.
            type: bool
            default: false
          macsec_cipher_suite:
            description:
            - Configure MACsec cipher suite.
            type: str
            default: GCM-AES-XPN-256
            choices: [ GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128, GCM-AES-XPN-256 ]
          macsec_key_string:
            description:
            - MACsec primary key string. Cisco Type 7 encrypted octet string.
            type: str
            default: ""
          macsec_algorithm:
            description:
            - MACsec primary cryptographic algorithm. AES_128_CMAC or AES_256_CMAC.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          macsec_fallback_key_string:
            description:
            - MACsec fallback key string. Cisco Type 7 encrypted octet string.
            type: str
            default: ""
          macsec_fallback_algorithm:
            description:
            - MACsec fallback cryptographic algorithm. AES_128_CMAC or AES_256_CMAC.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          macsec_report_timer:
            description:
            - MACsec operational status periodic report timer in minutes.
            type: int
            default: 5
          enable_dpu_pinning:
            description:
            - Enable pinning of VRFs and networks to specific DPUs on smart switches.
            type: bool
            default: false
          connectivity_domain_name:
            description:
            - Domain name to connect to Hypershield.
            type: str
          hypershield_connectivity_proxy_server:
            description:
            - IPv4 address, IPv6 address, or DNS name of the proxy server for Hypershield communication.
            type: str
          hypershield_connectivity_proxy_server_port:
            description:
            - Proxy port number for communication with Hypershield.
            type: int
          hypershield_connectivity_source_intf:
            description:
            - Loopback interface on smart switch for communication with Hypershield.
            type: str
      telemetry_settings:
        description:
        - Telemetry configuration settings.
        type: dict
        suboptions:
          flow_collection:
            description:
            - Flow collection settings.
            type: dict
            suboptions:
              traffic_analytics:
                description:
                - Traffic analytics state.
                type: str
                default: enabled
              traffic_analytics_scope:
                description:
                - Traffic analytics scope.
                type: str
                default: intraFabric
              operating_mode:
                description:
                - Operating mode.
                type: str
                default: flowTelemetry
              udp_categorization:
                description:
                - UDP categorization.
                type: str
                default: enabled
          microburst:
            description:
            - Microburst detection settings.
            type: dict
            suboptions:
              microburst:
                description:
                - Enable microburst detection.
                type: bool
                default: false
              sensitivity:
                description:
                - Microburst sensitivity level.
                type: str
                default: low
          analysis_settings:
            description:
            - Telemetry analysis settings.
            type: dict
            suboptions:
              is_enabled:
                description:
                - Enable telemetry analysis.
                type: bool
                default: false
          nas:
            description:
            - NAS telemetry configuration.
            type: dict
            suboptions:
              server:
                description:
                - NAS server address.
                type: str
                default: ""
              export_settings:
                description:
                - NAS export settings.
                type: dict
                suboptions:
                  export_type:
                    description:
                    - Export type.
                    type: str
                    default: full
                  export_format:
                    description:
                    - Export format.
                    type: str
                    default: json
          energy_management:
            description:
            - Energy management settings.
            type: dict
            suboptions:
              cost:
                description:
                - Energy cost per unit.
                type: float
                default: 1.2
      external_streaming_settings:
        description:
        - External streaming settings.
        type: dict
        suboptions:
          email:
            description:
            - Email streaming configuration.
            type: list
            elements: dict
          message_bus:
            description:
            - Message bus configuration.
            type: list
            elements: dict
          syslog:
            description:
            - Syslog streaming configuration.
            type: dict
          webhooks:
            description:
            - Webhook configuration.
            type: list
            elements: dict
  state:
    description:
    - The desired state of the fabric resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new fabrics and update existing ones as defined in the configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the fabric configuration specified in the configuration.
      Any settings not explicitly provided will revert to their defaults.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      Any fabric existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the fabrics specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1.0 or higher.
- Only eBGP VXLAN fabric type (C(vxlanEbgp)) is supported by this module.
- When using O(state=replaced) with only required fields, all optional management settings revert to their defaults.
- The O(config.management.bgp_asn) field is optional when O(config.management.bgp_asn_auto_allocation) is C(true).
- The O(config.management.bgp_asn) field is required when O(config.management.bgp_asn_auto_allocation) is C(false).
- O(config.management.site_id) defaults to the value of O(config.management.bgp_asn) if not provided.
- The default O(config.management.vpc_peer_keep_alive_option) for eBGP fabrics is C(management), unlike iBGP fabrics.
"""

EXAMPLES = r"""
- name: Create an eBGP VXLAN fabric using state merged (with auto ASN allocation)
  cisco.nd.nd_manage_fabric_ebgp:
    state: merged
    config:
      - fabric_name: my_ebgp_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanEbgp
          bgp_asn_auto_allocation: true
          bgp_asn_range: "65000-65535"
          bgp_as_mode: multiAS
          target_subnet_mask: 30
          anycast_gateway_mac: "2020.0000.00aa"
          performance_monitoring: false
          replication_mode: multicast
          multicast_group_subnet: "239.1.1.0/25"
          auto_generate_multicast_group_address: false
          underlay_multicast_group_address_limit: 128
          tenant_routed_multicast: false
          rendezvous_point_count: 2
          rendezvous_point_loopback_id: 254
          vpc_peer_link_vlan: "3600"
          vpc_peer_link_enable_native_vlan: false
          vpc_peer_keep_alive_option: management
          vpc_auto_recovery_timer: 360
          vpc_delay_restore_timer: 150
          vpc_peer_link_port_channel_id: "500"
          advertise_physical_ip: false
          vpc_domain_id_range: "1-1000"
          bgp_loopback_id: 0
          nve_loopback_id: 1
          vrf_template: Default_VRF_Universal
          network_template: Default_Network_Universal
          vrf_extension_template: Default_VRF_Extension_Universal
          network_extension_template: Default_Network_Extension_Universal
          l3_vni_no_vlan_default_option: false
          fabric_mtu: 9216
          l2_host_interface_mtu: 9216
          tenant_dhcp: true
          nxapi: false
          nxapi_https_port: 443
          nxapi_http: false
          nxapi_http_port: 80
          snmp_trap: true
          anycast_border_gateway_advertise_physical_ip: false
          greenfield_debug_flag: disable
          tcam_allocation: true
          real_time_interface_statistics_collection: false
          interface_statistics_load_interval: 10
          bgp_loopback_ip_range: "10.2.0.0/22"
          nve_loopback_ip_range: "10.3.0.0/22"
          anycast_rendezvous_point_ip_range: "10.254.254.0/24"
          intra_fabric_subnet_range: "10.4.0.0/16"
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          network_vlan_range: "2300-2999"
          vrf_vlan_range: "2000-2299"
          sub_interface_dot1q_range: "2-511"
          vrf_lite_auto_config: manual
          vrf_lite_subnet_range: "10.33.0.0/16"
          vrf_lite_subnet_target_mask: 30
          auto_unique_vrf_lite_ip_prefix: false
          per_vrf_loopback_auto_provision: true
          per_vrf_loopback_ip_range: "10.5.0.0/22"
          banner: ""
          day0_bootstrap: false
          local_dhcp_server: false
          dhcp_protocol_version: dhcpv4
          dhcp_start_address: ""
          dhcp_end_address: ""
          management_gateway: ""
          management_ipv4_prefix: 24
  register: result

- name: Create an eBGP VXLAN fabric with a static BGP ASN
  cisco.nd.nd_manage_fabric_ebgp:
    state: merged
    config:
      - fabric_name: my_ebgp_fabric_static
        category: fabric
        management:
          type: vxlanEbgp
          bgp_asn: "65001"
          bgp_asn_auto_allocation: false
          site_id: "65001"
          bgp_as_mode: multiAS
          target_subnet_mask: 30
          anycast_gateway_mac: "2020.0000.00aa"
          replication_mode: multicast
          multicast_group_subnet: "239.1.1.0/25"
          bgp_loopback_ip_range: "10.2.0.0/22"
          nve_loopback_ip_range: "10.3.0.0/22"
          anycast_rendezvous_point_ip_range: "10.254.254.0/24"
          intra_fabric_subnet_range: "10.4.0.0/16"
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          network_vlan_range: "2300-2999"
          vrf_vlan_range: "2000-2299"
  register: result

- name: Update specific fields on an existing eBGP fabric using state merged (partial update)
  cisco.nd.nd_manage_fabric_ebgp:
    state: merged
    config:
      - fabric_name: my_ebgp_fabric
        category: fabric
        management:
          bgp_asn_range: "65100-65199"
          anycast_gateway_mac: "2020.0000.00bb"
          performance_monitoring: true
  register: result

- name: Create or fully replace an eBGP VXLAN fabric using state replaced
  cisco.nd.nd_manage_fabric_ebgp:
    state: replaced
    config:
      - fabric_name: my_ebgp_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanEbgp
          bgp_asn: "65004"
          bgp_asn_auto_allocation: false
          site_id: "65004"
          bgp_as_mode: multiAS
          target_subnet_mask: 30
          anycast_gateway_mac: "2020.0000.00dd"
          performance_monitoring: true
          replication_mode: multicast
          multicast_group_subnet: "239.1.3.0/25"
          rendezvous_point_count: 3
          rendezvous_point_loopback_id: 253
          vpc_peer_link_vlan: "3700"
          vpc_peer_keep_alive_option: management
          vpc_auto_recovery_timer: 300
          vpc_delay_restore_timer: 120
          vpc_peer_link_port_channel_id: "600"
          advertise_physical_ip: true
          vpc_domain_id_range: "1-800"
          fabric_mtu: 9000
          l2_host_interface_mtu: 9000
          tenant_dhcp: false
          snmp_trap: false
          anycast_border_gateway_advertise_physical_ip: true
          greenfield_debug_flag: disable
          tcam_allocation: false
          real_time_interface_statistics_collection: true
          interface_statistics_load_interval: 30
          bgp_loopback_ip_range: "10.22.0.0/22"
          nve_loopback_ip_range: "10.23.0.0/22"
          anycast_rendezvous_point_ip_range: "10.254.252.0/24"
          intra_fabric_subnet_range: "10.24.0.0/16"
          l2_vni_range: "40000-59000"
          l3_vni_range: "60000-69000"
          network_vlan_range: "2400-3099"
          vrf_vlan_range: "2100-2399"
          banner: "^ Managed by Ansible ^"
  register: result

- name: Replace fabric with only required fields (all optional settings revert to defaults)
  cisco.nd.nd_manage_fabric_ebgp:
    state: replaced
    config:
      - fabric_name: my_ebgp_fabric
        category: fabric
        management:
          type: vxlanEbgp
          bgp_asn: "65004"
          bgp_asn_auto_allocation: false
          site_id: "65004"
          banner: "^ Managed by Ansible ^"
  register: result

- name: Enforce exact fabric inventory using state overridden (deletes unlisted fabrics)
  cisco.nd.nd_manage_fabric_ebgp:
    state: overridden
    config:
      - fabric_name: fabric_east
        category: fabric
        location:
          latitude: 40.7128
          longitude: -74.0060
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanEbgp
          bgp_asn: "65010"
          bgp_asn_auto_allocation: false
          site_id: "65010"
          bgp_as_mode: multiAS
          target_subnet_mask: 30
          anycast_gateway_mac: "2020.0000.0010"
          replication_mode: multicast
          multicast_group_subnet: "239.1.10.0/25"
          bgp_loopback_ip_range: "10.10.0.0/22"
          nve_loopback_ip_range: "10.11.0.0/22"
          anycast_rendezvous_point_ip_range: "10.254.10.0/24"
          intra_fabric_subnet_range: "10.12.0.0/16"
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          network_vlan_range: "2300-2999"
          vrf_vlan_range: "2000-2299"
      - fabric_name: fabric_west
        category: fabric
        location:
          latitude: 34.0522
          longitude: -118.2437
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanEbgp
          bgp_asn: "65020"
          bgp_asn_auto_allocation: false
          site_id: "65020"
          bgp_as_mode: multiAS
          target_subnet_mask: 30
          anycast_gateway_mac: "2020.0000.0020"
          replication_mode: multicast
          multicast_group_subnet: "239.1.20.0/25"
          bgp_loopback_ip_range: "10.20.0.0/22"
          nve_loopback_ip_range: "10.21.0.0/22"
          anycast_rendezvous_point_ip_range: "10.254.20.0/24"
          intra_fabric_subnet_range: "10.22.0.0/16"
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          network_vlan_range: "2300-2999"
          vrf_vlan_range: "2000-2299"
  register: result

- name: Delete a specific eBGP fabric using state deleted
  cisco.nd.nd_manage_fabric_ebgp:
    state: deleted
    config:
      - fabric_name: my_ebgp_fabric
  register: result

- name: Delete multiple eBGP fabrics in a single task
  cisco.nd.nd_manage_fabric_ebgp:
    state: deleted
    config:
      - fabric_name: fabric_east
      - fabric_name: fabric_west
      - fabric_name: fabric_old
  register: result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ebgp import ManageEbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricEbgpModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageEbgpFabricOrchestrator,
        )

        # Manage state
        nd_state_machine.manage_state()

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}")


if __name__ == "__main__":
    main()
