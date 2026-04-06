#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_ibgp
version_added: "1.4.0"
short_description: Manage iBGP VXLAN fabrics on Cisco Nexus Dashboard
description:
- Manage iBGP VXLAN fabrics on Cisco Nexus Dashboard (ND).
- It supports creating, updating, replacing, and deleting iBGP VXLAN fabrics.
author:
- Mike Wiebe (@mwiebe)
options:
  config:
    description:
    - The list of iBGP VXLAN fabrics to configure.
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
        - The iBGP VXLAN management configuration for the fabric.
        type: dict
        suboptions:
          type:
            description:
            - The fabric management type. Must be C(vxlanIbgp) for iBGP VXLAN fabrics.
            type: str
            default: vxlanIbgp
            choices: [ vxlanIbgp ]
          bgp_asn:
            description:
            - The BGP Autonomous System Number for the fabric.
            - Accepts a plain integer (1-4294967295) or dotted notation (1-65535.0-65535).
            type: str
            required: true
          site_id:
            description:
            - The site identifier for the fabric (for EVPN Multi-Site support).
            - Must be a numeric value between 1 and 281474976710655.
            - Defaults to the value of O(config.management.bgp_asn) if not provided.
            type: str
            default: ""
          target_subnet_mask:
            description:
            - The target subnet mask for intra-fabric links (24-31).
            type: int
            default: 30
          anycast_gateway_mac:
            description:
            - The anycast gateway MAC address in xxxx.xxxx.xxxx format.
            type: str
            default: 2020.0000.00aa
          replication_mode:
            description:
            - The multicast replication mode.
            type: str
            default: multicast
            choices: [ multicast, ingress ]
          multicast_group_subnet:
            description:
            - The multicast group subnet.
            type: str
            default: "239.1.1.0/25"
          auto_generate_multicast_group_address:
            description:
            - Automatically generate multicast group addresses.
            type: bool
            default: false
          underlay_multicast_group_address_limit:
            description:
            - The underlay multicast group address limit.
            - The maximum supported value is 128 for NX-OS version 10.2(1) or earlier and 512 for versions above 10.2(1).
            type: int
            default: 128
            choices: [ 128, 512 ]
          tenant_routed_multicast:
            description:
            - Enable tenant routed multicast.
            type: bool
            default: false
          rendezvous_point_count:
            description:
            - The number of spines acting as Rendezvous-Points (RPs).
            type: int
            default: 2
            choices: [ 2, 4 ]
          rendezvous_point_loopback_id:
            description:
            - The rendezvous point loopback interface ID (0-1023).
            type: int
            default: 254
          overlay_mode:
            description:
            - The overlay configuration mode.
            type: str
            default: cli
            choices: [ cli, config-profile ]
          link_state_routing_protocol:
            description:
            - The underlay link-state routing protocol.
            type: str
            default: ospf
            choices: [ ospf, isis ]
          ospf_area_id:
            description:
            - The OSPF area ID.
            type: str
            default: "0.0.0.0"
          fabric_interface_type:
            description:
            - The fabric interface type. Numbered (Point-to-Point) or unnumbered.
            type: str
            default: p2p
            choices: [ p2p, unNumbered ]
          bgp_loopback_id:
            description:
            - The BGP loopback interface ID (0-1023).
            type: int
            default: 0
          nve_loopback_id:
            description:
            - The NVE loopback interface ID (0-1023).
            type: int
            default: 1
          route_reflector_count:
            description:
            - The number of spines acting as BGP route reflectors.
            type: int
            default: 2
            choices: [ 2, 4 ]
          bgp_loopback_ip_range:
            description:
            - The BGP loopback IP address pool.
            type: str
            default: "10.2.0.0/22"
          nve_loopback_ip_range:
            description:
            - The NVE loopback IP address pool.
            type: str
            default: "10.3.0.0/22"
          anycast_rendezvous_point_ip_range:
            description:
            - The anycast rendezvous point IP address pool.
            type: str
            default: "10.254.254.0/24"
          intra_fabric_subnet_range:
            description:
            - The intra-fabric subnet IP address pool.
            type: str
            default: "10.4.0.0/16"
          router_id_range:
            description:
            - The BGP router ID range in IPv4 subnet format. Used for IPv6 underlay.
            type: str
            default: "10.2.0.0/23"
          l2_vni_range:
            description:
            - The Layer 2 VNI range.
            type: str
            default: "30000-49000"
          l3_vni_range:
            description:
            - The Layer 3 VNI range.
            type: str
            default: "50000-59000"
          network_vlan_range:
            description:
            - The network VLAN range.
            type: str
            default: "2300-2999"
          vrf_vlan_range:
            description:
            - The VRF VLAN range.
            type: str
            default: "2000-2299"
          sub_interface_dot1q_range:
            description:
            - The sub-interface 802.1q range (minimum 2, maximum 4093).
            type: str
            default: "2-511"
          l3_vni_no_vlan_default_option:
            description:
            - Enable L3 VNI no-VLAN default option.
            type: bool
            default: false
          fabric_mtu:
            description:
            - The fabric MTU size (1500-9216).
            type: int
            default: 9216
          l2_host_interface_mtu:
            description:
            - The L2 host interface MTU size (1500-9216).
            type: int
            default: 9216
          vpc_domain_id_range:
            description:
            - The vPC domain ID range.
            type: str
            default: "1-1000"
          vpc_peer_link_vlan:
            description:
            - The vPC peer link VLAN ID.
            type: str
            default: "3600"
          vpc_peer_link_enable_native_vlan:
            description:
            - Enable native VLAN on the vPC peer link.
            type: bool
            default: false
          vpc_peer_keep_alive_option:
            description:
            - The vPC peer keep-alive option.
            type: str
            default: management
            choices: [ loopback, management ]
          vpc_auto_recovery_timer:
            description:
            - The vPC auto recovery timer in seconds (240-3600).
            type: int
            default: 360
          vpc_delay_restore_timer:
            description:
            - The vPC delay restore timer in seconds (1-3600).
            type: int
            default: 150
          vpc_peer_link_port_channel_id:
            description:
            - The vPC peer link port-channel ID.
            type: str
            default: "500"
          vpc_ipv6_neighbor_discovery_sync:
            description:
            - Enable vPC IPv6 neighbor discovery synchronization.
            type: bool
            default: true
          vpc_layer3_peer_router:
            description:
            - Enable vPC layer-3 peer router.
            type: bool
            default: true
          vpc_tor_delay_restore_timer:
            description:
            - The vPC TOR delay restore timer.
            type: int
            default: 30
          fabric_vpc_domain_id:
            description:
            - Enable fabric vPC domain ID.
            type: bool
            default: false
          shared_vpc_domain_id:
            description:
            - The shared vPC domain ID.
            type: int
            default: 1
          fabric_vpc_qos:
            description:
            - Enable fabric vPC QoS.
            type: bool
            default: false
          fabric_vpc_qos_policy_name:
            description:
            - The fabric vPC QoS policy name.
            type: str
            default: spine_qos_for_fabric_vpc_peering
          enable_peer_switch:
            description:
            - Enable peer switch.
            type: bool
            default: false
          vrf_template:
            description:
            - The VRF template name.
            type: str
            default: Default_VRF_Universal
          network_template:
            description:
            - The network template name.
            type: str
            default: Default_Network_Universal
          vrf_extension_template:
            description:
            - The VRF extension template name.
            type: str
            default: Default_VRF_Extension_Universal
          network_extension_template:
            description:
            - The network extension template name.
            type: str
            default: Default_Network_Extension_Universal
          performance_monitoring:
            description:
            - Enable performance monitoring.
            type: bool
            default: false
          tenant_dhcp:
            description:
            - Enable tenant DHCP.
            type: bool
            default: true
          advertise_physical_ip:
            description:
            - Advertise physical IP address for NVE loopback.
            type: bool
            default: false
          advertise_physical_ip_on_border:
            description:
            - Advertise physical IP address on border switches.
            type: bool
            default: true
          anycast_border_gateway_advertise_physical_ip:
            description:
            - Enable anycast border gateway to advertise physical IP.
            type: bool
            default: false
          snmp_trap:
            description:
            - Enable SNMP traps.
            type: bool
            default: true
          cdp:
            description:
            - Enable CDP.
            type: bool
            default: false
          tcam_allocation:
            description:
            - Enable TCAM allocation.
            type: bool
            default: true
          real_time_interface_statistics_collection:
            description:
            - Enable real-time interface statistics collection.
            type: bool
            default: false
          interface_statistics_load_interval:
            description:
            - The interface statistics load interval in seconds.
            type: int
            default: 10
          greenfield_debug_flag:
            description:
            - Allow switch configuration to be cleared without a reload when preserveConfig is set to false.
            type: str
            default: disable
            choices: [ enable, disable ]
          nxapi:
            description:
            - Enable NX-API (HTTPS).
            type: bool
            default: false
          nxapi_https_port:
            description:
            - The NX-API HTTPS port (1-65535).
            type: int
            default: 443
          nxapi_http:
            description:
            - Enable NX-API over HTTP.
            type: bool
            default: false
          nxapi_http_port:
            description:
            - The NX-API HTTP port (1-65535).
            type: int
            default: 80
          bgp_authentication:
            description:
            - Enable BGP authentication.
            type: bool
            default: false
          bgp_authentication_key_type:
            description:
            - "BGP key encryption type: 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7."
            type: str
            default: 3des
            choices: [ 3des, type6, type7 ]
          bgp_authentication_key:
            description:
            - The BGP authentication key.
            type: str
            default: ""
          bfd:
            description:
            - Enable BFD globally.
            type: bool
            default: false
          bfd_ibgp:
            description:
            - Enable BFD for iBGP sessions.
            type: bool
            default: false
          bfd_ospf:
            description:
            - Enable BFD for OSPF.
            type: bool
            default: false
          bfd_isis:
            description:
            - Enable BFD for IS-IS.
            type: bool
            default: false
          bfd_pim:
            description:
            - Enable BFD for PIM.
            type: bool
            default: false
          bfd_authentication:
            description:
            - Enable BFD authentication.
            type: bool
            default: false
          bfd_authentication_key_id:
            description:
            - The BFD authentication key ID.
            type: int
            default: 100
          bfd_authentication_key:
            description:
            - The BFD authentication key.
            type: str
            default: ""
          ospf_authentication:
            description:
            - Enable OSPF authentication.
            type: bool
            default: false
          ospf_authentication_key_id:
            description:
            - The OSPF authentication key ID.
            type: int
            default: 127
          ospf_authentication_key:
            description:
            - The OSPF authentication key.
            type: str
            default: ""
          pim_hello_authentication:
            description:
            - Enable PIM hello authentication.
            type: bool
            default: false
          pim_hello_authentication_key:
            description:
            - The PIM hello authentication key.
            type: str
            default: ""
          isis_level:
            description:
            - The IS-IS level.
            type: str
            default: level-2
            choices: [ level-1, level-2 ]
          isis_area_number:
            description:
            - The IS-IS area number.
            type: str
            default: "0001"
          isis_point_to_point:
            description:
            - Enable IS-IS point-to-point.
            type: bool
            default: true
          isis_authentication:
            description:
            - Enable IS-IS authentication.
            type: bool
            default: false
          isis_authentication_keychain_name:
            description:
            - The IS-IS authentication keychain name.
            type: str
            default: ""
          isis_authentication_keychain_key_id:
            description:
            - The IS-IS authentication keychain key ID.
            type: int
            default: 127
          isis_authentication_key:
            description:
            - The IS-IS authentication key.
            type: str
            default: ""
          isis_overload:
            description:
            - Enable IS-IS overload bit.
            type: bool
            default: true
          isis_overload_elapse_time:
            description:
            - The IS-IS overload elapse time in seconds.
            type: int
            default: 60
          macsec:
            description:
            - Enable MACsec on intra-fabric links.
            type: bool
            default: false
          macsec_cipher_suite:
            description:
            - The MACsec cipher suite.
            type: str
            default: GCM-AES-XPN-256
            choices: [ GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128, GCM-AES-XPN-256 ]
          macsec_key_string:
            description:
            - The MACsec primary key string.
            type: str
            default: ""
          macsec_algorithm:
            description:
            - The MACsec primary cryptographic algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          macsec_fallback_key_string:
            description:
            - The MACsec fallback key string.
            type: str
            default: ""
          macsec_fallback_algorithm:
            description:
            - The MACsec fallback cryptographic algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          macsec_report_timer:
            description:
            - The MACsec report timer.
            type: int
            default: 5
          vrf_lite_macsec:
            description:
            - Enable MACsec on DCI links.
            type: bool
            default: false
          vrf_lite_macsec_cipher_suite:
            description:
            - The DCI MACsec cipher suite.
            type: str
            default: GCM-AES-XPN-256
            choices: [ GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128, GCM-AES-XPN-256 ]
          vrf_lite_macsec_key_string:
            description:
            - The DCI MACsec primary key string (Cisco Type 7 Encrypted Octet String).
            type: str
            default: ""
          vrf_lite_macsec_algorithm:
            description:
            - The DCI MACsec primary cryptographic algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          vrf_lite_macsec_fallback_key_string:
            description:
            - The DCI MACsec fallback key string (Cisco Type 7 Encrypted Octet String).
            - This parameter is used when DCI link has QKD disabled.
            type: str
            default: ""
          vrf_lite_macsec_fallback_algorithm:
            description:
            - The DCI MACsec fallback cryptographic algorithm.
            - This parameter is used when DCI link has QKD disabled.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          quantum_key_distribution:
            description:
            - Enable quantum key distribution.
            type: bool
            default: false
          quantum_key_distribution_profile_name:
            description:
            - The quantum key distribution profile name.
            type: str
            default: ""
          key_management_entity_server_ip:
            description:
            - The key management entity server IP address.
            type: str
            default: ""
          key_management_entity_server_port:
            description:
            - The key management entity server port.
            type: int
            default: 0
          trustpoint_label:
            description:
            - The trustpoint label for TLS authentication.
            type: str
            default: ""
          skip_certificate_verification:
            description:
            - Skip verification of incoming certificate.
            type: bool
            default: false
          vrf_lite_auto_config:
            description:
            - "VRF Lite Inter-Fabric Connection deployment options. If C(back2BackAndToExternal) is selected,
              VRF Lite IFCs are auto created between border devices of two Easy Fabrics, and between
              border devices in Easy Fabric and edge routers in External Fabric."
            type: str
            default: manual
            choices: [ manual, back2BackAndToExternal ]
          vrf_lite_subnet_range:
            description:
            - The VRF lite subnet IP address pool.
            type: str
            default: "10.33.0.0/16"
          vrf_lite_subnet_target_mask:
            description:
            - The VRF lite subnet target mask.
            type: int
            default: 30
          auto_unique_vrf_lite_ip_prefix:
            description:
            - Enable auto unique VRF lite IP prefix.
            type: bool
            default: false
          auto_symmetric_vrf_lite:
            description:
            - Enable auto symmetric VRF lite.
            type: bool
            default: false
          auto_vrf_lite_default_vrf:
            description:
            - Enable auto VRF lite for the default VRF.
            type: bool
            default: false
          auto_symmetric_default_vrf:
            description:
            - Enable auto symmetric default VRF.
            type: bool
            default: false
          default_vrf_redistribution_bgp_route_map:
            description:
            - Route Map used to redistribute BGP routes to IGP in default VRF in auto created VRF Lite IFC links.
            type: str
            default: extcon-rmap-filter
          per_vrf_loopback_auto_provision:
            description:
            - Enable per-VRF loopback auto-provisioning.
            type: bool
            default: false
          per_vrf_loopback_ip_range:
            description:
            - The per-VRF loopback IP address pool.
            type: str
            default: "10.5.0.0/22"
          per_vrf_loopback_auto_provision_ipv6:
            description:
            - Enable per-VRF loopback auto-provisioning for IPv6.
            type: bool
            default: false
          per_vrf_loopback_ipv6_range:
            description:
            - The per-VRF loopback IPv6 address pool.
            type: str
            default: "fd00::a05:0/112"
          per_vrf_unique_loopback_auto_provision:
            description:
            - Auto provision a unique IPv4 loopback on a VTEP on VRF attachment.
            - This option and per VRF per VTEP loopback auto-provisioning are mutually exclusive.
            type: bool
            default: false
          per_vrf_unique_loopback_ip_range:
            description:
            - Prefix pool to assign unique IPv4 addresses to loopbacks on VTEPs on a per VRF basis.
            type: str
            default: "10.6.0.0/22"
          per_vrf_unique_loopback_auto_provision_v6:
            description:
            - Auto provision a unique IPv6 loopback on a VTEP on VRF attachment.
            type: bool
            default: false
          per_vrf_unique_loopback_ipv6_range:
            description:
            - Prefix pool to assign unique IPv6 addresses to loopbacks on VTEPs on a per VRF basis.
            type: str
            default: "fd00::a06:0/112"
          underlay_ipv6:
            description:
            - Enable IPv6 underlay.
            type: bool
            default: false
          ipv6_multicast_group_subnet:
            description:
            - The IPv6 multicast group subnet.
            type: str
            default: "ff1e::/121"
          tenant_routed_multicast_ipv6:
            description:
            - Enable tenant routed multicast for IPv6.
            type: bool
            default: false
          ipv6_link_local:
            description:
            - Enable IPv6 link-local addressing.
            type: bool
            default: true
          ipv6_subnet_target_mask:
            description:
            - The IPv6 subnet target mask.
            type: int
            default: 126
          ipv6_subnet_range:
            description:
            - The IPv6 subnet range.
            type: str
            default: "fd00::a04:0/112"
          bgp_loopback_ipv6_range:
            description:
            - The BGP loopback IPv6 address pool.
            type: str
            default: "fd00::a02:0/119"
          nve_loopback_ipv6_range:
            description:
            - The NVE loopback IPv6 address pool.
            type: str
            default: "fd00::a03:0/118"
          ipv6_anycast_rendezvous_point_ip_range:
            description:
            - The IPv6 anycast rendezvous point IP address pool.
            type: str
            default: "fd00::254:254:0/118"
          mvpn_vrf_route_import_id:
            description:
            - Enable MVPN VRI ID generation for Tenant Routed Multicast with IPv4 underlay.
            type: bool
            default: true
          mvpn_vrf_route_import_id_range:
            description:
            - MVPN VRI ID range (minimum 1, maximum 65535) for vPC.
            - Applicable when TRM is enabled with IPv6 underlay, or mvpn_vrf_route_import_id is enabled with IPv4 underlay.
            type: str
            default: ""
          vrf_route_import_id_reallocation:
            description:
            - One time VRI ID re-allocation based on MVPN VRI ID Range.
            type: bool
            default: false
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
          rendezvous_point_mode:
            description:
            - Multicast rendezvous point mode. For IPv6 underlay, use C(asm) only.
            type: str
            default: asm
            choices: [ asm, bidir ]
          phantom_rendezvous_point_loopback_id1:
            description:
            - Underlay phantom RP loopback primary ID for PIM Bi-dir deployments.
            type: int
            default: 2
          phantom_rendezvous_point_loopback_id2:
            description:
            - Underlay phantom RP loopback secondary ID for PIM Bi-dir deployments.
            type: int
            default: 3
          phantom_rendezvous_point_loopback_id3:
            description:
            - Underlay phantom RP loopback tertiary ID for PIM Bi-dir deployments.
            type: int
            default: 4
          phantom_rendezvous_point_loopback_id4:
            description:
            - Underlay phantom RP loopback quaternary ID for PIM Bi-dir deployments.
            type: int
            default: 5
          anycast_loopback_id:
            description:
            - Underlay Anycast Loopback ID. Used for vPC Peering in VXLANv6 Fabrics.
            type: int
            default: 10
          auto_bgp_neighbor_description:
            description:
            - Enable automatic BGP neighbor description.
            type: bool
            default: true
          ibgp_peer_template:
            description:
            - The iBGP peer template name.
            type: str
            default: ""
          leaf_ibgp_peer_template:
            description:
            - The leaf iBGP peer template name.
            type: str
            default: ""
          link_state_routing_tag:
            description:
            - The link state routing tag.
            type: str
            default: UNDERLAY
          static_underlay_ip_allocation:
            description:
            - Enable static underlay IP allocation.
            type: bool
            default: false
          security_group_tag:
            description:
            - Enable Security Group Tag (SGT) support.
            type: bool
            default: false
          security_group_tag_prefix:
            description:
            - The SGT prefix.
            type: str
            default: SG_
          security_group_tag_mac_segmentation:
            description:
            - Enable SGT MAC segmentation.
            type: bool
            default: false
          security_group_tag_id_range:
            description:
            - The SGT ID range.
            type: str
            default: "10000-14000"
          security_group_tag_preprovision:
            description:
            - Enable SGT pre-provisioning.
            type: bool
            default: false
          security_group_status:
            description:
            - The security group status.
            type: str
            default: disabled
            choices: [ enabled, enabledStrict, enabledLoose, enablePending, enablePendingStrict, enablePendingLoose, disablePending, disabled ]
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
            - Queuing policy for all Nexus R-series switches.
            type: str
            default: queuing_policy_default_r_series
          default_queuing_policy_other:
            description:
            - Queuing policy for all other switches in the fabric.
            type: str
            default: queuing_policy_default_other
          aiml_qos:
            description:
            - Enable AI/ML QoS. Configures QoS and queuing policies specific to N9K Cloud Scale and Silicon One switch fabric
              for AI network workloads.
            type: bool
            default: false
          aiml_qos_policy:
            description:
            - Queuing policy based on predominant fabric link speed.
            type: str
            default: 400G
            choices: [ 800G, 400G, 100G, 25G, User-defined ]
          roce_v2:
            description:
            - DSCP for RDMA traffic. Numeric (0-63) with ranges/comma, or named values.
            type: str
            default: "26"
          cnp:
            description:
            - DSCP value for Congestion Notification. Numeric (0-63) with ranges/comma, or named values.
            type: str
            default: "48"
          wred_min:
            description:
            - WRED minimum threshold (in kbytes).
            type: int
            default: 950
          wred_max:
            description:
            - WRED maximum threshold (in kbytes).
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
            - Enable fabric-level Dynamic Load Balancing (DLB). Inter-Switch-Links will be configured as DLB interfaces.
            type: bool
            default: false
          dlb_mode:
            description:
            - "Select system-wide DLB mode: flowlet, per-packet (packet spraying), or policy driven mixed mode.
              Mixed mode is supported on Silicon One (S1) platform only."
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
            - "Flowlet aging timer in microseconds. Valid range depends on platform: Cloud Scale (CS)=1-2000000,
              Silicon One (S1)=1-1024."
            type: int
            default: 1
          flowlet_dscp:
            description:
            - DSCP values for flowlet load balancing. Numeric (0-63) with ranges/comma, or named values.
            type: str
            default: ""
          per_packet_dscp:
            description:
            - DSCP values for per-packet load balancing. Numeric (0-63) with ranges/comma, or named values.
            type: str
            default: ""
          ai_load_sharing:
            description:
            - Enable IP load sharing using source and destination address for AI workloads.
            type: bool
            default: false
          priority_flow_control_watch_interval:
            description:
            - PFC watch interval in milliseconds (101-1000). Leave blank for system default (100ms).
            type: int
            default: 101
          ptp:
            description:
            - Enable Precision Time Protocol (PTP).
            type: bool
            default: false
          ptp_loopback_id:
            description:
            - The PTP loopback ID.
            type: int
            default: 0
          ptp_domain_id:
            description:
            - The PTP domain ID for multiple independent PTP clocking subdomains on a single network.
            type: int
            default: 0
          ptp_vlan_id:
            description:
            - Precision Time Protocol (PTP) source VLAN ID. SVI used for PTP source on ToRs.
            type: int
            default: 2
          stp_root_option:
            description:
            - "Which protocol to use for configuring root bridge: rpvst+ (Rapid Per-VLAN Spanning Tree),
              mst (Multiple Spanning Tree), or unmanaged (STP Root not managed by ND)."
            type: str
            default: unmanaged
            choices: [ rpvst+, mst, unmanaged ]
          stp_vlan_range:
            description:
            - The STP VLAN range (minimum 1, maximum 4094).
            type: str
            default: "1-3967"
          mst_instance_range:
            description:
            - The MST instance range (minimum 0, maximum 4094).
            type: str
            default: "0"
          stp_bridge_priority:
            description:
            - The STP bridge priority.
            type: int
            default: 0
          mpls_handoff:
            description:
            - Enable MPLS handoff.
            type: bool
            default: false
          mpls_loopback_identifier:
            description:
            - The MPLS loopback identifier used for VXLAN to MPLS SR/LDP Handoff.
            type: int
            default: 101
          mpls_isis_area_number:
            description:
            - IS-IS area number for DCI MPLS link. Used only if routing protocol on DCI MPLS link is IS-IS.
            type: str
            default: "0001"
          mpls_loopback_ip_range:
            description:
            - The MPLS loopback IP address pool.
            type: str
            default: "10.101.0.0/25"
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
          allow_vlan_on_leaf_tor_pairing:
            description:
            - "Set trunk allowed VLAN to 'none' or 'all' for leaf-TOR pairing port-channels."
            type: str
            default: none
            choices: [ none, all ]
          leaf_tor_id_range:
            description:
            - Use specific vPC/Port-channel ID range for leaf-TOR pairings.
            type: bool
            default: false
          leaf_tor_vpc_port_channel_id_range:
            description:
            - Specify vPC/Port-channel ID range (minimum 1, maximum 4096) for leaf-TOR pairings.
            type: str
            default: "1-499"
          ip_service_level_agreement_id_range:
            description:
            - The IP SLA ID range.
            type: str
            default: "10000-19999"
          object_tracking_number_range:
            description:
            - The object tracking number range.
            type: str
            default: "100-299"
          route_map_sequence_number_range:
            description:
            - The route map sequence number range (minimum 1, maximum 65534).
            type: str
            default: "1-65534"
          service_network_vlan_range:
            description:
            - Per Switch Overlay Service Network VLAN Range (minimum 2, maximum 4094).
            type: str
            default: "3000-3199"
          day0_bootstrap:
            description:
            - Enable day-0 bootstrap (POAP).
            type: bool
            default: false
          local_dhcp_server:
            description:
            - Enable local DHCP server for bootstrap.
            type: bool
            default: false
          dhcp_protocol_version:
            description:
            - The IP protocol version for local DHCP server.
            type: str
            default: dhcpv4
            choices: [ dhcpv4, dhcpv6 ]
          dhcp_start_address:
            description:
            - The DHCP start address for bootstrap.
            type: str
            default: ""
          dhcp_end_address:
            description:
            - The DHCP end address for bootstrap.
            type: str
            default: ""
          management_gateway:
            description:
            - The management gateway for bootstrap.
            type: str
            default: ""
          management_ipv4_prefix:
            description:
            - The management IPv4 prefix length for bootstrap.
            type: int
            default: 24
          management_ipv6_prefix:
            description:
            - The management IPv6 prefix length for bootstrap.
            type: int
            default: 64
          extra_config_nxos_bootstrap:
            description:
            - Additional CLIs required during device bootup/login (e.g. AAA/Radius).
            type: str
            default: ""
          unnumbered_bootstrap_loopback_id:
            description:
            - Bootstrap Seed Switch Loopback Interface ID.
            type: int
            default: 253
          unnumbered_dhcp_start_address:
            description:
            - Switch Loopback DHCP Scope Start Address. Must be a subset of IGP/BGP Loopback Prefix Pool.
            type: str
            default: ""
          unnumbered_dhcp_end_address:
            description:
            - Switch Loopback DHCP Scope End Address. Must be a subset of IGP/BGP Loopback Prefix Pool.
            type: str
            default: ""
          inband_management:
            description:
            - Manage switches with only inband connectivity.
            type: bool
            default: false
          inband_dhcp_servers:
            description:
            - List of external DHCP server IP addresses (Max 3).
            type: list
            elements: str
          seed_switch_core_interfaces:
            description:
            - Seed switch fabric interfaces. Core-facing interface list on seed switch.
            type: list
            elements: str
          spine_switch_core_interfaces:
            description:
            - Spine switch fabric interfaces. Core-facing interface list on all spines.
            type: list
            elements: str
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
                - Default gateway for bootstrap subnet.
                type: str
                required: true
              subnet_prefix:
                description:
                - Subnet prefix length (8-30).
                type: int
                required: true
          netflow_settings:
            description:
            - Settings associated with netflow.
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
            - Enable real-time backup.
            type: bool
            default: false
          scheduled_backup:
            description:
            - Enable scheduled backup.
            type: bool
            default: false
          scheduled_backup_time:
            description:
            - The scheduled backup time.
            type: str
            default: ""
          nve_hold_down_timer:
            description:
            - The NVE hold-down timer in seconds.
            type: int
            default: 180
          next_generation_oam:
            description:
            - Enable the Next Generation (NG) OAM feature for all switches in the fabric.
            type: bool
            default: true
          ngoam_south_bound_loop_detect:
            description:
            - Enable the Next Generation (NG) OAM southbound loop detection.
            type: bool
            default: false
          ngoam_south_bound_loop_detect_probe_interval:
            description:
            - Set NG OAM southbound loop detection probe interval in seconds.
            type: int
            default: 300
          ngoam_south_bound_loop_detect_recovery_interval:
            description:
            - Set NG OAM southbound loop detection recovery interval in seconds.
            type: int
            default: 600
          strict_config_compliance_mode:
            description:
            - Enable bi-directional compliance checks to flag additional configs in the running config
              that are not in the intent/expected config.
            type: bool
            default: false
          advanced_ssh_option:
            description:
            - Enable AAA IP Authorization. Enable only when IP Authorization is enabled in the AAA Server.
            type: bool
            default: false
          copp_policy:
            description:
            - The fabric wide CoPP policy. Customized CoPP policy should be provided when C(manual) is selected.
            type: str
            default: strict
            choices: [ dense, lenient, moderate, strict, manual ]
          power_redundancy_mode:
            description:
            - Default power supply mode for NX-OS switches.
            type: str
            default: redundant
            choices: [ redundant, combined, inputSrcRedundant ]
          host_interface_admin_state:
            description:
            - Enable host interface admin state.
            type: bool
            default: true
          heartbeat_interval:
            description:
            - The heartbeat interval.
            type: int
            default: 190
          policy_based_routing:
            description:
            - Enable policy-based routing.
            type: bool
            default: false
          brownfield_network_name_format:
            description:
            - The brownfield network name format.
            type: str
            default: "Auto_Net_VNI$$VNI$$_VLAN$$VLAN_ID$$"
          brownfield_skip_overlay_network_attachments:
            description:
            - Skip brownfield overlay network attachments.
            type: bool
            default: false
          allow_smart_switch_onboarding:
            description:
            - Enable onboarding of smart switches to Hypershield for firewall service.
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
          aaa:
            description:
            - Enable AAA.
            type: bool
            default: false
          extra_config_leaf:
            description:
            - Extra freeform configuration applied to leaf switches.
            type: str
            default: ""
          extra_config_spine:
            description:
            - Extra freeform configuration applied to spine switches.
            type: str
            default: ""
          extra_config_tor:
            description:
            - Extra freeform configuration applied to TOR switches.
            type: str
            default: ""
          extra_config_intra_fabric_links:
            description:
            - Extra freeform configuration applied to intra-fabric links.
            type: str
            default: ""
          extra_config_aaa:
            description:
            - Extra freeform AAA configuration.
            type: str
            default: ""
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
          banner:
            description:
            - The fabric banner text displayed on switch login.
            type: str
            default: ""
          ntp_server_collection:
            description:
            - The list of NTP server IP addresses.
            type: list
            elements: str
          ntp_server_vrf_collection:
            description:
            - The list of VRFs for NTP servers.
            type: list
            elements: str
          dns_collection:
            description:
            - The list of DNS server IP addresses.
            type: list
            elements: str
          dns_vrf_collection:
            description:
            - The list of VRFs for DNS servers.
            type: list
            elements: str
          syslog_server_collection:
            description:
            - The list of syslog server IP addresses.
            type: list
            elements: str
          syslog_server_vrf_collection:
            description:
            - The list of VRFs for syslog servers.
            type: list
            elements: str
          syslog_severity_collection:
            description:
            - The list of syslog severity levels (0-7).
            type: list
            elements: int
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
- Only iBGP VXLAN fabric type (C(vxlanIbgp)) is supported by this module.
- When using O(state=replaced) with only required fields, all optional management settings revert to their defaults.
- The O(config.management.bgp_asn) field is required when creating a fabric.
- O(config.management.site_id) defaults to the value of O(config.management.bgp_asn) if not provided.
"""

EXAMPLES = r"""
- name: Create an iBGP VXLAN fabric using state merged
  cisco.nd.nd_manage_fabric_ibgp:
    state: merged
    config:
      - fabric_name: my_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanIbgp
          bgp_asn: "65001"
          site_id: "65001"
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
          vpc_peer_keep_alive_option: loopback
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
          nxapi: true
          nxapi_https_port: 443
          nxapi_http: false
          nxapi_http_port: 80
          snmp_trap: true
          anycast_border_gateway_advertise_physical_ip: false
          greenfield_debug_flag: enable
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

- name: Update specific fields on an existing fabric using state merged (partial update)
  cisco.nd.nd_manage_fabric_ibgp:
    state: merged
    config:
      - fabric_name: my_fabric
        category: fabric
        management:
          bgp_asn: "65002"
          site_id: "65002"
          anycast_gateway_mac: "2020.0000.00bb"
          performance_monitoring: true
  register: result

- name: Create or fully replace an iBGP VXLAN fabric using state replaced
  cisco.nd.nd_manage_fabric_ibgp:
    state: replaced
    config:
      - fabric_name: my_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanIbgp
          bgp_asn: "65004"
          site_id: "65004"
          target_subnet_mask: 30
          anycast_gateway_mac: "2020.0000.00dd"
          performance_monitoring: true
          replication_mode: multicast
          multicast_group_subnet: "239.1.3.0/25"
          auto_generate_multicast_group_address: false
          underlay_multicast_group_address_limit: 128
          tenant_routed_multicast: false
          rendezvous_point_count: 3
          rendezvous_point_loopback_id: 253
          vpc_peer_link_vlan: "3700"
          vpc_peer_link_enable_native_vlan: false
          vpc_peer_keep_alive_option: loopback
          vpc_auto_recovery_timer: 300
          vpc_delay_restore_timer: 120
          vpc_peer_link_port_channel_id: "600"
          vpc_ipv6_neighbor_discovery_sync: false
          advertise_physical_ip: true
          vpc_domain_id_range: "1-800"
          bgp_loopback_id: 0
          nve_loopback_id: 1
          vrf_template: Default_VRF_Universal
          network_template: Default_Network_Universal
          vrf_extension_template: Default_VRF_Extension_Universal
          network_extension_template: Default_Network_Extension_Universal
          l3_vni_no_vlan_default_option: false
          fabric_mtu: 9000
          l2_host_interface_mtu: 9000
          tenant_dhcp: false
          nxapi: false
          nxapi_https_port: 443
          nxapi_http: true
          nxapi_http_port: 80
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
          sub_interface_dot1q_range: "2-511"
          vrf_lite_auto_config: manual
          vrf_lite_subnet_range: "10.53.0.0/16"
          vrf_lite_subnet_target_mask: 30
          auto_unique_vrf_lite_ip_prefix: false
          per_vrf_loopback_auto_provision: true
          per_vrf_loopback_ip_range: "10.25.0.0/22"
          per_vrf_loopback_auto_provision_ipv6: true
          per_vrf_loopback_ipv6_range: "fd00::a25:0/112"
          banner: "^ Managed by Ansible ^"
          day0_bootstrap: false
          local_dhcp_server: false
          dhcp_protocol_version: dhcpv4
          dhcp_start_address: ""
          dhcp_end_address: ""
          management_gateway: ""
          management_ipv4_prefix: 24
          management_ipv6_prefix: 64
  register: result

- name: Replace fabric with only required fields (all optional settings revert to defaults)
  cisco.nd.nd_manage_fabric_ibgp:
    state: replaced
    config:
      - fabric_name: my_fabric
        category: fabric
        management:
          type: vxlanIbgp
          bgp_asn: "65004"
          site_id: "65004"
          banner: "^ Managed by Ansible ^"
  register: result

- name: Enforce exact fabric inventory using state overridden (deletes unlisted fabrics)
  cisco.nd.nd_manage_fabric_ibgp:
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
          type: vxlanIbgp
          bgp_asn: "65010"
          site_id: "65010"
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
          type: vxlanIbgp
          bgp_asn: "65020"
          site_id: "65020"
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

- name: Delete a specific fabric using state deleted
  cisco.nd.nd_manage_fabric_ibgp:
    state: deleted
    config:
      - fabric_name: my_fabric
  register: result

- name: Delete multiple fabrics in a single task
  cisco.nd.nd_manage_fabric_ibgp:
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp import FabricIbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp import ManageIbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricIbgpModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageIbgpFabricOrchestrator,
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
