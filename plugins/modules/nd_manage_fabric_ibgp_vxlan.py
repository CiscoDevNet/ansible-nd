#!/usr/bin/python

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_ibgp_vxlan
version_added: "2.0.0"
short_description: Manage iBGP VXLAN fabrics on Cisco Nexus Dashboard
description:
- Manage iBGP VXLAN fabrics on Cisco Nexus Dashboard (ND).
- It supports creating, updating, replacing, deleting, and gathering iBGP VXLAN fabrics.
author:
- Mike Wiebe (@mwiebe)
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of iBGP VXLAN fabrics to configure.
    - For O(state=gathered), O(config) may be omitted to return all iBGP VXLAN fabrics.
    - When O(config) is provided with O(state=gathered), every supplied supported property acts as a filter criterion.
      Criteria within one list item use AND semantics, while multiple list items use OR semantics.
    - Omitted properties are not used as gathered filter criteria, even when those properties have documented defaults.
    - "Supported gathered filter properties: O(config.fabric_name), O(config.license_tier),
      O(config.security_domain), O(config.alert_suspend), and O(config.telemetry_collection)."
    - Other properties, including properties under O(config.management), are not supported as gathered filter criteria.
    type: list
    elements: dict
    required: false
    suboptions:
      fabric_name:
        description:
        - The name of the fabric.
        - Only letters, numbers, underscores, and hyphens are allowed.
        - The O(config.fabric_name) must be defined when creating, updating or deleting a fabric.
        - Optional filter for O(state=gathered).
        type: str
        required: false
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
        - Optional filter for O(state=gathered).
        type: str
        default: essentials
        choices: [ essentials, advantage, premier ]
      alert_suspend:
        description:
        - The alert suspension state for the fabric.
        - Optional filter for O(state=gathered).
        type: str
        default: disabled
        choices: [ enabled, disabled ]
      telemetry_collection:
        description:
        - Controls whether collection type, streaming protocol, and in-band source settings take effect.
        - Enable telemetry collection for the fabric.
        - Optional filter for O(state=gathered).
        type: bool
        default: false
      telemetry_collection_type:
        description:
        - Applies when O(config.telemetry_collection=true).
        - The telemetry collection type.
        type: str
        default: inBand
        choices: [ inBand, outOfBand ]
      telemetry_streaming_protocol:
        description:
        - Applies when O(config.telemetry_collection=true).
        - The telemetry streaming protocol.
        type: str
        default: ipv4
        choices: [ ipv4, ipv6 ]
      telemetry_source_interface:
        description:
        - Applies when O(config.telemetry_collection=true) and O(config.telemetry_collection_type=inBand).
        - The telemetry source interface.
        type: str
        default: loopback0
      telemetry_source_vrf:
        description:
        - Applies when O(config.telemetry_collection=true) and O(config.telemetry_collection_type=inBand).
        - The telemetry source VRF.
        type: str
        default: default
      security_domain:
        description:
        - The security domain associated with the fabric.
        - Optional filter for O(state=gathered).
        type: str
        default: all
      management:
        description:
        - The iBGP VXLAN management configuration for the fabric.
        - Properties are grouped by template section for readability in the module documentation source.
        type: dict
        suboptions:
          # General
          bgp_asn:
            description:
            - The BGP Autonomous System Number for the fabric.
            - Accepts a plain integer (1-4294967295) or dotted notation (1-65535.0-65535).
            - Required when creating a fabric and when using O(state=replaced) or O(state=overridden).
            - May be omitted from a partial O(state=merged) update to an existing fabric.
            type: str
          underlay_ipv6:
            description:
            - Selects IPv6 underlay address pools; IPv4-only underlay features such as BFD and PIM authentication apply when disabled.
            - Enable IPv6 underlay.
            type: bool
            default: false
          fabric_interface_type:
            description:
            - When O(config.management.underlay_ipv6=true), only C(p2p) is supported.
            - C(p2p) uses numbered links; when day-0 bootstrap is enabled, C(unNumbered) uses the unnumbered bootstrap loopback and DHCP scope settings.
            - The fabric interface type. Numbered (Point-to-Point) or unnumbered.
            type: str
            default: p2p
            choices: [ p2p, unNumbered ]
          link_state_routing_protocol:
            description:
            - OSPF-specific and IS-IS-specific settings apply only when the corresponding protocol is selected.
            - The underlay link-state routing protocol.
            type: str
            default: ospf
            choices: [ ospf, isis ]
          target_subnet_mask:
            description:
            - The target subnet mask for intra-fabric links (30-31).
            type: int
            default: 30
          ipv6_link_local:
            description:
            - When enabled, O(config.management.ipv6_subnet_target_mask) and O(config.management.ipv6_subnet_range) are not editable on ND.
            - Applies when O(config.management.underlay_ipv6=true).
            - Enable IPv6 link-local addressing.
            type: bool
            default: true
          ipv6_subnet_target_mask:
            description:
            - Applies when O(config.management.underlay_ipv6=true) and O(config.management.ipv6_link_local=false).
            - The IPv6 subnet target mask.
            type: int
            default: 126
          route_reflector_count:
            description:
            - The number of spines acting as BGP route reflectors.
            type: int
            default: 2
            choices: [ 2, 4 ]
          anycast_gateway_mac:
            description:
            - The anycast gateway MAC address in xxxx.xxxx.xxxx format.
            type: str
            default: 2020.0000.00aa
          performance_monitoring:
            description:
            - Enable performance monitoring.
            type: bool
            default: false

          # Replication
          replication_mode:
            description:
            - O(config.management.multicast_group_subnet) applies when set to C(multicast); C(ingress) uses ingress replication for BUM traffic.
            - The multicast replication mode.
            type: str
            default: multicast
            choices: [ multicast, ingress ]
          multicast_group_subnet:
            description:
            - Applies when O(config.management.replication_mode=multicast) and O(config.management.underlay_ipv6=false).
            - IPv4 multicast pool in CIDR notation with a prefix length from C(8) through C(30).
            type: str
            default: "239.1.1.0/25"
          ipv6_multicast_group_subnet:
            description:
            - Applies when O(config.management.replication_mode=multicast) and O(config.management.underlay_ipv6=true).
            - The IPv6 multicast group subnet.
            type: str
            default: "ff1e::/121"
          auto_generate_multicast_group_address:
            description:
            - Applies when O(config.management.replication_mode=multicast); addresses come from
              O(config.management.multicast_group_subnet) for IPv4 or O(config.management.ipv6_multicast_group_subnet) for IPv6.
            - Automatically generate multicast group addresses.
            type: bool
            default: false
          underlay_multicast_group_address_limit:
            description:
            - Controls underlay multicast group allocation when O(config.management.replication_mode=multicast).
            - The underlay multicast group address limit.
            - The maximum supported value is 128 for NX-OS version 10.2(1) or earlier and 512 for versions above 10.2(1).
            type: int
            default: 128
            choices: [ 128, 512 ]
          tenant_routed_multicast:
            description:
            - Use O(config.management.replication_mode=multicast) for TRM.
            - Enable tenant routed multicast.
            type: bool
            default: false
          tenant_routed_multicast_ipv6:
            description:
            - Use O(config.management.replication_mode=multicast) for TRMv6.
            - Controls IPv6 tenant routed multicast; O(config.management.tenant_routed_multicast) controls IPv4 tenant routed multicast separately.
            - Enable tenant routed multicast for IPv6.
            type: bool
            default: false
          rendezvous_point_count:
            description:
            - Applies when O(config.management.replication_mode=multicast); C(4) enables the third and fourth phantom RP loopback IDs in C(bidir) mode.
            - The number of spines acting as Rendezvous-Points (RPs).
            type: int
            default: 2
            choices: [ 2, 4 ]
          rendezvous_point_mode:
            description:
            - Applies when O(config.management.replication_mode=multicast).
            - C(bidir) applies only when O(config.management.underlay_ipv6=false); use C(asm) for IPv6 underlay.
            - Multicast rendezvous point mode. For IPv6 underlay, use C(asm) only.
            type: str
            default: asm
            choices: [ asm, bidir ]
          rendezvous_point_loopback_id:
            description:
            - Applies when O(config.management.replication_mode=multicast).
            - The rendezvous point loopback interface ID (0-1023).
            type: int
            default: 254
          phantom_rendezvous_point_loopback_id1:
            description:
            - Applies when O(config.management.rendezvous_point_mode=bidir).
            - Underlay phantom RP loopback primary ID for PIM Bi-dir deployments.
            type: int
            default: 2
          phantom_rendezvous_point_loopback_id2:
            description:
            - Applies when O(config.management.rendezvous_point_mode=bidir).
            - Underlay phantom RP loopback secondary ID for PIM Bi-dir deployments.
            type: int
            default: 3
          phantom_rendezvous_point_loopback_id3:
            description:
            - Also applies when O(config.management.rendezvous_point_count=4).
            - Applies when O(config.management.rendezvous_point_mode=bidir).
            - Underlay phantom RP loopback tertiary ID for PIM Bi-dir deployments.
            type: int
            default: 4
          phantom_rendezvous_point_loopback_id4:
            description:
            - Also applies when O(config.management.rendezvous_point_count=4).
            - Applies when O(config.management.rendezvous_point_mode=bidir).
            - Underlay phantom RP loopback quaternary ID for PIM Bi-dir deployments.
            type: int
            default: 5
          anycast_rendezvous_point_ip_range:
            description:
            - The IPv4 anycast rendezvous point pool applies to IPv4 multicast underlay operation.
            - The anycast rendezvous point IP address pool.
            type: str
            default: "10.254.254.0/24"
          ipv6_anycast_rendezvous_point_ip_range:
            description:
            - The IPv6 anycast rendezvous point pool applies to IPv6 multicast underlay operation when O(config.management.underlay_ipv6=true).
            - The IPv6 anycast rendezvous point IP address pool.
            type: str
            default: "fd00::254:254:0/118"
          l3vni_multicast_group:
            description:
            - Choose the address from O(config.management.multicast_group_subnet).
            - Used for IPv4 multicast of overlay VRF traffic.
            - Default underlay multicast group IPv4 address assigned for every overlay VRF.
            type: str
            default: "239.1.1.0"
          l3_vni_ipv6_multicast_group:
            description:
            - Choose the address from O(config.management.ipv6_multicast_group_subnet).
            - Used for IPv6 multicast of overlay VRF traffic.
            - Default underlay multicast group IPv6 address assigned for every overlay VRF.
            type: str
            default: "ff1e::"
          mvpn_vrf_route_import_id:
            description:
            - Applies to O(config.management.tenant_routed_multicast=true) with IPv4 underlay.
            - Enable MVPN VRI ID generation for Tenant Routed Multicast with IPv4 underlay.
            type: bool
            default: true
          mvpn_vrf_route_import_id_range:
            description:
            - Applies when O(config.management.tenant_routed_multicast=true) with IPv6 underlay,
              or O(config.management.mvpn_vrf_route_import_id=true) with IPv4 underlay.
            - MVPN VRI ID range (minimum 1, maximum 65535) for vPC.
            - Applicable when TRM is enabled with IPv6 underlay, or mvpn_vrf_route_import_id is enabled with IPv4 underlay.
            type: str
          vrf_route_import_id_reallocation:
            description:
            - Uses O(config.management.mvpn_vrf_route_import_id_range).
            - One time VRI ID re-allocation based on MVPN VRI ID Range.
            type: bool
            default: false

          # vPC
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
            - When enabled, O(config.management.shared_vpc_domain_id) supplies the domain ID.
            - Enable fabric vPC domain ID.
            type: bool
            default: false
          shared_vpc_domain_id:
            description:
            - Applies when O(config.management.fabric_vpc_domain_id=true).
            - The shared vPC domain ID.
            type: int
            default: 1
          fabric_vpc_qos:
            description:
            - When enabled, O(config.management.fabric_vpc_qos_policy_name) selects the policy.
            - Enable fabric vPC QoS.
            type: bool
            default: false
          fabric_vpc_qos_policy_name:
            description:
            - Applies when O(config.management.fabric_vpc_qos=true).
            - The fabric vPC QoS policy name.
            type: str
            default: spine_qos_for_fabric_vpc_peering
          enable_peer_switch:
            description:
            - Enable peer switch.
            type: bool
            default: false
          advertise_physical_ip:
            description:
            - Advertise physical IP address for NVE loopback.
            type: bool
            default: false
          advertise_physical_ip_on_border:
            description:
            - Applies when O(config.management.advertise_physical_ip=false).
            - Advertise physical IP address on border switches.
            type: bool
            default: true
          anycast_border_gateway_advertise_physical_ip:
            description:
            - Enable anycast border gateway to advertise physical IP.
            type: bool
            default: false
          allow_vlan_on_leaf_tor_pairing:
            description:
            - "Set trunk allowed VLAN to 'none' or 'all' for leaf-TOR pairing port-channels."
            type: str
            default: none
            choices: [ none, all ]
          leaf_tor_id_range:
            description:
            - When enabled, O(config.management.leaf_tor_vpc_port_channel_id_range) supplies the allocation pool.
            - Use specific vPC/Port-channel ID range for leaf-TOR pairings.
            type: bool
            default: false
          leaf_tor_vpc_port_channel_id_range:
            description:
            - Applies when O(config.management.leaf_tor_id_range=true).
            - Specify vPC/Port-channel ID range (minimum 1, maximum 4096) for leaf-TOR pairings.
            type: str
            default: "1-499"

          # Protocols
          ospf_area_id:
            description:
            - Applies when O(config.management.link_state_routing_protocol=ospf).
            - The OSPF area ID as a valid IPv4 address.
            type: str
            default: "0.0.0.0"
          bgp_loopback_id:
            description:
            - The BGP routing loopback interface ID (0-1023).
            type: int
            default: 0
          nve_loopback_id:
            description:
            - The NVE VTEP loopback interface ID (0-1023).
            type: int
            default: 1
          anycast_loopback_id:
            description:
            - Applies to vPC peering when O(config.management.underlay_ipv6=true).
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
            - The link state underlay routing tag.
            type: str
            default: UNDERLAY
          bgp_authentication:
            description:
            - Not supported when O(config.management.underlay_ipv6=true).
            - Enable BGP authentication.
            type: bool
            default: false
          bgp_authentication_key_type:
            description:
            - Applies when O(config.management.bgp_authentication=true).
            - "BGP key encryption type: 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7."
            type: str
            default: 3des
            choices: [ 3des, type6, type7 ]
          bgp_authentication_key:
            description:
            - Applies when O(config.management.bgp_authentication=true).
            - The BGP authentication key.
            type: str
          bfd:
            description:
            - Applies to IPv4 underlay when O(config.management.underlay_ipv6=false).
            - Enable BFD globally.
            type: bool
            default: false
          bfd_ibgp:
            description:
            - Applies when O(config.management.bfd=true).
            - Enable BFD for iBGP sessions.
            type: bool
            default: false
          bfd_ospf:
            description:
            - Applies when O(config.management.bfd=true) and O(config.management.link_state_routing_protocol=ospf).
            - Enable BFD for OSPF.
            type: bool
            default: false
          bfd_isis:
            description:
            - Applies when O(config.management.bfd=true) and O(config.management.link_state_routing_protocol=isis).
            - Enable BFD for IS-IS.
            type: bool
            default: false
          bfd_pim:
            description:
            - Applies when O(config.management.bfd=true) with IPv4 underlay PIM.
            - Enable BFD for PIM.
            type: bool
            default: false
          bfd_authentication:
            description:
            - Applies when O(config.management.bfd=true) and O(config.management.fabric_interface_type=p2p).
            - Enable BFD authentication.
            type: bool
            default: false
          bfd_authentication_key_id:
            description:
            - Applies when O(config.management.bfd_authentication=true).
            - The BFD authentication key ID.
            type: int
            default: 100
          bfd_authentication_key:
            description:
            - Applies when O(config.management.bfd_authentication=true).
            - The BFD authentication key.
            type: str
          ospf_authentication:
            description:
            - Not supported when O(config.management.underlay_ipv6=true).
            - Applies when O(config.management.link_state_routing_protocol=ospf).
            - Enable OSPF authentication.
            type: bool
            default: false
          ospf_authentication_key_id:
            description:
            - Applies when O(config.management.ospf_authentication=true).
            - The OSPF authentication key ID.
            type: int
            default: 127
          ospf_authentication_key:
            description:
            - Applies when O(config.management.ospf_authentication=true).
            - The OSPF authentication key.
            type: str
          pim_hello_authentication:
            description:
            - Applies to IPv4 underlay PIM when O(config.management.underlay_ipv6=false).
            - Enable PIM hello authentication.
            type: bool
            default: false
          pim_hello_authentication_key:
            description:
            - Applies when O(config.management.pim_hello_authentication=true).
            - The PIM hello authentication key.
            type: str
          isis_level:
            description:
            - Applies when O(config.management.link_state_routing_protocol=isis).
            - The IS-IS level.
            type: str
            default: level-2
            choices: [ level-1, level-2 ]
          isis_area_number:
            description:
            - Applies when O(config.management.link_state_routing_protocol=isis).
            - The IS-IS area number.
            type: str
            default: "0001"
          isis_point_to_point:
            description:
            - Applies when O(config.management.link_state_routing_protocol=isis) and O(config.management.fabric_interface_type=p2p).
            - Enable IS-IS point-to-point.
            type: bool
            default: true
          isis_authentication:
            description:
            - Not supported when O(config.management.underlay_ipv6=true).
            - Applies when O(config.management.link_state_routing_protocol=isis).
            - Enable IS-IS authentication.
            type: bool
            default: false
          isis_authentication_keychain_name:
            description:
            - Applies when O(config.management.isis_authentication=true).
            - The IS-IS authentication keychain name.
            type: str
          isis_authentication_keychain_key_id:
            description:
            - Applies when O(config.management.isis_authentication=true).
            - The IS-IS authentication keychain key ID.
            type: int
            default: 127
          isis_authentication_key:
            description:
            - Applies when O(config.management.isis_authentication=true).
            - The IS-IS authentication key.
            type: str
          isis_overload:
            description:
            - Applies when O(config.management.link_state_routing_protocol=isis).
            - Enable IS-IS overload bit.
            type: bool
            default: true
          isis_overload_elapse_time:
            description:
            - Applies when O(config.management.isis_overload=true).
            - The IS-IS overload elapse time in seconds.
            type: int
            default: 60

          # Security
          security_group_tag:
            description:
            - Requires O(config.management.overlay_mode=cli).
            - Enable Security Group Tag (SGT) support.
            type: bool
            default: false
          security_group_tag_prefix:
            description:
            - Applies when O(config.management.security_group_tag=true).
            - The SGT prefix.
            type: str
            default: SG_
          security_group_tag_mac_segmentation:
            description:
            - Applies when O(config.management.security_group_tag=true).
            - Enable SGT MAC segmentation.
            type: bool
            default: false
          security_group_tag_id_range:
            description:
            - Applies when O(config.management.security_group_tag=true).
            - The SGT ID range.
            type: str
            default: "10000-14000"
          security_group_tag_preprovision:
            description:
            - Applies when O(config.management.security_group_tag=true).
            - Enable SGT pre-provisioning.
            type: bool
            default: false
          macsec:
            description:
            - Enable MACsec on intra-fabric links.
            type: bool
            default: false
          macsec_cipher_suite:
            description:
            - Applies when O(config.management.macsec=true) on the fabric link.
            - The MACsec cipher suite.
            type: str
            default: GCM-AES-XPN-256
            choices: [ GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128, GCM-AES-XPN-256 ]
          macsec_key_string:
            description:
            - Applies when O(config.management.macsec=true) on the fabric link.
            - The MACsec primary key string.
            type: str
          macsec_algorithm:
            description:
            - Applies when O(config.management.macsec=true) on the fabric link.
            - The MACsec primary cryptographic algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          macsec_fallback_key_string:
            description:
            - Applies when O(config.management.macsec=true) on the fabric link.
            - The MACsec fallback key string.
            type: str
          macsec_fallback_algorithm:
            description:
            - Applies when O(config.management.macsec=true) on the fabric link.
            - The MACsec fallback cryptographic algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          macsec_report_timer:
            description:
            - Applies when O(config.management.macsec=true) on the fabric link.
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
            - Applies when O(config.management.vrf_lite_macsec=true) on a DCI link.
            - The DCI MACsec cipher suite.
            type: str
            default: GCM-AES-XPN-256
            choices: [ GCM-AES-128, GCM-AES-256, GCM-AES-XPN-128, GCM-AES-XPN-256 ]
          vrf_lite_macsec_key_string:
            description:
            - Applies when O(config.management.vrf_lite_macsec=true) on a DCI link.
            - The DCI MACsec primary key string (Cisco Type 7 Encrypted Octet String).
            type: str
          vrf_lite_macsec_algorithm:
            description:
            - Applies when O(config.management.vrf_lite_macsec=true) on a DCI link.
            - The DCI MACsec primary cryptographic algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          vrf_lite_macsec_fallback_key_string:
            description:
            - Applies when O(config.management.vrf_lite_macsec=true) and O(config.management.quantum_key_distribution=false) on a DCI link.
            - The DCI MACsec fallback key string (Cisco Type 7 Encrypted Octet String).
            - This parameter is used when DCI link has QKD disabled.
            type: str
          vrf_lite_macsec_fallback_algorithm:
            description:
            - Applies when O(config.management.vrf_lite_macsec=true) and O(config.management.quantum_key_distribution=false) on a DCI link.
            - The DCI MACsec fallback cryptographic algorithm.
            - This parameter is used when DCI link has QKD disabled.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          quantum_key_distribution:
            description:
            - Applies to DCI links using O(config.management.vrf_lite_macsec=true).
            - Enable quantum key distribution.
            type: bool
            default: false
          quantum_key_distribution_profile_name:
            description:
            - Applies when O(config.management.quantum_key_distribution=true).
            - The quantum key distribution profile name.
            type: str
          key_management_entity_server_ip:
            description:
            - Applies when O(config.management.quantum_key_distribution=true).
            - The key management entity server IP address.
            type: str
          key_management_entity_server_port:
            description:
            - Applies when O(config.management.quantum_key_distribution=true).
            - The key management entity server port.
            type: int
            default: 0
          trustpoint_label:
            description:
            - Applies when O(config.management.quantum_key_distribution=true).
            - The trustpoint label for TLS authentication.
            type: str
          skip_certificate_verification:
            description:
            - Applies when O(config.management.quantum_key_distribution=true).
            - Skip verification of incoming certificate.
            type: bool
            default: false

          # Advanced
          site_id:
            description:
            - The site identifier for the fabric (for EVPN Multi-Site support).
            - Accepts a non-zero decimal without leading zeros or dotted ASN notation (1-65535.0-65535).
            - Decimal values up to C(4294967295) are supported on ND 4.2.1 and later.
            - Decimal values from C(4294967296) through C(281474976710655) require ND 4.3.1 or later.
            - On creation and with O(state=replaced) or O(state=overridden), an omitted value defaults to O(config.management.bgp_asn).
            - On an existing fabric with O(state=merged), omission preserves its site ID even when O(config.management.bgp_asn) is supplied.
            type: str
          overlay_mode:
            description:
            - O(config.management.security_group_tag=true) is supported only with C(cli) overlay mode.
            - The overlay configuration mode.
            type: str
            default: cli
            choices: [ cli, config-profile ]
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
          tenant_dhcp:
            description:
            - Enable tenant DHCP.
            type: bool
            default: true
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
            - The interval is set with O(config.management.interface_statistics_load_interval).
            - Enable real-time interface statistics collection.
            type: bool
            default: false
          interface_statistics_load_interval:
            description:
            - Applies when O(config.management.real_time_interface_statistics_collection=true).
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
            default: true
          nxapi_https_port:
            description:
            - Applies when O(config.management.nxapi=true).
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
            - Applies when O(config.management.nxapi_http=true).
            - The NX-API HTTP port (1-65535).
            type: int
            default: 80
          default_queuing_policy:
            description:
            - Enable default queuing policies.
            type: bool
            default: false
          default_queuing_policy_cloudscale:
            description:
            - Applies when O(config.management.default_queuing_policy=true).
            - Queuing policy for all 92xx, -EX, -FX, -FX2, -FX3, -GX series switches in the fabric.
            type: str
            default: queuing_policy_default_8q_cloudscale
          default_queuing_policy_r_series:
            description:
            - Applies when O(config.management.default_queuing_policy=true).
            - Queuing policy for all Nexus R-series switches.
            type: str
            default: queuing_policy_default_r_series
          default_queuing_policy_other:
            description:
            - Applies when O(config.management.default_queuing_policy=true).
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
            - Applies when O(config.management.aiml_qos=true).
            - Queuing policy based on predominant fabric link speed.
            type: str
            default: 400G
            choices: [ 800G, 400G, 100G, 25G, User-defined ]
          roce_v2:
            description:
            - Applies when O(config.management.aiml_qos=true).
            - DSCP for RDMA traffic. Numeric (0-63) with ranges/comma, or named values.
            type: str
          cnp:
            description:
            - Applies when O(config.management.aiml_qos=true).
            - DSCP value for Congestion Notification. Numeric (0-63) with ranges/comma, or named values.
            type: str
            default: "48"
          wred_min:
            description:
            - Applies when O(config.management.aiml_qos=true).
            - WRED minimum threshold (in kbytes).
            type: int
            default: 950
          wred_max:
            description:
            - Applies when O(config.management.aiml_qos=true).
            - WRED maximum threshold (in kbytes).
            type: int
            default: 3000
          wred_drop_probability:
            description:
            - Applies when O(config.management.aiml_qos=true).
            - WRED drop probability percentage.
            type: int
            default: 7
          wred_weight:
            description:
            - Applies when O(config.management.aiml_qos=true).
            - Influences how quickly WRED reacts to queue depth changes.
            type: int
            default: 0
          bandwidth_remaining:
            description:
            - Applies when O(config.management.aiml_qos=true).
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
            - Applies when O(config.management.dlb=true).
            - "Select system-wide DLB mode: flowlet, per-packet (packet spraying), or policy driven mixed mode.
              Mixed mode is supported on Silicon One (S1) platform only."
            type: str
            default: flowlet
            choices: [ flowlet, per-packet, policy-driven-flowlet, policy-driven-per-packet, policy-driven-mixed-mode ]
          dlb_mixed_mode_default:
            description:
            - Applies when O(config.management.dlb=true) and O(config.management.dlb_mode=policy-driven-mixed-mode).
            - Default load balancing mode for policy driven mixed mode DLB.
            type: str
            default: ecmp
            choices: [ ecmp, flowlet, per-packet ]
          flowlet_aging:
            description:
            - Applies when O(config.management.dlb=true) and a flowlet O(config.management.dlb_mode) is selected.
            - "Flowlet aging timer in microseconds. Valid range depends on platform: Cloud Scale (CS)=1-2000000,
              Silicon One (S1)=1-1024."
            type: int
          flowlet_dscp:
            description:
            - Applies when O(config.management.dlb=true) and a flowlet O(config.management.dlb_mode) is selected.
            - DSCP values for flowlet load balancing. Numeric (0-63) with ranges/comma, or named values.
            type: str
            default: ""
          per_packet_dscp:
            description:
            - Applies when O(config.management.dlb=true) and a per-packet O(config.management.dlb_mode) is selected.
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
          ptp:
            description:
            - Enable Precision Time Protocol (PTP).
            type: bool
            default: false
          ptp_loopback_id:
            description:
            - Applies when O(config.management.ptp=true).
            - The PTP loopback ID.
            type: int
            default: 0
          ptp_domain_id:
            description:
            - Applies when O(config.management.ptp=true).
            - The PTP domain ID for multiple independent PTP clocking subdomains on a single network.
            type: int
            default: 0
          ptp_vlan_id:
            description:
            - Applies when O(config.management.ptp=true).
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
            - Applies when O(config.management.stp_root_option) is C(rpvst+) or C(mst).
            - The STP VLAN range (minimum 1, maximum 4094).
            type: str
            default: "1-3967"
          mst_instance_range:
            description:
            - Applies when O(config.management.stp_root_option=mst).
            - The MST instance range (minimum 0, maximum 4094).
            type: str
            default: "0"
          stp_bridge_priority:
            description:
            - Applies when O(config.management.stp_root_option) is C(rpvst+) or C(mst).
            - The STP bridge priority.
            type: int
            default: 0
          mpls_handoff:
            description:
            - Not supported when O(config.management.underlay_ipv6=true).
            - Enable MPLS handoff.
            type: bool
            default: false
          mpls_loopback_identifier:
            description:
            - Applies when O(config.management.mpls_handoff=true).
            - The MPLS loopback identifier used for VXLAN to MPLS SR/LDP Handoff.
            type: int
            default: 101
          mpls_isis_area_number:
            description:
            - Applies when O(config.management.mpls_handoff=true) and the DCI MPLS link uses IS-IS.
            - IS-IS area number for DCI MPLS link. Used only if routing protocol on DCI MPLS link is IS-IS.
            type: str
            default: "0001"
          mpls_loopback_ip_range:
            description:
            - Applies when O(config.management.mpls_handoff=true).
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
            - Applies when O(config.management.private_vlan=true).
            - Default PVLAN secondary network template.
            type: str
            default: Pvlan_Secondary_Network
          nve_hold_down_timer:
            description:
            - The NVE hold-down timer in seconds.
            type: int
            default: 180
          next_generation_oam:
            description:
            - Not supported when O(config.management.underlay_ipv6=true).
            - Enable the Next Generation (NG) OAM feature for all switches in the fabric.
            type: bool
            default: true
          ngoam_south_bound_loop_detect:
            description:
            - Applies when O(config.management.next_generation_oam=true).
            - Enable the Next Generation (NG) OAM southbound loop detection.
            type: bool
            default: false
          ngoam_south_bound_loop_detect_probe_interval:
            description:
            - Applies when O(config.management.ngoam_south_bound_loop_detect=true).
            - Set NG OAM southbound loop detection probe interval in seconds.
            type: int
            default: 300
          ngoam_south_bound_loop_detect_recovery_interval:
            description:
            - Applies when O(config.management.ngoam_south_bound_loop_detect=true).
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

          # Freeform
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

          # Resources
          static_underlay_ip_allocation:
            description:
            - Enable static underlay IP allocation.
            type: bool
            default: false
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
          bgp_loopback_ipv6_range:
            description:
            - Applies when O(config.management.underlay_ipv6=true).
            - The BGP loopback IPv6 address pool.
            type: str
            default: "fd00::a02:0/119"
          nve_loopback_ipv6_range:
            description:
            - Applies when O(config.management.underlay_ipv6=true).
            - The NVE loopback IPv6 address pool.
            type: str
            default: "fd00::a03:0/118"
          intra_fabric_subnet_range:
            description:
            - The intra-fabric subnet IP address pool.
            type: str
            default: "10.4.0.0/16"
          ipv6_subnet_range:
            description:
            - Applies when O(config.management.underlay_ipv6=true) and O(config.management.ipv6_link_local=false).
            - Applies when O(config.management.underlay_ipv6=true).
            - The IPv6 subnet range.
            type: str
            default: "fd00::a04:0/112"
          router_id_range:
            description:
            - Applies when O(config.management.underlay_ipv6=true).
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
            - The VRF Lite IPv4 address pool in CIDR notation.
            type: str
            default: "10.33.0.0/16"
          vrf_lite_subnet_target_mask:
            description:
            - The VRF lite subnet target mask.
            type: int
            default: 30
          vrf_lite_ipv6_subnet_range:
            description:
            - The IPv6 address range for VRF Lite point-to-point connections.
            - When omitted, Nexus Dashboard owns the default.
            type: str
          vrf_lite_ipv6_subnet_target_mask:
            description:
            - The IPv6 VRF Lite subnet mask length (112-127).
            - When omitted, Nexus Dashboard owns the default.
            type: int
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
            - Applies to default VRF peering generated by O(config.management.auto_vrf_lite_default_vrf=true).
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
            - Applies when O(config.management.per_vrf_loopback_auto_provision=true).
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
            - Applies when O(config.management.per_vrf_loopback_auto_provision_ipv6=true).
            - The per-VRF loopback IPv6 address pool.
            type: str
            default: "fd00::a05:0/112"
          per_vrf_unique_loopback_auto_provision:
            description:
            - Mutually exclusive with O(config.management.per_vrf_loopback_auto_provision=true).
            - Auto provision a unique IPv4 loopback on a VTEP on VRF attachment.
            - This option and per VRF per VTEP loopback auto-provisioning are mutually exclusive.
            type: bool
            default: false
          per_vrf_unique_loopback_ip_range:
            description:
            - Applies when O(config.management.per_vrf_unique_loopback_auto_provision=true).
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
            - Applies when O(config.management.per_vrf_unique_loopback_auto_provision_v6=true).
            - Prefix pool to assign unique IPv6 addresses to loopbacks on VTEPs on a per VRF basis.
            type: str
            default: "fd00::a06:0/112"
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

          # Manageability
          inband_management:
            description:
            - Manage switches with only inband connectivity.
            type: bool
            default: false
          aaa:
            description:
            - Applies to O(config.management.day0_bootstrap=true) during switch boot.
            - Enable AAA.
            type: bool
            default: false
          extra_config_aaa:
            description:
            - Applies when O(config.management.aaa=true).
            - Extra freeform AAA configuration.
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
            default: []
          ntp_server_vrf_collection:
            description:
            - VRF entries correspond to servers in O(config.management.ntp_server_collection).
            - The list of VRFs for NTP servers.
            type: list
            elements: str
            default: []
          dns_collection:
            description:
            - The list of DNS server IP addresses.
            type: list
            elements: str
            default: []
          dns_vrf_collection:
            description:
            - VRF entries correspond to servers in O(config.management.dns_collection).
            - The list of VRFs for DNS servers.
            type: list
            elements: str
            default: []
          syslog_server_collection:
            description:
            - The list of syslog server IP addresses.
            type: list
            elements: str
            default: []
          syslog_server_vrf_collection:
            description:
            - VRF entries correspond to servers in O(config.management.syslog_server_collection).
            - The list of VRFs for syslog servers.
            type: list
            elements: str
            default: []
          syslog_severity_collection:
            description:
            - Severity entries correspond to servers in O(config.management.syslog_server_collection).
            - The list of syslog severity levels (0-7).
            type: list
            elements: int
            default: []

          # Hypershield
          allow_smart_switch_onboarding:
            description:
            - Enable onboarding of smart switches to Hypershield for firewall service.
            type: bool
            default: false
          enable_dpu_pinning:
            description:
            - Applies to smart switches onboarded using O(config.management.allow_smart_switch_onboarding=true).
            - Enable pinning of VRFs and networks to specific DPUs on smart switches.
            type: bool
            default: false
          connectivity_domain_name:
            description:
            - Applies to smart switches onboarded using O(config.management.allow_smart_switch_onboarding=true).
            - Domain name to connect to Hypershield.
            type: str
          hypershield_connectivity_proxy_server:
            description:
            - Applies to smart switches onboarded using O(config.management.allow_smart_switch_onboarding=true).
            - IPv4 address, IPv6 address, or DNS name of the proxy server for Hypershield communication.
            type: str
          hypershield_connectivity_proxy_server_port:
            description:
            - Used with O(config.management.hypershield_connectivity_proxy_server) for smart switch onboarding.
            - Proxy port number for communication with Hypershield.
            type: int
          hypershield_connectivity_source_intf:
            description:
            - Applies to smart switches onboarded using O(config.management.allow_smart_switch_onboarding=true).
            - Loopback interface on smart switch for communication with Hypershield.
            type: str

          # Bootstrap
          day0_bootstrap:
            description:
            - Enable this before using O(config.management.local_dhcp_server=true) and other bootstrap settings.
            - Enable day-0 bootstrap (POAP).
            type: bool
            default: false
          local_dhcp_server:
            description:
            - Applies when O(config.management.day0_bootstrap=true); when disabled, bootstrap can use an external DHCP server.
            - Enables the local DHCP scope settings when true.
            - Enable local DHCP server for bootstrap.
            type: bool
            default: false
          dhcp_protocol_version:
            description:
            - Applies when O(config.management.day0_bootstrap=true) and O(config.management.local_dhcp_server=true).
            - The IP protocol version for local DHCP server.
            type: str
            default: dhcpv4
            choices: [ dhcpv4, dhcpv6 ]
          dhcp_start_address:
            description:
            - Applies to local DHCP scopes when O(config.management.local_dhcp_server=true) and
              O(config.management.day0_bootstrap=true).
            - The DHCP start address for bootstrap.
            - Use an IPv4 address without a prefix length with O(config.management.dhcp_protocol_version=dhcpv4) on ND 4.2 or later.
            - An IPv6 address without a prefix length requires ND 4.3.1 or later,
              O(config.management.dhcp_protocol_version=dhcpv6), and a V6 controller installation.
            - ND 4.3.1 alone does not establish V6 installation support; the controller may reject DHCPv6.
            - Omit on create to leave it unset; omission from a partial O(state=merged) update preserves the existing value.
            type: str
          dhcp_end_address:
            description:
            - Applies to local DHCP scopes when O(config.management.local_dhcp_server=true) and
              O(config.management.day0_bootstrap=true).
            - The DHCP end address for bootstrap.
            - Use an IPv4 address without a prefix length with O(config.management.dhcp_protocol_version=dhcpv4) on ND 4.2 or later.
            - An IPv6 address without a prefix length requires ND 4.3.1 or later,
              O(config.management.dhcp_protocol_version=dhcpv6), and a V6 controller installation.
            - ND 4.3.1 alone does not establish V6 installation support; the controller may reject DHCPv6.
            - Omit on create to leave it unset; omission from a partial O(state=merged) update preserves the existing value.
            type: str
          management_gateway:
            description:
            - Applies to bootstrap addressing when O(config.management.day0_bootstrap=true), including external DHCP.
            - The management gateway for bootstrap.
            - Use an IPv4 address without a prefix length on ND 4.2 or later.
            - An IPv6 address without a prefix length is accepted as module config on ND 4.3.1 or later.
            - With local DHCP, O(config.management.dhcp_protocol_version=dhcpv6) requires a V6 controller installation.
            - With external DHCP, controller acceptance of an IPv6 gateway alone has not been verified.
            - ND 4.3.1 alone does not establish V6 installation support; the controller may reject local DHCPv6.
            - Omit on create to leave it unset; omission from a partial O(state=merged) update preserves the existing value.
            type: str
          management_ipv4_prefix:
            description:
            - Applies to IPv4 bootstrap addressing when O(config.management.day0_bootstrap=true), with local or external DHCP.
            - For local DHCP, select O(config.management.dhcp_protocol_version=dhcpv4).
            - The management IPv4 prefix length for bootstrap.
            type: int
            default: 24
          management_ipv6_prefix:
            description:
            - Applies to IPv6 bootstrap addressing when O(config.management.day0_bootstrap=true), with local or external DHCP.
            - For local DHCP, select O(config.management.dhcp_protocol_version=dhcpv6).
            - The management IPv6 prefix length for bootstrap.
            type: int
            default: 64
          bootstrap_subnet_collection:
            description:
            - Applies when O(config.management.day0_bootstrap=true) and O(config.management.local_dhcp_server=true).
            - List of IPv4 or IPv6 subnets to be used for bootstrap.
            - Within each entry, C(start_ip), C(end_ip), and C(default_gateway) must be valid addresses from the same IP family.
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
                - Prefix length. Use C(8)-C(30) for IPv4 or C(64)-C(126) for IPv6.
                type: int
                required: true
          seed_switch_core_interfaces:
            description:
            - Applies when O(config.management.day0_bootstrap=true).
            - Seed switch fabric interfaces. Core-facing interface list on seed switch.
            - Each entry must be an Ethernet or port-channel interface name, optionally with a numeric range suffix
              (for example C(Ethernet1/1), C(Eth1/1-4), C(Port-Channel10), or C(Po10-12)).
            type: list
            elements: str
            default: []
          spine_switch_core_interfaces:
            description:
            - Applies when O(config.management.day0_bootstrap=true).
            - Spine switch fabric interfaces. Core-facing interface list on all spines.
            - Each entry must be an Ethernet or port-channel interface name, optionally with a numeric range suffix
              (for example C(Ethernet1/1), C(Eth1/1-4), C(Port-Channel10), or C(Po10-12)).
            type: list
            elements: str
            default: []
          inband_dhcp_servers:
            description:
            - Applies to inband bootstrap when O(config.management.day0_bootstrap=true).
            - List of external DHCP server IPv4 addresses (maximum 3).
            type: list
            elements: str
            default: []
          extra_config_nxos_bootstrap:
            description:
            - Applies when O(config.management.day0_bootstrap=true).
            - Additional CLIs required during device bootup/login (e.g. AAA/Radius).
            type: str
            default: ""
          unnumbered_bootstrap_loopback_id:
            description:
            - Applies to unnumbered bootstrap when O(config.management.day0_bootstrap=true) and O(config.management.fabric_interface_type=unNumbered).
            - Bootstrap Seed Switch Loopback Interface ID.
            type: int
            default: 253
          unnumbered_dhcp_start_address:
            description:
            - Applies to unnumbered local DHCP when O(config.management.local_dhcp_server=true) and O(config.management.fabric_interface_type=unNumbered).
            - Switch Loopback DHCP Scope Start Address. Must be a subset of IGP/BGP Loopback Prefix Pool.
            - Must be a valid IPv4 address without a prefix length.
            type: str
          unnumbered_dhcp_end_address:
            description:
            - Applies to unnumbered local DHCP when O(config.management.local_dhcp_server=true) and O(config.management.fabric_interface_type=unNumbered).
            - Switch Loopback DHCP Scope End Address. Must be a subset of IGP/BGP Loopback Prefix Pool.
            - Must be a valid IPv4 address without a prefix length.
            type: str

          # Configuration Backup
          real_time_backup:
            description:
            - Enable real-time backup.
            type: bool
            default: false
          scheduled_backup:
            description:
            - O(config.management.scheduled_backup_time) selects the daily run time when enabled.
            - Enable scheduled backup.
            type: bool
            default: false
          scheduled_backup_time:
            description:
            - Applies when O(config.management.scheduled_backup=true).
            - Scheduled backup time in 24-hour C(HH:MM) format (C(00:00) to C(23:59)).
            type: str

          # Flow Monitor
          netflow_settings:
            description:
            - Settings associated with netflow.
            type: dict
            suboptions:
              netflow:
                description:
                - When enabled, the exporter, record, and monitor collections configure NetFlow.
                - Enable netflow collection.
                type: bool
                default: false
              netflow_exporter_collection:
                description:
                - Applies when O(config.management.netflow_settings.netflow=true).
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
                - Applies when O(config.management.netflow_settings.netflow=true).
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
                - Applies when O(config.management.netflow_settings.netflow=true); monitor names link records
                  and exporters from the corresponding collections.
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
                    - Names a record from O(config.management.netflow_settings.netflow_record_collection).
                    - Associated record name.
                    type: str
                    required: true
                  exporter1_name:
                    description:
                    - Names an exporter from O(config.management.netflow_settings.netflow_exporter_collection).
                    - Primary exporter name.
                    type: str
                    required: true
                  exporter2_name:
                    description:
                    - Names an optional second exporter from O(config.management.netflow_settings.netflow_exporter_collection).
                    - Secondary exporter name.
                    type: str
                    default: ""
      telemetry_settings:
        description:
        - Telemetry analysis, flow, microburst, NAS export, and energy settings.
        type: dict
        suboptions:
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
          energy_management:
            description:
            - Telemetry energy-management settings.
            type: dict
            suboptions:
              cost:
                description:
                - Energy cost per unit owned by the module.
                type: float
                default: 1.2
          flow_collection:
            description:
            - Telemetry flow-collection settings.
            type: dict
            suboptions:
              traffic_analytics:
                description:
                - Traffic analytics state.
                type: str
                choices:
                - compatibility
                - disabled
                - enabled
                default: enabled
              traffic_analytics_scope:
                description:
                - Traffic analytics scope.
                type: str
                choices:
                - interFabric
                - interFabricAndExternal
                - intraFabric
                default: intraFabric
              udp_categorization:
                description:
                - UDP categorization state.
                type: str
                choices:
                - disabled
                - enabled
                default: enabled
          microburst:
            description:
            - Microburst-detection settings.
            type: dict
            suboptions:
              microburst:
                description:
                - O(config.telemetry_settings.microburst.sensitivity) selects the sensitivity when enabled.
                - Enable microburst detection.
                type: bool
                default: false
              sensitivity:
                description:
                - Applies when O(config.telemetry_settings.microburst.microburst=true).
                - Microburst sensitivity level.
                type: str
                choices:
                - high
                - low
                - medium
                default: low
          nas:
            description:
            - NAS telemetry settings.
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
                  export_format:
                    description:
                    - NAS export format.
                    type: str
                    choices:
                    - json
                    default: json
                  export_type:
                    description:
                    - NAS export type.
                    type: str
                    choices:
                    - base
                    - full
                    default: full
      external_streaming_settings:
        description:
        - External streaming settings for the fabric.
        type: dict
        suboptions:
          email:
            description:
            - Email streaming configuration.
            type: list
            elements: dict
            default: []
          message_bus:
            description:
            - Message bus configuration.
            type: list
            elements: dict
            default: []
          syslog:
            description:
            - Syslog streaming configuration.
            type: dict
          webhooks:
            description:
            - Webhook configuration.
            type: list
            elements: dict
            default: []
  state:
    description:
    - The desired state of the fabric resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new fabrics and update existing ones as defined in the configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the supported configuration of each fabric specified in O(config).
      Omitted settings revert to their documented defaults except for dynamic or controller-owned settings identified
      by the module for preservation; those settings retain their existing values. Explicitly supplied values take precedence.
    - Use O(state=overridden) to apply the same per-fabric replacement behavior and enforce O(config) as the complete
      inventory for this fabric type. Existing fabrics of this type that are absent from O(config) are deleted.
      Use with extra caution.
    - Use O(state=deleted) to remove the fabrics specified in the configuration from the Cisco Nexus Dashboard.
    - Use O(state=gathered) to read iBGP VXLAN fabric configurations from Nexus Dashboard without making changes.
      Omit O(config) to gather all iBGP VXLAN fabrics, or provide O(config) to return matching fabrics.
      The result is returned under C(gathered) in a format that can be reused as O(config).
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, gathered ]
  config_actions:
    description:
    - Controls save and deploy behavior after fabric configuration is updated.
    - Save writes pending configuration to the controller.
    - Deploy pushes the saved configuration to switches.
    - Omitting O(config_actions), or leaving both actions disabled, stages changes only; it does not save or deploy them.
    - Must not enable O(config_actions.save) or O(config_actions.deploy) when O(state=gathered).
    - Skipped automatically when O(state=deleted) or when no changes are made.
    type: dict
    suboptions:
      save:
        description:
        - Whether to save fabric configuration after changes.
        type: bool
        default: false
      deploy:
        description:
        - Whether to deploy fabric configuration to switches after saving.
        - Requires O(config_actions.save=true) when enabled.
        type: bool
        default: false
      type:
        description:
        - Scope of the deploy operation.
        - C(switch) deploys only to affected switches.
        - C(global) deploys to all switches in the fabric.
        type: str
        default: switch
        choices: [ switch, global ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.0 or higher.
- Only iBGP VXLAN fabric type (C(vxlanIbgp)) is supported by this module.
- With O(state=replaced) or O(state=overridden), omitted settings revert to their documented defaults except for identified
  dynamic or controller-owned values, which are preserved from an existing fabric.
- The O(config.management.bgp_asn) field is required when creating a fabric.
- O(config.management.site_id) defaults to the value of O(config.management.bgp_asn) if not provided.
"""

EXAMPLES = r"""
# Omitting config_actions stages changes without saving or deploying them.
- name: Create an iBGP VXLAN fabric using state merged
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: merged
    config:
      - fabric_name: my_fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
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
          management_ipv4_prefix: 24
  register: result

- name: Update specific fields on an existing fabric using state merged (partial update)
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: merged
    config:
      - fabric_name: my_fabric
        management:
          bgp_asn: "65002"
          site_id: "65002"
          anycast_gateway_mac: "2020.0000.00bb"
          performance_monitoring: true
  register: result

- name: Create or fully replace an iBGP VXLAN fabric using state replaced
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: replaced
    config:
      - fabric_name: my_fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
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
          management_ipv4_prefix: 24
          management_ipv6_prefix: 64
  register: result

- name: Replace fabric with only required fields
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: replaced
    config:
      - fabric_name: my_fabric
        management:
          bgp_asn: "65004"
          site_id: "65004"
          banner: "^ Managed by Ansible ^"
  register: result

- name: Enforce exact fabric inventory using state overridden (deletes unlisted fabrics)
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: overridden
    config:
      - fabric_name: fabric_east
        location:
          latitude: 40.7128
          longitude: -74.0060
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
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
        location:
          latitude: 34.0522
          longitude: -118.2437
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
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

- name: Save and deploy iBGP VXLAN fabric configuration after changes
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: merged
    config:
      - fabric_name: my_fabric
        management:
          bgp_asn: "65001"
          fabric_mtu: 9216
    config_actions:
      save: true
      deploy: true
      type: switch
  register: result

- name: Delete a specific fabric using state deleted
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: deleted
    config:
      - fabric_name: my_fabric
  register: result

- name: Delete multiple fabrics in a single task
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: deleted
    config:
      - fabric_name: fabric_east
      - fabric_name: fabric_west
      - fabric_name: fabric_old
  register: result

- name: Gather all iBGP VXLAN fabrics
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: gathered
  register: result

- name: Gather selected iBGP VXLAN fabrics
  cisco.nd.nd_manage_fabric_ibgp_vxlan:
    state: gathered
    config:
      - fabric_name: fabric_east
      - license_tier: advantage
        security_domain: production
        alert_suspend: disabled
        telemetry_collection: true
  register: filtered_result
"""

RETURN = r"""
msg:
    description: A human-readable error message, present only when the module fails.
    type: str
    returned: on failure
    sample: "Module execution failed: fabric validation failed"
changed:
    description: Whether the module made any changes.
    type: bool
    returned: always
    sample: true
before:
    description:
    - Normalized, supported iBGP VXLAN fabric configuration before changes.
    - Unsupported controller-only properties are omitted.
    type: list
    returned: always
    sample: [{"fabric_name": "fabric_east", "management": {"bgp_asn": "65001"}}]
after:
    description:
    - Normalized, supported iBGP VXLAN fabric configuration after changes.
    - Unsupported controller-only properties are omitted.
    type: list
    returned: always
    sample: [{"fabric_name": "fabric_east", "management": {"bgp_asn": "65002"}}]
diff:
    description: Configuration differences between before and after states.
    type: list
    returned: always
    sample: [{"fabric_name": "fabric_east", "management": {"bgp_asn": "65002"}}]
proposed:
    description: Proposed configuration sent to the module.
    type: list
    returned: info or debug output_level
    sample: [{"fabric_name": "fabric_east", "management": {"bgp_asn": "65002"}}]
output_level:
    description: The output level set for the module.
    type: str
    returned: always
    sample: normal
logs:
    description: Debug log messages from module execution.
    type: list
    returned: debug output_level
    sample: ["Starting state machine for merged state"]
api_paths:
    description: API endpoint paths used during operations.
    type: list
    returned: verbosity >= 2 (-vv)
    sample: ["/api/v1/manage/fabrics/fabric_east"]
api_verbs:
    description: HTTP methods used during operations.
    type: list
    returned: verbosity >= 2 (-vv)
    sample: ["PUT"]
api_response:
    description: Full API responses from the controller.
    type: list
    returned: verbosity >= 3 (-vvv)
    sample: [{"RETURN_CODE": 200, "MESSAGE": "Success"}]
api_result:
    description: Operation results from the controller.
    type: list
    returned: verbosity >= 3 (-vvv)
    sample: [{"success": true, "changed": true}]
api_diff:
    description: API-level differences for each operation.
    type: list
    returned: verbosity >= 3 (-vvv)
api_metadata:
    description: Operation metadata with sequence and identifiers.
    type: list
    returned: verbosity >= 3 (-vvv)
api_payload:
    description: Request payloads sent to the API.
    type: list
    returned: verbosity >= 3 (-vvv)
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import FabricIbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ibgp_vxlan import ManageIbgpFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.raw_args import get_raw_module_args


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricIbgpModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=FabricIbgpModel.get_required_if(),
    )

    require_pydantic(module)

    # Parse and validate config_actions BEFORE any state mutation so invalid
    # input fails deterministically on every run, including idempotent no-drift
    # runs, and never mutates ND before failing.
    state = module.params.get("state", "merged")
    try:
        config_actions = parse_config_actions(
            params=module.params,
            raw_args=get_raw_module_args(),
            policy=FABRIC_CONFIG_ACTIONS,
            state=state,
        )
    except ValueError as e:
        module.fail_json(msg=str(e))

    nd_state_machine = None
    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageIbgpFabricOrchestrator,
        )

        # Manage state
        nd_state_machine.manage_state()

        # Execute config save/deploy actions via the shared controller (only on real changes)
        if state != "deleted" and len(nd_state_machine.sent) > 0:
            fabric_names = []
            for item in nd_state_machine.sent:
                name = item.get_identifier_value()
                if name and name not in fabric_names:
                    fabric_names.append(name)
            if fabric_names:
                nd_state_machine.model_orchestrator.run_config_actions(
                    actions=config_actions,
                    fabric_names=fabric_names,
                    state=state,
                    check_mode=module.check_mode,
                )

        verbosity = module._verbosity if hasattr(module, "_verbosity") else 0
        module.exit_json(**nd_state_machine.output.format_with_verbosity(verbosity, nd_state_machine.results))

    except NDStateMachineError as e:
        verbosity = module._verbosity if hasattr(module, "_verbosity") else 0
        output = nd_state_machine.output.format_with_verbosity(verbosity, nd_state_machine.results) if nd_state_machine else {}
        module.fail_json(msg=str(e), **output)
    except Exception as e:
        verbosity = module._verbosity if hasattr(module, "_verbosity") else 0
        output = nd_state_machine.output.format_with_verbosity(verbosity, nd_state_machine.results) if nd_state_machine else {}
        module.fail_json(msg=f"Module execution failed: {str(e)}", **output)


if __name__ == "__main__":
    main()
