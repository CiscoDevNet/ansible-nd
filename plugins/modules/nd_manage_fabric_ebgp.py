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
      name:
        description:
        - The name of the fabric.
        - Only letters, numbers, underscores, and hyphens are allowed.
        - The O(config.name) must be defined when creating, updating or deleting a fabric.
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
        choices: [ essentials, premier ]
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
            - C(multiAS) assigns a unique AS number to each leaf tier.
            - C(sameTierAS) assigns the same AS number within a tier.
            type: str
            default: multiAS
            choices: [ multiAS, sameTierAS ]
          bgp_allow_as_in_num:
            description:
            - The number of times BGP allows an AS-path containing the local AS number.
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
            - Automatically configure eBGP EVPN peering between spine and leaf switches.
            type: bool
            default: true
          allow_leaf_same_as:
            description:
            - Allow leaf switches to share the same BGP AS number.
            type: bool
            default: false
          assign_ipv4_to_loopback0:
            description:
            - Assign an IPv4 address to the loopback0 interface.
            type: bool
            default: true
          evpn:
            description:
            - Enable the EVPN control plane.
            type: bool
            default: true
          route_map_tag:
            description:
            - The route map tag used for redistribution.
            type: int
            default: 12345
          disable_route_map_tag:
            description:
            - Disable route map tag usage.
            type: bool
            default: false
          leaf_bgp_as:
            description:
            - The BGP AS number for leaf switches (used with C(sameTierAS) mode).
            type: str
          border_bgp_as:
            description:
            - The BGP AS number for border switches.
            type: str
          super_spine_bgp_as:
            description:
            - The BGP AS number for super-spine switches.
            type: str
          site_id:
            description:
            - The site identifier for the fabric.
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
            - The underlay multicast group address limit (1-255).
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
          first_hop_redundancy_protocol:
            description:
            - The first-hop redundancy protocol for tenant networks.
            type: str
            default: hsrp
            choices: [ hsrp, vrrp ]
          rendezvous_point_count:
            description:
            - The number of rendezvous points (1-4).
            type: int
            default: 2
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
          anycast_loopback_id:
            description:
            - The anycast loopback interface ID.
            type: int
            default: 10
          bgp_loopback_ip_range:
            description:
            - The BGP loopback IP address pool.
            type: str
            default: "10.2.0.0/22"
          bgp_loopback_ipv6_range:
            description:
            - The BGP loopback IPv6 address pool.
            type: str
            default: "fd00::a02:0/119"
          nve_loopback_ip_range:
            description:
            - The NVE loopback IP address pool.
            type: str
            default: "10.3.0.0/22"
          nve_loopback_ipv6_range:
            description:
            - The NVE loopback IPv6 address pool.
            type: str
            default: "fd00::a03:0/118"
          anycast_rendezvous_point_ip_range:
            description:
            - The anycast rendezvous point IP address pool.
            type: str
            default: "10.254.254.0/24"
          ipv6_anycast_rendezvous_point_ip_range:
            description:
            - The IPv6 anycast rendezvous point IP address pool.
            type: str
            default: "fd00::254:254:0/118"
          intra_fabric_subnet_range:
            description:
            - The intra-fabric subnet IP address pool.
            type: str
            default: "10.4.0.0/16"
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
            - The sub-interface 802.1q range.
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
          underlay_ipv6:
            description:
            - Enable IPv6 underlay.
            type: bool
            default: false
          static_underlay_ip_allocation:
            description:
            - Disable dynamic underlay IP address allocation.
            type: bool
            default: false
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
            - The greenfield debug flag.
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
            - Enable NX-API HTTP.
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
            - The BGP authentication key type.
            type: str
            default: 3des
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
          macsec_key_string:
            description:
            - The MACsec primary key string.
            type: str
            default: ""
          macsec_algorithm:
            description:
            - The MACsec algorithm.
            type: str
            default: AES_128_CMAC
          macsec_fallback_key_string:
            description:
            - The MACsec fallback key string.
            type: str
            default: ""
          macsec_fallback_algorithm:
            description:
            - The MACsec fallback algorithm.
            type: str
            default: AES_128_CMAC
          macsec_report_timer:
            description:
            - The MACsec report timer in minutes.
            type: int
            default: 5
          vrf_lite_auto_config:
            description:
            - The VRF lite auto-configuration mode.
            type: str
            default: manual
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
          default_queuing_policy:
            description:
            - Enable default queuing policy.
            type: bool
            default: false
          aiml_qos:
            description:
            - Enable AI/ML QoS.
            type: bool
            default: false
          aiml_qos_policy:
            description:
            - The AI/ML QoS policy.
            type: str
            default: 400G
          dlb:
            description:
            - Enable dynamic load balancing.
            type: bool
            default: false
          dlb_mode:
            description:
            - The DLB mode.
            type: str
            default: flowlet
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
            - The PTP domain ID.
            type: int
            default: 0
          private_vlan:
            description:
            - Enable private VLAN support.
            type: bool
            default: false
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
            - The DHCP protocol version for bootstrap.
            type: str
            default: dhcpv4
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
          real_time_backup:
            description:
            - Enable real-time backup.
            type: bool
          scheduled_backup:
            description:
            - Enable scheduled backup.
            type: bool
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
            - Enable next-generation OAM.
            type: bool
            default: true
          strict_config_compliance_mode:
            description:
            - Enable strict configuration compliance mode.
            type: bool
            default: false
          copp_policy:
            description:
            - The CoPP policy.
            type: str
            default: strict
          power_redundancy_mode:
            description:
            - The power redundancy mode.
            type: str
            default: redundant
          heartbeat_interval:
            description:
            - The heartbeat interval.
            type: int
            default: 190
          allow_smart_switch_onboarding:
            description:
            - Allow smart switch onboarding.
            type: bool
            default: false
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
          dns_collection:
            description:
            - The list of DNS server IP addresses.
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
      - name: my_ebgp_fabric
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
      - name: my_ebgp_fabric_static
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
      - name: my_ebgp_fabric
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
      - name: my_ebgp_fabric
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
      - name: my_ebgp_fabric
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
      - name: fabric_east
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
      - name: fabric_west
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
      - name: my_ebgp_fabric
  register: result

- name: Delete multiple eBGP fabrics in a single task
  cisco.nd.nd_manage_fabric_ebgp:
    state: deleted
    config:
      - name: fabric_east
      - name: fabric_west
      - name: fabric_old
  register: result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.nd_manage_fabric.manage_fabric_ebgp import FabricEbgpModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric import ManageEbgpFabricOrchestrator


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

    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}")

if __name__ == "__main__":
    main()
