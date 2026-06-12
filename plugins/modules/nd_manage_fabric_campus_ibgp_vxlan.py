#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_campus_ibgp_vxlan
version_added: "1.4.0"
short_description: Manage Campus iBGP VXLAN fabrics on Cisco Nexus Dashboard
description:
- Manage Campus iBGP VXLAN fabrics on Cisco Nexus Dashboard (ND).
- This module maps to the Manage API fabric discriminator O(config.management.type=vxlanCampus).
- It supports creating, updating, replacing, and deleting Campus iBGP VXLAN fabrics.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of VXLAN Campus fabrics to configure.
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
        - License Tier value of a fabric.
        type: str
        default: premier
        choices: [ essentials, advantage, premier ]
      alert_suspend:
        description:
        - Alert Suspend state configured on the fabric.
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
        - Telemetry collection method.
        type: str
        default: outOfBand
        choices: [ inBand, outOfBand ]
      telemetry_streaming_protocol:
        description:
        - Telemetry Streaming Protocol.
        type: str
        default: ipv4
        choices: [ ipv4, ipv6 ]
      telemetry_source_interface:
        description:
        - Telemetry Source Interface (VLAN id or Loopback id) only valid if Telemetry Collection is set to inBand.
        type: str
        default: ""
      telemetry_source_vrf:
        description:
        - VRF over which telemetry is streamed, valid only if telemetry collection is set to inband.
        type: str
        default: ""
      security_domain:
        description:
        - Security Domain associated with the fabric.
        type: str
        default: all
      management:
        description:
        - The Campus iBGP VXLAN management configuration for the fabric.
        type: dict
        suboptions:
          type:
            description:
            - The fabric management type. Must be C(vxlanCampus) for Campus iBGP VXLAN fabrics.
            type: str
            default: vxlanCampus
            choices: [ vxlanCampus ]
          bgp_asn:
            description:
            - Autonomous system number 1-4294967295 | 1-65535[.0-65535].
            type: str
            required: true
          target_subnet_mask:
            description:
            - Mask for underlay subnet IP range.
            type: int
            default: 30
          anycast_gateway_mac:
            description:
            - Shared anycast gateway MAC address.
            type: str
            default: "2020.0000.00aa"
          performance_monitoring:
            description:
            - Enable switch metrics via periodic SNMP polling.
            type: bool
            default: false
          replication_mode:
            description:
            - Replication Mode for BUM Traffic.
            type: str
            default: multicast
            choices: [ multicast, ingress ]
          multicast_group_subnet:
            description:
            - Multicast pool prefix (8-30), CIDR v4 format.
            type: str
            default: "239.1.1.0/25"
          auto_generate_multicast_group_address:
            description:
            - Generate multicast group address from pool (round-robin).
            type: bool
            default: false
          underlay_multicast_group_address_limit:
            description:
            - Max supported multicast group address value.
            type: int
            default: 128
            choices: [ 128, 512 ]
          tenant_routed_multicast:
            description:
            - Overlay IPv4 multicast support in VXLAN fabrics.
            type: bool
            default: false
          rendezvous_point_count:
            description:
            - Number of spines acting as Rendezvous-Points.
            type: int
            default: 2
            choices: [ 2, 4 ]
          rendezvous_point_loopback_id:
            description:
            - Rendezvous point loopback Id (0-1023).
            type: int
            default: 254
          vpc_peer_link_vlan:
            description:
            - VLAN range (2-4094) for vPC Peer Link SVI.
            type: str
            default: "3600"
          vpc_peer_link_enable_native_vlan:
            description:
            - Enable vPC Peer Link for Native VLAN.
            type: bool
            default: false
          vpc_peer_keep_alive_option:
            description:
            - vPC Peer Keep Alive with Loopback or Management.
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
            - vPC Peer Link Port Channel ID (1-4096).
            type: str
            default: "500"
          vpc_ipv6_neighbor_discovery_sync:
            description:
            - Enable IPv6 ND sync between vPC peers.
            type: bool
            default: true
          advertise_physical_ip:
            description:
            - Primary VTEP IP advertisement as next-hop of prefix routes.
            type: bool
            default: false
          vpc_domain_id_range:
            description:
            - vPC Domain Id range (1-1000).
            type: str
            default: "1-1000"
          bgp_loopback_id:
            description:
            - Underlay Routing Loopback Id (0-1023).
            type: int
            default: 0
          nve_loopback_id:
            description:
            - Underlay VTEP loopback Id (NVE interface) (0-1023).
            type: int
            default: 1
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
          l3_vni_no_vlan_default_option:
            description:
            - L3 VNI config without VLAN; propagated on VRF creation.
            type: bool
            default: false
          site_id:
            description:
            - EVPN Multi-Site Support. Defaults to Fabric ASN.
            type: str
          fabric_mtu:
            description:
            - Intra Fabric Interface MTU (must be even, 576-9216).
            type: int
            default: 9216
          l2_host_interface_mtu:
            description:
            - Layer 2 host interface MTU (must be even, 1500-9216).
            type: int
            default: 9216
          tenant_dhcp:
            description:
            - Enable Tenant DHCP.
            type: bool
            default: true
          nxapi:
            description:
            - Enable NX-API over HTTPS.
            type: bool
            default: false
          nxapi_https_port:
            description:
            - HTTPS port for NX-API (1-65535).
            type: int
            default: 443
          nxapi_http:
            description:
            - Enable NX-API over HTTP.
            type: bool
            default: false
          nxapi_http_port:
            description:
            - HTTP port for NX-API (1-65535).
            type: int
            default: 80
          snmp_trap:
            description:
            - Configure Nexus Dashboard as a receiver for SNMP traps.
            type: bool
            default: true
          anycast_border_gateway_advertise_physical_ip:
            description:
            - Advertise Anycast Border Gateway PIP as VTEP.
            type: bool
            default: false
          greenfield_debug_flag:
            description:
            - Allow switch config to be cleared without reload.
            type: str
            default: disable
            choices: [ enable, disable ]
          tcam_allocation:
            description:
            - TCAM commands auto-generated for VxLAN and vPC Fabric Peering.
            type: bool
            default: true
          real_time_interface_statistics_collection:
            description:
            - Enable real-time interface statistics (NX-OS only).
            type: bool
            default: false
          interface_statistics_load_interval:
            description:
            - Interface Statistics Load Interval in seconds (5-300).
            type: int
            default: 10
          bgp_loopback_ip_range:
            description:
            - Typically Loopback0 IP Address Range.
            type: str
            default: "10.2.0.0/22"
          nve_loopback_ip_range:
            description:
            - Typically Loopback1 IP Address Range.
            type: str
            default: "10.3.0.0/22"
          anycast_rendezvous_point_ip_range:
            description:
            - Anycast or Phantom RP IP Address Range.
            type: str
            default: "10.254.254.0/24"
          intra_fabric_subnet_range:
            description:
            - Address range for numbered and peer link SVI IPs.
            type: str
            default: "10.4.0.0/16"
          l2_vni_range:
            description:
            - Overlay network identifier range (1-16777214).
            type: str
            default: "30000-49000"
          l3_vni_range:
            description:
            - Overlay VRF identifier range (1-16777214).
            type: str
            default: "50000-59000"
          network_vlan_range:
            description:
            - Per Switch Overlay Network VLAN Range (2-4094).
            type: str
            default: "2300-2999"
          vrf_vlan_range:
            description:
            - Per Switch Overlay VRF VLAN Range (2-4094).
            type: str
            default: "2000-2299"
          sub_interface_dot1q_range:
            description:
            - Per aggregation dot1q range for VRF-Lite (2-4093).
            type: str
            default: "2-511"
          vrf_lite_auto_config:
            description:
            - VRF Lite Inter-Fabric Connection Deployment Options.
            type: str
            default: manual
            choices: [ manual, back2BackAndToExternal ]
          vrf_lite_subnet_range:
            description:
            - P2P Interfabric Connection address range (CIDR v4).
            type: str
            default: "10.33.0.0/16"
          vrf_lite_subnet_target_mask:
            description:
            - VRF Lite Subnet Mask (8-31).
            type: int
            default: 30
          auto_unique_vrf_lite_ip_prefix:
            description:
            - Unique IP prefix per VRF extension over VRF LITE IFC.
            type: bool
            default: false
          per_vrf_loopback_auto_provision:
            description:
            - Auto provision IPv4 loopback on VTEP on VRF attachment.
            type: bool
            default: false
          per_vrf_loopback_ip_range:
            description:
            - Prefix pool for IPv4 loopback addresses on VTEPs per VRF.
            type: str
            default: "10.5.0.0/22"
          per_vrf_loopback_auto_provision_ipv6:
            description:
            - Auto provision IPv6 loopback on VTEP on VRF attachment.
            type: bool
            default: false
          per_vrf_loopback_ipv6_range:
            description:
            - Prefix pool for IPv6 loopback addresses on VTEPs per VRF.
            type: str
            default: "fd00::a05:0/112"
          banner:
            description:
            - MOTD banner (delimiter char + message + delimiter).
            type: str
            default: ""
          day0_bootstrap:
            description:
            - Automatic IP Assignment For POAP.
            type: bool
            default: false
          local_dhcp_server:
            description:
            - Automatic IP Assignment For POAP from Local DHCP Server.
            type: bool
            default: false
          dhcp_protocol_version:
            description:
            - IP protocol version for Local DHCP Server.
            type: str
            default: dhcpv4
            choices: [ dhcpv4, dhcpv6 ]
          dhcp_start_address:
            description:
            - DHCP Scope Start Address.
            type: str
            default: ""
          dhcp_end_address:
            description:
            - DHCP Scope End Address.
            type: str
            default: ""
          management_gateway:
            description:
            - Default Gateway For Management VRF.
            type: str
            default: ""
          management_ipv4_prefix:
            description:
            - Switch Mgmt IP Subnet Prefix (IPv4, 8-30).
            type: int
            default: 24
          management_ipv6_prefix:
            description:
            - Switch Mgmt IP Subnet Prefix (IPv6, 64-126).
            type: int
            default: 64
          bootstrap_subnet_collection:
            description:
            - List of IPv4/IPv6 subnets for bootstrap.
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
          real_time_backup:
            description:
            - Backup hourly only if config deployed since last backup.
            type: bool
          scheduled_backup:
            description:
            - Enable daily backup at scheduled time.
            type: bool
          scheduled_backup_time:
            description:
            - Backup time (UTC) in 24 hour format HH:MM (00:00 to 23:59).
            type: str
            default: ""
          link_state_routing_protocol:
            description:
            - Link-State Routing Protocol. Supported: OSPF.
            type: str
            default: ospf
          route_reflector_count:
            description:
            - Number of spines acting as Route-Reflectors.
            type: int
            default: 2
            choices: [ 2, 4 ]
          bgp_ipv4_unicast_peering:
            description:
            - Enable BGP IPv4 unicast session between RR and RR client.
            type: bool
            default: false
          auto_bgp_neighbor_description:
            description:
            - Generate BGP EVPN Neighbor Description.
            type: bool
            default: true
          ospf_process_id:
            description:
            - OSPF Process Id (for Nexus - OSPF Process Tag, 1-65535).
            type: int
            default: 1
          ospf_area_id:
            description:
            - OSPF Area Id in IP address format.
            type: str
            default: "0.0.0.0"
          system_mtu:
            description:
            - IOS XE System MTU (1500-9198).
            type: int
            default: 1500
          vlan_trunking_protocol_mode:
            description:
            - VLAN Trunking Protocol Mode.
            type: str
            default: "off"
            choices: [ "off", transparent ]
          overlay_conversion:
            description:
            - One-time conversion of existing VRFs/networks from IOS_XE templates to Universal templates.
            type: bool
            default: false
          ssh_bulk_mode:
            description:
            - Enable optimizations for bulk data transfer (IOS XE only).
            type: bool
            default: false
          ssh_window_size:
            description:
            - SSH window size (IOS XE only).
            type: int
            default: 131072
          ios_xe_banner:
            description:
            - MOTD banner for IOS XE (delimiter + message + delimiter).
            type: str
            default: ""
          ios_xe_leaf_freeform:
            description:
            - Additional CLIs for all leafs (from show run).
            type: str
            default: ""
          extra_config_xe_spine:
            description:
            - Additional CLIs for all spines (from show run).
            type: str
            default: ""
          extra_config_xe_intra_fabric_links:
            description:
            - Additional CLIs for all intra-fabric links.
            type: str
            default: ""
          auto_symmetric_vrf_lite:
            description:
            - Auto-generate VRF LITE sub-interface and BGP peering on managed neighbor devices.
            type: bool
            default: false
          auto_vrf_lite_default_vrf:
            description:
            - Auto-generate Default VRF interface and BGP peering on VRF LITE IFC auto deployment.
            type: bool
            default: false
          auto_symmetric_default_vrf:
            description:
            - Auto-generate Default VRF interface and BGP peering on managed neighbor devices.
            type: bool
            default: false
          default_vrf_redistribution_bgp_route_map:
            description:
            - Route Map for redistributing BGP routes to IGP in default VRF.
            type: str
            default: "extcon-rmap-filter"
          domain_name:
            description:
            - Domain name for DHCP server PnP block.
            type: str
            default: ""
          inband_management:
            description:
            - Manage switches with only Inband connectivity.
            type: bool
            default: false
          seed_switch_core_interfaces:
            description:
            - Core-facing interface list on seed switch (N9K border gateway spine).
            type: list
            elements: str
          extra_config_xe_bootstrap:
            description:
            - Additional CLIs during device bootup/login (IOS-XE, e.g. AAA/Radius).
            type: str
            default: ""
          extra_config_bootstrap_nxos_border_gateway:
            description:
            - Additional CLIs during device bootup/login for NX-OS border gateways.
            type: str
            default: ""
          extra_config_nxos_border_gateway:
            description:
            - Additional CLIs for all Border Gateways (from show run).
            type: str
            default: ""
          extra_config_nxos_intra_fabric_links:
            description:
            - Additional CLIs for all NX-OS intra-fabric links.
            type: str
            default: ""
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
      telemetry_settings:
        description:
        - Telemetry configuration for the fabric.
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
            - Analysis settings.
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
        - External streaming settings for the fabric.
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
- Only Campus iBGP VXLAN fabric type (C(vxlanCampus)) is supported by this module.
- When using O(state=replaced) with only required fields, all optional management settings revert to their defaults.
- The O(config.management.bgp_asn) field is required when creating a fabric.
"""

EXAMPLES = r"""
- name: Create a VXLAN Campus fabric using state merged
  cisco.nd.nd_manage_fabric_campus_ibgp_vxlan:
    state: merged
    config:
      - fabric_name: my_campus_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanCampus
          bgp_asn: "65001"
          replication_mode: multicast
          anycast_gateway_mac: "2020.0000.00aa"
          link_state_routing_protocol: ospf
          ospf_process_id: 1
          ospf_area_id: "0.0.0.0"
          system_mtu: 1500
          vlan_trunking_protocol_mode: "off"
          route_reflector_count: 2
          bgp_ipv4_unicast_peering: false
          auto_bgp_neighbor_description: true
          snmp_trap: true
          nxapi: false
          nxapi_http: false
          nxapi_https_port: 443
          nxapi_http_port: 80
          performance_monitoring: false
          real_time_interface_statistics_collection: false
          interface_statistics_load_interval: 10
          sub_interface_dot1q_range: "2-511"
          day0_bootstrap: false
          local_dhcp_server: false
          dhcp_protocol_version: dhcpv4
          dhcp_start_address: ""
          dhcp_end_address: ""
          management_gateway: ""
          management_ipv4_prefix: 24
  register: result

- name: Update specific fields on an existing fabric using state merged (partial update)
  cisco.nd.nd_manage_fabric_campus_ibgp_vxlan:
    state: merged
    config:
      - fabric_name: my_campus_fabric
        category: fabric
        management:
          bgp_asn: "65002"
          performance_monitoring: true
          snmp_trap: false
          ospf_process_id: 2
          system_mtu: 9198
  register: result

- name: Create or fully replace a VXLAN Campus fabric using state replaced
  cisco.nd.nd_manage_fabric_campus_ibgp_vxlan:
    state: replaced
    config:
      - fabric_name: my_campus_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: vxlanCampus
          bgp_asn: "65004"
          replication_mode: ingress
          link_state_routing_protocol: ospf
          ospf_process_id: 3
          ospf_area_id: "0.0.0.1"
          system_mtu: 9198
          vlan_trunking_protocol_mode: transparent
          route_reflector_count: 4
          bgp_ipv4_unicast_peering: true
          snmp_trap: false
          nxapi: true
          nxapi_http: true
          nxapi_https_port: 443
          nxapi_http_port: 80
          performance_monitoring: true
          real_time_interface_statistics_collection: true
          interface_statistics_load_interval: 30
          sub_interface_dot1q_range: "2-511"
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
  cisco.nd.nd_manage_fabric_campus_ibgp_vxlan:
    state: replaced
    config:
      - fabric_name: my_campus_fabric
        category: fabric
        management:
          type: vxlanCampus
          bgp_asn: "65004"
  register: result

- name: Delete a specific fabric using state deleted
  cisco.nd.nd_manage_fabric_campus_ibgp_vxlan:
    state: deleted
    config:
      - fabric_name: my_campus_fabric
  register: result

- name: Delete multiple fabrics in a single task
  cisco.nd.nd_manage_fabric_campus_ibgp_vxlan:
    state: deleted
    config:
      - fabric_name: campus_fabric_east
      - fabric_name: campus_fabric_west
  register: result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_campus_ibgp_vxlan import FabricCampusIbgpVxlanModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_campus_ibgp_vxlan import ManageCampusIbgpVxlanFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricCampusIbgpVxlanModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    nd_state_machine = None
    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageCampusIbgpVxlanFabricOrchestrator,
        )

        # Manage state
        nd_state_machine.manage_state()

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
