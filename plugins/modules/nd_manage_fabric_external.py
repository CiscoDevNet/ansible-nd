#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_external
version_added: "1.4.0"
short_description: Manage External Connectivity fabrics on Cisco Nexus Dashboard
description:
- Manage External Connectivity fabrics on Cisco Nexus Dashboard (ND).
- It supports creating, updating, replacing, and deleting External Connectivity fabrics.
author:
- Mike Wiebe (@mwiebe)
options:
  config:
    description:
    - The list of External Connectivity fabrics to configure.
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
        - The External Connectivity management configuration for the fabric.
        type: dict
        suboptions:
          type:
            description:
            - The fabric management type. Must be C(externalConnectivity) for External Connectivity fabrics.
            type: str
            default: externalConnectivity
            choices: [ externalConnectivity ]
          bgp_asn:
            description:
            - Autonomous system number 1-4294967295 | 1-65535[.0-65535].
            type: str
            required: true
          aaa:
            description:
            - Include AAA configs from Advanced tab during device bootup.
            type: bool
            default: false
          advanced_ssh_option:
            description:
            - Enable only, when IP Authorization is enabled in the AAA Server.
            type: bool
            default: false
          allow_same_loopback_ip_on_switches:
            description:
            - Allow the same loopback IP address to be configured on multiple switches (e.g. RP loopback IP).
            type: bool
            default: false
          allow_smart_switch_onboarding:
            description:
            - Enable onboarding of smart switches to Hypershield for firewall service.
            type: bool
            default: false
          bootstrap_subnet_collection:
            description:
            - List of IPv4 or IPv6 subnets to be used for bootstrap.
            - When O(state=merged), omitting this option preserves the existing collection, but providing it replaces the entire collection with the supplied list.
            - Under O(state=merged), entries in this list are not merged item-by-item. Removing one entry from the playbook removes it from the fabric, and setting an empty list clears the collection.
            - When O(state=replaced), this option is also treated as the exact desired collection. If omitted, the collection is reset to its default empty value.
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
          cdp:
            description:
            - Enable CDP on management interface.
            type: bool
            default: false
          copp_policy:
            description:
            - Fabric wide CoPP policy.
            - Customized CoPP policy should be provided when C(manual) is selected.
            type: str
            default: manual
            choices: [ dense, lenient, moderate, strict, manual ]
          create_bgp_config:
            description:
            - Generate BGP configuration for core and edge routers.
            type: bool
            default: true
          day0_bootstrap:
            description:
            - Support day 0 touchless switch bringup.
            type: bool
            default: false
          day0_plug_and_play:
            description:
            - Enable Plug n Play for Catalyst 9000 switches.
            type: bool
            default: false
          dhcp_end_address:
            description:
            - DHCP Scope End Address For Switch POAP.
            type: str
            default: ""
          dhcp_protocol_version:
            description:
            - IP protocol version for Local DHCP Server.
            type: str
            default: dhcpv4
            choices: [ dhcpv4, dhcpv6 ]
          dhcp_start_address:
            description:
            - DHCP Scope Start Address For Switch POAP.
            type: str
            default: ""
          dns_collection:
            description:
            - List of IPv4 and IPv6 DNS addresses.
            type: list
            elements: str
          dns_vrf_collection:
            description:
            - DNS Server VRFs.
            - One VRF for all DNS servers or a list of VRFs, one per DNS server.
            type: list
            elements: str
          domain_name:
            description:
            - Domain name for DHCP server PnP block.
            type: str
            default: ""
          enable_dpu_pinning:
            description:
            - Enable pinning of VRFs and networks to specific DPUs on smart switches.
            type: bool
            default: false
          extra_config_aaa:
            description:
            - Additional CLIs for AAA Configuration.
            type: str
            default: ""
          extra_config_fabric:
            description:
            - Additional CLIs for all switches.
            type: str
            default: ""
          extra_config_nxos_bootstrap:
            description:
            - Additional CLIs required during device bootup/login e.g. AAA/Radius (NX-OS).
            type: str
            default: ""
          extra_config_xe_bootstrap:
            description:
            - Additional CLIs required during device bootup/login e.g. AAA/Radius (IOS-XE).
            type: str
            default: ""
          inband_day0_bootstrap:
            description:
            - Support day 0 touchless switch bringup via inband management.
            type: bool
            default: false
          inband_management:
            description:
            - Import switches with reachability over the switch front-panel ports.
            type: bool
            default: false
          interface_statistics_load_interval:
            description:
            - Interface Statistics Load Interval Time in seconds.
            type: int
            default: 10
          local_dhcp_server:
            description:
            - Automatic IP Assignment For POAP from Local DHCP Server.
            type: bool
            default: false
          management_gateway:
            description:
            - Default Gateway For Management VRF On The Switch.
            type: str
            default: ""
          management_ipv4_prefix:
            description:
            - Switch Mgmt IP Subnet Prefix if ipv4.
            type: int
            default: 24
          management_ipv6_prefix:
            description:
            - Switch Management IP Subnet Prefix if ipv6.
            type: int
            default: 64
          monitored_mode:
            description:
            - If enabled, fabric is only monitored.
            - No configuration will be deployed.
            type: bool
            default: false
          mpls_handoff:
            description:
            - Enable MPLS Handoff.
            type: bool
            default: false
          mpls_loopback_identifier:
            description:
            - Underlay MPLS Loopback Identifier.
            type: int
          mpls_loopback_ip_range:
            description:
            - MPLS Loopback IP Address Range.
            type: str
            default: "10.102.0.0/25"
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
                    required: true
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
          nxapi_http_port:
            description:
            - HTTP port for NX-API (1-65535).
            type: int
            default: 80
          nxapi_https_port:
            description:
            - HTTPS port for NX-API (1-65535).
            type: int
            default: 443
          performance_monitoring:
            description:
            - If enabled, switch metrics are collected through periodic SNMP polling.
            - Alternative to real-time telemetry.
            type: bool
            default: false
          power_redundancy_mode:
            description:
            - Default Power Supply Mode for NX-OS Switches.
            type: str
            default: redundant
            choices: [ redundant, combined, inputSrcRedundant ]
          ptp:
            description:
            - Enable Precision Time Protocol (PTP).
            type: bool
            default: false
          ptp_domain_id:
            description:
            - Multiple Independent PTP Clocking Subdomains on a Single Network.
            type: int
            default: 0
          ptp_loopback_id:
            description:
            - Precision Time Protocol Source Loopback Id.
            type: int
            default: 0
          real_time_backup:
            description:
            - Hourly Fabric Backup only if there is any config deployment since last backup.
            type: bool
          real_time_interface_statistics_collection:
            description:
            - Enable Real Time Interface Statistics Collection.
            - Valid for NX-OS only.
            type: bool
            default: false
          scheduled_backup:
            description:
            - Enable backup at the specified time daily.
            type: bool
          scheduled_backup_time:
            description:
            - Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59).
            type: str
            default: ""
          snmp_trap:
            description:
            - Configure Nexus Dashboard as a receiver for SNMP traps.
            type: bool
            default: true
          sub_interface_dot1q_range:
            description:
            - Per aggregation dot1q range for VRF-Lite connectivity (minimum 2, maximum 4093).
            type: str
            default: "2-511"
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
- Only External Connectivity fabric type (C(externalConnectivity)) is supported by this module.
- When using O(state=replaced) with only required fields, all optional management settings revert to their defaults.
- The O(config.management.bgp_asn) field is required when creating a fabric.
"""

EXAMPLES = r"""
- name: Create an External Connectivity fabric using state merged
  cisco.nd.nd_manage_fabric_external:
    state: merged
    config:
      - fabric_name: my_ext_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: externalConnectivity
          bgp_asn: "65001"
          copp_policy: manual
          create_bgp_config: true
          cdp: false
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
  cisco.nd.nd_manage_fabric_external:
    state: merged
    config:
      - fabric_name: my_ext_fabric
        category: fabric
        management:
          bgp_asn: "65002"
          performance_monitoring: true
          snmp_trap: false
  register: result

- name: Create or fully replace an External Connectivity fabric using state replaced
  cisco.nd.nd_manage_fabric_external:
    state: replaced
    config:
      - fabric_name: my_ext_fabric
        category: fabric
        location:
          latitude: 37.7749
          longitude: -122.4194
        license_tier: premier
        alert_suspend: disabled
        security_domain: all
        telemetry_collection: false
        management:
          type: externalConnectivity
          bgp_asn: "65004"
          copp_policy: strict
          create_bgp_config: true
          cdp: true
          snmp_trap: false
          nxapi: true
          nxapi_http: true
          nxapi_https_port: 443
          nxapi_http_port: 80
          performance_monitoring: true
          real_time_interface_statistics_collection: true
          interface_statistics_load_interval: 30
          sub_interface_dot1q_range: "2-511"
          power_redundancy_mode: combined
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
  cisco.nd.nd_manage_fabric_external:
    state: replaced
    config:
      - fabric_name: my_ext_fabric
        category: fabric
        management:
          type: externalConnectivity
          bgp_asn: "65004"
  register: result

- name: Delete a specific fabric using state deleted
  cisco.nd.nd_manage_fabric_external:
    state: deleted
    config:
      - fabric_name: my_ext_fabric
  register: result

- name: Delete multiple fabrics in a single task
  cisco.nd.nd_manage_fabric_external:
    state: deleted
    config:
      - fabric_name: ext_fabric_east
      - fabric_name: ext_fabric_west
  register: result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_external import FabricExternalConnectivityModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_external import ManageExternalFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricExternalConnectivityModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageExternalFabricOrchestrator,
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
