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
            - The BGP Autonomous System Number for the fabric.
            - Must be a numeric value between 1 and 4294967295 or dotted notation 1-65535.0-65535.
            type: str
            required: true
          aaa:
            description:
            - Enable AAA.
            type: bool
            default: false
          advanced_ssh_option:
            description:
            - Enable advanced SSH option.
            type: bool
            default: false
          allow_same_loopback_ip_on_switches:
            description:
            - Allow same loopback IP on switches.
            type: bool
            default: false
          allow_smart_switch_onboarding:
            description:
            - Allow smart switch onboarding.
            type: bool
            default: false
          cdp:
            description:
            - Enable CDP.
            type: bool
            default: false
          copp_policy:
            description:
            - The CoPP policy.
            type: str
            default: manual
            choices: [ dense, lenient, moderate, strict, manual ]
          create_bgp_config:
            description:
            - Create BGP configuration.
            type: bool
            default: true
          day0_bootstrap:
            description:
            - Enable day-0 bootstrap (POAP).
            type: bool
            default: false
          day0_plug_and_play:
            description:
            - Enable day-0 plug and play.
            type: bool
            default: false
          dhcp_end_address:
            description:
            - The DHCP end address for bootstrap.
            type: str
            default: ""
          dhcp_protocol_version:
            description:
            - The DHCP protocol version for bootstrap.
            type: str
            default: dhcpv4
            choices: [ dhcpv4, dhcpv6 ]
          dhcp_start_address:
            description:
            - The DHCP start address for bootstrap.
            type: str
            default: ""
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
          domain_name:
            description:
            - The domain name.
            type: str
            default: ""
          enable_dpu_pinning:
            description:
            - Enable DPU pinning.
            type: bool
            default: false
          extra_config_aaa:
            description:
            - Extra freeform AAA configuration.
            type: str
            default: ""
          extra_config_fabric:
            description:
            - Extra freeform fabric configuration.
            type: str
            default: ""
          extra_config_nxos_bootstrap:
            description:
            - Extra NX-OS bootstrap configuration.
            type: str
            default: ""
          extra_config_xe_bootstrap:
            description:
            - Extra XE bootstrap configuration.
            type: str
            default: ""
          inband_day0_bootstrap:
            description:
            - Enable inband day-0 bootstrap.
            type: bool
            default: false
          inband_management:
            description:
            - Enable in-band management.
            type: bool
            default: false
          interface_statistics_load_interval:
            description:
            - The interface statistics load interval in seconds.
            type: int
            default: 10
          local_dhcp_server:
            description:
            - Enable local DHCP server for bootstrap.
            type: bool
            default: false
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
          monitored_mode:
            description:
            - Enable monitored mode.
            type: bool
            default: false
          mpls_handoff:
            description:
            - Enable MPLS handoff.
            type: bool
            default: false
          mpls_loopback_identifier:
            description:
            - The MPLS loopback identifier.
            type: int
          mpls_loopback_ip_range:
            description:
            - The MPLS loopback IP address pool.
            type: str
            default: "10.102.0.0/25"
          nxapi:
            description:
            - Enable NX-API (HTTPS).
            type: bool
            default: false
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
          nxapi_https_port:
            description:
            - The NX-API HTTPS port (1-65535).
            type: int
            default: 443
          performance_monitoring:
            description:
            - Enable performance monitoring.
            type: bool
            default: false
          power_redundancy_mode:
            description:
            - The power redundancy mode.
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
            - The PTP domain ID.
            type: int
            default: 0
          ptp_loopback_id:
            description:
            - The PTP loopback ID.
            type: int
            default: 0
          real_time_backup:
            description:
            - Enable real-time backup.
            type: bool
          real_time_interface_statistics_collection:
            description:
            - Enable real-time interface statistics collection.
            type: bool
            default: false
          scheduled_backup:
            description:
            - Enable scheduled backup.
            type: bool
          scheduled_backup_time:
            description:
            - The scheduled backup time.
            type: str
            default: ""
          snmp_trap:
            description:
            - Enable SNMP traps.
            type: bool
            default: true
          sub_interface_dot1q_range:
            description:
            - The sub-interface 802.1q range.
            type: str
            default: "2-511"
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
      - name: my_ext_fabric
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
      - name: my_ext_fabric
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
      - name: my_ext_fabric
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
      - name: my_ext_fabric
        category: fabric
        management:
          type: externalConnectivity
          bgp_asn: "65004"
  register: result

- name: Delete a specific fabric using state deleted
  cisco.nd.nd_manage_fabric_external:
    state: deleted
    config:
      - name: my_ext_fabric
  register: result

- name: Delete multiple fabrics in a single task
  cisco.nd.nd_manage_fabric_external:
    state: deleted
    config:
      - name: ext_fabric_east
      - name: ext_fabric_west
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
