#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_multi_cluster_fabric_group_vxlan
version_added: "2.0.0"
short_description: Manage multi-cluster VXLAN Fabric Groups (MCFG) on Cisco Nexus Dashboard
description:
- Manage multi-cluster VXLAN Fabric Groups (MCFG) on Cisco Nexus Dashboard (ND) via the OneManage service.
- It supports creating, updating, replacing and deleting multi-cluster VXLAN fabric groups.
- A multi-cluster fabric group aggregates member fabrics across Nexus Dashboard clusters for multi-site operations.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of multi-cluster VXLAN fabric groups to configure.
    type: list
    elements: dict
    suboptions:
      fabric_name:
        description:
        - The name of the multi-cluster fabric group.
        - Only letters, numbers, underscores, and hyphens are allowed.
        - The O(config.fabric_name) must be defined when creating, updating or deleting a fabric group.
        type: str
        required: true
      management:
        description:
        - The multi-cluster VXLAN fabric group management configuration.
        - Properties control multi-site overlay/underlay, CloudSec, security groups, and VNI ranges.
        type: dict
        suboptions:
          # General
          l2_vni_range:
            description:
            - The Layer 2 VNI range (minimum 1, maximum 16777214).
            type: str
            default: "30000-49000"
          l3_vni_range:
            description:
            - The Layer 3 VNI range (minimum 1, maximum 16777214).
            type: str
            default: "50000-59000"
          downstream_vni:
            description:
            - Enable unique per-fabric virtual network identifier (VNI).
            type: bool
            default: false
          downstream_l2_vni_range:
            description:
            - Unique Range for L2VNI when downstream VNI is enabled (min 1, max 16777214).
            - Should not conflict with any VNI already used in member fabric.
            type: str
            default: "60000-69000"
          downstream_l3_vni_range:
            description:
            - Unique Range for L3VNI when downstream VNI is enabled (min 1, max 16777214).
            - Should not conflict with any VNI already used in member fabric.
            type: str
            default: "80000-89000"
          underlay_ipv6:
            description:
            - Enable IPv6 underlay. If not enabled, IPv4 underlay is used.
            type: bool
            default: false

          # Templates
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

          # PVLAN
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

          # Anycast Gateway
          anycast_gateway_mac:
            description:
            - Shared anycast gateway MAC address for all VTEPs in xxxx.xxxx.xxxx format.
            type: str
            default: 2020.0000.00aa

          # Multi-Site Overlay
          multisite_overlay_inter_connect_type:
            description:
            - Type of Multi-Site Overlay Interconnect.
            type: str
            default: manual
            choices: [ manual, routeServer, directPeering ]
          route_server_collection:
            description:
            - List of Multi-Site Route-Servers.
            - Each entry requires a route server IP address and BGP ASN.
            type: list
            elements: dict
            suboptions:
              route_server_ip:
                description:
                - Route Server IP Address.
                type: str
                required: true
              route_server_asn:
                description:
                - Autonomous system number (1-4294967295 or dotted notation).
                type: str
                required: true
          route_server_redistribute_direct_route_map:
            description:
            - Redistribute direct on route servers for auto-created Multi-Site overlay IFC links.
            - Applicable only when deployment method is centralizedToRouteServers.
            type: bool
            default: false
          route_server_routing_tag:
            description:
            - Routing tag associated with Route Server IP for redistribute direct (0-4294967295).
            type: int
            default: 54321
          enable_ms_overlay_ifc_bgp_desc:
            description:
            - Generate BGP neighbor description for auto-created Multi-Site overlay IFC links.
            type: bool
            default: true

          # Multi-Site Underlay
          auto_multisite_underlay_inter_connect:
            description:
            - Auto-configures Multi-Site underlay Inter-Fabric links.
            type: bool
            default: false
          bgp_send_community:
            description:
            - Send community for auto-created Multi-Site Underlay Inter-Fabric links.
            type: bool
            default: false
          bgp_log_neighbor_change:
            description:
            - Log neighbor change for auto-created Multi-Site Underlay Inter-Fabric links.
            type: bool
            default: false
          bgp_bfd:
            description:
            - BFD for auto-created Multi-Site Underlay Inter-Fabric links.
            type: bool
            default: false
          multisite_delay_restore:
            description:
            - Multi-Site underlay and overlay control plane convergence time in seconds (30-1000).
            type: int
            default: 300
          multisite_inter_connect_bgp_authentication:
            description:
            - Enables or disables the BGP authentication for inter-site links.
            type: bool
            default: false
          multisite_inter_connect_bgp_auth_key_type:
            description:
            - "BGP key encryption type: 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7."
            type: str
            default: 3des
            choices: [ 3des, type6, type7 ]
          multisite_inter_connect_bgp_key:
            description:
            - Encrypted BGP authentication key based on type.
            type: str
          multisite_loopback_id:
            description:
            - Loopback ID for multi-site, typically Loopback100 (0-1023).
            type: int
            default: 100
          border_gateway_routing_tag:
            description:
            - Routing tag associated with IP address of loopback and DCI interfaces (0-4294967295).
            type: int
            default: 54321

          # Multi-Site IP Ranges
          multisite_loopback_ip_range:
            description:
            - Typically Loopback100 IP Address Range.
            type: str
            default: "10.10.0.0/24"
          multisite_underlay_subnet_range:
            description:
            - Address range to assign P2P DCI Links.
            type: str
            default: "10.10.1.0/24"
          multisite_underlay_subnet_target_mask:
            description:
            - Target Mask for Subnet Range (8-31).
            type: int
            default: 30
          multisite_loopback_ipv6_range:
            description:
            - Typically Loopback100 IPv6 Address Range.
            type: str
            default: "fd00::a10:0/120"
          multisite_underlay_ipv6_subnet_range:
            description:
            - Address range to assign P2P DCI IPv6 Links.
            type: str
            default: "fd00::a11:0/120"
          multisite_underlay_ipv6_subnet_target_mask:
            description:
            - Target IPv6 Mask for Subnet Range (120-127).
            type: int
            default: 126

          # Tenant Routed Multicast
          tenant_routed_multicast_v4_v6:
            description:
            - If enabled, MVPN VRI IDs are tracked in MSD fabric to ensure uniqueness within MSD.
            type: bool
            default: false

          # Security Groups
          security_group_tag:
            description:
            - Security Group Tag enforcement. If set to C(strict), only security groups enabled child fabrics will be allowed.
            type: str
            default: "off"
            choices: [ "off", loose, strict ]
          security_group_tag_prefix:
            description:
            - Prefix to be used when a new security group is created.
            type: str
            default: SG_
          security_group_tag_mac_segmentation:
            description:
            - Enable MAC based segmentation for security groups.
            type: bool
            default: false
          security_group_tag_id_range:
            description:
            - Security group tag (SGT) identifier range (min 16, max 65535).
            type: str
            default: "10000-14000"
          security_group_tag_preprovision:
            description:
            - Generate security groups configuration for non-enforced VRFs.
            type: bool
            default: false

          # CloudSec
          auto_configure_cloud_sec:
            description:
            - Auto Config CloudSec on Border Gateways.
            type: bool
            default: false
          cloud_sec_key:
            description:
            - Cisco Type 7 Encrypted Octet String for CloudSec.
            type: str
          cloud_sec_algorithm:
            description:
            - CloudSec Encryption Algorithm.
            type: str
            default: AES_128_CMAC
            choices: [ AES_128_CMAC, AES_256_CMAC ]
          cloud_sec_enforcement:
            description:
            - CloudSec enforcement type. If set C(strict), data across site must be encrypted.
            type: str
            default: strict
            choices: [ strict, loose ]
          cloud_sec_report_timer:
            description:
            - CloudSec Operational Status periodic report timer in minutes (5-60).
            type: int
            default: 5

          # Configuration Backup
          scheduled_backup:
            description:
            - Enable backup at the specified time daily.
            type: bool
          scheduled_backup_time:
            description:
            - Time (UTC) in 24 hour format to take a daily backup if enabled (00:00 to 23:59).
            type: str
  state:
    description:
    - The desired state of the multi-cluster fabric group resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new fabric groups and update existing ones as defined in the configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the fabric group configuration specified in the configuration.
      Any settings not explicitly provided will revert to their defaults.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      Any fabric group existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the fabric groups specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, deleted, overridden ]
  config_actions:
    description:
    - Controls save and deploy behavior after fabric group configuration is updated.
    - Save writes pending configuration to the controller.
    - Deploy pushes the saved configuration to switches.
    - Skipped automatically when O(state=deleted) or when no changes are made.
    type: dict
    suboptions:
      save:
        description:
        - Whether to save fabric group configuration after changes.
        type: bool
        default: false
      deploy:
        description:
        - Whether to deploy fabric group configuration to switches after saving.
        - Requires O(config_actions.save=true) when enabled.
        type: bool
        default: false
      type:
        description:
        - Scope of the deploy operation.
        - C(switch) deploys only to affected switches.
        - C(global) deploys to all switches in the fabric group.
        type: str
        default: switch
        choices: [ switch, global ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- This module manages multi-cluster fabric groups (C(multiClusterFabricGroup)) via the OneManage service.
- Only VXLAN fabric group type (C(vxlan)) is supported by this module.
- When using O(state=replaced) with only required fields, all optional management settings revert to their defaults.
- Fabric group member management (add/remove members) is not handled by this module. Use M(cisco.nd.nd_manage_fabric_group_members).
"""

EXAMPLES = r"""
- name: Create a multi-cluster VXLAN fabric group (MCFG) using state merged
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: merged
    config:
      - fabric_name: my_mcfg
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          anycast_gateway_mac: "2020.0000.00aa"
          multisite_overlay_inter_connect_type: manual
          multisite_loopback_ip_range: "10.10.0.0/24"
          multisite_underlay_subnet_range: "10.10.1.0/24"
          multisite_underlay_subnet_target_mask: 30
          multisite_delay_restore: 300
  register: result

- name: Update specific fields on an existing MCFG using state merged (partial update)
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: merged
    config:
      - fabric_name: my_mcfg
        management:
          anycast_gateway_mac: "2020.0000.00bb"
          auto_multisite_underlay_inter_connect: true
          multisite_delay_restore: 600
  register: result

- name: Create a multi-cluster VXLAN fabric group with route servers
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: merged
    config:
      - fabric_name: my_mcfg
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          anycast_gateway_mac: "2020.0000.00aa"
          multisite_overlay_inter_connect_type: routeServer
          route_server_collection:
            - route_server_ip: "10.1.1.1"
              route_server_asn: "65000"
            - route_server_ip: "10.1.1.2"
              route_server_asn: "65001"
          multisite_loopback_ip_range: "10.10.0.0/24"
          multisite_underlay_subnet_range: "10.10.1.0/24"
          multisite_underlay_subnet_target_mask: 30
          multisite_delay_restore: 300
  register: result

- name: Create a multi-cluster VXLAN fabric group with CloudSec enabled
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: merged
    config:
      - fabric_name: my_secure_mcfg
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          anycast_gateway_mac: "2020.0000.00aa"
          auto_configure_cloud_sec: true
          cloud_sec_algorithm: AES_256_CMAC
          cloud_sec_enforcement: strict
          cloud_sec_report_timer: 10
  register: result

- name: Create or fully replace a multi-cluster VXLAN fabric group using state replaced
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: replaced
    config:
      - fabric_name: my_mcfg
        management:
          l2_vni_range: "40000-59000"
          l3_vni_range: "60000-69000"
          anycast_gateway_mac: "2020.0000.00cc"
          multisite_overlay_inter_connect_type: directPeering
          multisite_loopback_ip_range: "10.20.0.0/24"
          multisite_underlay_subnet_range: "10.20.1.0/24"
          multisite_underlay_subnet_target_mask: 30
          multisite_delay_restore: 500
          downstream_vni: true
          downstream_l2_vni_range: "60000-69000"
          downstream_l3_vni_range: "80000-89000"
  register: result

- name: Replace MCFG with only required fields (all optional settings revert to defaults)
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: replaced
    config:
      - fabric_name: my_mcfg
  register: result

- name: Enforce exact MCFG inventory using state overridden (deletes unlisted groups)
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: overridden
    config:
      - fabric_name: mcfg_east
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          anycast_gateway_mac: "2020.0000.0010"
          multisite_loopback_ip_range: "10.10.0.0/24"
          multisite_underlay_subnet_range: "10.10.1.0/24"
      - fabric_name: mcfg_west
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          anycast_gateway_mac: "2020.0000.0020"
          multisite_loopback_ip_range: "10.20.0.0/24"
          multisite_underlay_subnet_range: "10.20.1.0/24"
  register: result

- name: Delete a specific multi-cluster fabric group using state deleted
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: deleted
    config:
      - fabric_name: my_mcfg
  register: result

- name: Delete multiple multi-cluster fabric groups in a single task
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: deleted
    config:
      - fabric_name: mcfg_east
      - fabric_name: mcfg_west
      - fabric_name: mcfg_old
  register: result

- name: Save and deploy multi-cluster fabric group configuration after changes
  cisco.nd.nd_manage_multi_cluster_fabric_group_vxlan:
    state: merged
    config:
      - fabric_name: my_mcfg
        management:
          l2_vni_range: "30000-49000"
    config_actions:
      save: true
      deploy: true
      type: switch
  register: result
"""

RETURN = r"""
changed:
    description: Whether the module made any changes.
    type: bool
    returned: always
    sample: true
before:
    description:
    - Multi-cluster VXLAN fabric group configuration before changes.
    - Queried from the controller and may contain read-only properties.
    type: list
    returned: always
    sample: [{"fabric_name": "my_mcfg", "management": {"l2_vni_range": "30000-49000"}}]
after:
    description:
    - Multi-cluster VXLAN fabric group configuration after changes.
    - Refreshed from the controller after write operations.
    type: list
    returned: always
    sample: [{"fabric_name": "my_mcfg", "management": {"l2_vni_range": "40000-59000"}}]
diff:
    description: Configuration differences between before and after states.
    type: list
    returned: always
    sample: [{"fabric_name": "my_mcfg", "management": {"l2_vni_range": "40000-59000"}}]
proposed:
    description: Proposed configuration sent to the module.
    type: list
    returned: info or debug output_level
    sample: [{"fabric_name": "my_mcfg", "management": {"l2_vni_range": "40000-59000"}}]
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
    sample: ["/api/v1/oneManage/manage/fabrics/my_mcfg"]
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_multi_cluster_fabric_group_vxlan import (
    MultiClusterFabricGroupVxlanModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_multi_cluster_fabric_group_vxlan import (
    ManageMultiClusterFabricGroupVxlanOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(MultiClusterFabricGroupVxlanModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    require_pydantic(module)

    # Parse and validate config_actions BEFORE any state mutation so invalid
    # input fails deterministically on every run, including idempotent no-drift
    # runs, and never mutates ND before failing.
    config_actions = module.params.get("config_actions") or {}
    save = config_actions.get("save", False)
    deploy = config_actions.get("deploy", False)
    deploy_type = config_actions.get("type", "switch")
    state = module.params.get("state", "merged")

    try:
        ManageMultiClusterFabricGroupVxlanOrchestrator.validate_config_actions(save=save, deploy=deploy, deploy_type=deploy_type)
    except ValueError as e:
        module.fail_json(msg=str(e))

    nd_state_machine = None
    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageMultiClusterFabricGroupVxlanOrchestrator,
        )

        # Manage state
        nd_state_machine.manage_state()

        # Execute config save/deploy actions via orchestrator mixin (only on real changes)
        if state != "deleted" and len(nd_state_machine.sent) > 0:
            fabric_names = []
            for item in nd_state_machine.sent:
                name = item.get_identifier_value()
                if name and name not in fabric_names:
                    fabric_names.append(name)
            if fabric_names:
                nd_state_machine.model_orchestrator.execute_config_actions(
                    fabric_names=fabric_names,
                    save=save,
                    deploy=deploy,
                    deploy_type=deploy_type,
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
