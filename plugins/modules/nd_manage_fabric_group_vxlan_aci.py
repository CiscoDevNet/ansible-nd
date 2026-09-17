#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_group_vxlan_aci
version_added: "2.0.0"
short_description: Manage VXLAN-to-ACI Fabric Groups on Cisco Nexus Dashboard
description:
- Manage VXLAN-to-ACI Fabric Groups on Cisco Nexus Dashboard (ND).
- A VXLAN-to-ACI fabric group is a Multi-Site domain that contains both ACI and VXLAN EVPN fabrics.
- It supports creating, updating, replacing and deleting VXLAN-to-ACI fabric groups.
- Fabric groups aggregate multiple member fabrics for multi-site operations.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of VXLAN-to-ACI fabric groups to configure.
    type: list
    elements: dict
    suboptions:
      fabric_name:
        description:
        - The name of the fabric group.
        - Only letters, numbers, underscores, and hyphens are allowed.
        - The O(config.fabric_name) must be defined when creating, updating or deleting a fabric group.
        type: str
        required: true
      management:
        description:
        - The VXLAN-to-ACI fabric group management configuration.
        - Properties control multi-site overlay/underlay interconnect, security groups, and VNI ranges.
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

          # Anycast Gateway
          anycast_gateway_mac:
            description:
            - Shared anycast gateway MAC address for all VTEPs in xxxx.xxxx.xxxx format.
            - Should be set to APIC's default bridge domain (BD) MAC address.
            type: str
            default: 0022.bdf8.19ff

          # Multi-Site Overlay
          multisite_overlay_inter_connect_type:
            description:
            - Type of Multi-Site Overlay Interconnect.
            type: str
            default: directPeering
            choices: [ manual, directPeering ]

          # Multi-Site Underlay
          auto_multisite_underlay_inter_connect:
            description:
            - Auto-configures Multi-Site underlay Inter-Fabric links.
            type: bool
            default: true
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
            - Loopback ID for multi-site, typically Loopback100 (0-1023). Only applicable for NX fabric.
            type: int
            default: 100
          border_gateway_routing_tag:
            description:
            - Routing tag associated with IP address of loopback and DCI interfaces (0-4294967295). Only applicable for NX fabric.
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

          # Security Groups
          security_group_tag:
            description:
            - Security Group Tag enforcement. If set to C(strict), only security groups enabled child fabrics will be allowed.
            type: str
            default: strict
            choices: [ loose, strict ]
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
            default: true
  state:
    description:
    - The desired state of the fabric group resources on the Cisco Nexus Dashboard.
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
- Only VXLAN-to-ACI fabric group type (C(vxlanAci)) is supported by this module.
- When using O(state=replaced) with only required fields, all optional management settings revert to their defaults.
- Fabric group member management (add/remove members) is not handled by this module. Use a dedicated member module.
"""

EXAMPLES = r"""
- name: Create a VXLAN-to-ACI fabric group using state merged
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: merged
    config:
      - fabric_name: my_vxlan_aci_group
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          anycast_gateway_mac: "0022.bdf8.19ff"
          multisite_overlay_inter_connect_type: directPeering
          multisite_loopback_ip_range: "10.10.0.0/24"
          multisite_underlay_subnet_range: "10.10.1.0/24"
          multisite_underlay_subnet_target_mask: 30
          multisite_delay_restore: 300
  register: result

- name: Update specific fields on an existing fabric group using state merged (partial update)
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: merged
    config:
      - fabric_name: my_vxlan_aci_group
        management:
          auto_multisite_underlay_inter_connect: false
          multisite_delay_restore: 600
  register: result

- name: Create a VXLAN-to-ACI fabric group with strict security group enforcement
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: merged
    config:
      - fabric_name: my_secure_group
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          security_group_tag: strict
          security_group_tag_prefix: SGT_
          security_group_tag_id_range: "10000-14000"
          security_group_tag_preprovision: true
  register: result

- name: Create or fully replace a VXLAN-to-ACI fabric group using state replaced
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: replaced
    config:
      - fabric_name: my_vxlan_aci_group
        management:
          l2_vni_range: "40000-59000"
          l3_vni_range: "60000-69000"
          anycast_gateway_mac: "0022.bdf8.19ff"
          multisite_overlay_inter_connect_type: manual
          multisite_loopback_ip_range: "10.20.0.0/24"
          multisite_underlay_subnet_range: "10.20.1.0/24"
          multisite_underlay_subnet_target_mask: 30
          multisite_delay_restore: 500
  register: result

- name: Replace fabric group with only required fields (all optional settings revert to defaults)
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: replaced
    config:
      - fabric_name: my_vxlan_aci_group
  register: result

- name: Enforce exact fabric group inventory using state overridden (deletes unlisted groups)
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: overridden
    config:
      - fabric_name: group_east
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          multisite_loopback_ip_range: "10.10.0.0/24"
          multisite_underlay_subnet_range: "10.10.1.0/24"
      - fabric_name: group_west
        management:
          l2_vni_range: "30000-49000"
          l3_vni_range: "50000-59000"
          multisite_loopback_ip_range: "10.20.0.0/24"
          multisite_underlay_subnet_range: "10.20.1.0/24"
  register: result

- name: Delete a specific fabric group using state deleted
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: deleted
    config:
      - fabric_name: my_vxlan_aci_group
  register: result

- name: Delete multiple fabric groups in a single task
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: deleted
    config:
      - fabric_name: group_east
      - fabric_name: group_west
      - fabric_name: group_old
  register: result

- name: Save and deploy fabric group configuration after changes
  cisco.nd.nd_manage_fabric_group_vxlan_aci:
    state: merged
    config:
      - fabric_name: my_vxlan_aci_group
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
    - VXLAN-to-ACI fabric group configuration before changes.
    - Queried from the controller and may contain read-only properties.
    type: list
    returned: always
    sample: [{"fabric_name": "my_vxlan_aci_group", "management": {"l2_vni_range": "30000-49000"}}]
after:
    description:
    - VXLAN-to-ACI fabric group configuration after changes.
    - Refreshed from the controller after write operations.
    type: list
    returned: always
    sample: [{"fabric_name": "my_vxlan_aci_group", "management": {"l2_vni_range": "40000-59000"}}]
diff:
    description: Configuration differences between before and after states.
    type: list
    returned: always
    sample: [{"fabric_name": "my_vxlan_aci_group", "management": {"l2_vni_range": "40000-59000"}}]
proposed:
    description: Proposed configuration sent to the module.
    type: list
    returned: info or debug output_level
    sample: [{"fabric_name": "my_vxlan_aci_group", "management": {"l2_vni_range": "40000-59000"}}]
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
    sample: ["/api/v1/manage/fabrics/my_vxlan_aci_group"]
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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan_aci import FabricGroupVxlanAciModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_vxlan_aci import ManageFabricGroupVxlanAciOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricGroupVxlanAciModel.get_argument_spec())

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
        ManageFabricGroupVxlanAciOrchestrator.validate_config_actions(save=save, deploy=deploy, deploy_type=deploy_type)
    except ValueError as e:
        module.fail_json(msg=str(e))

    nd_state_machine = None
    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageFabricGroupVxlanAciOrchestrator,
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
