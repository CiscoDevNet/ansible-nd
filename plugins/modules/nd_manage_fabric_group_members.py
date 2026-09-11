# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_group_members
version_added: "2.0.0"
short_description: Manage fabric group members on Cisco Nexus Dashboard
description:
- Manage fabric group members on Cisco Nexus Dashboard (ND).
- Add or remove member fabrics from a fabric group.
- This module does not create or delete fabric groups themselves, only manages the membership.
author:
- Matt Tarkington (@mtarking)
options:
  fabric_name:
    description:
    - The name of the fabric group to manage members for.
    - This is the parent fabric group, not the member fabric name.
    type: str
    required: true
  config:
    description:
    - The list of member fabrics to manage within the fabric group.
    type: list
    elements: dict
    required: true
    suboptions:
      member_name:
        description:
        - The name of the member fabric to add or remove from the fabric group.
        type: str
        required: true
      cluster_name:
        description:
        - The name of the cluster that hosts the member fabric.
        - Only applicable when O(fabric_name) is a multi-cluster fabric group, where a member
          fabric is identified by its cluster and name. Ignored for a plain fabric group.
        type: str
        required: false
  state:
    description:
    - The desired state of the fabric group members on the Cisco Nexus Dashboard.
    - Use O(state=merged) to add member fabrics to the fabric group.
      Members already in the group will be left unchanged.
    - Use O(state=deleted) to remove the specified member fabrics from the fabric group.
    - Use O(state=gathered) to retrieve the current members of the fabric group without making changes.
    type: str
    default: merged
    choices: [ merged, deleted, gathered ]
  config_actions:
    description:
    - Controls save and deploy behavior after fabric group membership is updated.
    - Save writes the pending fabric group configuration to the controller.
    - Deploy pushes the saved configuration to switches.
    - Skipped automatically when O(state=deleted) or O(state=gathered), or when no changes are made.
    - Routed to the ND Manage or OneManage surface automatically, matching the detected
      O(fabric_name) type (plain fabric group vs multi-cluster fabric group).
    type: dict
    suboptions:
      save:
        description:
        - Whether to save the fabric group configuration after changes.
        type: bool
        default: false
      deploy:
        description:
        - Whether to deploy the fabric group configuration to switches after saving.
        - Requires O(config_actions.save=true) when enabled.
        type: bool
        default: false
      type:
        description:
        - Scope of the deploy operation.
        - C(switch) deploys only to switches that are out of sync.
        - C(global) deploys to all switches in the fabric group.
        type: str
        default: switch
        choices: [ switch, global ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- The O(fabric_name) must refer to an existing fabric group or multi-cluster fabric group.
- The module auto-detects whether O(fabric_name) is a plain fabric group (managed via the ND
  Manage API) or a multi-cluster fabric group (managed via the ND OneManage API) and routes
  member operations to the correct surface.
- Fabric group members are identified by their fabric name; multi-cluster fabric group members
  are identified by the combination of O(config.cluster_name) and O(config.member_name).
"""

EXAMPLES = r"""
- name: Add members to a fabric group
  cisco.nd.nd_manage_fabric_group_members:
    fabric_name: my-fabric-group
    config:
      - member_name: member-fabric-1
      - member_name: member-fabric-2
    state: merged
  register: result

- name: Remove members from a fabric group
  cisco.nd.nd_manage_fabric_group_members:
    fabric_name: my-fabric-group
    config:
      - member_name: member-fabric-1
    state: deleted
  register: result

- name: Gather current members of a fabric group
  cisco.nd.nd_manage_fabric_group_members:
    fabric_name: my-fabric-group
    config: []
    state: gathered
  register: result

- name: Add members to a multi-cluster fabric group
  cisco.nd.nd_manage_fabric_group_members:
    fabric_name: my-multi-cluster-fabric-group
    config:
      - member_name: member-fabric-1
        cluster_name: cluster-a
      - member_name: member-fabric-2
        cluster_name: cluster-b
    state: merged
  register: result

- name: Add members then save and deploy the fabric group
  cisco.nd.nd_manage_fabric_group_members:
    fabric_name: my-fabric-group
    config:
      - member_name: member-fabric-1
    state: merged
    config_actions:
      save: true
      deploy: true
      type: switch
  register: result
"""

RETURN = r"""
changed:
  description: Whether the module made any change on the Cisco Nexus Dashboard.
  returned: always
  type: bool
  sample: true
before:
  description: The fabric group members that existed before the task ran.
  returned: always
  type: list
  elements: dict
  sample:
    - member_name: member-fabric-1
      fabric_type: vxlanIbgp
after:
  description: The fabric group members after the task ran.
  returned: always
  type: list
  elements: dict
  sample:
    - member_name: member-fabric-1
      fabric_type: vxlanIbgp
    - member_name: member-fabric-2
      fabric_type: vxlanEbgp
gathered:
  description: The current fabric group members, returned only for O(state=gathered).
  returned: when O(state=gathered)
  type: list
  elements: dict
  sample:
    - member_name: member-fabric-1
      fabric_type: vxlanIbgp
proposed:
  description: The member configuration provided by the user.
  returned: always
  type: list
  elements: dict
  sample:
    - member_name: member-fabric-1
diff:
  description: The difference between the previous and current fabric group membership.
  returned: always
  type: dict
  sample: {}
msg:
  description: A human-readable message describing the result of the task.
  returned: always
  type: str
  sample: ""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_members import ManageFabricGroupMembersOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler


def _run_gathered(module):
    """
    Query the current members of the fabric group without making any change.

    Builds a RestSend-backed orchestrator (mirroring NDStateMachine's REST wiring) so the
    generic orchestrator can read O(fabric_name) from C(rest_send.params).
    """
    sender = Sender()
    sender.ansible_module = module
    rest_send = RestSend(dict(module.params))
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.check_mode = False

    orchestrator = ManageFabricGroupMembersOrchestrator(rest_send=rest_send)
    return [FabricGroupMemberModel.from_response(member).to_config() for member in orchestrator.query_all()]


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricGroupMemberModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    # Validate config_actions before any state mutation so invalid input fails
    # deterministically, including on idempotent no-drift runs, without mutating ND.
    config_actions = module.params.get("config_actions") or {}
    save = config_actions.get("save", False)
    deploy = config_actions.get("deploy", False)
    deploy_type = config_actions.get("type", "switch")

    try:
        ManageFabricGroupMembersOrchestrator.validate_config_actions(save=save, deploy=deploy, deploy_type=deploy_type)
    except ValueError as e:
        module.fail_json(msg=str(e))

    try:
        if module.params["state"] == "gathered":
            module.exit_json(changed=False, gathered=_run_gathered(module))
        else:
            nd_state_machine = NDStateMachine(
                module=module,
                model_orchestrator=ManageFabricGroupMembersOrchestrator,
            )

            nd_state_machine.manage_state()

            # Save/deploy the parent fabric group only when membership actually changed.
            if module.params["state"] != "deleted" and len(nd_state_machine.sent) > 0:
                nd_state_machine.model_orchestrator.execute_config_actions(
                    fabric_names=[module.params["fabric_name"]],
                    save=save,
                    deploy=deploy,
                    deploy_type=deploy_type,
                )

            module.exit_json(**nd_state_machine.output.format())

    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}")


if __name__ == "__main__":
    main()
