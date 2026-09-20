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
        - Required when O(fabric_name) is a multi-cluster fabric group, which identifies a member
          by its cluster and name.
        - Must be omitted when O(fabric_name) is a single-cluster fabric group, which identifies a
          member by name alone.
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
    - Skipped automatically when O(state=gathered), or when membership is already as requested.
    - Routed to the ND Manage or OneManage API automatically, matching the detected
      O(fabric_name) type (fabric group vs multi-cluster fabric group).
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
  Pointing it at a fabric, or at a name that does not exist, fails the task.
- The module detects whether O(fabric_name) is a fabric group (managed through the ND Manage
  API) or a multi-cluster fabric group (managed through the ND OneManage API) and routes
  member operations accordingly.
- Multi-cluster fabric groups are only reachable from a session authenticated through the
  multi-cluster login domain. Set O(login_domain) to that domain, otherwise ND refuses every
  OneManage request and the module cannot manage multi-cluster fabric group membership.
- A fabric can belong to only one fabric group at a time. Remove it from its current group
  before adding it to another.
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
    login_domain: multi-cluster-domain
    fabric_name: my-multi-cluster-fabric-group
    config:
      - member_name: member-fabric-1
        cluster_name: cluster-a
      - member_name: member-fabric-2
        cluster_name: cluster-b
    state: merged
  register: result

- name: Remove a member from a multi-cluster fabric group
  cisco.nd.nd_manage_fabric_group_members:
    login_domain: multi-cluster-domain
    fabric_name: my-multi-cluster-fabric-group
    config:
      - member_name: member-fabric-1
        cluster_name: cluster-a
    state: deleted
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
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.raw_args import get_raw_module_args
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_members import FabricGroupMemberModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_group_members import ManageFabricGroupMembersOrchestrator


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricGroupMemberModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    # Parse and validate config_actions BEFORE any API call so invalid input fails
    # deterministically on every run, including idempotent no-drift runs and the
    # read-only gathered state, and never mutates ND before failing.
    state = module.params["state"]
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
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageFabricGroupMembersOrchestrator,
        )

        nd_state_machine.manage_state()

        surface_note = nd_state_machine.model_orchestrator.surface_note
        if surface_note:
            nd_state_machine.output.assign(logs=[surface_note])

        # Membership changes stage pending configuration on the group whether a member was
        # added or removed, so both are save/deploy candidates; an unchanged group is not.
        if len(nd_state_machine.sent) > 0 or len(nd_state_machine.removed) > 0:
            nd_state_machine.model_orchestrator.run_config_actions(
                actions=config_actions,
                fabric_names=[module.params["fabric_name"]],
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
