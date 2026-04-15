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
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- Members are identified solely by their fabric name.
- The O(fabric_name) must refer to an existing fabric group.
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
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
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

    try:
        if module.params["state"] == "gathered":
            from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule
            from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput

            nd_module = NDModule(module)
            orchestrator = ManageFabricGroupMembersOrchestrator(sender=nd_module)
            output = NDOutput(output_level=module.params.get("output_level", "normal"))

            members_data = orchestrator.query_all()
            gathered = []
            for member in members_data:
                model = FabricGroupMemberModel.from_response(member)
                gathered.append(model.to_config())

            module.exit_json(changed=False, gathered=gathered)
        else:
            nd_state_machine = NDStateMachine(
                module=module,
                model_orchestrator=ManageFabricGroupMembersOrchestrator,
            )

            nd_state_machine.manage_state()

            module.exit_json(**nd_state_machine.output.format())

    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}")


if __name__ == "__main__":
    main()
