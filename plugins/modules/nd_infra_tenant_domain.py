# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_infra_tenant_domain
version_added: "2.0.0"
short_description: Manage tenant domains on Cisco Nexus Dashboard
description:
- Manage tenant domains on Cisco Nexus Dashboard (ND).
- It supports creating, updating, and deleting tenant domains.
- Tenant domains group tenants together by referencing their names.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of the tenant domains to configure.
    type: list
    elements: dict
    required: True
    suboptions:
      name:
        description:
        - The name of the tenant domain.
        - The name must be between 1 and 63 characters and can contain alphanumeric characters, dashes, and underscores.
        type: str
        required: true
      tenant_names:
        description:
        - The list of tenant names that belong to this tenant domain.
        type: list
        elements: str
      description:
        description:
        - The description of the tenant domain.
        type: str
  state:
    description:
    - The desired state of the tenant domain resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new tenant domains and update existing ones as defined in your configuration.
      Tenant domains on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the tenant domains specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The tenant domains on ND will be modified to exactly match the configuration.
      Any tenant domain existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the tenant domains specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
"""

EXAMPLES = r"""
- name: Create a new tenant domain
  cisco.nd.nd_infra_tenant_domain:
    config:
      - name: ansible_tenant_domain
        tenant_names:
          - tenant_1
          - tenant_2
        description: Tenant domain managed by Ansible
    state: merged
  register: result

- name: Update tenant domain membership
  cisco.nd.nd_infra_tenant_domain:
    config:
      - name: ansible_tenant_domain
        tenant_names:
          - tenant_1
          - tenant_2
          - tenant_3
    state: replaced

- name: Delete a tenant domain
  cisco.nd.nd_infra_tenant_domain:
    config:
      - name: ansible_tenant_domain
    state: deleted
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.infra_tenant_domain.infra_tenant_domain import InfraTenantDomainModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.infra_tenant_domain import InfraTenantDomainOrchestrator


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(InfraTenantDomainModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=InfraTenantDomainOrchestrator,
        )

        nd_state_machine.manage_state()

        module.exit_json(**nd_state_machine.output.format())

    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}", **nd_state_machine.output.format())


if __name__ == "__main__":
    main()
