# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_infra_tenant
version_added: "2.0.0"
short_description: Manage tenants on Cisco Nexus Dashboard
description:
- Manage tenants on Cisco Nexus Dashboard (ND).
- It supports creating, updating, and deleting tenants.
- Optionally manage fabric associations for each tenant, linking tenants to NDFC-managed fabrics
  with VLAN allocation.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of the tenants to configure.
    type: list
    elements: dict
    required: True
    suboptions:
      name:
        description:
        - The name of the tenant.
        - The name must be between 1 and 63 characters and can contain alphanumeric characters, dots, dashes, and underscores.
        type: str
        required: true
      description:
        description:
        - The description of the tenant.
        - The description can be up to 128 characters.
        type: str
      fabric_associations:
        description:
        - The list of fabric associations for the tenant.
        - Each entry associates the tenant with a fabric managed by NDFC and defines the allowed VLANs.
        - When specified, the module will reconcile the associations on the ND Manage API
          (C(/api/v1/manage/tenantFabricAssociations)).
        - When not specified, existing fabric associations are left unchanged.
        type: list
        elements: dict
        suboptions:
          fabric_name:
            description:
            - The name of the fabric to associate with the tenant.
            type: str
            required: true
          allowed_vlans:
            description:
            - The list of allowed VLAN ranges for the tenant on this fabric.
            - Each element can be a single VLAN ID or a range (e.g., C(10-20), C(30-40)).
            type: list
            elements: str
          local_name:
            description:
            - The local name for the tenant in the cluster.
            type: str
          tenant_prefix:
            description:
            - The tenant prefix for ACI fabrics.
            type: str
  state:
    description:
    - The desired state of the tenant resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new tenants and update existing ones as defined in your configuration.
      Tenants on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the tenants specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The tenants on ND will be modified to exactly match the configuration.
      Any tenant existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the tenants specified in the configuration from the Cisco Nexus Dashboard.
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
- name: Create a new tenant
  cisco.nd.nd_infra_tenant:
    config:
      - name: ansible_tenant
        description: Tenant managed by Ansible
    state: merged
  register: result

- name: Create multiple tenants
  cisco.nd.nd_infra_tenant:
    config:
      - name: ansible_tenant_1
        description: First tenant
      - name: ansible_tenant_2
        description: Second tenant
    state: merged

- name: Create a tenant with fabric associations
  cisco.nd.nd_infra_tenant:
    config:
      - name: ansible_tenant
        description: Tenant with fabric access
        fabric_associations:
          - fabric_name: my_fabric
            allowed_vlans:
              - "10-20"
              - "30-40"
          - fabric_name: my_other_fabric
            allowed_vlans:
              - "100-200"
            local_name: tenant_local
    state: merged

- name: Update tenant description and fabric associations
  cisco.nd.nd_infra_tenant:
    config:
      - name: ansible_tenant
        description: Updated description
        fabric_associations:
          - fabric_name: my_fabric
            allowed_vlans:
              - "10-50"
    state: replaced

- name: Delete a tenant (also removes its fabric associations)
  cisco.nd.nd_infra_tenant:
    config:
      - name: ansible_tenant
    state: deleted
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.infra_tenant.infra_tenant import InfraTenantModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.infra_tenant import InfraTenantOrchestrator


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(InfraTenantModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=InfraTenantOrchestrator,
        )

        nd_state_machine.manage_state()

        module.exit_json(**nd_state_machine.output.format())

    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}", **nd_state_machine.output.format())


if __name__ == "__main__":
    main()
