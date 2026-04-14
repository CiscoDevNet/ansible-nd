#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_fabric_ndb
version_added: "2.0.0"
short_description: Manage Data Broker (NDB) fabrics on Cisco Nexus Dashboard
description:
- Manage Nexus Dashboard Data Broker (NDB) fabrics on Cisco Nexus Dashboard (ND).
- It supports creating, updating, replacing, and deleting Data Broker fabrics.
- The Data Broker fabric type (C(dataBroker)) has minimal management settings compared to other fabric types.
author:
- Matt Tarkington (@mtarking)
options:
  config:
    description:
    - The list of Data Broker fabrics to configure.
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
      license_tier:
        description:
        - License Tier for fabric. Only C(essentials) is supported for Data Broker fabrics.
        type: str
        default: essentials
        choices: [ essentials ]
      security_domain:
        description:
        - Security Domain associated with the fabric.
        type: str
        default: all
      management:
        description:
        - The Data Broker management configuration for the fabric.
        type: dict
        suboptions:
          type:
            description:
            - The fabric management type. Must be C(dataBroker) for Data Broker fabrics.
            type: str
            default: dataBroker
            choices: [ dataBroker ]
          auto_isl_deploy:
            description:
            - Enable automatic ISL deployment.
            type: bool
            default: true
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
- Only Data Broker fabric type (C(dataBroker)) is supported by this module.
- The Data Broker management configuration is minimal — it contains only the C(type) discriminator field.
"""

EXAMPLES = r"""
- name: Create a Data Broker fabric using state merged
  cisco.nd.nd_manage_fabric_ndb:
    state: merged
    config:
      - fabric_name: my_ndb_fabric
        security_domain: all
        management:
          type: dataBroker
          auto_isl_deploy: true
  register: result

- name: Update management settings on an existing Data Broker fabric using state merged
  cisco.nd.nd_manage_fabric_ndb:
    state: merged
    config:
      - fabric_name: my_ndb_fabric
        management:
          auto_isl_deploy: false
  register: result

- name: Replace a Data Broker fabric configuration using state replaced
  cisco.nd.nd_manage_fabric_ndb:
    state: replaced
    config:
      - fabric_name: my_ndb_fabric
        security_domain: all
        management:
          type: dataBroker
          auto_isl_deploy: true
  register: result

- name: Delete a Data Broker fabric using state deleted
  cisco.nd.nd_manage_fabric_ndb:
    state: deleted
    config:
      - fabric_name: my_ndb_fabric
  register: result

- name: Delete multiple Data Broker fabrics in a single task
  cisco.nd.nd_manage_fabric_ndb:
    state: deleted
    config:
      - fabric_name: ndb_fabric_east
      - fabric_name: ndb_fabric_west
  register: result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ndb import FabricDataBrokerModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_fabric_ndb import ManageNdbFabricOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(FabricDataBrokerModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageNdbFabricOrchestrator,
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
