# Copyright: (c) 2026, Cisco Systems

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_tor
version_added: "1.7.0"
short_description: Manage access or ToR switch associations on Cisco Nexus Dashboard
description:
- Manage access or ToR (Top of Rack) switch associations with aggregation or leaf switches on Cisco Nexus Dashboard (ND).
- It supports associating, disassociating, and querying ToR switch pairings within a fabric.
- Four association topologies are supported: single (1:1), aggregation VPC, back-to-back VPC, and bulk mixed.
author:
- Cisco Systems
options:
  fabric_name:
    description:
    - The name of the fabric containing the switches.
    type: str
    required: true
  config:
    description:
    - The list of access or ToR switch associations to configure.
    - Required when O(state=merged) or O(state=deleted).
    type: list
    elements: dict
    suboptions:
      access_or_tor_switch_id:
        description:
        - The serial number of the access or ToR switch.
        type: str
        required: true
      aggregation_or_leaf_switch_id:
        description:
        - The serial number of the aggregation or leaf switch.
        type: str
        required: true
      access_or_tor_peer_switch_id:
        description:
        - The serial number of the access or ToR VPC peer switch.
        - Required for back-to-back VPC topologies.
        type: str
      aggregation_or_leaf_peer_switch_id:
        description:
        - The serial number of the aggregation or leaf VPC peer switch.
        - Required for aggregation VPC and back-to-back VPC topologies.
        type: str
      access_or_tor_port_channel_id:
        description:
        - The port channel number on the access or ToR switch.
        - Value must be between 1 and 4096.
        - Required when O(state=merged).
        type: int
      aggregation_or_leaf_port_channel_id:
        description:
        - The port channel number on the aggregation or leaf switch.
        - Value must be between 1 and 4096.
        - Required when O(state=merged).
        type: int
      access_or_tor_peer_port_channel_id:
        description:
        - The port channel number on the access or ToR VPC peer switch.
        - Value must be between 1 and 4096.
        type: int
      access_or_tor_vpc_id:
        description:
        - The VPC ID of the VPC pair of access or ToR switches.
        - Value must be between 1 and 4096.
        type: int
      aggregation_or_leaf_peer_port_channel_id:
        description:
        - The port channel number on the aggregation or leaf VPC peer switch.
        - Value must be between 1 and 4096.
        type: int
      aggregation_or_leaf_vpc_id:
        description:
        - The VPC ID of the VPC pair of aggregation or leaf switches.
        - Value must be between 1 and 4096.
        type: int
  state:
    description:
    - The desired state of the access or ToR switch associations on the Cisco Nexus Dashboard.
    - Use O(state=merged) to associate access or ToR switches with aggregation or leaf switches.
      Existing associations not specified in the configuration will be left unchanged.
    - Use O(state=deleted) to disassociate the access or ToR switches specified in the configuration.
    - Use O(state=gathered) to retrieve current access or ToR switch associations from the fabric without making changes.
    type: str
    default: merged
    choices: [ merged, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- The associate and disassociate API operations are bulk operations that return per-item status.
"""

EXAMPLES = r"""
- name: Associate a ToR switch with a leaf switch
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch_id: "98AFDSD8V0"
        aggregation_or_leaf_switch_id: "98AM4FFFFV0"
        access_or_tor_port_channel_id: 501
        aggregation_or_leaf_port_channel_id: 502
    state: merged

- name: Associate a ToR VPC pair with a leaf VPC pair (back-to-back VPC)
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch_id: "98AFDSD8V0"
        aggregation_or_leaf_switch_id: "98AM4FFFFV0"
        access_or_tor_peer_switch_id: "98AWSETG8V0"
        aggregation_or_leaf_peer_switch_id: "98AMDDDD8V0"
        access_or_tor_port_channel_id: 501
        aggregation_or_leaf_port_channel_id: 502
        access_or_tor_peer_port_channel_id: 503
        aggregation_or_leaf_peer_port_channel_id: 504
        access_or_tor_vpc_id: 1
        aggregation_or_leaf_vpc_id: 2
    state: merged

- name: Disassociate a ToR switch
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    config:
      - access_or_tor_switch_id: "98AFDSD8V0"
        aggregation_or_leaf_switch_id: "98AM4FFFFV0"
    state: deleted

- name: Gather all ToR associations for a fabric
  cisco.nd.nd_manage_tor:
    fabric_name: my-fabric
    state: gathered
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_tor.manage_tor import ManageTorModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_tor import ManageTorOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(ManageTorModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "merged", ["config"]],
            ["state", "deleted", ["config"]],
        ],
    )
    require_pydantic(module)

    state = module.params["state"]
    fabric_name = module.params["fabric_name"]

    # Inject fabric_name into each config item for model construction
    config = module.params.get("config") or []
    for item in config:
        item["fabric_name"] = fabric_name

    try:
        if state == "gathered":
            # Handle gathered state: query and return without changes
            nd_module = NDModule(module)
            orchestrator = ManageTorOrchestrator(sender=nd_module)
            response_data = orchestrator.query_all()
            gathered = NDConfigCollection.from_api_response(
                response_data=response_data,
                model_class=ManageTorModel,
            )
            output = NDOutput(output_level=module.params.get("output_level", "normal"))
            output.assign(before=gathered, after=gathered)
            module.exit_json(**output.format())
        else:
            # Handle merged/deleted states via the state machine
            nd_state_machine = NDStateMachine(
                module=module,
                model_orchestrator=ManageTorOrchestrator,
            )
            nd_state_machine.manage_state()
            module.exit_json(**nd_state_machine.output.format())

    except Exception as e:
        module.fail_json(msg="Module execution failed: {0}".format(str(e)))


if __name__ == "__main__":
    main()
