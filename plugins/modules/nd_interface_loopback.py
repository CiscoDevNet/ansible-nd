#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_loopback
version_added: "1.4.0"
short_description: Manage loopback interfaces on Cisco Nexus Dashboard
description:
- Manage loopback interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, querying, and deleting loopback interfaces on switches within a fabric.
author:
- Allen Robel (@allenrobel)
options:
  fabric_name:
    description:
    - The name of the fabric containing the target switches.
    type: str
    required: true
  config:
    description:
    - The list of loopback interfaces to configure.
    - Each item specifies the target switch and interface configuration.
    - Multiple switches can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage this loopback interface.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_name:
        description:
        - The name of the loopback interface (e.g., C(loopback0), C(Loopback10)).
        type: str
        required: true
      interface_type:
        description:
        - The type of the interface.
        - Defaults to C(loopback) for this module.
        type: str
        default: loopback
      config_data:
        description:
        - The configuration data for the interface, following the ND API structure.
        type: dict
        suboptions:
          mode:
            description:
            - The interface management mode.
            type: str
            default: managed
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
              network_os_type:
                description:
                - The network OS type of the switch.
                type: str
                default: nx-os
              policy:
                description:
                - The policy configuration for the loopback interface.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the loopback interface.
                    - It defaults to C(true) when unset during creation.
                    type: bool
                  ip:
                    description:
                    - The IPv4 address of the loopback interface.
                    type: str
                  ipv6:
                    description:
                    - The IPv6 address of the loopback interface.
                    type: str
                  vrf:
                    description:
                    - The VRF to which the loopback interface belongs.
                    - Maximum 32 characters.
                    type: str
                  route_map_tag:
                    description:
                    - The route-map tag associated with the interface IP address.
                    type: str
                  description:
                    description:
                    - The description of the loopback interface.
                    - Maximum 254 characters.
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    type: str
                  policy_type:
                    description:
                    - The policy template type for the loopback interface.
                    - V(loopback) is the standard loopback policy.
                    - V(ipfm_loopback) is the IP Fabric for Media loopback policy.
                    - V(user_defined) allows a custom user-defined policy.
                    type: str
                    choices: [ loopback, ipfm_loopback, user_defined ]
                    default: loopback
  deploy:
    description:
    - Whether to deploy interface changes after mutations are complete.
    - When V(true), all queued interface changes are deployed in a single bulk API call at the end of module execution
      via the C(interfaceActions/deploy) API. Only the interfaces modified by this task are deployed.
    - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
    - Setting O(deploy=false) is useful when batching changes across multiple interface tasks before a single deploy.
    type: bool
    default: true
  state:
    description:
    - The desired state of the network resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new resources and update existing ones as defined in your configuration.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the resources specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The resources on ND will be modified to exactly match the configuration.
      Any resource existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the resources specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module currently supports NX-OS loopback interfaces only.
"""

EXAMPLES = r"""
- name: Create a loopback interface on a single switch
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.1
              admin_state: true
              description: Management loopback
              route_map_tag: 12345
              vrf: default
    state: merged
  register: result

- name: Create loopback interfaces across multiple switches
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.1
              description: Router ID loopback
      - switch_ip: 192.168.1.1
        interface_name: loopback1
        config_data:
          network_os:
            policy:
              ip: 10.2.1.1
              description: VTEP loopback
              route_map_tag: "12345"
      - switch_ip: 192.168.1.2
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.2
              description: Router ID loopback on switch 2
    state: merged

- name: Replace a loopback interface
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.2
              description: Updated loopback description
    state: replaced

- name: Delete a loopback interface
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
    state: deleted

- name: Create loopback interfaces without deploying (for batching)
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.1
    deploy: false
    state: merged

"""

RETURN = r"""
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_interface_loopback` Ansible module. Initializes the `NDStateMachine` with
    `LoopbackInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(LoopbackInterfaceModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=LoopbackInterfaceOrchestrator,
        )
        nd_state_machine.model_orchestrator.deploy = module.params["deploy"]

        # Manage state
        nd_state_machine.manage_state()

        # Execute all queued bulk operations
        if not module.check_mode:
            nd_state_machine.model_orchestrator.remove_pending()
            nd_state_machine.model_orchestrator.deploy_pending()

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module execution failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
