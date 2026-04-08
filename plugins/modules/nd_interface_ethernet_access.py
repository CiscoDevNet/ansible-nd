#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_ethernet_access
version_added: "1.4.0"
short_description: Manage ethernet accessHost interfaces on Cisco Nexus Dashboard
description:
- Manage ethernet accessHost interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, querying, and deleting accessHost interface configurations on switches within a fabric.
- Multiple interfaces can share the same configuration via the O(config[].interface_names) list.
- Interfaces that are port-channel members have restricted mutability; only O(config[].config_data.network_os.policy.description),
  O(config[].config_data.network_os.policy.admin_state), and O(config[].config_data.network_os.policy.extra_config)
  can be modified on port-channel member interfaces.
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
    - The list of ethernet accessHost interface groups to configure.
    - Each item specifies the target switch, a list of interface names, and a shared configuration.
    - Multiple switches can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage the ethernet interfaces.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_names:
        description:
        - The list of ethernet interface names to configure with the same settings.
        - Each name should be in the format C(Ethernet1/1), C(Ethernet1/2), etc.
        type: list
        elements: str
        required: true
      interface_type:
        description:
        - The type of the interface.
        - Defaults to C(ethernet) for this module.
        type: str
        default: ethernet
      config_data:
        description:
        - The configuration data shared by all interfaces in O(config[].interface_names), following the ND API structure.
        type: dict
        suboptions:
          mode:
            description:
            - The interface operational mode.
            - Defaults to C(access) for this module. The ND API uses this as a discriminator
              to select the access interface configuration schema.
            type: str
            default: access
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
                - The policy configuration for the accessHost interface.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the interface.
                    - It defaults to C(true) when unset during creation.
                    type: bool
                  access_vlan:
                    description:
                    - The access VLAN for the interface.
                    - Valid range is 1-4094.
                    type: int
                  bpdu_guard:
                    description:
                    - BPDU guard setting for the interface.
                    type: str
                    choices: [ enable, disable, default ]
                  cdp:
                    description:
                    - Whether Cisco Discovery Protocol is enabled on the interface.
                    type: bool
                  description:
                    description:
                    - The description of the interface.
                    - Maximum 254 characters.
                    type: str
                  duplex_mode:
                    description:
                    - The duplex mode of the interface.
                    type: str
                    choices: [ auto, full, half ]
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    type: str
                  mtu:
                    description:
                    - The MTU setting for the interface.
                    type: str
                    choices: [ default, jumbo ]
                  netflow:
                    description:
                    - Whether netflow is enabled on the interface.
                    type: bool
                  netflow_monitor:
                    description:
                    - The netflow Layer-2 monitor name for the interface.
                    type: str
                  netflow_sampler:
                    description:
                    - The netflow Layer-2 sampler name for the interface.
                    - Only applicable for Nexus 7000 platforms.
                    type: str
                  orphan_port:
                    description:
                    - Whether VPC orphan port suspension is enabled.
                    type: bool
                  pfc:
                    description:
                    - Whether Priority Flow Control is enabled on the interface.
                    type: bool
                  policy_type:
                    description:
                    - The policy template type for the interface.
                    - V(access_host) is the standard accessHost policy.
                    type: str
                    choices: [ access_host ]
                    default: access_host
                  port_type_edge_trunk:
                    description:
                    - Whether spanning-tree edge port (PortFast) is enabled.
                    type: bool
                  qos:
                    description:
                    - Whether a QoS policy is applied to the interface.
                    type: bool
                  qos_policy:
                    description:
                    - Custom QoS policy name associated with the interface.
                    - The policy must be defined prior to associating it with the interface.
                    type: str
                  queuing_policy:
                    description:
                    - Custom queuing policy name associated with the interface.
                    - The policy must be defined prior to associating it with the interface.
                    type: str
                  speed:
                    description:
                    - The speed setting for the interface.
                    type: str
                    choices: [ auto, 10Mb, 100Mb, 1Gb, 2.5Gb, 5Gb, 10Gb, 25Gb, 40Gb, 50Gb, 100Gb, 200Gb, 400Gb, 800Gb ]
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
    - Use O(state=deleted) to reset the specified interfaces to their fabric default configuration via the
      C(interfaceActions/normalize) API. Physical ethernet interfaces cannot be truly deleted from a switch;
      this operation is the API equivalent of the NX-OS C(default interface) CLI command.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module manages NX-OS ethernet accessHost interfaces only.
- Interfaces that are port-channel members have restricted mutability.
"""

EXAMPLES = r"""
- name: Create three accessHost interfaces with the same configuration
  cisco.nd.nd_interface_ethernet_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_names:
          - Ethernet1/1
          - Ethernet1/2
          - Ethernet1/3
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 100
              bpdu_guard: enable
              cdp: true
              description: Access Host Interface
              speed: auto
    state: merged
  register: result

- name: Create accessHost interfaces across multiple switches
  cisco.nd.nd_interface_ethernet_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_names:
          - Ethernet1/1
          - Ethernet1/2
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 100
              description: Server ports switch 1
      - switch_ip: 192.168.1.2
        interface_names:
          - Ethernet1/1
          - Ethernet1/2
          - Ethernet1/3
          - Ethernet1/4
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 200
              description: Server ports switch 2
    state: merged

- name: Delete accessHost interface configurations
  cisco.nd.nd_interface_ethernet_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_names:
          - Ethernet1/1
          - Ethernet1/2
    state: deleted

- name: Create accessHost interfaces without deploying (for batching)
  cisco.nd.nd_interface_ethernet_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_names:
          - Ethernet1/1
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 100
    deploy: false
    state: merged

"""

RETURN = r"""
"""

import copy
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import EthernetAccessInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import EthernetAccessInterfaceOrchestrator


def expand_config(config_list):
    """
    # Summary

    Expand grouped config items (with `interface_names` list) into flat config items (with singular `interface_name`).
    Each group produces one flat item per interface name, all sharing the same `config_data` and `switch_ip`.

    ## Raises

    None
    """
    expanded = []
    for group in config_list:
        interface_names = group.get("interface_names", [])
        for name in interface_names:
            item = copy.deepcopy(group)
            item.pop("interface_names", None)
            item["interface_name"] = name
            expanded.append(item)
    return expanded


def main():
    """
    # Summary

    Entry point for the `nd_interface_ethernet_access` Ansible module. Expands grouped config items,
    initializes the `NDStateMachine` with `EthernetAccessInterfaceOrchestrator`, and executes the
    requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(EthernetAccessInterfaceModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    # Expand grouped config (interface_names list) into flat config items (interface_name singular)
    module.params["config"] = expand_config(module.params["config"])

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=EthernetAccessInterfaceOrchestrator,
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
