#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_port_channel_access
version_added: "1.4.0"
short_description: Manage port-channel accessPoHost interfaces on Cisco Nexus Dashboard
description:
- Manage port-channel accessPoHost interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, querying, and deleting accessPoHost port-channel configurations on switches within a fabric.
- Each config item represents one port-channel interface. Member ethernet interfaces are listed in
  O(config[].config_data.network_os.policy.ports) and inherit access-mode configuration from the port-channel policy.
- Member interface field mutability is restricted while members of a port-channel; only description, admin_state, and
  extra_config can be modified on members via the C(nd_interface_ethernet_access) module.
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
    - The list of port-channel accessPoHost interfaces to configure.
    - Each item specifies the target switch, the port-channel interface name, and its configuration.
    - Multiple switches can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage the port-channel.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_name:
        description:
        - The port-channel interface name (e.g. C(port-channel501)).
        type: str
        required: true
      interface_type:
        description:
        - The type of the interface.
        - Defaults to C(portChannel) for this module.
        type: str
        default: portChannel
      config_data:
        description:
        - The configuration data for the port-channel, following the ND API structure.
        type: dict
        suboptions:
          mode:
            description:
            - The interface operational mode.
            - Defaults to C(access) for this module. The ND API uses this as a discriminator
              to select the access-mode port-channel configuration schema.
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
                - The policy configuration for the accessPoHost port-channel.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the port-channel.
                    type: bool
                  access_vlan:
                    description:
                    - The access VLAN for the port-channel.
                    - Valid range is 1-4094.
                    type: int
                  bpdu_filter:
                    description:
                    - BPDU filter setting for the port-channel.
                    type: str
                    choices: [ enable, disable, default ]
                  bpdu_guard:
                    description:
                    - BPDU guard setting for the port-channel.
                    type: str
                    choices: [ enable, disable, default ]
                  cdp:
                    description:
                    - Whether Cisco Discovery Protocol is enabled on the port-channel.
                    type: bool
                  copy_description:
                    description:
                    - Whether to propagate the port-channel description to all member interfaces.
                    type: bool
                  description:
                    description:
                    - The description of the port-channel.
                    - Maximum 254 characters.
                    type: str
                  duplex_mode:
                    description:
                    - The duplex mode of the port-channel.
                    type: str
                    choices: [ auto, full, half ]
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the port-channel.
                    type: str
                  lacp_port_priority:
                    description:
                    - LACP port priority.
                    - Valid range is 1-65535. Default 32768.
                    type: int
                  lacp_rate:
                    description:
                    - LACP rate (PDU transmit interval).
                    - V(normal) = 30 seconds, V(fast) = 1 second.
                    type: str
                    choices: [ normal, fast ]
                  lacp_suspend:
                    description:
                    - Whether to suspend the port if LACP PDUs are not received.
                    type: bool
                  monitor:
                    description:
                    - Whether the port-channel is configured as a SPAN/ERSPAN monitor source.
                    type: bool
                  mtu:
                    description:
                    - The MTU setting for the port-channel.
                    type: str
                    choices: [ default, jumbo ]
                  netflow:
                    description:
                    - Whether netflow is enabled on the port-channel.
                    type: bool
                  netflow_monitor:
                    description:
                    - The netflow Layer-2 monitor name for the port-channel.
                    type: str
                  netflow_sampler:
                    description:
                    - The netflow Layer-2 sampler name for the port-channel.
                    type: str
                  policy_type:
                    description:
                    - The policy template type for the port-channel.
                    - V(access_po_host) is the standard accessPoHost policy.
                    type: str
                    choices: [ access_po_host ]
                    default: access_po_host
                  port_channel_mode:
                    description:
                    - The port-channel mode.
                    type: str
                    choices: [ on, active, passive ]
                  ports:
                    description:
                    - The list of member ethernet interface names for this port-channel.
                    - Each name should be in the format C(Ethernet1/1), C(Ethernet1/2), etc.
                    - The port-channel policy is the single source of truth for member configuration; member
                      interfaces inherit access-mode settings from this policy.
                    type: list
                    elements: str
                  qos:
                    description:
                    - Whether a QoS policy is applied to the port-channel.
                    type: bool
                  qos_policy:
                    description:
                    - Custom QoS policy name associated with the port-channel.
                    type: str
                  queuing_policy:
                    description:
                    - Custom queuing policy name associated with the port-channel.
                    type: str
                  speed:
                    description:
                    - The speed setting for the port-channel.
                    type: str
                    choices: [ auto, 10Mb, 100Mb, 1Gb, 2.5Gb, 5Gb, 10Gb, 25Gb, 40Gb, 50Gb, 100Gb, 200Gb, 400Gb, 800Gb ]
                  storm_control:
                    description:
                    - Whether traffic storm control is enabled on the port-channel.
                    type: bool
                  storm_control_action:
                    description:
                    - Storm control action on threshold violation.
                    type: str
                    choices: [ shutdown, trap, default ]
                  storm_control_broadcast_level:
                    description:
                    - Broadcast storm control level in percentage (0.00-100.00).
                    type: float
                  storm_control_broadcast_level_pps:
                    description:
                    - Broadcast storm control level in packets per second (0-200000000).
                    type: int
                  storm_control_multicast_level:
                    description:
                    - Multicast storm control level in percentage (0.00-100.00).
                    type: float
                  storm_control_multicast_level_pps:
                    description:
                    - Multicast storm control level in packets per second (0-200000000).
                    type: int
                  storm_control_unicast_level:
                    description:
                    - Unicast storm control level in percentage (0.00-100.00).
                    type: float
                  storm_control_unicast_level_pps:
                    description:
                    - Unicast storm control level in packets per second (0-200000000).
                    type: int
  deploy:
    description:
    - Whether to deploy port-channel changes after mutations are complete.
    - When V(true), all queued port-channel changes are deployed in a single bulk API call at the end of module
      execution via the C(interfaceActions/deploy) API. Only the port-channels modified by this task are deployed.
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
    - Use O(state=deleted) to remove the specified port-channels via the C(interfaceActions/remove) API.
      Member ethernet interfaces are reverted to their fabric default configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module manages NX-OS port-channel accessPoHost interfaces only.
- The port-channel policy is the source of truth for member interface configuration.
"""

EXAMPLES = r"""
- name: Create an accessPoHost port-channel with two members
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 100
              ports:
                - Ethernet1/1
                - Ethernet1/2
              port_channel_mode: active
              lacp_rate: fast
              description: Server bundle
    state: merged
  register: result

- name: Add a third member to an existing port-channel
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              ports:
                - Ethernet1/1
                - Ethernet1/2
                - Ethernet1/3
    state: merged

- name: Delete a port-channel
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
    state: deleted

- name: Stage port-channel changes without deploying
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 100
              ports:
                - Ethernet1/1
    deploy: false
    state: merged

"""

RETURN = r"""
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_access_interface import (
    PortChannelAccessInterfaceOrchestrator,
)


def main():
    """
    # Summary

    Entry point for the `nd_interface_port_channel_access` Ansible module. Initializes the
    `NDStateMachine` with `PortChannelAccessInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(PortChannelAccessInterfaceModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_port_channel_access")

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=PortChannelAccessInterfaceOrchestrator,
        )
        if not isinstance(nd_state_machine.model_orchestrator, NDBaseInterfaceOrchestrator):
            raise AssertionError(f"Expected NDBaseInterfaceOrchestrator, got {type(nd_state_machine.model_orchestrator)}")
        nd_state_machine.model_orchestrator.deploy = module.params["deploy"]

        module_log.debug(
            "manage_state begin state=%s check_mode=%s deploy=%s",
            module.params.get("state"),
            module.check_mode,
            module.params["deploy"],
        )
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")

        if not module.check_mode:
            nd_state_machine.model_orchestrator.remove_pending()
            nd_state_machine.model_orchestrator.deploy_pending()

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        module_log.exception("NDStateMachineError during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module execution failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
