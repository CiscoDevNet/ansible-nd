#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing port-channel (trunkPoHost) interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_port_channel_trunk_host
version_added: "2.0.0"
short_description: Manage port-channel (trunkPoHost) interfaces on Cisco Nexus Dashboard
description:
- Manage port-channel (trunkPoHost) interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, and deleting (trunkPoHost) port-channel configurations on switches within a fabric.
- Each config item represents one port-channel interface. Member ethernet interfaces are listed in
  O(config[].config_data.network_os.policy.ports) and inherit trunk-mode configuration from the port-channel policy.
- Member interface field mutability is restricted while members of a port-channel; only description, admin_state, and
  extra_config can be modified on members via the C(nd_interface_ethernet_trunk_host) module.
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
    - The list of port-channel (trunkPoHost) interfaces to configure.
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
      config_data:
        description:
        - The configuration data for the port-channel, following the ND API structure.
        type: dict
        suboptions:
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
              policy:
                description:
                - The policy configuration for the (trunkPoHost) port-channel.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the port-channel.
                    type: bool
                  allowed_vlans:
                    description:
                    - Trunk allowed VLANs.
                    - Accepts V(none), V(all), or a comma-separated list of VLAN ids/ranges (e.g. V(100-200,300)).
                    - VLAN ids must be in the range 1-4094.
                    type: str
                  bandwidth:
                    description:
                    - Interface bandwidth in kilobits per second.
                    - Valid range is 1-100000000.
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
                  inherit_bandwidth:
                    description:
                    - Inherited interface bandwidth in kilobits per second.
                    - Valid range is 1-100000000.
                    type: int
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
                  link_type:
                    description:
                    - Spanning-tree link type for the port-channel.
                    type: str
                    choices: [ auto, pointToPoint, shared ]
                  monitor:
                    description:
                    - Whether the port-channel is configured as a SPAN/ERSPAN monitor source.
                    type: bool
                  mtu:
                    description:
                    - The MTU setting for the port-channel.
                    type: str
                    choices: [ default, jumbo ]
                  native_vlan:
                    description:
                    - Trunk native VLAN id.
                    - Valid range is 1-4094.
                    type: int
                  negotiate_auto:
                    description:
                    - Whether link auto-negotiation is enabled.
                    type: bool
                  netflow:
                    description:
                    - Whether netflow is enabled on the port-channel.
                    type: bool
                  netflow_monitor:
                    description:
                    - The netflow Layer-2 monitor name for the port-channel.
                    - Required when O(config[].config_data.network_os.policy.netflow=true).
                    type: str
                  netflow_sampler:
                    description:
                    - The netflow Layer-2 sampler name for the port-channel.
                    type: str
                  orphan_port:
                    description:
                    - Configure the port-channel as a vPC orphan port.
                    - When V(true), the port is suspended by the secondary peer on vPC failure.
                    type: bool
                  pfc:
                    description:
                    - Whether Priority Flow Control is enabled on the port-channel.
                    type: bool
                  port_channel_mode:
                    description:
                    - The port-channel mode.
                    type: str
                    choices: [ 'on', active, passive ]
                  port_type_edge_trunk:
                    description:
                    - Configure the port-channel as an edge trunk port (PortFast on trunk).
                    type: bool
                  ports:
                    description:
                    - The list of member ethernet interface names for this port-channel.
                    - Each name should be in the format C(Ethernet1/1), C(Ethernet1/2), etc.
                    - The port-channel policy is the single source of truth for member configuration; member
                      interfaces inherit trunk-mode settings from this policy.
                    type: list
                    elements: str
                  ptp:
                    description:
                    - Whether Precision Time Protocol is enabled on the port-channel.
                    type: bool
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
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_broadcast_level_pps).
                    type: float
                  storm_control_broadcast_level_pps:
                    description:
                    - Broadcast storm control level in packets per second (0-200000000).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_broadcast_level).
                    type: int
                  storm_control_multicast_level:
                    description:
                    - Multicast storm control level in percentage (0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_multicast_level_pps).
                    type: float
                  storm_control_multicast_level_pps:
                    description:
                    - Multicast storm control level in packets per second (0-200000000).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_multicast_level).
                    type: int
                  storm_control_unicast_level:
                    description:
                    - Unicast storm control level in percentage (0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_unicast_level_pps).
                    type: float
                  storm_control_unicast_level_pps:
                    description:
                    - Unicast storm control level in packets per second (0-200000000).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_unicast_level).
                    type: int
                  vlan_mapping:
                    description:
                    - Whether VLAN mapping is enabled on the trunk.
                    - Use with O(config[].config_data.network_os.policy.vlan_mapping_entries) to translate customer VLAN ids to provider VLAN ids.
                    - Note that virtual switches (e.g. N9K-C9300v) may reject VLAN mapping with selective dot1q-tunnel.
                    type: bool
                  vlan_mapping_entries:
                    description:
                    - VLAN mapping entries. Used when O(config[].config_data.network_os.policy.vlan_mapping=true).
                    type: list
                    elements: dict
                    suboptions:
                      customer_inner_vlan_id:
                        description:
                        - Inner customer VLAN id (selective dot1q-tunnel only).
                        - Valid range is 1-4094.
                        type: int
                      customer_vlan_id:
                        description:
                        - Customer VLAN id list (single id or range strings, e.g. V(["100", "200-300"])).
                        - VLAN ids must be in the range 1-4094.
                        type: list
                        elements: str
                      dot1q_tunnel:
                        description:
                        - Use selective dot1q-tunnel mode for this entry.
                        type: bool
                      provider_vlan_id:
                        description:
                        - Provider VLAN id.
                        - Valid range is 1-4094.
                        type: int
  config_actions:
    description:
    - Controls deploy behavior after interface mutations are complete.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy port-channel changes after mutations are complete.
        - When V(true), all queued port-channel changes are deployed in a single bulk API call at the end of module
          execution via the C(interfaceActions/deploy) API. Only the port-channels modified by this task are deployed.
        - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
        - Setting O(config_actions.deploy=false) is useful when batching changes across multiple interface tasks before a single deploy.
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
- This module manages NX-OS port-channel trunkPoHost interfaces only (interface_type C(portChannel), mode C(trunk),
  network_os_type C(nx-os), policy_type C(trunkPoHost)). These values are hardcoded by the module and are not user-configurable.
- The port-channel policy is the source of truth for member interface configuration.
"""

EXAMPLES = r"""
- name: Create a trunkPoHost port-channel with two members
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              allowed_vlans: "100-200"
              native_vlan: 99
              ports:
                - Ethernet1/1
                - Ethernet1/2
              port_channel_mode: active
              lacp_rate: fast
              description: Server trunk bundle
    state: merged
  register: result

- name: Add a third member and update allowed VLANs
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              allowed_vlans: "100-200,300"
              ports:
                - Ethernet1/1
                - Ethernet1/2
                - Ethernet1/3
    state: merged

- name: Configure VLAN mapping with selective dot1q-tunnel
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              vlan_mapping: true
              vlan_mapping_entries:
                - customer_vlan_id: ["100"]
                  provider_vlan_id: 200
                  dot1q_tunnel: true
    state: merged

- name: Replace a port-channel configuration
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              allowed_vlans: "all"
              ports:
                - Ethernet1/1
              port_channel_mode: active
              description: Replaced port-channel configuration
    state: replaced

- name: Override all port-channels in the fabric to match this configuration
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              allowed_vlans: "100-200"
              ports:
                - Ethernet1/1
                - Ethernet1/2
              port_channel_mode: active
    state: overridden

- name: Delete a port-channel
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
    state: deleted

- name: Stage port-channel changes without deploying
  cisco.nd.nd_interface_port_channel_trunk_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              allowed_vlans: "all"
              ports:
                - Ethernet1/1
    config_actions:
      deploy: false
    state: merged
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, the fabric configuration.
  returned: always
  type: bool
  sample: true
output_level:
  description: The output verbosity level in effect for the run, echoing the O(output_level) parameter.
  returned: always
  type: str
  sample: normal
before:
  description:
  - The existing configuration of the targeted interfaces before the module ran, structured the same as the O(config) parameter.
  - An empty list when no matching interface configuration existed.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: port-channel501
    config_data:
      network_os:
        policy:
          admin_state: true
          allowed_vlans: "100-200"
          native_vlan: 99
          ports:
          - Ethernet1/1
          - Ethernet1/2
          port_channel_mode: active
after:
  description:
  - The configuration of the targeted interfaces after the module ran, structured the same as the O(config) parameter.
  - In check mode, the configuration that would result had the module run outside of check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: port-channel501
    config_data:
      network_os:
        policy:
          admin_state: true
          allowed_vlans: "100-300"
          native_vlan: 99
          ports:
          - Ethernet1/1
          - Ethernet1/2
          port_channel_mode: active
diff:
  description: The per-interface difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: port-channel501
    config_data:
      network_os:
        policy:
          allowed_vlans: "100-300"
proposed:
  description: The configuration the module proposed to apply, before reconciliation with the controller.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: port-channel501
    config_data:
      network_os:
        policy:
          allowed_vlans: "100-300"
logs:
  description: Internal diagnostic log messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample:
  - "Querying existing port-channel interface configuration"
msg:
  description: A human-readable error message, present only when the module fails.
  returned: on failure
  type: str
  sample: "Configuration error: ..."
"""

# pylint: disable=wrong-import-position
import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_trunk_host_interface import (
    PortChannelTrunkHostInterfaceOrchestrator,
)


def main():
    """
    # Summary

    Entry point for the `nd_interface_port_channel_trunk_host` Ansible module. Initializes the
    `NDStateMachine` with `PortChannelTrunkHostInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(PortChannelTrunkHostInterfaceModel.get_argument_spec())
    argument_spec.update(
        config_actions={
            "type": "dict",
            "options": {
                "deploy": {"type": "bool", "default": True},
            },
        },
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_port_channel_trunk_host")

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=PortChannelTrunkHostInterfaceOrchestrator,
        )
        if not isinstance(nd_state_machine.model_orchestrator, NDBaseInterfaceOrchestrator):
            raise AssertionError(f"Expected NDBaseInterfaceOrchestrator, got {type(nd_state_machine.model_orchestrator)}")
        config_actions = module.params.get("config_actions") or {}
        deploy = config_actions.get("deploy", True)
        nd_state_machine.model_orchestrator.deploy = deploy

        module_log.debug(
            "manage_state begin state=%s check_mode=%s deploy=%s",
            module.params.get("state"),
            module.check_mode,
            deploy,
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

    except Exception as e:  # pylint: disable=broad-except
        module_log.exception("Unhandled exception during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
