#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing vPC accessVpcHost interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_vpc_access
version_added: "2.0.0"
short_description: Manage vPC accessVpcHost interfaces on Cisco Nexus Dashboard
description:
- Manage vPC accessVpcHost interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, and deleting accessVpcHost vPC configurations on switches within a fabric.
- Each config item represents one vPC interface that spans the two switches in a vPC pair.
- The user supplies one peer's management IP as O(config[].switch_ip); the module reads the vPC pair record to
  auto-resolve the second peer's serial and injects it as C(peerSwitchId) in the payload.
- Per-peer policy fields use the API-native C(peer1_*) / C(peer2_*) naming, where C(peer1) corresponds to the
  switch supplied in O(config[].switch_ip) and C(peer2) corresponds to the auto-resolved peer.
- The switch supplied in O(config[].switch_ip) must already be in a vPC pair (created via M(cisco.nd.nd_manage_vpc_pair))
  before this module can manage interfaces on it.
author:
- Allen Robel (@allenrobel)
options:
  fabric_name:
    description:
    - The name of the fabric containing the target vPC pair.
    type: str
    required: true
  config:
    description:
    - The list of vPC accessVpcHost interfaces to configure.
    - Each item specifies the primary switch, the vPC interface name, and its configuration.
    - Multiple vPC pairs can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of one peer in the vPC pair (typically the primary).
        - This is resolved to the switch serial number (switchId) internally; the peer's serial is auto-resolved
          via the vPC pair record.
        type: str
        required: true
      interface_name:
        description:
        - The vPC interface name (e.g. C(vpc100)).
        type: str
        required: true
      config_data:
        description:
        - The configuration data for the vPC interface, following the ND API structure.
        type: dict
        suboptions:
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
              policy:
                description:
                - The policy configuration for the accessVpcHost vPC interface.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the vPC interface.
                    type: bool
                  bandwidth:
                    description:
                    - Configured bandwidth value for the interface.
                    - Valid range is 1-100000000.
                    type: int
                  bpdu_filter:
                    description:
                    - BPDU filter setting for the vPC interface.
                    type: str
                    choices: [ enable, disable, default ]
                  bpdu_guard:
                    description:
                    - BPDU guard setting for the vPC interface.
                    type: str
                    choices: [ enable, disable, default ]
                  cdp:
                    description:
                    - Whether Cisco Discovery Protocol is enabled on the vPC interface.
                    type: bool
                  copy_description:
                    description:
                    - Whether to propagate the per-peer port-channel description to all member interfaces.
                    type: bool
                  duplex_mode:
                    description:
                    - The duplex mode of the vPC interface.
                    type: str
                    choices: [ auto, full, half ]
                  inherit_bandwidth:
                    description:
                    - Bandwidth value inherited by sub-interfaces.
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
                    - If disabled, LACP puts the port in individual state instead of suspending when LACP BPDUs are
                      not received.
                    type: bool
                  lacp_vpc_convergence:
                    description:
                    - Enable LACP convergence for vPC port-channels.
                    type: bool
                  link_type:
                    description:
                    - Spanning-tree link type.
                    type: str
                    choices: [ auto, pointToPoint, shared ]
                  mirror_config:
                    description:
                    - Copy Peer-1 configuration to Peer-2.
                    type: bool
                  mtu:
                    description:
                    - Interface MTU.
                    type: str
                    choices: [ default, jumbo ]
                  negotiate_auto:
                    description:
                    - Enable link auto-negotiation.
                    type: bool
                  netflow:
                    description:
                    - Enable Netflow on the vPC interface.
                    type: bool
                  netflow_monitor:
                    description:
                    - Layer 2 Netflow monitor name.
                    type: str
                  netflow_sampler:
                    description:
                    - Netflow sampler name (N7K only).
                    type: str
                  access_vlan:
                    description:
                    - Access VLAN for the vPC. Applied identically on both peers.
                    - ND collapses the OpenAPI per-peer C(peer1AccessVlan)/C(peer2AccessVlan) into a single
                      C(accessVlan) value on the wire; this module splits the single value back to both per-peer
                      keys when writing.
                    - Valid range is 1-4094.
                    type: int
                  peer1_member_ports:
                    description:
                    - Member interface names on Peer-1 (e.g. C(Ethernet1/1)).
                    type: list
                    elements: str
                  peer1_port_channel_configuration:
                    description:
                    - Additional CLI configuration commands for Peer-1's port-channel.
                    type: str
                  peer1_port_channel_description:
                    description:
                    - Description for Peer-1's port-channel.
                    - Maximum 254 characters.
                    type: str
                  peer1_port_channel_id:
                    description:
                    - Peer-1 vPC port-channel number.
                    - Valid range is 1-4096.
                    type: int
                  peer2_member_ports:
                    description:
                    - Member interface names on Peer-2 (e.g. C(Ethernet1/1)).
                    type: list
                    elements: str
                  peer2_port_channel_configuration:
                    description:
                    - Additional CLI configuration commands for Peer-2's port-channel.
                    type: str
                  peer2_port_channel_description:
                    description:
                    - Description for Peer-2's port-channel.
                    - Maximum 254 characters.
                    type: str
                  peer2_port_channel_id:
                    description:
                    - Peer-2 vPC port-channel number.
                    - Valid range is 1-4096.
                    type: int
                  pfc:
                    description:
                    - Enable priority flow control.
                    type: bool
                  port_channel_mode:
                    description:
                    - Port-channel mode.
                    type: str
                    choices: [ 'on', active, passive ]
                  port_type_edge_trunk:
                    description:
                    - Enable spanning-tree edge port (PortFast) behavior.
                    type: bool
                  qos:
                    description:
                    - Enable QoS configuration for the vPC interface.
                    type: bool
                  qos_policy:
                    description:
                    - Custom QoS policy name.
                    type: str
                  queuing_policy:
                    description:
                    - Custom queuing policy name.
                    type: str
                  speed:
                    description:
                    - Interface speed.
                    type: str
                    choices: [ auto, 10Mb, 100Mb, 1Gb, 2.5Gb, 5Gb, 10Gb, 25Gb, 40Gb, 50Gb, 100Gb, 200Gb, 400Gb, 800Gb ]
                  storm_control:
                    description:
                    - Enable traffic storm control on the vPC interface.
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
  config_actions:
    description:
    - Controls deploy behavior after interface mutations are complete.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy vPC interface changes after mutations are complete.
        - When V(true), all queued vPC interface changes are deployed in a single bulk API call at the end of module
          execution via the C(interfaceActions/deploy) API. Only the vPC interfaces modified by this task are deployed.
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
    - Use O(state=deleted) to remove the specified vPC interfaces via the C(interfaceActions/remove) API.
      Member ethernet interfaces on both peers are reverted to their fabric default configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module manages NX-OS vPC accessVpcHost interfaces only (interface_type C(vpc), mode C(access), network_os_type C(nx-os), policy_type C(accessVpcHost)). These values are hardcoded by the module and are not user-configurable.
- The primary switch supplied in O(config[].switch_ip) must already be in a vPC pair (managed by M(cisco.nd.nd_manage_vpc_pair)). The peer serial is auto-resolved from the pair record.
- C(peer1) refers to the switch supplied in O(config[].switch_ip); C(peer2) refers to the auto-resolved peer.
"""

EXAMPLES = r"""
- name: Create an accessVpcHost vPC with one member on each peer
  cisco.nd.nd_interface_vpc_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vpc100
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 10
              peer1_port_channel_id: 100
              peer1_member_ports:
                - Ethernet1/1
              peer2_port_channel_id: 100
              peer2_member_ports:
                - Ethernet1/1
              port_channel_mode: active
              lacp_rate: fast
              peer1_port_channel_description: Server-A on peer1
              peer2_port_channel_description: Server-A on peer2
    state: merged
  register: result

- name: Update member ports on Peer-1 only
  cisco.nd.nd_interface_vpc_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vpc100
        config_data:
          network_os:
            policy:
              peer1_member_ports:
                - Ethernet1/1
                - Ethernet1/2
    state: merged

- name: Delete a vPC interface
  cisco.nd.nd_interface_vpc_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vpc100
    state: deleted

- name: Stage vPC interface changes without deploying
  cisco.nd.nd_interface_vpc_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: vpc100
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 10
              peer1_port_channel_id: 100
              peer2_port_channel_id: 100
    config_actions:
      deploy: false
    state: merged

"""

RETURN = r"""
"""

# pylint: disable=wrong-import-position
import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_access_interface import (
    AccessVpcHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_access_interface import (
    AccessVpcHostInterfaceOrchestrator,
)


def main():
    """
    # Summary

    Entry point for the `nd_interface_vpc_access` Ansible module. Initializes the
    `NDStateMachine` with `AccessVpcHostInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(AccessVpcHostInterfaceModel.get_argument_spec())
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
    module_log = logging.getLogger("nd.nd_interface_vpc_access")

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=AccessVpcHostInterfaceOrchestrator,
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


if __name__ == "__main__":
    main()
