#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing port-channel accessPoHost interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_port_channel_access
version_added: "2.0.0"
short_description: Manage port-channel (accessPoHost, iosXeAccessPoHost) interfaces on Cisco Nexus Dashboard
description:
- Manage port-channel (accessPoHost, iosXeAccessPoHost) interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, and deleting (accessPoHost, iosXeAccessPoHost) port-channel configurations on switches within a fabric.
- Each config item represents one port-channel interface. Member ethernet interfaces are listed in
  O(config[].config_data.network_os.policy.ports) and inherit access-mode configuration from the port-channel policy.
- Member interface field mutability is restricted while members of a port-channel; only description, admin_state, and
  extra_config can be modified on members via the C(nd_interface_ethernet_access) module.
- A port-channel that lists a member ethernet already belonging to a different port-channel is rejected before any
  change is made (also in check mode); remove the member from its current port-channel first.
- Supports NX-OS (C(accessPoHost)) and IOS-XE (C(iosXeAccessPoHost)) port-channels; select the platform with
  O(config[].config_data.network_os.network_os_type).
- On IOS-XE the members named in O(config[].config_data.network_os.policy.ports) must already be access-host interfaces
  (C(iosXeAccess)); convert them with M(cisco.nd.nd_interface_ethernet_access) first. The module fails before any change
  when they are not.
- On IOS-XE switches, O(state=deleted) and O(state=overridden) remove the port-channel from Nexus Dashboard and detach its
  members, but Nexus Dashboard does not remove the C(interface Port-channelN) object from the switch running configuration.
  Remove it on the switch if it must not remain.
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
    - The list of port-channel (accessPoHost) interfaces to configure.
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
              network_os_type:
                description:
                - The network OS (platform) type of the target switch. This is a discriminator that determines which
                  policy templates are applicable.
                - Use V(nx-os) for Nexus switches and V(ios-xe) for Catalyst IOS-XE switches.
                type: str
                default: nx-os
                choices: [ nx-os, ios-xe ]
              policy:
                description:
                - The policy configuration for the port-channel.
                - The policy fields present depend on O(config[].config_data.network_os.policy.policy_type).
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - The port-channel policy template to apply. This is a discriminator that determines which of the
                      remaining C(policy) suboptions are applicable.
                    - Optional. When omitted it is derived from O(config[].config_data.network_os.network_os_type),
                      V(accessPoHost) for C(nx-os) and V(iosXeAccessPoHost) for C(ios-xe).
                    type: str
                    choices: [ accessPoHost, iosXeAccessPoHost ]
                  admin_state:
                    description:
                    - The administrative state of the port-channel.
                    - Applies to all policy_type values.
                    type: bool
                  access_vlan:
                    description:
                    - The access VLAN for the port-channel.
                    - Valid range is 1-4094.
                    - Applies to all policy_type values.
                    type: int
                  bandwidth:
                    description:
                    - Interface bandwidth in kilobits per second.
                    - Valid range is 1-100000000.
                    - Applies when policy_type is C(accessPoHost).
                    type: int
                  bpdu_filter:
                    description:
                    - BPDU filter setting for the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                    choices: [ enable, disable, default ]
                  bpdu_guard:
                    description:
                    - BPDU guard setting for the port-channel.
                    - Applies to all policy_type values.
                    type: str
                    choices: [ enable, disable, default ]
                  cdp:
                    description:
                    - Whether Cisco Discovery Protocol is enabled on the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  copy_description:
                    description:
                    - Whether to propagate the port-channel description to all member interfaces.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  description:
                    description:
                    - The description of the port-channel.
                    - Maximum length is 254 characters for C(accessPoHost), 200 for C(iosXeAccessPoHost).
                    - Applies to all policy_type values.
                    type: str
                  duplex_mode:
                    description:
                    - The duplex mode of the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                    choices: [ auto, full, half ]
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the port-channel.
                    - Applies to all policy_type values.
                    type: str
                  inherit_bandwidth:
                    description:
                    - Inherited interface bandwidth in kilobits per second.
                    - Valid range is 1-100000000.
                    - Applies when policy_type is C(accessPoHost).
                    type: int
                  lacp_port_priority:
                    description:
                    - LACP port priority.
                    - Valid range is 1-65535. Default 32768.
                    - Applies when policy_type is C(accessPoHost).
                    type: int
                  lacp_rate:
                    description:
                    - LACP rate (PDU transmit interval).
                    - V(normal) = 30 seconds, V(fast) = 1 second.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                    choices: [ normal, fast ]
                  lacp_suspend:
                    description:
                    - Whether to suspend the port if LACP PDUs are not received.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  link_type:
                    description:
                    - Spanning-tree link type for the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                    choices: [ auto, pointToPoint, shared ]
                  monitor:
                    description:
                    - Whether the port-channel is configured as a SPAN/ERSPAN monitor source.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  mtu:
                    description:
                    - The MTU setting for the port-channel.
                    - For C(accessPoHost), one of C(default) or C(jumbo). It defaults to C(jumbo) when unset during creation.
                    - For C(iosXeAccessPoHost), an integer in the range 1500-9198 (for example C(8000)).
                    - A value outside the selected policy_type's form is rejected by the module.
                    - Applies to all policy_type values.
                    type: str
                  negotiate_auto:
                    description:
                    - Whether link auto-negotiation is enabled.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  netflow:
                    description:
                    - Whether netflow is enabled on the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  netflow_monitor:
                    description:
                    - The netflow Layer-2 monitor name for the port-channel.
                    - Required when O(config[].config_data.network_os.policy.netflow=true).
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                  netflow_sampler:
                    description:
                    - The netflow Layer-2 sampler name for the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                  orphan_port:
                    description:
                    - Configure the port-channel as a vPC orphan port.
                    - When V(true), the port is suspended by the secondary peer on vPC failure.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  pfc:
                    description:
                    - Whether Priority Flow Control is enabled on the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  port_channel_mode:
                    description:
                    - The port-channel (channel-group) mode.
                    - For C(accessPoHost), one of C(on), C(active) or C(passive). It defaults to C(active) when unset during creation.
                    - For C(iosXeAccessPoHost), additionally C(auto) or C(desirable) (PAgP).
                    - A value outside the selected policy_type's subset is rejected by the module.
                    - Applies to all policy_type values.
                    type: str
                    choices: [ 'on', active, passive, auto, desirable ]
                  port_type_edge_trunk:
                    description:
                    - Configure the port-channel as an edge trunk port (PortFast on trunk).
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  ports:
                    description:
                    - The list of member ethernet interface names for this port-channel.
                    - Each name should be in the format C(Ethernet1/1), C(Ethernet1/2), etc.
                    - On IOS-XE, member names such as C(GigabitEthernet1/0/2); abbreviations such as C(gi1/0/2) are expanded.
                    - The port-channel policy is the single source of truth for member configuration; member
                      interfaces inherit access-mode settings from this policy.
                    - Applies to all policy_type values.
                    type: list
                    elements: str
                  qos:
                    description:
                    - Whether a QoS policy is applied to the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  qos_policy:
                    description:
                    - Custom QoS policy name associated with the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                  queuing_policy:
                    description:
                    - Custom queuing policy name associated with the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                  speed:
                    description:
                    - The speed setting for the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                    choices: [ auto, 10Mb, 100Mb, 1Gb, 2.5Gb, 5Gb, 10Gb, 25Gb, 40Gb, 50Gb, 100Gb, 200Gb, 400Gb, 800Gb ]
                  storm_control:
                    description:
                    - Whether traffic storm control is enabled on the port-channel.
                    - Applies when policy_type is C(accessPoHost).
                    type: bool
                  storm_control_action:
                    description:
                    - Storm control action on threshold violation.
                    - Applies when policy_type is C(accessPoHost).
                    type: str
                    choices: [ shutdown, trap, default ]
                  storm_control_broadcast_level:
                    description:
                    - Broadcast storm control level in percentage (0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_broadcast_level_pps).
                    - Applies when policy_type is C(accessPoHost).
                    type: float
                  storm_control_broadcast_level_pps:
                    description:
                    - Broadcast storm control level in packets per second (0-200000000).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_broadcast_level).
                    - Applies when policy_type is C(accessPoHost).
                    type: int
                  storm_control_multicast_level:
                    description:
                    - Multicast storm control level in percentage (0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_multicast_level_pps).
                    - Applies when policy_type is C(accessPoHost).
                    type: float
                  storm_control_multicast_level_pps:
                    description:
                    - Multicast storm control level in packets per second (0-200000000).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_multicast_level).
                    - Applies when policy_type is C(accessPoHost).
                    type: int
                  storm_control_unicast_level:
                    description:
                    - Unicast storm control level in percentage (0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_unicast_level_pps).
                    - Applies when policy_type is C(accessPoHost).
                    type: float
                  storm_control_unicast_level_pps:
                    description:
                    - Unicast storm control level in packets per second (0-200000000).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_unicast_level).
                    - Applies when policy_type is C(accessPoHost).
                    type: int
  config_actions:
    description:
    - Controls deploy behavior after port-channel mutations are complete.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy port-channel changes after mutations are complete.
        - When V(true), all queued port-channel changes are deployed in a single bulk API call at the end of module
          execution via the C(interfaceActions/deploy) API. Only the port-channels modified by this task are deployed.
        - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
        - When V(true) and the module fails after the controller has already accepted a subset of the requested changes, that
          accepted subset is still deployed and is named in the failure message, so a failed task does not leave accepted
          changes staged but undeployed.
        - Setting O(config_actions.deploy=false) is useful when batching changes across multiple interface tasks before a single deploy.
        - Deployment is opt-in. Set O(config_actions.deploy=true) explicitly to push changes to switches.
        type: bool
        default: false
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
- This module supports both NX-OS and IOS-XE access-mode port-channel interfaces (interface_type C(portChannel), mode
  C(access)), selected via O(config[].config_data.network_os.network_os_type).
- This module manages the C(accessPoHost) (NX-OS) and C(iosXeAccessPoHost) (IOS-XE) policy templates. Port-channels
  carrying any other policy type are never read or modified by this module.
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
    config_actions:
      deploy: true
    state: merged
  register: result

- name: Create an IOS-XE access port-channel on a Catalyst leaf (members must already be iosXeAccess)
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: CAMPUS1
    config:
      - switch_ip: 192.168.12.181
        interface_name: port-channel101
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              admin_state: true
              access_vlan: 100
              port_channel_mode: active
              ports:
                - GigabitEthernet1/0/2
                - GigabitEthernet1/0/3
              description: "Catalyst access EtherChannel"
    config_actions:
      deploy: true
    state: merged

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
    config_actions:
      deploy: true
    state: merged

- name: Delete a port-channel
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
    config_actions:
      deploy: true
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
    config_actions:
      deploy: false
    state: merged

# state=replaced reconciles ONLY the port-channels listed in config so that each
# exactly matches the given policy. Port-channels not listed are left unchanged.
# Here port-channel501 is reduced to a single member on access_vlan 200; any
# previously configured members or settings not present below are removed from it.
- name: Replace a single port-channel so its config exactly matches
  cisco.nd.nd_interface_port_channel_access:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel501
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 200
              ports:
                - Ethernet1/1
              port_channel_mode: active
    config_actions:
      deploy: true
    state: replaced

# WARNING: state=overridden is FABRIC-WIDE. Every accessPoHost port-channel on
# ANY switch in my_fabric that is not listed in config below is DELETED (its
# member interfaces revert to their fabric default configuration), and the
# listed port-channels are reconciled to exactly match. Use with extra caution.
- name: Enforce config as the single source of truth for all accessPoHost port-channels in the fabric
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
    config_actions:
      deploy: true
    state: overridden
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
          access_vlan: 100
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
        network_os_type: nx-os
        policy:
          policy_type: accessPoHost
          admin_state: true
          access_vlan: 200
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
          access_vlan: 200
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
          access_vlan: 200
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_access_interface import (
    PortChannelAccessInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec, nd_argument_spec
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
    argument_spec.update(config_actions_spec(include=("deploy",)))

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
        deploy = nd_state_machine.model_orchestrator.apply_config_actions(module.params)

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

    except Exception as e:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, nd_state_machine, e)


if __name__ == "__main__":
    main()
