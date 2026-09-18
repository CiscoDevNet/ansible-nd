#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing routed (L3) port-channel interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_port_channel_routed
version_added: "2.0.0"
short_description: Manage routed port-channel (l3Po, iosXeL3PortChannel) interfaces on Cisco Nexus Dashboard
description:
- Manage routed (Layer 3) port-channel (l3Po, iosXeL3PortChannel) interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, and deleting (l3Po, iosXeL3PortChannel) port-channel configurations on switches within a fabric.
- Each config item represents one port-channel interface. Member ethernet interfaces are listed in
  O(config[].config_data.network_os.policy.ports) and are owned by the port-channel while they are members.
- A routed port-channel can be the parent of subinterfaces managed with M(cisco.nd.nd_interface_subinterface_managed) and
  M(cisco.nd.nd_interface_subinterface_unmanaged).
- A port-channel that lists a member ethernet already belonging to a different port-channel is rejected before any
  change is made (also in check mode); remove the member from its current port-channel first.
- Supports NX-OS (C(l3Po)) and IOS-XE (C(iosXeL3PortChannel)) port-channels; select the platform with
  O(config[].config_data.network_os.network_os_type).
- On IOS-XE the members named in O(config[].config_data.network_os.policy.ports) must already be routed-host interfaces
  (C(iosXeRoutedHost)); convert them with M(cisco.nd.nd_interface_ethernet_routed) first. The module fails before any change
  when they are not.
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
    - The list of routed port-channel interfaces to configure.
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
        - The port-channel interface name (e.g. C(port-channel20)).
        - A bare port-channel ID is also accepted and expanded, so V(501) means C(port-channel501).
        - The port-channel ID must be in the range 1-4096.
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
                - The module fails before any change when the value does not match the platform of the target switch.
                type: str
                required: true
                choices: [ nx-os, ios-xe ]
              policy:
                description:
                - The policy configuration for the port-channel.
                - The policy fields present depend on O(config[].config_data.network_os.policy.policy_type).
                - Where a suboption names an ND default, that is the value Nexus Dashboard applies when the suboption is omitted.
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - The port-channel policy template to apply. This is a discriminator that determines which of the
                      remaining C(policy) suboptions are applicable.
                    - Optional. When omitted it is derived from O(config[].config_data.network_os.network_os_type),
                      V(l3Po) for C(nx-os) and V(iosXeL3PortChannel) for C(ios-xe).
                    type: str
                    choices: [ l3Po, iosXeL3PortChannel ]
                  admin_state:
                    description:
                    - The administrative state of the port-channel.
                    - The ND default is V(true).
                    - Applies to all policy_type values.
                    type: bool
                  copy_description:
                    description:
                    - Whether to copy the port-channel description to all member interfaces.
                    - The ND default is V(false).
                    - Applies when policy_type is C(l3Po).
                    type: bool
                  description:
                    description:
                    - The description of the port-channel.
                    - The maximum length is 254 characters for C(l3Po) and 200 characters for C(iosXeL3PortChannel).
                    - Applies to all policy_type values.
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the port-channel.
                    - Applies to all policy_type values.
                    type: str
                  ip:
                    description:
                    - The IPv4 address of the port-channel (e.g. C(10.1.1.1)). Required together with
                      O(config[].config_data.network_os.policy.prefix).
                    - CIDR input such as C(10.1.1.1/30) is accepted. Its mask length fills
                      O(config[].config_data.network_os.policy.prefix) when that option is omitted and must agree with it when it is set.
                    - Applies to all policy_type values.
                    type: str
                  ip_redirects:
                    description:
                    - Whether to disable IPv4 and IPv6 redirects on the port-channel.
                    - The ND default is V(false).
                    - Applies when policy_type is C(l3Po).
                    type: bool
                  ipv6:
                    description:
                    - The IPv6 address of the port-channel. Required together with
                      O(config[].config_data.network_os.policy.ipv6_prefix).
                    - CIDR input such as C(2001:db8::1/64) is accepted. Its prefix length fills
                      O(config[].config_data.network_os.policy.ipv6_prefix) when that option is omitted and must agree with it when it is set.
                    - Applies when policy_type is C(l3Po).
                    type: str
                  ipv6_prefix:
                    description:
                    - The prefix length used with O(config[].config_data.network_os.policy.ipv6).
                    - Valid range is 1-127.
                    - Applies when policy_type is C(l3Po).
                    type: int
                  mtu:
                    description:
                    - The MTU of the port-channel.
                    - Valid range is 576-9216 for C(l3Po), where the ND default is V(9216), and 1500-9216 for C(iosXeL3PortChannel).
                    - Applies to all policy_type values.
                    type: int
                  netflow:
                    description:
                    - Whether to enable Netflow on the port-channel. Netflow must be enabled on the fabric.
                    - The ND default is V(false).
                    - Applies when policy_type is C(l3Po).
                    type: bool
                  netflow_monitor:
                    description:
                    - The Netflow monitor name.
                    - Applies when policy_type is C(l3Po).
                    type: str
                  netflow_sampler:
                    description:
                    - The Netflow sampler name. Applicable to Nexus 7000 switches only.
                    - Applies when policy_type is C(l3Po).
                    type: str
                  pfc:
                    description:
                    - Whether to enable priority flow control on the port-channel.
                    - The ND default is V(false).
                    - Applies when policy_type is C(l3Po).
                    type: bool
                  pim_dr_priority:
                    description:
                    - The priority for PIM designated-router election on the port-channel.
                    - Valid range is 1-4294967295. The ND default is V(1).
                    - Applies when policy_type is C(l3Po).
                    type: int
                  pim_sparse:
                    description:
                    - Whether to enable PIM sparse mode on the port-channel.
                    - The ND default is V(false).
                    - Applies when policy_type is C(l3Po).
                    type: bool
                  port_channel_mode:
                    description:
                    - The port-channel mode.
                    - V(on), V(active) and V(passive) apply to all policy_type values. The PAgP modes V(auto) and V(desirable)
                      apply when policy_type is C(iosXeL3PortChannel).
                    - The ND default is V(active).
                    type: str
                    choices: [ 'on', active, passive, auto, desirable ]
                  ports:
                    description:
                    - The list of member ethernet interface names (e.g. C(Ethernet1/10), C(GigabitEthernet1/0/2)).
                    - Applies to all policy_type values.
                    type: list
                    elements: str
                  prefix:
                    description:
                    - The mask length used with O(config[].config_data.network_os.policy.ip).
                    - Valid range is 1-31 for C(l3Po) and 8-31 for C(iosXeL3PortChannel).
                    - Applies to all policy_type values.
                    type: int
                  qos:
                    description:
                    - Whether to configure a QoS policy on the port-channel.
                    - The ND default is V(false).
                    - Applies when policy_type is C(l3Po).
                    type: bool
                  qos_policy:
                    description:
                    - The custom QoS policy name. The policy must already be defined.
                    - Applies when policy_type is C(l3Po).
                    type: str
                  queuing_policy:
                    description:
                    - The queuing policy name. The policy must already be defined.
                    - Applies when policy_type is C(l3Po).
                    type: str
                  routing_tag:
                    description:
                    - The routing tag associated with the port-channel IP address.
                    - Applies when policy_type is C(l3Po).
                    type: str
                  speed:
                    description:
                    - The speed of the port-channel.
                    - The ND default is V(auto).
                    - Applies when policy_type is C(l3Po).
                    type: str
                    choices: [ auto, 10Mb, 100Mb, 1Gb, 2.5Gb, 5Gb, 10Gb, 25Gb, 40Gb, 50Gb, 100Gb, 200Gb, 400Gb, 800Gb ]
                  vrf:
                    description:
                    - The VRF the port-channel belongs to. Omit it to place the port-channel in the default (global) routing table.
                    - Applies to all policy_type values.
                    type: str
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
      Member ethernet interfaces are released from the port-channel.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module supports both NX-OS and IOS-XE routed port-channel interfaces (interface_type C(portChannel), mode
  C(routed)), selected via O(config[].config_data.network_os.network_os_type).
- This module manages the C(l3Po) (NX-OS) and C(iosXeL3PortChannel) (IOS-XE) policy templates. Port-channels
  carrying any other policy type, including routed port-channels provisioned by Nexus Dashboard itself, are never read or
  modified by this module.
- The port-channel policy is the source of truth for member interface configuration.
- Removing a port-channel (O(state=deleted), or O(state=overridden) for a port-channel absent from O(config)) also releases its
  member interfaces, which the controller returns to its own default policy for the platform. This module does not set a policy on
  released members; configure them with the C(nd_interface_ethernet_*) modules afterwards.
"""

EXAMPLES = r"""
- name: Create a routed port-channel on a Nexus switch and deploy it
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel20
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              description: routed uplink
              ip: 10.1.1.1
              prefix: 30
              mtu: 9216
              port_channel_mode: active
              ports:
                - Ethernet1/10
                - Ethernet1/11
    config_actions:
      deploy: true
    state: merged

- name: Create a routed port-channel in a VRF with IPv6 and PIM on a Nexus switch
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel21
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: l3Po
              vrf: blue
              ip: 10.1.2.1
              prefix: 30
              ipv6: "2001:db8:1::1"
              ipv6_prefix: 64
              pim_sparse: true
              routing_tag: "12345"
              ports:
                - Ethernet1/12
    config_actions:
      deploy: true
    state: merged

- name: Convert the Catalyst members to routed hosts before creating the IOS-XE port-channel
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_campus_fabric
    config:
      - switch_ip: 192.168.1.10
        interface_name: GigabitEthernet1/0/2
        config_data:
          network_os:
            network_os_type: ios-xe
      - switch_ip: 192.168.1.10
        interface_name: GigabitEthernet1/0/3
        config_data:
          network_os:
            network_os_type: ios-xe
    config_actions:
      deploy: true
    state: merged

- name: Create a routed port-channel on a Catalyst IOS-XE switch
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_campus_fabric
    config:
      - switch_ip: 192.168.1.10
        interface_name: port-channel30
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              description: routed uplink
              ip: 10.2.1.1
              prefix: 30
              port_channel_mode: active
              ports:
                - GigabitEthernet1/0/2
                - GigabitEthernet1/0/3
    config_actions:
      deploy: true
    state: merged

- name: Stage routed port-channels on two switches without deploying
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel22
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              ip: 10.1.3.1
              prefix: 31
              ports:
                - Ethernet1/13
      - switch_ip: 192.168.1.2
        interface_name: port-channel22
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              ip: 10.1.3.0
              prefix: 31
              ports:
                - Ethernet1/13
    state: merged

- name: Replace a routed port-channel so it carries exactly this configuration
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel20
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              ip: 10.1.1.1
              prefix: 30
              ports:
                - Ethernet1/10
    config_actions:
      deploy: true
    state: replaced

- name: Make this the only routed port-channel managed by this module in the fabric
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel20
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              ip: 10.1.1.1
              prefix: 30
              ports:
                - Ethernet1/10
    config_actions:
      deploy: true
    state: overridden

- name: Delete routed port-channels
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel20
      - switch_ip: 192.168.1.1
        interface_name: port-channel21
    config_actions:
      deploy: true
    state: deleted

- name: Preview a change without applying it
  cisco.nd.nd_interface_port_channel_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: port-channel20
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              mtu: 1500
    state: merged
  check_mode: true
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
    interface_name: port-channel20
    config_data:
      network_os:
        network_os_type: nx-os
        policy:
          policy_type: l3Po
          admin_state: true
          ip: 10.1.1.1
          prefix: 30
          ports:
          - Ethernet1/10
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
    interface_name: port-channel20
    config_data:
      network_os:
        network_os_type: nx-os
        policy:
          policy_type: l3Po
          admin_state: true
          ip: 10.1.1.1
          prefix: 30
          mtu: 1500
          ports:
          - Ethernet1/10
          port_channel_mode: active
diff:
  description: The per-interface difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: port-channel20
    config_data:
      network_os:
        policy:
          mtu: 1500
proposed:
  description: The configuration the module proposed to apply, before reconciliation with the controller.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: port-channel20
    config_data:
      network_os:
        network_os_type: nx-os
        policy:
          mtu: 1500
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_routed_interface import (
    PortChannelRoutedInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_routed_interface import (
    PortChannelRoutedInterfaceOrchestrator,
)


def main():
    """
    # Summary

    Entry point for the `nd_interface_port_channel_routed` Ansible module. Initializes the
    `NDStateMachine` with `PortChannelRoutedInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(PortChannelRoutedInterfaceModel.get_argument_spec())
    argument_spec.update(config_actions_spec(include=("deploy",)))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_port_channel_routed")

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=PortChannelRoutedInterfaceOrchestrator,
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
