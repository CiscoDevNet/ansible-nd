#!/usr/bin/python

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone NX-OS dot1q-tunnel interface management."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_port_channel_dot1q_tunnel_host
version_added: 2.0.0
short_description: Manage NX-OS port-channel dot1q-tunnel interfaces on Nexus Dashboard
description:
- Create, update, and delete NX-OS port-channel dot1q-tunnel parent interfaces in a Nexus Dashboard fabric.
- The module uses the ND Manage Interfaces API. Ethernet members inherit their dot1q-tunnel policy from the parent.
- The configured VLAN is the dot1q-tunnel service VLAN.
- Only this parent policy is managed. Unrelated interface families and fabric-owned interfaces are excluded.
- Set O(config_actions.deploy=false) to stage changes for a later deployment. Check mode reports planned changes without writing them.
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description:
    - Name of the fabric containing the target switches.
    type: str
    required: true
  config:
    description:
    - Interfaces to manage. Each item identifies a switch and a logical interface.
    - Required for mutation states. For O(state=gathered), omit O(config) or use an empty list to read all dot1q port-channels.
    - Gathered filtering is not supported; nonempty O(config) is rejected for O(state=gathered).
    type: list
    elements: dict
    suboptions:
      switch_ip:
        description:
        - Management IP address of the switch. For vPC, this identifies Peer-1; ND supplies the reciprocal peer.
        type: str
        required: true
      interface_name:
        description:
        - Port-channel name, such as C(port-channel61). A bare ID from 1 to 4096 is also accepted.
        type: str
        required: true
      config_data:
        description:
        - Desired interface settings. Omit for identifier-only deletion.
        type: dict
        suboptions:
          network_os:
            description:
            - NX-OS interface policy settings.
            type: dict
            suboptions:
              network_os_type:
                description:
                - Network OS of the managed switch. Only NX-OS is supported.
                type: str
                default: nx-os
                choices:
                - nx-os
              policy:
                description:
                - Dot1q-tunnel parent policy. Members are assigned by Nexus Dashboard.
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - Access port-channel policy template discriminator; injected as `dot1qTunnelPoHost` when omitted (see `default_policy_type`)
                    type: str
                    choices:
                    - dot1qTunnelPoHost
                  admin_state:
                    description:
                    - Enable or disable the interface
                    type: bool
                  access_vlan:
                    description:
                    - VLAN for this dot1q-tunnel port-channel
                    type: int
                  bandwidth:
                    description:
                    - Interface bandwidth in kilobits per second
                    type: int
                  bpdu_filter:
                    description:
                    - Configure spanning-tree BPDU filter
                    type: str
                    choices:
                    - enable
                    - disable
                    - default
                  bpdu_guard:
                    description:
                    - Enable spanning-tree BPDU guard
                    type: str
                    choices:
                    - enable
                    - disable
                    - default
                  cdp:
                    description:
                    - Enable CDP on the interface
                    type: bool
                  copy_description:
                    description:
                    - Propagate the port-channel description to all member interfaces
                    type: bool
                  description:
                    description:
                    - Interface description
                    type: str
                  duplex_mode:
                    description:
                    - Port duplex mode
                    type: str
                    choices:
                    - auto
                    - full
                    - half
                  extra_config:
                    description:
                    - Additional CLI for the interface
                    type: str
                  inherit_bandwidth:
                    description:
                    - Inherited interface bandwidth in kilobits per second
                    type: int
                  lacp_port_priority:
                    description:
                    - LACP port priority (1-65535, default 32768)
                    type: int
                  lacp_rate:
                    description:
                    - LACP rate (normal=30s, fast=1s)
                    type: str
                    choices:
                    - normal
                    - fast
                  lacp_suspend:
                    description:
                    - Suspend port if LACP PDUs not received
                    type: bool
                  link_type:
                    description:
                    - Spanning-tree link type
                    type: str
                    choices:
                    - auto
                    - pointToPoint
                    - shared
                  mtu:
                    description:
                    - Interface MTU
                    type: str
                    choices:
                    - default
                    - jumbo
                  negotiate_auto:
                    description:
                    - Enable link auto-negotiation
                    type: bool
                  netflow:
                    description:
                    - Enable Netflow on the interface
                    type: bool
                  netflow_monitor:
                    description:
                    - Layer 2 Netflow monitor name (required when `netflow=true`)
                    type: str
                  netflow_sampler:
                    description:
                    - Netflow sampler name
                    type: str
                  orphan_port:
                    description:
                    - Configure as a vPC orphan port (suspended by secondary peer on vPC failure)
                    type: bool
                  pfc:
                    description:
                    - Enable Priority Flow Control
                    type: bool
                  port_channel_mode:
                    description:
                    - Port-channel mode (on/active/passive)
                    type: str
                    choices:
                    - 'on'
                    - active
                    - passive
                  port_type_edge_trunk:
                    description:
                    - Configure as edge trunk port (PortFast on trunk)
                    type: bool
                  ports:
                    description:
                    - Member interface names (e.g. ['Ethernet1/1', 'Ethernet1/2'])
                    type: list
                    elements: str
                  qos:
                    description:
                    - Enable QoS configuration for this interface
                    type: bool
                  qos_policy:
                    description:
                    - Custom QoS policy name
                    type: str
                  queuing_policy:
                    description:
                    - Custom queuing policy name
                    type: str
                  speed:
                    description:
                    - Interface speed
                    type: str
                    choices:
                    - auto
                    - 10Mb
                    - 100Mb
                    - 1Gb
                    - 2.5Gb
                    - 5Gb
                    - 10Gb
                    - 25Gb
                    - 40Gb
                    - 50Gb
                    - 100Gb
                    - 200Gb
                    - 400Gb
                    - 800Gb
                  storm_control:
                    description:
                    - Enable traffic storm control
                    type: bool
                  storm_control_action:
                    description:
                    - Storm control action on threshold violation
                    type: str
                    choices:
                    - shutdown
                    - trap
                    - default
                  storm_control_broadcast_level:
                    description:
                    - Broadcast storm control level in percentage (0.00-100.00)
                    type: float
                  storm_control_broadcast_level_pps:
                    description:
                    - Broadcast storm control level in packets per second
                    type: int
                  storm_control_multicast_level:
                    description:
                    - Multicast storm control level in percentage (0.00-100.00)
                    type: float
                  storm_control_multicast_level_pps:
                    description:
                    - Multicast storm control level in packets per second
                    type: int
                  storm_control_unicast_level:
                    description:
                    - Unicast storm control level in percentage (0.00-100.00)
                    type: float
                  storm_control_unicast_level_pps:
                    description:
                    - Unicast storm control level in packets per second
                    type: int
  state:
    description:
    - Whether to merge, replace, override, delete, or gather the managed dot1q-tunnel parent interfaces.
    - O(state=gathered) reads only port-channel dot1q parent policies and returns them under C(gathered) in a format reusable as O(config).
    - Gathered does not change controller or switch configuration, including when O(config_actions.deploy=true).
    type: str
    default: merged
    choices:
    - merged
    - replaced
    - overridden
    - deleted
    - gathered
  config_actions:
    description:
    - Controls deploy behavior after port-channel mutations are complete.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy port-channel changes after mutations are complete.
        - When V(true), all queued port-channel changes are deployed in a single bulk API call at the end of module execution via the C(interfaceActions/deploy)
          API. An explicitly named interface can also be deployed when this task makes no ND intent change, but only if its preview shows pending
          switch configuration (possibly staged by another task or operator).
        - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
        - When V(true) and the module fails after the controller accepts a subset of the requested changes, the module attempts to deploy that
          subset and names any unconfirmed targets in the failure message.
        - Replaying the same port-channel config with V(true) previews unchanged intent and deploys it when pending switch configuration remains.
          For an accepted deletion whose controller intent is already absent, replay the exact identifiers with O(state=deleted); an O(state=overridden)
          omission alone cannot identify an already-absent target on a later run.
        - Setting O(config_actions.deploy=false) is useful when batching changes across multiple interface tasks before a single deploy.
        - Deployment is opt-in. Set O(config_actions.deploy=true) explicitly to push changes to switches.
        type: bool
        default: false
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Only NX-OS switches are supported.
- State V(overridden) removes omitted interfaces only within this module's managed policy scope.
- A member already owned by a different port-channel or vPC must first be removed from that parent.
"""

EXAMPLES = r"""
- name: Stage an NX-OS port-channel dot1q-tunnel parent
  cisco.nd.nd_interface_port_channel_dot1q_tunnel_host:
    fabric_name: my_fabric
    state: replaced
    config_actions:
      deploy: false
    config:
      - switch_ip: 192.0.2.11
        interface_name: port-channel61
        config_data:
          network_os:
            policy:
              access_vlan: 261
              description: NAC_INT dot1q port-channel
              ports: [Ethernet1/35, Ethernet1/36]

- name: Delete the port-channel dot1q-tunnel parent and deploy its removal
  cisco.nd.nd_interface_port_channel_dot1q_tunnel_host:
    fabric_name: my_fabric
    state: deleted
    config_actions:
      deploy: true
    config:
      - switch_ip: 192.0.2.11
        interface_name: port-channel61

- name: Gather all dot1q port-channel interfaces without making changes
  cisco.nd.nd_interface_port_channel_dot1q_tunnel_host:
    fabric_name: my_fabric
    state: gathered
  register: dot1q_interfaces
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
  - The existing matching port-channel configuration in the module's query scope before the module ran, structured like O(config).
  - The list can include matching interfaces on the selected switches that were not explicitly listed in O(config); O(state=overridden)
    uses fabric-wide scope.
  - An empty list when no matching interface configuration existed, or when O(state=gathered).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.0.2.11
    interface_name: port-channel261
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
  - The matching port-channel configuration in the same query scope after the module ran, structured like O(config).
  - Successfully deleted interfaces are absent. The list can include matching interfaces not explicitly listed in O(config).
  - In check mode, the configuration that would result had the module run outside of check mode.
  - An empty list when O(state=gathered); use C(gathered) for the read results.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.0.2.11
    interface_name: port-channel261
    config_data:
      network_os:
        network_os_type: nx-os
        policy:
          policy_type: dot1qTunnelPoHost
          admin_state: true
          access_vlan: 200
          ports:
          - Ethernet1/1
          - Ethernet1/2
          port_channel_mode: active
gathered:
  description:
  - Matching dot1q port-channel configuration, returned without making changes.
  - Uses the module's input field names and can be reused as O(config) for a mutation state.
  returned: when O(state=gathered)
  type: list
  elements: dict
  sample: []
diff:
  description:
  - Reserved for the per-interface difference between C(before) and C(after).
  - Currently always an empty list for mutation states; compare C(before) and C(after) directly.
  returned: when O(state) is not V(gathered)
  type: list
  elements: dict
  sample: []
proposed:
  description: The configuration the module proposed to apply, before reconciliation with the controller.
  returned: when O(state) is not V(gathered) and O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - switch_ip: 192.0.2.11
    interface_name: port-channel261
    config_data:
      network_os:
        policy:
          access_vlan: 200
logs:
  description:
  - Reserved for internal diagnostic log messages collected during the run.
  - Currently always an empty list for this module family; use the C(ND_LOGGING_CONFIG) file-based logging
    described in the collection docs instead.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample: []
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_dot1q_tunnel_host_interface import (
    PortChannelDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_dot1q_tunnel_host_interface import (
    PortChannelDot1qTunnelHostInterfaceOrchestrator,
)


def main():
    """
    # Summary

    Entry point for the `nd_interface_port_channel_dot1q_tunnel_host` Ansible module. Initializes the
    `NDStateMachine` with `PortChannelDot1qTunnelHostInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(PortChannelDot1qTunnelHostInterfaceModel.get_argument_spec())
    argument_spec.update(config_actions_spec(include=("deploy",)))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "replaced", ["config"]),
            ("state", "overridden", ["config"]),
            ("state", "deleted", ["config"]),
        ],
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_port_channel_dot1q_tunnel_host")

    if module.params["state"] == "gathered" and module.params.get("config"):
        module.fail_json(msg="state: gathered reads all dot1q port-channels; omit config or set config: []. Gathered filtering is not supported.")

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=PortChannelDot1qTunnelHostInterfaceOrchestrator,
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

        if not module.check_mode and module.params["state"] != "gathered":
            nd_state_machine.model_orchestrator.remove_pending()
            nd_state_machine.model_orchestrator.deploy_pending()

        module.exit_json(**nd_state_machine.output.format())

    except Exception as e:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, nd_state_machine, e)


if __name__ == "__main__":
    main()
