#!/usr/bin/python
# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Manage NX-OS Ethernet dot1q-tunnel host policies on Nexus Dashboard."""

from __future__ import annotations

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_interface_ethernet_dot1q_tunnel_host
version_added: "2.0.0"
short_description: Manage NX-OS Ethernet dot1q-tunnel host interfaces on Nexus Dashboard
description:
- Manage the NX-OS C(dot1qTunnelHost) Ethernet policy (C(int_dot1q_tunnel_host) template).
- Each O(config[]) group applies the same policy to its O(config[].interface_names) on one switch.
- Physical Ethernet interfaces are reset to the default trunk policy, not removed, by O(state=deleted).
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description: Name of the fabric containing the target NX-OS switches.
    type: str
    required: true
  config:
    description:
    - Groups of Ethernet interfaces to manage.
    - An empty list with O(state=overridden) resets every managed dot1q-tunnel host in the fabric.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description: Management IP of the switch in O(fabric_name).
        type: str
        required: true
      interface_names:
        description:
        - Physical Ethernet interface names in this group; a group must name at least one interface.
        - Use an empty top-level O(config) list, not an empty group, to reset all dot1q hosts with O(state=overridden).
        type: list
        elements: str
        required: true
      config_data:
        description:
        - Desired dot1q-tunnel host configuration; omit for an identifier-only O(state=deleted) item.
        - C(mode=dot1qTunnel) is derived by the module and is not user-configurable.
        type: dict
        suboptions:
          network_os:
            description: NX-OS-specific policy container.
            type: dict
            suboptions:
              network_os_type:
                description: Only NX-OS implements this ND policy.
                type: str
                default: nx-os
                choices: [ nx-os ]
              policy:
                description: C(dot1qTunnelHost) policy properties.
                type: dict
                suboptions:
                  policy_type:
                    description: Optional policy discriminator; defaults to V(dot1qTunnelHost).
                    type: str
                    choices: [ dot1qTunnelHost ]
                  admin_state:
                    description: Enable or disable the interface; ND default is V(true).
                    type: bool
                  access_vlan:
                    description: Service VLAN for the tunnel host, 1 through 4094.
                    type: int
                  bandwidth:
                    description: Bandwidth in kilobits, 1 through 100000000.
                    type: int
                  bpdu_filter:
                    description: BPDU filtering; the dot1q-tunnel template default is V(enable).
                    type: str
                    choices: [ enable, disable, default ]
                  bpdu_guard:
                    description: BPDU guard; ND default is V(enable).
                    type: str
                    choices: [ enable, disable, default ]
                  cdp:
                    description: Enable Cisco Discovery Protocol; ND default is V(true).
                    type: bool
                  debounce_linkup_timer:
                    description: Link-up debounce timer in milliseconds, 1000 through 10000.
                    type: int
                  debounce_timer:
                    description: Link debounce timer in milliseconds, 0 through 20000.
                    type: int
                  description:
                    description:
                    - ASCII interface description, up to 254 characters.
                    - An explicit empty string clears an existing description; ND 4.3.1 requires the module to omit the field on retry.
                    type: str
                  duplex_mode:
                    description: Duplex mode; ND default is V(auto).
                    type: str
                    choices: [ auto, full, half ]
                  error_detection_acl:
                    description: Enable ACL installation error detection; ND default is V(true).
                    type: bool
                  extra_config:
                    description: Additional interface CLI configuration.
                    type: str
                  fec:
                    description: Forward error correction; ND default is V(auto).
                    type: str
                    choices: [ auto, fcFec, 'off', rsCons16, rsFec, rsIEEE ]
                  inherit_bandwidth:
                    description: Inherited subinterface bandwidth in kilobits, 1 through 100000000.
                    type: int
                  link_type:
                    description: Spanning-tree link type; ND default is V(auto).
                    type: str
                    choices: [ auto, pointToPoint, shared ]
                  mtu:
                    description: NX-OS MTU preset; ND default is V(jumbo).
                    type: str
                    choices: [ default, jumbo ]
                  negotiate_auto:
                    description: Enable link autonegotiation; ND default is V(true).
                    type: bool
                  netflow:
                    description: Enable NetFlow; ND default is V(false).
                    type: bool
                  netflow_monitor:
                    description: Layer-2 NetFlow monitor name.
                    type: str
                  netflow_sampler:
                    description: NetFlow sampler name.
                    type: str
                  orphan_port:
                    description: Enable vPC orphan-port behavior; ND default is V(false).
                    type: bool
                  pfc:
                    description: Enable priority flow control; ND default is V(false).
                    type: bool
                  port_type_edge_trunk:
                    description: Enable spanning-tree edge behavior; ND default is V(true).
                    type: bool
                  qos:
                    description: Enable QoS; ND default is V(false).
                    type: bool
                  qos_policy:
                    description: Custom QoS policy name.
                    type: str
                  queuing_policy:
                    description: Custom queuing policy name.
                    type: str
                  speed:
                    description: Interface speed; ND default is V(auto).
                    type: str
                    choices: [ auto, 10Mb, 100Mb, 1Gb, 2.5Gb, 5Gb, 10Gb, 25Gb, 40Gb, 50Gb, 100Gb, 200Gb, 400Gb, 800Gb ]
                  storm_control:
                    description: Enable storm control; ND default is V(false).
                    type: bool
                  storm_control_action:
                    description: Storm-control action; ND default is V(default).
                    type: str
                    choices: [ default, shutdown, trap ]
                  storm_control_broadcast_level:
                    description: Broadcast threshold as a percentage, 0 through 100.
                    type: float
                  storm_control_broadcast_level_pps:
                    description: Broadcast threshold in packets per second, 0 through 200000000.
                    type: int
                  storm_control_multicast_level:
                    description: Multicast threshold as a percentage, 0 through 100.
                    type: float
                  storm_control_multicast_level_pps:
                    description: Multicast threshold in packets per second, 0 through 200000000.
                    type: int
                  storm_control_unicast_level:
                    description: Unicast threshold as a percentage, 0 through 100.
                    type: float
                  storm_control_unicast_level_pps:
                    description: Unicast threshold in packets per second, 0 through 200000000.
                    type: int
  config_actions:
    description: Optional deployment control.
    type: dict
    suboptions:
      deploy:
        description:
        - V(false) stages ND intent without deploying to switches.
        - V(true) deploys exact queued interface targets after mutations, including accepted changes from a partial request.
        type: bool
        default: false
  state:
    description:
    - V(merged) merges the supplied fields into named host interfaces.
    - V(replaced) replaces the named host policy fields.
    - V(overridden) additionally resets every omitted C(dot1qTunnelHost) interface in the entire fabric; use with care.
    - V(deleted) resets named physical Ethernet interfaces to the fabric default rather than removing them.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Only NX-OS C(dot1qTunnelHost) interfaces belong to this module's managed scope.
- C(dot1qTunnelPoMember), C(dot1qTunnelVpcMember), and C(dot1qTunnelVpcPoMember) are protected, not managed here.
- This is distinct from selective dot1q VLAN mappings on trunk-host interfaces and from routed subinterface dot1q encapsulation.
"""

EXAMPLES = r"""
- name: Stage an NX-OS dot1q-tunnel host on an Ethernet port
  cisco.nd.nd_interface_ethernet_dot1q_tunnel_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.0.2.11
        interface_names:
          - Ethernet1/40
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              access_vlan: 150
              description: Customer dot1q tunnel
              bpdu_guard: disable
              speed: 1Gb
    state: merged
    config_actions:
      deploy: false

- name: Reset this dot1q-tunnel host to its fabric-default Ethernet policy
  cisco.nd.nd_interface_ethernet_dot1q_tunnel_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.0.2.11
        interface_names: [Ethernet1/40]
    state: deleted
    config_actions:
      deploy: true

- name: Replace the named dot1q-tunnel host policy
  cisco.nd.nd_interface_ethernet_dot1q_tunnel_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.0.2.11
        interface_names: [Ethernet1/40]
        config_data:
          network_os:
            policy:
              access_vlan: 150
              description: Replacement host policy
    state: replaced
    config_actions:
      deploy: false

- name: Keep one dot1q host and reset all others in the fabric
  cisco.nd.nd_interface_ethernet_dot1q_tunnel_host:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.0.2.11
        interface_names: [Ethernet1/40]
        config_data:
          network_os:
            policy:
              access_vlan: 150
    state: overridden
    config_actions:
      deploy: false
"""

RETURN = r"""
---
changed:
  description: Whether the module planned or accepted an interface change.
  returned: always
  type: bool
  sample: true
output_level:
  description: The output verbosity level in effect for the run, echoing the O(output_level) parameter.
  returned: always
  type: str
  sample: normal
before:
  description: Managed dot1q-tunnel host interfaces before the operation.
  returned: always
  type: list
  elements: dict
  sample: []
after:
  description: Managed dot1q-tunnel host interfaces after the operation, or projected state in check mode.
  returned: always
  type: list
  elements: dict
  sample: []
diff:
  description: Reserved per-interface differences; compare before and after directly.
  returned: always
  type: list
  elements: dict
  sample: []
proposed:
  description: Configuration proposed before controller reconciliation.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample: []
logs:
  description: Internal diagnostic log messages.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample: []
msg:
  description: Error detail on failure, including any accepted partial mutations.
  returned: on failure
  type: str
  sample: "Configuration error: ..."
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.interface_config_normalizer import expand_ethernet_config
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_dot1q_tunnel_host_interface import (
    EthernetDot1qTunnelHostInterfaceOrchestrator,
)


def expand_config(config_list: list[dict]) -> list[dict]:
    """Reject accidental empty groups without changing other Ethernet families."""
    for index, group in enumerate(config_list):
        if isinstance(group, dict) and group.get("interface_names") == []:
            raise ValueError(
                f"interface_names for dot1q config item {index} must name at least one interface. "
                "Use top-level config: [] with state: overridden for an intentional fabric-wide reset."
            )
    return expand_ethernet_config(config_list)


def main() -> None:
    """Run the shared state machine with the dot1q-tunnel host family."""
    argument_spec = nd_argument_spec()
    argument_spec.update(EthernetDot1qTunnelHostInterfaceModel.get_argument_spec())
    argument_spec.update(config_actions_spec(include=("deploy",)))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_ethernet_dot1q_tunnel_host")

    try:
        module.params["config"] = expand_config(module.params["config"])
    except ValueError as exc:
        module.fail_json(msg=f"Configuration error: {exc}")

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(module=module, model_orchestrator=EthernetDot1qTunnelHostInterfaceOrchestrator)
        if not isinstance(nd_state_machine.model_orchestrator, NDBaseInterfaceOrchestrator):
            raise AssertionError(f"Expected NDBaseInterfaceOrchestrator, got {type(nd_state_machine.model_orchestrator)}")
        nd_state_machine.model_orchestrator.apply_config_actions(module.params)
        nd_state_machine.manage_state()
        if not module.check_mode:
            nd_state_machine.model_orchestrator.remove_pending()
            nd_state_machine.model_orchestrator.deploy_pending()
        module.exit_json(**nd_state_machine.output.format())
    except Exception as exc:  # pylint: disable=broad-except
        fail_from_exception(module, module_log, nd_state_machine, exc)


if __name__ == "__main__":
    main()
