#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_ethernet_access
version_added: "2.0.0"
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
      config_data:
        description:
        - The configuration data shared by all interfaces in O(config[].interface_names), following the ND API structure.
        type: dict
        suboptions:
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
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
                  bandwidth:
                    description:
                    - Bandwidth value of the interface in kilobits.
                    - Valid range is 1-100000000.
                    type: int
                  bpdu_filter:
                    description:
                    - Spanning-tree BPDU filter setting for the interface.
                    type: str
                    choices: [ enable, disable, default ]
                  bpdu_guard:
                    description:
                    - BPDU guard setting for the interface.
                    type: str
                    choices: [ enable, disable, default ]
                  cdp:
                    description:
                    - Whether Cisco Discovery Protocol is enabled on the interface.
                    type: bool
                  debounce_timer:
                    description:
                    - Link debounce timer (in milliseconds).
                    - Valid range is 0-20000.
                    type: int
                  debounce_linkup_timer:
                    description:
                    - Link debounce timer for link-up event (in milliseconds).
                    - Valid range is 1000-10000.
                    type: int
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
                  error_detection_acl:
                    description:
                    - Whether error detection for access-list installation failures is enabled.
                    type: bool
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    type: str
                  fec:
                    description:
                    - The forward error correction (FEC) mode for the interface.
                    type: str
                    choices: [ "auto", "fcFec", "off", "rsCons16", "rsFec", "rsIEEE" ]
                  inherit_bandwidth:
                    description:
                    - Inherit bandwidth (in kilobits) for sub-interfaces.
                    - Valid range is 1-100000000.
                    type: int
                  link_type:
                    description:
                    - Spanning-tree link type.
                    type: str
                    choices: [ auto, pointToPoint, shared ]
                  monitor:
                    description:
                    - Whether switchport monitor for SPAN / ERSPAN is enabled.
                    type: bool
                  mtu:
                    description:
                    - The MTU setting for the interface.
                    type: str
                    choices: [ default, jumbo ]
                  negotiate_auto:
                    description:
                    - Whether link auto-negotiation is enabled.
                    type: bool
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
                  storm_control:
                    description:
                    - Whether traffic storm control is enabled on the interface.
                    type: bool
                  storm_control_action:
                    description:
                    - Storm control action on threshold violation.
                    type: str
                    choices: [ shutdown, trap, default ]
                  storm_control_broadcast_level:
                    description:
                    - Broadcast storm control level in percentage (format V(whole.decimal), range 0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_broadcast_level_pps).
                    type: float
                  storm_control_broadcast_level_pps:
                    description:
                    - Broadcast storm control level in packets per second.
                    - Valid range is 0-200000000.
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_broadcast_level).
                    type: int
                  storm_control_multicast_level:
                    description:
                    - Multicast storm control level in percentage (format V(whole.decimal), range 0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_multicast_level_pps).
                    type: float
                  storm_control_multicast_level_pps:
                    description:
                    - Multicast storm control level in packets per second.
                    - Valid range is 0-200000000.
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_multicast_level).
                    type: int
                  storm_control_unicast_level:
                    description:
                    - Unicast storm control level in percentage (format V(whole.decimal), range 0.00-100.00).
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_unicast_level_pps).
                    type: float
                  storm_control_unicast_level_pps:
                    description:
                    - Unicast storm control level in packets per second.
                    - Valid range is 0-200000000.
                    - Mutually exclusive with O(config[].config_data.network_os.policy.storm_control_unicast_level).
                    type: int
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
- This module manages NX-OS ethernet accessHost interfaces only (interface_type C(ethernet), mode C(access), network_os_type C(nx-os),
  policy_type C(accessHost)). These values are hardcoded by the module and are not user-configurable.
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

- name: Apply different access configurations to different interfaces on the same switch
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
              description: VLAN 100 access ports
      - switch_ip: 192.168.1.1
        interface_names:
          - Ethernet1/3
          - Ethernet1/4
        config_data:
          network_os:
            policy:
              admin_state: true
              access_vlan: 200
              description: VLAN 200 access ports
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
import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_access_interface import EthernetAccessInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_access_interface import EthernetAccessInterfaceOrchestrator


# TODO: When all interface modules using `interface_names: list` are merged, lift
# `validate_within_item_duplicates`, `validate_across_item_duplicates`, and
# `expand_config` into a shared helper module (e.g.
# `plugins/module_utils/interfaces/config_expansion.py`) and import from there.
def validate_within_item_duplicates(config_list):
    """
    # Summary

    Raise `ValueError` if any single config item lists the same interface name more than once
    in its `interface_names` list. Comparison is case-insensitive.

    ## Raises

    ### ValueError

    - If an interface name appears more than once within a single config item's `interface_names` list
    """
    for item_index, group in enumerate(config_list):
        switch_ip = group.get("switch_ip")
        interface_names = group.get("interface_names") or []
        seen = {}
        for name in interface_names:
            key = name.lower()
            if key in seen:
                raise ValueError(
                    f"Duplicate interface '{name}' in interface_names for switch '{switch_ip}' "
                    f"(config item {item_index}). Each interface may appear only once per config item."
                )
            seen[key] = True


# TODO: See note above `validate_within_item_duplicates`.
def validate_across_item_duplicates(config_list):
    """
    # Summary

    Raise `ValueError` if the same `(switch_ip, interface_name)` pair appears in more than one
    config item. Comparison of interface names is case-insensitive. The error message identifies
    both offending config item indices so the user can locate them in the playbook.

    ## Raises

    ### ValueError

    - If the same `(switch_ip, interface_name)` pair appears in more than one config item
    """
    seen = {}
    for item_index, group in enumerate(config_list):
        switch_ip = group.get("switch_ip")
        interface_names = group.get("interface_names") or []
        for name in interface_names:
            key = (switch_ip, name.lower())
            if key in seen:
                raise ValueError(
                    f"Interface '{name}' on switch '{switch_ip}' is specified in multiple config items "
                    f"({seen[key]} and {item_index}). Each switch/interface pair may appear only once."
                )
            seen[key] = item_index


def expand_config(config_list):
    """
    # Summary

    Validate then expand grouped config items (with `interface_names` list) into flat config items
    (with singular `interface_name`). Each group produces one flat item per interface name, all
    sharing the same `config_data` and `switch_ip`.

    ## Raises

    ### ValueError

    - If an interface name appears more than once within a single config item's `interface_names` list
    - If the same `(switch_ip, interface_name)` pair appears in more than one config item
    """
    validate_within_item_duplicates(config_list)
    validate_across_item_duplicates(config_list)

    expanded = []
    for group in config_list:
        # `or []` (not a `.get` default) so an explicit `interface_names: ~` in YAML,
        # which yields None, is treated as empty -- consistent with the validators above.
        interface_names = group.get("interface_names") or []
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
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_ethernet_access")

    # Expand grouped config (interface_names list) into flat config items (interface_name singular)
    try:
        module.params["config"] = expand_config(module.params["config"])
    except ValueError as e:
        module.fail_json(msg=f"Configuration error: {e}")
    module_log.debug(
        "expand_config done items=%d switches=%d",
        len(module.params["config"]),
        len({item.get("switch_ip") for item in module.params["config"]}),
    )

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=EthernetAccessInterfaceOrchestrator,
        )
        # Narrow type from NDBaseOrchestrator to NDBaseInterfaceOrchestrator so that
        # interface-specific attributes (deploy, remove_pending, deploy_pending) are
        # visible to Pylance and validated at runtime.
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

        # Execute all queued bulk operations
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
