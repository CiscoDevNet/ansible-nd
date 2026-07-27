#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing routed-mode ethernet interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_ethernet_routed
version_added: "2.0.0"
short_description: Manage routed-mode (L3) ethernet interfaces on Cisco Nexus Dashboard
description:
- Manage routed-mode (L3) ethernet interfaces on Cisco Nexus Dashboard.
- It supports configuring, updating, and resetting routed ethernet interfaces on switches within a fabric.
- Physical ethernet interfaces always exist on the switch; configuring one with this module changes its mode to
  C(routed) and applies the requested policy.
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
    - The list of routed ethernet interfaces to configure.
    - Each item specifies the target switch and interface configuration.
    - Multiple switches can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage this interface.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_name:
        description:
        - The name of the ethernet interface (e.g., C(Ethernet1/7), C(GigabitEthernet3)).
        type: str
        required: true
      config_data:
        description:
        - The configuration data for the interface, following the ND API structure.
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
                  policy templates are applicable, and is required by the ND API schema.
                - Use V(nx-os) for Nexus switches and V(ios-xe) for Catalyst/CSR IOS-XE devices.
                type: str
                required: true
                choices: [ nx-os, ios-xe ]
              policy:
                description:
                - The policy configuration for the routed ethernet interface.
                - The policy fields present depend on O(config[].config_data.network_os.policy.policy_type).
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - The routed ethernet policy template to apply. This is a discriminator that determines which of the
                      remaining C(policy) suboptions are applicable.
                    - Use V(routedHost) for an NX-OS routed host interface.
                    - Use V(iosXeRoutedHost) for an IOS-XE routed host interface.
                    type: str
                    required: true
                    choices: [ routedHost, iosXeRoutedHost ]
                  admin_state:
                    description:
                    - The administrative state of the interface.
                    - It defaults to C(true) when unset during creation.
                    - Applies to all policy_type values.
                    type: bool
                  description:
                    description:
                    - The description of the interface.
                    - Applies to all policy_type values. Maximum length is 200 for C(iosXeRoutedHost), 254 for C(routedHost).
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    - Applies to all policy_type values.
                    type: str
                  ip:
                    description:
                    - The IPv4 address of the interface.
                    - Accepts bare (C(10.1.1.1)) or CIDR (C(10.1.1.1/30)) input. CIDR input is normalized to the bare address, which is
                      what is sent to the controller and returned in module output, because ND rejects CIDR notation for this field.
                    - Applies to all policy_type values.
                    type: str
                  prefix:
                    description:
                    - The netmask length for the interface IP address (1-31).
                    - Applies to all policy_type values.
                    type: int
                  mtu:
                    description:
                    - The interface MTU.
                    - Range is 576-9216 (default 9216) for C(routedHost), 1500-9216 (default 1500) for C(iosXeRoutedHost).
                    - Applies to all policy_type values.
                    type: int
                  speed:
                    description:
                    - The interface speed.
                    - For C(routedHost), one of C(auto), C(10Mb), C(100Mb), C(1Gb), C(2.5Gb), C(5Gb), C(10Gb), C(25Gb), C(40Gb),
                      C(50Gb), C(100Gb), C(200Gb), C(400Gb), C(800Gb).
                    - For C(iosXeRoutedHost), one of C(auto), C(10Mb), C(100Mb), C(1Gb), C(2.5Gb), C(5Gb), C(10Gb), C(25Gb),
                      C(40Gb), C(100Gb), C(noNegotiate).
                    - Applies to all policy_type values.
                    type: str
                  vrf:
                    description:
                    - The VRF to which the interface belongs.
                    - Maximum 32 characters.
                    - Applies to all policy_type values.
                    type: str
                  fec:
                    description:
                    - The forward error correction (FEC) mode.
                    - Applies when policy_type is C(routedHost).
                    type: str
                  ip_redirects:
                    description:
                    - Whether to disable IPv4 and IPv6 redirects on the interface.
                    - Applies when policy_type is C(routedHost).
                    type: bool
                  netflow:
                    description:
                    - Whether to enable netflow on the interface. Netflow must be enabled on the fabric.
                    - Applies when policy_type is C(routedHost).
                    type: bool
                  netflow_monitor:
                    description:
                    - The netflow monitor name.
                    - Applies when policy_type is C(routedHost).
                    type: str
                  netflow_sampler:
                    description:
                    - The netflow sampler name (Nexus 7000 platforms only).
                    - Applies when policy_type is C(routedHost).
                    type: str
                  pfc:
                    description:
                    - Whether to enable priority flow control.
                    - Applies when policy_type is C(routedHost).
                    type: bool
                  pim_dr_priority:
                    description:
                    - The PIM DR election priority (1-4294967295).
                    - Applies when policy_type is C(routedHost).
                    type: int
                  pim_sparse:
                    description:
                    - Whether to enable PIM sparse mode on the interface.
                    - Applies when policy_type is C(routedHost).
                    type: bool
                  qos:
                    description:
                    - Whether to apply a QoS policy to the interface.
                    - Applies when policy_type is C(routedHost).
                    type: bool
                  qos_policy:
                    description:
                    - The custom QoS policy name. The policy must be defined previously.
                    - Applies when policy_type is C(routedHost).
                    type: str
                  queuing_policy:
                    description:
                    - The queuing policy name. The policy must be defined previously.
                    - Applies when policy_type is C(routedHost).
                    type: str
                  routing_tag:
                    description:
                    - The routing tag associated with the interface IP address.
                    - Applies when policy_type is C(routedHost).
                    type: str
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
    - Use O(state=deleted) to reset the specified interfaces to their fabric default configuration. Physical
      ethernet interfaces cannot be truly deleted from a switch. NX-OS interfaces reset to the fabric default
      C(trunkHost) policy, taking them out of routed mode; IOS-XE interfaces reset to a default routed
      configuration with all policy fields cleared.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module supports both NX-OS and IOS-XE routed ethernet interfaces (interface_type C(ethernet), mode C(routed)),
  selected via O(config[].config_data.network_os.network_os_type).
- This module manages the C(routedHost) (NX-OS) and C(iosXeRoutedHost) (IOS-XE) policy templates. System routed
  policy types (fabric links, multi-site link members, VRF-Lite link members, and similar) are never read or modified
  by this module, so O(state=overridden) cannot affect fabric underlay configuration.
- Interfaces that are port-channel members have restricted mutability.
- O(state=overridden) operates fabric-wide for NX-OS interfaces. An empty O(config) list resets every managed
  NX-OS routed interface in the fabric to its fabric default configuration.
- IOS-XE interfaces are merge-only under O(state=overridden), they are converged when named in O(config) and
  are never reset when absent from it. To reset an IOS-XE interface, name it explicitly under O(state=deleted).
"""

EXAMPLES = r"""
- name: Configure a routed interface on a single NX-OS switch
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/7
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: routedHost
              admin_state: true
              ip: 10.99.99.1
              prefix: 30
              description: L3 uplink to WAN edge
              vrf: blue
    state: merged
  register: result

- name: Convert a trunk interface to routed (mode flip) across multiple switches
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/7
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: routedHost
              ip: 10.99.99.1
              prefix: 30
              pim_sparse: true
              pim_dr_priority: 100
      - switch_ip: 192.168.1.2
        interface_name: Ethernet1/7
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: routedHost
              ip: 10.99.99.5
              prefix: 30
    state: merged

- name: Configure an IOS-XE routed interface
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: GigabitEthernet3
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeRoutedHost
              admin_state: true
              ip: 10.200.3.1
              prefix: 30
              description: XE routed link
    state: merged

- name: Replace a routed interface configuration (full desired state)
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/7
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: routedHost
              admin_state: true
              ip: 10.99.99.9
              prefix: 30
              description: Replaced routed uplink
    state: replaced

- name: Override managed routed interfaces on a fabric (single source of truth)
  # Any routed interface managed by this module that exists on the fabric but is
  # NOT listed in `config` will be reset to the fabric default. System routed
  # interfaces (fabric links, multi-site links) are never touched. Use with caution.
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/7
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: routedHost
              ip: 10.99.99.1
              prefix: 30
      - switch_ip: 192.168.2.1
        interface_name: GigabitEthernet3
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeRoutedHost
              ip: 10.200.3.1
              prefix: 30
    state: overridden

- name: Reset routed interfaces to the fabric default configuration
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/7
    state: deleted

- name: Configure a routed interface without deploying (for batching)
  cisco.nd.nd_interface_ethernet_routed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/7
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: routedHost
              ip: 10.99.99.1
              prefix: 30
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import EthernetRoutedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_routed_interface import EthernetRoutedInterfaceOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_interface_ethernet_routed` Ansible module. Initializes the `NDStateMachine` with
    `EthernetRoutedInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(EthernetRoutedInterfaceModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_ethernet_routed")

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=EthernetRoutedInterfaceOrchestrator,
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
