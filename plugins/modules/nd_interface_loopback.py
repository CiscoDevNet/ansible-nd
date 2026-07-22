#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing loopback interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_loopback
version_added: "2.0.0"
short_description: Manage loopback interfaces on Cisco Nexus Dashboard
description:
- Manage loopback interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, and deleting loopback interfaces on switches within a fabric.
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
    - The list of loopback interfaces to configure.
    - Each item specifies the target switch and interface configuration.
    - Multiple switches can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage this loopback interface.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_name:
        description:
        - The name of the loopback interface (e.g., C(loopback0), C(Loopback10)).
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
                - The policy configuration for the loopback interface.
                - The policy fields present depend on O(config[].config_data.network_os.policy.policy_type).
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - The loopback policy template to apply. This is a discriminator that determines which of the
                      remaining C(policy) suboptions are applicable.
                    - Use V(loopback) for a standard NX-OS loopback interface.
                    - Use V(ipfmLoopback) for an IP Fabric for Media loopback interface.
                    - Use V(mplsLoopback) for an MPLS loopback interface.
                    - Use V(iosXeLoopback) for a general-purpose IOS-XE loopback.
                    - Use V(iosXeLoopbackShutNoshut) to manage only the admin state of an IOS-XE loopback.
                    - Use V(iosXeUnderlayLoopback) for an IOS-XE underlay (NVE source) loopback.
                    - Use V(iosXeInternalLoopback) for an IOS-XE internal loopback (unvalidated ip/ipv6, PIM option).
                    - Use V(csrLoopback) for a CSR loopback.
                    - Use V(csr1kvLoopback) for a CSR1kv loopback (admin state and freeform config only).
                    type: str
                    required: true
                    choices: [ loopback, ipfmLoopback, mplsLoopback, iosXeLoopback, iosXeLoopbackShutNoshut, iosXeUnderlayLoopback,
                      iosXeInternalLoopback, csrLoopback, csr1kvLoopback ]
                  admin_state:
                    description:
                    - The administrative state of the loopback interface.
                    - It defaults to C(true) when unset during creation.
                    - Applies to all policy_type values.
                    type: bool
                  ip:
                    description:
                    - The IPv4 address of the loopback interface.
                    - Accepts bare (C(10.1.1.1)) or CIDR (C(10.1.1.1/32)) input. CIDR input is normalized to the bare address, which is
                      what is sent to the controller and returned in module output, because ND rejects CIDR notation for this field.
                    - Applies to all policy_type values except C(iosXeLoopbackShutNoshut) and C(csr1kvLoopback).
                    type: str
                  description:
                    description:
                    - The description of the loopback interface.
                    - Applies to all policy_type values except C(iosXeLoopbackShutNoshut) and C(csr1kvLoopback). Maximum length is 200 for
                      C(iosXeLoopback) and C(iosXeInternalLoopback), 254 otherwise.
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    - Applies to all policy_type values except C(iosXeLoopbackShutNoshut).
                    type: str
                  vrf:
                    description:
                    - The VRF to which the loopback interface belongs.
                    - Maximum 32 characters.
                    - Applies when policy_type is C(loopback), C(ipfmLoopback), C(iosXeLoopback), C(iosXeInternalLoopback), or C(csrLoopback).
                    type: str
                  ipv6:
                    description:
                    - The IPv6 address of the loopback interface.
                    - Applies when policy_type is C(loopback) or C(iosXeInternalLoopback).
                    type: str
                  route_map_tag:
                    description:
                    - The route-map tag associated with the interface IP address.
                    - Applies when policy_type is C(loopback).
                    type: str
                  advertise_loopback:
                    description:
                    - Whether to advertise the loopback address via OSPF/IS-IS.
                    - Applies when policy_type is C(ipfmLoopback).
                    type: bool
                  is_service_reflect:
                    description:
                    - Whether to use this loopback as the service-reflect source address.
                    - Applies when policy_type is C(ipfmLoopback).
                    type: bool
                  routing_tag:
                    description:
                    - The routing tag associated with the interface IP address.
                    - Applies when policy_type is C(ipfmLoopback).
                    type: str
                  secondary_ip_list:
                    description:
                    - A list of secondary IPv4 addresses configured on the loopback interface.
                    - Applies when policy_type is C(ipfmLoopback).
                    type: list
                    elements: dict
                    suboptions:
                      ip:
                        description:
                        - The secondary IPv4 address.
                        type: str
                      prefix:
                        description:
                        - The subnet mask length for the secondary IPv4 address (4-32).
                        type: int
                  secondary_ip:
                    description:
                    - Secondary IP address of the NVE interface loopback.
                    - Applies when policy_type is C(iosXeUnderlayLoopback).
                    type: str
                  enable_pim:
                    description:
                    - Enable PIM on the interface.
                    - Applies when policy_type is C(iosXeInternalLoopback).
                    type: bool
                  dci_routing_protocol:
                    description:
                    - The DCI (Data Center Interconnect) link-state routing protocol.
                    - Applies when policy_type is C(mplsLoopback).
                    type: str
                    choices: [ ospf, isis ]
                  dci_routing_tag:
                    description:
                    - The DCI (Data Center Interconnect) routing tag.
                    - Applies when policy_type is C(mplsLoopback).
                    type: str
                  ospf_area_id:
                    description:
                    - The OSPF area identifier.
                    - Maximum 15 characters.
                    - Applies when policy_type is C(mplsLoopback).
                    type: str
  config_actions:
    description:
    - Controls deploy behavior after interface mutations are complete.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy interface changes after mutations are complete.
        - When V(true), all queued interface changes are deployed in a single bulk API call at the end of module
          execution via the C(interfaceActions/deploy) API. Only the interfaces modified by this task are deployed.
        - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
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
    - Use O(state=deleted) to remove the resources specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module supports both NX-OS and IOS-XE loopback interfaces (interface_type C(loopback)), selected via
  O(config[].config_data.network_os.network_os_type).
- This module manages three NX-OS loopback policy templates, selected via O(config[].config_data.network_os.policy.policy_type)
  C(loopback), C(ipfmLoopback) (IP Fabric for Media), and C(mplsLoopback), plus six IOS-XE managed templates
  C(iosXeLoopback), C(iosXeLoopbackShutNoshut), C(iosXeUnderlayLoopback), C(iosXeInternalLoopback), C(csrLoopback), and
  C(csr1kvLoopback). The user-defined (C(userDefined)) loopback policy is not yet supported for either network OS.
"""

EXAMPLES = r"""
- name: Create a loopback interface on a single switch
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.1
              admin_state: true
              description: Management loopback
              route_map_tag: 12345
              vrf: default
    config_actions:
      deploy: true
    state: merged
  register: result

- name: Create loopback interfaces across multiple switches
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.1
              description: Router ID loopback
      - switch_ip: 192.168.1.1
        interface_name: loopback1
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.2.1.1
              description: VTEP loopback
              route_map_tag: "12345"
      - switch_ip: 192.168.1.2
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.2
              description: Router ID loopback on switch 2
    config_actions:
      deploy: true
    state: merged

- name: Replace a loopback interface
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.2
              description: Updated loopback description
    config_actions:
      deploy: true
    state: replaced

- name: Delete a loopback interface
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
    config_actions:
      deploy: true
    state: deleted

- name: Override loopback interfaces on a fabric (single source of truth)
  # Any loopback interface managed by this module that exists on the fabric
  # but is NOT listed in `config` will be DELETED. Use with extra caution.
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.1
              description: Router ID loopback
      - switch_ip: 192.168.1.2
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.2
              description: Router ID loopback on switch 2
    config_actions:
      deploy: true
    state: overridden

- name: Create loopback interfaces without deploying (for batching)
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.1
    config_actions:
      deploy: false
    state: merged

- name: Create a loopback interface with extra CLI configuration
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              ip: 10.1.1.1
              ipv6: 2001:db8::1/128
              description: Loopback with PIM and OSPF tuning
              vrf: default
              extra_config: |
                ip pim sparse-mode
                ip ospf network point-to-point
                no ip redirects
    config_actions:
      deploy: true
    state: merged

- name: Create an IPFM loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback11
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: ipfmLoopback
              ip: 10.2.2.2
              vrf: default
              advertise_loopback: true
              is_service_reflect: false
              routing_tag: "100"
              secondary_ip_list:
                - ip: 10.2.2.3
                  prefix: 32
    state: merged

- name: Create an MPLS loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback12
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: mplsLoopback
              ip: 10.3.3.3
              dci_routing_protocol: ospf
              dci_routing_tag: "200"
              ospf_area_id: "0.0.0.0"
    state: merged

- name: Merge an IOS-XE loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeLoopback
              admin_state: true
              ip: "10.200.100.1"
              description: "XE loopback100"
              vrf: blue
    state: merged

- name: Replace an IOS-XE loopback (full desired state)
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeLoopback
              admin_state: true
              ip: "10.200.100.2"
              description: "XE loopback100 replaced"
    state: replaced

- name: Override all managed loopbacks (mixed NX-OS and IOS-XE desired state)
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: nx-os
            policy:
              policy_type: loopback
              admin_state: true
              ip: "10.100.100.1"
      - switch_ip: 192.168.2.1
        interface_name: loopback100
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: iosXeLoopback
              admin_state: true
              ip: "10.200.100.1"
    state: overridden

- name: Delete an IOS-XE loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.1
        interface_name: loopback100
    state: deleted

- name: Merge a CSR loopback
  cisco.nd.nd_interface_loopback:
    fabric_name: fabric-xe
    config:
      - switch_ip: 192.168.2.2
        interface_name: loopback101
        config_data:
          network_os:
            network_os_type: ios-xe
            policy:
              policy_type: csrLoopback
              admin_state: true
              ip: "10.200.101.1"
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import config_actions_spec, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_interface_loopback` Ansible module. Initializes the `NDStateMachine` with
    `LoopbackInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(LoopbackInterfaceModel.get_argument_spec())
    argument_spec.update(config_actions_spec(include=("deploy",)))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_loopback")

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=LoopbackInterfaceOrchestrator,
        )
        # Narrow type from NDBaseOrchestrator to NDBaseInterfaceOrchestrator so that
        # interface-specific attributes (deploy, remove_pending, deploy_pending) are
        # visible to Pylance and validated at runtime.
        if not isinstance(nd_state_machine.model_orchestrator, NDBaseInterfaceOrchestrator):
            raise AssertionError(f"Expected NDBaseInterfaceOrchestrator, got {type(nd_state_machine.model_orchestrator)}")
        config_actions = module.params.get("config_actions") or {}
        deploy = config_actions.get("deploy", False)
        nd_state_machine.model_orchestrator.deploy = deploy

        module_log.debug(
            "manage_state begin state=%s check_mode=%s deploy=%s",
            module.params.get("state"),
            module.check_mode,
            deploy,
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
