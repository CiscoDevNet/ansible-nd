#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing loopback interfaces on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_interface_loopback
version_added: "1.4.0"
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
    - Required for O(state=merged), O(state=replaced), O(state=overridden), and O(state=deleted).
    - Not required for O(state=gathered).
    - For O(state=gathered), every supplied field is a filter criterion. Criteria within one list item use AND semantics,
      while multiple list items use OR semantics.
    - Supported endpoint criteria are used to reduce candidates with server-side Lucene queries. All criteria are then
      evaluated locally to preserve complete and consistent matching semantics.
    type: list
    elements: dict
    required: false
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage this loopback interface.
        - This is resolved to the switch serial number (switchId) internally.
        - Required for O(state=merged), O(state=replaced), O(state=overridden), and O(state=deleted).
        - Optional filter for O(state=gathered).
        type: str
        required: false
      interface_name:
        description:
        - The name of the loopback interface (e.g., C(loopback0), C(Loopback10)).
        - Required for O(state=merged), O(state=replaced), O(state=overridden), and O(state=deleted).
        - Optional filter for O(state=gathered).
        type: str
        required: false
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
              policy:
                description:
                - The policy configuration for the loopback interface.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the loopback interface.
                    - It defaults to C(true) when unset during creation.
                    type: bool
                  ip:
                    description:
                    - The IPv4 address of the loopback interface.
                    type: str
                  ipv6:
                    description:
                    - The IPv6 address of the loopback interface.
                    type: str
                  vrf:
                    description:
                    - The VRF to which the loopback interface belongs.
                    - Maximum 32 characters.
                    type: str
                  route_map_tag:
                    description:
                    - The route-map tag associated with the interface IP address.
                    type: str
                  description:
                    description:
                    - The description of the loopback interface.
                    - Maximum 254 characters.
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
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
    - Use O(state=deleted) to remove the resources specified in the configuration from the Cisco Nexus Dashboard.
    - Use O(state=gathered) to read all user-managed loopback interfaces in the fabric without making changes.
      The result is returned under C(gathered) in a format that can be reused as O(config).
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module currently supports NX-OS loopback interfaces only (interface_type C(loopback), policy_type C(loopback)).
- The IP Fabric for Media (C(ipfmLoopback)) and user-defined (C(userDefined)) loopback policies will be managed by dedicated modules.
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
            policy:
              ip: 10.1.1.1
              admin_state: true
              description: Management loopback
              route_map_tag: 12345
              vrf: default
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
            policy:
              ip: 10.1.1.1
              description: Router ID loopback
      - switch_ip: 192.168.1.1
        interface_name: loopback1
        config_data:
          network_os:
            policy:
              ip: 10.2.1.1
              description: VTEP loopback
              route_map_tag: "12345"
      - switch_ip: 192.168.1.2
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.2
              description: Router ID loopback on switch 2
    state: merged

- name: Replace a loopback interface
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.2
              description: Updated loopback description
    state: replaced

- name: Delete a loopback interface
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
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
            policy:
              ip: 10.1.1.1
              description: Router ID loopback
      - switch_ip: 192.168.1.2
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.2
              description: Router ID loopback on switch 2
    state: overridden

- name: Create loopback interfaces without deploying (for batching)
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: loopback0
        config_data:
          network_os:
            policy:
              ip: 10.1.1.1
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
            policy:
              ip: 10.1.1.1
              ipv6: 2001:db8::1/128
              description: Loopback with PIM and OSPF tuning
              vrf: default
              extra_config: |
                ip pim sparse-mode
                ip ospf network point-to-point
                no ip redirects
    state: merged

- name: Gather all user-managed loopback interfaces in a fabric
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    state: gathered
  register: gathered_loopbacks

- name: Gather one loopback interface from a specific switch
  cisco.nd.nd_interface_loopback:
    fabric_name: my_fabric
    state: gathered
    config:
      - switch_ip: 192.168.1.1
        interface_name: Loopback10
  register: gathered_loopback10
"""

RETURN = r"""
gathered:
  description:
  - User-managed loopback interfaces matching the supplied O(config) filters.
  - Returned in reusable Ansible configuration format.
  returned: when O(state=gathered)
  type: list
  elements: dict
"""
# pylint: disable=wrong-import-position

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LoopbackInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import (
    LoopbackInterfaceOrchestrator,
)


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
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

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
        if not module.check_mode and module.params["state"] != "gathered":
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
