#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_subinterface_unmanaged
version_added: "2.0.0"
short_description: Manage L3 (unmanaged / monitor-mode) subinterfaces on Cisco Nexus Dashboard
description:
- Manage L3 subinterfaces (unmanaged variant) on Cisco Nexus Dashboard.
- A subinterface is created on an Ethernet or Port-channel parent interface; the parent type is encoded in the
  O(config[].interface_name) value (e.g. C(Ethernet1/3.20) or C(Port-channel10.20)).
- This module manages the unmanaged variant only (C(policyType) C(monitorSubinterface)).
  The managed variant (C(policyType) C(subinterface)) is handled by C(nd_interface_subinterface_managed).
- The policy body for the unmanaged variant carries only the C(policyType) discriminator; no L3 configuration fields are exposed.
- It supports creating, querying, and deleting subinterface configurations on switches within a fabric.
- Each config item targets a single subinterface identified by O(config[].interface_name).
- Configure multiple subinterfaces in one task by listing multiple config items.
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
    - The list of L3 unmanaged (monitor-mode) subinterfaces to configure.
    - Each item specifies the target switch and the subinterface name.
    - Multiple subinterfaces and multiple switches can be configured in a single task by listing additional items.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage the subinterface.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      interface_name:
        description:
        - The full subinterface name, including the dot-separated sub-id (e.g. C(Ethernet1/3.20), C(Port-channel10.20)).
        - The parent kind is inferred from the prefix; only Ethernet and Port-channel parents are supported.
        type: str
        required: true
  deploy:
    description:
    - Whether to deploy interface changes after mutations are complete.
    - When V(true), all queued interface changes are deployed in a single bulk API call at the end of module execution
      via the C(interfaceActions/deploy) API. Only the subinterfaces modified by this task are deployed.
    - When V(false), changes are staged but not deployed. Use a separate deploy module or task to deploy later.
    - Setting O(deploy=false) is useful when batching changes across multiple interface tasks before a single deploy.
    type: bool
    default: true
  state:
    description:
    - The desired state of the network resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new unmanaged subinterfaces and leave others unchanged.
      Resources on ND that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the unmanaged subinterfaces specified in the configuration.
      For unmanaged subinterfaces, replaced is effectively a no-op on existing subinterfaces because the policy body
      carries only the C(policyType) discriminator with no user-configurable fields. It is still useful when the target
      subinterface is missing, in which case it falls back to create.
    - Use O(state=overridden) to enforce the configuration as the single source of truth across the entire fabric.
      Any unmanaged subinterface that exists on ND but is not present in the configuration will be deleted.
      Use with extra caution.
    - Use O(state=deleted) to remove the specified subinterfaces via the C(interfaceActions/remove) API followed by a deploy.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module manages NX-OS L3 subinterfaces in unmanaged (monitor) mode (interface_type C(subInterface), mode C(unmanaged),
  network_os_type C(nx-os), policy_type C(monitorSubinterface)). These values are hardcoded by the module and are not user-configurable.
- The managed variant (C(policyType) C(subinterface)) is handled by C(nd_interface_subinterface_managed).
- The parent interface must be in routed (L3) mode before a subinterface can be created on it.
  ND rejects subinterface POST against L2 access/trunk parents with the message
  "Sub-interface can be created only on routed physical or port-channel interfaces (discovered mode is not routed)".
  In practice this blocks subinterfaces on typical vPC port-channels and peer-link port-channels, which are L2.
  Change the parent's policy to a routed type (e.g. routedHost for Ethernet, l3PortChannel for Port-channel) before
  using this module; the module does not auto-normalize the parent.
"""

EXAMPLES = r"""
- name: Create an unmanaged L3 subinterface on an Ethernet parent
  cisco.nd.nd_interface_subinterface_unmanaged:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.20
    state: merged

- name: Create multiple unmanaged subinterfaces on different parents in one task
  cisco.nd.nd_interface_subinterface_unmanaged:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.20
      - switch_ip: 192.168.1.1
        interface_name: Port-channel10.20
    state: merged

# Note: For unmanaged subinterfaces, replaced is effectively a no-op on existing
# subinterfaces - the policy body carries only policyType (no user-configurable fields).
# replaced is still useful when the target subinterface is missing: it falls back to create.
- name: Replace (or create if missing) an unmanaged subinterface
  cisco.nd.nd_interface_subinterface_unmanaged:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.20
    state: replaced

- name: Override fabric-wide - delete any unmanaged subinterfaces not listed here
  cisco.nd.nd_interface_subinterface_unmanaged:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.20
    state: overridden

- name: Delete an unmanaged subinterface
  cisco.nd.nd_interface_subinterface_unmanaged:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.20
    state: deleted

- name: Stage an unmanaged subinterface without deploying
  cisco.nd.nd_interface_subinterface_unmanaged:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Port-channel10.20
    deploy: false
    state: merged
"""

RETURN = r"""
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_interface_subinterface_unmanaged` Ansible module. Initializes the `NDStateMachine` with
    `SubinterfaceUnmanagedInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(SubinterfaceUnmanagedInterfaceModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_subinterface_unmanaged")
    module_log.debug(
        "config items=%d switches=%d",
        len(module.params["config"]),
        len({item.get("switch_ip") for item in module.params["config"]}),
    )

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=SubinterfaceUnmanagedInterfaceOrchestrator,
        )
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
