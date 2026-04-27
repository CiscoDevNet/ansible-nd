#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_svi
version_added: "1.4.0"
short_description: Manage SVI (switched virtual) interfaces on Cisco Nexus Dashboard
description:
- Manage SVI interfaces on Cisco Nexus Dashboard.
- It supports creating, updating, querying, and deleting SVI interface configurations on switches within a fabric.
- Multiple SVIs can share the same configuration via the O(config[].vlan_ids) list.
- The interface name is derived from O(config[].vlan_ids) as C(vlan<id>) (e.g. V(333) -> C(vlan333)).
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
    - The list of SVI interface groups to configure.
    - Each item specifies the target switch, a list of VLAN IDs, and a shared configuration.
    - Multiple switches can be configured in a single task.
    - The structure mirrors the ND Manage Interfaces API payload.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_ip:
        description:
        - The management IP address of the switch on which to manage the SVI interfaces.
        - This is resolved to the switch serial number (switchId) internally.
        type: str
        required: true
      vlan_ids:
        description:
        - The list of VLAN IDs for which to manage SVI interfaces.
        - Each ID is expanded into a separate interface named C(vlan<id>).
        type: list
        elements: int
        required: true
      interface_type:
        description:
        - The type of the interface.
        - Defaults to C(svi) for this module.
        type: str
        default: svi
      config_data:
        description:
        - The configuration data shared by all SVIs in O(config[].vlan_ids), following the ND API structure.
        type: dict
        suboptions:
          mode:
            description:
            - The interface operational mode.
            - Defaults to C(managed) for SVIs. The ND API uses this as a discriminator
              to select the SVI configuration schema.
            type: str
            default: managed
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
              network_os_type:
                description:
                - The network OS type of the switch.
                type: str
                default: nx-os
              policy:
                description:
                - The policy configuration for the SVI.
                type: dict
                suboptions:
                  policy_type:
                    description:
                    - The policy template type for the interface.
                    type: str
                    choices: [ svi ]
                    default: svi
                  admin_state:
                    description:
                    - The administrative state of the interface.
                    - It defaults to C(true) when unset during creation.
                    type: bool
                  description:
                    description:
                    - The description of the interface.
                    - Maximum 254 characters.
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the interface.
                    type: str
                  mtu:
                    description:
                    - The MTU setting for the interface.
                    - Valid range is 576-9216.
                    type: int
                  ip:
                    description:
                    - The IPv4 address of the SVI.
                    type: str
                  prefix:
                    description:
                    - The IPv4 netmask length used with O(config[].config_data.network_os.policy.ip).
                    - Valid range is 1-31.
                    type: int
                  ipv6:
                    description:
                    - The IPv6 address of the SVI.
                    type: str
                  v6prefix:
                    description:
                    - The IPv6 netmask length used with O(config[].config_data.network_os.policy.ipv6).
                    - Valid range is 1-127.
                    type: int
                  ip_redirects:
                    description:
                    - Disable both IPv4/IPv6 redirects on the interface.
                    type: bool
                  pim_sparse:
                    description:
                    - Enable PIM sparse-mode on the interface.
                    type: bool
                  pim_dr_priority:
                    description:
                    - Priority for PIM DR election on the interface.
                    - Valid range is 1-4294967295.
                    type: int
                  hsrp_group:
                    description:
                    - The HSRP group number for the interface.
                    type: int
                  hsrp_version:
                    description:
                    - The HSRP version.
                    type: str
                  preempt:
                    description:
                    - Enable HSRP preemption.
                    type: bool
                  advertise_subnet_in_underlay:
                    description:
                    - Advertise the SVI subnet into the underlay routing protocol.
                    type: bool
                  netflow:
                    description:
                    - Whether netflow is enabled on the interface.
                    type: bool
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
      Any SVI managed by this module that exists on ND but is not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to remove the specified SVIs via the C(interfaceActions/remove) API followed by a deploy.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This module manages NX-OS SVI interfaces only.
- Phase 1 of this module supports the SVI options that the ND GUI sends on create. OSPF, ISIS, BFD, and underlay
  routing-protocol options are not yet exposed and will be added in a follow-up release.
"""

EXAMPLES = r"""
- name: Create three SVI interfaces with the same configuration
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        vlan_ids:
          - 333
          - 334
          - 335
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
              description: Tenant SVI
    state: merged
  register: result

- name: Create SVIs across multiple switches
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        vlan_ids:
          - 333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
      - switch_ip: 192.168.1.2
        vlan_ids:
          - 333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.2
              prefix: 24
    state: merged

- name: Delete SVI interfaces
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        vlan_ids:
          - 333
          - 334
    state: deleted

- name: Stage SVI changes without deploying (for batching)
  cisco.nd.nd_interface_svi:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        vlan_ids:
          - 333
        config_data:
          network_os:
            policy:
              admin_state: true
              ip: 10.99.99.1
              prefix: 24
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
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator


def expand_config(config_list):
    """
    # Summary

    Expand grouped config items (with `vlan_ids` list) into flat config items (with singular `interface_name`). Each
    group produces one flat item per VLAN ID, all sharing the same `config_data` and `switch_ip`. The `interface_name`
    is set to `vlan<id>` (lowercase, matching the ND API convention).

    ## Raises

    None
    """
    expanded = []
    for group in config_list:
        vlan_ids = group.get("vlan_ids", []) or []
        for vlan_id in vlan_ids:
            item = copy.deepcopy(group)
            item.pop("vlan_ids", None)
            item["interface_name"] = f"vlan{vlan_id}"
            expanded.append(item)
    return expanded


def main():
    """
    # Summary

    Entry point for the `nd_interface_svi` Ansible module. Expands grouped config items, initializes the
    `NDStateMachine` with `SviInterfaceOrchestrator`, and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(SviInterfaceModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_svi")

    # Expand grouped config (vlan_ids list) into flat config items (interface_name singular)
    module.params["config"] = expand_config(module.params["config"])
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
            model_orchestrator=SviInterfaceOrchestrator,
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


if __name__ == "__main__":
    main()
