#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_subinterface_managed
version_added: "2.0.0"
short_description: Manage L3 (managed) subinterfaces on Cisco Nexus Dashboard
description:
- Manage L3 subinterfaces (managed variant) on Cisco Nexus Dashboard.
- A subinterface is created on an Ethernet or Port-channel parent interface; the parent type is encoded in the
  O(config[].interface_name) value (e.g. C(Ethernet1/3.2) or C(Port-channel10.5)).
- This module manages the managed variant only (C(policyType) C(subinterface)).
  The unmanaged variant (C(policyType) C(monitorSubinterface)) is handled by C(nd_interface_subinterface_unmanaged).
- It supports creating, updating, and deleting subinterface configurations on switches within a fabric.
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
    - The list of L3 subinterfaces to configure.
    - Each item specifies the target switch, the subinterface name, and the policy configuration.
    - Multiple subinterfaces and multiple switches can be configured in a single task by listing additional items.
    - The structure mirrors the ND Manage Interfaces API payload.
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
        - The full subinterface name, including the dot-separated sub-id (e.g. C(Ethernet1/3.2), C(Port-channel10.5)).
        - The parent kind is inferred from the prefix; only Ethernet and Port-channel parents are supported.
        type: str
        required: true
      config_data:
        description:
        - The configuration data for this subinterface, following the ND API structure.
        type: dict
        suboptions:
          network_os:
            description:
            - Network OS specific configuration.
            type: dict
            suboptions:
              policy:
                description:
                - The policy configuration for the subinterface.
                type: dict
                suboptions:
                  admin_state:
                    description:
                    - The administrative state of the subinterface.
                    - Defaults to V(true) when unset during creation.
                    type: bool
                  description:
                    description:
                    - Subinterface description.
                    - Maximum 254 characters.
                    type: str
                  extra_config:
                    description:
                    - Additional CLI configuration commands to apply to the subinterface.
                    type: str
                  mtu:
                    description:
                    - Subinterface MTU.
                    - Valid range is 576-9216.
                    type: int
                  vlan_id:
                    description:
                    - 802.1Q VLAN tag for the subinterface.
                    - Valid range is 2-4094.
                    type: int
                  vrf_interface:
                    description:
                    - VRF the subinterface is bound to.
                    - Use V(default) for the default VRF.
                    type: str
                  ip:
                    description:
                    - IPv4 address of the subinterface.
                    type: str
                  prefix:
                    description:
                    - IPv4 netmask length used with O(config[].config_data.network_os.policy.ip).
                    - Valid range is 8-31.
                    type: int
                  ipv6:
                    description:
                    - IPv6 address of the subinterface.
                    type: str
                  ipv6_prefix:
                    description:
                    - IPv6 netmask length used with O(config[].config_data.network_os.policy.ipv6).
                    - Valid range is 1-127.
                    type: int
                  routing_tag:
                    description:
                    - Routing tag associated with the subinterface IP address.
                    type: str
                  ip_redirects:
                    description:
                    - Disable both IPv4/IPv6 redirects on the subinterface.
                    type: bool
                  pim_sparse:
                    description:
                    - Enable PIM sparse-mode on the subinterface.
                    type: bool
                  pim_dr_priority:
                    description:
                    - Priority for PIM DR election on the subinterface.
                    - Valid range is 1-4294967295.
                    type: int
                  netflow:
                    description:
                    - Whether netflow is enabled on the subinterface.
                    type: bool
                  netflow_monitor:
                    description:
                    - Layer 3 Netflow monitor name.
                    - Required when O(config[].config_data.network_os.policy.netflow=true).
                    type: str
                  netflow_sampler:
                    description:
                    - Netflow sampler name (applicable to N7K only).
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
          execution via the C(interfaceActions/deploy) API. Only the subinterfaces modified by this task are deployed.
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
      Any managed subinterface managed by this module that exists on ND but is not present in the configuration will be deleted.
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
- This module manages NX-OS L3 subinterfaces only (interface_type C(subInterface), mode C(managed),
  network_os_type C(nx-os), policy_type C(subinterface)). These values are hardcoded by the module and are not user-configurable.
- The unmanaged variant (C(policyType) C(monitorSubinterface)) is handled by C(nd_interface_subinterface_unmanaged).
- The parent interface must be in routed (L3) mode before a subinterface can be created on it.
  ND rejects subinterface POST against L2 access/trunk parents with the message
  "Sub-interface can be created only on routed physical or port-channel interfaces (discovered mode is not routed)".
  In practice this blocks subinterfaces on typical vPC port-channels and peer-link port-channels, which are L2.
  Change the parent's policy to a routed type (e.g. routedHost for Ethernet, l3PortChannel for Port-channel) before
  using this module; the module does not auto-normalize the parent.
"""

EXAMPLES = r"""
- name: Create a managed L3 subinterface on an Ethernet parent
  cisco.nd.nd_interface_subinterface_managed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.2
        config_data:
          network_os:
            policy:
              admin_state: true
              description: "Tenant subinterface vlan 2"
              vlan_id: 2
              vrf_interface: VRF1
              ip: 192.168.50.50
              prefix: 24
              ipv6: "2001:192:168:50::50"
              ipv6_prefix: 64
              routing_tag: "12345"
              mtu: 9216
              ip_redirects: true
              pim_sparse: true
              pim_dr_priority: 1
              netflow: false
    config_actions:
      deploy: true
    state: merged

- name: Create multiple subinterfaces on different parents in one task
  cisco.nd.nd_interface_subinterface_managed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.10
        config_data:
          network_os:
            policy:
              admin_state: true
              vlan_id: 10
              ip: 10.10.10.1
              prefix: 24
      - switch_ip: 192.168.1.1
        interface_name: Port-channel10.20
        config_data:
          network_os:
            policy:
              admin_state: true
              vlan_id: 20
              ip: 10.10.20.1
              prefix: 24
    config_actions:
      deploy: true
    state: merged

- name: Replace the configuration of a specific subinterface
  cisco.nd.nd_interface_subinterface_managed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.2
        config_data:
          network_os:
            policy:
              admin_state: true
              vlan_id: 2
              ip: 10.20.30.40
              prefix: 24
              description: Reprovisioned subinterface Ethernet1/3.2
    config_actions:
      deploy: true
    state: replaced

# state=overridden is fabric-wide: every managed subinterface in the fabric that is managed by this module and is
# NOT listed below is deleted. An empty config list deletes ALL such subinterfaces in the fabric. Use with caution.
- name: Enforce subinterfaces fabric-wide, deleting all others managed by this module
  cisco.nd.nd_interface_subinterface_managed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.2
        config_data:
          network_os:
            policy:
              admin_state: true
              vlan_id: 2
              ip: 10.10.10.1
              prefix: 24
              description: Subinterface to keep; all other managed subinterfaces deleted
    config_actions:
      deploy: true
    state: overridden

- name: Delete a subinterface
  cisco.nd.nd_interface_subinterface_managed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.2
    config_actions:
      deploy: true
    state: deleted

- name: Stage changes without deploying
  cisco.nd.nd_interface_subinterface_managed:
    fabric_name: my_fabric
    config:
      - switch_ip: 192.168.1.1
        interface_name: Ethernet1/3.2
        config_data:
          network_os:
            policy:
              admin_state: true
              vlan_id: 2
              ip: 192.168.50.50
              prefix: 24
    config_actions:
      deploy: false
    state: merged
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
    interface_name: Ethernet1/3.2
    config_data:
      network_os:
        policy:
          admin_state: true
          vlan_id: 2
          vrf_interface: VRF1
          ip: 192.168.50.50
          prefix: 24
after:
  description:
  - The configuration of the targeted interfaces after the module ran, structured the same as the O(config) parameter.
  - In check mode, the configuration that would result had the module run outside of check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: Ethernet1/3.2
    config_data:
      network_os:
        policy:
          admin_state: true
          vlan_id: 2
          vrf_interface: VRF1
          ip: 192.168.50.60
          prefix: 24
diff:
  description: The per-interface difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: Ethernet1/3.2
    config_data:
      network_os:
        policy:
          ip: 192.168.50.60
proposed:
  description: The configuration the module proposed to apply, before reconciliation with the controller.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - switch_ip: 192.168.1.1
    interface_name: Ethernet1/3.2
    config_data:
      network_os:
        policy:
          ip: 192.168.50.60
logs:
  description: Internal diagnostic log messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample:
  - "Querying existing subinterface configuration"
msg:
  description: A human-readable error message, present only when the module fails.
  returned: on failure
  type: str
  sample: "Configuration error: ..."
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import SubinterfaceManagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_managed_interface import SubinterfaceManagedInterfaceOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_interface_subinterface_managed` Ansible module. Initializes the `NDStateMachine` with
    `SubinterfaceManagedInterfaceOrchestrator` and executes the requested state operation.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(SubinterfaceManagedInterfaceModel.get_argument_spec())
    argument_spec.update(
        config_actions={
            "type": "dict",
            "options": {
                "deploy": {"type": "bool", "default": False},
            },
        },
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_interface_subinterface_managed")
    module_log.debug(
        "config items=%d switches=%d",
        len(module.params["config"]),
        len({item.get("switch_ip") for item in module.params["config"]}),
    )

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=SubinterfaceManagedInterfaceOrchestrator,
        )
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
