#!/usr/bin/python

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module for managing vPC pairs on Cisco Nexus Dashboard."""

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_vpc_pair
version_added: "2.0.0"
short_description: Manage vPC pairs on Cisco Nexus Dashboard
description:
- Manage virtual Port-Channel (vPC) pairs on Cisco Nexus Dashboard.
- Supports creating, updating, querying, and tearing down vPC pairs between two leaf switches in a fabric.
- This module manages the pair-level lifecycle only (peer-link, keepalive, domain ID, role priority).
  Member vPC interfaces are managed by the C(nd_interface_vpc_access) and C(nd_interface_vpc_trunk_host) modules.
- Tearing down a pair (O(state=deleted)) cascades on the ND side and removes all member vPC interfaces on both peers.
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
    - The list of vPC pairs to configure.
    - Each item specifies the two peer switches by management IP and the pair-level configuration.
    type: list
    elements: dict
    suboptions:
      switch_ip:
        description:
        - The management IP address of the first peer switch.
        - Resolved to the switch serial number internally.
        type: str
        required: true
      peer_switch_ip:
        description:
        - The management IP address of the second peer switch.
        - Resolved to the switch serial number internally.
        - Must differ from O(config.switch_ip).
        type: str
        required: true
      domain_id:
        description:
        - The vPC domain ID. Must be in the range 1-1000.
        type: int
        required: true
      keep_alive_vrf:
        description:
        - The VRF used for vPC peer keepalive.
        - Defaults to C(management) to align with the typical SITE1 fabric setting.
        type: str
        default: management
        choices: [ default, management ]
      keep_alive_hold_timeout:
        description:
        - The peer keepalive hold timeout in seconds.
        type: int
      switch_po_id:
        description:
        - The peer-link port-channel ID on peer 1. Range 1-4096.
        type: int
      peer_switch_po_id:
        description:
        - The peer-link port-channel ID on peer 2. Range 1-4096.
        type: int
      switch_member_interfaces:
        description:
        - List of peer-link member interfaces on peer 1 (e.g. C(["Ethernet1/3"])).
        type: list
        elements: str
      peer_switch_member_interfaces:
        description:
        - List of peer-link member interfaces on peer 2.
        type: list
        elements: str
      enable_mirror_config:
        description:
        - Mirror peer-1 configuration onto peer-2.
        type: bool
      is_vpc_plus:
        description:
        - Enable vPC+ (FabricPath).
        type: bool
      is_vteps:
        description:
        - Both peers act as VTEPs.
        type: bool
      nve_interface:
        description:
        - The NVE interface ID for VXLAN.
        type: int
      po_mode:
        description:
        - The peer-link port-channel mode (e.g. C(active), C(passive), C(on)).
        type: str
      admin_state:
        description:
        - The administrative state of the peer link.
        type: bool
      allowed_vlans:
        description:
        - VLAN list permitted across the peer link.
        type: str
  deploy:
    description:
    - Whether to deploy pair changes to the switches after the intent is configured.
    - When V(true), both peer serials are queued and pushed via C(switchActions/deploy) at the end of module execution.
    - When V(false), the pair intent is configured on ND but not pushed to the switches.
    type: bool
    default: true
  state:
    description:
    - The desired state of the vPC pair on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new pairs and update existing ones.
    - Use O(state=replaced) to replace the pairs specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
    - Use O(state=deleted) to unpair the switches. This cascades and also removes member vPC interfaces on both peers.
    - Use O(state=query) to retrieve the current pair state without making changes.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, query ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard.
- This release supports direct vPC peering only (C(useVirtualPeerLink=false)).
  Fabric peering will be added in a follow-up release.
- ND deploy returns when the intent has been handed off to the switches; switch-side discovery converges
  asynchronously (typically 30-40 seconds on virtual switches).
"""

EXAMPLES = r"""
- name: Create a vPC pair between two leafs
  cisco.nd.nd_vpc_pair:
    fabric_name: SITE1
    config:
      - switch_ip: 192.168.12.151
        peer_switch_ip: 192.168.12.155
        domain_id: 1
        keep_alive_vrf: management
        switch_po_id: 1
        peer_switch_po_id: 1
        switch_member_interfaces:
          - Ethernet1/3
        peer_switch_member_interfaces:
          - Ethernet1/2
    state: merged

- name: Query the current vPC pair state for two switches
  cisco.nd.nd_vpc_pair:
    fabric_name: SITE1
    config:
      - switch_ip: 192.168.12.151
        peer_switch_ip: 192.168.12.155
        domain_id: 1
    state: query
  register: result

- name: Unpair two switches (cascades to all member vPC interfaces)
  cisco.nd.nd_vpc_pair:
    fabric_name: SITE1
    config:
      - switch_ip: 192.168.12.151
        peer_switch_ip: 192.168.12.155
        domain_id: 1
    state: deleted

- name: Configure pair intent without deploying (stage for batched deploy)
  cisco.nd.nd_vpc_pair:
    fabric_name: SITE1
    config:
      - switch_ip: 192.168.12.151
        peer_switch_ip: 192.168.12.155
        domain_id: 1
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
from ansible_collections.cisco.nd.plugins.module_utils.models.vpc.vpc_pair import VpcPairModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_pair import VpcPairOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_vpc_pair` Ansible module. Initializes the `NDStateMachine` with `VpcPairOrchestrator`
    and executes the requested state operation, then flushes any queued switch deploys.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(VpcPairModel.get_argument_spec())
    argument_spec.update(
        deploy=dict(type="bool", default=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_vpc_pair")

    # fabric_name is module-level in the argspec but a per-item field on VpcPairModel
    # (composite identifier includes fabric_name). Inject it into each config item
    # so model validation sees a complete record.
    fabric_name = module.params.get("fabric_name")
    for item in module.params.get("config") or []:
        if isinstance(item, dict):
            item.setdefault("fabric_name", fabric_name)

    nd_state_machine = None

    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=VpcPairOrchestrator,
        )
        if not isinstance(nd_state_machine.model_orchestrator, VpcPairOrchestrator):
            raise AssertionError(f"Expected VpcPairOrchestrator, got {type(nd_state_machine.model_orchestrator)}")
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
