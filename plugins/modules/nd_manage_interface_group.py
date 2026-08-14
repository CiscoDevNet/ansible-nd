# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_manage_interface_group
version_added: "2.0.0"
short_description: Manage Interface Groups on Cisco Nexus Dashboard fabrics
description:
- Create, update, replace, override, delete, and gather Interface Groups on a Cisco Nexus Dashboard fabric.
- Interface Groups associate existing switch interfaces with optional shared Ethernet settings
  and existing networks in the fabric.
- This module references networks but does not create them.
author:
- L Nikhil Sri Krishna (@nisaikri)
options:
  timeout:
    description:
    - Socket-level timeout in seconds.
    - Interface Group operations can take longer as the member count grows, so
      this module uses a higher default than the shared ND module default.
    - If the value is not specified in the task, the value of environment
      variable C(ND_TIMEOUT) will be used instead.
    type: int
    default: 300
  fabric_name:
    description:
    - Name of the fabric that owns the Interface Groups.
    type: str
    required: true
    aliases: [ fabric ]
  config:
    description:
    - Interface Groups to manage.
    - Optional for O(state=gathered). When omitted or empty, all Interface Groups
      in the fabric are returned.
    - With O(state=gathered), each entry is a filter. Fields within one entry are
      combined with AND; multiple entries are combined with OR and overlapping
      results are returned once.
    - With O(state=merged), omitted groups are preserved and supplied network/member collections
      are additive. With O(state=replaced), supply the complete desired collection to remove
      individual networks or members, or supply an explicit empty list to clear the collection.
    type: list
    elements: dict
    suboptions:
      interface_group_name:
        description:
        - Name of the Interface Group.
        - Required for C(merged), C(replaced), C(overridden), and C(deleted).
        - Optional for C(gathered), where it is an exact-name filter.
        type: str
      type:
        description:
        - Interface Group type.
        - With O(state=gathered), this is an exact normalized-type filter.
        - Required when O(config.interface_group_name) does not identify an existing group and
          O(state=merged) must create it. Also required for O(state=replaced) and
          O(state=overridden).
        - May be omitted only when O(state=merged) additively updates an existing group
          identified by O(config.interface_group_name); the existing group supplies its type.
        - C(any) accepts Ethernet and port-channel member interfaces together,
          or vPC member interfaces by themselves. The controller rejects vPC
          members combined with either of the other member kinds, so the module
          fails that combination before making any write request.
        - C(ethernetWithoutPolicy) accepts Ethernet interfaces but does not apply shared
          Ethernet attributes to them. Membership alone does not change member interface
          configuration; associated networks can still add VLAN bindings to those members.
        type: str
        choices:
        - any
        - ethernetCustom
        - ethernetWithPolicy
        - ethernetWithoutPolicy
        - portChannel
        - vpc
      description:
        description:
        - Description of the Interface Group.
        - This describes the group itself. For the description applied to member
          interfaces, use O(config.ethernet_attributes.description).
        - Manage 1.1.411 declares this field, but the target controller silently
          drops it on both create and update and omits it from readback. Write
          states therefore reject it before mutation to prevent a permanently
          non-idempotent configuration.
        - With O(state=gathered), this remains an exact-description filter for
          controller data that includes the field.
        type: str
      networks:
        description:
        - Names of existing NDFC networks associated with this Interface Group.
        - With O(state=gathered), all supplied names must be associated with a
          returned group. An explicit empty list returns groups with no networks.
        - For write states, the module fails with C(changed=false) if a supplied
          network does not exist.
        - Under O(state=merged), these values are added and existing associations are preserved.
        - Under O(state=replaced) and O(state=overridden), a supplied value is the complete desired
          list. Omission preserves the existing list; an explicit empty list clears it.
        type: list
        elements: str
      switch_interfaces:
        description:
        - Switch serial numbers and member interfaces associated with this group.
        - With O(state=gathered), every supplied switch must be associated with a
          returned group and every supplied interface must be a member on that
          switch. Omit O(config.switch_interfaces.interface_names) to filter only
          by switch. An explicit empty list returns groups with no members.
        - Under O(state=merged), switches and interfaces are added without removing existing members.
        - Under O(state=replaced) and O(state=overridden), a supplied value is the complete desired
          membership. Omission preserves the existing membership; an explicit empty list clears it.
        type: list
        elements: dict
        suboptions:
          switch_id:
            description:
            - Switch serial number or management IP address.
            - For a vPC Interface Group, use the primary switch serial number or
              management IP address of the vPC pair.
            - ND can return a logical vPC member under either peer. Confirmed vPC peers are
              treated as equivalent when existing membership is compared.
            type: str
            required: true
          interface_names:
            description:
            - Interfaces on the switch that are members of this group.
            - Optional only for O(state=gathered), where omission matches any
              member association on O(config.switch_interfaces.switch_id).
            type: list
            elements: str
      template_name:
        description:
        - Name of an existing custom Ethernet shared-policy template.
        - For write states, required and valid only when
          O(config.type=ethernetCustom).
        - The referenced template must be user-defined, must be an Ethernet
          interface policy template that is eligible for shared interface
          editing, and must declare supported switch platforms.
        - With O(state=gathered), this is an exact custom-template filter and can
          be supplied without O(config.type).
        type: str
      template_config:
        description:
        - Inputs for O(config.template_name).
        - Keys, required values, basic value types, and enumerated values are
          validated against the referenced template before any changes are made.
        - Under O(state=merged), explicitly supplied keys are merged with existing keys.
        - With O(state=gathered), supplied key/value pairs must be present in the
          returned custom-template configuration.
        type: dict
      ethernet_attributes:
        description:
        - Shared Ethernet attributes applied to group members.
        - For write states, valid for O(config.type=ethernetWithPolicy). Omit
          this option for O(config.type=ethernetWithoutPolicy).
        - All attributes are optional. For a newly created C(ethernetWithPolicy)
          group, omitted settings use the standard shared-policy values.
        - Under O(state=merged), explicitly supplied keys are merged with existing keys.
        - With O(state=gathered), supplied attributes must be present in the
          returned shared Ethernet settings.
        type: dict
        suboptions:
          admin_state:
            description:
            - Administrative state of member interfaces.
            type: bool
          allowed_vlans:
            description:
            - Allowed VLANs as C(all), C(none), individual VLAN IDs, ranges, or
              comma-separated combinations. VLAN IDs must be in the range 1 through 4094.
            type: str
          auto_negotiate:
            description:
            - Whether Ethernet speed auto-negotiation is enabled.
            type: bool
          bpdu_guard:
            description:
            - Spanning Tree BPDU Guard setting.
            type: str
            choices: [ enable, disable, default ]
          cdp:
            description:
            - Whether Cisco Discovery Protocol is enabled.
            type: bool
          description:
            description:
            - Interface description applied to members. The value must contain
              1 to 254 ASCII characters.
            type: str
          extra_config:
            description:
            - Additional interface configuration commands.
            type: str
          mtu:
            description:
            - Interface maximum transmission unit profile.
            type: str
            choices: [ default, jumbo ]
          native_vlan:
            description:
            - Native VLAN ID in the range 1 through 4094.
            type: int
          netflow:
            description:
            - Whether NetFlow is enabled.
            type: bool
          netflow_monitor:
            description:
            - NetFlow monitor name.
            type: str
          netflow_sampler:
            description:
            - NetFlow sampler name.
            type: str
          duplex_mode:
            description:
            - Interface duplex mode.
            type: str
            choices: [ auto, full, half ]
          orphan_port:
            description:
            - Whether member interfaces are vPC orphan ports.
            type: bool
          port_type_edge:
            description:
            - Whether the Interface Group is used for Fabric Extender ports.
            type: bool
          port_type_edge_trunk:
            description:
            - Whether Spanning Tree edge-trunk behavior is enabled.
            type: bool
          speed:
            description:
            - Interface speed.
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
      deploy:
        description:
        - Resource-level deployment decision for this Interface Group.
        - Valid only when O(config_actions.type=resource).
        - Not valid with O(state=gathered).
        - The effective default is C(true). Set C(false) to stage this resource without deploying it.
        type: bool
  config_actions:
    description:
    - Controls deployment after Interface Group intent is updated.
    - Not used by O(state=gathered), which is always read-only.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether to deploy switch-affecting changes.
        - Defaults to C(true). Set C(false) to stage changes only.
        type: bool
        default: true
      type:
        description:
        - Deployment scope.
        - C(resource) deploys only the affected interfaces.
        - C(switch) deploys all pending configuration on the affected switches, including
          pending changes outside this task.
        type: str
        default: switch
        choices: [ resource, switch ]
  state:
    description:
    - C(merged) creates missing groups and additively updates supplied groups. It never removes
      omitted networks, switches, or interfaces; explicit empty collections are no-ops.
    - C(replaced) creates missing groups and authoritatively replaces supplied fields on named groups.
      Omitted network/member collections are preserved; explicit empty collections clear them.
      Other groups are preserved.
    - C(overridden) applies authoritative replacement to supplied groups and deletes every other
      Interface Group in the fabric.
    - C(deleted) deletes the named groups. Member and network associations are cleared first.
    - C(gathered) returns playbook-compatible Interface Group configuration
      without making changes. O(config) can be omitted or used as filters.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted, gathered ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- Supported Interface Group types are C(any), C(ethernetCustom), C(ethernetWithPolicy),
  C(ethernetWithoutPolicy), C(portChannel), and C(vpc).
- The module contract is aligned with Manage API OpenAPI version C(1.1.411).
  The three convenient Ethernet types are translated on the wire to
  C(type=ethernet) with C(policyDetails.policyType=userDefinedSharedTrunk),
  C(sharedTrunkHost), or C(none), respectively.
- A switch interface can belong to only one Interface Group. Under O(state=merged), attempting
  to add a member owned by another group fails because merged is additive. O(state=replaced) and
  O(state=overridden) can move it when the source group's desired membership removes it.
- With O(config_actions.type=resource), network deployment is not handled by this module.
  The module verifies that referenced networks exist, but does not query or enforce their
  deployment status. It proceeds with the requested Interface Group intent, deploys affected
  interfaces only, and returns a warning for referenced networks. Use
  M(cisco.nd.nd_manage_networks) to deploy those networks separately.
- With O(config_actions.type=switch), the selected switch-level deploy is intentionally broad and
  can deploy unrelated pending switch configuration.
- O(config_actions.deploy=false) does not deploy any configuration.
- O(state=gathered) performs one paginated fabric read and applies the complete
  filter contract locally so nested network/member filters and normalized
  Ethernet types produce consistent results.
"""

EXAMPLES = r"""
- name: Add a port-channel and network to an Interface Group
  cisco.nd.nd_manage_interface_group:
    fabric_name: fabric-1
    config:
      - interface_group_name: server-port-channels
        type: portChannel
        networks:
          - Network-A
        switch_interfaces:
          - switch_id: FDO12345678
            interface_names:
              - Port-channel10
    config_actions:
      type: resource
      deploy: true
    state: merged

- name: Replace the complete membership of one Interface Group without deploying
  cisco.nd.nd_manage_interface_group:
    fabric_name: fabric-1
    config:
      - interface_group_name: server-port-channels
        type: portChannel
        networks:
          - Network-A
        switch_interfaces:
          - switch_id: FDO12345678
            interface_names:
              - Port-channel20
    config_actions:
      deploy: false
      type: switch
    state: replaced

- name: Create a shared-policy Ethernet Interface Group with Manage 1.1.411 attributes
  cisco.nd.nd_manage_interface_group:
    fabric_name: fabric-1
    config:
      - interface_group_name: server-ethernet-ports
        type: ethernetWithPolicy
        ethernet_attributes:
          admin_state: true
          allowed_vlans: 100-120,200
          auto_negotiate: true
          bpdu_guard: enable
          cdp: true
          description: Managed by Ansible
          duplex_mode: auto
          mtu: jumbo
          native_vlan: 100
          orphan_port: false
          port_type_edge: false
          port_type_edge_trunk: true
          speed: auto
        switch_interfaces:
          - switch_id: FDO12345678
            interface_names:
              - Ethernet1/10
    config_actions:
      type: resource
      deploy: true
    state: merged

- name: Delete Interface Groups
  cisco.nd.nd_manage_interface_group:
    fabric_name: fabric-1
    config:
      - interface_group_name: server-port-channels
    state: deleted

- name: Gather groups containing a network and member interface
  cisco.nd.nd_manage_interface_group:
    fabric_name: fabric-1
    config:
      - networks:
          - Network-A
        switch_interfaces:
          - switch_id: FDO12345678
            interface_names:
              - Ethernet1/10
    state: gathered
  register: matching_interface_groups
"""

RETURN = r"""
changed:
  description: Whether the task changed, or in check mode would change, Interface Group intent.
  returned: always
  type: bool
output_level:
  description: The output verbosity level in effect for the run, echoing O(output_level).
  returned: always
  type: str
before:
  description: Interface Group configuration before reconciliation.
  returned: always
  type: list
  elements: dict
after:
  description: Interface Group configuration after reconciliation.
  returned: always
  type: list
  elements: dict
diff:
  description: Difference between the configuration before and after reconciliation.
  returned: always
  type: list
  elements: dict
proposed:
  description: Normalized configuration proposed by the task.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
logs:
  description: Internal diagnostic messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
warnings_nd:
  description:
    - Warnings produced by Interface Group processing.
    - Resource-level deployment warnings identify referenced networks that this module does not deploy.
  returned: when warnings are produced
  type: list
  elements: str
gathered:
  description:
  - Current Interface Groups matching the supplied filters.
  - The returned list is normalized in the same shape accepted by O(config).
  returned: when state is gathered
  type: list
  elements: dict
api_paths:
  description: Controller request paths for write operations.
  returned: when Ansible verbosity is C(-vv) or higher
  type: list
  elements: str
api_verbs:
  description: Controller request methods for write operations.
  returned: when Ansible verbosity is C(-vv) or higher
  type: list
  elements: str
api_response:
  description: Controller responses for recorded operations.
  returned: when Ansible verbosity is C(-vvv) or higher
  type: list
  elements: dict
api_result:
  description: Parsed results for recorded operations.
  returned: when Ansible verbosity is C(-vvv) or higher
  type: list
  elements: dict
api_diff:
  description: Per-operation differences recorded during the run.
  returned: when Ansible verbosity is C(-vvv) or higher
  type: list
  elements: dict
api_metadata:
  description: Metadata for recorded operations.
  returned: when Ansible verbosity is C(-vvv) or higher
  type: list
  elements: dict
api_payload:
  description: Request payloads for recorded operations.
  returned: when Ansible verbosity is C(-vvv) or higher
  type: list
  elements: raw
msg:
  description: Human-readable failure details.
  returned: on failure
  type: str
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.config_models import (
    InterfaceGroupGatheredFilterModel,
    InterfaceGroupModuleConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import (
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_interface_group import (
    ManageInterfaceGroupOrchestrator,
)


def _normalize_module_params(
    module: AnsibleModule,
) -> list[InterfaceGroupGatheredFilterModel]:
    """Run Pydantic validation and isolate read-only gathered filters."""
    validated = InterfaceGroupModuleConfigModel.model_validate(module.params)
    module.params["fabric_name"] = validated.fabric_name
    module.params["state"] = validated.state
    module.params["config_actions"] = validated.config_actions.model_dump(mode="json") if validated.config_actions is not None else None
    if validated.state == "gathered":
        filters = list(validated.config)
        module.params["config"] = []
        return filters

    module.params["config"] = [item.to_config() for item in validated.config]
    return []


def _module_verbosity(module: AnsibleModule) -> int:
    """Return the active Ansible CLI verbosity, or zero when unavailable."""
    return module._verbosity if hasattr(module, "_verbosity") else 0


def _format_output(
    module: AnsibleModule,
    nd_state_machine: NDStateMachine | None,
    **kwargs,
) -> dict:
    """Format the generic state machine's NDOutput and attach IG warnings."""
    output = nd_state_machine.output if nd_state_machine is not None else NDOutput(module.params.get("output_level", "normal") or "normal")
    results = nd_state_machine.results if nd_state_machine is not None else None
    warnings = nd_state_machine.model_orchestrator.warnings if nd_state_machine is not None else []
    if warnings:
        kwargs["warnings_nd"] = warnings
    return output.format_with_verbosity(
        _module_verbosity(module),
        results,
        **kwargs,
    )


def main():
    """Entry point for the nd_manage_interface_group module."""
    argument_spec = nd_argument_spec()
    argument_spec.setdefault("timeout", {"type": "int"})["default"] = 300
    argument_spec.update(InterfaceGroupModuleConfigModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_interface_group")

    nd_state_machine = None
    try:
        gathered_filters = _normalize_module_params(module)
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageInterfaceGroupOrchestrator,
        )
        if module.params.get("state") == "gathered":
            gathered = nd_state_machine.model_orchestrator.gather(gathered_filters)
            module.exit_json(
                **_format_output(
                    module,
                    nd_state_machine,
                    before=[],
                    after=[],
                    diff=[],
                    changed=False,
                    gathered=gathered,
                )
            )
            return

        nd_state_machine.manage_state()
        if not module.check_mode:
            nd_state_machine.model_orchestrator.deploy_pending()
        module.exit_json(**_format_output(module, nd_state_machine))

    except (ValidationError, ValueError) as exc:
        module_log.exception("Interface Group input validation failed")
        output = _format_output(module, nd_state_machine, changed=False)
        module.fail_json(
            msg=f"Module validation failed: {exc}",
            **output,
        )

    except NDStateMachineError as exc:
        module_log.exception("NDStateMachineError during Interface Group execution")
        output = _format_output(module, nd_state_machine)
        error_msg = f"Module execution failed: {exc}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)

    except Exception as exc:  # pylint: disable=broad-except
        module_log.exception("Unhandled exception during Interface Group execution")
        output = _format_output(module, nd_state_machine)
        error_msg = f"Module failed: {exc}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
