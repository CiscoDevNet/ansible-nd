#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nd_interfaces_workflow
version_added: "2.0.0"
short_description: Manage multiple Cisco Nexus Dashboard interface families with one shared snapshot
description:
- Coordinates several interface resource families in one module execution.
- Validates and plans every resource group before the first possible mutation.
- Fetches the complete configured-interface inventory once per targeted switch and shares it across all requested families.
- Each O(resources[].config) uses the authoritative input contract and validation logic of the standalone module selected by
  O(resources[].type).
- Check mode returns the complete multi-family plan, aggregate diff, conflicts, and request statistics without sending mutation or
  deployment requests.
- Normal mode executes the complete validated plan in dependency-safe order, consolidates deferred remove and deploy actions, and
  refetches affected switches to report actual controller state.
author:
- Mike Wiebe (@mikewiebe)
options:
  fabric_name:
    description:
    - Name of the Nexus Dashboard fabric containing the interfaces.
    type: str
    required: true
  resources:
    description:
    - Ordered interface resource groups to validate and plan together.
    - Repeated values of O(resources[].type) are supported; results retain C(resource_index) so groups are not collapsed.
    - The coordinator rejects ownership, policy-transition, delete/write, override, and physical-member conflicts across groups.
    type: list
    elements: dict
    required: true
    suboptions:
      type:
        description:
        - Selects the standalone interface contract used to validate O(resources[].config).
        - V(ethernet_access) uses M(cisco.nd.nd_interface_ethernet_access).
        - V(ethernet_trunk_host) uses M(cisco.nd.nd_interface_ethernet_trunk_host).
        - V(loopback) uses M(cisco.nd.nd_interface_loopback).
        - V(port_channel_access) uses M(cisco.nd.nd_interface_port_channel_access).
        - V(port_channel_trunk_host) uses M(cisco.nd.nd_interface_port_channel_trunk_host).
        - V(subinterface_managed) uses M(cisco.nd.nd_interface_subinterface_managed).
        - V(subinterface_unmanaged) uses M(cisco.nd.nd_interface_subinterface_unmanaged).
        - V(svi) uses M(cisco.nd.nd_interface_svi).
        - V(vpc_access) uses M(cisco.nd.nd_interface_vpc_access).
        - V(vpc_trunk_host) uses M(cisco.nd.nd_interface_vpc_trunk_host).
        type: str
        required: true
        choices:
        - ethernet_access
        - ethernet_trunk_host
        - loopback
        - port_channel_access
        - port_channel_trunk_host
        - subinterface_managed
        - subinterface_unmanaged
        - svi
        - vpc_access
        - vpc_trunk_host
      state:
        description:
        - Desired state for this resource group.
        - V(merged) creates missing resources and merges supplied fields when the current policy already belongs to the selected family.
          If an explicitly listed interface has a different eligible policy in the same structural interface domain, it performs an
          implicit policy transition and applies the selected family's desired configuration.
        - V(replaced) replaces the fields of explicitly listed resources. If the current policy belongs to another eligible family in the
          same structural interface domain, it performs the same implicit policy transition.
        - V(overridden) treats this family's configuration as authoritative and expands interface inventory scope to the complete fabric.
          It does not claim unlisted interfaces owned by other policy families.
        - V(deleted) acts on each explicitly listed identity regardless of its current policy family, provided the current interface is in
          the same structural domain and is safe to delete. Physical Ethernet interfaces are reset to the unconfigured fabric-default
          policy; deletable logical interfaces are removed.
        - All ten initial interface adapters support all four values.
        type: str
        choices: [ merged, replaced, overridden, deleted ]
        default: merged
      config:
        description:
        - Interface configuration using the same list-of-dictionaries shape accepted by the standalone module selected by
          O(resources[].type).
        - Interface-specific fields, constraints, defaults, and examples intentionally remain documented by that standalone module.
        - Validation errors identify the resource index, selected type, model, state, and standalone module.
        type: list
        elements: dict
        required: true
  config_actions:
    description:
    - Controls actions coordinated after all interface mutation groups complete.
    - Deployment is attempted only after every planned interface mutation succeeds. A mutation failure stops later writes and deployment.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether changed interfaces should be deployed in one consolidated action after successful mutation groups.
        - Has no side effect in check mode.
        type: bool
        default: false
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is supported only on Cisco Nexus Dashboard.
- C(cisco.nd.nd_interface_flow_rules) is intentionally outside this workflow and is not a valid O(resources[].type).
- A non-overridden workflow reads only the union of switches named by its resource groups. Any V(overridden) group expands the shared
  inventory scope to all switches in the fabric.
- vPC groups load the complete intended fabric vPC-pair inventory with deterministic pagination in the same execution. They reject
  missing, self-referential, conflicting, or inverse-inconsistent pair records.
- vPC identity is pair-scoped. Equal vPC names on different pairs are planned independently, while both peer echoes for one pair are
  required and treated as one resource.
- For V(merged) and V(replaced), O(resources[].type) is the desired policy family. An explicitly listed interface using another eligible
  policy in the same structural interface domain is changed with one destination-family replacement request; no separate transition
  option is required.
- A policy transition is rejected before writes when controller safety metadata, structural type, vPC peer consistency, port-channel or
  vPC membership, or parent-child interface dependencies make the change unsafe.
- Current and final physical members of port-channel and vPC interfaces are protected from independent Ethernet resets, transitions,
  creates, and non-whitelisted updates, including when operational membership data is stale.
- Ethernet and port-channel parents cannot be mutated in the same workflow as a child-subinterface mutation and cannot be changed while
  an existing child subinterface remains. Managed and unmanaged subinterface writes require an existing routed parent configured in a
  prior workflow; V(routedHost) for Ethernet or V(l3PortChannel) for a port-channel.
- For V(deleted), the selected type supplies the input and execution contract, but explicit identity lookup is policy-independent within
  that structural interface domain. A physical Ethernet delete resets the interface to the unconfigured default instead of removing the
  physical interface.
- An unconfigured default V(trunkHost) physical interface retains the ordinary bulk-create path and is never converted into a
  per-interface transition, preserving the workflow's scale advantage.
- Interface inventories and transition/delete safety data are shared for the complete workflow. They are not fetched once per resource
  group or once per interface; pagination may require more than one GET for a switch or fabric-level safety inventory.
- The authoritative vPC-pair map is shared with all vPC resource orchestrators, preventing repeated per-resource peer-lookup GETs.
- The shared snapshot is execution-scoped and is never accepted from arbitrary caller input or persisted across Ansible tasks.
- Normal-mode execution uses the same current interface model and orchestrator contracts as the standalone modules, so merged validation,
  normalization, and deployment behavior is inherited automatically.
- Deletes and deferred normalize/reset operations run before transitions, updates, and creates. Deployments are consolidated across
  compatible resource groups.
- The Ethernet V(routedHost) to V(accessHost) and V(accessHost) to V(trunkHost) cross-policy PUTs have been live-qualified during this
  development effort. Destination orchestrators exist for port-channel, vPC, managed and unmanaged subinterface, SVI, loopback, and other
  Ethernet transitions, but those source/destination combinations must be live-qualified against the intended Nexus Dashboard release
  and fabric type before production use. Architectural support is not a claim of live qualification.
- The executor stops after the first failed mutation phase, does not replay mixed-success requests, reports succeeded, failed, uncertain,
  skipped, and not-attempted items, and refreshes affected switches after any mutation request.
"""

EXAMPLES = r"""
- name: Configure several interface families with one shared snapshot
  cisco.nd.nd_interfaces_workflow:
    fabric_name: FABRIC1
    resources:
      - type: loopback
        state: merged
        config:
          - switch_ip: 192.168.1.11
            interface_name: loopback10
            config_data:
              network_os:
                policy:
                  ip: 192.0.2.10
                  description: Router ID
      - type: ethernet_access
        state: merged
        config:
          - switch_ip: 192.168.1.11
            interface_names:
              - Ethernet1/10
              - Ethernet1/11
            config_data:
              network_os:
                policy:
                  admin_state: true
                  access_vlan: 100
                  description: Application servers
      - type: port_channel_trunk_host
        state: replaced
        config:
          - switch_ip: 192.168.1.12
            interface_name: port-channel20
            config_data:
              network_os:
                policy:
                  allowed_vlans: "100-200"
                  ports:
                    - Ethernet1/20
                    - Ethernet1/21
                  port_channel_mode: active
    config_actions:
      deploy: true
  register: interface_result

- name: Preview a fabric-wide authoritative SVI group
  cisco.nd.nd_interfaces_workflow:
    fabric_name: FABRIC1
    resources:
      - type: svi
        state: overridden
        config:
          - switch_ip: 192.168.1.11
            interface_name: vlan100
            config_data:
              network_os:
                policy:
                  ip: 192.0.2.1
                  prefix: 24
  check_mode: true

- name: Converge a routed or dot1q-tunnel interface to the Ethernet access policy
  cisco.nd.nd_interfaces_workflow:
    fabric_name: FABRIC1
    resources:
      - type: ethernet_access
        state: merged
        config:
          - switch_ip: 192.168.1.11
            interface_names:
              - Ethernet1/40
            config_data:
              network_os:
                policy:
                  admin_state: true
                  access_vlan: 3900
    config_actions:
      deploy: false

- name: Reset an explicitly named physical interface regardless of its current policy
  cisco.nd.nd_interfaces_workflow:
    fabric_name: FABRIC1
    resources:
      - type: ethernet_access
        state: deleted
        config:
          - switch_ip: 192.168.1.11
            interface_names:
              - Ethernet1/40
    config_actions:
      deploy: false
"""

RETURN = r"""
changed:
  description:
  - In check mode, whether the plan contains at least one transition, create, update, or delete.
  - In normal mode, whether mutation responses or the reconciled actual state show a controller change.
  returned: always
  type: bool
planned_changed:
  description: Whether the validated aggregate plan contains at least one mutation.
  returned: always
  type: bool
check_mode:
  description: Whether the module executed in Ansible check mode.
  returned: always
  type: bool
output_level:
  description: Output detail level selected for the task.
  returned: always
  type: str
fabric_name:
  description: Fabric used by the shared snapshot and every resource group.
  returned: always
  type: str
config_actions:
  description: Coordinated action settings accepted by the task.
  returned: always
  type: dict
mutation_count:
  description: Total number of planned transitions, creates, updates, and deletes across resource groups.
  returned: always
  type: int
target_switch_ids:
  description: De-duplicated switch serial numbers loaded into the shared interface snapshot.
  returned: always
  type: list
  elements: str
resources:
  description:
  - Ordered per-resource-group results. Repeated interface types remain separate through C(resource_index).
  returned: always
  type: list
  elements: dict
  contains:
    resource_index:
      description: Zero-based position of the group in O(resources).
      type: int
    type:
      description: Interface family discriminator.
      type: str
    module:
      description: Standalone module that supplied the authoritative model and validation contract.
      type: str
    state:
      description: State planned for this group.
      type: str
    transitions:
      description: One-request implicit policy transitions planned for this group.
      type: list
      elements: dict
      contains:
        action:
          description: Always V(transition).
          type: str
        switch_ip:
          description: Management IP of the target switch.
          type: str
        switch_id:
          description: Controller serial identity of the target switch.
          type: str
        interface_name:
          description: Interface name.
          type: str
        from_policy_type:
          description: Current controller policy discriminator.
          type: str
        to_policy_type:
          description: Destination controller policy discriminator.
          type: str
    changed:
      description:
      - Whether C(before) and the reported C(after) differ.
      - In check mode this is prospective; in normal mode it is actual when reconciliation succeeds.
      type: bool
    planned_changed:
      description: Whether this group had a planned transition, create, update, or delete.
      type: bool
    before:
      description: Existing selected family configuration before execution.
      type: list
      elements: dict
    after:
      description: Prospective family configuration in check mode and reconciled actual configuration after normal-mode writes.
      type: list
      elements: dict
    after_verified:
      description: Whether C(after) represents observed controller state rather than an unverified plan after a reconciliation failure.
      type: bool
    diff:
      description: An Ansible-style C(before) and C(after) dictionary, or an empty dictionary when the collections match.
      type: dict
    proposed:
      description: Normalized user configuration validated by the standalone model.
      returned: when O(output_level) is V(info) or V(debug)
      type: list
      elements: dict
    created:
      description: Models planned for creation.
      type: list
      elements: dict
    updated:
      description: Models planned for update.
      type: list
      elements: dict
    deleted:
      description:
      - Models planned for deletion.
      - Physical Ethernet entries represent reset-to-default operations; deletable logical entries represent removals.
      type: list
      elements: dict
before:
  description: Per-resource C(before) collections retaining resource index and type.
  returned: always
  type: list
  elements: dict
after:
  description: Per-resource prospective C(after) collections retaining resource index and type.
  returned: always
  type: list
  elements: dict
diff:
  description: Per-resource differences retaining resource index and type.
  returned: always
  type: list
  elements: dict
request_stats:
  description: Shared configured-interface inventory, lazy transition/delete safety inventory, vPC context, mutation, deployment, cache,
    refresh, and overlay counters for this execution.
  returned: always
  type: dict
  contains:
    switches:
      description: Number of switches fetched into the interface snapshot.
      type: int
    interface_inventory_gets:
      description: Interface inventory GET requests, including pagination.
      type: int
    interface_inventory_pages:
      description: Interface inventory pages fetched.
      type: int
    interface_inventory_cache_hits:
      description: Family reads served from the shared snapshot.
      type: int
    interface_inventory_refreshes:
      description: Explicit switch refreshes.
      type: int
    interface_inventory_dirty_refetches:
      description: Automatic refetches caused by dirty snapshot state.
      type: int
    interface_summary_switches:
      description: Number of switches fetched into the lazy transition/delete safety summary cache.
      type: int
    interface_summary_gets:
      description: Interface-summary safety GET requests, including pagination.
      type: int
    interface_summary_pages:
      description: Interface-summary safety pages fetched.
      type: int
    interface_summary_cache_hits:
      description: Safety lookups served from the shared interface-summary cache.
      type: int
    snapshot_overlays:
      description: Atomic known-success overlays applied to the snapshot.
      type: int
    vpc_pair_gets:
      description: Fabric vPC-pair inventory GETs.
      type: int
    mutation_requests:
      description: Interface mutation requests sent.
      type: int
    deploy_requests:
      description: Consolidated deployment requests sent.
      type: int
execution:
  description: Execution status and write counters.
  returned: always
  type: dict
  contains:
    status:
      description: One of V(check_mode), V(no_change), V(completed), V(staged), V(failed), or V(partial_failure).
      type: str
    mutations_sent:
      description: Number of non-GET, non-deployment mutation requests sent.
      type: int
    deployments_sent:
      description: Number of consolidated deployment requests sent.
      type: int
    affected_switch_ids:
      description: Switch serial numbers refreshed after mutation requests.
      type: list
      elements: str
    items:
      description: Per-planned-mutation execution status, identity, transition source and destination policy types when applicable, and
        controller message when available.
      type: list
      elements: dict
    deployment:
      description: Consolidated deployment request, target, and partial-success details.
      type: dict
    errors:
      description: Execution and reconciliation errors collected for the failed result.
      type: list
      elements: str
conflicts:
  description: Structured cross-family conflicts collected before mutation.
  returned: on conflict
  type: list
  elements: dict
msg:
  description: Human-readable validation, conflict, prerequisite, or unexpected failure.
  returned: on failure
  type: str
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import (
    InterfaceWorkflowCoordinator,
    InterfaceWorkflowExecutionFailed,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowConflictError,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import (
    config_actions_spec,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_plan import (
    SUPPORTED_STATES,
)


def interface_workflow_argument_spec():
    """Return the workflow-only argspec while family models remain authoritative."""
    argument_spec = nd_argument_spec()
    argument_spec.update(
        {
            "fabric_name": {"type": "str", "required": True},
            "resources": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {
                    "type": {
                        "type": "str",
                        "required": True,
                        "choices": list(INTERFACE_FAMILY_ADAPTERS),
                    },
                    "state": {
                        "type": "str",
                        "default": "merged",
                        "choices": sorted(SUPPORTED_STATES),
                    },
                    "config": {"type": "list", "elements": "dict", "required": True},
                },
            },
        }
    )
    argument_spec.update(config_actions_spec(include=("deploy",)))
    return argument_spec


def main():
    """Run the public aggregate workflow module."""
    module = AnsibleModule(argument_spec=interface_workflow_argument_spec(), supports_check_mode=True)
    require_pydantic(module)
    try:
        module.exit_json(**InterfaceWorkflowCoordinator(module=module).run())
    except InterfaceWorkflowExecutionFailed as exc:
        module.fail_json(msg=str(exc), **exc.result)
    except InterfaceWorkflowConflictError as exc:
        module.fail_json(
            msg=str(exc),
            changed=False,
            conflicts=[conflict.to_dict() for conflict in exc.conflicts],
        )
    except InterfaceWorkflowValidationError as exc:
        module.fail_json(msg=str(exc), changed=False)
    except Exception as exc:  # pylint: disable=broad-except
        module.fail_json(msg=f"Unexpected interface workflow error: {exc}", changed=False)


if __name__ == "__main__":
    main()
