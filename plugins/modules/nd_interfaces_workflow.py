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
        - V(merged) creates missing resources and merges supplied fields into existing resources.
        - V(replaced) replaces the fields of the explicitly listed resources according to the selected standalone model.
        - V(overridden) treats this family's configuration as authoritative and expands interface inventory scope to the complete fabric.
        - V(deleted) removes the listed resources that currently exist.
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
        default: true
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is supported only on Cisco Nexus Dashboard.
- C(cisco.nd.nd_interface_flow_rules) is intentionally outside this workflow and is not a valid O(resources[].type).
- A non-overridden workflow reads only the union of switches named by its resource groups. Any V(overridden) group expands the shared
  inventory scope to all switches in the fabric.
- vPC groups load authoritative fabric vPC-pair inventory in the same execution and reject a configured switch that is not paired.
- Sibling policy-type transitions are rejected unless an explicit, tested transition sequence is added; they are never inferred as an
  independent create.
- The shared snapshot is execution-scoped and is never accepted from arbitrary caller input or persisted across Ansible tasks.
- Normal-mode execution uses the interface model and orchestrator contracts currently present in the develop branch. Outstanding interface
  pull-request behavior is intentionally deferred until those pull requests merge.
- Deletes run before updates and creates. Deferred logical removes, Ethernet normalize/reset operations, and deployments are consolidated
  across compatible resource groups.
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
"""

RETURN = r"""
changed:
  description:
  - In check mode, whether the plan contains at least one create, update, or delete.
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
  description: Total number of planned creates, updates, and deletes across resource groups.
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
    changed:
      description:
      - Whether C(before) and the reported C(after) differ.
      - In check mode this is prospective; in normal mode it is actual when reconciliation succeeds.
      type: bool
    planned_changed:
      description: Whether this group had a planned create, update, or delete.
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
      description: Models planned for deletion.
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
  description: Shared inventory, vPC context, mutation, deployment, cache, refresh, and overlay counters for this execution.
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
      description: Per-planned-mutation execution status, identity, and controller message when available.
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
    module = AnsibleModule(
        argument_spec=interface_workflow_argument_spec(), supports_check_mode=True
    )
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
        module.fail_json(
            msg=f"Unexpected interface workflow error: {exc}", changed=False
        )


if __name__ == "__main__":
    main()
