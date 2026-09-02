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
- Keeps that complete family inventory internal for planning and safety while reporting only explicitly requested identities for
  V(merged), V(replaced), and V(deleted). V(overridden) continues to report its complete authoritative family scope.
- Each O(resources[].config) uses the authoritative input contract and validation logic of the standalone module selected by
  O(resources[].type).
- Check mode returns the complete multi-family plan, aggregate diff, conflicts, prospective deployment-only targets, and request
  statistics without sending mutation or deployment requests.
- Normal mode executes the complete validated plan in dependency-safe order, consolidates deferred remove and deploy actions, and
  refetches switches affected by interface mutations to report actual controller state. It can also deploy previously staged intent for
  explicitly requested interfaces when the current workflow has no interface mutations.
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
        - Configured V(loopback) items require C(config_data.network_os.network_os_type) plus
          C(config_data.network_os.policy.policy_type). Identifier-only V(deleted) items may omit C(config_data).
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
    - A zero-mutation workflow can deploy previously staged controller intent for explicitly requested interfaces when the already-fetched
      fabric switch record has an explicit out-of-sync or pending status.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether changed interfaces and explicitly requested interfaces with staged controller intent should be deployed in one
          consolidated action.
        - An identical replay after O(config_actions.deploy=false) can therefore perform deployment with no new interface mutation.
        - Check mode reports a prospective deployment but sends no request.
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
- Controller/orchestrator-resolved vPC C(peerSwitchId) is internal routing metadata. It is injected into mutation payloads but omitted as
  C(peer_switch_id) from public target and family snapshots and from operation C(changes).
- For V(merged) and V(replaced), O(resources[].type) is the desired policy family. An explicitly listed interface using another eligible
  policy in the same structural interface domain is changed with one destination-family replacement request; no separate transition
  option is required.
- Within the V(loopback) family, V(merged) and V(replaced) also treat a same-NOS C(policy_type) change as an explicit
  destination-policy transition. Changing C(network_os_type) is rejected before writes.
- Configured V(loopback) items require both C(network_os_type) and C(policy_type); the workflow does not invent discriminator defaults.
  Identifier-only V(deleted) loopback items remain valid without C(config_data).
- The managed V(loopback) scope comprises NX-OS C(loopback), C(ipfmLoopback), and C(mplsLoopback), plus IOS-XE C(iosXeLoopback),
  C(iosXeLoopbackShutNoshut), C(iosXeUnderlayLoopback), C(iosXeInternalLoopback), C(csrLoopback), and C(csr1kvLoopback).
  V(overridden) is authoritative across those nine policies but excludes C(userDefined) and system-owned NX-OS C(underlayLoopback).
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
- Loopback creates sharing both switch and C(policy_type) remain bulked. Different loopback policy types require one POST per switch and
  policy-type combination because Nexus Dashboard rejects mixed-policy loopback bulk requests; this does not add inventory GETs.
- Deployment-only candidate detection reuses the fabric switch records already fetched to resolve switch identities. It sends no
  additional GET request. Only an explicitly normalized out-of-sync or pending switch status qualifies; an in-sync, missing, or unknown status does
  not cause deployment.
- Deployment-only requests contain only explicitly requested interface identities and are combined with any mutation-produced targets in
  one de-duplicated deployment POST. The switch status is coarser than an interface status, so an explicitly requested interface can be
  harmlessly redeployed when different pending intent keeps the same switch out of sync; unrelated interfaces are never added.
- For a vPC identity, an explicit out-of-sync or pending status on either authoritative peer qualifies the pair-scoped target. The consolidated
  request retains the vPC orchestrator's primary-switch target convention.
- Deployment-only replay cannot reconstruct interfaces implicitly removed by a prior V(overridden) task because those omitted identities
  are not explicit in the later task. Include an interface explicitly when a later deployment-only action must target it.
- A successful deployment-only run, or its check-mode preview, reports C(changed=true), C(planned_changed=false), and
  C(mutation_count=0). Its per-resource C(changed) values remain false because controller intent did not change.
- The authoritative vPC-pair map is shared with all vPC resource orchestrators, preventing repeated per-resource peer-lookup GETs.
- The shared snapshot is execution-scoped and is never accepted from arbitrary caller input or persisted across Ansible tasks.
- Normal-mode execution reuses the current standalone interface models and orchestrator contracts for validation, normalization, and
  mutation payload construction. Final deployment orchestration is workflow-owned; pending targets are consolidated only after every mutation
  phase succeeds. If a later mutation fails, earlier accepted mutations remain staged; no automatic failure-path deployment is performed.
- For V(merged), V(replaced), and V(deleted), C(resources[].before) and C(resources[].after) contain only identities explicitly listed in
  that resource group. Aggregate-interface members remain visible inside the requested port-channel or vPC policy instead of being mixed
  into the result as unrelated Ethernet-family records.
- Target-scoped C(before) and C(after) include C(policy_type), including when a requested identity starts in another eligible policy family.
  A deleted logical interface is absent from C(after); a deleted physical Ethernet interface remains present with the normalized default
  V(trunkHost) policy.
- C(resources[].operations) is the single operation ledger. It combines create, update, transition, physical-reset, and logical-delete
  actions with their target identities and execution status; update-like actions can include leaf-level C(changes).
- Successful output intentionally omits duplicate top-level snapshots and task-input echoes. C(request_stats) contains read, cache,
  refresh, overlay, and vPC metrics; C(execution) exclusively owns mutation and deployment write counters.
- At O(output_level=debug), C(resources[].family_before) and C(resources[].family_after) expose the complete selected-family collections
  used for diagnostics. Result projection is in-memory and sends no additional controller GET requests.
- Deletes and deferred normalize/reset operations run before transitions, updates, and creates. Deployments are consolidated across
  compatible resource groups.
- The Ethernet V(routedHost) to V(accessHost) and V(accessHost) to V(trunkHost) cross-policy PUTs have been live-qualified during this
  development effort. Destination orchestrators exist for port-channel, vPC, managed and unmanaged subinterface, SVI, loopback, and other
  Ethernet transitions, but those source/destination combinations must be live-qualified against the intended Nexus Dashboard release
  and fabric type before production use. Architectural support is not a claim of live qualification.
- In particular, NX-OS and IOS-XE loopback policy-to-policy PUT combinations have not yet been live-qualified through this workflow.
  IOS-XE loopback integration coverage requires an explicitly declared IOS-XE test switch and is not inferred from NX-OS inventory.
- The executor stops after the first failed mutation phase, does not replay mixed-success requests, reports succeeded, failed, uncertain,
  skipped, and not-attempted items, and refreshes affected switches after any mutation request. For HTTP 207 responses, only an exact
  per-item V(success) is successful; missing, warning, notexecuted, unknown, and omitted-target outcomes fail closed while identifiable
  successes remain reported separately.
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
                network_os_type: nx-os
                policy:
                  policy_type: loopback
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

- name: Deploy the same explicitly requested interface after staging it in an earlier task
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
      deploy: true

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
  - In check mode, whether the plan contains a mutation or an explicitly requested deployment-only target.
  - In normal mode, whether mutation responses, reconciled actual state, or a successful deployment request show a controller action.
  returned: always
  type: bool
planned_changed:
  description:
  - Whether the validated aggregate plan contains at least one interface mutation.
  - Remains V(false) for deployment-only execution.
  returned: always
  type: bool
mutation_count:
  description: Total number of planned creates, updates, transitions, physical resets, and logical deletes across resource groups.
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
  - Controller-injected vPC C(peer_switch_id) routing metadata is omitted from public C(before), C(after), C(family_before),
    C(family_after), and operation C(changes), while remaining present in mutation payloads.
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
    operations:
      description:
      - Unified planned or executed operation records for this group.
      - Update, transition, and physical-reset records include C(changes) when their reported before and after values differ.
      - Create and logical-delete records omit C(changes).
      type: list
      elements: dict
      contains:
        action:
          description:
          - One of V(create), V(update), V(transition), V(reset), or V(delete).
          - Physical resets use V(reset); logical removals use V(delete).
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
        status:
          description:
          - V(planned) in check mode.
          - The actual execution outcome in normal mode. HTTP 207 outcomes require an identified exact V(success); any requested target
            without that evidence is V(failed), not V(uncertain).
          type: str
        message:
          description: Controller or execution detail associated with this operation outcome.
          returned: when the controller or executor supplies detail
          type: str
        from_policy_type:
          description: Current controller policy discriminator for a transition.
          returned: for transition operations
          type: str
        to_policy_type:
          description: Destination controller policy discriminator for a transition.
          returned: for transition operations
          type: str
        changes:
          description: Leaf-level differences for update, transition, or physical-reset operations whose reported values differ.
          returned: when an update-like operation has reported differences
          type: list
          elements: dict
          contains:
            path:
              description: Dot-delimited path of the changed property.
              type: str
            before:
              description: Value before the operation.
              type: raw
            after:
              description: Value after the operation.
              type: raw
    changed:
      description:
      - Whether C(before) and the reported C(after) differ.
      - In check mode this is prospective; in normal mode it is actual when reconciliation succeeds.
      - Remains V(false) when this resource is only a target of deployment for already-staged intent.
      type: bool
    planned_changed:
      description: Whether this group had a planned create, update, transition, physical reset, or logical delete.
      type: bool
    before:
      description:
      - Initial observed controller state for the identities explicitly listed by this group when O(resources[].state) is V(merged),
        V(replaced), or V(deleted).
      - For V(overridden), the complete selected-family configuration in the authoritative fabric scope.
      - Each returned target includes C(policy_type), so a source policy owned by another eligible family remains visible. Loopback input
        and C(proposed) keep this discriminator nested under C(config_data.network_os.policy), while C(before) promotes it to the target
        top level and omits the duplicate nested key.
      type: list
      elements: dict
    after:
      description:
      - Target-scoped prospective configuration in check mode and reconciled observed configuration after normal-mode writes.
      - Like C(before), each target reports C(policy_type) at top level; loopback input uses the nested policy discriminator.
      - A removed logical interface is absent. A reset physical Ethernet interface remains present with C(policy_type=trunkHost) and its
        normalized default configuration.
      - For V(overridden), the complete selected-family configuration in the authoritative fabric scope.
      type: list
      elements: dict
    after_verified:
      description:
      - Whether C(after) represents coherent observed controller state rather than an unverified plan after reconciliation failure.
      - V(false) also covers reconciliation that cannot establish consistent vPC state because a peer record is missing or incoherent.
      type: bool
    proposed:
      description: Normalized user configuration validated by the standalone model.
      returned: when O(output_level) is V(info) or V(debug)
      type: list
      elements: dict
    family_before:
      description: Complete unprojected selected-family configuration before execution for diagnostic use.
      returned: when O(output_level) is V(debug)
      type: list
      elements: dict
    family_after:
      description: Complete unprojected prospective or reconciled selected-family configuration after execution for diagnostic use.
      returned: when O(output_level) is V(debug)
      type: list
      elements: dict
request_stats:
  description: Shared configured-interface inventory, lazy transition/delete safety inventory, vPC context, cache, refresh, and overlay
    counters for this execution. Write counters are reported only under C(execution).
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
      description:
      - Number of per-switch interface-inventory refresh attempts explicitly initiated during this execution.
      - A refresh invalidates the execution-scoped local snapshot before loading it again, so the same operation also increments
        C(interface_inventory_dirty_refetches).
      - This is a logical per-switch count. Paginated HTTP requests are counted separately by C(interface_inventory_gets).
      type: int
    interface_inventory_dirty_refetches:
      description:
      - Number of switch-inventory load attempts caused by an execution-scoped local snapshot being marked stale.
      - Local dirty state is unrelated to controller C(configSyncStatus) values such as C(outOfSync) or C(pending).
      - The counter increments once before each dirty switch fetch, including a fetch initiated by an explicit refresh. A switch can
        contribute more than once if it is marked stale and loaded again, and paginated HTTP requests are counted separately by
        C(interface_inventory_gets).
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
    deployment:
      description: Consolidated deployment request, prospective or attempted exact targets, and partial-success details. A check-mode
        deployment-only preview uses V(would_deploy) status without incrementing C(deployments_sent).
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
