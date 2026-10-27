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
- Shares a complete configured-interface snapshot across the requested families on each targeted switch.
- Keeps that complete family inventory internal for planning and safety while reporting only explicitly requested identities for
  V(merged), V(replaced), and V(deleted). V(overridden) continues to report its complete authoritative family scope.
- Each O(resources[].config) uses the authoritative input contract and validation logic of the standalone module selected by
  O(resources[].type).
- Check mode returns the complete multi-family plan, per-resource operation changes, prospective deployment-only targets, and request
  statistics without sending mutation or deployment requests. Validation conflicts are returned on failure.
- Normal mode executes the complete validated plan in dependency-safe order and consolidates compatible deferred remove and deploy
  actions. A newly routed parent needed by a same-workflow subinterface is an exception that requires an earlier parent deployment.
  Successful mutations return projected intended state by default; O(verify.enabled=true) refetches affected switches to report observed
  controller state. With O(config_actions.deploy=true), the module can also deploy previously staged intent for explicitly requested
  interfaces, alongside new interface mutations or on its own.
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
    - Repeated values of O(resources[].type) are supported for non-overridden states; results retain C(resource_index) so groups are not collapsed.
    - When a type uses V(overridden), place every desired interface of that type in one resource group's O(resources[].config).
      Multiple groups of that type are rejected before writes.
    - The coordinator rejects ownership, policy-transition, delete/write, override, and physical-member conflicts across groups.
    type: list
    elements: dict
    required: true
    suboptions:
      type:
        description:
        - Selects the standalone interface contract used to validate O(resources[].config).
        - V(ethernet_access) uses M(cisco.nd.nd_interface_ethernet_access).
        - V(ethernet_routed) uses M(cisco.nd.nd_interface_ethernet_routed).
        - Configured V(ethernet_routed) items require C(config_data.network_os.network_os_type). The routed policy discriminator is
          optional and is derived as V(routedHost) for V(nx-os) or V(iosXeRoutedHost) for V(ios-xe). Identifier-only V(deleted) items
          may omit C(config_data).
        - V(ethernet_trunk_host) uses M(cisco.nd.nd_interface_ethernet_trunk_host).
        - V(loopback) uses M(cisco.nd.nd_interface_loopback).
        - Configured V(loopback) items require C(config_data.network_os.network_os_type) plus
          C(config_data.network_os.policy.policy_type). Identifier-only V(deleted) items may omit C(config_data).
        - V(port_channel_access) uses M(cisco.nd.nd_interface_port_channel_access).
        - V(port_channel_routed) uses M(cisco.nd.nd_interface_port_channel_routed).
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
        - ethernet_routed
        - ethernet_trunk_host
        - loopback
        - port_channel_access
        - port_channel_routed
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
        - V(loopback) groups use standalone-family create/update handling for V(merged) and V(replaced), without implicit workflow policy transitions.
        - V(overridden) treats this family's configuration as authoritative and expands interface inventory scope to the complete fabric.
          It does not claim unlisted interfaces owned by other policy families.
          IOS-XE physical Ethernet families retain the standalone modules' merge-only override behavior; unlisted IOS-XE ports are
          not reset. Explicitly name a port with V(deleted) to reset it.
        - V(deleted) acts on each explicitly listed identity regardless of its current policy family, provided the current interface is in
          the same structural domain and is safe to delete. Physical Ethernet interfaces are reset to the unconfigured fabric-default
          policy; deletable logical interfaces are removed.
        - All twelve interface adapters support all four values.
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
    - A mutation failure stops later mutation writes. When O(config_actions.deploy=true), any earlier targets backed by exact controller
      success evidence are still deployed together in one failure-path request; failed, uncertain, and unattempted targets are excluded.
    - Previously staged controller intent for explicitly requested interfaces can be deployed alongside new changes or in a
      zero-mutation workflow when the fabric switch record has an explicit out-of-sync or pending status.
    type: dict
    suboptions:
      deploy:
        description:
        - Whether changed interfaces and explicitly requested interfaces with staged controller intent should be deployed in one
          consolidated action when dependencies allow. A same-workflow subinterface whose routed parent is not yet operationally
          discovered requires an exact parent deployment before the child write, followed by a later child deployment.
        - When V(false), such a parent/child combination fails before any interface write; create and deploy the parent in an earlier
          task, or enable deployment for this workflow. The same preflight applies in check mode.
        - An identical replay after O(config_actions.deploy=false) can therefore perform deployment with no new interface mutation.
        - Check mode reports a prospective deployment but sends no request.
        type: bool
        default: false
  verify:
    description:
    - Controls post-mutation interface-inventory verification.
    - Initial discovery and all planning and safety reads are always performed, regardless of this setting.
    type: dict
    suboptions:
      enabled:
        description:
        - Whether a completely successful mutating workflow refetches affected switch inventories before returning.
        - When V(false), successful writes return projected C(resources[].after) state with C(resources[].after_verified=false), avoiding
          the post-write inventory GETs.
        - No-op and deployment-only runs continue to return observed state from initial discovery. Partial or failed write execution
          forces reconciliation even when this option is V(false).
        type: bool
        default: false
  execution_options:
    description:
    - Optional versioned execution evidence and experimental member-update batching.
    type: dict
    default: {}
    suboptions:
      contract_version:
        description: Requested version of the execution receipt contract.
        type: int
        choices: [1]
        default: 1
      desired_equality:
        description:
        - Return per-target equality from a detached copy of observed inventories without additional controller requests.
        - Mutating workflows require O(verify.enabled=true) for a complete observation. Unsupported scopes return incomplete proof.
        type: bool
        default: false
      observed_satisfaction:
        description:
        - Return a distinct actual-observation receipt for a completely satisfied read-only check-mode preplan.
        - Requires O(config_actions.deploy=false) and O(verify.enabled=false). This is not an apply or postdeployment receipt.
        - Initially qualifies seven ordinary NX-OS families and strict already-reset physical deletions.
        - Unsupported, changing, unknown or incomplete observations decline the proof and retain ordinary execution behavior.
        type: bool
        default: false
      member_batching:
        description:
        - V(disabled) retains singular member PUTs.
        - V(switch_policy) is an opt-in qualification path grouping ready ordinary NX-OS members by switch and member policy.
        - V(experimental_policy) groups by member policy across switches; V(experimental_mixed) permits mixed policies and switches.
        - Experimental grouping modes require separate bounded live qualification before operational use.
        - Preserves member safety checks and dependency barriers. IOS-XE and paired vPC member policies retain the singular path.
        type: str
        choices: [disabled, switch_policy, experimental_policy, experimental_mixed]
        default: disabled
  profile:
    description:
    - Include aggregate phase, CPU, transport-attempt, and logical JSON-size measurements for performance experiments.
    - Phase timings are inclusive and can overlap; JSON byte counts exclude HTTP/TLS overhead. No payloads or responses are returned.
    type: bool
    default: false
  output_level:
    description:
    - Controls the workflow's nested result detail; it does not add standalone-module top-level C(current), C(previous), or C(sent) keys.
    - V(normal) returns target-scoped C(resources[].before) and C(resources[].after) with the operation ledger.
    - V(info) also returns C(resources[].proposed).
    - V(debug) also returns C(resources[].family_before) and C(resources[].family_after). Raw REST/debug payload keys from the common
      module fragment are not emitted by this workflow result.
    type: str
    choices: [debug, info, normal]
    default: normal
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is supported only on Cisco Nexus Dashboard.
- C(cisco.nd.nd_interface_flow_rules) is intentionally outside this workflow and is not a valid O(resources[].type).
- C(cisco.nd.nd_manage_links) manages fabric-link resources rather than a host-interface family and is not a valid
  O(resources[].type). Link-owned interfaces remain protected from host-interface transitions and resets.
- A non-overridden workflow reads only the union of switches named by its resource groups. Any V(overridden) group expands the shared
  inventory scope to all switches in the fabric.
- vPC groups load the complete intended fabric vPC-pair inventory with deterministic pagination in the same execution. They reject
  missing, self-referential, conflicting, or inverse-inconsistent pair records.
- vPC identity is pair-scoped. Equal vPC names on different pairs are planned independently, while both peer echoes for one pair are
  required and treated as one resource.
- vPC peer identity is resolved by the module and is not exposed as a user-configurable C(peer_switch_id) field or an operation change.
- For non-loopback groups with V(merged) or V(replaced), O(resources[].type) is the desired policy family. An explicitly listed interface
  using another eligible policy in the same structural interface domain is changed with one destination-family replacement request;
  no separate transition option is required.
- V(loopback) groups with V(merged) or V(replaced) use the standalone loopback family's ordinary create/update planning and API requests.
  An existing operational row without a managed loopback policy does not trigger a workflow source-policy check or transition.
  No additional summary queries, polling, or refresh retries are added for loopback creation or updates.
- Configured V(loopback) items require both C(network_os_type) and C(policy_type); the workflow does not invent discriminator defaults.
  Identifier-only V(deleted) loopback items remain valid without C(config_data).
- Configured V(ethernet_routed) items require C(network_os_type). The standalone model derives the matching routed policy when
  C(policy_type) is omitted. A configured item cannot change between V(nx-os) and V(ios-xe) during an implicit transition.
- The managed V(loopback) scope comprises NX-OS C(loopback), C(ipfmLoopback), and C(mplsLoopback), plus IOS-XE C(iosXeLoopback),
  C(iosXeLoopbackShutNoshut), C(iosXeUnderlayLoopback), C(iosXeInternalLoopback), C(csrLoopback), and C(csr1kvLoopback).
  V(overridden) is authoritative across those nine policies but excludes C(userDefined) and system-owned NX-OS C(underlayLoopback).
- A policy transition is rejected before writes when controller safety metadata, structural type, vPC peer consistency, port-channel or
  vPC membership, or parent-child interface dependencies make the change unsafe.
- Current and final physical members of port-channel and vPC interfaces are protected from Ethernet resets, detach/reparent requests,
  ambiguous ownership, and non-whitelisted updates, including when operational membership data is stale. A supported existing member can
  change only C(admin_state), C(description), and C(extra_config) through its matching Ethernet family with V(merged).
- A retained aggregate-parent mutation is ordered before a safe update to one of its existing members. For a new IOS-XE port-channel,
  the registry-required Ethernet host-policy conversion is ordered before the parent attaches that member. The member policy itself is
  never synthesized by the workflow.
- Managed and unmanaged subinterface writes require a routed parent. Accepted policies are V(routedHost) or V(iosXeRoutedHost) for Ethernet, and V(l3Po) or
  V(iosXeL3PortChannel) for a port-channel, with matching network OS. A compatible routed parent may be created or transitioned in the
  same workflow when deployment is enabled. If the parent is not already operationally routed, the workflow writes and deploys only
  that parent, waits for the controller's discovered mode to become routed, then writes the child and deploys the remaining targets.
  With deployment disabled, this combination fails preflight without writes. A planned child delete executes before its parent mutation;
  an unplanned existing child continues to block that parent mutation.
- For V(deleted), the selected type supplies the input and execution contract, but explicit identity lookup is policy-independent within
  that structural interface domain. A physical Ethernet delete resets the interface to the unconfigured default instead of removing the
  physical interface.
- For V(ethernet_routed), an NX-OS delete resets the physical port to the default V(trunkHost) policy. An IOS-XE delete keeps the physical
  port under V(iosXeRoutedHost) but clears its configurable policy fields to the IOS-XE template defaults.
- An unconfigured default V(trunkHost) physical interface retains the ordinary bulk-create path and is never converted into a
  per-interface transition, preserving the workflow's scale advantage.
- Interface inventory and safety data must be complete and internally consistent before planning or mutation; incomplete or
  contradictory controller results cause the workflow to fail safely.
- O(verify.enabled) affects only the post-write refresh for a completely successful mutating workflow. Its default V(false) avoids those
  additional inventory GETs and reports projected state with C(resources[].after_verified=false). Initial discovery, validation, and
  safety reads are unchanged.
- No-op and deployment-only workflows report observed initial state. Partial or failed writes force a post-write reconciliation attempt
  even when O(verify.enabled=false), so mixed or uncertain outcomes are diagnosed against current controller state when possible.
- On supported ND 4.3.1 controllers, eligible NX-OS logical creates can be grouped across interface families after exact identity,
  vPC-pair, member, and routed-parent safety checks. Unqualified creates, including IOS-XE and member-bearing parents, retain their
  established family paths. Physical Ethernet interfaces already exist and are managed through policy assignments instead of logical creates.
- Only an explicitly reported out-of-sync or pending switch status qualifies an explicitly requested interface for staged-intent
  deployment; an in-sync, missing, or unknown status does not.
- Previously staged intent is deployed only for explicitly requested interface identities, together with eligible mutation-produced
  targets. A routed-parent dependency can require an earlier parent deployment. Switch status is coarser than interface status, so an
  explicitly requested interface can be harmlessly redeployed when different pending intent keeps the same switch out of sync;
  unrelated interfaces are never added.
- For a vPC identity, an explicit out-of-sync or pending status on either authoritative peer qualifies the pair-scoped target.
- Deployment-only replay cannot reconstruct interfaces implicitly removed by a prior V(overridden) task because those omitted identities
  are not explicit in the later task. Include an interface explicitly when a later deployment-only action must target it.
- A successful deployment-only run, or its check-mode preview, reports C(changed=true), C(planned_changed=false), and
  C(mutation_count=0). Its per-resource C(changed) values remain false because controller intent did not change.
- Normal-mode execution applies the standalone interface modules' validation and safety contracts. When deployment is enabled,
  compatible targets are consolidated; if a later mutation fails, only earlier targets with confirmed success may still be deployed.
  Failed, uncertain, and unattempted mutation targets are excluded.
- For V(merged), V(replaced), and V(deleted), C(resources[].before) and C(resources[].after) contain only identities explicitly listed in
  that resource group. Aggregate-interface members remain visible inside the requested port-channel or vPC policy instead of being mixed
  into the result as unrelated Ethernet-family records.
- Target-scoped C(before) and C(after) include C(policy_type), including when a requested identity starts in another eligible policy family.
  A deleted logical interface is absent from C(after). A deleted physical NX-OS Ethernet interface remains present with the normalized
  default V(trunkHost) policy; a deleted IOS-XE routed interface remains present with a defaults-only V(iosXeRoutedHost) policy.
- C(resources[].operations) is the single operation ledger. It combines create, update, transition, physical-reset, and logical-delete
  actions with their target identities and execution status; update-like actions can include leaf-level C(changes).
- A member-limited update also reports C(requested_state), C(effective_state), C(member_limited=true), C(applied_fields), and
  C(suppressed_fields). Its projected C(after) preserves the authentic member policy and ownership fields instead of presenting the
  host-shaped model used internally for planning.
- Successful output intentionally omits duplicate top-level snapshots and task-input echoes. C(request_stats) contains interface and
  fabric-link read, cache, refresh, overlay, and vPC metrics; C(execution) exclusively owns mutation and deployment write counters.
- Workflow differences are reported under C(resources[].operations[].changes), not a top-level C(diff) key. The common connection
  documentation applies, but its standalone-module C(current), C(previous), C(sent), and raw REST debug-key descriptions do not describe
  this workflow's return shape.
- At O(output_level=debug), C(resources[].family_before) and C(resources[].family_after) expose the complete selected-family collections
  used for diagnostics.
- Parent/child, parent/member, delete, and policy-transition operations are ordered by their safety dependencies, even when that
  differs from resource-group input order.
- The Ethernet V(routedHost) to V(accessHost) and V(accessHost) to V(trunkHost) cross-policy PUTs have been live-qualified during this
  development effort. Destination orchestrators exist for port-channel, vPC, managed and unmanaged subinterface, SVI, and other
  Ethernet transitions, but those source/destination combinations must be live-qualified against the intended Nexus Dashboard release
  and fabric type before production use. Architectural support is not a claim of live qualification.
- NX-OS and IOS-XE loopback policy changes follow standalone-family planning and have not yet been live-qualified through this workflow.
  IOS-XE loopback integration coverage requires an explicitly declared IOS-XE test switch and is not inferred from NX-OS inventory.
- The workflow stops after a failed mutation phase, does not blindly retry mixed-success requests, and reports succeeded, failed,
  uncertain, skipped, and not-attempted items. It refreshes affected switches after successful writes when O(verify.enabled=true)
  and attempts reconciliation after partial or failed writes. For bulk modify, only exact per-interface success proves an update;
  unconfirmed outcomes fail safely while identifiable successes remain reported separately. Exact omitted-target classification
  for remove/reset responses is tracked separately in issue #533 (IFACE-007).
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
      - type: ethernet_routed
        state: merged
        config:
          - switch_ip: 192.168.1.11
            interface_name: Ethernet1/12
            config_data:
              network_os:
                network_os_type: nx-os
                policy:
                  ip: 198.51.100.1
                  prefix: 30
                  description: Routed service handoff
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
    verify:
      enabled: true
  register: interface_result

- name: Preview dependency ordering and required parent deployment
  cisco.nd.nd_interfaces_workflow:
    fabric_name: FABRIC1
    resources:
      # Resource order does not need to match execution order. The routed parent
      # is created or transitioned before this child.
      - type: subinterface_managed
        state: merged
        config:
          - switch_ip: 192.168.1.11
            interface_name: Ethernet1/52.100
            config_data:
              network_os:
                network_os_type: nx-os
                policy:
                  vlan_id: 100
                  ip: 198.51.100.2
                  prefix: 30
      - type: ethernet_routed
        state: merged
        config:
          - switch_ip: 192.168.1.11
            interface_name: Ethernet1/52
            config_data:
              network_os:
                network_os_type: nx-os
                policy:
                  ip: 198.51.100.1
                  prefix: 30
      # The IOS-XE host conversion is executed before this routed
      # port-channel attaches the physical member.
      - type: port_channel_routed
        state: merged
        config:
          - switch_ip: 192.168.1.21
            interface_name: Port-channel120
            config_data:
              network_os:
                network_os_type: ios-xe
                policy:
                  ip: 203.0.113.1
                  prefix: 30
                  ports:
                    - GigabitEthernet1/0/2
                  port_channel_mode: active
      - type: ethernet_routed
        state: merged
        config:
          - switch_ip: 192.168.1.21
            interface_name: GigabitEthernet1/0/2
            config_data:
              network_os:
                network_os_type: ios-xe
                policy:
                  description: Routed port-channel member
    config_actions:
      deploy: true
  check_mode: true

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
    verify:
      enabled: false

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
  - In normal mode, whether an exact successful mutation response, reconciled actual state, or a successful deployment request shows a
    controller action. Successful mutations remain changed when O(verify.enabled=false) skips readback.
  returned: always
  type: bool
planned_changed:
  description:
  - Whether the validated aggregate plan contains at least one interface mutation.
  - Remains V(false) for deployment-only execution.
  returned: when planning completes, including post-plan execution failures; omitted when planning fails before producing a plan
  type: bool
mutation_count:
  description: Total number of planned creates, updates, transitions, physical resets, and logical deletes across resource groups.
  returned: when planning completes, including post-plan execution failures; omitted when planning fails before producing a plan
  type: int
target_switch_ids:
  description: De-duplicated switch serial numbers loaded into the shared interface snapshot.
  returned: when planning completes, including post-plan execution failures; omitted when planning fails before producing a plan
  type: list
  elements: str
resources:
  description:
  - Ordered per-resource-group results. Repeated interface types remain separate through C(resource_index).
  - Controller-injected vPC C(peer_switch_id) routing metadata is omitted from public C(before), C(after), C(family_before),
    C(family_after), and operation C(changes), while remaining present in mutation payloads.
  returned: when planning completes, including post-plan execution failures; omitted when planning fails before producing a plan
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
        requested_state:
          description: State requested for a member-limited Ethernet update.
          returned: for a safe update to an existing aggregate member
          type: str
        effective_state:
          description: Effective state applied by the member-safe path; currently V(merged).
          returned: for a safe update to an existing aggregate member
          type: str
        member_limited:
          description: Whether the operation is constrained by the authoritative aggregate-member contract.
          returned: for a safe update to an existing aggregate member
          type: bool
        applied_fields:
          description: Explicit safe policy fields applied to the authentic member policy.
          returned: for a safe update to an existing aggregate member
          type: list
          elements: str
        suppressed_fields:
          description:
          - Host-planning fields deliberately excluded from member intent and payload reconstruction.
          - Controller-owned member identity and ownership fields remain preserved from the authentic current policy.
          returned: for a safe update to an existing aggregate member
          type: list
          elements: str
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
      - In check mode this is prospective. In normal mode it compares observed state when C(after_verified=true) and projected state when
        C(after_verified=false).
      - Remains V(false) when this resource is only a target of deployment for already-staged intent.
      type: bool
    planned_changed:
      description: Whether this group had a planned create, update, transition, physical reset, or logical delete.
      type: bool
    before:
      description:
      - Initial observed controller state for the identities explicitly listed by this group when O(resources[].state) is V(merged),
        V(replaced), or V(deleted).
      - For V(overridden), all identities in the selected family's eligible override scope. Omitted IOS-XE physical Ethernet ports are
        outside that scope and are not reset; use an explicit V(deleted) group to reset them.
      - Each returned target includes C(policy_type), so a source policy owned by another eligible family remains visible. Loopback and
        routed-Ethernet input and C(proposed) keep this discriminator nested under C(config_data.network_os.policy), while C(before)
        promotes it to the target top level and omits the duplicate nested key.
      type: list
      elements: dict
    after:
      description:
      - Target-scoped prospective configuration in check mode.
      - After a successful normal-mode mutation, this is reconciled observed state when O(verify.enabled=true) and projected intended
        state when O(verify.enabled=false). Consult C(after_verified) before treating it as controller-observed state.
      - No-op and deployment-only normal-mode runs return observed state from initial discovery. Partial or failed writes force a
        reconciliation attempt even when verification is disabled.
      - Like C(before), each target reports C(policy_type) at top level; loopback and routed-Ethernet input use the nested policy
        discriminator.
      - A removed logical interface is absent. A reset physical NX-OS Ethernet interface remains present with C(policy_type=trunkHost)
        and its normalized default configuration. A reset IOS-XE routed interface remains present with
        C(policy_type=iosXeRoutedHost) and defaults-only policy configuration.
      - For V(overridden), all identities in the selected family's eligible override scope. Omitted IOS-XE physical Ethernet ports are
        outside that scope and are not reset.
      type: list
      elements: dict
    after_verified:
      description:
      - Whether C(after) represents coherent observed controller state rather than projected or unverified state.
      - V(false) follows a successful mutation when O(verify.enabled=false), a failed reconciliation, or reconciliation that cannot
        establish consistent vPC state because a peer record is missing or incoherent.
      - No-op and deployment-only normal-mode runs remain V(true) because C(after) comes from initial observed discovery.
      type: bool
    proposed:
      description: Normalized user configuration validated by the standalone model.
      returned: when O(output_level) is V(info) or V(debug)
      type: list
      elements: dict
    family_before:
      description: Unprojected configuration for the selected family's eligible override scope before execution for diagnostic use.
        Omitted IOS-XE physical Ethernet ports are outside this scope.
      returned: when O(output_level) is V(debug)
      type: list
      elements: dict
    family_after:
      description:
      - Unprojected prospective, projected, or reconciled configuration for the selected family's eligible override scope after
        execution for diagnostic use. Omitted IOS-XE physical Ethernet ports are outside this scope.
      - C(after_verified) identifies whether the result was observed after execution.
      returned: when O(output_level) is V(debug)
      type: list
      elements: dict
request_stats:
  description: Shared configured-interface inventory, lazy transition/delete and fabric-link safety inventory, vPC context, cache,
    refresh, and overlay counters for this execution. Write counters are reported only under C(execution).
  returned: when planning completes, including post-plan execution failures; omitted when planning fails before producing a plan
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
      - A completely successful mutation increments this only when O(verify.enabled=true). Partial or failed write execution can increment
        it even when verification is disabled because reconciliation is forced.
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
    fabric_link_gets:
      description:
      - Fabric-link inventory GET requests used to protect IOS-XE link endpoints from host-interface transitions and resets.
      - The lazy link cache is shared by all routed resource and platform-reset orchestrators in one workflow, including pagination.
      type: int
    vpc_pair_gets:
      description: Fabric vPC-pair inventory GETs.
      type: int
workflow_contract:
  description:
  - Version, capabilities, normalized requested options and C(request_sha256) binding fabric, exact resources and execution semantics.
  returned: after coordinator initialization, including planning failures
  type: dict
write_receipt:
  description:
  - Versioned mutation and deployment dispatch-attempt counts, including failed attempts and lost responses.
  - C(no_mutation_attempted=true) means no mutation or deployment dispatch began; it is bound by C(request_sha256).
  returned: after coordinator initialization, including planning failures
  type: dict
staged_deletions:
  description:
  - Current non-vPC logical deletions independently proved during planning from exact controller tombstones and scoped configuration previews.
  - Bound to the current C(workflow_contract.request_sha256) and advertised by the C(staged_deletions_v1) capability.
  - This establishes staging only. It does not prove a historical accepted write, final interface absence,
    member default configuration, or postdeployment convergence.
  - Consumers requiring a read-only proof must also check the matching C(write_receipt) reports zero mutation and deployment attempts.
  returned: when planning completes
  type: list
  elements: dict
  contains:
    resource_index:
      description: Index of the exact requested resource group.
      type: int
    type:
      description: Requested non-vPC logical interface family.
      type: str
    state:
      description: Always V(deleted).
      type: str
    switch_id:
      description: Exact controller chassis identity.
      type: str
    interface_name:
      description: Canonical requested interface name.
      type: str
    status:
      description: Always V(staged); final absence requires a separate fresh observation after deployment.
      type: str
    raw_observation_sha256:
      description: SHA256 of canonical JSON for the entire actual controller interface row before any name normalization or desired-state projection.
      type: str
    member_interfaces:
      description:
      - Canonical physical members independently named by both this parent's current running channel-group and its pending membership removal.
      - Empty for other logical interfaces. Historical member lists and another parent's members do not grant correction authority.
      type: list
      elements: str
desired_equality:
  description:
  - Versioned cache-only residual planning over actual observed inventories, bound by C(request_sha256).
  - Includes every supported resource's exact targets with satisfied and residual-action evidence.
  - Incomplete, unverified, removal and unqualified generated-vPC scopes cannot certify desired equality.
  returned: when O(execution_options.desired_equality=true) and normal planning completes
  type: dict
observed_satisfaction:
  description:
  - Exact request-bound read-only observation of complete no-op intent, with strict cached raw configuration and ownership checks.
  - C(complete=false) declines reuse; it does not reject an otherwise valid create or update.
  - Never proves logical deletion, vPC generated-footprint recovery or postdeployment convergence.
  returned: when O(execution_options.observed_satisfaction=true) and check-mode planning completes
  type: dict
performance_profile:
  description:
  - Inclusive phase wall/CPU measurements and categorized transport-attempt counts, durations, and logical JSON byte sizes.
  - Available only when O(profile=true). Values are diagnostic measurements, not stable controller throughput guarantees.
  returned: when O(profile=true) and planning completes
  type: dict
execution:
  description: Execution status and write counters.
  returned: when planning completes, including post-plan execution failures; omitted when planning fails before producing a plan
  type: dict
  contains:
    status:
      description: One of V(check_mode), V(no_change), V(completed), V(staged), V(failed), or V(partial_failure).
      type: str
    mutations_sent:
      description: Number of non-GET, non-deployment mutation requests sent.
      type: int
    deployments_sent:
      description: Number of deployment requests sent, including any required routed-parent barrier request.
      type: int
    affected_switch_ids:
      description:
      - Switch serial numbers in the affected scope after mutation requests.
      - They are refreshed after a successful mutation only when O(verify.enabled=true), and are also the forced reconciliation scope for
        partial or failed writes.
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
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
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
            "verify": {
                "type": "dict",
                "options": {
                    "enabled": {"type": "bool", "default": False},
                },
            },
            "profile": {"type": "bool", "default": False},
            "execution_options": {
                "type": "dict",
                "default": {},
                "options": {
                    "contract_version": {"type": "int", "choices": [1], "default": 1},
                    "desired_equality": {"type": "bool", "default": False},
                    "observed_satisfaction": {"type": "bool", "default": False},
                    "member_batching": {
                        "type": "str",
                        "choices": ["disabled", "switch_policy", "experimental_policy", "experimental_mixed"],
                        "default": "disabled",
                    },
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
    setup_logging(module)
    coordinator = InterfaceWorkflowCoordinator(module=module)
    try:
        module.exit_json(**coordinator.run())
    except InterfaceWorkflowExecutionFailed as exc:
        module.fail_json(msg=str(exc), **coordinator.attach_contract(exc.result))
    except InterfaceWorkflowConflictError as exc:
        module.fail_json(
            **coordinator.attach_contract(
                dict(
                    msg=str(exc),
                    changed=False,
                    conflicts=[conflict.to_dict() for conflict in exc.conflicts],
                )
            )
        )
    except InterfaceWorkflowValidationError as exc:
        module.fail_json(**coordinator.attach_contract(dict(msg=str(exc), changed=False)))
    except Exception as exc:  # pylint: disable=broad-except
        module.fail_json(**coordinator.attach_contract(dict(msg=f"Unexpected interface workflow error: {exc}", changed=False)))


if __name__ == "__main__":
    main()
