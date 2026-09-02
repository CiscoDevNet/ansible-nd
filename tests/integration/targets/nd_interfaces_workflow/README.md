<!--
Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
-->

# `nd_interfaces_workflow` network integration target

This target qualifies `cisco.nd.nd_interfaces_workflow` against live Nexus Dashboard fabrics. It exercises all ten interface-family adapters, aggregate lifecycle behavior, shared snapshots, implicit policy transitions, policy-independent explicit deletion, conflicts, output controls, invalid inputs, optional property packs, and guarded cleanup.

## Run the target

Run this as an Ansible **network integration** target from the collection root. Do not use the generic `ansible-test integration` command.

```shell
ansible-test network-integration nd_interfaces_workflow \
  --inventory /absolute/path/to/inventory.yaml \
  --python 3.11 -v --truncate 0
```

Put the target variables in inventory or associated inventory/group variables. The profile selector is exactly `nd_iw_profile`; `nd_iw_test_profile` is not an alias.

| `nd_iw_profile` | Check-mode coverage | Additional live behavior |
|---|---|---|
| `smoke` | Minimal family payloads plus batched merged-create, merged-update, and deleted previews; core aggregation, cache, output, conflict, and request-count checks | Applies the lifecycle, checks idempotency, and cleans reserved identities |
| `full` | Maximal payloads, the replaced preview, implicit-transition metadata, mutex alternatives, invalid cases, optional packs, and all smoke checks | Attempts create/update/replace/delete, merged and replaced accessHost↔trunkHost transitions, opposite-family Ethernet deletion/reset, and prerequisite-approved optional packs when live mutation is enabled |
| `destructive` | Full coverage plus a separately opted-in authoritative `overridden` preview | May apply the guarded fabric-wide override; deployment remains separately gated |

The defaults are `nd_iw_profile: smoke`, `nd_iw_execution_mode: check`, and `nd_iw_enable_live_mutation: false`. Check mode still queries the live controller and validates plans, but it must send no mutation or deployment requests.

Measured on one fabric in the current live setup:

- Smoke profile: **57.56 seconds**
- Full check profile: **306.82 seconds** (about 5 minutes 7 seconds)

These are reference measurements, not timeouts; controller load, latency, and selected families can change runtime. The role is guarded with `run_once`, and selected fabrics run serially to protect the shared lab.
### Scale and request-count invariants

The target treats request counts as part of the module contract:

- Configured-interface inventory is shared by every resource group and fetched per targeted switch and page, never per family or interface.
- Any additional transition/delete safety inventory is shared for the whole workflow rather than repeated for each candidate.
- Intended vPC-pair inventory is fetched once per deterministic page for the fabric. The resulting authoritative peer map is shared by
  every vPC resource group, so access and trunk groups do not repeat per-primary peer-lookup GETs.
- Equal vPC names on different pairs remain independent pair-scoped resources; reciprocal peer echoes must agree.
- A real cross-policy transition uses one destination-family PUT per interface because Nexus Dashboard does not expose a bulk transition API.
- Unconfigured default `trunkHost` ports continue through the established bulk-create path, so ordinary access-port provisioning remains
  one bulk request per switch rather than one PUT per interface.
- Compatible physical resets, logical removals, and deployments remain consolidated. The live Ethernet delete scenario asserts that two
  opposite-family deletes on one switch share one normalize request and send no deployment when deployment is disabled.
- An exact `deploy: true` replay after an earlier `deploy: false` mutation can deploy already-staged intent with zero new interface
  mutations. Candidate selection reuses the fabric switch rows already fetched for identity resolution, adds no GET, and sends all
  qualifying explicitly requested identities in one de-duplicated deployment POST.
- Only an explicitly normalized `outOfSync` or `pending` switch status qualifies for deployment-only execution. An `inSync`, absent, or unknown status
  does not trigger deployment. A vPC target qualifies when either authoritative peer is explicitly out of sync or pending.
- Switch sync status is coarser than interface sync status. Unrelated pending intent on the same switch can therefore cause a harmless
  redeploy of a requested interface, but the request never expands to unrelated interface identities.
- A later replay cannot recover interfaces implicitly removed because they were omitted from an earlier `overridden` resource. A future
  deployment-only task must name each intended target explicitly.

### Compact result contract

The complete configured-family snapshot remains available internally for planning, conflict detection, transition safety, and authoritative
override behavior. Successful public output has one authoritative resource-level representation and deliberately avoids repeating task
inputs or snapshots:

- The top level contains `changed`, `planned_changed`, `mutation_count`, `target_switch_ids`, `resources`, `request_stats`, and
  `execution`. It does not echo `check_mode`, `output_level`, `fabric_name`, or `config_actions`, and it does not duplicate
  `before`, `after`, or `diff`.
- Each ordered resource result retains `resource_index`, `type`, `module`, `state`, `changed`, `planned_changed`, `before`,
  `after`, and `after_verified`.
- `resources[].operations` is the single action ledger. Each entry reports `action`, `switch_ip`, `switch_id`,
  `interface_name`, and `status`. Transitions also report `from_policy_type` and `to_policy_type`. Update, transition, and
  physical-reset entries can report `changes: [{path, before, after}]`; creates and logical deletes omit leaf deltas.
- Physical Ethernet normalization is `action: reset`; logical removal is `action: delete`. Check mode reports `status: planned`.
  Normal mode carries the matching execution outcome into the same operation entry, so `execution.items` is not duplicated.
- `output_level: info` adds `resources[].proposed`. `output_level: debug` adds `resources[].proposed`,
  `resources[].family_before`, and `resources[].family_after`. The selected output level is an input control and is not echoed.
- `request_stats` contains only read, cache, refresh, overlay, and vPC metrics. `execution.mutations_sent` and
  `execution.deployments_sent` are the sole write-request counters.

Resource snapshot scope remains state-aware:

- `merged`, `replaced`, and `deleted` report only identities explicitly listed in the corresponding resource group under `before`
  and `after`.
- `overridden` remains authoritative and reports the complete selected-family scope because omitted resources are intentional mutation
  targets.
- Target records include `policy_type`. Cross-policy transitions and policy-independent deletes therefore show the actual source policy
  in `before` and the destination or normalized policy in `after`.
- Logical deletion removes the requested identity from `after`. Physical Ethernet deletion keeps the requested identity in `after`
  with the normalized default `trunkHost` policy.
- Port-channel and vPC members remain nested in their requested aggregate-interface policy; unrelated Ethernet-family records are not
  added.
- Full-family debug projection and compact operation deltas are derived in memory and require no additional controller GETs.
- A successful deployment-only run, and its prospective check-mode form, reports top-level `changed: true`,
  `planned_changed: false`, and `mutation_count: 0`; each resource remains unchanged. Check mode reports deployment status
  `would_deploy` while both write counters stay zero.

## Live and destructive safety gates

Normal live reconciliation requires both:

```yaml
nd_iw_execution_mode: live
nd_iw_enable_live_mutation: true
```

Selecting authoritative overridden tests, even in check mode, additionally requires:

```yaml
nd_iw_profile: destructive
nd_iw_enable_destructive: true
```

Physical deployment is independently gated by `nd_iw_enable_deploy: true`. Leave it false unless the reserved interfaces may safely be deployed. The target cleans only its reserved identities before and after live execution; `nd_iw_cleanup_strict` defaults to true so cleanup failures fail the run.

With that gate enabled, `deploy_controls.yaml` stages an exact reserved configuration with deployment disabled, previews an identical
deployment-only replay in check mode, performs the identical replay as one zero-mutation deployment, and replays it once more. The final
no-deployment assertion is conditional on the independently observed switch status having converged to `inSync`; a shared switch can
remain out of sync because of unrelated lab intent.

Some shared-lab inventories or wrapper tooling use a `STOP` marker as an operator safety interlock. If one is present, do not delete, bypass, or automate around it. Confirm why the marker was placed, that the fabric and reserved resources are available, and that the owner has authorized the run before clearing it. A stale marker can explain why an otherwise valid invocation does not start, but it must not be assumed stale.

## Fabric and inventory mapping

The supported fabric discriminators are:

- `vxlanEbgp`
- `vxlanIbgp`
- `externalConnectivity`

`aimlVxlanEbgp` and `aimlVxlanIbgp` are intentionally excluded from this target for now. `interface_flow_rules` is also outside this interface-aggregator matrix.

`nd_iw_selected_fabric_types` defaults to all three supported discriminators. For a one-fabric run, set it to a one-item list. Each selected fabric must have an enabled matrix entry, an inventory host present in `hostvars`, the real fabric name, and the management IP of a reserved primary switch. The inventory host must securely supply `ansible_host`, `ansible_user`, and `ansible_password`; do not commit those credentials to this target.

Use the following exact override families:

| Fabric | Inventory/fabric overrides | Switch overrides |
|---|---|---|
| `vxlanEbgp` | `nd_iw_vxlan_ebgp_inventory_host`, `nd_iw_vxlan_ebgp_fabric_name` | `nd_iw_vxlan_ebgp_switch_primary`, plus `nd_iw_vxlan_ebgp_vpc_peer1` and `nd_iw_vxlan_ebgp_vpc_peer2` for vPC families |
| `vxlanIbgp` | `nd_iw_vxlan_ibgp_inventory_host`, `nd_iw_vxlan_ibgp_fabric_name` | `nd_iw_vxlan_ibgp_switch_primary`, plus `nd_iw_vxlan_ibgp_vpc_peer1` and `nd_iw_vxlan_ibgp_vpc_peer2` for vPC families |
| `externalConnectivity` | `nd_iw_external_inventory_host`, `nd_iw_external_fabric_name` | `nd_iw_external_switch_primary`, plus `nd_iw_external_vpc_peer1` and `nd_iw_external_vpc_peer2` for vPC families |

The matrix also defines a `secondary` slot for future scenarios. Both vPC peer management addresses are required when vPC families are selected; independent raw verification binds the expected interface to both authoritative switch serials.

The preflight reads the mapped fabric and, when `nd_iw_verify_fabric_type` is true, requires its observed discriminator to match the matrix. Empty required switch mappings are rejected before test mutation. Operators must verify that every nonempty mapping is a reserved lab resource; preflight does not infer ownership from an address value.

## Interface-family capabilities

Each fabric currently lists the same ten `candidate_families`:

- `ethernet_access`
- `ethernet_trunk_host`
- `loopback`
- `port_channel_access`
- `port_channel_trunk_host`
- `subinterface_managed`
- `subinterface_unmanaged`
- `svi`
- `vpc_access`
- `vpc_trunk_host`

Use `nd_iw_selected_families` to restrict a run. A family is active only when it is selected, is present in the fabric `candidate_families`, is not in `unsupported_families`, is permitted by any optional `supported_families` allow-list, and supports the fabric discriminator in the property matrix. Candidate families declared unsupported are exercised as `nd_iw_unsupported_cases` and must fail in check mode without reporting a change. A per-family string or discriminator/default mapping in `unsupported_expected_error` can constrain the diagnostic.

The checked-in mappings currently declare no unsupported families. Add an exclusion only after collecting controller evidence, and keep it as a subset of `candidate_families`; preflight rejects unknown or inconsistent names. Live setup and cleanup send only active, declared-supported resource types.

## Lab prerequisites

Before selecting a family, reserve controller-visible resources that will not collide with other tests:

- Physical interfaces for Ethernet cases and physical member interfaces for port channels.
- A valid vPC pair and per-peer member interfaces for vPC cases.
- Routed parent interfaces for managed and unmanaged subinterfaces.
- Test-owned loopback, port-channel, subinterface, SVI, vPC, and VLAN identifiers matching the reserved-resource overrides.
- Existing NetFlow monitors/samplers, QoS and queuing policies, and controller/switch support for PFC or VLAN mapping when those optional packs are exercised.

Subinterface writes are intentionally fail-closed in the aggregator. Their Ethernet or port-channel parent must already exist in routed
mode from a separately completed workflow: `routedHost` for Ethernet or `l3PortChannel` for a port-channel. The aggregator rejects a
missing, structurally incompatible, access, or trunk parent before mutation. It also rejects any workflow that mutates a parent and its
child together, and any parent mutation while existing child subinterfaces remain.

Optional live packs are gated by `nd_iw_optional_prerequisites`, a mapping of prerequisite name to boolean. Set a prerequisite true only after verifying the referenced object or hardware capability in that fabric. Check-profile previews prove model normalization and zero-write planning, but they do not prove that a named NetFlow or QoS object exists. Object existence remains a live prerequisite.

Configured loopback cases use the standalone module's discriminated union: `network_os_type` is required and `policy_type` must be one
of the three managed NX-OS policies (`loopback`, `ipfmLoopback`, `mplsLoopback`) or six managed IOS-XE policies (`iosXeLoopback`,
`iosXeLoopbackShutNoshut`, `iosXeUnderlayLoopback`, `iosXeInternalLoopback`, `csrLoopback`, `csr1kvLoopback`) appropriate to that OS.
Identifier-only loopback deletion intentionally omits both discriminators. The checked-in live property matrix covers only the classic
NX-OS `loopback` policy today. IPFM, MPLS, and IOS-XE property packs are explicit follow-up work; IOS-XE requires an explicitly
declared IOS-XE test inventory.

The full check-only profile cannot deterministically preview a sibling-policy transition without first seeding live source state. The full live profile uses the standalone Ethernet access and trunk-host modules to establish deterministic sibling-policy sources, then verifies implicit accessHost↔trunkHost transitions under both `merged` and `replaced`, transition metadata, idempotency, and policy-independent deletion through the opposite Ethernet type. It also verifies that physical deletion resets both interfaces to the default `trunkHost` policy without physical deployment. Other structural domains and source policies remain unit-tested until each combination has a safe, model-backed live setup path; do not use fabric-owned loopbacks, SVIs, peer links, or other controller-owned interfaces merely to manufacture transition coverage.

The Ethernet `routedHost → accessHost` and `accessHost → trunkHost` cross-policy PUTs now have recorded live qualification. The latter was
verified on `nac-msd-fabric1` for `10.122.84.182/Ethernet1/40` with `state: replaced`: one staged PUT, an authoritative post-write refetch,
and a zero-change check-mode replay. Deployment was disabled, so this qualifies controller intent mutation rather than physical switch
deployment. The reverse trunk-to-access scenario and all port-channel, vPC, managed/unmanaged subinterface, SVI, and loopback
cross-policy combinations remain qualification workloads, not completed qualification claims. Run them against each intended Nexus
Dashboard release and fabric type before production use.

Loopback policy changes on the same network OS are planned as explicit transitions for both `merged` and `replaced`; an NX-OS-to-IOS-XE
discriminator change is rejected. Loopback creates batch per `(switch, policy_type)` because Nexus Dashboard does not accept mixed-policy
loopback bulk requests. Interfaces sharing both values still use one POST, and all loopback families continue to reuse the workflow's
single shared per-switch inventory snapshot. These loopback policy-transition PUTs remain pending live qualification.
