# nd_manage_links ND 4.x harness parity

## Live validation status

Live ND controller validation was started on 2026-11-03 using the local ND
inventory and the Python 3.11 test environment.

The numbered harness scenario completed successfully:

```text
ok=250 changed=12 unreachable=0 failed=0 skipped=55 rescued=0 ignored=6
```

The six ignored tasks are expected negative-test failures. The 55 skipped tasks
are policy families and optional phases that were not enabled by the focused
numbered run. The numbered lifecycle, gathered round-trip, negative coverage,
REST validation, and cleanup completed with no unexpected failures.

The unnumbered harness scenario also completed successfully:

```text
ok=207 changed=7 unreachable=0 failed=0 skipped=58 rescued=0 ignored=0
```

The 58 skipped tasks are expected because this focused run enabled only the
unnumbered scenario; the other policy families, extended phases, and optional
states were not selected. The unnumbered lifecycle, gathered round-trip, REST
validation, and cleanup completed with no unexpected failures.

The preprovision harness scenario also completed successfully:

```text
ok=202 changed=7 unreachable=0 failed=0 skipped=60 rescued=0 ignored=0
```

The 60 skipped tasks are expected because this focused run enabled only the
preprovision scenario; the other policy families, extended phases, and optional
states were not selected. The preprovision lifecycle, gathered round-trip,
REST validation, and cleanup completed with no unexpected failures.

The Layer2 DCI harness scenario also completed successfully:

```text
ok=208 changed=7 unreachable=0 failed=0 skipped=58 rescued=0 ignored=0
```

The 58 skipped tasks are expected because this focused run enabled only the
Layer2 DCI scenario; the other policy families, extended phases, and optional
states were not selected. The Layer2 DCI lifecycle, gathered round-trip, REST
validation, and cleanup completed with no unexpected failures.

The multisite overlay harness scenario also completed successfully:

```text
ok=208 changed=7 unreachable=0 failed=0 skipped=58 rescued=0 ignored=0
```

The 58 skipped tasks are expected because this focused run enabled only the
multisite overlay scenario; the other policy families, extended phases, and
optional states were not selected. The multisite overlay lifecycle, gathered
round-trip, REST validation, and cleanup completed with no unexpected failures.

The multisite underlay harness scenario also completed successfully:

```text
ok=208 changed=7 unreachable=0 failed=0 skipped=58 rescued=0 ignored=0
```

The 58 skipped tasks are expected because this focused run enabled only the
multisite underlay scenario; the other policy families, extended phases, and
optional states were not selected. The multisite underlay lifecycle, gathered
round-trip, REST validation, and cleanup completed with no unexpected failures.

The eBGP VRF Lite harness scenario also completed successfully:

```text
ok=212 changed=8 unreachable=0 failed=0 skipped=54 rescued=0 ignored=0
```

The 54 skipped tasks are expected because this focused run enabled only the
eBGP VRF Lite scenario; the other policy families, extended phases, and optional
states were not selected. The eBGP VRF Lite lifecycle, gathered round-trip, REST
validation, secret handling, reversed-endpoint coverage, and cleanup completed
with no unexpected failures.

The IPv6 link-local extended scenario completed successfully:

```text
ok=220 changed=7 unreachable=0 failed=0 skipped=53 rescued=0 ignored=0
```

The 53 skipped tasks are expected because this focused run enabled only the
`ipv6LinkLocal` scenario; the other extended policy families, One Manage, and
optional states were not selected. The IPv6 link-local lifecycle, REST
validation, and cleanup completed with no unexpected failures.

The Layer 3 DCI VRF Lite extended scenario completed successfully:

```text
ok=220 changed=7 unreachable=0 failed=0 skipped=53 rescued=0 ignored=0
```

The 53 skipped tasks are expected because this focused run enabled only the
`layer3DciVrfLite` scenario; the other extended policy families, One Manage,
and optional states were not selected. The two-fabric Layer 3 DCI lifecycle,
gathered round-trip, source and destination REST validation, and cleanup
completed with no unexpected failures.

The `userDefined` extended scenario also completed successfully using the
`nd4x_user_defined_link` custom interface template:

```text
ok=220 changed=7 unreachable=0 failed=0 skipped=53 rescued=0 ignored=0
```

The 53 skipped tasks are expected because this focused run enabled only the
`userDefined` scenario; the other extended policy families, One Manage, and
optional states were not selected. The user-defined lifecycle, custom-template
input validation, REST validation, and cleanup completed with no unexpected
failures.

All migrated standard and extended policy families that have been exercised are
now live-passed: numbered, unnumbered, preprovision, Layer2 DCI, multisite
overlay, multisite underlay, eBGP VRF Lite, IPv6 link-local, Layer 3 DCI VRF
Lite, and user-defined links. The remaining extended policy families, One
Manage, and destructive overridden coverage remain pending or lab-gated.
They must not be reported as live-covered until their corresponding runs pass.

The latest destructive numbered run reached the lifecycle but did not pass:

```text
ok=385 changed=13 unreachable=0 failed=1 skipped=30 rescued=0 ignored=1
```

The single failure was the intentional safety assertion
`numbered OVERRIDDEN: Reject unsafe destructive scope`. ND still reported three
active `ethisl` links outside the reserved harness identity on
`<test-fabric>`:

```text
<link-id-1>: <switch-a>/Ethernet1/4 -> <peer-fabric>/<switch-b>/Ethernet1/2
<link-id-2>: <switch-a>/Ethernet1/3 -> <peer-fabric>/<switch-b>/Ethernet1/1
<link-id-3>: <switch-c>/Ethernet1/5 -> <peer-fabric>/<switch-d>/Ethernet1/2
```

This was a harness safety stop, not a module or lifecycle assertion failure;
the destructive `overridden` mutation was not executed. The one ignored task
was the expected conflicting-switch-selector negative test. Overridden live
coverage remains incomplete until the underlying cross-fabric topology is
removed and the complete `<test-fabric>` collection is empty.

## Remaining live coverage and lab limitations

The following coverage remains pending or lab-gated:

- `mplsUnderlay`: live testing was attempted but deferred because ND rejected
  both test fabrics during apply:

  ```text
  Fabric [<mpls-fabric-a>]: MPLS Handoff is not enabled
  Fabric [<mpls-fabric-b>]: MPLS Handoff is not enabled
  ```

  The current Data Center VXLAN EVPN iBGP lab does not expose an editable MPLS
  Handoff setting, and no supported MPLS-SR platform/license combination is
  available in this testbed. This is recorded as a lab capability limitation,
  not a harness failure. Live coverage requires MPLS-SR-capable border devices,
  an eligible ND license tier, and MPLS Handoff enabled and deployed on both
  fabrics.
- `mplsOverlay`: live testing is deferred because the prerequisite MPLS Handoff
  capability is unavailable in the current lab. The scenario also requires two
  supported physical MPLS/SR-capable border switches, one per fabric, deployed
  MPLS underlay connectivity, and usable `loopback100`/`loopback101` resources
  for the eBGP overlay. The available virtual switch platforms cannot provide
  this live coverage.
- `iosXeNumbered`: not live-tested because the required lab setup is
  unavailable. Live validation requires a Campus VXLAN EVPN fabric with two
  compatible Catalyst 9000 IOS-XE switches, suitable reserved interfaces, and
  working ND device management. The current `<unsupported-NX-OS-platform>`
  switches cannot
  provide this coverage.
- `vpcPeerKeepalive`: not live-tested because the lab does not provide the
  required resources: two compatible physical switches configured as an
  operational ND-managed vPC pair, with working peer-link and management
  connectivity. The available switches currently report `vpcConfigured=false`.
- One Manage: not live-tested because the lab does not provide the required
  physical ND-managed switches. Live validation also requires source and
  destination fabrics across multiple ND clusters, cluster-qualified
  credentials, live One Manage REST access, and one reserved physical switch
  endpoint in each fabric.
- Destructive `overridden`: the latest run was stopped by the safety preflight
  because three active cross-fabric `ethisl` links remained in the disposable
  fabric. It requires those topology links to be removed, an isolated fabric
  with no unrelated managed links, and explicit destructive-test opt-in.
- Deferred feature combinations (`auto` scope, switch-ID selectors, eBGP
  password variants, MACsec, QKD, Netflow, and broader field combinations)
  require dedicated harness fixtures and policy-specific live capabilities.

These limitations do not affect the completed standard matrix. They remain
undocumented as live passes until the required lab capabilities and fixtures
are available.

The original integration suite remains unchanged and is still the default target
execution. Harness tasks retain the task-level `never` tag so they are excluded
from the default target run, but callers must not include `never` in the
`--tags` option. Invoke the harness with `nd4x_demo` and the desired
policy-scenario tag so the matching preflight runs first.

The focused live runs use a temporary inventory copy. `ansible-test` does not
accept Ansible playbook `-e` extra-vars; put the runtime variables in the
temporary inventory instead:

```bash
export ANSIBLE_COLLECTIONS_PATHS=/absolute/path/to/ansible_collections
export ND4X_INV=/absolute/path/to/inventory.networking

ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_numbered
```

Set only the desired `nd_test_run_*` variable to `true` in the temporary
inventory for a focused run, and set the other policy flags to `false` or remove
them. The selected fabric, switches, reserved interfaces, scope owner, and
isolation confirmation must also be valid for that scenario.

Run the remaining standard scenarios individually with:

```bash
# nd_test_run_unnumbered=true
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_unnumbered

# nd_test_run_preprovision=true
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_preprovision

# nd_test_run_layer2_dci=true
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_layer2_dci

# nd_test_run_multisite_overlay=true
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_multisite_overlay

# nd_test_run_multisite_underlay=true
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_multisite_underlay

# nd_test_run_ebgp_vrf_lite=true
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo,nd4x_demo_ebgp_vrf_lite
```

For a complete harness review, set `nd_test_run_all=true`. This enables every
non-destructive migrated policy scenario and the target reports both enabled
and skipped scenarios before execution. The legacy default remains
numbered-only.

Run the complete non-destructive matrix with:

```bash
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo
```

The `overridden` scenarios remain separately gated because they can delete
resources outside the requested configuration. Run them only on a dedicated
testbed after adding both explicit opt-ins to the temporary inventory:

```ini
nd_test_nd4x_links_run_overridden=true
nd_test_nd4x_links_destructive_tests=true
```

```bash
ansible-test network-integration nd_manage_links \
  --inventory "$ND4X_INV" \
  --tags nd4x_demo
```

## Scope ownership and safety

The harness requires the selected fabrics, switches, and reserved interfaces
to be dedicated to the run. Set `nd_test_nd4x_links_scope_owner` to a
run-unique owner marker and set `nd_test_nd4x_links_scope_isolated=true` only
after confirming that scope is isolated. Preflight queries ND's switch
interface inventory for every non-preprovision endpoint and fails if a
reserved interface is not physically/discovered on the selected switch.
Preprovision is intentionally exempt because it validates links for offline
switches.

ND does not expose a universal API flag proving that an interface is unused by
all unrelated switch configuration. The ownership variable is therefore an
explicit operator/CI assertion, and the testbed must use dedicated fabrics,
switches, or uniquely allocated interfaces. The harness also takes an atomic
controller-local lock at `<controller-local-lock-path>/nd4x-nd_manage_links-<nd-host>` before any
mutation and records the owner in `owner`. A stale lock may be removed only
after confirming that no harness process is still active. CI systems with a
shared workspace can set `nd_test_nd4x_links_scope_lock_path` to a shared lock
directory to coordinate jobs running on different controller processes.

## Coverage acceptance decision

The module documents fourteen link policy types. The harness has an explicit
decision for each one; a scenario is not considered live-covered merely
because its task file exists. It is live-covered only after the corresponding
scenario is enabled in a compatible lab and completes successfully.

| Module feature | Harness decision | Execution / acceptance condition |
|---|---|---|
| `numbered` | Implemented; default | Runs with the default harness selection and must pass the numbered lifecycle. |
| `unnumbered`, `preprovision`, `layer2Dci`, `multisiteOverlay`, `multisiteUnderlay`, `ebgpVrfLite` | Implemented; opt-in | Enable the corresponding `nd_test_run_*` flag and require a passing lifecycle in the compatible ND lab. |
| `ipv6LinkLocal` | Implemented; live-passed | Completed successfully with the IPv6-enabled fabric and supported switch endpoints. |
| `layer3DciVrfLite` | Implemented; live-passed | Completed successfully using two compatible fabrics and border-capable switch endpoints. |
| `mplsUnderlay` | Implemented; deferred live validation | ND apply was rejected because MPLS Handoff is disabled and cannot be enabled in the current lab. Requires supported MPLS-SR platforms, license capability, and MPLS Handoff deployment. |
| `mplsOverlay` | Implemented; deferred live validation | Requires MPLS Handoff, two supported physical MPLS/SR-capable border switches, deployed underlay connectivity, and usable loopback resources. |
| `userDefined` | Implemented; live-passed | Completed successfully with the `nd4x_user_defined_link` custom interface template, including lifecycle and REST assertions. |
| `iosXeNumbered` | Implemented; not live-tested | The required Campus VXLAN EVPN fabric with two compatible Catalyst 9000 IOS-XE switches and reserved interfaces is not available in the current lab. |
| `vpcPeerKeepalive` | Implemented; not live-tested | Live testing is blocked by the lack of two compatible physical switches configured as an operational ND-managed vPC pair with working management interfaces. |
| `one_manage` scope with `multisiteOverlay` | Implemented; not live-tested | Live testing is blocked by the lack of physical ND-managed switches. It also requires source/destination clusters and fabrics, reserved interfaces on both switches, cluster-qualified credentials, and cluster-qualified REST access. |
| `auto` scope | Deferred as a separate integration scenario | The legacy and harness scenarios use explicit `manage` or `one_manage`; automatic scope selection remains covered by module/unit validation and is not claimed as live integration coverage. |
| `src_switch_id` / `dst_switch_id` selectors | Deferred feature fixture | The harness preflight resolves and validates switch identifiers, but no live mutation claims ID-selector coverage until a dedicated fixture supplies stable IDs and matching reserved endpoints. |
| eBGP password variants | Deferred feature fixture | The standard eBGP case covers one masked password intent. The alternate password/encryption combinations require a compatible ND policy and secret fixture; REST comparisons intentionally exclude all secret values. |
| MACsec fields and secrets | Deferred feature fixture | Requires fabric/device MACsec capability and safe test secrets. No live coverage is claimed without those prerequisites. |
| QKD fields | Deferred feature fixture | Requires KME/QKD infrastructure and certificates; no live coverage is claimed without those prerequisites. |
| Netflow fields | Deferred feature fixture | Requires interfaces with the named Netflow monitors; no live coverage is claimed without those prerequisites. |
| Broader per-policy field combinations | Deferred feature fixture | Each live policy case asserts the fields it declares; combinations outside those fixtures remain explicitly unclaimed until supplied by a compatible lab. |

The target reports `skipped`, `lab_gated_not_selected`, and
`deferred_acceptance` scenarios before harness execution. Therefore a normal
numbered-only run must not be reported as complete module coverage. Use
`nd_test_run_all=true` in a lab satisfying all prerequisites for the full
non-destructive acceptance run. If a prerequisite is unavailable, retain the
feature as lab-gated/deferred and record the lab limitation rather than
claiming the feature is covered.

## Managed-link pagination

ND's `GET /api/v1/manage/links` endpoint supports `max` and `offset`, and
returns continuation state in `meta.counts.remaining`. Harness link paths
request the configured page size (default `10000`) from offset `0`.
Predictive snapshots use the ND4X harness paginator and follow all pages up to
`nd4x_links_max_pages` (default `1000`). Direct preflight, cleanup, and
post-apply reads fail closed unless `meta.counts.remaining` is present and
zero; a truncated collection is never treated as complete state.

## Scenario mapping

| Original suite | Harness replacement | Coverage |
|---|---|---|
| `numbered.yml` | `nd4x_demo_numbered.yml` | Three-link merged create, selector matching/conflict, gathered round-trip, merged update, replaced, overridden, single/bulk delete, cleanup |
| `unnumbered.yml` | `nd4x_demo_unnumbered.yml` | Three-link merged create, gathered round-trip, merged update, replaced, overridden, single/bulk delete, cleanup |
| `preprovision.yml` | `nd4x_demo_preprovision.yml` | Three-link merged create, gathered round-trip, merged update, replaced, overridden, single/bulk delete, cleanup |
| `layer2_dci.yml` | `nd4x_demo_layer2_dci.yml` | Two inter-fabric links, merged update, replaced, gathered round-trip, single/bulk delete, cleanup |
| `multisite_overlay.yml` | `nd4x_demo_multisite_overlay.yml` | Two inter-fabric links, merged update, replaced, gathered round-trip, single/bulk delete, cleanup |
| `multisite_underlay.yml` | `nd4x_demo_multisite_underlay.yml` | Two inter-fabric links, merged update, replaced, gathered round-trip, single/bulk delete, cleanup |
| `ebgp_vrf_lite.yml` | `nd4x_demo_ebgp_vrf_lite.yml` | Two-link lifecycle, gathered round-trip, reversed endpoint declaration, update, secret masking, replaced, single/bulk delete, cleanup |
| `gathered.yml` | `nd4x_demo_gathered.yml` | Read-only gathered result, config-shaped output, no `link_id`, and round-trip idempotency |
| `discriminated_union.yml` | `nd4x_demo_negative.yml` | Invalid policy fields, policy-type change rejection, persistent preprovision intent with realized-field assertions, optional cross-policy delete/recreate with eBGP policy-field assertions |

The negative harness coverage also includes an apply-time failure scenario in
`nd4x_demo_apply_negative.yml`. It uses `check_mode: false` and
`idempotency: false` with a schema-valid configuration targeting a deliberately
nonexistent fabric, then verifies the failure returned by the harness action
plugin. The existing direct negative calls remain responsible for exact
module-validation and discriminated-union error assertions.

The extended harness matrix is opt-in because these cases require additional
fabric capabilities, custom templates, IOS-XE switches, vPC peers, or a
multi-cluster One Manage environment:

| Module feature | Harness scenario | Enable variable |
|---|---|---|
| `ipv6LinkLocal` | Extended manage lifecycle | `nd_test_run_ipv6_link_local=true` |
| `layer3DciVrfLite` | Extended inter-fabric lifecycle | `nd_test_run_layer3_dci_vrf_lite=true` |
| `mplsUnderlay` | Extended inter-fabric lifecycle | `nd_test_run_mpls_underlay=true` |
| `mplsOverlay` | Extended inter-fabric lifecycle | `nd_test_run_mpls_overlay=true` |
| `userDefined` | Extended custom-template lifecycle | `nd_test_run_user_defined=true` |
| `iosXeNumbered` | Extended IOS-XE lifecycle | `nd_test_run_iosxe_numbered=true` |
| `vpcPeerKeepalive` | Extended vPC keepalive lifecycle | `nd_test_run_vpc_peer_keepalive=true` |
| `one_manage` + `multisiteOverlay` | Cluster-qualified lifecycle | `nd_test_run_one_manage=true` |

The extended scenarios use the same harness lifecycle as the original seven
families: pre-test cleanup, predictive snapshot, check mode, apply,
idempotency, gathered round-trip, update, replace, delete, policy-specific
returned-field assertions, and cleanup under `always`. Inter-fabric cases
snapshot both fabric link collections. One Manage uses the same `/manage/links`
surface with `fabricName`, `srcClusterName`, and `dstClusterName` filters, and
the expected link identity includes both cluster names. The One Manage case
now requires both the control-fabric response and a destination-fabric
projection to return the same complete link identity and policy fields. A
lab that does not expose the destination projection must leave this case
disabled rather than treating the control-fabric response as authoritative.

Feature-level coverage is also explicit. The extended matrix can validate
policy families, but a policy-family pass does not claim coverage for every
optional field. `auto` scope, switch-ID selectors, eBGP password variants,
MACsec, QKD, and Netflow require dedicated lab capabilities and values. They
are deferred unless the lab supplies a compatible feature fixture; the target
reports them as deferred instead of silently claiming full module coverage.

The extended matrix is never enabled by default. It requires dedicated
variables for fabrics, switches, cluster names, and (for `userDefined`) the
custom template. The default values are placeholders and must be overridden by
the lab inventory or extra vars. `vpcPeerKeepalive`, `iosXeNumbered`, and
`one_manage` should only be enabled on environments that explicitly support
those resources.

Every mutating harness task snapshots the complete links collection with
`GET /api/v1/manage/links?fabricName=...` before predictive execution, then
validates it again after apply and idempotency. Same-fabric scenarios snapshot one
collection; inter-fabric scenarios snapshot both source and destination fabric
collections so predictive mutations on either side are detected. Setup and cleanup
remain direct module calls so the harness does not hide lifecycle failures.

The target exercises `link_scope: manage` for the single-cluster scenarios and
`link_scope: one_manage` for the explicit cluster-qualified scenario. The One
Manage case is still lab-gated because it requires a real multi-cluster fabric
group and both REST projections described above.

All lifecycle phases reject unexpected extra identities and assert exact
expected collection membership through both module results and independent
REST reads. Preflight validates controller/fabric/switch availability,
reserved physical interfaces where applicable, complete managed-link reads,
scope ownership, and overridden safety. Scope locks remain held through final
cleanup verification.

The ND 4.x preflight validates every enabled fabric and both test switches,
rejects unknown policies or endpoint pairs on reserved interfaces, and requires
the reserved scope to be empty after setup cleanup. Fabric-wide overridden
coverage is disabled by default; request it with
`nd_test_nd4x_links_run_overridden=true` and explicitly opt in with
`nd_test_nd4x_links_destructive_tests=true` on a dedicated testbed.

Each lifecycle phase validates all expected returned links and template inputs,
not only the primary link. Gathered scenarios validate every reserved link and
round-trip the complete gathered configuration.

The lifecycle also generates independent REST expectations from each phase's
complete expected state. Each expected link is matched by source and
destination fabric, switch, interface, and (for One Manage) cluster identity;
its policy, user-defined template, and every non-secret template input are
validated through REST. Delete and override phases assert the full two-ended
identity is absent, and replacement asserts any old identity is absent when
the replacement changes identity. Secret inputs are intentionally excluded
from REST value comparisons because ND masks them; their handling remains
covered by the module-result assertions.
