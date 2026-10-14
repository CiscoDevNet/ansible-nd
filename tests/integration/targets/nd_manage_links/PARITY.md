# nd_manage_links ND 4.x harness parity

## Live validation status

Live ND controller testing is in progress. The execution results, including
the enabled scenarios, pass/fail status, and any lab-specific limitations, will
be added to this document as soon as testing completes.

The original integration suite remains unchanged and is still the default target
execution. The harness scenarios are registered with `never` tags and can be run
explicitly after the ND 4.x preflight.

Example:

```bash
ansible-test network-integration nd_manage_links \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo,nd4x_demo_preflight,nd4x_demo_numbered \
  -e nd_test_nd4x_links_scope_owner=nd4x-review-<unique-id> \
  -e nd_test_nd4x_links_scope_isolated=true
```

Set the existing `nd_test_run_*` variables to `true` to opt into the other policy
families. The original defaults are preserved: numbered tests run by default and
the other policy families are opt-in.

For a complete harness review, set `nd_test_run_all=true`. This enables every
non-destructive migrated policy scenario and the target reports both enabled
and skipped scenarios before execution. The legacy default remains
numbered-only.

Run the complete non-destructive matrix with:

```bash
ansible-test network-integration nd_manage_links \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo \
  -e nd_test_run_all=true \
  -e nd_test_nd4x_links_scope_owner=nd4x-review-<unique-id> \
  -e nd_test_nd4x_links_scope_isolated=true
```

The `overridden` scenarios remain separately gated because they can delete
resources outside the requested configuration. Run them only on a dedicated
testbed with both explicit opt-ins:

```bash
ansible-test network-integration nd_manage_links \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo \
  -e nd_test_run_all=true \
  -e nd_test_nd4x_links_scope_owner=nd4x-review-<unique-id> \
  -e nd_test_nd4x_links_scope_isolated=true \
  -e nd_test_nd4x_links_run_overridden=true \
  -e nd_test_nd4x_links_destructive_tests=true
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
controller-local lock at `/tmp/nd4x-nd_manage_links-<nd-host>` before any
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
| `ipv6LinkLocal`, `layer3DciVrfLite`, `mplsUnderlay`, `mplsOverlay` | Implemented; lab-gated | Requires compatible fabrics, interfaces, and policy capabilities; enable explicitly and do not count while reported as skipped. |
| `userDefined` | Implemented; lab-gated | Requires a compatible custom template supplied through `nd_test_user_defined_template`. |
| `iosXeNumbered` | Implemented; lab-gated | Requires compatible IOS-XE switches and fabric support. |
| `vpcPeerKeepalive` | Implemented; lab-gated | Requires a compatible vPC pair and management interfaces. |
| `one_manage` scope with `multisiteOverlay` | Implemented; lab-gated | Requires source/destination clusters, fabrics, and cluster-qualified REST access. |
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
