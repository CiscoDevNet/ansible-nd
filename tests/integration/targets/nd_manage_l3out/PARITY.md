# `nd_manage_l3out` Harness Parity

This document maps every scenario in the original `nd_manage_l3out` integration
suite to its ND 4.x harness replacement. The original task files remain
enabled while parity is validated against the same controller and fabric.

## Live validation status

Live controller testing of the L3Out response shape, pagination behavior,
create-only ownership claim, and scenario execution is in progress. The test
results and any controller-specific adjustments will be updated in this
`PARITY.md` soon.

## Scenario mapping

| Original scenario | Original file | Harness replacement | Coverage |
|---|---|---|---|
| Reserve the BGP, static, and SVI L3Out names before testing | `tasks/setup.yaml` | Unique-name reservation preflight plus scenario-local owned-resource cleanup in each `nd4x_demo_*.yaml` file | Pre-existing names are rejected; cleanup is limited to proven ownership |
| Create routed BGP L3Out in check mode and normal mode | `tasks/merged.yaml` | `MERGED CREATE` in `nd4x_demo_merged.yaml` | Predictive snapshot, apply, idempotency, returned-state, and REST assertions |
| Re-apply the BGP L3Out and verify no change | `tasks/merged.yaml` | `MERGED IDEMPOTENT` in `nd4x_demo_merged.yaml` | Predictive and real no-change checks plus REST revalidation |
| Create subInterface static L3Out in check mode and normal mode | `tasks/merged.yaml` | Static `MERGED CREATE` in `nd4x_demo_merged.yaml` | Interface type, routing protocol, static route, returned-state, and idempotency checks |
| Create dual-stack SVI L3Out in check mode and normal mode | `tasks/merged.yaml` | SVI `MERGED CREATE` in `nd4x_demo_merged.yaml` | Dual-stack, SVI, BGP, returned-state, and idempotency checks |
| Update BGP hold interval in check mode and normal mode | `tasks/merged.yaml` | `MERGED UPDATE` in `nd4x_demo_merged.yaml` | Updated hold interval, returned-state, REST, and idempotency checks |
| Re-apply the updated BGP L3Out and verify no change | `tasks/merged.yaml` | `MERGED UPDATE` harness idempotency phase | Harness-managed second real application must report `changed: false` |
| Re-apply BGP configuration using management IP switch identifiers | `tasks/merged.yaml` | `MERGED MGMT-IP` in `nd4x_demo_merged.yaml` | Management-IP resolution, predictive no-change, real no-change, and REST checks |
| Replace the static L3Out with routed BGP configuration | `tasks/replaced.yaml` | `REPLACED` in `nd4x_demo_replaced.yaml` | Replacement, routing/interface assertions, returned-state, and idempotency checks |
| Re-apply the replacement in check mode and normal mode | `tasks/replaced.yaml` | `REPLACED IDEMPOTENT` in `nd4x_demo_replaced.yaml` | Dedicated predictive no-change, real no-change, REST, and harness idempotency checks |
| Delete the SVI L3Out in check mode and normal mode | `tasks/deleted.yaml` | `DELETED` in `nd4x_demo_deleted.yaml` | Identifier-only deletion, 404 REST absence, returned-state, and idempotency checks |
| Re-delete the already absent SVI L3Out in check mode and normal mode | `tasks/deleted.yaml` | `DELETED IDEMPOTENT` in `nd4x_demo_deleted.yaml` | Dedicated predictive no-change, real no-change, 404 REST, and harness idempotency checks |
| Bulk-delete BGP and static L3Outs in check mode and normal mode | `tasks/deleted.yaml` | `DELETED BULK` in `nd4x_demo_deleted.yaml` | Bulk deletion, per-resource REST absence, returned-state, and idempotency checks |
| Re-delete the bulk-deleted L3Outs and verify no change | `tasks/deleted.yaml` | `DELETED BULK` harness idempotency phase | Second real bulk deletion must report `changed: false` |

## Harness behavior

- `nd4x_demo_preflight.yaml` gates the scenarios at ND 4.1.0, matching the
  module documentation.
- Harness execution requires `nd_test_l3out_run_id`, which must be unique for
  each run. The preflight embeds it in the three L3Out names and rejects the
  run if any generated name already exists in the target fabric. The generated
  names are also checked against the module's 64-character limit.
- Before harness scenarios mutate the fabric, the harness claims a
  controller-side ownership marker as a temporary, fabric-pair-scoped L3Out
  using a direct create-only `POST /api/v1/manage/l3Outs`. The controller's
  per-item result must report success for the marker; duplicate-name responses
  are rejected. This provides controller-side claim protection assuming the ND
  endpoint enforces create-only name uniqueness; live verification is in
  progress. The marker is deleted only when this run successfully claimed it,
  including failure cleanup through the outer `always` block.
- Switch serials are resolved from the live per-fabric switch inventory by
  management IP before switch, interface, and L3Out checks. The configured
  serial variables remain unchanged in `vars/main.yaml` for legacy coverage,
  but harness configuration uses the discovered IDs so switch replacement is
  handled automatically.
- Harness setup no longer pre-registers names for cleanup. Setup-only L3Outs
  use the controller create-only operation, and merged scenarios add a
  generated name to their ownership list only after the target module proves
  the name was absent in `before` and exists exactly once in `after`. Its
  `always` cleanup deletes only that proven ownership list; failed setup
  creates are not registered. A narrow external create race between the
  target module's read and write cannot be eliminated by this post-create
  proof alone and remains part of live shared-fabric validation.
- Every predictive phase snapshots the complete, paginated unfiltered
  `/api/v1/manage/l3Outs` collection using `collection_key: l3Outs` and
  unordered comparison so L3Outs associated with either participating fabric
  are covered and unrelated collection ordering does not cause false failures.
- The L3Out snapshot explicitly accepts HTTP 404 as an empty collection page,
  matching the module's documented `not_found_ok` behavior. The shared harness
  normalizes that response to an empty collection only for paginated queries.
- The preflight performs a bounded read-only `max=1` page walk before scenarios
  run, validating accepted statuses, `current.l3Outs`, terminal-page behavior,
  page bounds, and non-overlapping L3Out identities across the full response.
- The preflight is scheduled before harness cleanup so the unfiltered
  pagination probe sees the controller's live collection rather than only the
  reserved test state.
- The preflight performs read-only existence checks for every referenced fabric,
  switch, routed/subinterface/SVI endpoint, VRF, and route map before any
  harness mutation. Interface and route-map prerequisites are derived from the
  effective L3Out configuration objects. Optional effective tenant values are
  asserted in both returned module state and persisted REST state whenever
  supplied, including direct `test_tenant*_name` overrides.
- Every harness mutation enables and validates idempotency through the shared
  harness contract.
- Create, update, and replacement assertions verify the complete configured
  L3Out shape: fabric/VRF identity, interface type, every link endpoint,
  addressing and encapsulation, static-route fields, BGP timers/flags,
  default-route behavior, and IPv4/IPv6 peering route maps. These checks cover
  both the module's returned configuration and the persisted REST response.
- REST validation uses the single-L3Out endpoint for exact persisted values and
  expects HTTP 404 plus `expected_failed: true` for deleted resources.
- The original suite has no negative-validation, attach/detach, or destructive
  override scenario; none was added as unrelated harness coverage.

## Tags and execution

Harness scenarios are opt-in and retain the `never` tag while parity is being
validated. The original suite continues to run during this period.

Safe harness scenarios:

```bash
ansible-test network-integration nd_manage_l3out \
  --inventory /absolute/path/to/inventory.networking \
  --extra-vars nd_test_l3out_run_id=ci-job-12345 \
  --tags never,nd4x_demo,nd4x_demo_preflight -vv
```

Use a new run identifier for each concurrent or repeated harness run. Do not
enable an automatic stale-resource cleanup in a shared fabric; inspect and
remove stale resources explicitly before reusing an identifier.

Run a state-specific harness scenario with one of:

```text
nd4x_demo_merged
nd4x_demo_replaced
nd4x_demo_deleted
```

Do not retire `merged.yaml`, `replaced.yaml`, or `deleted.yaml` until the
legacy and harness suites have both passed against the same environment and
the results have been recorded.
