# `nd_manage_community_list` Harness Parity

The original integration suite remains enabled while the harness replacement
is validated against the same controller and fabric. Harness scenarios run as
part of the normal target suite and can be opted out with `--skip-tags nd4x_demo`.

## Scenario mapping

| Original scenario | Original file | Harness replacement | Coverage |
|---|---|---|---|
| Remove reserved default-tenant and optional tenant-scoped lists before and after resource-creating scenarios | `tasks/setup.yaml` | Scenario-local setup and `always` cleanup in the resource-creating `nd4x_demo_*.yaml` files; the negative check-mode-only scenario creates no resource | Implemented; reserved cleanup retained |
| Reject a standard entry with neither community numbers nor a well-known flag | `tasks/validation.yaml` | `nd4x_demo_negative.yaml` | Fully covered; harness check-mode-only failure with the original validation-reason assertion |
| Create a standard community list in check and normal mode | `tasks/merged.yaml` | `MERGED CREATE` in `nd4x_demo_merged.yaml` | Harness predictive, apply, idempotency, returned-state, and REST assertions |
| Create an expanded community list | `tasks/merged.yaml` | `MERGED CREATE` in `nd4x_demo_merged.yaml` | Harness predictive, apply, idempotency, returned-state, and REST assertions |
| Re-apply the standard list in check and normal mode | `tasks/merged.yaml` | Explicit check-mode reapply with predictive and normal no-change assertions plus automatic idempotency phase in the standard merged scenario | Fully covered |
| Replace standard community-list entries in check and normal mode | `tasks/replaced.yaml` | `REPLACED UPDATE` in `nd4x_demo_replaced.yaml` | Harness predictive, apply, idempotency, returned-state, and REST assertions |
| Re-apply replaced configuration | `tasks/replaced.yaml` | Automatic idempotency phase in the replaced scenario | Implemented by harness lifecycle |
| Delete standard and expanded lists with name-only configuration | `tasks/deleted.yaml` | `DELETED` in `nd4x_demo_deleted.yaml` | Harness predictive, apply, idempotency, returned-state, and expected-404 REST assertions |
| Re-apply deletion | `tasks/deleted.yaml` | Automatic idempotency phase in the deleted scenario | Implemented by harness lifecycle |
| Enforce only the overridden list after creating extra lists | `tasks/overridden.yaml` | `OVERRIDDEN` in `nd4x_demo_overridden.yaml` | Destructive opt-in, reserved-name preflight, paginated fabric-wide inventory and predictive snapshot, apply, idempotency, returned-state, and REST assertions |
| Preserve same-name identity across two tenants and re-apply idempotently | `tasks/tenant_identity.yaml` | `TENANT IDENTITY` in `nd4x_demo_tenant_identity.yaml` | Optional harness predictive, apply, idempotency, returned-state, and tenant-specific REST assertions |

## Harness execution

Safe harness coverage:

```bash
ansible-test network-integration nd_manage_community_list \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  -vv
```

Tenant identity coverage additionally requires
`nd_test_tenant_name_a` and `nd_test_tenant_name_b`.

Overridden coverage requires a dedicated test fabric and:

```ini
nd_test_community_lists_run_overridden=true
```

The overridden scenario refuses to run when the fabric contains a community
list outside the reserved test names, then snapshots the complete
`communityLists` collection around predictive execution.

## Scope and follow-up

- ND version preflight gates harness scenarios at 4.2.1, matching the module's
  documented support floor.
- The preflight is tagged with every state-specific harness tag, so selecting a
  single state still runs the version gate and predictive snapshot setup.
- Predictive snapshots and overridden safety inventory use 100-resource pages
  with a 10,000-page bound; overridden inventory validation fails closed if the
  complete collection cannot be established.
- The full collection snapshot ignores only `lastUpdateTimestamp`, the
  controller-owned volatile field excluded by the module model.
- The harness `check_mode_only` phase is used where the legacy suite requires
  a predictive check without a subsequent real apply.
- Harness scenarios require an explicit `nd_test_fabric_name`; the guard and
  fabric selection run before the state-test block, so a missing fabric cannot
  enter the block's cleanup path. The legacy `SITE1` fallback remains
  available only to the unchanged legacy suite.
- Harness returned-state assertions validate scenario-specific `before` and
  `after` entry fields in addition to REST postconditions.
- The legacy suite is intentionally retained until original and harness suites
  pass in the same environment and retirement is approved.
- Live controller testing is complete for all isolated harness scenarios. An
  aggregate harness run passed with `ok=69`,
  `changed=14`, `failed=0`, and
  `skipped=4`; those totals are not scenario-specific. The isolated
  `nd4x_demo_merged` scenario has passed with `ok=23`, `changed=3`,
  `unreachable=0`, `failed=0`, and `skipped=2`. Isolated results for the
  `nd4x_demo_replaced` scenario have passed with `ok=16`, `changed=3`,
  `unreachable=0`, `failed=0`, and `skipped=2`. Isolated results for the
  `nd4x_demo_deleted` scenario have passed with `ok=16`, `changed=2`,
  `unreachable=0`, `failed=0`, and `skipped=2`. Isolated results for the
  `nd4x_demo_negative` scenario have passed with `ok=11`, `changed=0`,
  `unreachable=0`, `failed=0`, and `skipped=2`. Isolated results for the
  `nd4x_demo_tenant_identity` scenario have passed with `ok=19`, `changed=3`,
  `unreachable=0`, `failed=0`, and `skipped=2`. The isolated overridden
  `nd4x_demo_overridden` scenario has passed with `ok=24`, `changed=3`,
  `unreachable=0`, `failed=0`, and `skipped=4`.
