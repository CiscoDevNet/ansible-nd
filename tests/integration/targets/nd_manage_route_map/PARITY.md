# `nd_manage_route_map` Harness Parity

This document maps every scenario in the original integration suite to its
ND 4.x harness replacement. The legacy files remain enabled while parity is
validated against the same controller and fabric.

## Scenario mapping

| Original scenario | Original file | Harness replacement |
|---|---|---|
| Remove primary, secondary, and tertiary route maps before testing | `tasks/setup.yaml` | Scenario-local setup and `always` cleanup in each `nd4x_demo_*.yaml` file |
| Create the primary route map in check mode and normal mode | `tasks/merged.yaml` | `MERGED CREATE` in `nd4x_demo_merged.yaml`; harness predictive, apply, idempotency, REST, and returned-state checks |
| Re-apply the primary route map in check mode and normal mode | `tasks/merged.yaml` | `MERGED IDEMPOTENT`; explicit no-change harness phases and REST validation |
| Update primary local preference in check mode and normal mode | `tasks/merged.yaml` | `MERGED UPDATE`; returned `after` state and REST value validation |
| Replace the primary route map with a deny/match-tag entry | `tasks/replaced.yaml` | `REPLACED` in `nd4x_demo_replaced.yaml`; exact returned-state and REST checks |
| Re-apply the replacement idempotently | `tasks/replaced.yaml` | Harness idempotency phase in `REPLACED` |
| Add secondary and tertiary route maps before override | `tasks/overridden.yaml` | `OVERRIDDEN SETUP` in `nd4x_demo_overridden.yaml` |
| Retain only the primary route map and remove the other two | `tasks/overridden.yaml` | `OVERRIDDEN`; fabric-wide snapshots, destructive opt-in, reserved-scope preflight, REST absence checks, and returned-state checks |
| Delete the primary route map in check mode and normal mode | `tasks/deleted.yaml` | `DELETED` in `nd4x_demo_deleted.yaml`; predictive, apply, idempotency, and REST absence checks |
| Re-apply deletion idempotently | `tasks/deleted.yaml` | Harness idempotency phase in `DELETED` |
| Distinguish same-name route maps in separate tenants, update by qualified name, and delete one tenant's map | No legacy equivalent | Opt-in `TENANT IDENTITY` in `nd4x_demo_tenant_identity.yaml` |

The legacy suite has no tenant-identity scenario; the harness adds one because
tenant-qualified identity handling is a module feature that needs integration
coverage. There is no negative-validation scenario or multi-resource
merged/replaced scenario in the legacy suite.

## Harness behavior

- `nd4x_demo_preflight.yaml` gates the harness scenarios to ND 4.2.1 or newer,
  matching the module documentation.
- Predictive phases page through the complete route-map collection and ignore
  only the controller-owned `lastUpdateTimestamp` field. A request failure or
  page-limit hit fails the snapshot instead of treating a partial collection
  as complete.
- Every harness mutation enables idempotency and validates both the module's
  returned `after` state and persisted ND REST state.
- The overridden workflow requires
  `nd_route_map_destructive_tests_enabled=true` and refuses to run when the
  complete, paginated fabric inventory contains route maps outside the three
  reserved test names.
- Tenant-identity coverage requires two existing, distinct tenant names in
  `nd_test_tenant_name_a` and `nd_test_tenant_name_b`.

## Tags and execution

Harness scenarios are opt-in and retain the `never` tag while parity is being
validated. The original suite continues to run during this period.

Safe harness execution:

```bash
ansible-test network-integration nd_manage_route_map \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo,nd4x_demo_preflight \
  --skip-tags nd4x_demo_overridden,nd4x_demo_tenant_identity -vv
```

Run tenant identity coverage separately with two existing tenant names:

```bash
ansible-test network-integration nd_manage_route_map \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo_tenant_identity,nd4x_demo_preflight -vv
```

The overridden replacement requires a dedicated fabric, the inventory
variable below, and Ansible's destructive-test allowance:

```ini
nd_route_map_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_manage_route_map \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo_overridden,nd4x_demo_preflight \
  --allow-destructive -vv
```

Do not retire `setup.yaml`, `merged.yaml`, `replaced.yaml`, `overridden.yaml`,
or `deleted.yaml` until the legacy and replacement suites have both passed
against the same environment and the results are recorded.
