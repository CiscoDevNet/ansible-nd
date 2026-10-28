# `nd_manage_extended_community_list` Harness Parity

The original integration suite remains enabled while the harness replacement
is validated against the same controller environment. Harness scenarios use
explicit `nd4x_demo` and state-specific tags and run only when selected.

## Scenario mapping

| Original scenario | Original task file | Harness replacement | Coverage |
|---|---|---|---|
| Remove reserved default-tenant and optional tenant-scoped lists before and after the suite | `tasks/setup.yaml` | Scenario-local setup and `always` cleanup in each `nd4x_demo_*.yaml` file | Implemented; exercised in all live harness runs |
| Create a standard list in check and normal mode | `tasks/merged.yaml` | `MERGED CREATE: Create standard extended community list` | Harness predictive, apply, idempotency, returned-state, and REST assertions; live validation passed (`ok=63`, `failed=0`) |
| Create an expanded list | `tasks/merged.yaml` | `MERGED CREATE: Create expanded extended community list` | Harness predictive, apply, idempotency, returned-state, and REST assertions; live validation passed (`ok=63`, `failed=0`) |
| Re-apply the merged standard list in check and normal mode | `tasks/merged.yaml` | Post-apply check-mode assertion plus automatic idempotency phase in the standard merged scenario | Implemented |
| Replace standard entries in check and normal mode | `tasks/replaced.yaml` | `REPLACED UPDATE: Replace standard extended community list entries` | Harness predictive, apply, idempotency, returned-state, and REST assertions; live validation passed (`ok=63`, `failed=0`) |
| Re-apply replaced configuration | `tasks/replaced.yaml` | Automatic idempotency phase in the replaced scenario | Implemented by harness lifecycle |
| Delete standard and expanded lists with name-only configuration | `tasks/deleted.yaml` | `DELETED: Delete extended community lists with name-only config` | Harness predictive, apply, idempotency, returned-state, and expected-404 REST assertions; live validation passed (`ok=63`, `failed=0`) |
| Re-apply deletion | `tasks/deleted.yaml` | Automatic idempotency phase in the deleted scenario | Implemented by harness lifecycle |
| Enforce only the overridden list after creating extra lists | `tasks/overridden.yaml` | `OVERRIDDEN: Keep only the requested extended community list` | Destructive opt-in, tenant-aware reserved-identity preflight, fabric-wide predictive snapshot, apply, idempotency, returned-state, and REST assertions; live validation passed (`ok=63`, `failed=0`) |
| Preserve same-name identity across two tenants and re-apply idempotently | `tasks/tenant_identity.yaml` | `TENANT IDENTITY: Create same-name lists in two tenants` | Optional harness predictive, apply, idempotency, returned-state, and tenant-specific REST assertions; live validation passed (`ok=63`, `failed=0`) |

## Harness execution

Safe aggregate harness coverage requires an inventory where
`nd_test_community_lists_run_overridden=false` (the `ansible-test`
`network-integration` command does not accept `--extra-vars`):

```bash
ansible-test network-integration nd_manage_extended_community_list \\
  --inventory /absolute/path/to/inventory.networking \\
  --tags nd4x_demo \\
  -vv
```

The preflight is inherited by each scenario tag, so individual runs such as
`--tags nd4x_demo_replaced` also perform version detection and gating.
Do not use `--skip-tags nd4x_demo_overridden` with the aggregate harness tag,
because the shared preflight also carries that scenario tag.

Tenant identity coverage additionally requires `nd_test_tenant_name_a` and
`nd_test_tenant_name_b`.

Overridden coverage requires a dedicated test fabric and:

```ini
nd_test_community_lists_run_overridden=true
```

The overridden scenario refuses to run when the complete paginated fabric
inventory contains a list outside the reserved test identities. Default-tenant
resources use `name`; tenant-scoped resources use `tenantName~name`. It also
rejects incomplete or duplicate page results, then snapshots the complete
paginated extended-community-list collection around predictive execution.

## Scope and follow-up

- ND version preflight gates harness scenarios at 4.2.1, matching the module's
  documented support floor.
- The module does not expose a `timeout` argument; both direct and harness
  executions use `RestSend`'s built-in 300-second controller timeout, while
  `ansible_command_timeout: 300` bounds the Ansible task execution.
- The full collection snapshot ignores only `lastUpdateTimestamp`, which is a
  read-only volatile field excluded by the module model.
- The legacy suite is intentionally retained until original and harness suites
  pass in the same environment and retirement is approved.
- Live controller validation passed for merged, replaced, deleted, overridden,
  and tenant-identity harness scenarios. Each run reported `ok=63`,
  `changed=14`, `skipped=6`, and `failed=0`. The legacy suite remains enabled
  for comparison and retirement review.
