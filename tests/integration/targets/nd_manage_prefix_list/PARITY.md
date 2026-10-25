# `nd_manage_prefix_list` Harness Parity

This document maps every scenario in the original integration suite to the
ND 4.x harness replacement. The legacy files remain enabled while parity is
validated against the same controller and fabric.

Live testing status: ND 4.x harness preflight completed successfully on
2026-10-22 against the local live inventory :
`ok=6`, `changed=0`, `failed=0`, `skipped=2`. The merged scenario completed
successfully: `ok=52`, `changed=6`, `failed=0`, `skipped=10`. The replaced
scenario also completed successfully: `ok=48`, `changed=5`, `failed=0`,
`skipped=10`. The deleted scenario completed successfully: `ok=52`,
`changed=6`, `failed=0`, `skipped=10`.
The validation scenario also completed successfully on 2026-10-24:
`ok=55`, `changed=2`, `failed=0`, `skipped=14`.
The overridden-only scenario completed successfully on 2026-10-24:
`ok=62`, `changed=4`, `failed=0`, `skipped=14`. It was run with a dedicated
temporary inventory containing `nd_prefix_list_destructive_tests_enabled=true`
and `--allow-destructive`.

The extended scenario is blocked during tenant-scoped IPv6 replacement. The
tenant-scoped resource was created successfully and was visible through the
qualified GET endpoint. Both the direct module `state=replaced` operation and
an independent raw REST `PUT` received HTTP 500 from ND:

`Prefix list not found for key: CompositeKey
[ANSIBLE_TENANT_B~PL-ND4X-TENANT-SHARED, 1949020, ipv6]`

The raw REST endpoint was
`/api/v1/manage/fabrics/VXLAN_Fabric/ipv6PrefixLists/ANSIBLE_TENANT_B~PL-ND4X-TENANT-SHARED`
and the ND trace ID was `b6105287560041cdbd04bbccd1fa56d7`. The resource was
successfully removed afterward with `state=deleted`. This is an ND
controller/API or API-contract blocker, not a harness sequencing failure.

Core state, validation, and overridden live testing is complete. Extended
feature-surface coverage remains incomplete because the tenant-scoped IPv6
replacement fails with an ND HTTP 500. Tenant replacement verification,
tenant-scoped deletion, and conditional cluster create, replacement, deletion,
and cleanup are not proven by that run. The overridden scenario has a
successful isolated live result recorded above.

## Scenario mapping

| Original scenario | Original file | Harness replacement |
|---|---|---|
| Remove reserved IPv4 and IPv6 prefix lists before testing | `tasks/setup.yaml` | Scenario-local setup and `always` cleanup in each `nd4x_demo_*.yaml` file |
| Create IPv4 `PL-IPV4-BORDERS` in check and normal mode | `tasks/merged.yaml` | `MERGED CREATE` in `nd4x_demo_merged.yaml`; harness predictive, apply, idempotency, REST, and returned-state checks |
| Create IPv6 `PL-IPV6-DATACENTER` in check and normal mode | `tasks/merged.yaml` | IPv6 `MERGED CREATE` |
| Re-apply IPv4 and IPv6 together as a mixed-family operation | `tasks/merged.yaml` | `MERGED CREATE MULTI`; expected no change and both families validated |
| Re-apply the IPv4 create idempotently | `tasks/merged.yaml` | Explicit IPv4-only `MERGED IDEMPOTENT` harness reapply after the mixed-family operation |
| Add IPv4 sequence 40 and change its description | `tasks/merged.yaml` | IPv4 `MERGED UPDATE`; REST and returned `after` state validate four entries |
| Re-apply the IPv4 update idempotently | `tasks/merged.yaml` | Harness idempotency phase in IPv4 `MERGED UPDATE` |
| Add IPv6 sequence 30 | `tasks/merged.yaml` | IPv6 `MERGED UPDATE`; REST and returned `after` state validate three entries |
| Re-apply the IPv6 update idempotently | `tasks/merged.yaml` | Harness idempotency phase in IPv6 `MERGED UPDATE` |
| Replace IPv4 borders with one entry and no description | `tasks/replaced.yaml` | `REPLACED` in `nd4x_demo_replaced.yaml`; exact returned state and REST checks |
| Re-apply the single replacement idempotently | `tasks/replaced.yaml` | Explicit converged check-mode and normal reapply plus harness idempotency phase in `REPLACED` |
| Replace IPv4 and IPv6 together | `tasks/replaced.yaml` | `REPLACED MULTI`; both returned configurations and REST values validated |
| Add a second IPv4 list before overridden | `tasks/overridden.yaml` | Exact pre-override setup in `nd4x_demo_overridden.yaml` |
| Override to only IPv4 borders and remove the other lists | `tasks/overridden.yaml` | `OVERRIDDEN`; fabric-wide snapshots, destructive opt-in, reserved-scope preflight, full retained-configuration REST and returned-state checks, and removal checks |
| Re-apply the same overridden configuration | `tasks/overridden.yaml` | Explicit converged check-mode and normal reapply plus harness idempotency phase in `OVERRIDDEN` |
| Swap IPv4 borders for IPv6 datacenter | `tasks/overridden.yaml` | `OVERRIDDEN SWAP`; fabric-wide snapshots, full retained IPv6 configuration checks, and both family REST checks |
| Delete one IPv6 prefix list | `tasks/deleted.yaml` | `DELETED SINGLE`; harness idempotency covers the second delete |
| Delete IPv4 and IPv6 together | `tasks/deleted.yaml` | `DELETED MULTI`; both family REST absence checks |
| Delete using only `ip_version` and `name` | `tasks/deleted.yaml` | `DELETED IDENTIFIER-ONLY`; both returned and REST states validated |
| Re-apply identifier-only deletion idempotently | `tasks/deleted.yaml` | Harness idempotency phase in `DELETED IDENTIFIER-ONLY` |
| Delete a nonexistent IPv4 prefix list | `tasks/deleted.yaml` | `DELETED NON-EXISTENT`; expected no change through predictive, apply, and idempotency phases |

## Extended module-surface coverage

The opt-in `nd4x_demo_extended` tag adds coverage beyond the original legacy
scenario suite:

- default `permit` action and IPv4 host-bit normalization;
- explicit IPv4 and IPv6 masks plus IPv6 spelling normalization;
- `ipVersion`, `tenantName`, `sequenceNumber`, `exactLength`, `minLength`,
  and `maxLength` aliases;
- same-name resources across IPv4 and IPv6;
- same-name IPv4 and IPv6 resources across two existing tenants, with full
  per-tenant action, prefix, and returned-state validation;
- tenant-scoped merged, replaced, and deleted lifecycles, including
  cross-tenant preservation checks, when `nd_test_tenant_name_a` and
  `nd_test_tenant_name_b` are defined;
- `cluster_name` routing for merged, replaced, and deleted operations with
  cluster-specific predictive snapshots and REST checks, when
  `nd_test_cluster_name` is defined.

The opt-in `nd4x_demo_validation` tag exercises expected module failures for
invalid CIDRs, wrong address families, invalid masks, duplicate sequence
numbers, conflicting or out-of-range length constraints, invalid sequence
numbers, missing entries, invalid names and tenant names, default-tenant and
tenant-qualified name length limits, description length and ASCII constraints,
invalid actions, and missing required fields. Each invalid case must fail in
both predictive and apply phases without creating a resource, and each phase's
error message must contain its case-specific validation marker. It also verifies
that omitting `state` defaults to `merged` and that an omitted entry action
defaults to `permit`.

Tenant coverage requires two existing tenants supplied through
`nd_test_tenant_name_a` and `nd_test_tenant_name_b`. Cluster coverage requires
an existing multi-cluster target supplied through `nd_test_cluster_name`; both
scenarios skip when their prerequisite variables are absent.

## Harness behavior

- `nd4x_demo_preflight.yaml` gates the replacement scenarios to ND 4.2.1 or
  newer, matching the module documentation.
- The shared `nd4x_module_test` action permits `state` to be omitted; in that
  case it preserves the target module's own default. The validation suite
  exercises this with `nd_manage_prefix_list` defaulting to `merged`.
- Every predictive phase snapshots both `/ipv4PrefixLists` and
  `/ipv6PrefixLists` with harness pagination, compares them unordered, and
  ignores only the controller-owned `lastUpdateTimestamp` field.
- The overridden safety preflight independently walks every IPv4 and IPv6
  inventory page and validates names against the matching address-family
  allowlist before allowing the fabric-wide destructive operation.
- Primary mutation scenarios enable harness idempotency and validate the
  target module's returned `after` state in addition to post-apply REST
  queries.
- Post-apply REST checks for named resources use item endpoints rather than
  first-page collection filters, so presence and absence assertions are not
  affected by collection pagination. Validation inventories use the shared
  paginated inventory helper.
- `replaced` and `overridden` also run an explicit converged check-mode
  prediction followed by a normal reapply with both phases required to report
  no change; those dedicated reapply tasks disable the harness's additional
  internal retry.
- The overridden workflow is intentionally destructive. It requires
  `nd_prefix_list_destructive_tests_enabled=true` and refuses to run when any
  existing prefix list lies outside the reserved family/name combinations.
- Every state-scenario cleanup still uses the legacy deletion tasks for
  compatibility, but now walks all IPv4 and IPv6 inventory pages afterward and
  fails if any reserved resource remains; cleanup errors cannot be hidden by
  the deletion tasks' `failed_when: false`.
- Each scenario also verifies the expected resources are absent immediately
  after its initial best-effort setup cleanup, so stale fixtures are reported
  before the scenario starts.
- Extended feature and validation scenarios also perform paginated final
  absence checks for every resource they create, including tenant-scoped names;
  tenant cleanup additionally verifies each tenant/family item endpoint
  directly;
  cluster-scoped cleanup is verified with a cluster-specific item query.
- The original suite has no negative validation scenario; no unrelated
  negative case was invented for this parity migration.

## Tags and execution

Harness scenarios are opt-in and retain the `never` tag while parity is being
validated. The original suite continues to run during this period.

Core replacement scenarios:

```bash
ansible-test network-integration nd_manage_prefix_list \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged,nd4x_demo_replaced,nd4x_demo_deleted -vv
```

The overridden replacement requires a dedicated fabric, the inventory
variable below, and Ansible's destructive-test allowance:

```ini
nd_prefix_list_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_manage_prefix_list \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden \
  --allow-destructive -vv
```

Extended feature and validation scenarios are non-destructive after their
scenario-local cleanup and can be selected with:

```bash
ansible-test network-integration nd_manage_prefix_list \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_extended -vv

ansible-test network-integration nd_manage_prefix_list \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_validation -vv
```

Do not retire `setup.yaml`, `merged.yaml`, `replaced.yaml`,
`overridden.yaml`, or `deleted.yaml` until the legacy and replacement suites
have both passed against the same environment and the results are recorded.
