# `nd_manage_acl` Harness Parity

This document maps every scenario in the original `nd_manage_acl` integration
suite to its ND 4.x harness replacement. The original task files remain
enabled while parity is validated against the same controller and fabric.

## Live testing status

Live integration testing is in progress. The testing results will be updated
in this document once testing completes.

## Scenario mapping

| Original scenario | Original file | Harness replacement | Coverage |
|---|---|---|---|
| Confirm the configured fabric is reachable with an empty merged read | `tasks/acl_ipv4.yaml` | `nd4x_demo_preflight.yaml` no-op module probe | Harness preflight, ND version gate, and fabric reachability assertion |
| Remove leftover IPv4 and IPv6 ACLs before testing | `tasks/acl_ipv4.yaml` | Scenario-local setup and `always` cleanup in each `nd4x_demo_*.yaml` file | Reserved cleanup retained |
| Create IPv4 ACL in check mode, normal mode, and idempotently | `tasks/acl_ipv4.yaml` | `MERGED CREATE` in `nd4x_demo_merged.yaml` | Harness predictive, apply, idempotency, returned-state, and REST assertions |
| Merge a new IPv4 entry list and verify only sequence 30 remains | `tasks/acl_ipv4.yaml` | `MERGED UPDATE` in `nd4x_demo_merged.yaml` | Harness predictive, apply, idempotency, returned-state, and REST assertions |
| Replace IPv4 ACL entries in check mode, normal mode, and idempotently | `tasks/acl_ipv4.yaml` | `REPLACED` in `nd4x_demo_replaced.yaml` | Harness predictive, apply, idempotency, returned-state, and REST assertions |
| Validate persisted IPv4 ACL wire representation | `tasks/acl_ipv4.yaml` | IPv4 `nd_queries` in merged/replaced scenarios | Name, type, entry count, sequence, action, and protocol checks |
| Delete IPv4 ACL in check mode, normal mode, and idempotently | `tasks/acl_ipv4.yaml` | `DELETED` in `nd4x_demo_deleted.yaml` | Identifier-only deletion, absence REST query, and returned-state checks |
| Create IPv6 ACL with port range and re-apply idempotently | `tasks/acl_ipv6.yaml` | IPv6 `MERGED CREATE` in `nd4x_demo_merged.yaml` | Harness lifecycle, returned IPv6 state, and persisted port-range checks |
| Validate persisted IPv6 ACL wire representation | `tasks/acl_ipv6.yaml` | IPv6 `nd_queries` in `nd4x_demo_merged.yaml` | Validates entries and string port bounds on all supported versions; checks the documented `type: ipv4` readback on ND 4.2.1+ |
| Override with empty config to remove all ACLs and re-apply idempotently | `tasks/acl_ipv6.yaml` | `OVERRIDDEN` in `nd4x_demo_overridden.yaml` | Destructive opt-in, check-mode scope probe, reserved-scope guard, fabric-wide snapshot, REST absence, and returned-state checks |

## Harness behavior

- `nd4x_demo_preflight.yaml` gates the harness scenarios at ND 4.1.1, matching
  the module documentation.
- Every predictive phase snapshots the complete `/accessControlLists` collection
  with harness pagination (`page_size: 100`, `collection_key:
  accessControlLists`) and ignores only the controller-owned
  `lastUpdateTimestamp` field.
- Every harness mutation enables idempotency and validates both the module's
  returned `after` state and persisted ND REST state.
- The overridden workflow is intentionally destructive. It requires
  `nd_acl_destructive_tests_enabled=true` and refuses to run when the
  check-mode scope probe finds an ACL outside the two reserved test names.
- The original suite has no negative-validation scenario; none was added as an
  unrelated harness case.

## Tags and execution

Harness scenarios are opt-in and retain the `never` tag while parity is being
validated. The original suite continues to run during this period.

Safe harness scenarios:

```bash
ansible-test network-integration nd_manage_acl \
  --inventory inventory.LOCAL.networking \
  --tags never,nd4x_demo_merged,nd4x_demo_replaced,nd4x_demo_deleted -vv
```

The overridden replacement requires a dedicated test fabric, the inventory
variable below, and Ansible's destructive-test allowance:

```ini
nd_acl_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_manage_acl \
  --inventory inventory.LOCAL.networking \
  --tags never,nd4x_demo_overridden,nd4x_demo_preflight \
  --allow-destructive -vv
```

Do not retire `acl_ipv4.yaml` or `acl_ipv6.yaml` until the legacy and harness
suites have both passed against the same environment and the results have been
recorded.
