# `nd_manage_fabric_group_members` Harness Parity

The legacy scenario remains in `tasks/main.yml` and runs by default. The
opt-in ND 4.x scenario is in `tasks/nd4x_demo.yaml` and is selected with the
`nd4x_demo` tag. Harness-owned resource names use the `ansible_nd4x_fgm_`
prefix. Before creating resources, the scenario verifies that every configured
name is absent through the ND Manage API; it refuses to take over an existing
resource or continue after an inconclusive lookup. It also confirms the fixed
negative-test group name is missing before using it in an expected-failure case.

## Harness coverage

- Queries the controller version and skips the harness on releases before 4.0.
- Creates a dedicated single-cluster VXLAN fabric group and three member
  fabrics, then attempts ordered `always` cleanup and fails if any harness-owned
  fabric resource remains or its absence cannot be confirmed.
- Exercises merged membership with predictive check mode, apply, idempotency,
  and a post-apply REST query for the exact members.
- Verifies gathered state is empty before the first merge, then adds a third
  member and verifies populated gathered output.
- Exercises deleted state with predictive check mode, apply, idempotency, and
  post-delete REST checks.
- Verifies that unknown groups, member fabrics used as parent groups, and
  `cluster_name` on a single-cluster group are rejected without mutation.
- The separately tagged MCFG scenario verifies OneManage access and the
  configured resource category, rejects a missing `cluster_name`, and tests
  merge, idempotency, gathered cluster identity, and delete. It compares the
  full set of member/cluster identities before and after each mutation and
  verifies cleanup restores the baseline. Before capturing that baseline, it
  snapshots all pairs, removes only the configured harness member/cluster pair,
  and verifies every other pair is preserved. This makes interrupted runs
  retryable without hiding collateral membership changes.
- Snapshots the complete membership list around predictive execution so an
  unintended membership change prevents the real apply.

## Legacy scenario mapping

| Legacy coverage | Harness coverage | Status |
|---|---|---|
| Single-cluster prerequisite fabrics and group | Harness-owned prerequisites | Implemented |
| Gather an empty group and gather populated membership | Exact empty result before merge and exact three-member result after merge | Implemented |
| Merge one or multiple members; check mode and idempotency | Shared harness merge calls | Implemented |
| Delete one or multiple members; check mode and idempotency | Shared harness delete calls | Implemented |
| Reject `cluster_name` on a single-cluster group | Direct expected-failure call | Implemented |
| Reject unknown group and reject a fabric used as the group | Direct expected-failure calls | Implemented |
| Multi-cluster group validation, merge, gather, and delete | Separate `nd4x_demo_mcfg` scenario | Implemented; requires a federated ND controller, OneManage login, and explicit `test_mcfg_*` inventory values |

## Live results

- Single-cluster `nd4x_demo`: passed on the live controller. Recap: `ok=29`,
  `changed=8`, `unreachable=0`, `failed=0`, `skipped=1`, `ignored=6`.
- Multi-cluster `nd4x_demo_mcfg`: passed on the live federated controller.
  Recap: `ok=32`, `changed=2`, `unreachable=0`, `failed=0`, `skipped=4`,
  `ignored=1`. The selected group was empty, so the four skipped pair-recording
  loops did not exercise preservation of pre-existing MCFG members.
- Multi-cluster `nd4x_demo_mcfg` with a populated baseline: passed against
  `MCFG_C`. Recap: `ok=36`, `changed=2`, `unreachable=0`, `failed=0`,
  `skipped=0`, `ignored=1`. The existing member/cluster pairs were included in
  the before/after preservation checks.
- Original default legacy suite: passed on the live controller. Recap:
  `ok=44`, `changed=13`, `unreachable=0`, `failed=0`, `skipped=1`,
  `ignored=5`. The live run included the legacy MCFG validation, merge,
  idempotency, gather, and delete cases. The skipped task only reports missing
  inventory prerequisites when those variables are undefined.
- The pre-ND-4.0 version-gate skip branch was not live-exercised; all recorded
  live runs used ND 4.2.1.

## Running the harness

```text
ansible-test network-integration nd_manage_fabric_group_members \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo -vv
```

Run the federated multi-cluster scenarios separately:

```text
ansible-test network-integration nd_manage_fabric_group_members \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_mcfg -vv
```

The scenario requires working Nexus Dashboard inventory credentials, as does
the legacy target. It uses dedicated default resource names defined in
`defaults/main.yml`; inventory can override them if those names already exist
on the controller. The harness does not modify inventory or credential files.
The MCFG scenario requires `test_mcfg_group`, `test_mcfg_member`, and
`test_mcfg_cluster` to be supplied by the private inventory. It requires the
configured session to read the existing MCFG group through OneManage. Each run
removes only the configured member/cluster pair before capturing the baseline;
use a dedicated pair because that membership is reserved for the harness.
