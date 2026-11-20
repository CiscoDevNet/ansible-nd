# `nd_manage_networks` Harness Parity

This document maps the original standalone, MSD, and MCFG integration scenarios
to their ND4X harness replacements. The legacy state files remain in place
while parity is reviewed; no original scenario is retired by this change.

The module worktree contains uncommitted harness and test changes. This
document records reported manual lab runs; it does not claim that the current
working tree has passed a complete same-environment run. Lab identifiers and
addresses are replaced with placeholders for sharing.

Current status is **implemented; standalone validation is partial; repeated
idempotency failures remain under module-owner investigation; MSD/MCFG live
validation and retirement review are outstanding**.

## Scenario mapping

| Original scenario | Original task file(s) | Harness replacement | Status |
|---|---|---|---|
| Pre-test cleanup and fixture preparation | `tests/standalone/setup.yaml`; setup portions of the state files | Scenario-local setup and cleanup in `tasks/nd4x_demo_*.yaml` | Implemented. The harness uses reserved `harness-nd-network-*` names and scenario cleanup. |
| Merged create, deploy, repeat for idempotency, and attachment coverage | `tests/standalone/merged.yaml`, `tests/msd/merged.yaml`, `tests/mcfg/merged.yaml`, and merged portions of `sanity.yaml` | `tasks/nd4x_demo_merged.yaml` | Standalone lab run passed (`failed=0`). MSD/MCFG behavior is implemented but not live-tested. Parent cases exercise switch and Network deployment types and validate child Networks. |
| Replaced Network configuration and repeat for idempotency | `tests/standalone/replaced.yaml`, `tests/msd/replaced.yaml`, `tests/mcfg/replaced.yaml`, and replaced portions of `sanity.yaml` | `tasks/nd4x_demo_replaced.yaml` | Failed the repeat-call expectation: the module returned `changed=true` where the harness expected `false`. The exact cause has not been established for this scenario. Parent topology runs are untested. |
| Gather Network state without changing it | `tests/standalone/gathered.yaml`, `tests/msd/gathered.yaml`, `tests/mcfg/gathered.yaml`, and gathered portions of `sanity.yaml` | `tasks/nd4x_demo_gathered.yaml` | Standalone lab run passed (`failed=0`) after assertions selected objects from the module's `gathered` result. MSD/MCFG runs are untested. |
| Override the managed Network set and repeat for idempotency | `tests/standalone/overridden.yaml`, `tests/msd/overridden.yaml`, `tests/mcfg/overridden.yaml`, and overridden portions of `sanity.yaml` | `tasks/nd4x_demo_overridden.yaml` | Failed the repeat-call expectation (`changed=true`) after aligning the fixture with legacy `rt_auto: true`. Requires destructive-test opt-in. A full result trace is still needed to establish whether this shares the staged/replaced cause. Parent topology runs are untested. |
| Delete managed Networks and verify absence | `tests/standalone/deleted.yaml`, `tests/msd/deleted.yaml`, `tests/mcfg/deleted.yaml`, and deleted portions of `sanity.yaml` | `tasks/nd4x_demo_deleted.yaml` | Standalone lab run passed (`failed=0`) with destructive-test opt-in. Parent topology runs are untested. |
| Stage Networks and exercise attachment add/remove/detach behavior | `tests/standalone/staged.yaml`, `tests/msd/staged.yaml`, `tests/mcfg/staged.yaml` | `tasks/nd4x_demo_staged.yaml` | Failed the repeat-call expectation (`second_run_result.changed=true`). The direct legacy standalone run reproduced it outside the harness. The module owner is addressing the module-side idempotency issue. Parent topology runs are untested. |
| Reject invalid `child_fabric_config` | Standalone and MCFG cases in `tests/standalone/sanity.yaml` and `tests/mcfg/sanity.yaml` | `tasks/nd4x_demo_negative.yaml` | Standalone negative case passed as an expected rejection (`failed=0`, `ignored=1`). The MCFG negative case is implemented but has not been run on an MCFG topology. |

## Assertion coverage

The shared `_nd_network_validate` helper checks supported fields supplied by
each scenario against gathered post-apply state. Mutating scenarios assert
predictive and apply results, including `changed`/`failed`, and verify repeat
call idempotency. Parent workflows snapshot and validate parent and child
Network collections; MCFG parent snapshots use the OneManage Network endpoint.
The harness also checks topology metadata and attachment transitions. The
staged case checks create/add/remove/detach, preservation of an omitted Network,
attachment query state, and idempotency.

The staged harness currently reads the omitted Network from
`nd4x_network_staged_gathered.gathered`. The legacy standalone staged test had
been checking `staged_gather_result.after`; diagnostics showed the omitted
Network in `staged_gather_result.gathered`, so the assertion in
`tests/standalone/staged.yaml` was corrected to read `gathered`. This is a test
assertion correction, not a production-code change, and it does not resolve the
repeat-call failure.

## Review result

All listed standalone, MSD, and MCFG scenario groups have corresponding
harness workflows. The reported live runs cover standalone only. In those
runs, `<fabric-name>` resolved as a standalone fabric; no MSD/MCFG parent-child
topology was used, and no MCFG cluster name was supplied. Setting a topology
variable does not create the corresponding ND topology. Record MSD/MCFG parity
as **untested** until the harness runs against actual ND parent and child
relationships.

The staged repeat failure is not specific to the harness: the direct legacy
standalone test also returned `staged_repeat_result.changed=true`. Its full
result reported `changed=true`, `failed=false`, and an empty `diff`. Existing
data had `rt_auto: true` on all four configured Networks, while proposed data
and the four CRUD PUT payloads had `rt_auto: false`. The API trace showed one
GET and four successful PUTs (HTTP 204); both attachment phases were no-ops
with `payload_count: 0`. This points to repeated writes in the module's
CRUD/state-management path, not the harness wrapper or attachment phases.
The module owner is investigating the module-side behavior. Rerun staged,
replaced, and overridden after the owner fix; do not relax the harness's
idempotency expectation to accept `changed: true`.

The implementation entry point is `plugins/modules/nd_manage_networks.py`;
the staged workflow is in
`plugins/module_utils/orchestrators/network_state_machine.py`. The staged
repeat result and API trace were shared with the module owner. Temporary
diagnostic tasks used to capture the trace were removed after collection.

## Tags and safety

The legacy dispatcher remains the default path. Harness includes are opt-in
through these tags:

```text
nd4x_demo_merged
nd4x_demo_replaced
nd4x_demo_gathered
nd4x_demo_staged
nd4x_demo_overridden
nd4x_demo_deleted
nd4x_demo_negative
```

Each scenario tag selects the shared preflight. Use `nd4x_demo` by itself only
when intentionally running the complete harness; do not combine it with a
scenario tag. Overridden and deleted mutate or remove controller state and
require both explicit opt-ins on an isolated test scope:

```yaml
nd_network_harness_destructive_tests_enabled: true
nd_network_harness_destructive_scope_confirmed: true
```

For standalone runs, set `nd_network_harness_topology: standalone` and the
actual `nd_network_harness_standalone_fabric`. MSD runs need the actual parent
and child fabric names. MCFG runs need the actual parent and child fabric names
and `nd_network_harness_mcfg_cluster_name`. Staged attachment coverage requires
two distinct switch/interface pairs; the second pair may use the same switch
with a different interface. Use reserved test resources and verify the
interfaces are valid and synchronized in ND before running attachment tests.

## Deployment scope

These are live ND integration scenarios: mutating cases call the controller
and perform cleanup. The reported runs used a standalone lab fabric. The
available evidence does not establish live switch deployment behavior for
every topology, nor does it establish MSD/MCFG parent-child parity. Those
topologies require actual ND relationships; a different physical switch set
is not inherently required if the existing lab can be configured into the
needed topology.

## Same-environment execution record

The results below are reported manual runs, not a same-environment CI
certification of every scenario and topology.

| Evidence | Result |
|---|---|
| Current working tree | Module branch with uncommitted harness/test changes; branch name and commit hash omitted. |
| Nexus Dashboard and fabric | `<fabric-name>`, resolved as standalone; exact ND version was not retained. |
| Merged, gathered, deleted, and standalone negative harness runs | Passed in the reported standalone runs; recap showed `failed=0`. Deleted used destructive-test opt-in. The negative case was an expected rejection (`ignored=1`). |
| Replaced and overridden harness runs | Failed repeat-call idempotency (`changed=true`); the overridden full result trace has not been retained here. |
| Staged harness run | Failed repeat-call idempotency (`second_run_result.changed=true`). |
| Legacy standalone staged run | Corrected gathered-result assertion passed. Repeat returned `changed=true`, `failed=false`, and `diff=[]`; four PUTs followed the `rt_auto` difference, and attachment phases were no-ops. |
| Legacy staged attachment pair | `<switch-ip-1>` and `<switch-ip-2>`, using `<interface-name>` on each; reported as distinct, non-peer switches in `<fabric-name>`. These are placeholders, not runnable inventory values. |
| Harness staged attachment pair | Exact pair used for the reported harness run was not retained. |
| MSD/MCFG harness runs | Not tested. No eligible MSD/MCFG parent-child topology or MCFG cluster was used. |
| Unit tests | A unit-test file has changes, but no current passing unit-test result is recorded here. |

## Retirement decision

Keep the legacy dispatcher and state files enabled. Before considering
retirement, resolve or disposition the repeated `changed=true` behavior, rerun
staged/replaced/overridden after the module fix, validate the implemented
parent workflows on real MSD and MCFG topologies, run and record unit tests,
and complete a same-environment review. The staged legacy assertion correction
does not change production code and is separate from the idempotency issue.
