# ND Prerequisite Orchestration — Stopped-State Handoff

Date: 2026-08-27

Status: **All implementation and review work is stopped at the user's request.**

This document records the intended design, the exact local implementation state, the unresolved owner decisions, and the safe continuation boundary. It does not authorize or claim a controller mutation, Consul publication, Jenkins execution, Git push, or deployment into the OneDrive target.

## 1. Executive state

- The requested outcome is a prerequisite orchestrator that prepares the correct fabrics, switch memberships and roles, links, vPC state, resources, and runtime variables **before** invoking each ND module test.
- The execution order is designed to minimize disruptive switch changes by batching compatible targets into topology phases.
- Same-fabric role changes use ND `changeRoles`. Remove/re-onboard is allowed only for the declared cross-fabric move of `ext_1`.
- Retained fabrics must never be deleted.
- Every target is protected by job-, phase-, and target-level snapshots and normalized restore verification.
- All 32 logical profiles are represented. `integration.nd_vpc_pair` expands into two executions, so the complete registry resolves to 33 execution units.
- Every profile is currently blocked because owner confirmation is not complete. No pending value is to be guessed or converted into desired state.
- Task 1 is implemented and independently reviewed in the isolated staging repository.
- Task 2 is implemented and unit-tested in staging, but its independent review was interrupted when work was stopped. Treat Task 2 as a draft until that review is completed.
- Tasks after Task 2 have not been started.
- No staged implementation file has been applied to the OneDrive target.

## 2. Workspaces and source-of-truth boundary

Requested target:

`/Users/sivakasi/OneDrive - Cisco/2/Ansible work/NX_ansible/jenkins/jenkins_nd/nd`

The canonical path resolved by macOS is:

`/Users/sivakasi/Library/CloudStorage/OneDrive-Cisco/2/Ansible work/NX_ansible/jenkins/jenkins_nd/nd`

Both supplied path forms resolve to the same directory.

Isolated implementation staging repository:

`/private/tmp/nd-prerequisite-phase.tVdPHq/nd`

The staging repository is the only place where implementation changes were made. Its current Git worktree is clean at commit `03acab6`. The OneDrive target still matches the staging baseline for every existing file changed by Tasks 1 and 2, and none of the new Task 2 files exists there.

## 3. Approved lab contract

### Retained fabrics

| Reference | Fabric | Type | Lifecycle |
|---|---|---|---|
| `advanced` | `Siva_Fabric_Adv` | `vxlanIbgp` | retained; never delete |
| `external` | `Siva_External_Fabric` | `externalConnectivity` | retained; never delete |

### Disposable fabrics

| Reference | Exact fabric name | Type |
|---|---|---|
| `disposable_ibgp` | `ANSIBLE_NIGHTLY_IBGP` | `vxlanIbgp` |
| `disposable_ebgp` | `ANSIBLE_NIGHTLY_EBGP` | `vxlanEbgp` |
| `disposable_ai_ibgp` | `ANSIBLE_NIGHTLY_AI_IBGP` | `aimlVxlanIbgp` |
| `disposable_ai_ebgp` | `ANSIBLE_NIGHTLY_AI_EBGP` | `aimlVxlanEbgp` |
| `disposable_external` | `ANSIBLE_NIGHTLY_EXTERNAL` | `externalConnectivity` |

Only exact namespaced disposable fabrics may be created or deleted automatically.

### Switch identities

| Ref | Baseline fabric | Serial | Seed/management IP |
|---|---|---|---|
| `adv_1` | advanced | `99WMIU1JLQ3` | `10.122.84.203` |
| `adv_2` | advanced | `9484O9IOVJK` | `10.122.84.204` |
| `ext_1` | external | `94HIZLNUVCI` | `10.122.84.55` |
| `ext_2` | external | `90SRMMW6APK` | `10.122.84.56` |

These identities are expected inventory, not an assumption about current live membership or role. Current state must be discovered into L0 before any mutation.

### Physical-interface allowlist

| Switch | Interfaces the orchestrator may touch |
|---|---|
| `adv_1` | `Ethernet1/1`–`Ethernet1/4` (four-port lab variant) |
| `adv_2` | `Ethernet1/1`–`Ethernet1/4` (four-port lab variant) |
| `ext_1` | `Ethernet1/1`, `Ethernet1/2` |
| `ext_2` | none |

Physical cabling is assumed to be pre-wired. In the four-port lab variant,
Ethernet1/3 is reused sequentially by the access and trunk-host targets, and
Ethernet1/4 is used by network/VRF-Lite targets. The orchestrator may set only
declared admin/policy state on allowlisted interfaces; it must not infer, create,
or delete physical links.

## 4. Snapshot, restore, and failure model

| Level | Meaning | Required behavior |
|---|---|---|
| L0 | Immutable job baseline | Capture before any mutation; retain until final restore and comparison succeed. |
| L1 | Verified phase baseline | Capture after each declared topology transition; only compatible profiles may share it. |
| L2 | Target snapshot | Capture the target's managed domains and generated objects; restore to L1 after every target. |

Failure policy:

- Preflight or snapshot-capture failure: make no mutation and invoke no module test.
- Target failure: retain the test result, restore L2, and compare with L1.
- Target failure with successful restore: later profiles may continue only when policy permits.
- Restore mismatch, verification failure, transition failure, or final L0 mismatch: retain snapshots, write a redacted recovery report, quarantine the lab, and stop later targets.
- Never run an automatic aggressive reset.
- Never delete a retained fabric.
- Reject HTTP 207 as failure.
- Poll every 15 seconds; use 20 attempts for normal work and 40 for switch/vPC work; abort after three consecutive API errors.
- State directories must be mode `0700`; state files must be mode `0600`; credentials and secret environment values must not be serialized.

## 5. Minimal-change phase order

| Phase | Intended topology change | Targets grouped here |
|---|---|---|
| 1. `controller_disposable` | Controller-only; no retained switch mutation. | Five disposable-fabric smoke profiles and `integration.nd_manage_fabric`. |
| 2. `retained_no_switch` | Retained fabrics available; no switch, link, or vPC change. | ACL, prefix-list, route-map, VRF/network definition-only smoke, resource-manager gather, and zero-switch integration ACL/route-map profiles. |
| 3. `advanced_leaf` | Place/verify `adv_1` and `adv_2` in advanced as leaves when required. | Policy, VRF, network, smoke policy-group, and gather-only smoke switch profiles. |
| 4. `vpc_pair_isolated` | Leaf topology; each vPC-pair lifecycle target gets an isolated L2 envelope. | Smoke vPC pair and two expanded `integration.nd_vpc_pair` executions after confirmation. |
| 5. `advanced_virtual_vpc` | Verify one virtual vPC pair between `adv_1` and `adv_2`. | vPC access, vPC trunk-host, and resource-manager no-create-path targets. |
| 6. `border_external` | `adv_1=border`; `ext_1=edge_router` in external; unspecified members are preserved. | VRF-lite and L3Out smoke/integration profiles. |
| 7. `borrowed_switch` | Move `ext_1` once from external to advanced as leaf; keep `ext_2` snapshot-only. | `integration.nd_manage_policy_group`. |
| 8. `terminal_switch` | Advanced contains `adv_1=leaf`, `adv_2=spine`, `ext_1=border`. | Destructive `integration.nd_manage_switches`, always last. |
| 9. `final_restore` | Restore and compare the complete L0 baseline. | No module target; release the lock only after success. |

Transition rules:

- Use direct `changeRoles` for role drift when a switch remains in the same fabric.
- Remove/re-onboard only for a registry-declared membership move. The only approved candidate is the reversible `ext_1` borrow.
- `ext_2` is never an active test switch under the current draft; it is captured for restoration evidence only.
- A transition is legal only when its full membership, role, vPC, interface, resource, and managed-domain delta is declared in the registry.

## 6. Profile coverage by phase

The registry contains 19 smoke profiles and 13 integration profiles.

### Phase 1 — controller/disposable

| Profile | Fabric contract | Switches | Other prerequisite |
|---|---|---:|---|
| `smoke.nd_manage_fabric_ibgp_vxlan` | 1 disposable `vxlanIbgp` | 0 | exact `ANSIBLE_NIGHTLY_IBGP` lifecycle |
| `smoke.nd_manage_fabric_ebgp_vxlan` | 1 disposable `vxlanEbgp` | 0 | exact `ANSIBLE_NIGHTLY_EBGP` lifecycle |
| `smoke.nd_manage_fabric_ai_ibgp_vxlan` | 1 disposable `aimlVxlanIbgp` | 0 | exact `ANSIBLE_NIGHTLY_AI_IBGP` lifecycle |
| `smoke.nd_manage_fabric_ai_ebgp_vxlan` | 1 disposable `aimlVxlanEbgp` | 0 | exact `ANSIBLE_NIGHTLY_AI_EBGP` lifecycle |
| `smoke.nd_manage_fabric_external` | 1 disposable `externalConnectivity` | 0 | exact `ANSIBLE_NIGHTLY_EXTERNAL`; never retained external |
| `integration.nd_manage_fabric` | 0 prerequisite fabrics | 0 | target-created namespaced matrix across five types; pending owner confirmation |

### Phase 2 — retained/no-switch

| Profile | Fabric contract | Switches | Other prerequisite |
|---|---|---:|---|
| `smoke.nd_manage_acl` | advanced | 0 | ACL domain |
| `smoke.nd_manage_prefix_list` | advanced | 0 | prefix-list domain |
| `smoke.nd_manage_route_map` | advanced | 0 | route-map domain |
| `smoke.nd_manage_vrfs` | advanced | 0 | VRF domain |
| `smoke.nd_manage_networks` | advanced | 0 | definition-only network; no attachment link |
| `smoke.nd_manage_resource_manager` | advanced | 0 | existing `L3_VNI` pool, type `ID`; no replacement |
| `integration.nd_manage_route_map` | advanced | 0 proposed | owner table also names `switch_1`; confirmation required |
| `integration.nd_manage_acl` | advanced | 0 proposed | owner table also names `switch_1`; confirmation required |

### Phase 3 — advanced leaves

| Profile | Required switches/roles | Links/resources |
|---|---|---|
| `smoke.nd_manage_policy` | `adv_1=leaf` | none |
| `smoke.nd_manage_policy_group` | `adv_1=leaf`, `adv_2=leaf` | none |
| `smoke.nd_manage_switches` | `adv_1`, `adv_2`, roles preserved | gather-only |
| `integration.nd_manage_policy` | `adv_1=leaf`, `adv_2=leaf` | none |
| `integration.nd_manage_vrfs` | `adv_1=leaf` | standalone allocation range; no MSD/MCFG assumption |
| `integration.nd_manage_networks` | `adv_1=leaf` | `adv_1/Ethernet1/20`; standalone allocation range |

### Phase 4 — isolated vPC-pair lifecycle

| Profile/execution | Fabric | Required peers/roles | Pair contract |
|---|---|---|---|
| `smoke.nd_manage_vpc_pair` | advanced | `adv_1=leaf`, `adv_2=leaf` | virtual pair, no physical peer-link ports |
| `integration.nd_vpc_pair.advanced` | advanced | proposed `adv_1=leaf`, `adv_2=leaf` | mode is unresolved; blocked |
| `integration.nd_vpc_pair.external` | external | unresolved | peers, roles, fabric type, mode, and ports unresolved; blocked |

The two integration executions come from one logical profile and require separate confirmation evidence.

### Phase 5 — advanced virtual vPC

| Profile | Switch/vPC contract | Links/resources |
|---|---|---|
| `smoke.nd_interface_vpc_access` | advanced, `adv_1/adv_2=leaf`, virtual pair | Ethernet1/5–7 on both peers |
| `smoke.nd_interface_vpc_trunk_host` | same | Ethernet1/8–10 on both peers |
| `integration.nd_interface_vpc_access` | same | Ethernet1/5–7 on both peers |
| `integration.nd_interface_vpc_trunk_host` | same | Ethernet1/8–10 on both peers |
| `integration.nd_resource_manager` | same; existing-pair/no-create path | allocation entity tokens `Ethernet1/2`, `Ethernet1/3`, `Ethernet1/10`; they are not physical-link declarations; pending confirmation |

### Phase 6 — border/external

| Profile | Fabrics and roles | Links/resources |
|---|---|---|
| `smoke.nd_manage_vrf_lite` | advanced; `adv_1=border` | `adv_1/Ethernet1/20` |
| `smoke.nd_manage_l3out` | advanced + external; `adv_1=border`, `ext_1=edge_router` | Ethernet1/1 on both |
| `integration.nd_manage_l3out` | advanced + external; same roles | Ethernet1/1 routed and Ethernet1/2 subinterface mapping on both; VRF and route-map lifecycle unresolved |

### Phase 7 — borrowed switch

| Profile | Fabrics and roles | Other prerequisite |
|---|---|---|
| `integration.nd_manage_policy_group` | capture advanced + external; preserve `adv_1/adv_2`; move `ext_1` to advanced as leaf | confirm `ext_1` is the only borrowed switch and `ext_2` is snapshot-only |

### Phase 8 — terminal switch target

| Profile | Fabrics and roles | Other prerequisite |
|---|---|---|
| `integration.nd_manage_switches` | capture advanced + external; active advanced set `adv_1=leaf`, `adv_2=spine`, `ext_1=border` | snapshot all four switches; confirm active set, `ext_2` treatment, `save=true`, `deploy=true`, and switch-scoped config actions |

## 7. Owner confirmations still required

The schema default is `confirmation.status: pending`, with blank owner/evidence, so **all profiles are currently non-executable**. Ordinary profiles need an owner and evidence/reference confirming their encoded prerequisite contract. The following profiles also contain specific unresolved questions:

| Profile | Required owner decision |
|---|---|
| `integration.nd_manage_policy_group` | Is `ext_1` the sole borrowed switch? Is `ext_2` snapshot-only? |
| `integration.nd_manage_route_map` | Is the true prerequisite zero switches, or is the owner-table `switch_1` required? |
| `integration.nd_manage_acl` | Is the true prerequisite zero switches, or is the owner-table `switch_1` required? |
| `integration.nd_manage_l3out` | Confirm routed/subinterface wiring, prerequisite VRF lifecycle, and route-map names/lifecycle. |
| `integration.nd_manage_switches` | Confirm the three-switch active set, `ext_2` treatment, and save/deploy/config-action settings. |
| `integration.nd_manage_fabric` | Confirm zero prerequisite fabrics and the exact target-created disposable-fabric matrix. |
| `integration.nd_resource_manager` | Confirm existing virtual-vPC no-create path, prohibit physical fallback, and confirm interface strings are allocation entity tokens. |
| `integration.nd_vpc_pair.advanced` | Confirm virtual versus physical mode and physical ports if applicable. |
| `integration.nd_vpc_pair.external` | Confirm exact external peers, roles, fabric type, pair mode, and physical ports if applicable. |

No `??`, `proposed`, blank, or unresolved virtual-versus-physical value may be promoted into a live action.

## 8. Intended per-target invocation boundary

Before the first `cisco.nd` module task, the eventual wrapper must:

1. Validate the registry and exact profile/playbook mapping.
2. Reject pending/rejected confirmations.
3. Verify credentials and discover current fabric/switch/interface/vPC/resource state read-only.
4. Validate L0/L1 lineage and acquire the shared lab lock.
5. Plan only declared, allowlisted operations.
6. Reconcile the phase topology and poll to convergence.
7. Capture L2 and write a fresh restricted runtime-variable file plus prepared marker.
8. Require matching run ID, profile ID, phase ID, and freshness before module invocation.
9. Run the module target.
10. In `finally`, restore L2, compare to L1, and preserve the target exit code only if restore succeeds.

The current Jenkins runner does not yet implement this boundary. That is future work.

## 9. Implementation completed in staging

### Documentation/design commit

`e4b0cd2 docs: approve phase-batched prerequisite orchestration`

- Added the active phase-batched implementation plan.
- Updated the design with the L0/L1/L2 model, minimized topology transitions, confirmation gate, and strict failure policy.

### Task 1 — authoritative registry and static gate

Commits:

- `91eb0a1 feat: define phase-batched prerequisite profiles`
- `33789fc fix: harden prerequisite safety gates`
- `28628b4 fix: close prerequisite validation bypasses`
- `92dd615 fix: require concrete delete and runtime gates`

Implemented:

- Schema version 2 registry for all 32 logical profiles.
- Retained/disposable fabric registry, exact switch identities, interface allowlist, phases, topology templates, full managed-domain/runtime/timeout/restore/confirmation contracts.
- Expansion of `integration.nd_vpc_pair` into advanced and external executions.
- Static and semantic retained-fabric delete guards.
- Exact playbook/Jenkins mapping checks.
- Child-execution confirmation validation.
- Runtime-marker, lineage, checkpoint-permission, and symlink protections.
- Canonical registry/interface reference validation.

Task 1 received iterative independent review and the reported important findings were fixed before the latest clean review.

### Task 2 — offline planner and snapshot contracts

Commit:

`03acab6 feat: plan phase-batched prerequisite transitions`

Implemented as pure/offline logic:

- Deterministic phase and execution resolution.
- Pending-profile rejection.
- Snapshot normalization and L0/L1/L2 lineage checks.
- Current-versus-desired topology comparison.
- Allowlisted operation planning for namespaced disposable fabric creation, declared `ext_1` membership move, same-fabric role change, allowlisted interface reconciliation, virtual-vPC reconciliation, and resource verification.
- Rejection of retained-fabric deletion, undeclared switch/interface/resource actions, stale markers, invalid lineage, HTTP 207, and repeated API errors.
- Restricted YAML/JSON state writing and restore/quarantine state transitions.

Task 2's independent code review was started but intentionally interrupted when the user said to stop. It must not be called review-complete.

## 10. Files changed only in staging

Relative to staging baseline `97c3167`, these nine files differ:

1. `docs/superpowers/plans/2026-08-27-nd-phase-batched-prerequisite-orchestration.md` — new
2. `docs/superpowers/specs/2026-08-26-nd-integration-prerequisite-orchestration-design.md` — modified
3. `tests/fixtures/nd_prerequisite/transitions.yaml` — new
4. `tests/fixtures/nd_prerequisite/valid_state.yaml` — new
5. `tests/nd_prerequisite_orchestrator.py` — new
6. `tests/nd_prerequisite_profiles.yaml` — modified
7. `tests/test_nd_prerequisite_orchestrator.py` — new
8. `tests/test_validate_nd_prerequisites.py` — modified
9. `tests/validate_nd_prerequisites.py` — modified

Change size at stopped HEAD: 2,154 insertions and 57 deletions.

This handoff document is an additional documentation-only file created after the stop request. It does not change runtime behavior.

## 11. Verification evidence at the stop point

Freshly rerun in the staging repository on 2026-08-27:

```text
python3 -m pytest -q \
  tests/test_validate_nd_prerequisites.py \
  tests/test_nd_prerequisite_orchestrator.py

25 passed in 1.19s
```

Also verified:

- Staging Git status was clean before adding this handoff document.
- Staging HEAD was `03acab6`.
- The four pre-existing OneDrive files modified in staging matched their `97c3167` baseline Git blobs byte-for-byte.
- The new Task 2 files and the new phase plan were absent from the OneDrive target.

These are offline/unit/static checks only. They do not prove live ND behavior, Ansible wrapper correctness, Jenkins orchestration, Consul publication, or restoration against the real lab.

## 12. Work not done

- Task 2 independent review and any resulting fixes.
- Common Ansible lifecycle wrapper and capture/reconcile/wait/verify/restore task files.
- Metadata and prepared-marker gates in all 19 playbooks.
- Removal of retained-fabric delete hazards from the relevant playbooks.
- Integration runner conversion to generated runtime variables and visible cleanup failures.
- Jenkins phase scheduler, common target lifecycle, quarantine stop, and final L0 restore.
- Release manifest, publisher completion, reset-playbook restrictions, full local verification, secret scan, and checkpoint report.
- Whole-change independent review.
- Applying reviewed files into the OneDrive target.
- Any Consul write, ND/controller mutation, Jenkins run, Git push, PR, or publication.

The active staged plan has seven implementation/review work packages. It refines and repackages the earlier 11-task plan; task numbers from the two documents must not be mixed. At the stop point, only Tasks 1 and the unreviewed implementation portion of Task 2 in the active plan exist.

## 13. Safe continuation point

If work is explicitly resumed later, continue from the staging repository and use this order:

1. Confirm the staging directory still exists and is clean at `03acab6` plus this handoff-only change.
2. Re-run the 25 focused tests.
3. Complete an independent Task 2 review; fix and re-review all important findings.
4. Collect owner confirmation/evidence and update the registry. Do not start live preparation while any selected execution is pending.
5. Implement the common Ansible wrapper before touching playbooks or Jenkins ordering.
6. Wire all 19 playbooks and the integration runner.
7. Implement the Jenkins phase scheduler.
8. Complete release safety, full local verification, and whole-change review.
9. Only then apply reviewed diffs to the exact OneDrive target and verify each file byte-for-byte.
10. Do not push. Do not publish to Consul or mutate the controller without separate explicit authorization and confirmed profiles.

## 14. Current stop guarantee

At the time this handoff was written:

- no agent remained active;
- no implementation was running in the background;
- no live system was being polled or mutated;
- no implementation change had been copied into the OneDrive target;
- the only post-stop action was read-only verification and creation of this documentation.
