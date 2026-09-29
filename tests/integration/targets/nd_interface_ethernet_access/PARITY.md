# `nd_interface_ethernet_access` Harness Parity

This document maps every scenario in the original
`nd_interface_ethernet_access` integration suite to its ND 4.x harness-based
replacement.

All original scenarios have implemented replacements. The 2026-08-31 full
safe and destructive runs were against `VXLAN_Fabric`; the 2026-09-06
follow-up harness and legacy runs were against `Astha_Fabric`. The subsequently
added multi-switch scenarios were run on 2026-09-29 against `VXLAN_Fabric`; the
scenario-specific results are recorded separately.

## Status definitions

- **Live run passed**: the replacement exists and a successful controller run
  has been recorded.
- **Implemented; run pending**: the replacement exists, but current live-run
  evidence has not yet been recorded.

## Scenario mapping

### Setup and lifecycle

| Original scenario | Harness replacement | Status |
|---|---|---|
| Remove Ethernet1/41 through Ethernet1/50 before the state sequence | Scenario-local setup in every harness state file | Live run passed on 2026-08-31 |
| Final removal of all reserved test interfaces | Scenario-local cleanup under `always`; destructive and deleted files normalize the complete reserved range | Live run passed on 2026-08-31 |

### Merged state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Create Ethernet1/41 in check and normal mode | `MERGED CREATE: Configure Ethernet1/41` | Live run passed on 2026-08-31 |
| Create Ethernet1/42 and Ethernet1/43 through fan-out | `MERGED FAN-OUT: Configure Ethernet1/42 and Ethernet1/43` | Live run passed on 2026-08-31 |
| Create Ethernet1/44 separately | `MERGED CREATE: Configure Ethernet1/44` | Live run passed on 2026-08-31 |
| Re-run converged Ethernet1/41 in check and normal mode | `MERGED IDEMPOTENT: Re-run converged Ethernet1/41` | Live run passed on 2026-08-31 |
| Re-run fan-out configuration idempotently | Harness idempotency phase in the two-interface fan-out scenario | Live run passed on 2026-08-31 |
| Update Ethernet1/41 VLAN, description, BPDU guard, and CDP | `MERGED UPDATE: Update Ethernet1/41` | Live run passed on 2026-08-31 |
| Re-apply the Ethernet1/41 update idempotently | Harness idempotency phase in the single-interface update | Live run passed on 2026-08-31 |
| Update Ethernet1/42 and Ethernet1/43 through fan-out | `MERGED FAN-OUT UPDATE: Update Ethernet1/42 and Ethernet1/43` | Live run passed on 2026-08-31 |
| Stage Ethernet1/48 with `deploy: false` | `MERGED NO-DEPLOY: Stage Ethernet1/48` | Live run passed on 2026-08-31 |
| Create Ethernet1/45 through Ethernet1/47 through fan-out with jumbo MTU | `MERGED LARGE FAN-OUT: Configure Ethernet1/45 through Ethernet1/47` | Live run passed on 2026-08-31 |
| Re-apply the large fan-out idempotently | Harness idempotency phase in the large fan-out scenario | Live run passed on 2026-08-31 |
| Configure Ethernet1/49 and Ethernet1/50 with different config groups | `MERGED SPLIT: Configure different settings in one invocation` | Live run passed on 2026-08-31 |
| Re-apply the split configuration idempotently | Harness idempotency phase in the split-config scenario | Live run passed on 2026-08-31 |
| Configure the same interface name on two switches in one module call | `tasks/nd4x_demo_multi_switch.yaml`; uses the first VPC pair with different VLANs | Live run passed on 2026-09-29 |
| Replace the same interface on two switches in one module call | `tasks/nd4x_demo_replaced_multi_switch.yaml`; distinct VLAN and description on each switch | Live run passed on 2026-09-29 |
| Delete the same interface on two switches in one module call | `tasks/nd4x_demo_deleted_multi_switch.yaml`; per-switch API checks confirm both policies were removed | Live run passed on 2026-09-29 |

### Replaced state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Replace Ethernet1/41 with the original partial payload | `REPLACED SINGLE: Replace Ethernet1/41 with partial payload` | Live run passed on 2026-08-31 |
| Re-apply the single replacement idempotently | Harness idempotency phase in the single replacement | Live run passed on 2026-08-31 |
| Replace Ethernet1/42 and Ethernet1/43 through fan-out | `REPLACED FAN-OUT: Replace Ethernet1/42 and Ethernet1/43` | Live run passed on 2026-08-31 |
| Replace Ethernet1/41 and Ethernet1/44 through separate config groups | `REPLACED MULTI: Replace Ethernet1/41 and Ethernet1/44` | Live run passed on 2026-08-31 |

### Overridden state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Reduce the complete post-replaced set to Ethernet1/41 and Ethernet1/42 | Exact merged-to-replaced setup followed by `OVERRIDDEN REDUCE: Retain Ethernet1/41 and Ethernet1/42` | Live run passed on 2026-08-31 |
| Re-apply the same overridden configuration idempotently | Harness idempotency plus `OVERRIDDEN FILTER: Re-run identical override` | Live run passed on 2026-08-31 |
| Prove non-`accessHost` interfaces are excluded | Ethernet1/48 controller snapshot plus managed-collection exclusion and before/after comparison | Live run passed on 2026-08-31 |
| Swap the desired set to Ethernet1/42 through Ethernet1/44 | `OVERRIDDEN SWAP: Retain Ethernet1/42 through Ethernet1/44` | Live run passed on 2026-08-31 |
| Override to Ethernet1/45 through Ethernet1/47 through fan-out | `OVERRIDDEN FAN-OUT: Retain Ethernet1/45 through Ethernet1/47` | Live run passed on 2026-08-31 |
| Override two switches in one call, retaining Ethernet1/41 on A and Ethernet1/42 on B while normalizing the omitted test ports | `tasks/nd4x_demo_overridden_multi_switch.yaml`; fabric-wide preflight and cleanup | Live run passed on 2026-09-29 |

The original pre-override state includes Ethernet1/41 through Ethernet1/47 and
Ethernet1/49 through Ethernet1/50. Ethernet1/48 is normalized and is used as a
non-`accessHost` sentinel.

### Deleted state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Delete Ethernet1/45 in check and normal mode | `DELETED SINGLE: Normalize Ethernet1/45` | Live run passed on 2026-08-31 |
| Delete Ethernet1/45 again and expect no change | Harness idempotency phase in the single deletion | Live run passed on 2026-08-31 |
| Delete Ethernet1/46 and Ethernet1/47 through fan-out | `DELETED FAN-OUT: Normalize Ethernet1/46 and Ethernet1/47` | Live run passed on 2026-08-31 |
| Delete Ethernet1/41 through Ethernet1/43 through multiple config groups | `DELETED MULTI: Normalize multiple config groups` | Live run passed on 2026-08-31 |
| Delete independently normalized Ethernet1/48 and expect no change | `DELETED NON-EXISTENT: Normalize Ethernet1/48 again` | Live run passed on 2026-08-31 |

### Added negative coverage

| Added scenario | Harness replacement | Status |
|---|---|---|
| Reject missing `interface_names` and verify the reason | `tasks/nd4x_demo_negative.yaml` | Live run passed on 2026-08-31 |

The original suite contains no negative integration-test scenario. This added
case expects apply failure, verifies the required-argument reason, and confirms
that idempotency and REST phases did not execute.

### Added multi-switch coverage

The multi-switch scenarios configure, replace, and delete Ethernet1/41 on both
test switches in one module call. The 2026-09-29 live runs used
`VXLAN_Fabric`, with test switches `10.122.84.71` and `10.122.84.63`.
Preflight resolves both switch IDs from ND,
checks that the second switch ID matches the inventory value, and confirms the
test port exists and is not a port-channel member on both switches. Each
scenario compares whole-fabric snapshots around check mode, verifies both
per-switch API results, checks idempotency, and normalizes both ports under
`always` cleanup. All three scenarios passed the tagged live harness run on
2026-09-29 (`ok=42`, `changed=7`, `failed=0`).

The second switch is configured with `nd_test_vpc_peer2_ip` and
`nd_test_vpc_peer2_id` in `inventory.LOCAL.networking`.

The separate multi-switch `overridden` scenario is destructive. It seeds
Ethernet1/41 and Ethernet1/42 on each test switch, then
retains Ethernet1/41 on switch A and Ethernet1/42 on switch B. Its preflight
rejects any existing `accessHost` interface outside those four reserved ports
across the fabric. Its `always` cleanup normalizes all four ports. It checks
that omitted ports leave `accessHost` scope, both retained policies are
correct, non-accessHost sentinels on both switches are unchanged, and a repeat
override is idempotent. The tagged live run passed on 2026-09-29
(`ok=45`, `changed=3`, `failed=0`).

### Port-channel member protection

The separate `nd4x_demo_port_channel_guard` scenario checks that both a
forbidden `access_vlan` change and a delete request on a live port-channel
member fail during Ansible check-mode, and confirms through a REST read that
neither policy nor membership changed. It requires an explicitly dedicated
member fixture. Set
`nd_ethernet_pc_guard_confirmed=true` and provide
`nd_ethernet_pc_guard_switch_ip`, `nd_ethernet_pc_guard_interface`, and
`nd_ethernet_pc_guard_port_channel_id` in the test inventory. Preflight checks
that the interface is an Ethernet port with exactly that port-channel ID. The
scenario makes no normal-mode module call and does not alter the interface.
This scenario is implemented but has not been run because the current local
inventory does not identify a dedicated port-channel member fixture. **Live
validation pending.**

## Assertion and safety coverage

Each positive harness scenario provides:

- Predictive, real-apply, and real-idempotency expectations.
- Controller snapshots before and after predictive execution for every switch
  in the fabric.
- Interface collection ordering is ignored through the explicit `/interfaces`
  snapshot path; nested list ordering remains significant. Only the volatile
  `operData` field is excluded.
- Module-specific assertions against `first_run_result.after`.
- Post-apply REST validation of retained, updated, staged, normalized, and
  removed `accessHost` configuration.
- Scenario-local setup and cleanup under `always`.
- A 300-second Ansible connection timeout scoped to the target block.

The shared preflight additionally provides:

- ND 4.0.0-or-later gating.
- Explicit reserved-port confirmation.
- Dynamic `switchId` resolution from `fabricManagementIp`.
- Validation that every reserved port exists, is Ethernet, and is not a
  port-channel member.
- One predictive snapshot query per fabric switch.

The destructive overridden suite additionally provides:

- Explicit destructive-test opt-in.
- Read-only discovery of `accessHost` configuration on every fabric switch.
- Rejection of managed resources on other switches or outside Ethernet1/41
  through Ethernet1/50.
- Reconstruction and verification of the exact original pre-override state.
- A non-`accessHost` sentinel comparison across real override operations.
- Full reserved-range cleanup.

## Tags and safety

Harness scenarios retain the `never` tag while parity validation is in
progress. A normal untagged target run continues to execute the original
suite.

Safe scenarios require:

```ini
nd_ethernet_reserved_ports_confirmed=true
```

Multi-switch merged, replaced, and deleted cases run with
`nd4x_demo_multi_switch` (or the broader `nd4x_demo`) and require the second
switch IP and ID. The port-channel guard has its own tag and requires the
confirmed fixture variables above.

Run the complete safe replacement suite with:

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo,nd4x_demo_preflight \
  -vv
```

The destructive replacement requires both:

```ini
nd_ethernet_reserved_ports_confirmed=true
nd_ethernet_destructive_tests_enabled=true
```

Run it separately on a dedicated fabric:

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden,nd4x_demo_preflight \
  --allow-destructive \
  -vv
```

Run the multi-switch `overridden` scenario by itself with:

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden_multi_switch \
  --allow-destructive \
  -vv
```

Do not include the `never` tag in these commands. Ansible treats selected tags
as alternatives, so selecting `never` activates other opt-in scenarios too.

## Deployment scope

Live switch/controller integration is **IN SCOPE**. Current safe and
destructive harness runs performed real configuration and cleanup on
`Astha_Fabric`. The legacy suite remains enabled and also completed on the
same testbed.

## Same-environment execution record

The historical safe and destructive replacement suites passed against the same
ND 4.2.1 environment on 2026-08-31 using collection commit
`a682edd30efde3484d29e579535ad0b4366621ab`.

| Evidence | Result |
|---|---|
| Collection commit | `a682edd30efde3484d29e579535ad0b4366621ab` |
| Nexus Dashboard version | `platformVersion: 4.2.1` |
| Fabric | `VXLAN_Fabric` |
| Test switch | Management IP `10.122.84.71`; discovered switch ID `9WME34GIAPX` |
| Complete safe replacement run | Passed on 2026-08-31; 83 tests, 0 failures, 0 errors, 2 skipped |
| Complete destructive replacement run | Passed on 2026-08-31; 51 tests, 0 failures, 0 errors, 3 skipped |
| Safe-run JUnit artifact | `tests/output/junit/nd_interface_ethernet_access-ikvaey6o-1788157802.610605.xml` |
| Destructive-run JUnit artifact | `tests/output/junit/nd_interface_ethernet_access-b9j5k705-1788159564.175429.xml` |
| Original suite run at this commit/environment | Passed on 2026-08-31; 95 tests, 0 failures, 0 errors, 1 skipped; `ok=89 changed=30 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0` |
| Original-run JUnit artifact | `tests/output/junit/nd_interface_ethernet_access-23wmhdy4-1788161053.3463218.xml` |
| Earlier harness safe run | 2026-09-06 on `Astha_Fabric`; `ok=74 changed=21 failed=0 skipped=2` |
| Earlier harness destructive/overridden run | 2026-09-06 on `Astha_Fabric`; `ok=47 changed=9 failed=0 skipped=2` |
| Multi-switch merged/replaced/deleted run | 2026-09-29 on `VXLAN_Fabric`; `ok=42 changed=7 failed=0 skipped=2` |
| Multi-switch overridden run | 2026-09-29 on `VXLAN_Fabric`; `ok=45 changed=3 failed=0 skipped=3` |
| Current legacy run | Passed; `ok=89 changed=30 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0` |
| Earlier testbed | ND `4.2.1`; `Astha_Fabric`; selected switch `10.122.84.71` |
| Current PR base HEAD | `f19ece994ca7e3b9e1502c7d6a02c19a4998fc81` plus uncommitted changes |
| Current local develop reference | `576a681dd9c52b56640d7d27c8c5b6924735ed4a` |
| Static scenario mapping | Complete for the current Ethernet access scenario set |

The safe replacement run used the `nd4x_demo` tag. The destructive replacement
run used the `nd4x_demo_overridden` tag with explicit destructive-test opt-in.
The original run used no tag selection. All three runs completed their
reserved-interface cleanup.

The target harness and parity-document changes were uncommitted test-worktree
changes during these runs; the module implementation was based on the commit
recorded above.

## Retirement decision

The original suite should remain enabled until current-HEAD validation is
complete and reviewers approve retirement. Required validation is:

1. The complete safe and destructive replacement suites continue to pass live
   validation.
2. Any controller-specific assertion differences are resolved without
   weakening original behavior.
3. Reviewers accept the recorded evidence and explicitly approve retirement.
