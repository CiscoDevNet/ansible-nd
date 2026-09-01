# `nd_interface_ethernet_access` Harness Parity

This document maps every scenario in the original
`nd_interface_ethernet_access` integration suite to its ND 4.x harness-based
replacement.

All original scenarios now have implemented replacements. The complete safe,
destructive, and original suites passed live validation on 2026-08-31 against
the same controller, fabric, switch, and collection worktree based on commit
`a682edd30efde3484d29e579535ad0b4366621ab`.

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

## Assertion and safety coverage

Each positive harness scenario provides:

- Predictive, real-apply, and real-idempotency expectations.
- Controller snapshots before and after predictive execution for every switch
  in the fabric.
- Recursive normalization, unordered list comparison, and exclusion of only
  the volatile `operData` field.
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

Run the complete safe replacement suite with:

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
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
  --tags nd4x_demo_overridden \
  -vv
```

## Same-environment execution record

The complete safe and destructive replacement suites passed against the same
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
| Unmapped implementation scenarios | None |

The safe replacement run used the `nd4x_demo` tag. The destructive replacement
run used the `nd4x_demo_overridden` tag with explicit destructive-test opt-in.
The original run used no tag selection. All three runs completed their
reserved-interface cleanup.

The target harness and parity-document changes were uncommitted test-worktree
changes during these runs; the module implementation was based on the commit
recorded above.

## Retirement decision

All original scenarios now have live-passed replacements, and the original
suite has passed against the same environment. The original suite should
remain until:

1. The complete safe and destructive replacement suites continue to pass live
   validation.
2. Any controller-specific assertion differences are resolved without
   weakening original behavior.
3. Reviewers accept the recorded evidence and explicitly approve retirement.
