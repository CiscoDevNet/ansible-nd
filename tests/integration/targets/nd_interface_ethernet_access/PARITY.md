# `nd_interface_ethernet_access` Harness Parity

This document maps every scenario in the original
`nd_interface_ethernet_access` integration suite to its ND 4.x harness-based
replacement.

All original scenarios now have implemented replacements. Live validation of
the complete safe and destructive replacement suites is still required before
the original suite can be retired.

## Status definitions

- **Live run passed**: the replacement exists and a successful controller run
  has been recorded.
- **Implemented; run pending**: the replacement exists, but current live-run
  evidence has not yet been recorded.

## Scenario mapping

### Setup and lifecycle

| Original scenario | Harness replacement | Status |
|---|---|---|
| Remove Ethernet1/41 through Ethernet1/50 before the state sequence | Scenario-local setup in every harness state file | Implemented; run pending |
| Final removal of all reserved test interfaces | Scenario-local cleanup under `always`; destructive and deleted files normalize the complete reserved range | Implemented; run pending |

### Merged state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Create Ethernet1/41 in check and normal mode | `MERGED CREATE: Configure Ethernet1/41` | Implemented; run pending |
| Create Ethernet1/42 and Ethernet1/43 through fan-out | `MERGED FAN-OUT: Configure Ethernet1/42 and Ethernet1/43` | Live run passed on 2026-08-12 |
| Create Ethernet1/44 separately | `MERGED CREATE: Configure Ethernet1/44` | Implemented; run pending |
| Re-run converged Ethernet1/41 in check and normal mode | `MERGED IDEMPOTENT: Re-run converged Ethernet1/41` | Implemented; run pending |
| Re-run fan-out configuration idempotently | Harness idempotency phase in the two-interface fan-out scenario | Live run passed on 2026-08-12 |
| Update Ethernet1/41 VLAN, description, BPDU guard, and CDP | `MERGED UPDATE: Update Ethernet1/41` | Implemented; run pending |
| Re-apply the Ethernet1/41 update idempotently | Harness idempotency phase in the single-interface update | Implemented; run pending |
| Update Ethernet1/42 and Ethernet1/43 through fan-out | `MERGED FAN-OUT UPDATE: Update Ethernet1/42 and Ethernet1/43` | Implemented; run pending |
| Stage Ethernet1/48 with `deploy: false` | `MERGED NO-DEPLOY: Stage Ethernet1/48` | Implemented; run pending |
| Create Ethernet1/45 through Ethernet1/47 through fan-out with jumbo MTU | `MERGED LARGE FAN-OUT: Configure Ethernet1/45 through Ethernet1/47` | Implemented; run pending |
| Re-apply the large fan-out idempotently | Harness idempotency phase in the large fan-out scenario | Implemented; run pending |
| Configure Ethernet1/49 and Ethernet1/50 with different config groups | `MERGED SPLIT: Configure different settings in one invocation` | Implemented; run pending |
| Re-apply the split configuration idempotently | Harness idempotency phase in the split-config scenario | Implemented; run pending |

### Replaced state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Replace Ethernet1/41 with the original partial payload | `REPLACED SINGLE: Replace Ethernet1/41 with partial payload` | Implemented; run pending |
| Re-apply the single replacement idempotently | Harness idempotency phase in the single replacement | Implemented; run pending |
| Replace Ethernet1/42 and Ethernet1/43 through fan-out | `REPLACED FAN-OUT: Replace Ethernet1/42 and Ethernet1/43` | Implemented; run pending |
| Replace Ethernet1/41 and Ethernet1/44 through separate config groups | `REPLACED MULTI: Replace Ethernet1/41 and Ethernet1/44` | Implemented; run pending |

### Overridden state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Reduce the complete post-replaced set to Ethernet1/41 and Ethernet1/42 | Exact merged-to-replaced setup followed by `OVERRIDDEN REDUCE: Retain Ethernet1/41 and Ethernet1/42` | Implemented; run pending |
| Re-apply the same overridden configuration idempotently | Harness idempotency plus `OVERRIDDEN FILTER: Re-run identical override` | Implemented; run pending |
| Prove non-`accessHost` interfaces are excluded | Ethernet1/48 controller snapshot plus managed-collection exclusion and before/after comparison | Implemented; run pending |
| Swap the desired set to Ethernet1/42 through Ethernet1/44 | `OVERRIDDEN SWAP: Retain Ethernet1/42 through Ethernet1/44` | Implemented; run pending |
| Override to Ethernet1/45 through Ethernet1/47 through fan-out | `OVERRIDDEN FAN-OUT: Retain Ethernet1/45 through Ethernet1/47` | Implemented; run pending |

The original pre-override state includes Ethernet1/41 through Ethernet1/47 and
Ethernet1/49 through Ethernet1/50. Ethernet1/48 is normalized and is used as a
non-`accessHost` sentinel.

### Deleted state

| Original scenario | Harness replacement | Status |
|---|---|---|
| Delete Ethernet1/45 in check and normal mode | `DELETED SINGLE: Normalize Ethernet1/45` | Implemented; run pending |
| Delete Ethernet1/45 again and expect no change | Harness idempotency phase in the single deletion | Implemented; run pending |
| Delete Ethernet1/46 and Ethernet1/47 through fan-out | `DELETED FAN-OUT: Normalize Ethernet1/46 and Ethernet1/47` | Implemented; run pending |
| Delete Ethernet1/41 through Ethernet1/43 through multiple config groups | `DELETED MULTI: Normalize multiple config groups` | Implemented; run pending |
| Delete independently normalized Ethernet1/48 and expect no change | `DELETED NON-EXISTENT: Normalize Ethernet1/48 again` | Implemented; run pending |

### Added negative coverage

| Added scenario | Harness replacement | Status |
|---|---|---|
| Reject missing `interface_names` and verify the reason | `tasks/nd4x_demo_negative.yaml` | Implemented; run pending |

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
- A 300-second timeout for target-module operations.

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

The original and complete replacement suites have not yet been recorded as
passing against the same environment.

| Evidence | Result |
|---|---|
| Nexus Dashboard version | ND 4.x preflight passed previously; exact `platformVersion` not recorded |
| Fabric and switch | Pending |
| Original suite run | Pending |
| Complete safe replacement run | Pending |
| Complete destructive replacement run | Pending |
| Earlier merged fan-out run | Passed on 2026-08-12; `ok=25 changed=2 unreachable=0 failed=0 skipped=2 rescued=0 ignored=0` |
| Unmapped implementation scenarios | None |

Run the original, safe replacement, and destructive replacement suites against
the same controller, fabric, switch, and collection commit. Record the date,
commit SHA, exact `platformVersion`, fabric name, management IP, discovered
switch ID, commands, and play recaps.

## Retirement decision

All original scenarios now have implemented replacements, but the original
suite must remain until:

1. The complete safe and destructive replacement suites pass live validation.
2. The original suite passes against the same environment and collection
   commit.
3. Any controller-specific assertion differences are resolved without
   weakening original behavior.
4. Reviewers accept the recorded evidence and explicitly approve retirement.
