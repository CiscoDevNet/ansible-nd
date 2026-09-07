# `nd_interface_loopback` Harness Parity

This document maps every scenario in the original `nd_interface_loopback`
integration suite to its harness-based replacement.

The implementation in this worktree is based on local PR commit
`f19ece994ca7e3b9e1502c7d6a02c19a4998fc81`; the current changes are
uncommitted working-tree content. The current live harness runs below were
executed on 2026-09-06 against ND 4.2.1 and `Astha_Fabric`. Historical
`Live run passed` entries in the mapping are retained as historical evidence;
the current result is recorded in the current-HEAD section.

The original state files remain in place until the original and replacement
suites have both passed against the same controller environment and the results
below have been recorded.

## Scenario mapping

| Original scenario | Original task file | Harness replacement | Status |
|---|---|---|---|
| Pre-test removal of reserved loopbacks | `tasks/setup.yaml` | Scenario-local setup and `always` cleanup in every `nd4x_demo_*.yaml` file | Live run passed |
| Create loopback100 in check and normal mode | `tasks/merged.yaml` | `MERGED CREATE: Create loopback100 using the ND 4.x harness` | Live run passed |
| Create loopback101 and loopback102 together | `tasks/merged.yaml` | `MERGED MULTI: Create loopback101 and loopback102` | Live run passed |
| Check-mode and normal-mode idempotency after create | `tasks/merged.yaml` | `MERGED IDEMPOTENT: Re-run loopback100 through all phases` | Live run passed |
| Update loopback100 IP, description, and route-map tag | `tasks/merged.yaml` | `MERGED UPDATE: Update loopback100` | Live run passed |
| Re-apply merged update idempotently | `tasks/merged.yaml` | Harness idempotency phase in `MERGED UPDATE: Update loopback100` | Live run passed |
| Stage loopback103 with `deploy: false` | `tasks/merged.yaml` | `MERGED NO-DEPLOY: Stage loopback103 without deployment` | Live run passed |
| Create loopback204 with `10.100.104.1/32` and `2001:db8:204::1/128`, verify both bare-address normalizations, and reapply idempotently | `tasks/merged.yaml` | `MERGED CIDR: Create loopback204 with a CIDR-format ip` | Implemented; current-HEAD run reached this task but stalled in the controller call |
| Replace loopback100 with the original partial payload | `tasks/replaced.yaml` | `REPLACED: Replace loopback100 with the original test payload` | Live run passed |
| Re-apply single replacement idempotently | `tasks/replaced.yaml` | Harness idempotency phase in the single replacement | Live run passed |
| Replace loopback100 and loopback101 together | `tasks/replaced.yaml` | `REPLACED MULTI: Replace loopback100 and loopback101` | Live run passed |
| Reduce loopback100-loopback102 to loopback100 | `tasks/overridden.yaml` | Exact merged-to-replaced pre-state followed by `OVERRIDDEN REDUCE: Retain only loopback100`, with fabric-wide predictive snapshots | Destructive live run passed |
| Re-apply override idempotently | `tasks/overridden.yaml` | Harness idempotency phase plus `OVERRIDDEN FILTER: Re-run identical override`, with fabric-wide predictive snapshots | Destructive live run passed |
| Exclude system loopback0 and loopback1 from managed scope | `tasks/overridden.yaml` | `OVERRIDDEN FILTER: Verify system loopbacks are excluded` | Destructive live run passed |
| Swap loopback100 for loopback101 and loopback102 | `tasks/overridden.yaml` | `OVERRIDDEN SWAP: Replace loopback100 with loopback101 and loopback102`, with fabric-wide predictive snapshots | Destructive live run passed |
| Delete one loopback | `tasks/deleted.yaml` | `DELETED SINGLE: Delete loopback101` | Live run passed |
| Re-delete the same loopback idempotently | `tasks/deleted.yaml` | Harness idempotency phase in the single deletion | Live run passed |
| Delete loopback100-loopback102 together | `tasks/deleted.yaml` | `DELETED MULTI: Delete loopback100 through loopback102` | Live run passed |
| Delete independently nonexistent loopback199 | `tasks/deleted.yaml` | `DELETED NON-EXISTENT: Delete loopback199` | Live run passed |
| Optional IOS-XE merged/replaced/overridden/deleted workflows | `tasks/xe.yaml` | No ND4x harness equivalent; legacy optional suite remains enabled | Harness coverage pending; conditional on `nd_test_xe_switch_ip` |
| Reject missing `interface_name` and verify the reason | No original scenario | `tasks/nd4x_demo_negative.yaml` | Added coverage; live run passed |

## Assertion coverage

Each harness scenario preserves the original expectations for predictive
`changed`, real-apply `changed`, returned `after` state, and idempotency.

The replacement suite additionally provides:

- A full managed-interface controller snapshot before and after every
  predictive check-mode execution.
- Recursive normalization, unordered list comparison, and exclusion of the
  volatile `operData` field.
- REST validation of retained, updated, created, and removed loopbacks after
  real apply.
- Scenario-local setup and guaranteed `always` cleanup.
- A destructive-test opt-in and reserved-scope preflight for `overridden`.
- A 300-second target-module timeout for controller deploy operations.
- ND-version gating for 4.0.0 and later.
- Dynamic resolution of `switchId` from the configured
  `fabricManagementIp`; `nd_test_switch_id` is not used by this target.

The original suite contains no negative integration-test scenario, so there is
no original negative case to map. The replacement suite adds a safe validation
scenario that omits `interface_name`, expects apply failure, and verifies both
the required-argument reason and the missing field name. It does not accept an
arbitrary `failed: true` result.

## Tags and safety

Harness scenarios retain the `never` tag while parity validation is in
progress. A normal target run continues to execute only the original suite.

The safe replacement run excludes `overridden`:

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo,nd4x_demo_preflight \
  --skip-tags nd4x_demo_overridden \
  -vv
```

The destructive replacement run requires this inventory variable on a
dedicated test fabric:

```ini
nd_loopback_destructive_tests_enabled=true
```

Run it with:

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo_overridden,nd4x_demo_preflight \
  --allow-destructive \
  -vv
```

## Deployment scope

Live switch/controller integration is **IN SCOPE**. The current harness runs
performed real controller/switch configuration and cleanup on `Astha_Fabric`.
The legacy run was started against the same inventory but was interrupted in
the legacy no-deploy task after it stopped producing output; it is not claimed
as passed. The optional IOS-XE path was not run because no XE switch variable
was configured.

## Same-environment execution record

Run the original suite first:

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  -vv
```

Then run the complete replacement suite against the same fabric, switch, and
controller version:

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  -vv
```

Earlier original, safe, and destructive runs were recorded against a prior
test environment. They are not current-HEAD evidence.

The `overridden` replacement recreates the exact original pre-override state,
uses read-only fabric-wide safety discovery, and snapshots every fabric switch
around predictive check mode.

| Evidence | Result |
|---|---|
| Nexus Dashboard version | ND 4.x preflight passed; exact `platformVersion` was not retained in the run record |
| Fabric and switch management IP | `Astha_Fabric`; `10.122.84.71` |
| Original suite command and date | Untagged `nd_interface_loopback` target run; 2026-08-05 |
| Original suite recap (`failed=0`) | Passed |
| Safe replacement command and date | `nd4x_demo` aggregate excluding `nd4x_demo_overridden`; 2026-08-05 |
| Safe replacement recap (`failed=0`) | Passed; `ok=43 changed=13 failed=0` |
| Earlier overridden replacement command and date | `nd4x_demo_overridden`; 2026-08-05 |
| Earlier overridden replacement recap (`failed=0`) | Passed before the 2026-08-09 update |
| Updated overridden replacement command and date | `nd4x_demo_overridden`; 2026-08-09 |
| Updated overridden replacement recap | Passed; `failed=0` |
| Current harness safe run before current CIDR renumbering | 2026-09-06; `ok=50 changed=14 failed=0 skipped=2`; CIDR result used loopback104 and is superseded |
| Current harness destructive run | 2026-09-06; `ok=67 changed=20 failed=0 skipped=3` |
| Current legacy run | Incomplete/interrupted in legacy no-deploy; not a pass |
| Current testbed | ND `4.2.1`; `Astha_Fabric`; selected switch `10.122.84.71` |
| Current PR base HEAD | `f19ece994ca7e3b9e1502c7d6a02c19a4998fc81` plus uncommitted changes |
| Current local develop reference | `576a681dd9c52b56640d7d27c8c5b6924735ed4a` |
| Current harness CIDR rerun after alignment | 2026-09-07; preflight, setup, create/update/idempotency, and nested no-deploy workflow passed; controller call stalled at `loopback204` CIDR creation; reserved state was subsequently cleaned and API absence validation passed |
| Static gaps requiring follow-up | Optional IOS-XE harness coverage remains absent; current loopback CIDR runtime remains unvalidated because of the controller stall; legacy current-HEAD run is incomplete |

## Retirement decision

Keep `setup.yaml`, `merged.yaml`, `replaced.yaml`, `overridden.yaml`,
`deleted.yaml`, and optional `xe.yaml` enabled until current-HEAD validation is
complete and reviewers explicitly approve retirement of the legacy suites.
