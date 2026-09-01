# `nd_interface_loopback` Harness Parity

This document maps every scenario in the original `nd_interface_loopback`
integration suite to its harness-based replacement.

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
  --tags nd4x_demo \
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
  --tags nd4x_demo_overridden \
  -vv
```

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

The original suite, the safe replacement suite, and the earlier destructive
`overridden` replacement scenarios were run against the same test environment
on 2026-08-05. All three runs completed with `failed=0`.

The `overridden` replacement was updated on 2026-08-09 to recreate the
exact original pre-override state, use read-only fabric-wide safety discovery,
and snapshot every fabric switch around predictive check mode. The updated
destructive run completed on 2026-08-09 with `failed=0`.

| Evidence | Result |
|---|---|
| Nexus Dashboard version | ND 4.x preflight passed; exact `platformVersion` was not retained in the run record |
| Fabric and switch management IP | `VXLAN_Fabric`; `10.122.84.71` |
| Original suite command and date | Untagged `nd_interface_loopback` target run; 2026-08-05 |
| Original suite recap (`failed=0`) | Passed |
| Safe replacement command and date | `nd4x_demo` aggregate excluding `nd4x_demo_overridden`; 2026-08-05 |
| Safe replacement recap (`failed=0`) | Passed; `ok=43 changed=13 failed=0` |
| Earlier overridden replacement command and date | `nd4x_demo_overridden`; 2026-08-05 |
| Earlier overridden replacement recap (`failed=0`) | Passed before the 2026-08-09 update |
| Updated overridden replacement command and date | `nd4x_demo_overridden`; 2026-08-09 |
| Updated overridden replacement recap | Passed; `failed=0` |
| Unmapped or weakened scenarios | None identified; all mapped scenarios passed in live runs |

## Retirement decision

All original scenarios have an implemented replacement, and the original,
safe replacement, and updated destructive replacement runs completed with
`failed=0`. Keep `setup.yaml`, `merged.yaml`, `replaced.yaml`,
`overridden.yaml`, and `deleted.yaml` until reviewers approve this parity
evidence and explicitly agree to retire the original suite.
