# `nd_interface_svi` Harness Parity

This document maps every scenario in the original `nd_interface_svi`
integration suite to its ND 4.x harness replacement. The original task files
remain enabled while the replacement scenarios are validated against the same
controller and test fabric.

The harness implementation and static validation are complete. NX-OS
live-controller testing is complete. IOS-XE live validation could not be run
because an IOS-XE/Catalyst test switch is not available.

## Live-controller results

- `nd4x_demo_merged`: passed with `failed=0` (`ok=43`, `changed=9`,
  `skipped=4`).
- `nd4x_demo_overridden`: passed with `failed=0` (`ok=51`, `changed=4`,
  `skipped=13`).
- `nd4x_demo_replaced`: passed with `failed=0` (`ok=29`, `changed=4`,
  `skipped=4`).
- `nd4x_demo_deleted`: passed with `failed=0` (`ok=30`, `changed=3`,
  `skipped=4`).
- `nd4x_demo_hsrp_dhcp`: passed with `failed=0` (`ok=34`, `changed=4`,
  `skipped=4`).
- `nd4x_demo_negative`: passed with the expected module failure handled by the
  test (`failed=0`, `ok=21`, `changed=0`, `skipped=4`, `ignored=1`).
- Combined remaining safe NX-OS scenarios (`replaced`, `deleted`,
  `hsrp_dhcp`, and `negative`): passed with `failed=0` (`ok=60`,
  `changed=11`, `skipped=4`, `ignored=1`).
- IOS-XE scenarios are implemented and statically validated, but are not
  marked as passed because no IOS-XE/Catalyst testbed is available.

## Scenario mapping

| Original scenario | Original task file | Harness replacement | Status |
|---|---|---|---|
| Remove all reserved SVIs before the state suite | `tasks/setup.yaml` | Safety guard plus scenario-local setup and `always` cleanup in each harness state file | Implemented; live test passed |
| Create vlan333 in check and normal mode | `tasks/merged.yaml` | `MERGED CREATE: Create vlan333 with full config` | Implemented; live test passed |
| Create vlan334 and vlan335 together in check and normal mode | `tasks/merged.yaml` | `MERGED MULTI: Create vlan334 and vlan335 together` | Implemented; live test passed |
| Create vlan336 as a separate config group | `tasks/merged.yaml` | `MERGED CREATE: Create vlan336 as a separate config group` | Implemented; live test passed |
| Re-apply vlan333 idempotently in check and normal mode | `tasks/merged.yaml` | `MERGED IDEMPOTENT: Re-apply vlan333` | Implemented; live test passed |
| Re-apply vlan334 and vlan335 idempotently | `tasks/merged.yaml` | `MERGED IDEMPOTENT: Re-apply vlan334 and vlan335` | Implemented; live test passed |
| Update vlan333 description and policy fields | `tasks/merged.yaml` | `MERGED UPDATE: Update vlan333 description and policy fields` | Implemented; live test passed |
| Verify vlan333 updated fields and re-apply idempotently | `tasks/merged.yaml` | Returned-field assertions and harness idempotency in the vlan333 update | Implemented; live test passed |
| Update vlan334 and vlan335 together | `tasks/merged.yaml` | `MERGED UPDATE: Update vlan334 and vlan335 together` | Implemented; live test passed |
| Reject a non-ASCII description with the exact reason in normal mode | `tasks/merged.yaml` | `tasks/nd4x_demo_negative.yaml` direct normal-mode module negative test | Implemented; live test passed |
| Stage vlan337 with `deploy: false`, then remove it | `tasks/merged.yaml` | `MERGED NO-DEPLOY: Stage vlan337 without deployment` | Implemented; live test passed |
| Create vlan337 and vlan338 with independent L3 configuration and re-apply | `tasks/merged.yaml` | `MERGED MULTI: Create vlan337 and vlan338 with unique L3 settings` | Implemented; live test passed |
| Replace vlan333 in check and normal mode, then re-apply | `tasks/replaced.yaml` | `REPLACED: Replace vlan333 configuration entirely` | Implemented; live test passed |
| Replace vlan334 and vlan335 together, then re-apply | `tasks/replaced.yaml` | `REPLACED MULTI: Replace vlan334 and vlan335 together` | Implemented; live test passed |
| Override six SVIs down to vlan333 and vlan334 | `tasks/overridden.yaml` | `OVERRIDDEN REDUCE: Retain only vlan333 and vlan334` | Implemented; destructive live test passed |
| Verify vlan335 through vlan338 were removed by override | `tasks/overridden.yaml` | Removal JSONPath checks and returned-state assertions in overridden reduce | Implemented; destructive live test passed |
| Re-apply the reduced override idempotently | `tasks/overridden.yaml` | `OVERRIDDEN IDEMPOTENT: Re-apply the same override` | Implemented; destructive live test passed |
| Grow the override set by re-adding vlan335 | `tasks/overridden.yaml` | `OVERRIDDEN GROW: Re-add vlan335 to the override set` | Implemented; destructive live test passed |
| Delete vlan333 in check and normal mode, then re-delete | `tasks/deleted.yaml` | `DELETED SINGLE: Delete vlan333` | Implemented; live test passed |
| Delete vlan334 and vlan335 together in check and normal mode | `tasks/deleted.yaml` | `DELETED MULTI: Delete vlan334 and vlan335 together` | Implemented; live test passed |
| Final cleanup and verification of all reserved state-test SVIs | `tasks/deleted.yaml` | `DELETED CLEANUP` in the deleted harness scenario | Implemented; live test passed |
| Remove vlan500 and vlan501 before HSRP/DHCP tests | `tasks/hsrp_dhcp.yaml` | HSRP/DHCP scenario-local setup | Implemented; live test passed |
| Create vlan500 with HSRP in check and normal mode | `tasks/hsrp_dhcp.yaml` | `HSRP CREATE: Create vlan500 with the HSRP block` | Implemented; live test passed |
| Verify HSRP fields persisted and re-apply idempotently | `tasks/hsrp_dhcp.yaml` | HSRP returned-field assertions and harness idempotency | Implemented; live test passed |
| Update vlan500 HSRP priority | `tasks/hsrp_dhcp.yaml` | `HSRP UPDATE: Change vlan500 priority` | Implemented; live test passed |
| Create vlan501 with DHCP relay configuration | `tasks/hsrp_dhcp.yaml` | `DHCP CREATE: Create vlan501 with DHCP relay servers` | Implemented; live test passed |
| Re-apply vlan501 DHCP relay idempotently | `tasks/hsrp_dhcp.yaml` | `DHCP IDEMPOTENT: Re-apply vlan501 DHCP relay configuration` | Implemented; live test passed |
| Remove vlan500 and vlan501 after HSRP/DHCP tests | `tasks/hsrp_dhcp.yaml` | HSRP/DHCP `always` cleanup | Implemented; live test passed |
| Remove reserved IOS-XE SVIs and resolve the Catalyst switch | `tasks/xe.yaml` | `nd4x_demo_xe_preflight.yaml` and XE scenario setup/cleanup | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Reject HSRP on IOS-XE in check and normal mode | `tasks/xe.yaml` | `nd4x_demo_xe.yaml` direct negative tasks | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Create vlan980 and vlan981 with both IOS-XE policy types | `tasks/xe.yaml` | `XE MERGED CREATE` | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Re-apply the IOS-XE merged configuration idempotently | `tasks/xe.yaml` | `XE MERGED IDEMPOTENT` | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Update vlan980 description, redirects, and DHCP relays | `tasks/xe.yaml` | `XE MERGED UPDATE` | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Re-apply the IOS-XE update idempotently | `tasks/xe.yaml` | `XE MERGED UPDATE IDEMPOTENT` | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Replace vlan980 with its base IOS-XE configuration | `tasks/xe.yaml` | `XE REPLACED` | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Re-apply the IOS-XE replacement idempotently | `tasks/xe.yaml` | `XE REPLACED IDEMPOTENT` | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Create vlan982 with an explicit `iosXeSvi` policy type | `tasks/xe.yaml` | `XE MERGED CREATE` for vlan982 | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Wait for IOS-XE SVI discovery before fabric-wide removal | `tasks/xe.yaml` | XE discovery wait in safe and overridden scenarios | Implemented; live validation unavailable—no IOS-XE/Catalyst testbed |
| Override IOS-XE state to retain vlan980 and vlan981 only | `tasks/xe.yaml` | `nd4x_demo_xe_overridden.yaml` `XE OVERRIDDEN` | Implemented; destructive live validation unavailable—no IOS-XE/Catalyst testbed |
| Re-apply the reduced IOS-XE override idempotently | `tasks/xe.yaml` | `XE OVERRIDDEN IDEMPOTENT` | Implemented; destructive live validation unavailable—no IOS-XE/Catalyst testbed |
| Delete vlan980 and vlan981, then re-delete | `tasks/xe.yaml` | `XE DELETED` and `XE DELETED IDEMPOTENT` | Implemented; destructive live validation unavailable—no IOS-XE/Catalyst testbed |
| Verify and clean the IOS-XE running configuration | `tasks/xe.yaml` | XE diff assertions and `always` cleanup | Implemented; destructive live validation unavailable—no IOS-XE/Catalyst testbed |

## Harness coverage

Positive scenarios use `cisco.nd.nd4x_module_test` with:

- Predictive check-mode expectations.
- Fabric-wide read-only snapshots of the full managed-interface collection on
  every switch, with only volatile `operData` ignored.
- Interfaces snapshots use explicit pagination with a 100-item page size and a
  10,000-page safety limit, so predictive comparisons cannot silently stop at
  the first response page.
- Destructive override preflights use the target-local paginated interface
  collector (`nd4x_demo_collect_interfaces.yaml`) and aggregate every
  `max`/`offset` page from every fabric switch before evaluating safety scope.
- Fabric switch discovery also follows every `max`/`offset` page before
  building snapshots or destructive safety inventories.
- IOS-XE discovery polls each reserved interface endpoint directly instead of
  depending on a possibly paginated `/interfaces` collection.
- Deletion and overridden-removal REST assertions query each removed interface
  endpoint individually and require HTTP 404, so collection pagination cannot
  hide a retained interface.
- First real apply and one required idempotency execution.
- Post-apply ND REST assertions for created, updated, retained, and removed
  SVIs.
- Returned-field assertions matching the original suite.
- Scenario-local setup and guaranteed cleanup under `always`.
- Safe scenarios verify that all reserved SVI endpoints are absent before
  setup, so they fail without deleting pre-existing state.
- IOS-XE cleanup waits for each reserved interface to be discovered or absent
  before attempting deletion, including after an early scenario failure.
- `nd4x_demo_merged_fanout` selects the existing multi-SVI merged harness
  coverage; the original SVI suite has no separate fan-out task file.

The optional IOS-XE suite is split into two opt-in paths:

- `nd4x_demo_xe` covers validation, merged, update, replaced, explicit policy
  type, and discovery scenarios.
- `nd4x_demo_xe_overridden` covers the fabric-wide override, deletion, running
  configuration verification, and destructive cleanup.

The IOS-XE harness uses a separate fabric-wide snapshot for every switch in the
Catalyst fabric, and its destructive path rejects managed SVIs outside the
reserved vlan980-vlan983 scope before applying an override.

The non-ASCII validation remains a direct normal-mode module negative test
because the harness contract recommends direct target-module execution for exact
expected failure-reason assertions. This matches the legacy suite's execution
mode.

The overridden operation is fabric-wide. Its harness scenario therefore:

- Requires `nd_svi_destructive_tests_enabled=true`.
- Recreates the exact post-`replaced.yaml` state before exercising override:
  replaced vlan333-vlan335 plus the merged vlan336-vlan338 configurations.
- Reads every switch interface collection before applying anything.
- Rejects any managed SVI outside the selected test switch and reserved
  `vlan333`-`vlan338` scope.
- Uses one predictive snapshot query per fabric switch.

## Tags and safety

Harness scenarios are selected with `nd4x_demo` or a state-specific tag. Do
not add `never` to `--tags`, because that activates every harness scenario in
the target. The original suite continues to run in an ordinary target run.

To run all NX-OS harness scenarios, including the destructive overridden path:

```text
cd /path/to/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /path/to/inventory.networking \
  --tags nd4x_demo \
  -vv
```

Safe replacement scenarios can be selected with:

```text
cd /path/to/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /path/to/inventory.networking \
  --tags nd4x_demo_merged,nd4x_demo_merged_fanout,nd4x_demo_replaced,nd4x_demo_deleted,nd4x_demo_hsrp_dhcp,nd4x_demo_negative \
  -vv
```

The destructive overridden scenario requires a dedicated test fabric and:

```ini
# Add this temporarily under [nd:vars] in the test inventory.
# Do not commit the inventory change.
nd_svi_destructive_tests_enabled=true
```

The NX-OS overridden scenario can be selected explicitly with:

```text
cd /path/to/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /path/to/inventory.networking \
  --tags nd4x_demo_overridden \
  -vv
```

The IOS-XE harness scenarios can be selected with:

The IOS-XE commands require `nd_test_xe_switch_ip` to be defined in the
inventory. `ansible-test network-integration` does not accept Ansible
extra-vars directly.

```text
cd /path/to/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /path/to/inventory.networking \
  --tags nd4x_demo_xe \
  -vv
```

The IOS-XE overridden/deleted path additionally requires the destructive
opt-in and `nd_test_xe_switch_ip` to be defined in the inventory:

```text
ansible-test network-integration nd_interface_svi \
  --inventory /path/to/inventory.networking \
  --tags nd4x_demo_xe_overridden \
  -vv
```

NX-OS live-controller validation is complete. IOS-XE live-controller
validation was not performed because an IOS-XE/Catalyst test switch was not
available.
