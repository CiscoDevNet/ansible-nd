# `nd_interface_svi` Harness Parity

This document maps every scenario in the original `nd_interface_svi`
integration suite to its ND 4.x harness replacement. The original task files
remain enabled while the replacement scenarios are validated against the same
controller and test fabric.

The harness implementation and static validation are complete. Live-controller
testing is in progress, and the test results will be added to this document
soon.

## Scenario mapping

| Original scenario | Original task file | Harness replacement | Status |
|---|---|---|---|
| Remove all reserved SVIs before the state suite | `tasks/setup.yaml` | Safety guard plus scenario-local setup and `always` cleanup in each harness state file | Implemented; live testing in progress |
| Create vlan333 in check and normal mode | `tasks/merged.yaml` | `MERGED CREATE: Create vlan333 with full config` | Implemented; live testing in progress |
| Create vlan334 and vlan335 together in check and normal mode | `tasks/merged.yaml` | `MERGED MULTI: Create vlan334 and vlan335 together` | Implemented; live testing in progress |
| Create vlan336 as a separate config group | `tasks/merged.yaml` | `MERGED CREATE: Create vlan336 as a separate config group` | Implemented; live testing in progress |
| Re-apply vlan333 idempotently in check and normal mode | `tasks/merged.yaml` | `MERGED IDEMPOTENT: Re-apply vlan333` | Implemented; live testing in progress |
| Re-apply vlan334 and vlan335 idempotently | `tasks/merged.yaml` | `MERGED IDEMPOTENT: Re-apply vlan334 and vlan335` | Implemented; live testing in progress |
| Update vlan333 description and policy fields | `tasks/merged.yaml` | `MERGED UPDATE: Update vlan333 description and policy fields` | Implemented; live testing in progress |
| Verify vlan333 updated fields and re-apply idempotently | `tasks/merged.yaml` | Returned-field assertions and harness idempotency in the vlan333 update | Implemented; live testing in progress |
| Update vlan334 and vlan335 together | `tasks/merged.yaml` | `MERGED UPDATE: Update vlan334 and vlan335 together` | Implemented; live testing in progress |
| Reject a non-ASCII description with the exact reason in normal mode | `tasks/merged.yaml` | `tasks/nd4x_demo_negative.yaml` direct normal-mode module negative test | Implemented; live testing in progress |
| Stage vlan337 with `deploy: false`, then remove it | `tasks/merged.yaml` | `MERGED NO-DEPLOY: Stage vlan337 without deployment` | Implemented; live testing in progress |
| Create vlan337 and vlan338 with independent L3 configuration and re-apply | `tasks/merged.yaml` | `MERGED MULTI: Create vlan337 and vlan338 with unique L3 settings` | Implemented; live testing in progress |
| Replace vlan333 in check and normal mode, then re-apply | `tasks/replaced.yaml` | `REPLACED: Replace vlan333 configuration entirely` | Implemented; live testing in progress |
| Replace vlan334 and vlan335 together, then re-apply | `tasks/replaced.yaml` | `REPLACED MULTI: Replace vlan334 and vlan335 together` | Implemented; live testing in progress |
| Override six SVIs down to vlan333 and vlan334 | `tasks/overridden.yaml` | `OVERRIDDEN REDUCE: Retain only vlan333 and vlan334` | Implemented; destructive live testing in progress |
| Verify vlan335 through vlan338 were removed by override | `tasks/overridden.yaml` | Removal JSONPath checks and returned-state assertions in overridden reduce | Implemented; destructive live testing in progress |
| Re-apply the reduced override idempotently | `tasks/overridden.yaml` | `OVERRIDDEN IDEMPOTENT: Re-apply the same override` | Implemented; destructive live testing in progress |
| Grow the override set by re-adding vlan335 | `tasks/overridden.yaml` | `OVERRIDDEN GROW: Re-add vlan335 to the override set` | Implemented; destructive live testing in progress |
| Delete vlan333 in check and normal mode, then re-delete | `tasks/deleted.yaml` | `DELETED SINGLE: Delete vlan333` | Implemented; live testing in progress |
| Delete vlan334 and vlan335 together in check and normal mode | `tasks/deleted.yaml` | `DELETED MULTI: Delete vlan334 and vlan335 together` | Implemented; live testing in progress |
| Final cleanup and verification of all reserved state-test SVIs | `tasks/deleted.yaml` | `DELETED CLEANUP` in the deleted harness scenario | Implemented; live testing in progress |
| Remove vlan500 and vlan501 before HSRP/DHCP tests | `tasks/hsrp_dhcp.yaml` | HSRP/DHCP scenario-local setup | Implemented; live testing in progress |
| Create vlan500 with HSRP in check and normal mode | `tasks/hsrp_dhcp.yaml` | `HSRP CREATE: Create vlan500 with the HSRP block` | Implemented; live testing in progress |
| Verify HSRP fields persisted and re-apply idempotently | `tasks/hsrp_dhcp.yaml` | HSRP returned-field assertions and harness idempotency | Implemented; live testing in progress |
| Update vlan500 HSRP priority | `tasks/hsrp_dhcp.yaml` | `HSRP UPDATE: Change vlan500 priority` | Implemented; live testing in progress |
| Create vlan501 with DHCP relay configuration | `tasks/hsrp_dhcp.yaml` | `DHCP CREATE: Create vlan501 with DHCP relay servers` | Implemented; live testing in progress |
| Re-apply vlan501 DHCP relay idempotently | `tasks/hsrp_dhcp.yaml` | `DHCP IDEMPOTENT: Re-apply vlan501 DHCP relay configuration` | Implemented; live testing in progress |
| Remove vlan500 and vlan501 after HSRP/DHCP tests | `tasks/hsrp_dhcp.yaml` | HSRP/DHCP `always` cleanup | Implemented; live testing in progress |
| Remove reserved IOS-XE SVIs and resolve the Catalyst switch | `tasks/xe.yaml` | `nd4x_demo_xe_preflight.yaml` and XE scenario setup/cleanup | Implemented; live testing in progress |
| Reject HSRP on IOS-XE in check and normal mode | `tasks/xe.yaml` | `nd4x_demo_xe.yaml` direct negative tasks | Implemented; live testing in progress |
| Create vlan980 and vlan981 with both IOS-XE policy types | `tasks/xe.yaml` | `XE MERGED CREATE` | Implemented; live testing in progress |
| Re-apply the IOS-XE merged configuration idempotently | `tasks/xe.yaml` | `XE MERGED IDEMPOTENT` | Implemented; live testing in progress |
| Update vlan980 description, redirects, and DHCP relays | `tasks/xe.yaml` | `XE MERGED UPDATE` | Implemented; live testing in progress |
| Re-apply the IOS-XE update idempotently | `tasks/xe.yaml` | `XE MERGED UPDATE IDEMPOTENT` | Implemented; live testing in progress |
| Replace vlan980 with its base IOS-XE configuration | `tasks/xe.yaml` | `XE REPLACED` | Implemented; live testing in progress |
| Re-apply the IOS-XE replacement idempotently | `tasks/xe.yaml` | `XE REPLACED IDEMPOTENT` | Implemented; live testing in progress |
| Create vlan982 with an explicit `iosXeSvi` policy type | `tasks/xe.yaml` | `XE MERGED CREATE` for vlan982 | Implemented; live testing in progress |
| Wait for IOS-XE SVI discovery before fabric-wide removal | `tasks/xe.yaml` | XE discovery wait in safe and overridden scenarios | Implemented; live testing in progress |
| Override IOS-XE state to retain vlan980 and vlan981 only | `tasks/xe.yaml` | `nd4x_demo_xe_overridden.yaml` `XE OVERRIDDEN` | Implemented; destructive live testing in progress |
| Re-apply the reduced IOS-XE override idempotently | `tasks/xe.yaml` | `XE OVERRIDDEN IDEMPOTENT` | Implemented; destructive live testing in progress |
| Delete vlan980 and vlan981, then re-delete | `tasks/xe.yaml` | `XE DELETED` and `XE DELETED IDEMPOTENT` | Implemented; destructive live testing in progress |
| Verify and clean the IOS-XE running configuration | `tasks/xe.yaml` | XE diff assertions and `always` cleanup | Implemented; destructive live testing in progress |

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

Harness scenarios are opt-in and retain the `never` tag while parity is being
validated. The original suite continues to run in an ordinary target run.

Safe replacement scenarios can be selected with:

```text
cd /Users/astawast/ansible_collections/cisco/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /Users/astawast/ansible_collections/cisco/nd/tests/integration/inventory.LOCAL.networking \
  --tags never,nd4x_demo_preflight,nd4x_demo_merged,nd4x_demo_replaced,nd4x_demo_deleted,nd4x_demo_hsrp_dhcp,nd4x_demo_negative \
  -vv
```

The destructive overridden scenario requires a dedicated test fabric and:

```ini
nd_svi_destructive_tests_enabled=true
```

The NX-OS overridden scenario can be selected explicitly with:

```text
cd /Users/astawast/ansible_collections/cisco/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /Users/astawast/ansible_collections/cisco/nd/tests/integration/inventory.LOCAL.networking \
  --tags never,nd4x_demo_preflight,nd4x_demo_overridden \
  -e nd_svi_destructive_tests_enabled=true \
  -vv
```

The IOS-XE harness scenarios can be selected with:

The IOS-XE commands require `nd_test_xe_switch_ip` to be defined in the
inventory or supplied with `-e`.

```text
cd /Users/astawast/ansible_collections/cisco/nd_interface_svi

ansible-test network-integration nd_interface_svi \
  --inventory /Users/astawast/ansible_collections/cisco/nd/tests/integration/inventory.LOCAL.networking \
  --tags never,nd4x_demo_xe \
  -vv
```

The IOS-XE overridden/deleted path additionally requires the destructive
opt-in and `nd_test_xe_switch_ip` to be defined in the inventory or supplied
with `-e`:

```text
ansible-test network-integration nd_interface_svi \
  --inventory /Users/astawast/ansible_collections/cisco/nd/tests/integration/inventory.LOCAL.networking \
  --tags never,nd4x_demo_xe_overridden \
  -e nd_svi_destructive_tests_enabled=true \
  -vv
```

Live-controller testing is in progress. The results will be updated in this
document soon.
