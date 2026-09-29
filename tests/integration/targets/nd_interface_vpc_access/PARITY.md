# `nd_interface_vpc_access` harness parity

This file maps the original integration tests to the ND 4.x harness tests.
The execution records below include historical evidence and the current
working-tree verification recorded in the current-HEAD section. The current
vPC run used ND 4.2.1 and `Astha_Fabric`; the primary pair was `.71/.63` and
the requested second-pair peers were `.56/.55`.

## Scenario mapping

### Setup and cleanup

| Original behavior | Harness coverage |
|---|---|
| Remove an existing vPC pair and wait 30 seconds | `nd4x_demo_pair_setup.yaml` |
| Create the test pair and wait 30 seconds | `nd4x_demo_pair_setup.yaml` |
| Confirm that both switches report the pair | Reciprocal `vpcPair` REST queries in `nd4x_demo_pair_setup.yaml` |
| Remove remaining interfaces and unpair the switches | Each mutable state file has cleanup under `always` |

### Module states

| State | Original behavior | Harness coverage |
|---|---|---|
| `merged` | Check mode predicts creation; normal mode creates `vpc100` | `MERGED CREATE` |
| `merged` | After 30 seconds, check and normal mode report no change | `MERGED IDEMPOTENT` |
| `replaced` | Check and normal mode change VLAN 10 to 20 and add the second peer-1 member | `REPLACED UPDATE` |
| `replaced` | After 30 seconds, normal mode reports no change | `REPLACED IDEMPOTENT` |
| `overridden` | Check and normal mode replace `vpc100` with `vpc101` | `OVERRIDDEN REPLACE SET` |
| `overridden` | After 30 seconds, normal mode reports no change | `OVERRIDDEN IDEMPOTENT` |
| `deleted` | Check and normal mode remove `vpc101` | `DELETED SINGLE` |
| `deleted` | After 30 seconds, normal mode reports no change | `DELETED IDEMPOTENT` |

### Multi-pair same-vPC-id behavior

| Original behavior | Harness coverage |
|---|---|
| Require and discover the second vPC pair | `MULTI-PAIR PREFLIGHT` |
| Create the same `vpc211` name and ID on both pairs | `MULTI-PAIR MERGED` |
| Reapply both pair configurations idempotently | Harness idempotency phase in `MULTI-PAIR MERGED` |
| Reject the same vPC name under both peers of one pair | `MULTI-PAIR GUARD` |
| Override to retain only pair 1's copy | `MULTI-PAIR OVERRIDDEN` |
| Reapply the multi-pair override idempotently | `MULTI-PAIR OVERRIDDEN IDEMPOTENT` |
| Clean up both pair copies | `MULTI-PAIR CLEANUP` |

The harness reconstructs the required state locally because each state can be
run on its own. It also adds checks that the original suite did not have:

- Interface snapshots around check mode on both peers.
- Fabric-wide snapshots for `state: overridden`.
- REST validation of the resulting configuration on both peers.
- Exact validation of the missing-`interface_name` error.
- Resource confirmation, conditional pair-reset opt-in, and destructive-test opt-in.
- Scope checks before the fabric-wide overridden test.

## Testbed values

The original and harness suites were run with the same inventory overrides:

| Value | Current testbed |
|---|---|
| Nexus Dashboard version | `4.2.1` |
| Fabric | `Astha_Fabric` |
| Peer 1 | `10.122.84.71` / `9WME34GIAPX` |
| Peer 2 | `10.122.84.63` / `9AH5QNPD6XG` |
| Reserved vPC interfaces | `vpc100`, `vpc101` |
| Peer-1 member ports | `Ethernet1/5`, `Ethernet1/7`, `Ethernet1/8` |
| Peer-2 member ports | `Ethernet1/5`, `Ethernet1/7` |

The current testbed has four switches in `Astha_Fabric`, but the second pair
`.56/.55` is not configured as a vPC pair. The multi-pair harness therefore
stops at its explicit precondition rather than modifying an unapproved pair.

Two fixture values differ from the historical lab:

- The current fabric uses its ND-discovered physical peer-link instead of the
  historical virtual peer-link.
- `Ethernet1/8` replaces historical peer-1 member `Ethernet1/6` because it is
  the reserved, ND-discovered port available in this fabric.

Pair creation uses `config_actions.type: switch`. Pair deletion retains the
module's switch-scoped default.

## Deployment scope

Live switch/controller integration is **IN SCOPE**. Current harness runs
performed real vPC interface configuration and cleanup on `Astha_Fabric`.
Managed pair creation/reset was attempted, but the controller operation did
not return within roughly five minutes and was interrupted. The second pair
was not created because its explicit precondition was absent.

## Running the harness

All mutable workflows require these inventory values:

```ini
nd_vpc_access_reserved_resources_confirmed=true
nd_vpc_access_pair_reset_enabled=true
```

The safe aggregate excludes `state: overridden`:

```bash
ansible-test network-integration nd_interface_vpc_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo,nd4x_demo_preflight \
  -vv
```

The overridden workflow must be run separately with:

```ini
nd_vpc_access_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_interface_vpc_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags never,nd4x_demo_overridden,nd4x_demo_preflight \
  -vv
```

## Execution record

The historical collection baseline was
`5c1e7ec2eb19154b44ad42cb0925fa87fb3f7188`. The harness was tested as
uncommitted working-tree content. The recorded runtime YAML manifest is
SHA-256 `57fcf0b992eab6e312d354a92cf17b8aa5ca4e87040ad51dfbf67db20ad1bd6b`.

The historical commands below used:

```text
--inventory /Users/astawast/ansible_collections/cisco/nd/tests/integration/inventory.LOCAL.networking -vv
```

| Run | Date | Recap |
|---|---|---|
| Original suite | 2026-08-30 | `ok=36 changed=10 failed=0 skipped=1` |
| Merged | 2026-08-29 | `ok=41 changed=4 failed=0 skipped=2` |
| Replaced | 2026-08-30 | `ok=44 changed=5 failed=0 skipped=2` |
| Deleted | 2026-08-30 | `ok=44 changed=4 failed=0 skipped=2` |
| Negative | 2026-08-29 | `ok=26 changed=0 failed=0 skipped=2` |
| Overridden | 2026-08-30 | `ok=53 changed=6 failed=0 skipped=3` |
| Safe aggregate | 2026-08-30 | `ok=86 changed=13 failed=0 skipped=2` |

Final-run JUnit files:

- Original: `tests/output/junit/nd_interface_vpc_access-rxbac6c2-1788032782.0116858.xml`
  (`errors=0`, `failures=0`).
- Deleted: `tests/output/junit/nd_interface_vpc_access-95myk2jp-1788033335.21419.xml`
  (`errors=0`, `failures=0`).
- Safe aggregate:
  `tests/output/junit/nd_interface_vpc_access-h7kk0drf-1788034782.8594.xml`
  (`errors=0`, `failures=0`).
- Overridden:
  `tests/output/junit/nd_interface_vpc_access-1a5u6mvt-1788031141.547286.xml`
  (`errors=0`, `failures=0`).

An earlier original run reported `changed=11`. The final run reported
`changed=10` because the initial cleanup state differed; both runs completed
with `failed=0`.

## Open review items

All original changed/no-change assertions are covered. For complete validation
of every configured field, the harness can still be tightened by:

- Asserting `admin_state` in configured results and REST responses.
- Extending the replaced pre-state assertion to cover both port-channel IDs,
  port-channel mode, LACP rate, and `vpc101` absence.
- Extending the overridden pre-state assertion to cover both port-channel IDs,
  port-channel mode, and LACP rate.
- Extending the deleted pre-state assertion to cover admin state and
  port-channel mode. These assertions are now included in the harness.

## Latest develop follow-up

Commit `5927ac35` added the original `multi_pair.yaml` workflow after the
recorded parity runs. The workflow is now represented by
`nd4x_demo_multi_pair.yaml` and requires the second vPC pair configured in the
inventory.

The original suite remains enabled. The harness is not final parity evidence
for the complete vPC target until managed pair creation/reset and the
multi-pair workflow are executed on a testbed that provides both pairs.

### Current working-tree verification (2026-09-06)

The current code is based on PR base HEAD
`f19ece994ca7e3b9e1502c7d6a02c19a4998fc81` plus uncommitted changes. The local
develop reference was `576a681dd9c52b56640d7d27c8c5b6924735ed4a`.

| Run | Result |
|---|---|
| Harness merged, pair management disabled | Passed; `ok=35 changed=2 failed=0 skipped=8`; primary pair `.71/.63` discovered, vpc100 created/idempotently reapplied/cleaned |
| Harness overridden, pair management disabled | Passed; `ok=47 changed=4 failed=0 skipped=9`; vpc100/vpc101 override, idempotency, API validation, and cleanup passed |
| Harness pair management enabled | Incomplete; controller pair-create/reset did not return within roughly five minutes and was interrupted |
| Harness multi-pair precondition | Correctly failed; second pair `.56/.55` had no vPC pair record; cleanup completed |
| Legacy suite | Primary-pair workflows passed; multi-pair scenario stopped at the explicit missing-second-pair precondition; `ok=33 changed=8 unreachable=0 failed=1 skipped=6 rescued=0 ignored=0` |
| Final primary-pair state | Read-only query returned HTTP 200; reciprocal pair `.71/.63` was restored asynchronously by the controller after the interrupted request |
| Legacy suites | Remain enabled in `tasks/main.yaml` |
