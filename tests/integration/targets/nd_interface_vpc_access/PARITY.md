# `nd_interface_vpc_access` harness parity

This file maps the original integration tests to the ND 4.x harness tests.
The execution records below include historical evidence and the current
working-tree verification recorded in the current-HEAD section. The live vPC
runs used ND 4.2.1 on a dedicated VXLAN fabric, with a primary switch pair and
a second requested pair that was not configured as a vPC pair.

## Scenario mapping

### Setup and cleanup

| Original behavior | Harness coverage |
|---|---|
| Remove an existing vPC pair and wait 30 seconds | `nd4x_demo_pair_setup.yaml` |
| Create the test pair and wait 30 seconds | `nd4x_demo_pair_setup.yaml` |
| Confirm that both switches report the pair | Reciprocal `vpcPair` REST queries in `nd4x_demo_pair_setup.yaml` |
| Remove remaining interfaces, verify they are absent, and unpair the switches | Shared `nd4x_demo_cleanup.yaml` cleanup runs under `always`, deploys interface deletes, waits for pair removal when enabled, and verifies both the interface state and pair state |

### Module states

| State | Original behavior | Harness coverage |
|---|---|---|
| `merged` | Check mode predicts creation; normal mode creates `vpc100` | `MERGED CREATE` |
| `merged` | After 30 seconds, check and normal mode report no change | `MERGED IDEMPOTENT` |
| `merged` | Reject one-sided and two-sided member-ownership conflicts locally without creating candidate vPC interfaces | `MERGED OWNERSHIP GUARD` in `nd4x_demo_merged_edge_cases.yaml` |
| `merged` | Remove one peer's member list, update the remaining peer's Ethernet member, replay idempotently, and restore baseline | `MERGED ONE-SIDED MEMBER` in `nd4x_demo_merged_edge_cases.yaml` |
| `merged` | Stage empty member lists, deploy the staged intent, deploy empty lists from populated state, verify idempotency, and restore baseline | `MERGED EMPTY MEMBERS` in `nd4x_demo_merged_edge_cases.yaml` |
| `replaced` | Check and normal mode change VLAN 10 to 20 and add the second peer-1 member | `REPLACED UPDATE` |
| `replaced` | After 30 seconds, normal mode reports no change | `REPLACED IDEMPOTENT` |
| `overridden` | Assert the exact `vpc100` pre-override state, then check and normal mode replace it with `vpc101` | `OVERRIDDEN SETUP` and `OVERRIDDEN REPLACE SET` |
| `overridden` | After 30 seconds, normal mode reports no change | `OVERRIDDEN IDEMPOTENT` |
| `deleted` | Check and normal mode stage removal of `vpc101` without deployment | `DELETED SINGLE` |
| `deleted` | Snapshot both peers around the predictive reconciliation pass, deploy the exact staged deletion, and verify idempotency | `DELETED RECONCILE` |

### Multi-pair same-vPC-id behavior

| Original behavior | Harness coverage |
|---|---|
| Require and discover the second vPC pair | `MULTI-PAIR PREFLIGHT` |
| Create the same `vpc211` name and ID on both pairs, with pair-specific VLANs (10 and 11) | `MULTI-PAIR MERGED` |
| Reapply both pair configurations idempotently | Harness idempotency phase in `MULTI-PAIR MERGED` |
| Reject the same vPC name under both peers of one pair | `MULTI-PAIR GUARD` |
| Override to retain only pair 1's copy while preserving other fabric access vPCs | `MULTI-PAIR OVERRIDDEN` |
| Reapply the multi-pair override idempotently | `MULTI-PAIR OVERRIDDEN IDEMPOTENT` |
| Clean up both pair copies | `MULTI-PAIR CLEANUP` |

The harness reconstructs the required state locally because each state can be
run on its own. It also adds checks that the original suite did not have:

- Interface snapshots around check mode on both peers.
- Explicit unchanged-snapshot assertions around the deleted reconciliation check-mode pass.
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
| Fabric | Dedicated VXLAN fabric (name omitted) |
| Peer 1 | `192.0.2.71` / `<switch-id-1>` |
| Peer 2 | `192.0.2.63` / `<switch-id-2>` |
| Reserved vPC interfaces | `vpc100`, `vpc101` |
| Peer-1 member ports | `Ethernet1/5`, `Ethernet1/7`, `Ethernet1/8` |
| Peer-2 member ports | `Ethernet1/5`, `Ethernet1/7` |

The current testbed has four switches, but the other two discovered switches
are not configured as a vPC pair. The multi-pair harness therefore stops at its
explicit precondition rather than modifying an unapproved pair.

Two fixture values differ from the historical lab:

- The current fabric uses its ND-discovered physical peer-link instead of the
  historical virtual peer-link.
- `Ethernet1/8` replaces historical peer-1 member `Ethernet1/6` because it is
  the reserved, ND-discovered port available in this fabric.

Pair creation uses `config_actions.type: switch`. Pair deletion retains the
module's switch-scoped default.

## Deployment scope

Live switch/controller integration is **IN SCOPE**. Current harness runs
performed real vPC interface configuration and cleanup on a dedicated VXLAN
fabric.
Managed pair creation/reset was attempted, but the controller operation did
not return within roughly five minutes and was interrupted. The second pair
was not created because its explicit precondition was absent.

## Running the harness

All mutable workflows require these inventory values:

```ini
nd_vpc_access_reserved_resources_confirmed=true
nd_vpc_access_pair_reset_enabled=true
```

Do not include `never` in `--tags`: Ansible treats selected tags as
alternatives, so selecting `never` can activate every opt-in harness include.

The safe aggregate excludes all workflows containing `state: overridden`,
including the multi-pair scenario:

```bash
ansible-test network-integration nd_interface_vpc_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo,nd4x_demo_preflight \
  -vv
```

The overridden workflow must be run separately with:

```ini
nd_vpc_access_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_interface_vpc_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden,nd4x_demo_preflight \
  -vv
```

The multi-pair workflow also contains a fabric-wide `state: overridden` step.
It is excluded from the safe aggregate and must be run separately with the
destructive-test opt-in, a second vPC pair configured, and the same reserved
resource and pair-reset settings above. Confirm the multi-pair fixture resources
on all four switches with this additional inventory value:

```ini
nd_vpc_access_multi_pair_resources_confirmed=true
```

The multi-pair preflight requires `vpc211`, port-channel ID `211`, and
`Ethernet1/10` to be free on both peers of both vPC pairs. It refuses to proceed
if the interface is missing, is not Ethernet, is already bundled, or the vPC or
port-channel ID is already in use. Cleanup runs only after those resources were
confirmed free and the create operation is about to start.

```bash
ansible-test network-integration nd_interface_vpc_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_multi_pair_destructive,nd4x_demo_preflight \
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

The original merged-state edge cases and staged-delete reconciliation are
represented in the harness. State-changing workflows now request switch
deployment explicitly because `nd_interface_vpc_access` defaults to staging.
The multi-pair override probes and preserves other access-vPC records before
its fabric-wide override. Cleanup queries both primary peers and verifies the
reserved vPCs and managed pair are absent; multi-pair cleanup verifies `vpc211`
is absent from all four selected switches.

These implementation changes have not yet been executed on a supported
testbed at the time this review item was written. The later live run recorded
below covers the primary-pair preflight, merged, replaced, deleted, negative,
and overridden workflows. The merged readback assertion and deleted inventory
identity failures remain open; multi-pair behavior and managed pair
creation/reset are still not verified on a testbed with two configured pairs.

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
| Harness merged, pair management disabled | Passed; `ok=35 changed=2 failed=0 skipped=8`; primary pair discovered, vpc100 created/idempotently reapplied/cleaned |
| Harness overridden, pair management disabled | Passed; `ok=47 changed=4 failed=0 skipped=9`; vpc100/vpc101 override, idempotency, API validation, and cleanup passed |
| Harness pair management enabled | Incomplete; controller pair-create/reset did not return within roughly five minutes and was interrupted |
| Harness multi-pair precondition | Correctly failed; the second pair had no vPC pair record; cleanup completed |
| Legacy suite | Primary-pair workflows passed; multi-pair scenario stopped at the explicit missing-second-pair precondition; `ok=33 changed=8 unreachable=0 failed=1 skipped=6 rescued=0 ignored=0` |
| Final primary-pair state | Read-only query returned HTTP 200; the reciprocal pair was restored asynchronously by the controller after the interrupted request |
| Legacy suites | Remain enabled in `tasks/main.yaml` |

### Latest live verification (2026-10-12)

The live harness was run against ND 4.2.1 on a dedicated VXLAN fabric, using
peer 1 `192.0.2.71` / `<switch-id-1>` and peer 2 `192.0.2.63` /
`<switch-id-2>`. These are documentation placeholders. The `jsonpath-ng`
integration dependency was installed in the
Python 3.11 environment before these runs. The earlier runs that stopped with
`Cannot use JSONPath validation because the jsonpath-ng Python library is not
available` were dependency/setup failures and are not counted as state results.

| Workflow | Result | Details |
|---|---|---|
| Preflight | Passed; `ok=23 changed=0 failed=0 skipped=2` | Required lab resources and ND 4.x preconditions passed. |
| `merged` | Failed; `ok=72 changed=6 failed=1 skipped=2` | `MERGED ONE-SIDED MEMBER: Verify converged membership state` found `peer2MemberPorts` still present in the peer-2 vPC GET response. In a paused reproduction, switch CLI showed `Ethernet1/5` detached from `Po100` on peer 2 and still assigned to `Po100` on peer 1. Fresh GETs during the same paused phase showed peer 1 retaining `peer1MemberPorts` while the peer-2 GET still returned `peer2MemberPorts: [Ethernet1/5]`. This establishes a REST readback/device-state discrepancy; its cause is unresolved. |
| `replaced` | Passed; `ok=52 changed=5 failed=0 skipped=2` | Replaced workflow and its assertions completed. |
| `deleted` | Failed during check-mode initialization; no recap supplied | Before the staged deletion ran (`idempotency_attempts=0`), interface inventory for requested switch `<switch-id-1>` contained row 72 with `switchId=<switch-id-2>`. The collection rejected the cross-switch identity and aborted. It remains unresolved whether ND returned a peer-scoped row in this collection response or the collection's identity assumption differs from ND's response semantics. |
| Negative validation | Passed; `ok=26 changed=0 failed=0 skipped=2` | Negative validation workflow completed. |
| `overridden` | Passed; `ok=61 changed=6 failed=0 skipped=3` | Destructive opt-in workflow completed. |
| Multi-pair | Not run | The second pair is not configured as a vPC pair in this lab. |

The preflight include carries each state tag, so an isolated state selection
also runs preflight and sets `nd4x_supported` in the same invocation. Do not
include the broad `nd4x_demo` tag when isolating a single workflow; it selects
the safe aggregate. Examples:

```bash
--tags nd4x_demo_merged
--tags nd4x_demo_replaced
--tags nd4x_demo_deleted
--tags nd4x_demo_negative
--tags nd4x_demo_overridden
```

The overridden workflow still requires
`nd_vpc_access_destructive_tests_enabled=true`. The multi-pair workflow
requires its separate destructive opt-in and a configured second pair.

The deleted-state failure needs a read-only capture of the raw peer-1
`/interfaces?max=500&offset=0&sort=interfaceName:asc` response to identify
row 72 and determine whether the cross-switch row came from ND's response.
Switch clock output warned that no NTP peer/server was configured, so correlate
the paused-run observations by test phase and request trace IDs rather than
assuming the switch and controller timestamps are synchronized. Confirm the
test fixtures are back at baseline after any failed live run.
