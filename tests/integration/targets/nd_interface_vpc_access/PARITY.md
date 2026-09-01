# `nd_interface_vpc_access` harness parity

This file maps the original integration tests to the ND 4.x harness tests and
records the runs made against the current test fabric.

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

The harness reconstructs the required state locally because each state can be
run on its own. It also adds checks that the original suite did not have:

- Interface snapshots around check mode on both peers.
- Fabric-wide snapshots for `state: overridden`.
- REST validation of the resulting configuration on both peers.
- Exact validation of the missing-`interface_name` error.
- Resource confirmation, pair-reset opt-in, and destructive-test opt-in.
- Scope checks before the fabric-wide overridden test.

## Testbed values

The original and harness suites were run with the same inventory overrides:

| Value | Current testbed |
|---|---|
| Nexus Dashboard version | `4.2.1` |
| Fabric | `VXLAN_Fabric` |
| Peer 1 | `10.122.84.71` / `9WME34GIAPX` |
| Peer 2 | `10.122.84.63` / `9AH5QNPD6XG` |
| Reserved vPC interfaces | `vpc100`, `vpc101` |
| Peer-1 member ports | `Ethernet1/5`, `Ethernet1/7`, `Ethernet1/8` |
| Peer-2 member ports | `Ethernet1/5`, `Ethernet1/7` |

Two fixture values differ from the historical lab:

- The current fabric uses its ND-discovered physical peer-link instead of the
  historical virtual peer-link.
- `Ethernet1/8` replaces historical peer-1 member `Ethernet1/6` because it is
  the reserved, ND-discovered port available in this fabric.

Pair creation uses `config_actions.type: switch`. Pair deletion retains the
module's switch-scoped default.

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
  --tags nd4x_demo \
  -vv
```

The overridden workflow must be run separately with:

```ini
nd_vpc_access_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_interface_vpc_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden \
  -vv
```

## Execution record

The collection baseline was
`5c1e7ec2eb19154b44ad42cb0925fa87fb3f7188`. The harness was tested as
uncommitted working-tree content. The recorded runtime YAML manifest is
SHA-256 `57fcf0b992eab6e312d354a92cf17b8aa5ca4e87040ad51dfbf67db20ad1bd6b`.

All commands below used:

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
  port-channel mode.

## Latest develop follow-up

Commit `5927ac35` added the original `multi_pair.yaml` workflow after the
recorded parity runs. It is not yet represented in the ND 4.x harness and
requires a second vPC pair.

The original suite remains enabled. The harness is not a complete replacement
until the multi-pair workflow is migrated, executed, and recorded here.
