# `nd_interface_ethernet_trunk_host` Harness Parity

This document is the migration map for the original integration suite. The
original `merged.yaml`, `replaced.yaml`, `overridden.yaml`, `deleted.yaml`,
and `setup.yaml` files are retained while this map is reviewed.

Status is **Implemented; VLAN capability-gated skip accepted as an environment-specific exception; harness validation complete; retirement pending reviewer approval**.
The original suite remains in place pending explicit retirement review; the
destructive overridden path is separately opt-in.
No scenario is retired by this change.

## Scenario mapping

| Original scenario and assertion | Harness replacement | Status |
|---|---|---|
| Remove Ethernet1/41 through Ethernet1/48 before testing | Local setup in every harness workflow; complete cleanup in `always` | Implemented; passed |
| Merged create Ethernet1/41 in check and normal mode; assert changed and returned VLAN | `nd4x_demo_merged.yaml`: `MERGED CREATE` | Implemented; passed |
| Merged fan-out create Ethernet1/42 and Ethernet1/43; assert both returned | `MERGED FAN-OUT` | Implemented; passed |
| Merged create Ethernet1/44 as an independent config group | `MERGED CREATE` Ethernet1/44 | Implemented; passed |
| Merged re-apply Ethernet1/41 in check and normal mode; assert no change | `MERGED IDEMPOTENT` | Implemented; passed |
| Merged re-apply Ethernet1/42 and Ethernet1/43 fan-out; assert no change | Harness idempotency phase in `MERGED FAN-OUT` | Implemented; passed |
| Merged update Ethernet1/41 allowed VLANs, native VLAN, description, BPDU guard, and CDP | `MERGED UPDATE` | Implemented; passed |
| Merged re-apply Ethernet1/41 update; assert no change | Harness idempotency phase in `MERGED UPDATE` | Implemented; passed |
| Merged update Ethernet1/42 and Ethernet1/43; assert VLAN, native VLAN, description, and admin state | `MERGED FAN-OUT UPDATE` | Implemented; passed |
| Merged VLAN mapping create, exact two entries, and idempotency | `nd4x_demo_vlan_mapping.yaml`; included in `nd4x_demo` when enabled | Intentional environment-specific skip accepted; no successful execution exists on the available Nexus 9000v testbed |
| Merged `deploy: false` staging on Ethernet1/48; assert changed | `MERGED NO-DEPLOY` | Implemented; passed |
| Merged large fan-out Ethernet1/45 through Ethernet1/47 with jumbo MTU; assert same config | `MERGED LARGE FAN-OUT` | Implemented; passed |
| Merged large fan-out re-apply; assert no change | Harness idempotency phase in `MERGED LARGE FAN-OUT` | Implemented; passed |
| Storm-control percentage create and read-back; assert changed and interface exists | `nd4x_demo_storm_control.yaml`: `STORM READ-BACK` | Implemented; passed |
| Storm-control percentage re-apply; assert no change and GET shape accepted | Harness idempotency phase in `STORM READ-BACK` | Implemented; passed |
| Storm-control percentage-to-pps transition; assert pps set and percentage cleared | `STORM PCT-TO-PPS` | Implemented; passed |
| Storm-control pps re-apply; assert no change | Harness idempotency phase in `STORM PCT-TO-PPS` | Implemented; passed |
| Storm-control pps-to-percentage transition; assert percentage set and pps cleared | `STORM PPS-TO-PCT` | Implemented; passed |
| Storm-control percentage re-apply; assert no change | Harness idempotency phase in `STORM PPS-TO-PCT` | Implemented; passed |
| Seed exact dual-valued storm-control controller state and assert both fields are echoed | Local raw `nd_rest` pre-state reconstruction in `nd4x_demo_storm_control.yaml` | Implemented; passed |
| Remediate dual-valued state with matching pps; assert percentage cleared | `STORM DUAL` | Implemented; passed |
| Re-apply remediated dual state; assert no change | Harness idempotency phase in `STORM DUAL` | Implemented; passed |
| Replaced setup recreates exact post-merged state, including fields preserved by merged updates | Local setup in `nd4x_demo_replaced.yaml` replays the original merged base and update phases, then validates controller state | Implemented; passed |
| Replaced Ethernet1/41; assert changed and exact VLAN/native VLAN/description | `REPLACED SINGLE` | Implemented; passed |
| Replaced Ethernet1/41 re-apply; assert no change | Harness idempotency phase in `REPLACED SINGLE` | Implemented; passed |
| Replaced Ethernet1/42 and Ethernet1/43 fan-out; assert both exact values | `REPLACED FAN-OUT` | Implemented; passed |
| Replaced Ethernet1/41 and Ethernet1/44 from separate groups; assert exact values | `REPLACED MULTI` | Implemented; passed |
| Overridden reduce to Ethernet1/41 and Ethernet1/42; assert changed and exact retained values | `nd4x_demo_overridden.yaml`: `OVERRIDDEN REDUCE` | Implemented; passed |
| Overridden identical re-apply; assert no change | `OVERRIDDEN IDEMPOTENT` | Implemented; passed |
| Overridden swap to Ethernet1/42, Ethernet1/43, and Ethernet1/44; assert values | `OVERRIDDEN SWAP` | Implemented; passed |
| Overridden fan-out to Ethernet1/45 through Ethernet1/47; assert all values | `OVERRIDDEN FAN-OUT` | Implemented; passed |
| Overridden empty config; assert prior fan-out is normalized | `OVERRIDDEN EMPTY`; destructive opt-in required | Implemented; passed |
| Overridden empty config re-apply; assert no change | Harness idempotency phase in `OVERRIDDEN EMPTY` | Implemented; passed |
| Restore fan-out after empty overridden for the following deleted tests | Deleted workflow independently reconstructs its own exact pre-state | Implemented; passed |
| Deleted setup recreates Ethernet1/45 through Ethernet1/47 | Local setup in `nd4x_demo_deleted.yaml` | Implemented; passed |
| Deleted Ethernet1/45 in check and normal mode; assert reset or absent | `DELETED SINGLE`; physical interface and trunkHost state validated by `nd_queries` | Implemented; passed |
| Deleted Ethernet1/45 re-apply; assert no change | Harness idempotency phase in `DELETED SINGLE` | Implemented; passed |
| Deleted Ethernet1/46 and Ethernet1/47 fan-out; assert both reset | `DELETED FAN-OUT` | Implemented; passed |
| Deleted Ethernet1/41 through Ethernet1/43 from multiple groups; assert all reset | `DELETED MULTI` | Implemented; passed |
| Deleted Ethernet1/48 already at defaults; assert no change | `DELETED NON-EXISTENT` | Implemented; passed |
| Seed Ethernet1/48 `bandwidth: 1500000` | Local class-C setup in `nd4x_demo_deleted.yaml` | Implemented; passed |
| Deleted class-C state; assert bandwidth is cleared or resource normalized | `DELETED CLASS C` | Implemented; passed |
| Harness-only negative test: missing `interface_names`; assert exact module validation reason | `nd4x_demo_negative.yaml` with check mode and idempotency disabled | Supplemental harness coverage; not present in the original suite |

## Harness guarantees added to each positive workflow

- `nd4x_module_test` owns predictive, apply, and idempotency expectations.
- `nd4x_fabric_check_mode_queries` snapshots every interface endpoint in the
  fabric before and after predictive execution, ignoring only volatile
  `operData`.
- `nd_queries` validates persisted controller state independently of the
  module's returned `after` value.
- Assertions retain module-specific checks against registered phase results.
- Mutable workflows use `block`/`always` cleanup and reconstruct their own
  required pre-state, so state-specific runs do not depend on execution order.
- Each mutable state-specific workflow runs the original cleanup check-mode re-query
  probe through `nd4x_demo_setup_probe.yaml` after normalization.

## Discovery and safety

The shared preflight in `nd4x_demo_preflight.yaml` gates on ND 4.0.0 or later,
discovers `switchId` from `fabricManagementIp`, verifies every reserved
interface exists and is Ethernet/non-port-channel, and builds complete-fabric
predictive snapshot queries.

Reserved interfaces are declared in `vars/main.yaml`. Safe harness workflows
require:

```ini
nd_ethernet_reserved_ports_confirmed=true
```

The overridden workflow additionally requires:

```ini
nd_ethernet_destructive_tests_enabled=true
```

It discovers trunkHost resources on every switch and refuses to run if any
explicitly configured, non-default resource is outside the reserved switch and
interface range. ND reports the fabric-default `int_trunk_host` policy as
`policyType: trunkHost` on physical Ethernet interfaces, so the overridden
safety filter excludes interfaces whose `allowedVlans`, `description`, and
`nativeVlan` match the normalized default and whose unresettable fields
(`bandwidth`, `debounceLinkupTimer`, and `inheritBandwidth`) are absent.
The destructive workflow is tagged separately as `nd4x_demo_overridden` and
`nd4x_demo_destructive`; both tags run the shared preflight and neither is
selected by the safe aggregate tag.

## Tags

All harness includes are opt-in and carry `never`. The safe aggregate is:

```bash
ansible-test network-integration nd_interface_ethernet_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo -vv
```

State-specific tags are `nd4x_demo_merged`, `nd4x_demo_replaced`,
`nd4x_demo_deleted`, `nd4x_demo_negative`, `nd4x_demo_vlan_mapping`, and
`nd4x_demo_storm_control`. Destructive aliases are
`nd4x_demo_overridden` and `nd4x_demo_destructive`. The destructive run is
separate:

```bash
  ansible-test network-integration nd_interface_ethernet_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden --allow-destructive -vv
```

## Same-environment execution record

| Evidence | Result |
|---|---|
| Original suite | Aggregate run passed against the same virtual environment, but VLAN mapping was skipped; no successful VLAN-mapping execution exists. The original suite remains retained pending explicit retirement review. |
| Safe aggregate harness (`nd4x_demo`) | Passed against the same environment after strict-assertion additions and cleanup-probe coverage: `ok=96 changed=31 failed=0 skipped=3`; merged, replaced, deleted, negative, and storm-control workflows completed with `always` cleanup. VLAN mapping was reached but capability-skipped. |
| State-specific harness runs | `nd4x_demo_merged`, corrected `nd4x_demo_replaced`, `nd4x_demo_deleted`, `nd4x_demo_negative`, and `nd4x_demo_storm_control` passed. VLAN mapping remains intentionally skipped because `supports_vlan_mapping` is false; this is accepted for the available virtual environment. |
| Destructive harness (`nd4x_demo_overridden` / `nd4x_demo_destructive`) | Passed after strict-assertion and cleanup-probe additions: `ok=38 changed=7 failed=0 skipped=3`; both destructive tags reached shared preflight, normalized default `trunkHost` interfaces were ignored, the reserved-scope scenarios completed, and cleanup ran. |
| ND version/fabric/switch | ND 4.2.1; `VXLAN_Fabric`; discovered test switch `10.122.84.71` / `9WME34GIAPX`; second fabric switch `10.122.84.63` / `9AH5QNPD6XG`. |
| Unmapped original scenarios | None identified. VLAN mapping is mapped and intentionally capability-skipped because the available virtual platform rejects the policy before deployment; the exception is accepted for this environment. The negative validation test is supplemental, not an original mapping. Original-file retirement remains pending explicit reviewer approval. |

## Retirement decision

The original suite must remain until the complete original suite, safe harness
suite, and separately opted-in destructive harness suite pass on the same
environment, the VLAN capability-gated skip is explicitly accepted for the
current virtual environment, the execution evidence is recorded above, and
reviewers approve retirement explicitly. This migration change does not remove
or modify any original scenario implementation.
