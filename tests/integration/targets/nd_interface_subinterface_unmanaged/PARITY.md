# `nd_interface_subinterface_unmanaged` Harness Parity

This document maps the existing unmanaged subinterface integration scenarios
to their ND 4.x harness counterparts. The original state scenario files remain
intact and continue to run alongside the safe harness scenarios.

## Scenario mapping

| Original scenario | Harness scenario | Coverage |
|---|---|---|
| Remove reserved test subinterfaces before the suite | Scenario-local setup and `always` cleanup | Harness IDs are isolated in `.40`–`.49`; legacy IDs `.20`–`.29` are not changed. |
| `merged.yaml`: create one Ethernet subinterface and verify check mode, apply, and idempotency | `nd4x_demo_merged.yaml` | Creates reserved Ethernet subinterfaces and verifies `monitorSubinterface`, full-fabric predictive snapshots, REST state, and idempotency. |
| `merged.yaml`: create multiple Ethernet subinterfaces in one task | `nd4x_demo_merged.yaml` | Creates `.40` and `.41` together, matching the original same-parent batch case. |
| `merged.yaml`: create a subinterface on a port-channel parent | `nd4x_demo_merged.yaml` | Creates `.45` in the same call as the Ethernet subinterfaces. |
| `merged.yaml`: check-mode idempotency after creation | `nd4x_demo_merged.yaml` | Re-runs the existing three-subinterface config through the harness and expects predictive and apply `changed: false`. |
| `replaced.yaml`: replace an existing unmanaged subinterface (no-op) | `nd4x_demo_replaced.yaml` | Verifies unchanged predictive/apply results and idempotency. |
| `replaced.yaml`: missing subinterface falls back to create | `nd4x_demo_replaced.yaml` | Verifies create, returned state, REST state, and idempotency. |
| `overridden.yaml`: retain one Ethernet and one port-channel subinterface; remove other unmanaged subinterfaces | `nd4x_demo_overridden.yaml` | Explicit opt-in only; starts with four Ethernet resources across two switches and one port-channel resource on the second switch, retains `.40` and `.45`, and verifies `.41`, `.42`, and `.49` are removed with a full-fabric predictive snapshot and exact cross-switch scope preflight. |
| `deleted.yaml`: delete one subinterface and delete it again | `nd4x_demo_deleted.yaml` | Verifies deletion, absence, and idempotency. |
| `deleted.yaml`: bulk cleanup and verify all reserved resources are gone | `nd4x_demo_deleted.yaml` | The scenario's `always` cleanup removes and asserts absence for the complete harness reserved set. |
| No original negative validation scenario | `nd4x_demo_negative.yaml` | Adds a missing-`interface_name` validation case and checks the failure reason. |

## Safety and execution

The merged, replaced, deleted, and negative harness scenarios run during a
normal target run on ND 4.0.0 or later. They can also be selected with the
`nd4x_demo` tag. Select the fabric-wide harness scenario with its explicit
`nd4x_demo_overridden` tag. Do not add `never` to `--tags`: selecting `never`
can run every `never`-tagged task in the target. The original legacy
`overridden.yaml` remains unchanged, but its include is explicit opt-in via
the `legacy_overridden` tag. A wrapper requires the destructive-test
opt-in, checks the complete fabric for unmanaged subinterfaces outside the
reserved `.20`–`.29` resources, prepares the legacy entry state, and cleans up
afterward. It requires
`nd_subinterface_unmanaged_destructive_tests_enabled=true`; use the
`legacy_overridden` tag only on a dedicated test fabric. Predictive
snapshots cover the interface collection on every switch in the test fabric;
only the volatile `operData` field and interface-list ordering are excluded
from comparison.

The module's `overridden` state queries unmanaged subinterfaces across the
whole fabric. Its harness scenario requires
`nd_subinterface_unmanaged_destructive_tests_enabled=true` and a second switch
configured as `nd_test_switch_ip_2`. It starts resources on both test switches,
retains resources on each, and verifies that omitted resources are removed
across switches. Before applying override, it rejects any unmanaged
subinterface outside the exact reserved resource list on those two switches.
Use a dedicated test fabric for this scenario. The ordinary merged, replaced,
and deleted harness scenarios do not use `overridden`.

The unmanaged module defaults to `config_actions.deploy: false`; the harness
keeps that behavior so scenarios validate Nexus Dashboard intent without
deploying changes to switches. Parent preflight is scenario-specific: merged
checks the primary Ethernet and port-channel parents; replaced and deleted
check the primary Ethernet parent; negative validation does not require a
routed parent; and cross-switch overridden checks both parents on both test
switches.

Run safe harness scenarios with the full target suite (they run by default), or
select only the harness scenarios with:

```bash
ansible-test network-integration nd_interface_subinterface_unmanaged \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  -vv
```

Run the destructive override scenario separately on a dedicated two-switch
test fabric after setting both inventory variables:

```ini
nd_test_switch_ip_2=192.168.1.2
nd_subinterface_unmanaged_destructive_tests_enabled=true
```

```bash
ansible-test network-integration nd_interface_subinterface_unmanaged \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden \
  -vv
```

## Review status

The harness scenarios cover the original state flows, including same-parent
bulk creation, port-channel handling, the existing and missing `replaced`
paths, fabric-wide cross-switch `overridden` retention/removal, and bulk
cleanup.

Live run status:

- `nd4x_demo_merged` passed on 2026-10-31 using the local integration inventory:
  `ok=23`, `changed=2`, `failed=0`, `skipped=9`. The scenario validates ND intent;
  its module calls use `config_actions.deploy: false` and do not deploy the
  subinterfaces to the switches.
- `nd4x_demo_replaced` passed on 2026-10-31: `ok=22`, `changed=3`, `failed=0`,
  `skipped=10`.
- `nd4x_demo_deleted` passed on 2026-10-31: `ok=22`, `changed=3`, `failed=0`,
  `skipped=10`.
- `nd4x_demo_negative` passed on 2026-10-31: `ok=15`, `changed=0`, `failed=0`,
  `skipped=13`.
- `nd4x_demo_overridden` passed on 2026-10-31: `ok=33`, `changed=3`,
  `failed=0`, `skipped=3`.
