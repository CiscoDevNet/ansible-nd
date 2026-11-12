# `nd_manage_fabric` ND 4.x Harness Parity

This target contains six fabric modules. The harness selects the concrete
module for each fabric family; there is no `cisco.nd.nd_manage_fabric` module.
The original `fabric_*.yaml` files remain unchanged and continue to provide
the legacy integration suite.

## Harness coverage

The opt-in harness uses a shared target-local workflow parameterized by each
module's native fixture and configuration shape. Every family runs merged
create/update, replaced create/minimal replacement, delete, idempotency,
post-apply REST assertions, and config-actions validation. The iBGP, eBGP, and
External Connectivity families also retain the legacy multi-fabric call shape.
Campus fast-convergence coverage is gated by controller version: ND 4.3.1 and
later apply and verify the field through the harness; older versions retain the
direct local-validation failure check.

Predictive execution snapshots the complete paginated `category=fabric`
inventory before and after check mode. This is intentionally broader than the
requested test fabric so predictive writes to another fabric are detected.
The snapshot does not ignore fabric fields. Run the suite on a controller that
is not receiving concurrent fabric changes while a predictive phase executes.

The invalid `config_actions` cases remain direct module calls. They assert the
validation message, `failed: true`, `changed: false`, and repeat the invalid
request to verify validation is not bypassed on a no-drift path. A subsequent
harness call checks that the baseline field remains unchanged.

## Scenario map

| Fabric family | Module | Harness cases | Legacy reference |
|---|---|---|---|
| iBGP VXLAN | `cisco.nd.nd_manage_fabric_ibgp_vxlan` | merged create/update; replaced defaults; delete; multi-fabric configuration assertions; config-actions | `fabric_ibgp.yaml` |
| eBGP VXLAN | `cisco.nd.nd_manage_fabric_ebgp_vxlan` | merged create/update; same-fabric merged/replaced comparison; replaced defaults; delete; multi-fabric configuration assertions; config-actions | `fabric_ebgp.yaml` |
| Campus iBGP VXLAN | `cisco.nd.nd_manage_fabric_campus_ibgp_vxlan` | merged create/update; Campus field version gate; controlled-failure `always` cleanup; replaced defaults; delete; config-actions | `fabric_campus.yaml` |
| External Connectivity | `cisco.nd.nd_manage_fabric_external` | merged create/update; same-fabric merged/replaced comparison; replaced defaults; delete; multi-fabric configuration assertions; config-actions | `fabric_external.yaml` |
| AI iBGP VXLAN | `cisco.nd.nd_manage_fabric_ai_ibgp_vxlan` | merged create/update; replaced defaults; delete; config-actions | `fabric_ai_ibgp.yaml` |
| AI eBGP VXLAN | `cisco.nd.nd_manage_fabric_ai_ebgp_vxlan` | merged create/update; replaced defaults; delete; config-actions | `fabric_ai_ebgp.yaml` |

The merged-update and minimal-replacement REST checks include the direct
field-by-field assertions from each legacy suite (335 value/existence checks in
total). This keeps the original expected values and defaults in the harness
query matrix while the legacy files remain unchanged. Campus has no legacy
field-by-field replacement assertions; its harness still checks the Campus
type, replacement ASN, and restored system MTU. `overridden` is supported by
the modules but is not covered by the legacy suites and is intentionally not
part of this migration.

The eBGP and External Connectivity comparison scenarios reuse one disposable
fabric per family: the harness seeds the full fixture, applies a partial
`merged` update and queries the retained/updated values, then applies a partial
`replaced` update to that same fabric and queries the reset/default values.
Both resources are included in the block's unconditional cleanup list.

The iBGP, eBGP, and External Connectivity multi-fabric calls use the legacy
two-fabric payloads, with one ND 4.2.1 exception: the eBGP multi-fabric
fixture omits explicit `bgp_asn_auto_allocation: false` for `sameTierAS`,
because ND omits `bgpAsnAutoAllocation` from GET responses for that mode and
the module otherwise detects a change on every run. The option is covered in
the eBGP multi-AS scenarios. REST queries verify each resource's name and type
plus every applicable returned field: 66 checks per iBGP fabric, 70 per eBGP
fabric, and 24 per External Connectivity fabric. ND omits empty
strings and some inactive defaults from GET responses (including DHCP protocol
when local DHCP is disabled, interface-statistics interval when statistics are
disabled, and management IPv4 prefix when no management gateway is configured).
Those values remain in the exact request payloads but are not asserted on
read-back. The checks cover per-fabric ASN/site/MAC and address-range
differences as well as the other returned shared settings.

The iBGP and AI iBGP merged checks seed a distinct advisory banner, omit it
from the subsequent update, and assert that the exact value remains. eBGP and
AI eBGP checks also assert ASN allocation, ASN mode/range, path limits, and
automatic EVPN peering fields. AI eBGP likewise seeds a non-empty probe banner
before its partial merge so the harness proves preservation instead of merely
retaining the empty default.

The Campus harness creates a run-scoped cleanup probe, triggers and rescues the
same intentional failure used by the legacy suite, and removes the probe in an
`always` block. A follow-up harness delete checks for unchanged state, and a
404 REST assertion confirms that the cleanup already removed the probe. The
outer harness cleanup list also includes the probe as a safety net.

## Tags and execution

Harness scenarios are opt-in and tagged `never`, `nd4x_demo`, and one family
tag. The selected harness tags automatically suppress the legacy task blocks,
including their `always` cleanup. A normal run without harness tags continues
to run the legacy suite as before.

Run one group at a time with the existing private integration inventory, for
example:

```text
ansible-test network-integration nd_manage_fabric \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_ibgp -vv
```

Use one of `nd4x_demo_ebgp`, `nd4x_demo_campus`, `nd4x_demo_external`,
`nd4x_demo_ai_ibgp`, or `nd4x_demo_ai_ebgp` in place of
`nd4x_demo_ibgp` to select another family. The test target derives harness-only
mode from the selected tags; no inventory or credential edits are required.

## Live results

Run recorded on 2026-11-10 with Nexus Dashboard 4.2.1, Python 3.11.18,
`ansible-test` 2.19.14, and the private inventory.

| Family | Result | Recap | Notes |
|---|---|---|---|
| iBGP VXLAN | PASS | `ok=30 changed=9 unreachable=0 failed=0 skipped=17 rescued=0 ignored=2` | The two ignored failures are the expected invalid config-actions checks. |
| eBGP VXLAN | PASS | `ok=33 changed=12 unreachable=0 failed=0 skipped=14 rescued=0 ignored=2` | The two ignored failures are the expected invalid config-actions checks. The eBGP multi-fabric idempotency check passes after omitting `bgp_asn_auto_allocation` for `sameTierAS`, which ND 4.2.1 omits from GET responses. |
| Campus iBGP VXLAN | PASS | `ok=36 changed=10 unreachable=0 failed=0 skipped=17 rescued=1 ignored=3` | The rescued failure is the intentional Campus cleanup probe. The ignored failures are expected invalid config-actions checks and the ND-version-gated fast-convergence rejection. |
| External Connectivity | PASS | `ok=33 changed=12 unreachable=0 failed=0 skipped=17 rescued=0 ignored=2` | The two ignored failures are the expected invalid config-actions checks. |
| AI iBGP VXLAN | PASS | `ok=28 changed=8 unreachable=0 failed=0 skipped=22 rescued=0 ignored=2` | The two ignored failures are the expected invalid config-actions checks. |
| AI eBGP VXLAN | PASS | `ok=28 changed=8 unreachable=0 failed=0 skipped=22 rescued=0 ignored=2` | The two ignored failures are the expected invalid config-actions checks. The rerun passed after adding the legacy `nxapi: false` value to the replacement request. |
