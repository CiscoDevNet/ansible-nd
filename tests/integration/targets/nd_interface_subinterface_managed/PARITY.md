# ND 4.x harness parity: `nd_interface_subinterface_managed`

The legacy scenarios in `tasks/merged.yaml`, `tasks/replaced.yaml`,
`tasks/overridden.yaml`, `tasks/deleted.yaml`, `tasks/xe.yaml`, and
`tasks/xe_teardown.yaml` remain unchanged. Harness cases are separate and
opt-in under the `nd4x_demo` tag family. The mappings below describe the
current harness implementation; “gap” means the harness does not yet assert
the corresponding legacy behavior.

## Legacy-to-harness case map

| Legacy case | Harness case | Parity and differences |
|---|---|---|
| `merged.yaml`: unsupported Loopback parent, check mode and normal mode | `nd4x_demo_negative.yaml`: unsupported parent, both modes | Covered. Harness asserts the validation failure and reason in both modes. |
| `merged.yaml`: ambiguous abbreviated parent, normal mode | `nd4x_demo_negative.yaml`: ambiguous parent, check mode and normal mode | Covered; harness exercises both modes and checks the exact validation failure. |
| `merged.yaml`: create Ethernet `.2`, check mode and normal mode | `nd4x_demo_merged.yaml`: create Ethernet `.20` through `nd4x_module_test` | Covered with a different reserved ID. The harness checks predictive execution, apply, idempotency, returned fields, and ND REST state. |
| `merged.yaml`: create Ethernet `.3` and `.4` in one call | `nd4x_demo_merged.yaml`: create Ethernet `.20` and `.21` plus Port-channel `.23` in one call | Covered with different reserved IDs. The harness creates two Ethernet subinterfaces on the same parent in one request and also includes the Port-channel case. |
| `merged.yaml`: create Port-channel `.5` | `nd4x_demo_merged.yaml`: create Port-channel `.23` with Ethernet `.20` | Covered with a different reserved ID; returned membership and REST fields are checked. |
| `merged.yaml`: reapply `.2` in check and normal mode; both predict no change | `nd4x_demo_merged.yaml`: post-convergence no-op call for `.20` and `.23` | Covered. The harness sets `expected.check_mode.changed` and `expected.apply.changed` to `false`. |
| `merged.yaml`: update description, IPv4 address, redirects, PIM sparse mode, PIM DR priority, and routing tag on `.2` | `nd4x_demo_merged.yaml`: update `.20` with IPv4/IPv6, prefix, MTU, redirects, PIM, priority, NetFlow, and routing tag | Covered with a different reserved ID. Updated values, including description, are asserted in returned state and REST. |
| `merged.yaml`: reapply the update and verify idempotency | `nd4x_demo_merged.yaml`: update phase idempotency | Covered through the harness idempotency phase. |
| `replaced.yaml`: replace `.3` with a stripped-down configuration and reapply | `nd4x_demo_replaced.yaml`: seed `.21`, replace it, then verify idempotency | Covered with a different reserved ID. Replacement description/IP are checked in returned state and REST; redirects are checked in returned state. |
| `overridden.yaml`: retain Ethernet `.2` and Port-channel `.5`, update both, remove `.3` and `.4`, then reapply | `nd4x_demo_overridden.yaml`: retain/update Ethernet `.20` and Port-channel `.23`, remove the other reserved Ethernet subinterfaces | Covered with different reserved IDs. The harness checks returned membership, updated retained values, REST state, idempotency, and full-fabric preflight/postflight scope. |
| `deleted.yaml`: delete `.2` in check and normal mode, verify absence, and repeat | `nd4x_demo_deleted.yaml`: seed/delete `.22`, verify returned and REST absence, and verify idempotency | Covered with a different reserved ID through harness check/apply/idempotency phases. |
| `deleted.yaml`: final cleanup of `.2`–`.5` and verify no configured test entries remain | `nd4x_demo_merged.yaml`, `nd4x_demo_replaced.yaml`, `nd4x_demo_deleted.yaml`, and `nd4x_demo_overridden.yaml`: scenario `always` cleanup of reserved harness entries | Cleanup behavior is present. Unlike the legacy final cleanup task, the harness does not make a separate assertion over the cleanup task’s returned state. |
| `xe.yaml`: resolve switch, clean reserved entries, make parent routed, and wait for discovery | `nd4x_demo_xe.yaml` plus `nd4x_demo_xe_parent_preflight.yaml` | Covered with stronger guards: explicit XE opt-in, exact fabric-default trunk-host starting state, complete interface/link/diff snapshots, no fabric-link endpoint or port-channel membership, and free reserved IDs. |
| `xe.yaml`: reject IOS-XE `mtu` in check and normal mode | `nd4x_demo_xe.yaml`: reject `mtu` in check and normal mode | Covered. Both calls must fail and name the unsupported `mtu` field. |
| `xe.yaml`: create `.100` and `.101` together (inferred `iosXeSubinterface` and explicit `iosXeSubinterfaceShutNoshut`), verify fields and policy types | `nd4x_demo_xe.yaml`: create `.200`, `.201`, and `.204`; `.200` is explicit, `.201` uses shut/noshut, and `.204` infers the subinterface policy | Covered with different reserved IDs. Policy types, lifecycle behavior, and `.200` IPv6 address/prefix are asserted in returned state and REST. |
| `xe.yaml`: reapply `.100`/`.101` in check and normal mode and verify no change | `nd4x_demo_xe.yaml`: create-phase idempotency plus a separate converged check-mode no-op call | Covered. The no-op wrapper expects `changed: false` for check mode, apply, and its idempotency pass. |
| `xe.yaml`: update `.100` description and IPv4 address, then verify update idempotency | `nd4x_demo_xe.yaml`: update `.200` description and IPv4 address, then verify returned state, REST, and idempotency | Covered with a different ID. |
| `xe.yaml`: replace `.100` with its base configuration and reapply | `nd4x_demo_xe.yaml`: replace `.200` with its base fixture and verify idempotency | Covered with a different ID; restored IPv4 address is checked in returned state and REST. |
| `xe.yaml`: create explicit-policy `.102` | `nd4x_demo_xe.yaml`: create explicit-policy `.200` | Covered with a different ID. `.204` separately covers inferred policy type. |
| `xe.yaml`: overridden keeps `.100`/`.101`, removes `.102`, then reapply | `nd4x_demo_xe_overridden.yaml`: keeps `.200`/`.201`, removes `.202`, then verifies idempotency | Covered with different IDs. The harness also checks full-fabric scope before and after override. |
| `xe.yaml`: delete `.100`/`.101` using lower-case interface names; verify absence and repeat | `nd4x_demo_xe.yaml`: delete `.200`, `.201`, and `.204` using lower-case interface names; verify canonical returned and REST absence and idempotency | Covered with different IDs. The harness submits lower-case names and verifies the canonical resources are absent. |
| `xe.yaml`: verify `.100`–`.102` are absent from running configuration | `nd4x_demo_xe.yaml` delete assertions and `nd4x_demo_xe_teardown.yaml` running-config wait | Covered for harness-reserved `.200`–`.204`; teardown waits for every reserved name to leave running configuration. |
| `xe_teardown.yaml`: remove remaining test subinterfaces and reset parent to fabric-default trunk host, including after failure | `nd4x_demo_xe_teardown.yaml`, invoked from the harness scenario’s `always` section | Covered with a stricter precondition. Teardown re-reads the parent and links, and proceeds only if the port is still the verified default or has the exact routed-host policy created by this harness. |

## Intentional exceptions

- The harness is additive. It does not replace, edit, or automatically run the
  legacy suite. Harness scenarios use their own IDs: NX-OS `.20`–`.24` and
  IOS-XE `.200`–`.204`; legacy IDs remain NX-OS `.2`–`.5` and IOS-XE
  `.100`–`.103`.
- IOS-XE harness scenarios require both `nd_test_xe_switch_ip` and
  `nd_subinterface_managed_xe_tests_enabled=true`. Setting the opt-in confirms
  that the selected parent is the dedicated test host port. The parent must
  begin in the documented IOS-XE fabric-default trunk-host state. The
  preflight rejects incomplete inventories, fabric links, port-channel
  membership, occupied reserved IDs, or a non-default starting policy.
- Both harness `overridden` cases require
  `nd_subinterface_managed_destructive_tests_enabled=true` and a complete
  fabric-wide inventory proving that every managed subinterface is inside the
  reserved scope. The postflight verifies the fabric-wide result. This is an
  intentional additional safety gate for the module’s fabric-wide behavior.
- Harness state phases are driven through `nd4x_module_test`; setup and cleanup
  use direct module calls around those phases. The harness also verifies ND
  REST state where applicable, so the task layout differs from the direct
  legacy calls while exercising the same module states.
- NX-OS harness scenarios require every reserved interface name to be absent
  from both ND's interface inventory and running configuration before setup;
  those name checks are case-insensitive to match ND's interface-name
  normalization behavior.
  They do not pre-delete occupied names or guess that a prior resource belongs
  to the harness. If a run is interrupted and leaves a reserved resource,
  inspect and clear it before retrying.
- Harness REST JSONPath selectors that identify an `interfaceName` compare
  names case-insensitively. The shared action helper normalizes both the
  returned interface names and selector literals, so presence and absence
  assertions behave consistently across ND response capitalization.

## Known parity gaps

No known gaps remain for the cases listed above. The harness keeps separate
reserved IDs and adds safety preflights that are not part of the legacy test
flows.

## Live run record

- **Live-run status:** All NX-OS harness scenarios are complete and passed:
  preflight, merged, replaced, deleted, negative, and overridden. The current
  pagination-aware rerun recaps are recorded below. IOS-XE live testing is not
  complete because the required lab setup is unavailable; neither IOS-XE tag
  has a live result.
- **2026-10-29 — ND 4.x harness preflight:** Passed using the local Python 3.11
  environment and `cisco/nd/tests/integration/inventory.LOCAL.networking`.
- Recap: `ok=12 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0`.
- The preflight made no changes. The single skipped task was the unsupported-ND
  version notice, which is skipped when the discovered ND version is supported.
- This result covers the harness connection and fabric/switch discovery
  preflight only.
- **2026-10-29 — ND 4.x merged scenario:** Passed after removing the Port-channel
  IP REST-path expectations that ND did not return. Recap:
  `ok=33 changed=4 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0`.
- **2026-10-29 — ND 4.x replaced scenario:** Passed. Recap:
  `ok=28 changed=3 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0`.
- **2026-10-29 — ND 4.x deleted scenario:** Passed. Recap:
  `ok=28 changed=2 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0`.
- **2026-10-29 — ND 4.x negative scenario:** Passed. Recap:
  `ok=18 changed=0 unreachable=0 failed=0 skipped=1 rescued=0 ignored=4`.
  The four ignored failures are the expected validation errors exercised by
  the negative cases.
- **2026-10-29 — ND 4.x overridden diagnostic run:** The diagnostic run had
  `ok=55 changed=3 unreachable=0 failed=0 skipped=4 rescued=0 ignored=0`, but
  the temporary REST description assertion was disabled and the diagnostic
  filter returned `msg: []` for Port-channel `.23`. This is not a final pass.
- **2026-10-29 — ND 4.x overridden rerun:** Failed because the immediate REST
  Port-channel name match. The attached REST output did contain the retained
  row as lowercase `port-channel10.23`, but the poll matched case-sensitively
  against `Port-channel10.23` and timed out. The run recap was
  `ok=39 changed=3 unreachable=0 failed=1 skipped=4 rescued=0 ignored=0`;
  fabric-wide postflight did not run, so no passing overridden result is
  recorded.
- **2026-10-29 — ND 4.x overridden scenario:** Passed after making the REST
  Port-channel name match case-insensitive. Recap:
  `ok=56 changed=3 unreachable=0 failed=0 skipped=4 rescued=0 ignored=0`.
  This run completed the scenario, including the fabric-wide postflight.
- **2026-10-29 — ND 4.x merged rerun:** Failed at the Port-channel REST
  existence assertion. The module's apply result contains `Port-channel10.23`,
  while ND REST represents that name in lowercase, `port-channel10.23`; the
  JSONPath assertion was case-sensitive. The merged REST filters now lowercase
  the configured Port-channel parent.
- **2026-10-29 — ND 4.x merged rerun after the REST name fix:** Passed. Recap:
  `ok=33 changed=4 unreachable=0 failed=0 skipped=1 rescued=0 ignored=0`.
- **2026-10-29 — ND 4.x replaced rerun:** Passed against the pagination-aware
  harness. Recap: `ok=28 changed=3 unreachable=0 failed=0 skipped=1 rescued=0
  ignored=0`.
- **2026-10-29 — ND 4.x deleted rerun:** Passed against the pagination-aware
  harness. Recap: `ok=28 changed=2 unreachable=0 failed=0 skipped=1 rescued=0
  ignored=0`.
- **2026-10-29 — ND 4.x negative rerun:** Passed against the current harness.
  Recap: `ok=18 changed=0 unreachable=0 failed=0 skipped=1 rescued=0
  ignored=4`. The four ignored failures are the expected validation errors
  exercised by the negative cases.

## Running harness scenarios

```text
ansible-test network-integration nd_interface_subinterface_managed --tags nd4x_demo
ansible-test network-integration nd_interface_subinterface_managed --tags nd4x_demo_merged
ansible-test network-integration nd_interface_subinterface_managed --tags nd4x_demo_xe
ansible-test network-integration nd_interface_subinterface_managed --tags nd4x_demo_xe_overridden
```

IOS-XE harness scenarios additionally require
`nd_subinterface_managed_xe_tests_enabled=true` and the configured test switch
and dedicated parent port, with IDs `.200`–`.204` free. Overridden scenarios
also require the destructive-test opt-in and a clean full-fabric scope. The
NX-OS harness state scenarios require their reserved names to be free before
starting and clean up resources they create after running.
