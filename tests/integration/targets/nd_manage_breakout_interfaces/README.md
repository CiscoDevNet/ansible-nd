# Interface breakout integration tests

This is an ordinary policy-style role: module tasks, registered results, YAML
assertions, and a read-only action plugin for independent controller observations.
It does not use the interface-groups harness.

The operator supplies a reserved, initially native 100G parent on an NX-OS switch,
a known-supported map, and the complete affected hardware footprint. Setup validates local variables
and the full fixture schema through the validator's zero-GET `validate_only`
mode. In the default/lifecycle sequence, the first module invocation is
`merged` creation; there is no fabric-summary lookup, hardware-capability
discovery, initial full inventory scan, or pre-cleanup.
The module invocation itself validates NX-OS eligibility before its filtered
interface discovery. Serial inputs add one exact switch-detail GET per distinct
switch; management-IP inputs reuse their resolver metadata. These platform reads
are included in the lifecycle's asserted GET budgets. No full switch inventory
or hardware-model allowlist is introduced.

## Running

Keep credentials and HTTPAPI connection settings in the existing inventory and
private integration configuration, not in this role.

```sh
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
export ND_TIMEOUT=600
ansible-playbook -i tests/integration/inventory.networking \
  tests/integration/targets/nd_manage_breakout_interfaces/run_tests.yaml \
  -e @tests/integration/integration_config.yml \
  -e @/absolute/path/to/private_breakout_fixture.yml \
  -e testcase=lifecycle -vvv
```

Set `ansible_command_timeout`, `ansible_persistent_command_timeout`, and
`ansible_connect_timeout` to 600 in the private configuration when applicable.
Do not run the role with global `--check`: individual tasks exercise check mode
and independently prove that their controller state did not change.

`testcase=all` runs `lifecycle`, `validation`, `output`, and `bulk`. Each file can
also be selected separately. Run `-vvv` to enforce module write-count/order
assertions. Lower verbosity still validates registered business results and
independent topology, but intentionally cannot claim an absent trace proves zero
API calls.

Standalone validation/output selections use the operator's native fixture and
read-only observations; they do not implicitly create a breakout first.

## Fixture

For hardware where only the requested parent changes:

```yaml
test_fabric_name: fab1
test_switch_serial: YOUR_SWITCH_SERIAL
test_switch_ip: ""              # Optional management IPv4/IPv6 identity test.
test_breakout_parent: Ethernet1/50
test_breakout_map: 25g-4x         # Must already be known to work on this parent.
```

The default fixture expects four children and one restored native parent. If
hardware affects additional ports, override `test_breakout_fixture`; do not use
the default one-parent footprint. For the previously observed 21–24 footprint,
the same test cases can use:

```yaml
test_breakout_fixture:
  control_parent: Ethernet1/21
  native_interfaces:
    - Ethernet1/21
    - Ethernet1/22
    - Ethernet1/23
    - Ethernet1/24
  profiles:
    map_a:
      breakout_map: 25g-4x
      child_lanes:
        Ethernet1/21: [1, 2, 3, 4]
        Ethernet1/23: [1, 2, 3, 4]
      native_interfaces: []
```

This is a declared expected fixture, not automatic adjacency inference or a
hardware allowlist. The validator rejects extra/missing physical lanes and native
parents inside the reserved footprint. Module snapshots are not the observation
oracle. Config-only ghost parents do not count as native physical interfaces.

The all-broken-family merged no-op task uses the declared `child_lanes` families;
thus 23 is tested when 21 creates its children, while absent 22/24 are not
incorrectly treated as existing breakout families. Child deletion selects an
actual observed child rather than fabricating `/1`. The supplied child can alias a
coupled family; the complete footprint must still return to its native profile.

Only `merged` and `deleted` are supported. Changing an existing breakout map
requires explicit deletion followed by merged creation; this suite does not
attempt automatic map reconciliation. Each fixture declares only `profiles.map_a`.
The merged different-map no-op test supplies an intentionally different, nonempty
string. Because no action should be sent for an existing breakout, that string
does not need to describe a second hardware-supported map.

Optional `policy_maps` in a profile names additional exact parent-policy MAP
expectations. Optional `guard_interfaces` and `interface_filter` can narrow and
extend observation scope. Guard invariance is measured against the saved snapshot
after first creation; because setup performs no GET, it does not prove guards were
unchanged by that first creation.

## Lifecycle and validations

| Task group | Intended result and evidence |
|---|---|
| First merged creation | Must actually change the native parent; a pre-existing breakout is not accepted as setup success. One breakout POST; full map-A footprint independently observed. |
| Merged repeats | Normalized input, optional management IP, all broken-family aliases, and `verify.enabled=true` are no-ops. Zero POST, no extra verification readback, and unchanged independently observed footprint/MAP. |
| Check mode while broken | Merged remains no-op; parent/actual-child deletion is planned only. Zero writes and unchanged independent snapshot. |
| Merged different map | Existing breakout and actual MAP are preserved, including when a nonempty unsupported map is supplied. |
| Parent deletion | Whole declared footprint restored; repeated parent deletion is a no-op. |
| Check mode while native | Merged creation predicts a change without writes; a former-child deletion remains no-op. Native snapshot unchanged. |
| Verified merged creation | Creates A through one breakout POST; optional topology verification plus independent full footprint and MAP observation. |
| Actual-child deletion | Requested selector, logical family and verified wire child are distinguished. Whole footprint native; former-child and subsequent parent repeats are no-ops. |
| Local validation | Malformed identities, duplicate aliases, missing/blank maps, unsupported config actions/verify options, and unsupported `replaced`/`overridden` fail without recorded API calls. Unit tests additionally prove unsupported states fail before connection initialization. |
| Discovery validation | Nonexistent child membership and entirely absent parents fail before writes; optional management-IP/serial duplicate resolution also fails before writes. Independent topology/MAP observations remain unchanged. |

Assertions preserve the original `failed` and `changed` values, per-item outcomes,
snapshot provenance, planned diff, and NDOutput fields.
Expected rejection tests elsewhere in the role must retain `failed=true`; using
`failed_when: false` would erase the evidence being tested.

The observer uses filtered GETs, reads policy MAPs as controller intent, and never
performs breakout, unbreakout, config-save, or deploy. Its calls are outside the
module's `api_calls` budget. Controller intent/topology is not proof of running
configuration, link state, or absence of pending restored-interface intent.

Per-parent-map bulk and partial-batch cases require genuinely independent control groups,
not two coupled parents that represent one physical footprint. Conflicting maps
on coupled 21/23 are not a portable successful configuration. Response-order,
missing/foreign/duplicate identity, transport ambiguity, and accurate partial
change reporting additionally require deterministic unit coverage.

## Optional independent bulk groups

`test_breakout_bulk_fixtures` defaults to `[]`. Supply at least two complete
fixtures, each using the same `control_parent`, `native_interfaces` and `profiles`
schema as the primary fixture, with an optional explicit serial `switch_id`
(otherwise `test_switch_serial` is used). Their declared complete footprints must
be disjoint on each switch. A coupled 21–24 footprint is one fixture, not separate
21 and 23 bulk resources.

Bulk creation accepts each control parent's own supported `map_a`, including
different maps on independently acting parents of the same switch. The suite
checks one bulk write, all-parent idempotency, full-footprint observations and
bulk deletion/idempotency. Missing independent-resource prerequisites are
explicitly reported as skipped; the suite never finds extra ports or invents a
supported map.

The standalone bulk selection is intended for extra independent reserved
resources. Like the core fixture, initial native state and reservation are
operator prerequisites, not enforced by a pre-cleanup mutation.

## Cleanup safety

Cleanup runs in `always` only after the first module discovery proved the control
parent native and the test changed or may have changed it. A first-task no-op on a
pre-existing breakout fails the test and is not deleted as test-owned state.

Cleanup reads the reserved footprint and removes one observed broken family,
preferring the control parent. It refreshes before considering any surviving
collateral family, with at most one attempt per reserved family, and validates
the complete native profile. An original removal blocks further removes across
its entire footprint, including coupled aliases, if it failed, is uncertain, or
reported success but native topology did not converge. A successful direct
unbreakout gets bounded GET-only settling; its API success and any independent
topology failure stay separate. A noop or check-mode plan is not an attempted
removal. The same family is never replayed. After a cleanup-issued
confirmed remove, GET-only polling waits for that family's children to disappear
before a fresh snapshot can select another family; inventory lag never causes
an automatic write retry. Cleanup never blindly deletes every coupled child,
clears the whole switch, or hides cleanup failures. The original lifecycle
failure is retained and re-raised after successful cleanup; successful lifecycle
restoration releases ownership after independent final validation.
