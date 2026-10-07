# `nd_interface_port_channel_trunk_host` Harness Parity

This document maps every scenario and important assertion in the original
port-channel trunk-host integration suite to the ND 4.x action-plugin harness.
The original `setup.yaml`, `merged.yaml`, `replaced.yaml`, `overridden.yaml`,
`deleted.yaml`, and `vlan_mapping.yaml` files remain enabled. This migration
does not retire or alter the original suite.

## Comparison baseline

The current repository `develop` ref used for this comparison is
`084631c34dd22e1fe13137660fdf82358e246023` (`nd_log - playbook-side logging
(#283)`). It does not contain this target or the ND4X harness infrastructure, so
the original-suite baseline is the complete target present in the PR lineage at
`5c1e7ec2eb19154b44ad42cb0925fa87fb3f7188` (`WIP: preserve resolved ND module
development`). The current PR HEAD is
`2cb897cd721777e8bf8ee54b86714fe6b9bd0458`.

A direct develop-to-harness file comparison is therefore not possible; parity
is verified against the complete original target suite itself and against the
established harness implementations for the previously migrated modules.

## Scenario mapping

| Original scenario or assertion | Harness replacement |
|---|---|
| Remove port-channel501, 502, and 503 before the suite | Setup and `always` cleanup in each state workflow; port-channel504 is included because it is the no-deploy fixture. |
| Create port-channel501 in check mode and normal mode | `nd4x_demo_merged.yaml`: `MERGED CREATE`. |
| Assert port-channel501 VLANs, native VLAN, mode, LACP rate, description, and two members | Registered `first_run_result.after` assertions plus a persisted `nd_queries` GET. |
| Re-apply port-channel501 in check mode and normal mode with no change | `MERGED IDEMPOTENT`; harness check-mode, apply, and idempotency phases are all asserted unchanged. |
| Update port-channel501 allowed VLANs, native VLAN, and description | `MERGED UPDATE`; registered-result and REST assertions preserve all original field checks. |
| Re-apply the merged update idempotently | Harness idempotency phase in `MERGED UPDATE`. |
| Restore port-channel501 baseline before member tests | `MERGED MEMBERSHIP SETUP`. |
| Add member_c to port-channel501 | `MERGED MEMBER ADD`; harness phases and returned three-member state are asserted. |
| Remove member_b and member_c, retaining member_a | `MERGED MEMBER REMOVE`; returned membership and unchanged second application are asserted. |
| Create port-channel502 and port-channel503 in one task | `MERGED CREATE MULTI`; both returned resources and persisted policy types are checked. |
| Stage port-channel504 with `config_actions.deploy: false` | `MERGED NO-DEPLOY`; the harness applies the module with `module_args.config_actions.deploy: false`, checks changed/idempotency, and queries the staged policy. |
| Recreate the merged prerequisite for replaced tests | `nd4x_demo_replaced.yaml` reconstructs port-channel501 with one member plus port-channel502 and 503, then validates the exact prerequisite. |
| Replace port-channel501 and assert minimal replacement fields | `REPLACED SINGLE`; check/apply/idempotency, returned state, and REST state are asserted. |
| Re-apply port-channel501 replacement idempotently | Harness idempotency phase in `REPLACED SINGLE`. |
| Replace port-channel502 and port-channel503 together | `REPLACED MULTI`; allowed VLANs, native VLAN, description, and `admin_state: false` are asserted in both returned and REST state. |
| Override the replaced set to only port-channel501 | `nd4x_demo_overridden.yaml`: `OVERRIDDEN REDUCE`; destructive opt-in and reserved-scope preflight are required. |
| Assert port-channel502 and 503 were removed by override | REST collection absence queries and returned-resource assertions. |
| Re-apply the same override idempotently | `OVERRIDDEN IDEMPOTENT`. |
| Swap the overridden set to port-channel502 and 503 | `OVERRIDDEN SWAP`; port-channel501 absence and both retained policies are checked. |
| Confirm overridden filtering is restricted to port-channel resources | `OVERRIDDEN FILTER`; repeated no-change override asserts that every module `before` resource has `interface_type: portChannel`. Fabric-wide safety discovery separately filters to `policyType: trunkPoHost`. |
| Delete port-channel502 in check mode and normal mode | `nd4x_demo_deleted.yaml`: `DELETED SINGLE`; returned absence and REST collection absence are asserted. |
| Re-delete port-channel502 with no change | Harness idempotency phase in `DELETED SINGLE`. |
| Recreate port-channel501 with two members, delete it, and verify removal | `DELETED MEMBER REVERT`; the port-channel is absent and both former members are queried with no port-channel membership. |
| Recreate port-channel501, 502, and 503 and delete all three together | `DELETED MULTI`; all returned resources and REST collection entries are asserted absent. |
| Delete independently nonexistent port-channel599 with no change | `DELETED NON-EXISTENT`; every harness phase is asserted unchanged and the REST collection confirms absence. |
| Create port-channel501 with VLAN mapping enabled | `nd4x_demo_vlan_mapping.yaml`, gated by `supports_vlan_mapping` (or the original non-9000v platform condition). |
| Assert VLAN mapping, one entry, provider VLAN 1100, and dot1q tunnel | Registered exact entry assertions plus persisted REST checks. |
| Re-apply VLAN mapping idempotently and clean it up | Harness idempotency phase and `always` cleanup in the VLAN workflow. |

The original suite has no negative integration workflow. The migration adds
the standard supplemental negative test for a missing `interface_name` and
requires both the validation reason and field name; it does not replace an
original scenario.

### Supplemental IOS-XE coverage in the legacy workflow

The IOS-XE workflow in `tasks/xe.yaml` is supplemental coverage for issue
#537 in the original target's legacy execution block. It is optional there:
`tasks/main.yaml` includes `xe.yaml` only when `nd_test_xe_switch_ip` is
defined and non-empty. When that variable is absent, the legacy target skips
the IOS-XE workflow and still runs its normal non-IOS-XE scenarios.

This IOS-XE workflow is not implemented in the ND4X harness. It is not part
of the original-suite parity mapping above, is not selected by any
`nd4x_demo_*` tag, and is not included in the ND4X execution evidence below.

The optional workflow covers:

- Cleanup of port-channels 103-105 and discovery of the Catalyst switch ID.
- Negative validation when an `iosXeAccess` member is used in an
  `iosXeTrunkPoHost` port-channel, including check mode, normal mode, and
  cleanup back to `iosXeTrunkHost`.
- Merged creation of port-channels 103 and 104, including check mode, normal
  mode, returned discriminator assertions, and idempotency.
- Merged update of port-channel103, including allowed VLANs, BPDU guard,
  description, and idempotency.
- Replaced state for port-channel103 with check-mode, normal-mode, and
  returned-state assertions.
- Overridden state retaining port-channel103 and removing port-channel104,
  including idempotency.
- Deleted state for port-channel103, including check mode, normal mode,
  absence verification, and idempotency.
- Final member cleanup back to the IOS-XE fabric default. Cleanup retries are
  included because the controller can temporarily lag while reporting a
  detached member.

The required IOS-XE variables are:

```ini
nd_test_xe_switch_ip=<Catalyst leaf management IP>
nd_test_xe_fabric_name=<Catalyst fabric; defaults to nd_test_fabric_name>
nd_test_xe_pc_member_a=GigabitEthernet1/0/2
nd_test_xe_pc_member_b=GigabitEthernet1/0/3
nd_test_xe_pc_member_c=GigabitEthernet1/0/4
nd_test_xe_pc_member_d=GigabitEthernet1/0/5
nd_test_xe_pc_member_access=GigabitEthernet1/0/6
```

The Catalyst member ports must exist, must not be fabric-link endpoints, and
must be available for the test. The workflow uses port-channels 103-105 as
reserved test resources and does not set per-port-channel MTU because the
Catalyst 9000v rejects that configuration.

The original normal CRUD tasks omit `config_actions.deploy`, and this module's
default is `deploy: false`. The harness preserves that behavior and validates
the staged ND controller configuration. It does not claim switch-operational
deployment coverage for those normal workflows; explicit `deploy: true`
coverage would be an additional module-suite scenario, not an omitted original
integration scenario.

## Shared harness coverage

Every positive harness invocation uses `cisco.nd.nd4x_module_test` and
provides:

- Predictive check-mode, real apply, and one real idempotency application.
- Expected `changed` and `failed` values for every executed phase.
- A complete interface-collection snapshot for every switch in the fabric
  before and after predictive execution, with only volatile `operData`
  ignored.
- Module-specific assertions against the registered check-mode and
  `first_run_result.after` values.
- Persisted ND REST validation through `nd_queries`.
- Scenario-local prerequisite reconstruction, cleanup re-query validation,
  and guaranteed cleanup in `always` blocks.

The action plugin remains the single implementation of phase sequencing,
snapshot comparison, idempotency enforcement, and REST query expectation
handling. The scenario files retain responsibility for module-specific
fixtures, field assertions, safety, destructive scope, and cleanup.

## Discovery and safety

`nd4x_demo_preflight.yaml` gates on ND 4.0.0 or later, requires explicit
confirmation that port-channels 501-504 and member ports a-d are reserved,
discovers `switchId` from `fabricManagementIp`, builds one predictive snapshot
query per fabric switch, and verifies every reserved member exists as Ethernet.
An existing membership is allowed only when its port-channel ID is one of the
reserved test IDs; unrelated memberships fail before mutation.

The overridden workflow additionally:

- Requires `nd_port_channel_destructive_tests_enabled=true`.
- Discovers all interfaces on every switch.
- Refuses to run if any configured `trunkPoHost` port-channel is outside the
  target switch and port-channel501-504 reserved scope.
- Reconstructs the exact original merged/replaced prerequisite before the
  fabric-wide override.

The safe harness aggregate is selected with `nd4x_demo`. Overridden scenarios
are deliberately excluded and use the separate `nd4x_demo_overridden` and
`nd4x_demo_destructive` tags. All harness includes carry `never` so the
original untagged suite remains the default execution path while parity is
reviewed.

The generic contributor guide describes an aggregate that may include
overridden scenarios, but this target follows the established safe-migration
pattern used by the migrated interface targets: destructive overridden coverage
is selected separately and never runs as part of the safe aggregate.

VLAN mapping is capability-gated because virtual switches commonly reject the
selective dot1q-tunnel configuration. A hardware-backed run must explicitly
set `supports_vlan_mapping=true`; a skipped capability is not treated as a
missing scenario mapping.

Each state-specific harness tag also selects `nd4x_demo_preflight`, so the
controller-version and reserved-resource checks run before the state workflow.
This applies to `nd4x_demo_merged`, `nd4x_demo_replaced`,
`nd4x_demo_deleted`, `nd4x_demo_negative`, `nd4x_demo_vlan_mapping`,
`nd4x_demo_overridden`, and `nd4x_demo_destructive`. A separate preflight tag
is therefore not required when running one of these workflows.

## Run commands

Safe harness scenarios:

```text
ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo -vv
```

Individual safe workflows can also be selected directly:

```text
ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged -vv

ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_replaced -vv

ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_deleted -vv

ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_negative -vv
```

Destructive overridden scenarios:

```text
ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden,nd4x_demo_destructive \
  --allow-destructive -vv
```

Supplemental IOS-XE coverage is selected through the legacy target execution
and the `nd_test_xe_switch_ip` variable; it does not use an ND4X harness tag:

```text
ansible-test network-integration nd_interface_port_channel_trunk_host \
  --inventory /absolute/path/to/inventory.LOCAL.networking \
  -e nd_test_xe_switch_ip=<Catalyst leaf management IP> -vv
```

If `nd_test_xe_switch_ip` is not supplied, the IOS-XE workflow is skipped and
the run does not provide IOS-XE execution evidence.

Required inventory confirmation for the harness is:

```ini
nd_port_channel_reserved_resources_confirmed=true
```

The overridden run additionally requires:

```ini
nd_port_channel_destructive_tests_enabled=true
```

## Execution evidence

Against the same local inventory, fabric, switch set, and ND 4.2.1.10
controller, the unchanged legacy suite passed (`ok=59`, `failed=0`). The
non-destructive harness workflows passed (`ok=69`, `failed=0`), and the
separately opted-in overridden/destructive harness passed (`ok=38`,
`failed=0`). The 9000v VLAN-mapping scenario was skipped by the existing
capability gate in both suites. Offline validation also passed: 292 unit tests,
Python compilation, YAML parsing for 16 target YAML files, and `git diff
--check`.

The original integration files remain enabled; this evidence does not perform
the final suite cutover.
