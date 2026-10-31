# Standalone Ethernet dot1q-tunnel host integration tests

This is the collection integration target for
`cisco.nd.nd_interface_ethernet_dot1q_tunnel_host`. It follows the interface
targets' `tasks/main.yaml`, state task files, `tasks/setup.yaml`, and
`vars/main.yaml` structure. It uses real module calls and independent exact-port
ND GETs; the module's planned `after` value alone is not accepted as readback.

## Testbed and variables

Run against a dedicated NX-OS test fabric on ND **4.2.1** or **4.3.1**. Provide
exactly three existing, unused physical Ethernet ports on one switch. Before
any writes, the target checks the actual ND build, resolves the current switch
ID from a unique management-IP match in the selected fabric, and checks NX-OS
interface identities, down/non-member status,
default `trunkHost` policies with empty descriptions, and the absence of **any**
pre-existing `dot1qTunnelHost` policy anywhere in the fabric. A failed preflight
does not arm cleanup or reset ports. Existing dot1q policies make the suite stop.

The override tests are fabric-wide. The three ports must be reserved for this
run and already reset to fabric defaults; this target returns them to those
defaults, not an arbitrary saved port configuration. Do not use an occupied or
protected shared baseline. No controller addresses, credentials, or usable
physical port selection are supplied by default. Inventory and test variables
must identify the separately authorized testbed when executing later.

Copy `test_vars.yml.template` outside the repository and edit its values.
Supply credentials using your inventory's normal secret mechanism, for example
an Ansible Vault file; do not commit them. The inventory group is `nd`, with
`ansible_connection=ansible.netcommon.httpapi`, `ansible_network_os=cisco.nd.nd`,
SSL settings appropriate to the testbed, and `ansible_host`, `ansible_user`,
and `ansible_password`. Both the direct runner and ansible-test require the
collection's usual Ansible, netcommon, and Pydantic dependencies.
The target explicitly pins both ND modules to `ansible_host`, so an inherited
`ND_HOST` cannot redirect a run to another controller.

| Variable | Purpose |
| --- | --- |
| `nd_test_expected_release` | Required: `4.2.1` or `4.3.1`; compared with `/api/v1/infra/about` buildVersion before writes. |
| `nd_test_fabric_name` | Required dedicated test fabric. |
| `nd_test_switch_ip` | Required management IP; the current switch ID is resolved from fresh fabric inventory before writes. |
| `nd_test_dot1q_interface_names` | Required list of exactly three distinct canonical physical Ethernet names. |
| `nd_test_dot1q_vlan` | Base test service VLAN, default 150; the tests also use VLAN+1 through VLAN+3. |
| `nd_test_deploy` | Default false. True applies the same state suite and cleanup with exact-target deployment enabled. |
| `nd_test_output_level` | Default debug; before/after are asserted and optional logs can aid diagnosis. |
| `nd_test_dot1q_storm_transition` | Optional storm-unit merge regression test, default false; allowed only when deploy=false. |
| `nd_test_verify_cli` | Default false; with deploy=true, verify NX-OS running mode, VLAN, description, and CDP over SSH. Supply `nd_test_switch_username` and `nd_test_switch_password` securely. |
| `nd_test_cli_evidence_file` | Optional controller-local file for credential-free port-only CLI snapshots; mode 0600. |
| `nd_logging_config` | Optional existing collection logging configuration file. |

Provision the test VLANs if switch acceptance requires them. This suite does not
create fabric networks/VLANs or generate traffic. Optional SSH verification
checks selected running configuration as well as ND intent. Traffic forwarding
qualification remains separate.

## Run later

From the collection root, the normal target command is:

```sh
ansible-test network-integration nd_interface_ethernet_dot1q_tunnel_host \
  --inventory /absolute/path/to/inventory.networking --allow-destructive
```

The network alias selects inventory group `nd`. The destructive classification
reflects the real fabric-wide override/reset scenarios. Place test variables
in that inventory's host/group variables. Alternatively,
use the direct runner to supply a separate variables file:

```sh
ansible-playbook \
  -i /absolute/path/to/inventory.networking \
  tests/integration/targets/nd_interface_ethernet_dot1q_tunnel_host/run_tests.yaml \
  -e @/absolute/path/to/dot1q-421.yml
```

Repeat for each matrix entry, with one selected controller host per run:

| ND release | `nd_test_deploy` | Expected coverage |
| --- | --- | --- |
| 4.2.1 | false | Staged CRUD/reconciliation, all four states, check mode, readback, explicit description clearing, idempotency, negatives and cleanup. |
| 4.2.1 | true | Same suite with module-driven deployment enabled. |
| 4.3.1 | false | Same staging suite, including the empty-description compatibility path. |
| 4.3.1 | true | Same suite with module-driven deployment enabled. |

Do not run the whole playbook with `--check`: each scenario has its own
check-mode phase followed by actual setup/mutation/replay. The outer invocation
requires normal mode. The runner uses `serial: 1`; select one host explicitly
when an inventory contains more than one controller.

## Coverage

- `merged`: single and grouped creates, multiple config groups, partial update
  preserving omitted nondefault fields, normal/check-mode no-op replay.
- Empty-description clear: ordinary and check-mode clear, actual ND readback,
  unchanged other fields, empty/omitted GET echo replay on both release paths.
- `replaced`: omitted CDP, BPDU guard, and MTU reset to template defaults;
  unnamed hosts survive; normal/check-mode replay.
- `overridden`: two retained hosts and an omitted physical reset, idempotency,
  explicit top-level `config: []` reset-all and no-op replay.
- `deleted`: identifier-only single/grouped reset, retained-host preservation,
  physical default policy readback, repeated deletion as a no-op.
- Check-mode creates, updates, replacement, override and deletion compare fresh
  exact-port configData before and after to prove no intent changed.
- Negative cases: IOS-XE, foreign policy, unsupported monitor, mixed storm units,
  and named-empty overridden groups in ordinary/check mode. Every rejection
  must contain the expected diagnostic and leave all reserved policies unchanged.
- An `always` block performs named-only cleanup after a partially successful
  write or test failure, verifies all three physical ports are default trunks,
  and requires no remaining managed dot1q hosts. Cleanup failure is a test
  failure; it is not silently ignored. Initial preflight failures do not clean.

## Storm-control merge regression

Set `nd_test_dot1q_storm_transition=true` with `nd_test_deploy=false` to check
clearing a unicast percentage limit and setting broadcast PPS in one `merged`
request. The case seeds a percentage policy on ND, previews the transition in
check mode, proves that preview changed no intent, then stages the completed
merge without deployment. Independent GETs verify the cleared percentage and
new PPS limit, and replay must be a no-op. Cleanup returns the reserved ports
to defaults. No unit-family transition is deployed. Safe physical unit
transitions remain separately tracked by issue #533; this case does not
qualify them.

ND 4.2.1 ordinary empty-description clearing was previously unqualified live.
It is deliberately tested rather than skipped or treated as an expected error.
Real mixed-success HTTP 207 and deployment isolation require a controlled fault
scenario; existing unit tests cover synthetic partial outcomes. This target
does not fabricate a controller failure or mutate port-channel/vPC members.

Live qualification results are recorded separately from these reusable test
definitions; a passing local syntax check alone is not a live qualification.
