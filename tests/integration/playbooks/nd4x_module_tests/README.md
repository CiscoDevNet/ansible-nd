# ND 4.x Module Integration Test Framework Contributor Guide

## Purpose

The ND 4.x module integration-test framework provides a consistent execution pattern for testing Cisco Nexus Dashboard modules.

The framework standardizes:

- Predictive check-mode execution.
- Controller-state verification around predictive execution.
- Real configuration application.
- Idempotency validation.
- Post-apply REST validation.
- Phase-result reporting.
- Common validation and failure handling.

The framework does not replace module-specific test design. Contributors remain responsible for setup, cleanup, safety checks, module-specific assertions, negative tests, tags, and confirming coverage parity with the original integration suite.

## Authoritative implementation

The shared execution logic is implemented by:

```text
plugins/action/nd4x_module_test.py
```

The documentation-only module containing the concise Ansible interface is:

```text
plugins/modules/nd4x_module_test.py
```

Runnable integration scenarios are target-local and must live under:

```text
tests/integration/targets/<module_name>/
```

Examples:

```text
tests/integration/targets/nd_interface_loopback/
tests/integration/targets/nd_interface_ethernet_access/
```

The hierarchy under:

```text
tests/integration/playbooks/nd4x_module_tests/
```

contains this contributor guide and reusable examples. It is not a second source of runnable integration scenarios.

Do not maintain duplicate executable scenarios under both `playbooks/` and `targets/`. The target-local hierarchy is authoritative because `ansible-test network-integration` packages and executes integration targets from `tests/integration/targets/`.

## Responsibility split

### Responsibilities handled by the action plugin

The `cisco.nd.nd4x_module_test` action plugin handles:

- Validating supported top-level arguments.
- Rejecting unknown arguments.
- Validating nested expectation and query structures.
- Combining common and module-specific arguments.
- Passing `state` and `config` to the target module.
- Running the target module in predictive check mode.
- Capturing configured controller state before predictive execution.
- Capturing the same controller state after predictive execution.
- Normalizing and comparing the before and after snapshots.
- Preventing real apply when predictive execution changed controller state.
- Checking expected `changed` and `failed` values for each phase.
- Running the first real apply exactly once.
- Running one additional real application for idempotency.
- Automatically requiring the idempotency execution to report `changed: false`.
- Running configured post-apply ND REST validation queries.
- Restoring the original Ansible check-mode state after success or failure.
- Returning individual phase results to the calling playbook.

### Responsibilities that remain in the module scenario

The module-specific integration scenario must handle:

- ND-version discovery and gating.
- Fabric and resource prerequisites.
- Resolving current controller identifiers.
- Establishing a known pre-test state.
- Creating prerequisite resources.
- Selecting safe, reserved test resources.
- Module-specific returned-field assertions.
- Negative tests and exact failure-reason assertions.
- Destructive-test opt-in and scope preflight.
- Cleanup under `block`/`always`.
- Scenario and execution tags.
- Confirming coverage parity with the original integration suite.

The harness does not automatically perform setup, feature-specific assertions, safety preflight, version gating, identifier discovery, or cleanup.

## Normal execution lifecycle

During normal execution, the following sequence is used:

```text
module-specific setup
        ↓
GET configured check_mode_queries state
        ↓
run target module in predictive check mode
        ↓
GET the same controller state
        ↓
normalize and compare before == after
        ↓
validate predictive phase expectations
        ↓
run the first real apply
        ↓
validate apply expectations
        ↓
run one real idempotency application
        ↓
require changed == false
        ↓
run post-apply nd_queries
        ↓
module-specific assertions
        ↓
cleanup under always
```

Important behavior:

- A controller snapshot difference prevents the real apply.
- A predictive phase expectation failure prevents the real apply.
- An apply failure prevents idempotency and post-apply REST validation.
- Post-apply `nd_queries` run after idempotency.
- Cleanup is not performed by the harness.
- Cleanup must be implemented by the module scenario under `always`.

## Check-mode state restoration

The harness records the task's original check-mode value before execution and restores it after success or failure.

Snapshot GET operations temporarily disable task check mode because `cisco.nd.nd_rest` does not perform a real HTTP request while operating in check mode.

The snapshot operation:

- Temporarily disables task check mode.
- Performs a read-only GET.
- Restores the previous task check-mode value.
- Never changes the target module's intended predictive execution mode.

The original task check-mode state is restored before the action plugin returns or raises an error.

## Argument validation behavior

The harness validates its public input contract before executing the target module.

Unknown top-level arguments are rejected. Unknown nested keys are also rejected in:

- `expected`
- `expected.<phase>`
- `check_mode_queries`
- `nd_queries`
- `nd_queries.expect`

Boolean arguments accept:

- Boolean values: `true` and `false`
- Integer values: `1` and `0`
- Strings: `true`, `false`, `yes`, `no`, `on`, `off`, `1`, and `0`

String Boolean values are case-insensitive.

Invalid Boolean or integer values fail before the target module is executed.

The following arguments must be dictionaries:

- `common_args`
- `module_args`
- `expected`

The following arguments must be lists:

- `check_mode_queries`
- `nd_queries`

## Top-level input contract

### `module`

Required string containing the fully qualified target module name.

```yaml
module: cisco.nd.nd_interface_loopback
```

### `state`

Required string passed to the target module.

```yaml
state: merged
```

The harness does not restrict the state value. The target module determines which states it supports.

Common resource-module states include:

- `merged`
- `replaced`
- `overridden`
- `deleted`

### `config`

Optional raw configuration passed to the target module.

```yaml
config:
  - switch_ip: "{{ test_switch_ip }}"
    interface_name: loopback100
    config_data:
      network_os:
        policy:
          ip: 10.100.100.1
```

Whether `config` is required depends on the target module and state.

If `config` is omitted, the harness does not add a `config` argument to the target module invocation.

### `common_args`

Optional dictionary containing arguments shared across scenarios.

Default:

```yaml
common_args: {}
```

Example:

```yaml
common_args:
  fabric_name: "{{ test_fabric_name }}"
  output_level: "{{ nd_info.output_level }}"
  timeout: 300
```

### `module_args`

Optional dictionary containing arguments specific to the target module or scenario.

Default:

```yaml
module_args: {}
```

Example:

```yaml
module_args:
  deploy: false
```

Argument precedence is:

```text
common_args
    ↓ overridden by
module_args
    ↓ overridden by
harness-supplied state and config
```

Do not place `state` or `config` inside `common_args` or `module_args`.

### `expected`

Optional dictionary containing expectations for execution phases.

Default:

```yaml
expected: {}
```

Supported phase names are:

- `check_mode`
- `apply`
- `idempotency`

Each phase supports:

- `changed`
- `failed`

Complete example:

```yaml
expected:
  check_mode:
    changed: true
    failed: false
  apply:
    changed: true
    failed: false
  idempotency:
    changed: false
    failed: false
```

Rules:

- `failed` defaults to `false` for an executed check-mode phase.
- `failed` defaults to `false` for the real apply.
- `changed` is checked only when explicitly provided.
- When idempotency is enabled, `changed: false` is required automatically.
- When idempotency is enabled, `failed` defaults to `false`.
- `expected.idempotency.changed: true` is rejected.
- Unknown phase names are rejected.
- Unknown expectation keys are rejected.

### `check_mode`

Controls the internal predictive execution.

Default:

```yaml
check_mode: true
```

When `check_mode: true`:

- The internal predictive phase executes before real apply.
- Configured `check_mode_queries` execute around the predictive phase.
- Predictive expectations are checked before real apply.

When `check_mode: false`:

- The internal predictive phase is skipped.
- `check_mode_queries` must be empty.
- Real apply still executes.
- Optional idempotency still executes.

When Ansible itself runs globally in check mode:

- The predictive phase executes regardless of the internal `check_mode` argument.
- Configured `check_mode_queries` execute.
- Real apply is skipped.
- Idempotency is skipped.
- Post-apply `nd_queries` are skipped.
- The harness returns the predictive result.

The normal `ansible-test network-integration` command does not expose a global `--check` option. Normal harness execution already performs its internal predictive phase.

### `check_mode_queries`

Optional list of read-only REST queries used to prove that predictive execution did not mutate controller state.

Default:

```yaml
check_mode_queries: []
```

Example:

```yaml
check_mode_queries:
  - name: Snapshot all managed interfaces on test switch
    path: >-
      /api/v1/manage/fabrics/{{ test_fabric_name
      }}/switches/{{ test_switch_id }}/interfaces
    expected_status: 200
    unordered: true
    ignore_keys:
      - operData
```

Each query supports:

| Field | Required | Default | Description |
|---|---:|---|---|
| `name` | No | Query path | Human-readable query name |
| `path` | Yes | None | ND REST API path |
| `expected_status` | No | `200` | Required HTTP response status |
| `unordered` | No | `false` | Treat lists as unordered during normalization |
| `ignore_keys` | No | `[]` | Dictionary keys removed recursively before comparison |

Check-mode snapshot queries always use GET. A method cannot be supplied.

The harness performs:

```text
GET path
        ↓
run target module in check mode
        ↓
GET the same path
        ↓
normalize both responses
        ↓
compare both responses
```

If the normalized responses differ, the harness fails and does not execute the real apply.

### Selecting snapshot scope

The snapshot must cover every resource that the target module could unintentionally modify.

For an interface module, query the full managed-interface collection for the test switch:

```yaml
path: >-
  /api/v1/manage/fabrics/{{ test_fabric_name
  }}/switches/{{ test_switch_id }}/interfaces
```

Do not snapshot only the requested interface. A module defect could mutate another interface.

For a fabric-wide operation, select a scope wide enough to detect unintended changes to every resource managed by that operation.

### Snapshot normalization

The harness recursively:

- Sorts dictionary keys.
- Normalizes nested dictionaries and lists.
- Optionally sorts normalized list values.
- Removes explicitly configured ignored dictionary keys.

Use:

```yaml
unordered: true
```

when the controller does not guarantee list ordering.

Use `ignore_keys` only for fields known to be volatile and unrelated to managed configuration.

Example:

```yaml
ignore_keys:
  - operData
```

Do not ignore:

- `configData`
- Resource names
- Resource identifiers
- Resource membership
- Desired policy values
- Any field managed by the target module

A genuine change to managed configuration must continue to fail snapshot comparison.

### Snapshot behavior after predictive errors

The after-snapshot query executes even when the target module raises an exception during predictive execution.

The sequence remains:

```text
capture before snapshot
        ↓
attempt predictive target execution
        ↓
capture after snapshot in all cases
        ↓
compare snapshots
```

If predictive execution raises and the snapshots are unchanged, the original target-module exception is propagated.

If controller state also changed, the snapshot mutation failure prevents real apply and reports the controller-state difference.

### Snapshot difference diagnostics

When normalized controller state differs, the harness reports:

- The snapshot query name.
- Confirmation that real apply was not executed.
- The JSON path of the first detected difference.
- The normalized before value.
- The normalized after value.

Large values are truncated to keep failure output readable.

Use the diagnostic to distinguish:

- Genuine managed-configuration mutations.
- Unexpected resource additions or removals.
- Incorrect snapshot scope.
- Volatile fields that require a narrowly scoped `ignore_keys` entry.
- Unrelated concurrent controller changes.

Do not add an ignored key until the reported difference is confirmed to be operational and unrelated to managed configuration.

### `idempotency`

Controls whether the harness performs one additional real application.

Default:

```yaml
idempotency: true
```

When enabled:

- The target module is executed once after the initial real apply.
- The second execution must report `changed: false`.
- The second execution must not fail.
- `idempotency_attempts` is returned as `1`.

When disabled:

```yaml
idempotency: false
```

the second real execution is skipped and `idempotency_attempts` is returned as `0`.

### `idempotency_retries`

Legacy compatibility option.

The only supported value is:

```yaml
idempotency_retries: 1
```

The harness performs exactly one idempotency execution and does not retry module application.

Any value other than `1` is rejected.

### `idempotency_delay`

Legacy compatibility option.

The only supported value is:

```yaml
idempotency_delay: 0
```

The harness does not delay or poll between idempotency applications.

Any value other than `0` is rejected.

### `nd_queries`

Optional list of REST validation queries executed after successful apply and idempotency phases.

Default:

```yaml
nd_queries: []
```

Example:

```yaml
nd_queries:
  - name: Validate loopback100
    path: >-
      /api/v1/manage/fabrics/{{ test_fabric_name
      }}/switches/{{ test_switch_id }}/interfaces/loopback100
    method: get
    expected_status: 200
    expected_failed: false
    expect:
      - jsonpath: "$.current.interfaceName"
        equals: loopback100
      - jsonpath: "$.current.configData.networkOS.policy.ip"
        equals: 10.100.100.1
```

Each query supports:

| Field | Required | Default | Description |
|---|---:|---|---|
| `name` | No | Query path | Human-readable query name |
| `path` | Yes | None | Templated ND REST API path |
| `method` | No | `get` | HTTP method passed to `nd_rest` |
| `expected_status` | No | No status assertion | Expected HTTP status |
| `expected_failed` | No | `false` | Expected Ansible failure value |
| `expect` | No | `[]` | JSONPath expectations |

The underlying `nd_rest` module supports:

- `get`
- `post`
- `put`
- `patch`
- `delete`

Post-apply validation should normally use GET. Do not use a mutating method for ordinary state validation.

### JSONPath expectations

Each expectation requires:

```yaml
jsonpath: "$.current.exampleField"
```

It can additionally contain:

```yaml
exists: true
```

or:

```yaml
equals: expected-value
```

Both can be used together:

```yaml
expect:
  - jsonpath: "$.current.exampleField"
    exists: true
    equals: expected-value
```

`equals` compares the first value matched by the JSONPath expression.

At least one of `exists` or `equals` should be supplied. A JSONPath expression without an assertion does not prove expected state.

### JSONPath dependency

JSONPath validation requires the `jsonpath-ng` Python library.

If `nd_queries.expect` uses JSONPath and `jsonpath-ng` is unavailable, the harness fails with a clear dependency error.

Snapshot normalization and comparison do not require JSONPath.

### Expected absence

For an endpoint that reports a missing resource as an Ansible failure:

```yaml
nd_queries:
  - name: Verify resource is absent
    path: "/api/v1/example/missing-resource"
    method: get
    expected_status: 404
    expected_failed: true
```

JSONPath expectations are skipped when `expected_failed: true`.

If the failure message is significant, add a module-specific assertion against the returned query result.

## Phase-skipping behavior

### Predictive phase disabled

When:

```yaml
check_mode: false
```

the predictive target execution and associated snapshot queries are skipped.

### Global Ansible check mode

During global check mode:

- Predictive execution runs.
- Snapshot queries run.
- Predictive expectations are validated.
- Real apply does not run.
- Idempotency does not run.
- Post-apply REST validation does not run.

### Apply failure

When the real apply returns `failed: true`:

- The result is validated against `expected.apply.failed`.
- Idempotency is skipped.
- Post-apply `nd_queries` are skipped.
- The result remains available as `first_run_result`.

### Idempotency disabled

When:

```yaml
idempotency: false
```

the second real application is skipped.

### Expected predictive failure

When predictive execution returns `failed: true` and the scenario expects:

```yaml
expected:
  check_mode:
    failed: true
```

the expectation itself passes.

During normal non-global execution, an expected predictive failure does not automatically skip the real apply. Avoid this pattern unless applying after the predictive failure is intentionally part of the test.

For a negative test that only validates predictive failure, prefer a direct target-module task with:

```yaml
check_mode: true
```

and assert the exact failure reason.

## Result contract

Register the harness result:

```yaml
register: scenario_result
```

The result contains:

| Field | Description |
|---|---|
| `changed` | Apply result during normal execution or predictive result during global check mode |
| `check_mode_result` | Target-module predictive result |
| `check_mode_query_results` | Snapshot comparison results |
| `first_run_result` | First real apply result |
| `second_run_result` | Idempotency result |
| `idempotency_attempts` | Number of idempotency executions: `0` or `1` |
| `nd_query_results` | Post-apply REST query results |

Values for skipped phases are returned as `null` or empty collections as appropriate.

### Top-level `changed`

During normal execution, the top-level `changed` value reflects the first real apply result.

During global Ansible check mode, the top-level `changed` value reflects the predictive result because no real apply executes.

### Example phase assertions

```yaml
- name: Verify harness phases
  ansible.builtin.assert:
    that:
      - scenario_result.check_mode_result.changed | bool
      - scenario_result.first_run_result.changed | bool
      - scenario_result.idempotency_attempts == 1
      - scenario_result.second_run_result.changed == false
      - scenario_result.second_run_result.failed
        | default(false)
        | bool == false
      - scenario_result.check_mode_query_results | length == 1
      - scenario_result.check_mode_query_results[0].unchanged | bool
```

The harness validates common phase behavior. The scenario must still assert important module-specific fields.

## Canonical target structure

A migrated target should use:

```text
tests/integration/targets/<module_name>/
├── tasks/
│   ├── main.yaml
│   ├── setup.yaml
│   ├── nd4x_demo_merged.yaml
│   ├── nd4x_demo_replaced.yaml
│   ├── nd4x_demo_deleted.yaml
│   └── nd4x_demo_overridden.yaml
└── vars/
    └── main.yaml
```

Add separate files for meaningful module-specific scenarios:

```text
tasks/nd4x_demo_merged_fanout.yaml
tasks/nd4x_demo_split_config.yaml
tasks/nd4x_demo_negative.yaml
```

Do not force unrelated workflows into one large state file. Use one file per state or independently executable scenario.

## Registering scenarios in `tasks/main.yaml`

Harness scenarios are opt-in during migration and must use `never`.

Example:

```yaml
- name: Run merged state using the ND 4.x test harness
  ansible.builtin.include_tasks:
    file: nd4x_demo_merged.yaml
    apply:
      tags:
        - never
        - nd4x_demo
        - nd4x_demo_merged
  tags:
    - never
    - nd4x_demo
    - nd4x_demo_merged
  when: nd4x_supported | bool
```

Tags must be present:

- On the `include_tasks` task so Ansible selects the dynamic include.
- Under `apply.tags` so included tasks inherit the execution tags.

## Required preflight discovery

### ND-version gating

Query the running Nexus Dashboard version:

```yaml
- name: Query Nexus Dashboard version
  cisco.nd.nd_version:
  register: nd4x_version
  tags:
    - always

- name: Record whether ND 4.x tests are supported
  ansible.builtin.set_fact:
    nd4x_supported: >-
      {{
        nd4x_version.current.platformVersion
        is version('4.0.0', '>=')
      }}
  tags:
    - always
```

Apply the gate only to ND 4.x harness includes:

```yaml
when: nd4x_supported | bool
```

Do not silently run an ND 4.x-only scenario against an older controller.

If the module requires a later minimum version, use that actual version instead of `4.0.0`.

### Dynamic switch-ID resolution

A switch management IP and switch ID represent the same controller object. They must not be maintained as independent inventory values.

Use the switch's `fabricManagementIp` as the source of truth and resolve the current `switchId` from the controller.

```yaml
- name: Query switches in the test fabric
  cisco.nd.nd_rest:
    path: "/api/v1/manage/fabrics/{{ test_fabric_name }}/switches"
    method: get
  register: nd4x_switch_inventory
  changed_when: false
  tags:
    - always

- name: Select the switch matching the configured management IP
  ansible.builtin.set_fact:
    nd4x_switch_matches: >-
      {{
        nd4x_switch_inventory.current.switches
        | default([])
        | selectattr(
            'fabricManagementIp',
            'equalto',
            test_switch_ip
          )
        | list
      }}
  tags:
    - always

- name: Require exactly one matching fabric switch
  ansible.builtin.assert:
    that:
      - nd4x_switch_matches | length == 1
    fail_msg: >-
      Expected exactly one switch with fabricManagementIp
      {{ test_switch_ip }} in fabric {{ test_fabric_name }},
      but found {{ nd4x_switch_matches | length }}.
  tags:
    - always

- name: Record the current switch ID
  ansible.builtin.set_fact:
    test_switch_id: "{{ nd4x_switch_matches[0].switchId }}"
  tags:
    - always
```

Use the resolved `test_switch_id` in REST paths.

Do not require contributors to manually keep a management IP and switch ID synchronized.

## Copyable scenario template

```yaml
---
- name: Run standardized example-module merged scenario
  block:
    - name: "MERGED SETUP: Establish a clean baseline"
      cisco.nd.example_module:
        fabric_name: "{{ test_fabric_name }}"
        config:
          - "{{ example_cleanup_config }}"
        state: deleted

    - name: "MERGED APPLY: Run module through the shared harness"
      cisco.nd.nd4x_module_test:
        module: cisco.nd.example_module
        state: merged

        common_args:
          fabric_name: "{{ test_fabric_name }}"
          output_level: "{{ nd_info.output_level }}"
          timeout: 300

        module_args: {}

        config:
          - "{{ example_config }}"

        expected:
          check_mode:
            changed: true
            failed: false
          apply:
            changed: true
            failed: false
          idempotency:
            changed: false
            failed: false

        check_mode_queries:
          - name: Snapshot all relevant managed resources
            path: >-
              /api/v1/manage/fabrics/{{ test_fabric_name
              }}/switches/{{ test_switch_id }}/resources
            expected_status: 200
            unordered: true
            ignore_keys:
              - operData

        nd_queries:
          - name: Validate the created resource
            path: >-
              /api/v1/manage/fabrics/{{ test_fabric_name
              }}/switches/{{ test_switch_id }}/resources/example
            method: get
            expected_status: 200
            expected_failed: false
            expect:
              - jsonpath: "$.current.name"
                equals: example

      register: merged_result

    - name: "MERGED VERIFY: Validate module-specific output"
      ansible.builtin.assert:
        that:
          - merged_result.first_run_result.after | length == 1
          - merged_result.idempotency_attempts == 1
          - merged_result.second_run_result.changed == false
          - merged_result.check_mode_query_results[0].unchanged | bool

  always:
    - name: "MERGED CLEANUP: Remove the test resource"
      cisco.nd.example_module:
        fabric_name: "{{ test_fabric_name }}"
        config:
          - "{{ example_cleanup_config }}"
        state: deleted
      tags:
        - always
```

Replace the example endpoint, configuration, and assertions with module-specific values.

## Scenario patterns

### Simple create scenario

Use this pattern for a basic `merged` test:

1. Remove the reserved test resource.
2. Run the harness with `state: merged`.
3. Expect check mode and apply to report `changed: true`.
4. Expect idempotency to report `changed: false`.
5. Validate the resource using `nd_queries`.
6. Assert important fields from `first_run_result.after`.
7. Remove the resource under `always`.

### Simple delete scenario

Use this pattern for a `deleted` test:

1. Create the prerequisite resource.
2. Verify that the prerequisite exists.
3. Run the harness with `state: deleted`.
4. Expect check mode and apply to report `changed: true`.
5. Expect idempotency to report `changed: false`.
6. Query the resource endpoint and expect absence.
7. Run idempotent cleanup under `always`.

### Create-to-update workflow

Use this pattern for `merged` updates or `replaced`:

1. Create the original resource using a setup task.
2. Verify that setup succeeded.
3. Run the updated configuration through the harness.
4. Validate every field expected to change.
5. Validate important fields expected to remain unchanged.
6. Assert idempotency.
7. Restore or delete the resource under `always`.

Each state transition being evaluated should have its own harness execution. Prerequisite setup may use the target module directly.

### Multi-step create → update → delete workflow

Use a multi-step workflow when the original integration suite verifies the complete lifecycle of the same resource.

The scenario should execute each meaningful transition separately:

1. Establish a clean baseline.
2. Run `state: merged` through the harness to create the resource.
3. Assert the created module result and controller REST state.
4. Run `state: replaced` or an updating `state: merged` through the harness.
5. Assert the updated fields and fields expected to remain unchanged.
6. Run `state: deleted` through the harness.
7. Assert that the resource is absent from the module result and controller REST API.
8. Retain idempotent cleanup under `always` in case an intermediate step fails.

Each create, update, and delete transition should have its own harness call so that predictive check mode, controller-state snapshots, apply expectations, idempotency, and REST validation are verified independently.

Example structure:

```yaml
- name: Test complete resource lifecycle
  block:
    - name: "CREATE: Run merged state through the harness"
      cisco.nd.nd4x_module_test:
        module: cisco.nd.example_module
        state: merged
        common_args: "{{ example_common_args }}"
        config: "{{ example_create_config }}"
        expected: "{{ create_expectations }}"
        check_mode_queries: "{{ example_snapshot_queries }}"
        nd_queries: "{{ create_validation_queries }}"
      register: create_result

    - name: "CREATE VERIFY: Validate the created resource"
      ansible.builtin.assert:
        that:
          - create_result.first_run_result.changed | bool
          - create_result.second_run_result.changed == false

    - name: "UPDATE: Run replaced state through the harness"
      cisco.nd.nd4x_module_test:
        module: cisco.nd.example_module
        state: replaced
        common_args: "{{ example_common_args }}"
        config: "{{ example_updated_config }}"
        expected: "{{ update_expectations }}"
        check_mode_queries: "{{ example_snapshot_queries }}"
        nd_queries: "{{ update_validation_queries }}"
      register: update_result

    - name: "UPDATE VERIFY: Validate updated module fields"
      ansible.builtin.assert:
        that:
          - update_result.first_run_result.changed | bool
          - update_result.second_run_result.changed == false

    - name: "DELETE: Run deleted state through the harness"
      cisco.nd.nd4x_module_test:
        module: cisco.nd.example_module
        state: deleted
        common_args: "{{ example_common_args }}"
        config: "{{ example_delete_config }}"
        expected: "{{ delete_expectations }}"
        check_mode_queries: "{{ example_snapshot_queries }}"
        nd_queries: "{{ delete_validation_queries }}"
      register: delete_result

    - name: "DELETE VERIFY: Validate resource removal"
      ansible.builtin.assert:
        that:
          - delete_result.first_run_result.changed | bool
          - delete_result.second_run_result.changed == false

  always:
    - name: "CLEANUP: Ensure the test resource is absent"
      cisco.nd.example_module:
        fabric_name: "{{ test_fabric_name }}"
        config: "{{ example_delete_config }}"
        state: deleted
      tags:
        - always
```

### Multi-resource scenario

Pass multiple configurations when the target module supports bulk operations:

```yaml
config:
  - "{{ resource_1 }}"
  - "{{ resource_2 }}"
  - "{{ resource_3 }}"
```

Assertions must verify every intended resource. Do not validate only the first resource.

The check-mode snapshot must cover the complete managed collection affected by the operation.

### Fan-out scenario

For modules that accept one configuration applied to multiple resources:

```yaml
config:
  - switch_ip: "{{ test_switch_ip }}"
    interface_names:
      - Ethernet1/42
      - Ethernet1/43
    config_data:
      network_os:
        policy:
          access_vlan: 200
```

Validate every expanded resource independently.

A successful result for one interface does not prove that every fan-out target was handled correctly.

### Split-configuration scenario

For modules that accept multiple entries with different configurations:

```yaml
config:
  - switch_ip: "{{ test_switch_ip }}"
    interface_names:
      - Ethernet1/49
    config_data:
      network_os:
        policy:
          access_vlan: 500

  - switch_ip: "{{ test_switch_ip }}"
    interface_names:
      - Ethernet1/50
    config_data:
      network_os:
        policy:
          access_vlan: 600
```

Verify that each resource received its corresponding configuration and that values were not incorrectly shared between entries.

### Module-specific options

Pass target-module options through `module_args`.

Example:

```yaml
module_args:
  deploy: false
```

Do not add module-specific behavior to the shared action plugin unless it is genuinely common to the framework.

## Safety and lifecycle requirements

### Reserved test resources

Each target must define a reserved test scope.

Examples:

```text
loopback100 through loopback109
Ethernet1/41 through Ethernet1/50
```

The reserved range must:

- Be documented in `vars/main.yaml`.
- Be restricted to a dedicated test environment.
- Avoid production or shared-lab resources.
- Be used consistently by setup and cleanup.

### Pre-test cleanup

Every scenario should begin from a known baseline.

Pre-test cleanup must:

- Target only reserved resources.
- Be safe when the resource does not exist.
- Avoid modifying unrelated controller state.
- Run before the harness operation whose behavior is being tested.

### Cleanup under `always`

Every mutating scenario must use:

```yaml
block:
  # setup, harness execution, and assertions

always:
  # cleanup
```

This ensures cleanup is attempted when:

- Setup partially succeeds.
- Predictive expectations fail.
- Snapshot comparison fails.
- Real apply fails.
- Idempotency fails.
- REST validation fails.
- A module-specific assertion fails.

Cleanup must itself be idempotent.

Use the reserved Ansible `always` tag on cleanup when fine-grained tag execution could otherwise skip it.

### Destructive-test opt-in

A destructive scenario must default to disabled.

Example:

```yaml
nd4x_example_destructive_tests_enabled: >-
  {{
    nd_example_destructive_tests_enabled
    | default(false)
    | bool
  }}
```

Require explicit opt-in:

```yaml
- name: Require destructive-test opt-in
  ansible.builtin.assert:
    that:
      - nd4x_example_destructive_tests_enabled | bool
    fail_msg: >-
      This scenario can modify resources outside the requested configuration.
      Run it only on a dedicated test fabric and set
      nd_example_destructive_tests_enabled=true.
```

Never commit the opt-in as `true`.

### Destructive scope preflight

Before an `overridden` or fabric-wide operation:

1. Run the target module in check mode.
2. Register the existing managed-resource state.
3. Identify resources outside the reserved range.
4. Identify resources on switches outside the test switch.
5. Fail before real apply if unsafe resources exist.

Example structure:

```yaml
- name: Inspect destructive operation scope
  cisco.nd.example_module:
    fabric_name: "{{ test_fabric_name }}"
    config: "{{ desired_config }}"
    state: overridden
  check_mode: true
  changed_when: false
  register: destructive_scope_probe

- name: Reject resources outside the reserved scope
  ansible.builtin.assert:
    that:
      - unsafe_resources | length == 0
    fail_msg: >-
      Unsafe destructive testbed. Managed resources were found outside
      the reserved integration-test scope. No override was applied.
```

The safety preflight does not replace `check_mode_queries`.

The preflight verifies whether the test is safe to run. The snapshot queries prove that the target module did not mutate controller state during predictive execution.

## Assertions

### Phase assertions

The harness performs common phase assertions using `expected`.

A positive mutating scenario should normally specify:

```yaml
expected:
  check_mode:
    changed: true
    failed: false
  apply:
    changed: true
    failed: false
  idempotency:
    changed: false
    failed: false
```

A no-change scenario should expect the appropriate phase to report `changed: false`.

### Module-specific assertions

After the harness task, validate meaningful returned data.

Example:

```yaml
- name: Verify resulting interface configuration
  vars:
    interface_after: >-
      {{
        merged_result.first_run_result.after
        | selectattr(
            'interface_name',
            'equalto',
            'Ethernet1/41'
          )
        | first
      }}
  ansible.builtin.assert:
    that:
      - interface_after.config_data.network_os.policy.access_vlan == 100
      - interface_after.config_data.network_os.policy.description
        == "Ansible integration test"
```

Do not rely only on `changed: true`. Verify that the intended resource and fields changed.

### REST assertions

Use `nd_queries` to validate the controller's persisted state independently from the module's returned `after` value.

A complete positive scenario should normally validate both:

- The target module's returned state.
- The controller REST API state.

## Negative tests

This expectation alone is insufficient:

```yaml
expected:
  apply:
    failed: true
```

It proves only that some failure occurred.

A negative test must verify the intended failure reason.

```yaml
- name: Run expected negative scenario
  cisco.nd.nd4x_module_test:
    module: cisco.nd.example_module
    state: merged
    check_mode: false
    idempotency: false

    common_args:
      fabric_name: "{{ test_fabric_name }}"

    config:
      - "{{ invalid_config }}"

    expected:
      apply:
        changed: false
        failed: true

  register: negative_result

- name: Verify the intended failure reason
  ansible.builtin.assert:
    that:
      - negative_result.first_run_result.failed | bool
      - negative_result.first_run_result.msg
        is search("expected specific failure text")
```

Use `check_mode: false` for an apply-specific negative test unless the scenario intentionally tests predictive failure behavior.

Do not configure `check_mode_queries` when `check_mode: false`.

For predictive negative tests, a direct target-module task with `check_mode: true` may provide a clearer and safer assertion flow.

### Expected phase failures

When apply returns `failed: true`:

- The result is checked against `expected.apply.failed`.
- Idempotency is not executed.
- Post-apply `nd_queries` are not executed.
- The result remains available as `first_run_result`.

A matching `failed: true` expectation does not verify why the module failed. The scenario must separately assert the expected message or structured error field.

## Tags

### Default execution

Harness scenarios use `never` so they do not replace the original suite until migration parity has been approved.

Running the target without harness tags executes the original suite:

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  -vv
```

### Aggregate tag

The current aggregate tag is:

```text
nd4x_demo
```

It runs all migrated scenarios, including `overridden`.

Because `overridden` is destructive, the complete aggregate requires:

- A dedicated test fabric.
- The applicable destructive-test opt-in.
- A successful destructive scope preflight.

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  -vv
```

### Safe aggregate execution

Run all non-destructive migrated scenarios with:

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  --skip-tags nd4x_demo_overridden \
  -vv
```

This is the recommended aggregate command for ordinary development.

### State-specific tags

Supported state-specific tags include:

```text
nd4x_demo_merged
nd4x_demo_replaced
nd4x_demo_deleted
nd4x_demo_overridden
```

Example:

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_replaced \
  -vv
```

`nd4x_demo_overridden` is destructive and requires explicit opt-in.

### Fine-grained scenario tags

Use a distinct tag for an independently useful scenario.

Example:

```text
nd4x_demo_merged_fanout
```

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged_fanout \
  -vv
```

For dynamically included tasks, every fine-grained tag must be present on the `include_tasks` task. Otherwise, Ansible will not load the included file when that tag is selected.

Ensure cleanup remains selected for every mutating fine-grained execution.

## Exact commands for current migrated targets

Replace `/absolute/path/to/inventory.networking` with an absolute local inventory path.

Never commit live controller credentials or destructive opt-ins.

### Loopback safe aggregate

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  --skip-tags nd4x_demo_overridden \
  -vv
```

### Loopback merged

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged \
  -vv
```

### Loopback replaced

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_replaced \
  -vv
```

### Loopback deleted

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_deleted \
  -vv
```

### Loopback overridden

```bash
ansible-test network-integration nd_interface_loopback \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden \
  -vv
```

### Ethernet-access safe aggregate

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  --skip-tags nd4x_demo_overridden \
  -vv
```

### Ethernet-access merged

The merged state tag also includes the fan-out scenario:

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged \
  -vv
```

### Ethernet-access basic merged without fan-out

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged \
  --skip-tags nd4x_demo_merged_fanout \
  -vv
```

### Ethernet-access fan-out only

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_merged_fanout \
  -vv
```

### Ethernet-access replaced

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_replaced \
  -vv
```

### Ethernet-access deleted

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_deleted \
  -vv
```

### Ethernet-access overridden

```bash
ansible-test network-integration nd_interface_ethernet_access \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_overridden \
  -vv
```

## Migration process

### Step 1: Inventory the original suite

Before writing harness scenarios, inspect every original integration-test file.

Record:

- Supported states.
- Create scenarios.
- Update scenarios.
- Delete scenarios.
- Override scenarios.
- Check-mode behavior.
- Idempotency checks.
- Negative tests.
- Default-value behavior.
- Multi-resource behavior.
- Fan-out behavior.
- Split-configuration behavior.
- Module-specific options.
- Destructive behavior.
- Version-specific behavior.
- Setup and cleanup requirements.

Do not assume one file corresponds to one scenario. An original state file may contain several independent behaviors.

### Step 2: Create a parity matrix

Use a table such as:

| Original scenario | Original file/task | Harness replacement | Safety | Status |
|---|---|---|---|---|
| Create one resource | `merged.yaml` | `nd4x_demo_merged.yaml` | Safe | Pending |
| Update resource | `replaced.yaml` | `nd4x_demo_replaced.yaml` | Safe | Pending |
| Delete resource | `deleted.yaml` | `nd4x_demo_deleted.yaml` | Safe | Pending |
| Fabric-wide override | `overridden.yaml` | `nd4x_demo_overridden.yaml` | Destructive | Pending |
| Multi-resource fan-out | `merged.yaml` | `nd4x_demo_merged_fanout.yaml` | Safe | Pending |
| Invalid configuration | `merged.yaml` | `nd4x_demo_negative.yaml` | Safe | Pending |

Every original scenario must have one of these outcomes:

- Replaced by a harness scenario.
- Intentionally retained with an explanation.
- Removed as obsolete with reviewer approval.

### Step 3: Define reserved resources

Add module-specific test variables under:

```text
tests/integration/targets/<module>/vars/main.yaml
```

Document:

- Fabric input.
- Test switch management IP.
- Resource identifiers.
- Reserved resource range.
- Cleanup collection.
- Destructive opt-in.
- Minimum ND version.

### Step 4: Add discovery and safety preflight

Before state scenarios execute:

- Query the ND version.
- Gate ND 4.x scenarios.
- Resolve current switch IDs from management IPs.
- Verify required resources exist.
- Verify the selected resources are safe to modify.

### Step 5: Implement one scenario at a time

For each scenario:

1. Establish the baseline.
2. Run the operation through the harness.
3. Configure controller-state snapshots.
4. Define complete phase expectations.
5. Add REST validation.
6. Add module-specific assertions.
7. Add cleanup under `always`.
8. Add the appropriate tags.
9. Run the scenario independently.

### Step 6: Compare with the original suite

Run original and migrated scenarios against the same approved testbed.

Compare:

- Resources created.
- Resources updated.
- Resources deleted.
- Returned `before`, `after`, and `proposed` values.
- Check-mode behavior.
- Idempotency.
- REST state.
- Negative failure behavior.
- Cleanup results.

Do not retire the original suite merely because the new scenarios pass.

### Step 7: Review coverage parity

Migration is complete only after reviewers confirm:

- Every original scenario is represented.
- No safety preflight was lost.
- No negative assertion was weakened.
- No multi-resource behavior was dropped.
- No module-specific option was omitted.
- Predictive mutation safety is configured.
- Original and migrated results are equivalent.

## Migration acceptance checklist

- [ ] Every original integration scenario has been inventoried.
- [ ] A parity matrix maps each original scenario to its replacement.
- [ ] Positive scenarios are preserved.
- [ ] Negative scenarios are preserved.
- [ ] Check-mode behavior is preserved.
- [ ] Idempotency behavior is preserved.
- [ ] Multi-resource behavior is preserved.
- [ ] Fan-out behavior is preserved where supported.
- [ ] Split-configuration behavior is preserved where supported.
- [ ] Module-specific options are covered.
- [ ] The minimum supported ND version is checked.
- [ ] Controller identifiers are resolved dynamically.
- [ ] Reserved test resources are documented.
- [ ] Pre-test cleanup establishes a known baseline.
- [ ] Mutating scenarios use `block`/`always` cleanup.
- [ ] Destructive scenarios require explicit opt-in.
- [ ] Destructive scenarios perform a read-only scope preflight.
- [ ] Every harness call defines meaningful phase expectations.
- [ ] Predictive snapshots cover the complete mutation scope.
- [ ] Only proven volatile fields are excluded from snapshot comparison.
- [ ] Post-apply REST state is validated.
- [ ] Module-specific returned fields are asserted.
- [ ] Negative tests verify the intended failure reason.
- [ ] State-specific scenarios pass independently.
- [ ] The safe aggregate passes.
- [ ] Destructive scenarios pass on an approved dedicated testbed.
- [ ] The original suite remains until coverage parity is approved.
- [ ] Documentation and examples match implemented behavior.

## Validation before submitting a migration

Run formatting and sanity checks:

```bash
git diff --check
ansible-test sanity
```

Run the target's original suite:

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  -vv
```

Run the safe migrated aggregate:

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo \
  --skip-tags nd4x_demo_overridden \
  -vv
```

Run each state independently:

```bash
ansible-test network-integration <target> \
  --inventory /absolute/path/to/inventory.networking \
  --tags nd4x_demo_<state> \
  -vv
```

Run destructive scenarios only on an approved dedicated testbed with explicit opt-in.

## Reference implementations

Use these target-local implementations as examples:

```text
tests/integration/targets/nd_interface_loopback/
tests/integration/targets/nd_interface_ethernet_access/
```

Use the documentation-only module for the concise action-plugin interface:

```text
plugins/modules/nd4x_module_test.py
```

Use this guide for:

- Contributor responsibilities.
- Complete input behavior.
- Scenario design.
- Safety requirements.
- Execution conventions.
- Migration acceptance.
