# ND 4.x Module Integration Test Strategy Proposal

## Problem Statement

ND 4.x module integration tests currently use different playbook structures,
setup and cleanup patterns, assertion styles, and execution flows. This makes
tests harder to review, maintain, extend, and debug across modules.

The goal is to define one integration testing strategy that every ND 4.x module
can follow, while keeping module-specific state tests small and readable.

## Proposal Summary

Introduce a shared ND 4.x integration test harness built around:

- A common playbook directory for all ND 4.x module tests.
- A standard module test descriptor shape.
- A reusable action plugin that executes common test behavior.
- Small per-module playbooks for supported states such as `merged`,
  `replaced`, `overridden`, `deleted`, and `gathered`.

The action plugin should own repeatable mechanics such as variable loading,
module invocation, check mode execution, idempotency validation, common result
assertions, debug capture, and consistent failure handling.

State playbooks should focus only on the scenario:

- Which module is under test.
- Which state is being tested.
- Which inputs should be sent.
- What changed/unchanged behavior is expected.
- What module-specific result fields should be validated.
- What direct ND API validation is needed, if any.
- Which cleanup tasks should run at the end of the state playbook.

## Goals

- Standardize the integration test layout for ND 4.x modules.
- Reduce repeated setup, cleanup, idempotency, and assertion code.
- Make each module state test easy to scan and review.
- Make test failures easier to diagnose through consistent logs and debug data.
- Support both `ansible-test integration <target>` and direct playbook execution.
- Allow incremental migration from the current target-based tests.

## Non-Goals

- Replace existing module unit tests.
- Redesign module return schemas.
- Force every legacy ND test into the new structure immediately.
- Hide module-specific semantic validation in the action plugin.
- Build direct ND API validation into the first version of the action plugin.

## Proposed Directory Layout

Create the shared test harness under `tests/integration/playbooks` so it stays
close to `ansible-test` integration content:

```text
tests/integration/playbooks/nd4x_module_tests/
  inventory/
    hosts.yaml
    group_vars/
      nd.yaml
      common.yaml
  common/
    setup.yaml
    cleanup.yaml
    assert_result.yaml
    run_module_test.yaml
  module_tests/
    fabrics/
      merged.yaml
      replaced.yaml
      overridden.yaml
      deleted.yaml
      gathered.yaml
    vpc_pair/
    vrf/
    vrf_lite/
      merged.yaml
      replaced.yaml
      overridden.yaml
      deleted.yaml
      gathered.yaml
    policy/
    policy_group/
    l3out_links/
    resource_manager/
    acl/
    interfaces/
  README.md
```

For compatibility with `ansible-test`, each current integration target can keep
its existing entry point under `tests/integration/targets/<target>/tasks`, but
the entry point should delegate to the common harness where possible.

Example:

```yaml
---
- name: Run nd_vrf_lite merged state tests
  ansible.builtin.include_tasks: ../../../playbooks/nd4x_module_tests/module_tests/vrf_lite/merged.yaml
```

If `import_playbook` is not practical from an ansible-test target task file, the
target can include a thin wrapper task file that calls the same action plugin
with the same variables.

## Action Plugin

Add a collection action plugin:

```text
plugins/action/nd4x_module_test.py
```

The plugin is proposed as the single standard executor for one module test case.
It should be called from state playbooks or from a common wrapper task file.

Suggested task API:

```yaml
- name: "VRF LITE MERGED: create VRF lite configuration"
  cisco.nd.nd4x_module_test:
    module: cisco.nd.nd_vrf_lite
    state: merged
    config:
      - "{{ vrf_lite_100 }}"
    common_args:
      output_level: "{{ nd4x_output_level }}"
      fabric_name: "{{ nd4x_fabric_name }}"
    expected:
      first_run_changed: true
      check_mode_changed: true
      second_run_changed: false
      failed: false
  register: vrf_lite_merged_create
```

### Plugin Responsibilities

The action plugin should:

- Merge `common_args`, `config`, `state`, and test-specific module arguments.
- Validate that required ND connection variables are present.
- Run the module in check mode when requested.
- Run the module in normal mode.
- Optionally run the module a second time to validate idempotency.
- Assert the expected changed/unchanged/failed behavior.
- Save result payloads and failure context to a consistent log/debug location.
- Return a normalized summary result for the playbook.

The first version of the plugin should not own module-specific semantic
validation, direct ND API validation, or cleanup execution. Those should remain
in the state playbooks until repeated patterns are proven across migrated
modules.

### Proposed Plugin Arguments

```yaml
module: string              # Fully qualified module name under test.
state: string               # merged, replaced, overridden, deleted, gathered.
config: list | dict         # Module config payload.
common_args: dict           # Shared args such as fabric_name and output_level.
module_args: dict           # Optional additional module-specific arguments.
expected: dict              # Expected changed/failed/idempotency behavior.
idempotency: bool           # Default true for mutating states.
check_mode: bool            # Default true when module supports check mode.
log_name: string            # Optional stable name for debug artifacts.
```

### Expected Behavior Defaults

The plugin should use predictable defaults:

| State | Check Mode | First Run | Second Run |
| --- | --- | --- | --- |
| `merged` | changed | changed | unchanged |
| `replaced` | changed | changed | unchanged |
| `overridden` | changed | changed | unchanged |
| `deleted` | changed or unchanged, test-defined | changed or unchanged, test-defined | unchanged |
| `gathered` | unchanged | unchanged | skipped |

Any test can override these defaults through `expected`.

## Common Execution Flow

Every module test should follow this flow:

1. Load shared ND variables.
2. Verify required connection variables.
3. Run suite-level setup.
4. Run state playbooks in a standard order.
5. For each test case:
   - Run check mode, if enabled.
   - Run normal mode.
   - Run idempotency pass, if enabled.
   - Validate common result expectations.
   - Save debug artifacts.
6. Run module-specific semantic validation in the state playbook.
7. Run direct ND API validation from the state playbook when needed.
8. Run cleanup at the end of the state playbook with `always` behavior.
9. Print a concise summary.

Recommended state order:

```text
merged -> replaced -> overridden -> deleted -> gathered
```

Modules that do not support every state should only include the states they
support.

## Example State Playbook

`tests/integration/playbooks/nd4x_module_tests/module_tests/vrf_lite/merged.yaml`

```yaml
---
- name: Run VRF lite merged state tests
  block:
    - name: "VRF LITE MERGED: create one VRF lite object"
      cisco.nd.nd4x_module_test:
        module: cisco.nd.nd_vrf_lite
        state: merged
        common_args:
          output_level: "{{ nd4x_output_level }}"
          fabric_name: "{{ nd4x_fabric_name }}"
        config:
          - "{{ vrf_lite_100 }}"
        expected:
          check_mode_changed: true
          first_run_changed: true
          second_run_changed: false
      register: vrf_lite_merged_create

    - name: "VRF LITE MERGED: verify created object in module result"
      ansible.builtin.assert:
        that:
          - vrf_lite_merged_create.first_run_result.after
            | selectattr('vrf_name', 'equalto', vrf_lite_100.vrf_name)
            | list
            | length == 1

    - name: "VRF LITE MERGED: update one VRF lite object"
      cisco.nd.nd4x_module_test:
        module: cisco.nd.nd_vrf_lite
        state: merged
        common_args:
          output_level: "{{ nd4x_output_level }}"
          fabric_name: "{{ nd4x_fabric_name }}"
        config:
          - "{{ vrf_lite_100_updated }}"
        expected:
          check_mode_changed: true
          first_run_changed: true
          second_run_changed: false
      register: vrf_lite_merged_update

    - name: "VRF LITE MERGED: verify updated values in module result"
      ansible.builtin.assert:
        that:
          - vrf_lite_merged_update.first_run_result.after
            | selectattr('description', 'equalto', vrf_lite_100_updated.description)
            | list
            | length == 1
  always:
    - name: "VRF LITE MERGED CLEANUP: remove test objects"
      cisco.nd.nd_vrf_lite:
        output_level: "{{ nd4x_output_level }}"
        fabric_name: "{{ nd4x_fabric_name }}"
        state: deleted
        config:
          - vrf_name: "{{ vrf_lite_100.vrf_name }}"
```

## Shared Variables

Common variables should be loaded once by the harness:

```yaml
nd4x_output_level: "{{ api_key_output_level | default('debug') }}"
nd4x_log_dir: "{{ lookup('env', 'ND4X_TEST_LOG_DIR') | default('/tmp/nd4x-module-tests', true) }}"
nd4x_enable_check_mode: true
nd4x_enable_idempotency: true
nd4x_validate_certs: false
```

Module-specific variables should live beside the module state playbooks:

```text
module_tests/vrf_lite/vars.yaml
module_tests/interfaces/vars.yaml
```

This keeps shared harness settings separate from module scenario data.

## Assertion Strategy

Assertions should be split into two categories.

Common assertions handled by the plugin:

- The module did not fail unless failure is expected.
- Check mode reported the expected changed state.
- Normal mode reported the expected changed state.
- Idempotency reported unchanged on the second run.
- Required result keys exist when configured.

Module-specific assertions supplied by each state playbook:

- Expected object appears in `after`.
- Expected object is absent after delete.
- Updated field has the new value.
- Untouched fields are preserved after `merged`.
- Extra objects are removed after `overridden`.
- Gathered output contains the expected normalized shape.

## Direct ND API Validation

Direct ND API validation should be kept as optional module-specific validation
inside each module state playbook.

This means the action plugin validates common module execution behavior, while
state playbooks perform extra ND REST API checks manually when a scenario needs
proof from the live Nexus Dashboard API.

Example:

```yaml
- name: "FABRIC MERGED: query fabric from ND API"
  ansible.builtin.uri:
    url: "https://{{ ansible_host }}:{{ ansible_httpapi_port | default(443) }}/api/v1/manage/fabrics/{{ test_fabric_merged }}"
    method: GET
    headers:
      Authorization: "Bearer {{ nd_auth_response.json.jwttoken }}"
      Content-Type: "application/json"
    validate_certs: false
    return_content: true
    status_code:
      - 200
  register: merged_fabric_query
  delegate_to: localhost

- name: "FABRIC MERGED: verify fabric values from ND API"
  ansible.builtin.assert:
    that:
      - merged_fabric_query.json.management.bgpAsn == "65002"
```

This keeps the first action plugin small and avoids forcing module-specific
endpoints, response shapes, and object-matching rules into shared code too
early.

## Cleanup Strategy

Cleanup should be defined at the end of each state playbook. Use a `block` with
an `always` section when cleanup must run even if a test or assertion fails.

Example:

```yaml
- name: Run merged state tests
  block:
    - name: Run merged test cases
      cisco.nd.nd4x_module_test:
        ...
  always:
    - name: "MERGED CLEANUP: remove test objects"
      cisco.nd.nd_vrf_lite:
        output_level: "{{ nd4x_output_level }}"
        fabric_name: "{{ nd4x_fabric_name }}"
        state: deleted
        config:
          - vrf_name: "{{ vrf_lite_100.vrf_name }}"
```

Shared setup and cleanup for resources used across many state playbooks can
still live in `common/setup.yaml` and `common/cleanup.yaml`, but state-owned
resources should be cleaned up in the state playbook that created them.

## Logging And Debug Artifacts

The harness should consistently write debug payloads when enabled:

```text
{{ nd4x_log_dir }}/
  <suite>/
    <state>/
      <test_name>/
        check_mode_result.json
        first_run_result.json
        second_run_result.json
        failure_context.json
```

The action plugin should include enough context to reproduce the failing task:

- Module name.
- State.
- Redacted module arguments.
- Expected behavior.
- Actual changed/failed status.
- Assertion that failed.
- Relevant `before`, `after`, `diff`, or response fields.

Sensitive values such as passwords, tokens, and API keys must be redacted.

## Failure Handling

The plugin should standardize failures:

- Missing ND connection variables fail before running the module.
- Module execution errors include the module name, state, and test name.
- Assertion errors show expected versus actual behavior.
- Cleanup errors are handled by the state playbook cleanup task.
- Known negative tests can declare `expected.failed: true`.

## Migration Plan

1. Add the proposal and agree on the harness contract.
2. Implement `plugins/action/nd4x_module_test.py` with common execution,
   idempotency, common assertions, and logging support.
3. Add `tests/integration/playbooks/nd4x_module_tests/README.md` and common
   playbooks.
4. Migrate one representative module first, preferably `nd_interface_loopback`,
   because it already has state-specific playbooks and check mode coverage.
5. Migrate one fabric-management module next, such as `nd_manage_fabric_ibgp`,
   because it exercises larger payloads and direct ND validation needs.
6. Refine the action plugin API based on those two migrations.
7. Migrate the remaining ND 4.x modules incrementally.
8. Keep legacy tests until the migrated test reaches equivalent or better
   coverage.

## Acceptance Criteria

- A new ND 4.x module can add integration tests using only:
  - A module folder under `tests/integration/playbooks/nd4x_module_tests/module_tests`.
  - One vars file.
  - One state playbook per supported state.
- The same test task pattern works for `merged`, `replaced`, `overridden`,
  `deleted`, and `gathered`.
- Idempotency is validated consistently for all mutating states.
- Check mode is validated consistently for modules that support it.
- Logs/debug artifacts are written in a predictable location.
- Cleanup is defined at the end of each state playbook and runs after both
  success and failure where needed.
- Direct ND API validation is written as module-specific validation in the
  state playbook when needed.
- Test failures are readable without manually adding debug tasks to every
  module test.

## Resolved Decisions

- The common playbook directory will live under
  `tests/integration/playbooks/nd4x_module_tests`.
- Direct ND API validation will stay in module-specific state playbooks and will
  be added manually only when a test needs it.
- Cleanup will be defined at the end of each state playbook.

## Open Questions

- Should module-specific field assertions use normal Ansible `assert` tasks
  after the plugin returns, or should a small custom assertion schema be added
  after the first migrations?
- Should check mode be mandatory for all ND 4.x modules that claim check mode
  support?

## Recommendation

Start with a small action plugin contract that handles execution,
idempotency, common assertions, and debug capture. Keep module-specific
semantic validation, direct ND API validation, and state cleanup in state
playbooks at first. After two module migrations, promote repeated validation
patterns into the plugin only when the repetition is proven across modules.

This keeps the first version useful without making the harness too rigid before
the ND 4.x module test patterns have settled.
