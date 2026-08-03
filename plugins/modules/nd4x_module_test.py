#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: nd4x_module_test
short_description: Run standardized integration tests for ND 4.x modules
version_added: "1.6.0"
description:
  - Provides a common integration-test runner for Cisco ND 4.x modules.
  - During normal execution, optionally verifies that predictive check mode did
    not mutate controller state, applies the configuration, verifies idempotency,
    and optionally validates the resulting ND REST API state.
  - Execution is handled by the corresponding nd4x_module_test action plugin.
author:
  - Astha Awasthi (@astawast)
options:
  module:
    description:
      - Fully qualified name of the ND module being tested.
    type: str
    required: true
  state:
    description:
      - State passed to the target ND module.
    type: str
    required: true
  config:
    description:
      - Configuration passed to the target module.
    type: raw
  common_args:
    description:
      - Common arguments passed to the target module.
    type: dict
    default: {}
  module_args:
    description:
      - Additional module-specific arguments.
    type: dict
    default: {}
  expected:
    description:
      - Expected result for each execution phase.
      - Supported phase keys are C(check_mode), C(apply), and C(idempotency).
      - Each phase is a dictionary that supports the C(changed) and C(failed)
        expectation keys.
      - When O(idempotency=true), the idempotency phase automatically requires
        C(changed=false).
    type: dict
    default: {}
  check_mode:
    description:
      - Whether to execute an internal check-mode phase before applying configuration.
      - Global Ansible check mode always executes only the check-mode phase,
        regardless of this option.
    type: bool
    default: true
  check_mode_queries:
    description:
      - Read-only ND REST API queries used to capture controller state before
        and after predictive check mode.
      - The normalized before and after states must be equivalent before a real
        apply is allowed.
      - Query entries support C(name), C(path), C(expected_status),
        C(unordered), and C(ignore_keys). The HTTP method is always C(GET).
      - C(ignore_keys) contains dictionary key names that are removed recursively
        before comparison. Use it only for volatile operational data, never for
        module-managed configuration fields.
      - These queries also execute when Ansible is invoked globally with
        C(--check).
    type: list
    elements: dict
    default: []
  idempotency:
    description:
      - Whether to execute the target module exactly once after apply to validate
        idempotency.
      - The idempotency execution must report C(changed=false).
    type: bool
    default: true
  nd_queries:
    description:
      - ND REST API queries executed after a successful real apply.
      - Query entries can contain C(path), C(method), C(expected_status),
        C(expected_failed), and JSONPath expectations.
      - Queries are skipped when Ansible is running in global check mode.
    type: list
    elements: dict
    default: []
requirements:
  - jsonpath-ng
notes:
  - This is a documentation-only module. The corresponding action plugin
    performs the test execution.
  - When Ansible is invoked with C(--check), predictive check mode and configured
    O(check_mode_queries) execute; apply, idempotency, and post-apply ND REST
    validation are skipped.
  - Idempotency uses exactly one second real module execution and does not retry
    module application.
"""

EXAMPLES = r"""
- name: Test creation of an ND loopback interface
  cisco.nd.nd4x_module_test:
    module: cisco.nd.nd_interface_loopback
    state: merged
    common_args:
      fabric_name: "{{ test_fabric_name }}"
      output_level: normal
    config:
      - switch_ip: 192.0.2.10
        interface_name: loopback100
        ip_address: 10.100.100.1
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
      - name: Snapshot managed interfaces
        path: >-
          /api/v1/manage/fabrics/{{ test_fabric_name
          }}/switches/{{ test_switch_id }}/interfaces
        expected_status: 200
        unordered: true
        ignore_keys:
          - operData
    nd_queries:
      - name: Validate loopback interface
        path: "/api/v1/manage/fabrics/{{ test_fabric_name }}/interfaces/loopback100"
        method: get
        expected_status: 200
"""

RETURN = r"""
changed:
  description:
    - Whether the first real target-module execution reported a change during
      normal execution.
    - In global check mode, whether the check-mode execution predicted a change.
  type: bool
  returned: always
check_mode_result:
  description: Result returned by the check-mode execution.
  type: dict
  returned: when the check-mode phase executes
check_mode_query_results:
  description:
    - Results of the before and after predictive check-mode controller-state
      comparisons.
  type: list
  returned: always
first_run_result:
  description: Result returned by the first real apply execution.
  type: dict
  returned: when Ansible is not running in global check mode
second_run_result:
  description: Result returned by the single idempotency execution.
  type: dict
  returned: when idempotency is enabled and the real apply succeeds
idempotency_attempts:
  description:
    - Number of idempotency executions performed.
    - The value is C(0) when idempotency is skipped and C(1) when it executes.
  type: int
  returned: always
nd_query_results:
  description: Results returned by ND REST API validation queries.
  type: list
  returned: always
"""
