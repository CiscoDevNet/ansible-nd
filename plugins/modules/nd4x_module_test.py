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
  - Runs the target module in check mode, applies the configuration, verifies
    idempotency, and optionally validates the resulting ND REST API state.
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
      - Expected results from check mode, apply, idempotency, and failure validation.
      - Supported keys include C(check_mode_changed), C(apply_changed),
        C(first_run_changed), C(second_run_changed), C(idempotency), and C(failed).
    type: dict
    default: {}
  check_mode:
    description:
      - Whether to execute the target module in check mode before applying configuration.
    type: bool
    default: true
  idempotency:
    description:
      - Whether to run the target module again to validate idempotency.
    type: bool
    default: true
  idempotency_retries:
    description:
      - Maximum number of idempotency validation attempts.
    type: int
    default: 1
  idempotency_delay:
    description:
      - Delay in seconds between idempotency attempts.
    type: int
    default: 0
  nd_queries:
    description:
      - ND REST API queries executed after the target module completes.
      - Query entries can contain C(path), C(method), C(expected_status),
        C(expected_failed), and JSONPath expectations.
    type: list
    elements: dict
    default: []
requirements:
  - jsonpath-ng
notes:
  - This is a documentation-only module. The corresponding action plugin
    performs the test execution.
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
      check_mode_changed: true
      apply_changed: true
      idempotency: true
      failed: false
    nd_queries:
      - name: Validate loopback interface
        path: "/api/v1/manage/fabrics/{{ test_fabric_name }}/interfaces/loopback100"
        method: get
        expected_status: 200
"""

RETURN = r"""
changed:
  description: Whether the first real target-module execution reported a change.
  type: bool
  returned: always
check_mode_result:
  description: Result returned by the check-mode execution.
  type: dict
  returned: when check mode is enabled
first_run_result:
  description: Result returned by the first real target-module execution.
  type: dict
  returned: always
second_run_result:
  description: Result returned by the idempotency execution.
  type: dict
  returned: when idempotency validation is enabled
idempotency_attempts:
  description: Number of idempotency attempts performed.
  type: int
  returned: always
nd_query_results:
  description: Results returned by ND REST API validation queries.
  type: list
  returned: always
"""
