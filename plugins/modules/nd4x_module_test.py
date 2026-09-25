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
  - During normal execution, runs the target module in check mode, applies the
    configuration, verifies idempotency, and optionally validates the resulting
    ND REST API state.
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
      - Additional module-specific arguments passed to the target module.
    type: dict
    default: {}
  expected:
    description:
      - Expected result for each execution phase.
      - Supported phase keys are C(check_mode), C(apply), and C(idempotency).
    type: dict
    default: {}
  check_mode:
    description:
      - Whether to execute an internal check-mode phase before applying configuration.
    type: bool
    default: true
  idempotency:
    description:
      - Whether to execute the target module once after apply to validate idempotency.
    type: bool
    default: true
  idempotency_retries:
    description:
      - Compatibility option. Only the value C(1) is supported.
    type: int
    default: 1
  idempotency_delay:
    description:
      - Compatibility option. Only the value C(0) is supported.
    type: int
    default: 0
  nd_queries:
    description:
      - ND REST API queries executed after a successful real apply.
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
- name: Test creation of an ND resource
  cisco.nd.nd4x_module_test:
    module: cisco.nd.nd_manage_interface_group
    state: merged
    common_args:
      fabric_name: fabric1
    config:
      - interface_group_name: ANSIBLE-IG-ANY
        type: any
"""

RETURN = r"""
changed:
  description: Whether the reported execution phase changed configuration.
  type: bool
  returned: always
check_mode_result:
  description: Result returned by the check-mode execution.
  type: dict
  returned: when the check-mode phase executes
first_run_result:
  description: Result returned by the first real apply execution.
  type: dict
  returned: when Ansible is not running in global check mode
second_run_result:
  description: Result returned by the idempotency execution.
  type: dict
  returned: when idempotency is enabled and the real apply succeeds
idempotency_attempts:
  description: Number of idempotency executions performed.
  type: int
  returned: always
nd_query_results:
  description: Results returned by ND REST API validation queries.
  type: list
  returned: always
"""
