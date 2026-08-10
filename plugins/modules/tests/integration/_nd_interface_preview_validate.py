#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: _nd_interface_preview_validate
short_description: Validate Interface preview results in ND integration tests
version_added: "2.0.0"
description:
  - Validates the result of a read-only Interface configuration preview.
  - Confirms every requested interface succeeded and whether pending configuration
    is present or absent.
  - Optionally checks expected or running configuration fragments.
author:
  - L Nikhil Sri Krishna (@nisaikri)
options:
  nd_data:
    description:
      - Registered C(cisco.nd.nd_rest) result from an Interface preview request.
    type: raw
    required: true
  test_data:
    description:
      - Expected Interface preview results.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_id:
        description:
          - Serial number of the switch containing the Interface.
        type: str
        required: true
      interface_name:
        description:
          - Name of the Interface to validate.
        type: str
        required: true
      pending:
        description:
          - C(clean) requires zero pending lines.
          - C(present) requires one or more pending lines.
          - C(ignore) does not validate pending lines.
        type: str
        choices: [clean, present, ignore]
        default: clean
      expected_contains:
        description:
          - Configuration fragments that must be present in the expected configuration.
        type: list
        elements: str
      running_contains:
        description:
          - Configuration fragments that must be present in the running configuration.
        type: list
        elements: str
notes:
  - This is a documentation-only module. The corresponding action plugin performs
    the validation.
  - The helper does not mutate ND state.
"""

EXAMPLES = r"""
- name: Query Interface configuration preview
  cisco.nd.nd_rest:
    path: /api/v1/manage/fabrics/FABRIC-1/interfaceActions/preview
    method: post
    content:
      interfaces:
        - switchId: FDO12345678
          interfaceName: Ethernet1/20
  register: interface_preview

- name: Verify that the Interface has no pending configuration
  cisco.nd.tests.integration._nd_interface_preview_validate:
    nd_data: "{{ interface_preview }}"
    test_data:
      - switch_id: FDO12345678
        interface_name: Ethernet1/20
        pending: clean
"""

RETURN = r"""
changed:
  description: Always C(false), because validation is read-only.
  returned: always
  type: bool
report:
  description: Missing, failed, pending-state, duplicate, and configuration-fragment results.
  returned: always
  type: dict
"""
