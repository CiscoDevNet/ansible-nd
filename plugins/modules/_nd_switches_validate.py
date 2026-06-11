# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Private documentation stub for the _nd_switches_validate action plugin."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: _nd_switches_validate
short_description: Private test helper for validating ND switch inventory
description:
  - Private integration-test helper used by this collection's nd_manage_switches tests.
  - The implementation lives in the matching action plugin.
  - This plugin is not part of the public collection interface.
author:
  - Akshayanat C S (@achengam)
options:
  nd_data:
    description:
      - Registered result from a C(cisco.nd.nd_rest) GET call.
    type: dict
    required: true
  test_data:
    description:
      - Expected switch entry or list of switch entries.
    type: raw
    required: true
  changed:
    description:
      - Optional assertion that the upstream task changed data.
    type: bool
    required: false
  mode:
    description:
      - Match mode used by the inventory comparison.
    type: str
    choices:
      - both
      - ip
      - role
    default: both
"""

EXAMPLES = r"""
- name: Validate switch inventory in integration tests
  cisco.nd._nd_switches_validate:
    nd_data: "{{ switch_inventory }}"
    test_data:
      - seed_ip: 192.0.2.10
        role: leaf
"""

RETURN = r"""
missing_ips:
  description: Expected seed IP addresses not found in the ND response.
  returned: on validation failure
  type: list
  elements: str
role_mismatches:
  description: Switches whose role did not match the expected role.
  returned: on validation failure
  type: list
  elements: dict
"""
