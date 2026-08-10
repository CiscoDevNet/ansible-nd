#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: _nd_interface_group_validate
short_description: Validate live Interface Group state in ND integration tests
version_added: "2.0.0"
description:
  - Provides read-only, module-specific assertions for Interface Group integration tests.
  - Normalizes shared test-runner output and direct Interface Group read responses.
  - This is an integration-test helper and is not part of the public Interface Groups
    module interface.
author:
  - L Nikhil Sri Krishna (@nisaikri)
options:
  nd_data:
    description:
      - Registered result from C(cisco.nd.nd4x_module_test) or C(cisco.nd.nd_rest).
    type: raw
    required: true
  test_data:
    description:
      - Expected Interface Groups in C(nd_manage_interface_group) input shape.
    type: list
    elements: dict
  absent:
    description:
      - Interface Group names that must not be present.
    type: list
    elements: raw
  mode:
    description:
      - C(subset) requires supplied networks and members to be present.
      - C(exact) requires supplied network and member collections to match exactly.
    type: str
    default: subset
    choices: [subset, exact]
  scope_prefix:
    description:
      - Restrict validation and invariants to Interface Group names with this prefix.
    type: str
  vpc_peer_switch_ids:
    description:
      - Optional mapping of vPC peer switch IDs used to compare vPC members when
        ND reports the logical vPC interface under the opposite peer.
      - Ethernet and port-channel members continue to require an exact switch-ID match.
    type: dict
  invariants:
    description:
      - Optional cross-group assertions such as counts, required types, and unique membership.
    type: dict
notes:
  - This is a documentation-only module. The corresponding action plugin performs
    the validation.
  - The helper does not mutate ND state.
"""

EXAMPLES = r"""
- name: Fetch one Interface Group
  cisco.nd.nd_rest:
    method: GET
    path: /api/v1/manage/fabrics/FABRIC-1/interfaceGroups/ANSIBLE-IG-PC
  register: interface_group_live

- name: Validate exact association state
  cisco.nd.tests.integration._nd_interface_group_validate:
    nd_data: "{{ interface_group_live }}"
    mode: exact
    test_data:
      - interface_group_name: ANSIBLE-IG-PC
        type: portChannel
        networks:
          - Network-A
        switch_interfaces:
          - switch_id: FDO12345678
            interface_names:
              - Port-channel501
"""

RETURN = r"""
changed:
  description: Always C(false), because validation is read-only.
  returned: always
  type: bool
groups:
  description: Normalized Interface Groups considered by the validation.
  returned: always
  type: list
  elements: dict
report:
  description: Structured missing, mismatch, absence, and invariant results.
  returned: always
  type: dict
"""
