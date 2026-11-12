#!/usr/bin/python
# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_breakout_interfaces_validate
short_description: Validate breakout state in ND integration tests
version_added: "2.0.0"
description:
  - Independently reads interface and policy state for breakout integration tests.
  - Compares the observations with a declared test fixture or an earlier snapshot.
  - This integration-test helper is not part of the public breakout module interface.
author:
  - L Nikhil Sri Krishna (@nisaikri)
options:
  fabric_name:
    description: Name of the test fabric.
    type: str
    required: true
  switch_id:
    description: Switch serial number. Management IP addresses are not accepted by this helper.
    type: str
    required: true
  fixture:
    description:
      - Reserved parent interfaces and their expected native and breakout profiles.
      - Contains C(control_parent), C(native_interfaces) and C(profiles), with optional guard interfaces and filters.
    type: dict
    required: true
  expected_profile:
    description: C(native) or the name of a profile declared in O(fixture).
    type: str
    default: native
  observe_only:
    description: Capture a scoped snapshot without comparing it with the expected profile.
    type: bool
    default: false
  validate_only:
    description: Validate the fixture locally without making controller requests.
    type: bool
    default: false
  baseline:
    description: Earlier snapshot used to check unchanged interfaces and protected scope.
    type: dict
  unchanged:
    description: Require the observed reserved state to match O(baseline).
    type: bool
    default: false
  whole_switch:
    description: Include nonreserved breakout families when observing the switch.
    type: bool
    default: false
  owned_interfaces:
    description: Other reserved parents excluded from outside-scope preservation checks. Requires O(whole_switch=true).
    type: list
    elements: str
    default: []
  include_speeds:
    description: Include child speeds in the snapshot and profile comparisons.
    type: bool
    default: false
  topology_only:
    description: Skip reserved policy-map comparisons while preserving guard and outside-scope checks.
    type: bool
    default: false
  retries:
    description: Maximum number of observation attempts, from one to ten.
    type: int
    default: 3
  interval:
    description: Seconds between attempts. Total requested sleep must not exceed 60 seconds.
    type: float
    default: 1
notes:
  - This is a documentation-only module. The corresponding action plugin performs the validation on the Ansible control node.
  - All Nexus Dashboard requests made by this helper are read-only GETs.
  - Set C(check_mode=false) on observation tasks because M(cisco.nd.nd_rest) skips GET requests in check mode.
"""

EXAMPLES = r"""
- name: Validate a breakout test fixture without contacting Nexus Dashboard
  cisco.nd.nd_manage_breakout_interfaces_validate:
    fabric_name: fab1
    switch_id: FDO222425SE
    validate_only: true
    fixture:
      control_parent: Ethernet1/50
      native_interfaces: [Ethernet1/50]
      profiles:
        map_a:
          breakout_map: 25g-4x
          child_lanes:
            Ethernet1/50: [1, 2, 3, 4]
"""

RETURN = r"""
changed:
  description: Always C(false), because validation is read-only.
  returned: always
  type: bool
validated:
  description: Whether local fixture validation succeeded.
  returned: on successful validate_only
  type: bool
snapshot:
  description: Independently observed interface families and policy maps.
  returned: when a complete observation is available
  type: dict
observation_calls:
  description: GET requests made by this helper, separate from the production module's requests.
  returned: always
  type: list
  elements: dict
attempts:
  description: Number of completed observation attempts.
  returned: after an observation
  type: int
checks:
  description: Validation checks that succeeded.
  returned: on successful validation
  type: list
  elements: str
differences:
  description: Differences between the observed and expected state.
  returned: after an observation
  type: list
  elements: str
"""
