# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""ND Switches Validation Action Plugin (thin Ansible adapter)."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: _nd_switches_validate
short_description: Validate ND switch inventory in integration tests
version_added: "1.0.0"
description:
  - Integration-test helper for validating switch inventory returned by C(cisco.nd.nd_rest).
  - This action plugin compares expected switch data with the live ND switch inventory payload.
  - It is used by the C(nd_manage_switches) integration test target.
author:
  - Akshayanat C S (@achengam)
options:
  nd_data:
    description:
      - Registered result from a C(cisco.nd.nd_rest) task.
      - The plugin reads switch inventory from C(nd_data.current.switches).
    type: dict
    required: true
  test_data:
    description:
      - Expected switch entry or list of switch entries.
      - Entries are matched against the ND inventory by seed IP, role, or both depending on C(mode).
    type: raw
    required: true
  changed:
    description:
      - Optional assertion that the upstream task changed data.
      - When provided as C(false), validation fails immediately.
    type: bool
    required: false
  mode:
    description:
      - Match mode for inventory comparison.
      - C(both) matches by seed IP and role.
      - C(ip) matches by seed IP only.
      - C(role) matches by role only.
    type: str
    choices:
      - both
      - ip
      - role
    default: both
"""

EXAMPLES = r"""
- name: Validate switch inventory in integration tests
  cisco.nd.tests.integration._nd_switches_validate:
    nd_data: "{{ switch_inventory }}"
    test_data:
      - seed_ip: 192.0.2.10
        role: leaf
    mode: both
"""

RETURN = r"""
failed:
  description: Whether validation failed.
  type: bool
  returned: always
msg:
  description: Validation result message.
  type: str
  returned: always
missing_ips:
  description: Expected seed IP addresses not found in the ND response.
  type: list
  elements: str
  returned: on validation failure
role_mismatches:
  description: Switches whose role did not match the expected role.
  type: dict
  returned: on validation failure
"""

import json
from typing import Any

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    HAS_PYDANTIC,
)

try:
    from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.switches_inventory_matcher import (
        SwitchInventoryMatcher,
    )

    HAS_VALIDATOR = True
except ImportError:
    HAS_VALIDATOR = False

display = Display()


class ActionModule(ActionBase):
    """Ansible action plugin for validating ND switch inventory data.

    Task arguments:
        nd_data   (dict): The registered result of a cisco.nd.nd_rest GET call.
        test_data (list|dict): Expected switch entries, each with ``seed_ip``
                               and optionally ``role``.
        changed   (bool, optional): If provided and False, the task fails
                                    immediately (used to assert an upstream
                                    operation produced a change).
        mode      (str, optional): ``"both"`` (default), ``"ip"``, or ``"role"``.
    """

    def run(
        self,
        tmp: Any = None,
        task_vars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # pylint: disable=too-many-return-statements
        results = super().run(tmp, task_vars)
        results["failed"] = False

        if not HAS_PYDANTIC or not HAS_VALIDATOR:
            results["failed"] = True
            results["msg"] = "pydantic and the ND switch inventory matcher are required for _nd_switches_validate"
            return results

        args = self._task.args
        nd_data = args["nd_data"]
        test_data = args["test_data"]

        # Fail fast if the caller signals that no change occurred when one was expected.
        if "changed" in args and not args["changed"]:
            results["failed"] = True
            results["msg"] = 'Changed is "false"'
            return results

        # Fail fast if the upstream nd_rest task itself failed.
        if nd_data.get("failed"):
            results["failed"] = True
            results["msg"] = nd_data.get("msg", "ND module returned a failure")
            return results

        switches = nd_data.get("current", {}).get("switches", [])

        if isinstance(test_data, dict):
            test_data = [test_data]

        if not switches and not test_data:
            results["msg"] = "Validation Successful!"
            return results

        if not switches:
            results["failed"] = True
            results["msg"] = "No switches found in ND response"
            return results

        # Resolve matching mode.
        ignore_fields: dict[str, int] = {"seed_ip": 0, "role": 0}
        mode = args.get("mode", "both").lower()
        if mode == "ip":
            ignore_fields["role"] = 1
        elif mode == "role":
            ignore_fields["seed_ip"] = 1

        validation = SwitchInventoryMatcher(
            config_data=test_data,
            nd_data=switches,
            ignore_fields=ignore_fields,
        )

        if validation.response:
            results["msg"] = "Validation Successful!"
            return results

        # Surface diagnostics via Ansible's Display so they show up with -v.
        display.display("Invalid Data:")
        if validation.missing_ips:
            display.display(f"  Missing IPs: {validation.missing_ips}")
        if validation.role_mismatches:
            display.display(f"  Role mismatches: {json.dumps(validation.role_mismatches, indent=2)}")

        results["failed"] = True
        results["msg"] = "Validation Failed! Please check output above."
        results["missing_ips"] = validation.missing_ips
        results["role_mismatches"] = validation.role_mismatches
        return results
