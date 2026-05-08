# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""ND Switches Validation Action Plugin (thin Ansible adapter)."""

from __future__ import annotations

import json
from typing import Any

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    HAS_PYDANTIC,
)

try:
    from ansible_collections.cisco.nd.plugins.module_utils.validators.switches_validator import (
        SwitchesValidate,
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
        results = super().run(tmp, task_vars)
        results["failed"] = False

        if not HAS_PYDANTIC or not HAS_VALIDATOR:
            results["failed"] = True
            results["msg"] = (
                "pydantic and the ND collection validators are required "
                "for nd_switches_validate"
            )
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

        validation = SwitchesValidate(
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
            display.display(
                f"  Role mismatches: {json.dumps(validation.role_mismatches, indent=2)}"
            )

        results["failed"] = True
        results["msg"] = "Validation Failed! Please check output above."
        results["missing_ips"] = validation.missing_ips
        results["role_mismatches"] = validation.role_mismatches
        return results