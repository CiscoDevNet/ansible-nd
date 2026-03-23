# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""ND Inventory Validation Action Plugin.

Validates switch inventory data returned from nd_rest against expected
configuration entries. Checks that every entry in test_data has a matching
switch in the ND API response (fabricManagementIp == seed_ip,
switchRole == role).

Supports an optional ``mode`` argument:
  - ``"both"`` (default): match by seed_ip AND role.
  - ``"ip"``:   match by seed_ip only  (role is ignored).
  - ``"role"``: match by role only     (seed_ip is ignored).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import json
from typing import Any, Dict, List, Optional, Union

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

try:
    from pydantic import BaseModel, ValidationError, field_validator, model_validator
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False

try:
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import SwitchConfigModel
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import SwitchDataModel
    HAS_MODELS = True
except ImportError:
    HAS_MODELS = False

display = Display()


# ---------------------------------------------------------------------------
# Validation orchestration model
# ---------------------------------------------------------------------------

class InventoryValidate(BaseModel):
    """Orchestrates the match between playbook config entries and live ND inventory."""

    config_data: Optional[List[Any]] = None
    nd_data: Optional[List[Any]] = None
    ignore_fields: Optional[Dict[str, int]] = None
    response: Union[bool, None] = None

    @field_validator("config_data", mode="before")
    @classmethod
    def parse_config_data(cls, value):
        """Coerce raw dicts into SwitchConfigModel instances.

        Accepts a single dict or a list of dicts.
        """
        if isinstance(value, dict):
            return [SwitchConfigModel.model_validate(value)]
        if isinstance(value, list):
            try:
                return [
                    SwitchConfigModel.model_validate(item) if isinstance(item, dict) else item
                    for item in value
                ]
            except (ValidationError, ValueError) as e:
                raise ValueError("Invalid format in Config Data: {0}".format(e))
        if value is None:
            return None
        raise ValueError("Config Data must be a single/list of dictionary, or None.")

    @field_validator("nd_data", mode="before")
    @classmethod
    def parse_nd_data(cls, value):
        """Coerce raw ND API switch dicts into SwitchDataModel instances."""
        if isinstance(value, list):
            try:
                return [
                    SwitchDataModel.from_response(item) if isinstance(item, dict) else item
                    for item in value
                ]
            except (ValidationError, ValueError) as e:
                raise ValueError("Invalid format in ND Response: {0}".format(e))
        if value is None:
            return None
        raise ValueError("ND Response must be a list of dictionaries.")

    @model_validator(mode="after")
    def validate_lists_equality(self):
        """Match every config entry against the live ND switch inventory.

        Sets ``self.response = True`` when all entries match, ``False`` otherwise.
        Respects ``ignore_fields`` to support ip-only or role-only matching modes.

        Role comparison uses SwitchRole enum equality — no string normalization needed.
        """
        config_data = self.config_data
        nd_data_list = self.nd_data
        ignore_fields = self.ignore_fields

        # Both empty → nothing to validate, treat as success.
        # Exactly one empty → mismatch, treat as failure.
        if not config_data and not nd_data_list:
            self.response = True
            return self
        if not config_data or not nd_data_list:
            self.response = False
            return self

        missing_ips = []
        role_mismatches = {}
        nd_data_copy = nd_data_list.copy()
        matched_indices = set()

        for config_item in config_data:
            found_match = False
            seed_ip = config_item.seed_ip
            role_expected = config_item.role  # SwitchRole enum or None

            for i, nd_item in enumerate(nd_data_copy):
                if i in matched_indices:
                    continue

                ip_address = nd_item.fabric_management_ip
                switch_role = nd_item.switch_role  # SwitchRole enum or None

                seed_ip_match = (
                    (seed_ip is not None and ip_address is not None and ip_address == seed_ip)
                    or bool(ignore_fields["seed_ip"])
                )
                role_match = (
                    (role_expected is not None and switch_role is not None and switch_role == role_expected)
                    or bool(ignore_fields["role"])
                )

                if seed_ip_match and role_match:
                    matched_indices.add(i)
                    found_match = True
                    if ignore_fields["seed_ip"]:
                        break
                elif (
                    seed_ip_match
                    and role_expected is not None
                    and switch_role is not None
                    and switch_role != role_expected
                ) or ignore_fields["role"]:
                    role_mismatches.setdefault(
                        seed_ip or ip_address,
                        {
                            "expected_role": role_expected.value if role_expected else None,
                            "response_role": switch_role.value if switch_role else None,
                        },
                    )
                    matched_indices.add(i)
                    found_match = True
                    if ignore_fields["seed_ip"]:
                        break

            if not found_match and seed_ip is not None:
                missing_ips.append(seed_ip)

        if not missing_ips and not role_mismatches:
            self.response = True
        else:
            display.display("Invalid Data:")
            if missing_ips:
                display.display("  Missing IPs: {0}".format(missing_ips))
            if role_mismatches:
                display.display("  Role mismatches: {0}".format(json.dumps(role_mismatches, indent=2)))
            self.response = False

        return self


# ---------------------------------------------------------------------------
# Action plugin
# ---------------------------------------------------------------------------

class ActionModule(ActionBase):
    """Ansible action plugin for validating ND switch inventory data.

    Arguments (task args):
        nd_data   (dict): The registered result of a cisco.nd.nd_rest GET call.
        test_data (list|dict): Expected switch entries, each with ``seed_ip``
                               and optionally ``role``.
        changed   (bool, optional): If provided and False, the task fails
                                    immediately (used to assert an upstream
                                    operation produced a change).
        mode      (str, optional): ``"both"`` (default), ``"ip"``, or ``"role"``.
    """

    def run(self, tmp=None, task_vars=None):
        results = super(ActionModule, self).run(tmp, task_vars)
        results["failed"] = False

        if not HAS_PYDANTIC or not HAS_MODELS:
            results["failed"] = True
            results["msg"] = "pydantic and the ND collection models are required for nd_inventory_validate"
            return results

        nd_data = self._task.args["nd_data"]
        test_data = self._task.args["test_data"]

        # Fail fast if the caller signals that no change occurred when one was expected.
        if "changed" in self._task.args and not self._task.args["changed"]:
            results["failed"] = True
            results["msg"] = 'Changed is "false"'
            return results

        # Fail fast if the upstream nd_rest task itself failed.
        if nd_data.get("failed"):
            results["failed"] = True
            results["msg"] = nd_data.get("msg", "ND module returned a failure")
            return results

        # Extract switch list from nd_data.current.switches
        switches = nd_data.get("current", {}).get("switches", [])

        # Normalise test_data to a list.
        if isinstance(test_data, dict):
            test_data = [test_data]

        # If both are empty treat as success; if only nd response is empty it's a failure.
        if not switches and not test_data:
            results["msg"] = "Validation Successful!"
            return results

        if not switches:
            results["failed"] = True
            results["msg"] = "No switches found in ND response"
            return results

        # Resolve matching mode via ignore_fields flags.
        ignore_fields = {"seed_ip": 0, "role": 0}
        if "mode" in self._task.args:
            mode = self._task.args["mode"].lower()
            if mode == "ip":
                # IP mode: only match by seed_ip, ignore role
                ignore_fields["role"] = 1
            elif mode == "role":
                # Role mode: only match by role, ignore seed_ip
                ignore_fields["seed_ip"] = 1

        validation = InventoryValidate(
            config_data=test_data,
            nd_data=switches,
            ignore_fields=ignore_fields,
            response=None,
        )

        if validation.response:
            results["msg"] = "Validation Successful!"
        else:
            results["failed"] = True
            results["msg"] = "Validation Failed! Please check output above."

        return results

