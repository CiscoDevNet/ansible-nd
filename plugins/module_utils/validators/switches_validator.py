# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pure-Python validator for ND switch inventory data.

Validates that every entry in a user-supplied config list has a matching
switch in the ND API response. No Ansible dependencies — reusable from
any Python context.

Matching modes are expressed via ``ignore_fields``:
  - ``{"seed_ip": 0, "role": 0}`` (default): match by seed_ip AND role.
  - ``{"seed_ip": 0, "role": 1}``: match by seed_ip only.
  - ``{"seed_ip": 1, "role": 0}``: match by role only.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import (
    SwitchConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.switch_data_models import (
    SwitchDataModel,
)


class SwitchesValidate(BaseModel):
    """Matches playbook config entries against live ND inventory.

    After construction, inspect:
      - ``response``: True if all config entries matched, False otherwise.
      - ``missing_ips``: seed_ips from config with no matching ND switch.
      - ``role_mismatches``: {seed_ip: {"expected_role": ..., "response_role": ...}}
    """

    config_data: list[SwitchConfigModel] | None = None
    nd_data: list[SwitchDataModel] | None = None
    ignore_fields: dict[str, int] = Field(default_factory=lambda: {"seed_ip": 0, "role": 0})
    response: bool | None = None
    missing_ips: list[str] = Field(default_factory=list)
    role_mismatches: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @field_validator("config_data", mode="before")
    @classmethod
    def parse_config_data(cls, value: Any) -> list[SwitchConfigModel] | None:
        """Coerce raw dicts into SwitchConfigModel instances."""
        if value is None:
            return None
        if isinstance(value, dict):
            return [SwitchConfigModel.model_validate(value)]
        if isinstance(value, list):
            try:
                return [SwitchConfigModel.model_validate(item) if isinstance(item, dict) else item for item in value]
            except (ValidationError, ValueError) as e:
                raise ValueError(f"Invalid format in Config Data: {e}")
        raise ValueError("Config Data must be a dict, list of dicts, or None.")

    @field_validator("nd_data", mode="before")
    @classmethod
    def parse_nd_data(cls, value: Any) -> list[SwitchDataModel] | None:
        """Coerce raw ND API switch dicts into SwitchDataModel instances."""
        if value is None:
            return None
        if isinstance(value, list):
            try:
                return [SwitchDataModel.from_response(item) if isinstance(item, dict) else item for item in value]
            except (ValidationError, ValueError) as e:
                raise ValueError(f"Invalid format in ND Response: {e}")
        raise ValueError("ND Response must be a list of dictionaries.")

    @field_validator("ignore_fields", mode="before")
    @classmethod
    def default_ignore_fields(cls, value: dict[str, int] | None) -> dict[str, int]:
        """Ensure both keys are always present, defaulting to 0 (strict match)."""
        if value is None:
            return {"seed_ip": 0, "role": 0}
        return {"seed_ip": value.get("seed_ip", 0), "role": value.get("role", 0)}

    @model_validator(mode="after")
    def validate_lists_equality(self) -> SwitchesValidate:
        """Match every config entry against the live ND switch inventory."""
        config_data = self.config_data
        nd_data_list = self.nd_data
        ignore_seed_ip = bool(self.ignore_fields["seed_ip"])
        ignore_role = bool(self.ignore_fields["role"])

        # Both empty → nothing to validate, treat as success.
        # Exactly one empty → mismatch, treat as failure.
        if not config_data and not nd_data_list:
            self.response = True
            return self
        if not config_data or not nd_data_list:
            self.response = False
            return self

        matched_indices: set[int] = set()

        for config_item in config_data:
            seed_ip = config_item.seed_ip
            role_expected = config_item.role  # SwitchRole enum or None
            found_match = False
            role_mismatch_for_this_entry: dict[str, Any] | None = None

            for i, nd_item in enumerate(nd_data_list):
                if i in matched_indices:
                    continue

                ip_address = nd_item.fabric_management_ip
                switch_role = nd_item.switch_role  # SwitchRole enum or None

                seed_ip_match = ignore_seed_ip or (seed_ip is not None and ip_address is not None and ip_address == seed_ip)
                role_match = ignore_role or (role_expected is not None and switch_role is not None and switch_role == role_expected)

                if seed_ip_match and role_match:
                    matched_indices.add(i)
                    found_match = True
                    break

                # Full match failed. If seed_ip matched but role didn't,
                # remember it as a candidate role mismatch. We only commit
                # this diagnostic if no better match turns up later.
                if (
                    not ignore_role
                    and seed_ip_match
                    and not ignore_seed_ip
                    and role_expected is not None
                    and switch_role is not None
                    and switch_role != role_expected
                ):
                    role_mismatch_for_this_entry = {
                        "nd_index": i,
                        "ip_address": ip_address,
                        "expected_role": getattr(role_expected, "value", role_expected),
                        "response_role": getattr(switch_role, "value", switch_role),
                    }

            if not found_match:
                if role_mismatch_for_this_entry is not None:
                    # Seed IP was found but role disagreed — record and
                    # consume that nd_item so it's not re-matched.
                    rm = role_mismatch_for_this_entry
                    matched_indices.add(rm["nd_index"])
                    self.role_mismatches[seed_ip or rm["ip_address"]] = {
                        "expected_role": rm["expected_role"],
                        "response_role": rm["response_role"],
                    }
                elif seed_ip is not None:
                    self.missing_ips.append(seed_ip)

        self.response = not self.missing_ips and not self.role_mismatches
        return self
