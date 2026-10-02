# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Smart Switch association identity, payload aliases and state validation."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field, ValidationInfo, model_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class SmartSwitchOnboardingModel(NDBaseModel):
    """Manage an integration association, not a physical inventory switch."""

    model_config = ConfigDict(str_strip_whitespace=False)
    identifiers: ClassVar[list[str]] = ["switch_id"]
    identifier_strategy: ClassVar[Literal["single"]] = "single"
    exclude_from_diff: ClassVar[set[str]] = {"switch_name"}

    switch_id: str = Field(alias="switchId", min_length=1, strict=True)
    integration_name: str | None = Field(default=None, alias="integrationName", min_length=1, strict=True)
    switch_name: str | None = Field(default=None, alias="switchName", min_length=1, strict=True)

    @model_validator(mode="after")
    def _validate_write_fields(self, info: ValidationInfo) -> SmartSwitchOnboardingModel:
        context = info.context or {}
        if context.get("mode") == "config" and context.get("state") in ("replaced", "overridden"):
            for field in ("integration_name", "switch_name"):
                if not getattr(self, field):
                    raise ValueError(f"{field} is required for onboarding")
        return self

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        return {
            "config": {
                "type": "list",
                "elements": "dict",
                "required": True,
                "options": {"switch_id": {"type": "str", "required": True}, "integration_name": {"type": "str"}, "switch_name": {"type": "str"}},
            },
            "state": {"type": "str", "default": "replaced", "choices": ["replaced", "overridden", "deleted"]},
        }
