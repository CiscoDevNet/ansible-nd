# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Internal state-machine identity for policy-group execution."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)


class PolicyGroupExecution(PolicyGroupCreate):
    """Use the resolved controller ID without changing the public create model.

    New groups retain their initial composite execution key after the controller
    assigns ``policy_id``. Collection indexes therefore remain valid throughout
    one execution. The key is never included in public output or API payloads.
    """

    identifiers: ClassVar[list[str]] = ["execution_key"]
    identifier_strategy: ClassVar[Literal["single"]] = "single"
    exclude_from_diff: ClassVar[set] = PolicyGroupCreate.exclude_from_diff | {"execution_key"}
    payload_exclude_fields: ClassVar[set] = PolicyGroupCreate.payload_exclude_fields | {"execution_key"}

    execution_key: tuple[str, ...] | None = Field(default=None, exclude=True, repr=False)

    @model_validator(mode="before")
    @classmethod
    def initialize_execution_key(cls, data: Any) -> Any:
        """Assign a key once; assignment validation must not retarget a model."""
        if not isinstance(data, dict) or data.get("execution_key") is not None:
            return data
        values = dict(data)
        policy_id = values.get("policy_id") or values.get("policyId")
        if policy_id:
            values["execution_key"] = ("policy_id", policy_id)
        elif values.get("description") is not None:
            template_name = values.get("template_name") or values.get("templateName")
            description = values["description"]
            if isinstance(description, str):
                description = description.strip()
            if isinstance(template_name, str):
                template_name = template_name.strip()
            values["execution_key"] = ("create", description, template_name or "")
        return values
