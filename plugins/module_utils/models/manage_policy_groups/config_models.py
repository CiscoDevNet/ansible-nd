# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for validating Ansible playbook input (user-facing config)
for the nd_policy_group module.

These models validate user input **before** any API calls or config translation.
They enforce constraints from the ND API specification (``createPolicyGroup``
schema which extends ``createBasePolicy``) at the playbook boundary so errors
are caught early with clear messages.

Each config entry directly specifies the ``switch_ids`` list alongside the
policy template fields — there is no two-level global + per-switch override
structure (unlike ``nd_policy``).

Policy groups are identified by **description** (``use_desc_as_key=true``,
the default and recommended mode) because the ``POLICY-GROUP-xxxxx`` ID is
auto-generated internally and not user-facing.  The module flow is:

1. User provides ``name`` (template name) + ``description`` + ``switch_ids``.
2. On the controller, ``GET /policyGroups`` with a Lucene filter on
   ``description`` retrieves any existing policy group with that description.
3. If a match is found, its ``policyId`` (``POLICY-GROUP-xxxxx``) is used
   for ``PUT`` (update) or ``markDelete`` / ``remove`` (delete).
4. If no match is found, ``POST`` creates a new policy group.

When ``use_desc_as_key=false``, the user must provide a ``POLICY-GROUP-xxxxx``
ID directly in the ``name`` field for update/delete operations, because
template names alone are not unique.

Schema constraints (source: ND API specification, createPolicyGroup):
    - template_name (name): string, maxLength=255, required for merged
    - description: string, maxLength=255, unique identifier when use_desc_as_key=true
    - priority: integer, min=1, max=2000, default=500
    - switch_ids: list of switch serial numbers, required for merged
    - template_inputs: dict of name/value pairs

Usage in nd_policy_group.py main()::

    from .models.manage_policy_groups.config_models import PlaybookPolicyGroupConfig

    for idx, entry in enumerate(module.params["config"]):
        PlaybookPolicyGroupConfig.model_validate(
            entry,
            context={"state": state, "use_desc_as_key": use_desc_as_key},
        )
"""

from __future__ import annotations

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    ValidationInfo,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)

# ============================================================================
# Helper
# ============================================================================


def _is_policy_group_id(name: str) -> bool:
    """Return True if ``name`` looks like an auto-generated policy group ID.

    Policy group IDs follow the pattern ``POLICY-GROUP-<digits>``.

    Args:
        name: The name string to check.

    Returns:
        True if it matches the POLICY-GROUP-xxxxx pattern.
    """
    return name.startswith("POLICY-GROUP-") if name else False


# ============================================================================
# Top-level config entry (config[] entry)
# ============================================================================


class PlaybookPolicyGroupConfig(NDNestedModel):
    """Validates a top-level config entry from the Ansible playbook for policy groups.

    Corresponds to ``config[]`` in the nd_policy_group playbook.

    Each entry represents a single policy group definition containing:
    - ``name``: Template name or policy group ID (e.g., ``POLICY-GROUP-143310``)
    - ``description``: Policy group description (used as unique key by default)
    - ``priority``: Policy priority (1–2000)
    - ``template_inputs``: Template parameters
    - ``switch_ids``: List of target switch serial numbers

    Identification strategy:
    - When ``use_desc_as_key=true`` (default): The ``description`` uniquely
      identifies the policy group.  The module queries the controller by
      description (via Lucene filter on ``GET /policyGroups``) to resolve the
      internal ``POLICY-GROUP-xxxxx`` ID for update/delete operations.
      In-place updates are fully supported.
    - When ``use_desc_as_key=false``: The user must provide the
      ``POLICY-GROUP-xxxxx`` ID in the ``name`` field for update/delete.
      Template names alone cannot uniquely identify a policy group.

    Context-aware validation (pass via ``model_validate(..., context={})``:
        - ``state``: The module state (merged, deleted, gathered).
        - ``use_desc_as_key``: Whether descriptions are used as unique keys.

    OpenAPI constraints applied:
        - name: maxLength=255 (templateName)
        - description: maxLength=255
        - priority: 1–2000 (createBasePolicy.priority)
    """

    identifiers: ClassVar[list[str]] = []

    name: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "Template name or policy group ID. "
            "Template name (e.g., 'feature_enable') for creating new policy groups. "
            "Policy group ID (e.g., 'POLICY-GROUP-143310') for updating or "
            "deleting existing ones when use_desc_as_key=false."
        ),
    )
    description: str = Field(
        default="",
        max_length=255,
        description=(
            "Policy group description (max 255 characters). "
            "When use_desc_as_key=true (default), this serves as the unique "
            "identifier for the policy group and must be non-empty and unique "
            "across all policy groups in the fabric."
        ),
    )
    priority: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Policy priority (1–2000, default 500)",
    )
    template_inputs: dict[str, Any] | None = Field(
        default_factory=dict,
        description="Name/value pairs passed to the policy template",
    )
    switch_ids: list[str] | None = Field(
        default=None,
        description=(
            "List of target switch serial numbers, management IPs, or hostnames "
            "(e.g., ['FDO25031SY4', 'FDO245206N5']). "
            "Required for state=merged."
        ),
    )

    @field_validator("switch_ids")
    @classmethod
    def validate_switch_ids(cls, v: list[str] | None) -> list[str] | None:
        """Validate that switch IDs, when provided, are non-empty strings.

        Args:
            v: List of switch identifiers or None.

        Returns:
            The validated list, or None if not provided.

        Raises:
            ValueError: If any switch ID is empty or not a string.
        """
        if v is None:
            return v
        for idx, sid in enumerate(v):
            if not isinstance(sid, str) or not sid.strip():
                raise ValueError(
                    f"switch_ids[{idx}]: Invalid switch identifier {sid!r}. "
                    f"Must be a non-empty string (serial number, IP, or hostname)."
                )
        return v

    @model_validator(mode="after")
    def validate_state_requirements(
        self, info: ValidationInfo
    ) -> "PlaybookPolicyGroupConfig":
        """Apply state-aware validation using context.

        When ``context={"state": "merged", "use_desc_as_key": True}`` is
        passed to ``model_validate()``:

        - **merged**: ``name`` (template name) and ``switch_ids`` are required.
        - **merged + use_desc_as_key**: ``description`` must be non-empty when
          ``name`` is a template name (not a POLICY-GROUP-xxxxx ID).
        - **deleted + use_desc_as_key**: ``description`` must be non-empty when
          ``name`` is a template name.  Alternatively, the user can provide a
          ``POLICY-GROUP-xxxxx`` ID directly in ``name``.
        - **gathered**: No requirements; all fields are optional.

        Args:
            info: Pydantic ``ValidationInfo`` carrying the context dict.

        Returns:
            The validated model instance (``self``).

        Raises:
            ValueError: If required fields are missing for the given state.
        """
        ctx = info.context or {} if info else {}
        state = ctx.get("state")
        use_desc_as_key = ctx.get("use_desc_as_key", True)

        if state == "merged":
            if not self.name:
                raise ValueError(
                    "'name' (template name or policy group ID) is required for "
                    "state=merged. Provide a template name like 'feature_enable' "
                    "or a policy group ID like 'POLICY-GROUP-143310'."
                )
            if not self.switch_ids:
                raise ValueError(
                    "'switch_ids' is required for state=merged. "
                    "Provide at least one switch serial number, IP, or hostname."
                )

        # When use_desc_as_key=true, description must not be empty for
        # template-name entries (not policy group IDs) in merged/deleted states.
        if (
            use_desc_as_key
            and state in ("merged", "deleted")
            and self.name
            and not _is_policy_group_id(self.name)
            and not self.description
        ):
            raise ValueError(
                f"'description' cannot be empty when use_desc_as_key=true "
                f"and name is a template name ('{self.name}'). "
                f"Provide a unique description for each policy group "
                f"or set use_desc_as_key=false."
            )

        return self

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return the Ansible argument spec for nd_policy_group.

        Returns:
            Dict suitable for passing to ``AnsibleModule(argument_spec=...)``.
        """
        return dict(
            fabric_name=dict(type="str", required=True, aliases=["fabric"]),
            config=dict(type="list", elements="dict"),
            use_desc_as_key=dict(type="bool", default=True),
            deploy=dict(type="bool", default=True),
            ticket_id=dict(type="str"),
            cluster_name=dict(type="str"),
            state=dict(
                type="str", default="merged", choices=["merged", "deleted", "gathered"]
            ),
        )


__all__ = [
    "PlaybookPolicyGroupConfig",
]
