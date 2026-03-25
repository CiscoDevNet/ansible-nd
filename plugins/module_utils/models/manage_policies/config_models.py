# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pydantic models for validating Ansible playbook input (user-facing config).

These models validate user input **before** any API calls or config translation.
They enforce constraints from the OpenAPI spec (manage.json ``createBasePolicy``
schema) at the playbook boundary so errors are caught early with clear messages.

Schema constraints (source: manage.json createBasePolicy):
    - priority: integer, min=1, max=2000, default=500
    - description: string, maxLength=255
    - templateName: string, maxLength=255

Usage in nd_policy.py main()::

    from .models.manage_policies.config_models import PlaybookPolicyConfig

    for idx, entry in enumerate(module.params["config"]):
        PlaybookPolicyConfig.model_validate(
            entry,
            context={"state": state, "use_desc_as_key": use_desc_as_key},
        )
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, ClassVar, Dict, List, Optional

from pydantic import ValidationInfo, model_validator
from typing_extensions import Self

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


# ============================================================================
# Per-switch policy override (switch[].policies[] entry)
# ============================================================================


class PlaybookSwitchPolicyConfig(NDNestedModel):
    """Validates a per-switch policy override entry.

    Corresponds to ``config[].switch[].policies[]`` in the playbook.

    OpenAPI constraints applied:
        - name: maxLength=255 (templateName)
        - description: maxLength=255
        - priority: 1–2000 (createBasePolicy.priority)
    """

    identifiers: ClassVar[List[str]] = []

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Template name or policy ID (e.g., 'switch_freeform', 'POLICY-12345')",
    )
    description: str = Field(
        default="",
        max_length=255,
        description="Policy description (max 255 characters)",
    )
    priority: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Policy priority (1–2000, default 500)",
    )
    create_additional_policy: bool = Field(
        default=True,
        description="Create a new policy even if an identical one already exists",
    )
    template_inputs: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Name/value pairs passed to the policy template",
    )


# ============================================================================
# Switch list entry (config[].switch[] entry)
# ============================================================================


class PlaybookSwitchEntry(NDNestedModel):
    """Validates a switch entry within the config.

    Corresponds to ``config[].switch[]`` in the playbook.
    Accepts ``serial_number`` or the backward-compatible alias ``ip``.
    """

    identifiers: ClassVar[List[str]] = []

    serial_number: str = Field(
        ...,
        min_length=1,
        description="Switch serial number, management IP, or hostname",
    )
    policies: Optional[List[PlaybookSwitchPolicyConfig]] = Field(
        default_factory=list,
        description="Per-switch policy overrides",
    )

    @model_validator(mode="before")
    @classmethod
    def accept_ip_alias(cls, values: Any) -> Any:
        """Accept ``ip`` as a backward-compatible alias for ``serial_number``.

        If the user provides ``ip`` but not ``serial_number``, copy the value
        so validation succeeds on the canonical field name.

        Args:
            values: Raw input dict before field validation.

        Returns:
            The (possibly mutated) input dict with ``serial_number`` set.
        """
        if isinstance(values, dict):
            if "serial_number" not in values and "ip" in values:
                values["serial_number"] = values["ip"]
        return values


# ============================================================================
# Top-level config entry (config[] entry)
# ============================================================================


class PlaybookPolicyConfig(NDNestedModel):
    """Validates a top-level config entry from the Ansible playbook.

    Corresponds to ``config[]`` in the playbook. Supports two kinds of
    entries:

    1. **Policy entry** — has ``name`` (template name or policy ID) plus
       optional description, priority, template_inputs.
    2. **Switch entry** — has ``switch`` list only (no ``name``). Used to
       declare which switches receive the global policies.

    Context-aware validation (pass via ``model_validate(..., context={})``:
        - ``state``: The module state (merged, deleted, query).
        - ``use_desc_as_key``: Whether descriptions are used as unique keys.

    OpenAPI constraints applied:
        - name: maxLength=255 (templateName)
        - description: maxLength=255
        - priority: 1–2000 (createBasePolicy.priority)
    """

    identifiers: ClassVar[List[str]] = []

    name: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Template name or policy ID",
    )
    description: str = Field(
        default="",
        max_length=255,
        description="Policy description (max 255 characters)",
    )
    priority: int = Field(
        default=500,
        ge=1,
        le=2000,
        description="Policy priority (1–2000, default 500)",
    )
    create_additional_policy: bool = Field(
        default=True,
        description="Create a new policy even if an identical one already exists",
    )
    template_inputs: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Name/value pairs passed to the policy template",
    )
    switch: Optional[List[PlaybookSwitchEntry]] = Field(
        default=None,
        description="List of target switches with optional per-switch policy overrides",
    )

    @model_validator(mode="after")
    def validate_state_requirements(self, info: ValidationInfo) -> Self:
        """Apply state-aware validation using context.

        When ``context={"state": "merged", "use_desc_as_key": True}`` is
        passed to ``model_validate()``:

        - **merged + policy entry**: ``name`` is required.
        - **use_desc_as_key + merged/deleted + template name**: ``description``
          must be non-empty.

        Switch-only entries (``name`` is None, ``switch`` is present) skip
        these checks since they only declare target switches.

        Args:
            info: Pydantic ``ValidationInfo`` carrying the context dict.

        Returns:
            The validated model instance (``self``).

        Raises:
            ValueError: If required fields are missing for the given state.
        """
        ctx = info.context or {} if info else {}
        state = ctx.get("state")
        use_desc_as_key = ctx.get("use_desc_as_key", False)

        # Switch-only entry — no policy fields to validate
        if self.name is None and self.switch is not None:
            return self

        # For merged state, name is required on policy entries
        if state == "merged" and self.name is None and self.switch is None:
            raise ValueError(
                "'name' (template name or policy ID) is required for "
                "state=merged. Provide a template name like 'switch_freeform' "
                "or a policy ID like 'POLICY-12345'."
            )

        # When use_desc_as_key=true, description must not be empty for
        # template-name entries (not policy IDs) in merged/deleted states.
        if (
            use_desc_as_key
            and state in ("merged", "deleted")
            and self.name
            and not self.name.startswith("POLICY-")
            and not self.description
        ):
            raise ValueError(
                f"'description' cannot be empty when use_desc_as_key=true "
                f"and name is a template name ('{self.name}'). "
                f"Provide a unique description for each policy "
                f"or set use_desc_as_key=false."
            )

        return self

    @classmethod
    def get_argument_spec(cls) -> Dict[str, Any]:
        """Return the Ansible argument spec for nd_policy.

        Returns:
            Dict suitable for passing to ``AnsibleModule(argument_spec=...)``.
        """
        return dict(
            fabric_name=dict(type="str", required=True, aliases=["fabric"]),
            config=dict(type="list", elements="dict", required=True),
            use_desc_as_key=dict(type="bool", default=False),
            deploy=dict(type="bool", default=True),
            ticket_id=dict(type="str"),
            cluster_name=dict(type="str"),
            state=dict(type="str", default="merged", choices=["merged", "deleted", "query"]),
        )


__all__ = [
    "PlaybookPolicyConfig",
    "PlaybookSwitchEntry",
    "PlaybookSwitchPolicyConfig",
]
