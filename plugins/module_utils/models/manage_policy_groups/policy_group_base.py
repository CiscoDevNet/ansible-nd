# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Base Pydantic model for Policy Group API request bodies.

This module provides the foundational ``PolicyGroupCreate`` model.  All other
policy group models that extend or wrap ``PolicyGroupCreate`` live in separate files
and import from here.

The ``PolicyEntityType`` enum is reused from ``models.manage_policies.enums``.

## Schema origin

- ``PolicyGroupCreate``  ← ``createPolicyGroup`` (extends ``createBasePolicy`` + switchIds)
"""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import (
    PolicyEntityType,
)

# ============================================================================
# Policy Group Create Model (base for all CRUD body models)
# ============================================================================


class PolicyGroupCreate(NDBaseModel):
    """
    Request body model for creating a single policy group.

    ## Description

    Based on ``createPolicyGroup`` schema from the ND API specification which extends
    ``createBasePolicy`` with an additional required ``switchIds`` field.

    Unlike individual policies which target a single ``switchId``, policy groups
    target multiple switches via the ``switchIds`` list.

    ## API Endpoint

    POST /api/v1/manage/fabrics/{fabricName}/policyGroups

    ## Required Fields

    - switch_ids: List of switch serial numbers (e.g., ["FDO25031SY4", "FDO245206N5"])
    - template_name: Name of the policy template (e.g., "feature_enable")
    - entity_type: Type of entity (switch, configProfile, interface)
    - entity_name: Name of the entity (e.g., "SWITCH")

    ## Optional Fields

    - description: Policy group description (max 255 chars)
    - priority: Policy priority (1-2000, default 500)
    - source: Source of the policy (e.g., "UNDERLAY", "OVERLAY", "")
    - template_inputs: Name/value pairs passed to the template
    - secondary_entity_name: Secondary entity name (for configProfile)
    - secondary_entity_type: Secondary entity type

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import PolicyEntityType

    policy_group = PolicyGroupCreate(
        switch_ids=["FDO25031SY4", "FDO245206N5"],
        template_name="feature_enable",
        entity_type=PolicyEntityType.SWITCH,
        entity_name="SWITCH",
        template_inputs={"featureName": "lacp"},
        priority=500
    )
    payload = policy_group.to_request_dict()
    ```
    """

    # --- NDBaseModel ClassVars ---
    identifiers: ClassVar[list[str]] = ["description", "template_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"
    # Note: ``priority`` is intentionally NOT excluded — the base diff uses
    # ``exclude_none=True``, so an omitted priority on the user side is already
    # ignored, while an explicit priority change correctly triggers an update.
    exclude_from_diff: ClassVar[set] = {
        "source",
        "policy_id",
        "create_additional_policy",
    }
    payload_exclude_fields: ClassVar[set] = {"policy_id", "create_additional_policy"}

    # Server-generated policy group ID (populated from API responses)
    policy_id: str | None = Field(
        default=None,
        alias="policyId",
        description="Server-generated policy group ID (e.g., POLICY-GROUP-143310). Not sent in create/update payloads.",
    )

    # Required fields from createPolicyGroup schema
    switch_ids: list[str] = Field(
        default_factory=list,
        alias="switchIds",
        description="List of switch serial numbers (e.g., ['FDO25031SY4', 'FDO245206N5'])",
    )
    template_name: str = Field(
        ...,
        max_length=255,
        alias="templateName",
        description="Name of the policy template",
    )
    entity_type: PolicyEntityType = Field(
        default=PolicyEntityType.SWITCH,
        alias="entityType",
        description="Type of the entity (switch, configProfile, interface)",
    )
    entity_name: str = Field(
        default="SWITCH",
        max_length=255,
        alias="entityName",
        description="Name of the entity. Use 'SWITCH' for switch-level, or interface name for interface-level",
    )

    # Optional fields from createBasePolicy
    description: str | None = Field(
        default=None,
        max_length=255,
        description="Description of the policy group",
    )
    priority: int | None = Field(
        default=500,
        ge=0,  # 0 is the server-reset sentinel (controller zeroes the field for some
        # templates and echoes the value into templateInputs.PRIORITY instead).
        # User-visible range is 1-2000; 0 is never a valid user priority.
        le=2000,
        description="Priority of the policy group (1-2000). 0 is the server-reset sentinel.",
    )
    source: str | None = Field(
        default="",
        max_length=255,
        description="Source of the policy (UNDERLAY, OVERLAY, LINK, etc.). Empty means any source can update.",
    )
    template_inputs: dict[str, Any] | None = Field(
        default=None,
        alias="templateInputs",
        description="Name/value parameter list passed to the template",
    )
    secondary_entity_name: str | None = Field(
        default=None,
        alias="secondaryEntityName",
        description="Name of the secondary entity (e.g., overlay name for configProfile)",
    )

    # Module-only field (not sent to API)
    create_additional_policy: bool = Field(
        default=False,
        description="When True, always create a new policy group even if an identical one exists. Skips idempotency checks.",
    )
    secondary_entity_type: PolicyEntityType | None = Field(
        default=None,
        alias="secondaryEntityType",
        description="Type of the secondary entity",
    )

    @field_validator("switch_ids")
    @classmethod
    def validate_switch_ids(cls, v: list[str]) -> list[str]:
        """Validate that all switch IDs are non-empty strings."""
        if not v:
            return v
        for sid in v:
            if not isinstance(sid, str) or not sid.strip():
                raise ValueError(f"Invalid switch ID: {sid!r}. Must be a non-empty string.")
        return v

    # TODO(4.2.1): wire-shape-vs-schema workaround — the controller echoes the
    # user-set priority into ``templateInputs.PRIORITY`` and resets the top-level
    # ``priority`` field to 0 for some templates (e.g. ``switch_freeform``).  This
    # validator lifts the value back to the top level so that have/want comparisons
    # remain schema-consistent.  Remove once the controller stops doing this.
    @model_validator(mode="before")
    @classmethod
    def _normalize_priority_from_template_inputs(cls, data: Any) -> Any:
        """Normalize priority echoed by the controller into ``templateInputs.PRIORITY``.

        For some templates (e.g. ``switch_freeform``) the controller stores the
        user-set priority inside ``templateInputs.PRIORITY`` and zeroes out the
        top-level ``priority`` field in its GET response.  Without this
        normalization the ``have`` model (built from the API) and the ``want``
        model (built from gathered output round-trip) would compare unequally
        on either ``priority`` or ``template_inputs``, breaking idempotency.

        Normalization rules (applied symmetrically to both want and have):
          1. If ``templateInputs.PRIORITY`` is convertible to int AND top-level
             ``priority`` is the server-reset sentinel (None/0), lift it to
             top-level.  If the user explicitly set a non-zero top-level
             priority, respect it (the controller's stale echo loses).
          2. Always remove ``PRIORITY`` from ``template_inputs`` so the two
             sides compare equally on ``template_inputs``.

        User input never carries ``PRIORITY`` inside ``template_inputs`` (the
        argument spec exposes ``priority`` as a top-level field).  The only
        ``want`` path that has it is gathered round-trip, which lifts but does
        not strip; this validator strips on both sides for symmetry.
        """
        if not isinstance(data, dict):
            return data
        # Support both snake_case (from_config path) and camelCase (alias path)
        ti = data.get("template_inputs")
        ti_key = "template_inputs"
        if ti is None:
            ti = data.get("templateInputs")
            ti_key = "templateInputs"
        if not isinstance(ti, dict) or "PRIORITY" not in ti:
            return data

        new_data = dict(data)
        # Only lift to top-level when top-level is the server-reset sentinel.
        top_priority = data.get("priority")
        if top_priority in (None, 0, "0"):
            try:
                new_data["priority"] = int(ti["PRIORITY"])
            except (TypeError, ValueError):
                pass
        # Always strip PRIORITY from template_inputs for symmetric diff.
        new_ti = {k: v for k, v in ti.items() if k != "PRIORITY"}
        new_data[ti_key] = new_ti or None
        return new_data

    @classmethod
    def from_config(cls, ansible_config: dict[str, Any], **kwargs) -> "PolicyGroupCreate":
        """Create model instance from Ansible config dict.

        Handles the ``name`` → ``template_name`` translation so the user-facing
        arg_spec can use ``name`` while the model uses ``template_name``.

        Strips keys where Ansible injected default placeholders (None, 0, empty
        list) so that Pydantic's own defaults are used and ``model_fields_set``
        accurately reflects only user-provided fields.
        """
        config = dict(ansible_config)
        if "name" in config and "template_name" not in config:
            config["template_name"] = config.pop("name")
        # Remove Ansible-injected defaults so Pydantic defaults take effect.
        # Ansible injects None for unset str/dict/list, and 0 for unset int.
        config = {k: v for k, v in config.items() if v is not None and v != 0 and v != [] and v != {}}
        # Controller stringifies all templateInputs values after deploy
        # (e.g., int 5 → "5"). Normalize here so diff comparison works.
        if "template_inputs" in config and isinstance(config["template_inputs"], dict):
            config["template_inputs"] = {k: str(v) if not isinstance(v, str) else v for k, v in config["template_inputs"].items()}
        return cls.model_validate(config, by_name=True, **kwargs)

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return the Ansible argument spec for nd_manage_policy_group.

        Uses suboptions with no defaults for optional fields so that
        Ansible does not inject default values and Pydantic's
        ``model_fields_set`` accurately tracks user-provided fields.
        """
        return dict(
            fabric_name=dict(type="str", required=True, aliases=["fabric"]),
            deploy=dict(type="bool", default=True),
            config=dict(
                type="list",
                elements="dict",
                options=dict(
                    name=dict(type="str"),
                    policy_id=dict(type="str"),
                    description=dict(type="str"),
                    switch_ids=dict(type="list", elements="str"),
                    priority=dict(type="int"),
                    template_inputs=dict(type="dict"),
                    create_additional_policy=dict(type="bool", default=False),
                ),
            ),
            state=dict(type="str", default="merged", choices=["merged", "deleted", "gathered"]),
        )

    def to_request_dict(self) -> dict[str, Any]:
        """
        Convert model to API request dictionary with camelCase keys.

        Delegates to ``NDBaseModel.to_payload()`` for consistency.

        ## Returns

        Dictionary suitable for JSON request body, excluding None values.

        ## Example

        ```python
        policy_group = PolicyGroupCreate(
            switch_ids=["FDO123", "FDO456"],
            template_name="feature_enable",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH"
        )
        payload = policy_group.to_request_dict()
        # {"switchIds": ["FDO123", "FDO456"], "templateName": "feature_enable", ...}
        ```
        """
        return self.to_payload()
