# -*- coding: utf-8 -*-

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

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

__author__ = "L Nikhil Sri Krishna"

from typing import Any, ClassVar, Dict, List, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import PolicyEntityType

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
    identifiers: ClassVar[List[str]] = ["switch_ids", "template_name", "description"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "composite"
    exclude_from_diff: ClassVar[set] = {"source"}

    # Required fields from createPolicyGroup schema
    switch_ids: List[str] = Field(
        ...,
        alias="switchIds",
        min_length=1,
        description="List of switch serial numbers (e.g., ['FDO25031SY4', 'FDO245206N5'])",
    )
    template_name: str = Field(
        ...,
        max_length=255,
        alias="templateName",
        description="Name of the policy template",
    )
    entity_type: PolicyEntityType = Field(
        ...,
        alias="entityType",
        description="Type of the entity (switch, configProfile, interface)",
    )
    entity_name: str = Field(
        ...,
        max_length=255,
        alias="entityName",
        description="Name of the entity. Use 'SWITCH' for switch-level, or interface name for interface-level",
    )

    # Optional fields from createBasePolicy
    description: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Description of the policy group",
    )
    priority: Optional[int] = Field(
        default=500,
        ge=1,
        le=2000,
        description="Priority of the policy group (1-2000)",
    )
    source: Optional[str] = Field(
        default="",
        max_length=255,
        description="Source of the policy (UNDERLAY, OVERLAY, LINK, etc.). Empty means any source can update.",
    )
    template_inputs: Optional[Dict[str, Any]] = Field(
        default=None,
        alias="templateInputs",
        description="Name/value parameter list passed to the template",
    )
    secondary_entity_name: Optional[str] = Field(
        default=None,
        alias="secondaryEntityName",
        description="Name of the secondary entity (e.g., overlay name for configProfile)",
    )
    secondary_entity_type: Optional[PolicyEntityType] = Field(
        default=None,
        alias="secondaryEntityType",
        description="Type of the secondary entity",
    )

    @field_validator("switch_ids")
    @classmethod
    def validate_switch_ids(cls, v: List[str]) -> List[str]:
        """Validate that all switch IDs are non-empty strings."""
        if not v:
            raise ValueError("switch_ids must contain at least one switch ID")
        for sid in v:
            if not isinstance(sid, str) or not sid.strip():
                raise ValueError(f"Invalid switch ID: {sid!r}. Must be a non-empty string.")
        return v

    def to_request_dict(self) -> Dict[str, Any]:
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
