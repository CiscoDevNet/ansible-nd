# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Base Pydantic model for Policy API request bodies.

This module provides the foundational ``PolicyCreate`` model.  All other
policy models that extend or wrap ``PolicyCreate`` live in separate files
and import from here.

The ``PolicyEntityType`` enum is in ``enums.py``.

## Schema origin

- ``PolicyCreate``     ← ``createPolicy`` (extends ``createBasePolicy``)
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

from .enums import PolicyEntityType

# ============================================================================
# Policy Create Model (base for all CRUD body models)
# ============================================================================


class PolicyCreate(NDBaseModel):
    """
    Request body model for creating a single policy.

    ## Description

    Based on ``createPolicy`` schema from the ND API specification which extends
    ``createBasePolicy``.

    ## API Endpoint

    POST /api/v1/manage/fabrics/{fabricName}/policies

    ## Required Fields

    - switch_id: Switch serial number (e.g., "FDO25031SY4")
    - template_name: Name of the policy template (e.g., "switch_freeform", "feature_enable")
    - entity_type: Type of entity (switch, configProfile, interface)
    - entity_name: Name of the entity (e.g., "SWITCH", "Ethernet1/1")

    ## Optional Fields

    - description: Policy description (max 255 chars)
    - priority: Policy priority (1-2000, default 500)
    - source: Source of the policy (e.g., "UNDERLAY", "OVERLAY", "")
    - template_inputs: Name/value pairs passed to the template
    - secondary_entity_name: Secondary entity name (for configProfile)
    - secondary_entity_type: Secondary entity type

    ## Usage

    ```python
    from .enums import PolicyEntityType

    policy = PolicyCreate(
        switch_id="FDO25031SY4",
        template_name="feature_enable",
        entity_type=PolicyEntityType.SWITCH,
        entity_name="SWITCH",
        template_inputs={"featureName": "lacp"},
        priority=500
    )
    payload = policy.to_request_dict()
    ```
    """

    # --- NDBaseModel ClassVars ---
    identifiers: ClassVar[list[str]] = ["switch_id", "template_name", "description"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "composite"
    exclude_from_diff: ClassVar[set] = {"source"}

    # Required fields from createPolicy schema
    switch_id: str = Field(
        ...,
        alias="switchId",
        description="Switch serial number (e.g., FDO25031SY4)",
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

    # Optional fields
    description: str | None = Field(
        default=None,
        max_length=255,
        description="Description of the policy",
    )
    priority: int | None = Field(
        default=500,
        ge=1,
        le=2000,
        description="Priority of the policy (1-2000)",
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
    secondary_entity_type: PolicyEntityType | None = Field(
        default=None,
        alias="secondaryEntityType",
        description="Type of the secondary entity",
    )

    def to_request_dict(self) -> dict[str, Any]:
        """
        Convert model to API request dictionary with camelCase keys.

        Delegates to ``NDBaseModel.to_payload()`` for consistency.

        ## Returns

        Dictionary suitable for JSON request body, excluding None values.

        ## Example

        ```python
        policy = PolicyCreate(
            switch_id="FDO123",
            template_name="feature_enable",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH"
        )
        payload = policy.to_request_dict()
        # {"switchId": "FDO123", "templateName": "feature_enable", ...}
        ```
        """
        return self.to_payload()
