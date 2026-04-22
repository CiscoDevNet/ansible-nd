# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pydantic model for policy bulk-action request bodies.

This module provides ``PolicyIds``, the request body used by all three
policy action endpoints:

- POST /api/v1/manage/fabrics/{fabricName}/policyActions/markDelete
- POST /api/v1/manage/fabrics/{fabricName}/policyActions/pushConfig
- POST /api/v1/manage/fabrics/{fabricName}/policyActions/remove

## Schema origin

- ``PolicyIds`` ← ``policyActions`` request body schema per ND API specification
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)


class SwitchIds(NDNestedModel):
    """
    Request body model for switch-level deploy action.

    ## Description

    Used for ``POST /fabrics/{fabricName}/switchActions/deploy``.
    Contains a list of switch serial numbers to deploy config to.

    ## Request Body Schema

    ```json
    {
      "switchIds": ["FOC21373AFA", "FVT93126SKE"]
    }
    ```

    ## Usage

    ```python
    body = SwitchIds(switch_ids=["FOC21373AFA", "FVT93126SKE"])
    payload = body.to_request_dict()
    # {"switchIds": ["FOC21373AFA", "FVT93126SKE"]}
    ```
    """

    identifiers: ClassVar[list[str]] = []

    switch_ids: list[str] = Field(
        default_factory=list,
        min_length=1,
        alias="switchIds",
        description="List of switch serial numbers to deploy config to",
    )

    @field_validator("switch_ids")
    @classmethod
    def validate_switch_ids(cls, v: list[str]) -> list[str]:
        """Validate that all switch IDs are non-empty strings."""
        if not v:
            raise ValueError("switch_ids must contain at least one switch ID")
        for sid in v:
            if not isinstance(sid, str) or not sid.strip():
                raise ValueError(f"Invalid switch ID: {sid!r}. Must be a non-empty string.")
        return v

    def to_request_dict(self) -> dict[str, Any]:
        """Convert to API request dictionary with camelCase keys."""
        return self.to_payload()


class PolicyIds(NDNestedModel):
    """
    Request body model for policy bulk actions.

    ## Description

    Used for markDelete, pushConfig, and remove policy actions.
    Contains a list of policy IDs to perform the action on.

    ## API Endpoints

    - POST /api/v1/manage/fabrics/{fabricName}/policyActions/markDelete
    - POST /api/v1/manage/fabrics/{fabricName}/policyActions/pushConfig
    - POST /api/v1/manage/fabrics/{fabricName}/policyActions/remove

    ## Request Body Schema

    ```json
    {
      "policyIds": ["POLICY-121110", "POLICY-121120"]
    }
    ```

    ## Usage

    ```python
    # Mark-delete policies
    body = PolicyIds(policy_ids=["POLICY-121110", "POLICY-121120"])
    payload = body.to_request_dict()
    # {"policyIds": ["POLICY-121110", "POLICY-121120"]}

    # Push config for policies
    body = PolicyIds(policy_ids=["POLICY-121110"])
    payload = body.to_request_dict()

    # Remove/delete policies
    body = PolicyIds(policy_ids=["POLICY-121110", "POLICY-121120", "POLICY-121130"])
    payload = body.to_request_dict()
    ```
    """

    identifiers: ClassVar[list[str]] = []

    policy_ids: list[str] = Field(
        default_factory=list,
        min_length=1,
        alias="policyIds",
        description="List of policy IDs to perform action on",
    )

    @field_validator("policy_ids")
    @classmethod
    def validate_policy_ids(cls, v: list[str]) -> list[str]:
        """
        Validate that all policy IDs are non-empty strings.

        ## Parameters

        - v: List of policy IDs

        ## Returns

        - Validated list of policy IDs

        ## Raises

        - ValueError: If any policy ID is empty or not a string
        """
        if not v:
            raise ValueError("policy_ids must contain at least one policy ID")
        for policy_id in v:
            if not isinstance(policy_id, str) or not policy_id.strip():
                raise ValueError(f"Invalid policy ID: {policy_id!r}. Must be a non-empty string.")
        return v

    def to_request_dict(self) -> dict[str, Any]:
        """
        Convert to API request dictionary with camelCase keys.

        Delegates to ``NDBaseModel.to_payload()`` for consistency.

        ## Returns

        Dictionary suitable for JSON request body.

        ## Example

        ```python
        body = PolicyIds(policy_ids=["POLICY-123", "POLICY-456"])
        payload = body.to_request_dict()
        # {"policyIds": ["POLICY-123", "POLICY-456"]}
        ```
        """
        return self.to_payload()
