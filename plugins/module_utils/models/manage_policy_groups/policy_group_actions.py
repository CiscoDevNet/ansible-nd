# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pydantic model for policy group bulk-action request bodies.

This module provides ``PolicyGroupIds``, the request body used by the
policy group action endpoints:

- POST /api/v1/manage/fabrics/{fabricName}/policyGroups/actions/markDelete
- POST /api/v1/manage/fabrics/{fabricName}/policyGroups/actions/remove

## Schema origin

- ``PolicyGroupIds`` ← ``policyIds`` array in the request body per ND API specification
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

__author__ = "L Nikhil Sri Krishna"

from typing import Any, ClassVar, Dict, List

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


class PolicyGroupIds(NDNestedModel):
    """
    Request body model for policy group bulk actions.

    ## Description

    Used for markDelete and remove policy group actions.
    Contains a list of policy group IDs to perform the action on.

    ## API Endpoints

    - POST /api/v1/manage/fabrics/{fabricName}/policyGroups/actions/markDelete
    - POST /api/v1/manage/fabrics/{fabricName}/policyGroups/actions/remove

    ## Request Body Schema

    ```json
    {
        "policyIds": ["POLICY-GROUP-121110", "POLICY-GROUP-121120"]
    }
    ```

    ## Usage

    ```python
    # Mark-delete policy groups
    body = PolicyGroupIds(policy_ids=["POLICY-GROUP-121110", "POLICY-GROUP-121120"])
    payload = body.to_request_dict()
    # {"policyIds": ["POLICY-GROUP-121110", "POLICY-GROUP-121120"]}

    # Remove/delete policy groups
    body = PolicyGroupIds(policy_ids=["POLICY-GROUP-143310", "POLICY-GROUP-143320"])
    payload = body.to_request_dict()
    ```
    """

    identifiers: ClassVar[List[str]] = []

    policy_ids: List[str] = Field(
        default_factory=list,
        min_length=1,
        alias="policyIds",
        description="List of policy group IDs to perform action on",
    )

    @field_validator("policy_ids")
    @classmethod
    def validate_policy_ids(cls, v: List[str]) -> List[str]:
        """
        Validate that all policy group IDs are non-empty strings.

        ## Parameters

        - v: List of policy group IDs

        ## Returns

        - Validated list of policy group IDs

        ## Raises

        - ValueError: If any policy group ID is empty or not a string
        """
        if not v:
            raise ValueError("policy_ids must contain at least one policy group ID")
        for policy_id in v:
            if not isinstance(policy_id, str) or not policy_id.strip():
                raise ValueError(f"Invalid policy group ID: {policy_id!r}. Must be a non-empty string.")
        return v

    def to_request_dict(self) -> Dict[str, Any]:
        """
        Convert to API request dictionary with camelCase keys.

        Delegates to ``NDBaseModel.to_payload()`` for consistency.

        ## Returns

        Dictionary suitable for JSON request body.

        ## Example

        ```python
        body = PolicyGroupIds(policy_ids=["POLICY-GROUP-123", "POLICY-GROUP-456"])
        payload = body.to_request_dict()
        # {"policyIds": ["POLICY-GROUP-123", "POLICY-GROUP-456"]}
        ```
        """
        return self.to_payload()
