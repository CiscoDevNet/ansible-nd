# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pydantic models for Policy CRUD request bodies.

This module provides ``PolicyCreateBulk`` (bulk create wrapper) and
``PolicyUpdate`` (update a single policy).  Both depend on the base
``PolicyCreate`` model defined in ``policy_base``.

## Schema origin

- ``PolicyCreateBulk`` ← wraps a list of ``createPolicy``
- ``PolicyUpdate``     ← ``policyPut`` (identical to ``createPolicy``)
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_base import (
    PolicyCreate,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)

# ============================================================================
# Policy Create Bulk Model
# ============================================================================


class PolicyCreateBulk(NDNestedModel):
    """
    Request body model for creating multiple policies in bulk.

    ## Description

    Wrapper for bulk policy creation via POST endpoint.

    ## API Endpoint

    POST /api/v1/manage/fabrics/{fabricName}/policies

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.policy_base import (
        PolicyCreate,
    )
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import (
        PolicyEntityType,
    )

    bulk = PolicyCreateBulk(policies=[
        PolicyCreate(
            switch_id="FDO123",
            template_name="feature_enable",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH",
            template_inputs={"featureName": "lacp"}
        ),
        PolicyCreate(
            switch_id="FDO456",
            template_name="power_redundancy",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH",
            template_inputs={"REDUNDANCY_MODE": "ps-redundant"}
        ),
    ])
    payload = bulk.to_request_dict()
    ```
    """

    identifiers: ClassVar[list[str]] = []

    policies: list[PolicyCreate] = Field(
        default_factory=list,
        min_length=1,
        description="List of policies to create",
    )

    def to_request_dict(self) -> dict[str, Any]:
        """
        Convert to API request dictionary.

        ## Returns

        Dictionary with 'policies' key containing list of policy dicts.
        """
        return {"policies": [policy.to_request_dict() for policy in self.policies]}


# ============================================================================
# Policy Update Model
# ============================================================================


class PolicyUpdate(PolicyCreate):
    """
    Request body model for updating a policy.

    ## Description

    Based on ``policyPut`` schema from the ND API specification which extends ``createPolicy``.
    Inherits all fields from ``PolicyCreate``.

    ## API Endpoint

    PUT /api/v1/manage/fabrics/{fabricName}/policies/{policyId}

    ## Note

    The policyId is passed as a path parameter, not in the request body.
    All fields from PolicyCreate are available for update.

    ## Usage

    ```python
    from .enums import PolicyEntityType

    update = PolicyUpdate(
        switch_id="FDO25031SY4",
        template_name="feature_enable",
        entity_type=PolicyEntityType.SWITCH,
        entity_name="SWITCH",
        template_inputs={"featureName": "lacp"},
        priority=100,
        description="Updated policy description"
    )
    payload = update.to_request_dict()
    ```
    """

    # All fields inherited from PolicyCreate
    # policyPut schema is identical to createPolicy per the ND API specification
