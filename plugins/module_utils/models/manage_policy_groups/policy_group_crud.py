# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Pydantic models for Policy Group CRUD request bodies.

This module provides ``PolicyGroupCreateBulk`` (bulk create wrapper) and
``PolicyGroupUpdate`` (update a single policy group).  Both depend on the base
``PolicyGroupCreate`` model defined in ``policy_group_base``.

## Schema origin

- ``PolicyGroupCreateBulk`` ← wraps a list of ``createPolicyGroup``
- ``PolicyGroupUpdate``     ← ``putPolicyGroup`` (identical to ``createPolicyGroup``)
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
    PolicyGroupCreate,
)

# ============================================================================
# Policy Group Create Bulk Model
# ============================================================================


class PolicyGroupCreateBulk(NDNestedModel):
    """
    Request body model for creating multiple policy groups in bulk.

    ## Description

    Wrapper for bulk policy group creation via POST endpoint.

    ## API Endpoint

    POST /api/v1/manage/fabrics/{fabricName}/policyGroups

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policy_groups.policy_group_base import (
        PolicyGroupCreate,
    )
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import (
        PolicyEntityType,
    )

    bulk = PolicyGroupCreateBulk(policy_groups=[
        PolicyGroupCreate(
            switch_ids=["FDO25031SY4", "FDO245206N5"],
            template_name="feature_enable",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH",
            template_inputs={"featureName": "lacp"}
        ),
        PolicyGroupCreate(
            switch_ids=["FDO25031SY4", "FDO245206N5"],
            template_name="feature_enable",
            entity_type=PolicyEntityType.SWITCH,
            entity_name="SWITCH",
            template_inputs={"featureName": "lldp"}
        ),
    ])
    payload = bulk.to_request_dict()
    ```
    """

    identifiers: ClassVar[list[str]] = []

    policy_groups: list[PolicyGroupCreate] = Field(
        default_factory=list,
        min_length=1,
        alias="policyGroups",
        description="List of policy groups to create",
    )

    def to_request_dict(self) -> dict[str, Any]:
        """
        Convert to API request dictionary.

        ## Returns

        Dictionary with 'policyGroups' key containing list of policy group dicts.
        """
        return {"policyGroups": [pg.to_request_dict() for pg in self.policy_groups]}


# ============================================================================
# Policy Group Update Model
# ============================================================================


class PolicyGroupUpdate(PolicyGroupCreate):
    """
    Request body model for updating a policy group.

    ## Description

    Based on ``putPolicyGroup`` schema from the ND API specification which extends
    ``createPolicyGroup``.  Inherits all fields from ``PolicyGroupCreate``.

    ## API Endpoint

    PUT /api/v1/manage/fabrics/{fabricName}/policyGroups/{policyGroupId}

    ## Note

    The policyGroupId is passed as a path parameter, not in the request body.
    All fields from PolicyGroupCreate are available for update.

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_policies.enums import PolicyEntityType

    update = PolicyGroupUpdate(
        switch_ids=["FDO245206N5", "FDO245206N9"],
        template_name="feature_enable",
        entity_type=PolicyEntityType.SWITCH,
        entity_name="SWITCH",
        template_inputs={"featureName": "lacp"},
        priority=50,
        description="Update priority value for group policy"
    )
    payload = update.to_request_dict()
    ```
    """

    # All fields inherited from PolicyGroupCreate
    # putPolicyGroup schema is identical to createPolicyGroup per the ND API specification
