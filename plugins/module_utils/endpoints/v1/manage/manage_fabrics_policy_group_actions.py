# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Policy Group Actions endpoint models.

This module contains endpoint definitions for policy group action operations
in the ND Manage API.

Endpoints covered:
- POST /fabrics/{fabricName}/policyGroups/actions/markDelete  - Mark-delete policy groups
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# ============================================================================
# Query parameter classes
# ============================================================================


class PolicyGroupActionMutationEndpointParams(EndpointQueryParams):
    """
    # Summary

    Shared query parameters for policy group action mutation endpoints.

    ## Description

    Per the ND API specification, the following policy group action endpoints accept
    ``clusterName`` and ``ticketId``:

    - POST /policyGroups/actions/markDelete

    ## Parameters

    - cluster_name → clusterName
    - ticket_id   → ticketId
    """

    model_config = ConfigDict(extra="forbid")

    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )
    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z][a-zA-Z0-9_-]+$",
        description="Change Control Ticket Id",
    )


# ============================================================================
# Base class for /fabrics/{fabricName}/policyGroups/actions/{action}
# ============================================================================


class _EpManagePolicyGroupActionsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Policy Group Actions endpoints.

    Provides the common base path builder for all HTTP methods on the
    ``/api/v1/manage/fabrics/{fabricName}/policyGroups/actions/{action}`` endpoints.
    """

    def _action_path(self, action: str) -> str:
        """Build the base endpoint path for a specific action."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path(
            "fabrics", self.fabric_name, "policyGroups", "actions", action
        )


# ============================================================================
# POST /fabrics/{fabricName}/policyGroups/actions/markDelete
# ============================================================================


class EpManagePolicyGroupActionsMarkDeletePost(_EpManagePolicyGroupActionsBase):
    """
    # Summary

    ND Manage Policy Group Actions — Mark Delete Endpoint

    ## Description

    Mark-delete policy groups in bulk.  This flags policy groups for deletion
    without immediately removing them from the controller.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyGroups/actions/markDelete

    ## Verb

    - POST

    ## Usage

    ```python
    ep = EpManagePolicyGroupActionsMarkDeletePost()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "policyIds": ["POLICY-GROUP-121110", "POLICY-GROUP-121120"]
    }
    ```
    """

    class_name: Literal["EpManagePolicyGroupActionsMarkDeletePost"] = Field(
        default="EpManagePolicyGroupActionsMarkDeletePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyGroupActionMutationEndpointParams = Field(
        default_factory=PolicyGroupActionMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        base = self._action_path("markDelete")
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
