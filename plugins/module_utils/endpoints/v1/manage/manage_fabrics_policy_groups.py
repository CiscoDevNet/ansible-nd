# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Policy Groups endpoint models.

This module contains endpoint definitions for policy group CRUD operations
in the ND Manage API.

Endpoints covered:
- GET    /fabrics/{fabricName}/policyGroups                    - List policy groups (with Lucene filtering)
- GET    /fabrics/{fabricName}/policyGroups/{policyGroupId}    - Get policy group by ID
- GET    /fabrics/{fabricName}/policySummary                   - Summary-backed policy group reads
- POST   /fabrics/{fabricName}/policyGroups                    - Create policy groups in bulk
- PUT    /fabrics/{fabricName}/policyGroups/{policyGroupId}    - Update a policy group
- DELETE /fabrics/{fabricName}/policyGroups/{policyGroupId}    - Delete a policy group
"""

from __future__ import annotations

__author__ = "L Nikhil Sri Krishna"

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
    PolicyGroupIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    CompositeQueryParams,
    EndpointQueryParams,
    LuceneQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# ============================================================================
# Query parameter classes
# ============================================================================


class PolicyGroupsGetEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for GET /policyGroups.

    ## Description

    Per the ND API specification, the GET /policyGroups endpoint accepts only ``clusterName``
    as a named query parameter.  Lucene filtering (filter, max, offset, sort)
    is handled separately via ``LuceneQueryParams``.

    ## Parameters

    - cluster_name → clusterName
    """

    model_config = ConfigDict(extra="forbid")

    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )


class PolicyGroupMutationEndpointParams(EndpointQueryParams):
    """
    # Summary

    Shared query parameters for policy group mutation endpoints.

    ## Description

    Per the ND API specification, the following mutation endpoints accept
    ``clusterName`` and ``ticketId``:

    - POST   /policyGroups
    - PUT    /policyGroups/{policyGroupId}
    - DELETE /policyGroups/{policyGroupId}

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
# Base class for /fabrics/{fabricName}/policyGroups
# ============================================================================


class _EpManagePolicyGroupsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Policy Groups endpoints.

    Provides the common base path for all HTTP methods on the
    ``/api/v1/manage/fabrics/{fabricName}/policyGroups`` endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path (without policyGroupId)."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "policyGroups")


# ============================================================================
# GET /fabrics/{fabricName}/policyGroups
# GET /fabrics/{fabricName}/policyGroups/{policyGroupId}
# ============================================================================


class EpManagePolicyGroupsGet(PolicyGroupIdMixin, _EpManagePolicyGroupsBase):
    """
    # Summary

    ND Manage Policy Groups GET Endpoint

    ## Description

    Retrieve policy groups from a fabric.  Supports querying all policy groups,
    a specific policy group by ID, or filtered results via Lucene parameters.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyGroups
    - /api/v1/manage/fabrics/{fabricName}/policyGroups/{policyGroupId}

    ## Verb

    - GET

    ## Usage

    ```python
    # All policy groups for a fabric
    ep = EpManagePolicyGroupsGet()
    ep.fabric_name = "my-fabric"
    path = ep.path    # /api/v1/manage/fabrics/my-fabric/policyGroups
    verb = ep.verb    # GET

    # Specific policy group by ID
    ep = EpManagePolicyGroupsGet()
    ep.fabric_name = "my-fabric"
    ep.policy_group_id = "POLICY-GROUP-143310"
    path = ep.path    # /api/v1/manage/fabrics/my-fabric/policyGroups/POLICY-GROUP-143310

    # Lucene-filtered query
    ep = EpManagePolicyGroupsGet()
    ep.fabric_name = "my-fabric"
    ep.lucene_params.filter = "templateName:feature_enable"
    ep.lucene_params.max = 100
    path = ep.path
    ```
    """

    class_name: Literal["EpManagePolicyGroupsGet"] = Field(
        default="EpManagePolicyGroupsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyGroupsGetEndpointParams = Field(
        default_factory=PolicyGroupsGetEndpointParams,
        description="Endpoint-specific query parameters",
    )
    lucene_params: LuceneQueryParams = Field(
        default_factory=LuceneQueryParams,
        description="Lucene-style filtering parameters (max, offset, sort, filter)",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.policy_group_id:
            base = f"{self._base_path}/{quote(self.policy_group_id, safe='')}"
        else:
            base = self._base_path

        composite = CompositeQueryParams()
        composite.add(self.endpoint_params)
        composite.add(self.lucene_params)
        qs = composite.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class _EpManagePolicySummaryBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Policy Summary endpoint.

    ``GET /policyGroups`` is not reliable on some controller builds for
    priority and markDeleted fields.  Policy-group read paths therefore use
    ``/policySummary`` and normalize the response into the policy-group shape.
    """

    @property
    def _base_path(self) -> str:
        """Build the policySummary endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", quote(self.fabric_name, safe=""), "policySummary")


class EpManagePolicySummaryGet(_EpManagePolicySummaryBase):
    """
    # Summary

    ND Manage Policy Summary GET Endpoint.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policySummary

    ## Verb

    - GET
    """

    class_name: Literal["EpManagePolicySummaryGet"] = Field(
        default="EpManagePolicySummaryGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyGroupsGetEndpointParams = Field(
        default_factory=PolicyGroupsGetEndpointParams,
        description="Endpoint-specific query parameters",
    )
    lucene_params: LuceneQueryParams = Field(
        default_factory=LuceneQueryParams,
        description="Lucene-style filtering parameters (max, offset, sort, filter)",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        composite = CompositeQueryParams()
        composite.add(self.endpoint_params)
        composite.add(self.lucene_params)
        # Keep Lucene wildcard filters in the exact form accepted by the
        # controller, e.g. ``filter=policyId:*POLICY-GROUP-*``.
        qs = composite.to_query_string(url_encode=False)
        return f"{self._base_path}?{qs}" if qs else self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


# ============================================================================
# POST /fabrics/{fabricName}/policyGroups
# ============================================================================


class EpManagePolicyGroupsPost(_EpManagePolicyGroupsBase):
    """
    # Summary

    ND Manage Policy Groups POST Endpoint

    ## Description

    Create one or more policy groups in a fabric for multiple switches.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyGroups

    ## Verb

    - POST

    ## Usage

    ```python
    ep = EpManagePolicyGroupsPost()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "policyGroups": [
            {
                "switchIds": ["FDO25031SY4", "FDO245206N5"],
                "templateName": "feature_enable",
                "entityType": "switch",
                "entityName": "SWITCH",
                "templateInputs": {"featureName": "lacp"},
                "priority": 500
            }
        ]
    }
    ```
    """

    class_name: Literal["EpManagePolicyGroupsPost"] = Field(
        default="EpManagePolicyGroupsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyGroupMutationEndpointParams = Field(
        default_factory=PolicyGroupMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        qs = self.endpoint_params.to_query_string()
        return f"{self._base_path}?{qs}" if qs else self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# PUT /fabrics/{fabricName}/policyGroups/{policyGroupId}
# ============================================================================


class EpManagePolicyGroupsPut(PolicyGroupIdMixin, _EpManagePolicyGroupsBase):
    """
    # Summary

    ND Manage Policy Groups PUT Endpoint

    ## Description

    Update a specific policy group in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyGroups/{policyGroupId}

    ## Verb

    - PUT

    ## Usage

    ```python
    ep = EpManagePolicyGroupsPut()
    ep.fabric_name = "my-fabric"
    ep.policy_group_id = "POLICY-GROUP-143310"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "switchIds": ["FDO245206N5", "FDO245206N9"],
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "templateInputs": {"featureName": "lacp"},
        "priority": 50,
        "description": "Update priority value for group policy"
    }
    ```
    """

    class_name: Literal["EpManagePolicyGroupsPut"] = Field(
        default="EpManagePolicyGroupsPut",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyGroupMutationEndpointParams = Field(
        default_factory=PolicyGroupMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.policy_group_id is None:
            raise ValueError("policy_group_id must be set before accessing path")
        base = f"{self._base_path}/{quote(self.policy_group_id, safe='')}"
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


# ============================================================================
# DELETE /fabrics/{fabricName}/policyGroups/{policyGroupId}
# ============================================================================


class EpManagePolicyGroupsDelete(PolicyGroupIdMixin, _EpManagePolicyGroupsBase):
    """
    # Summary

    ND Manage Policy Groups DELETE Endpoint

    ## Description

    Delete a specific policy group from a fabric by its policy group ID.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policyGroups/{policyGroupId}

    ## Verb

    - DELETE

    ## Usage

    ```python
    ep = EpManagePolicyGroupsDelete()
    ep.fabric_name = "my-fabric"
    ep.policy_group_id = "POLICY-GROUP-143310"
    path = ep.path
    verb = ep.verb
    ```
    """

    class_name: Literal["EpManagePolicyGroupsDelete"] = Field(
        default="EpManagePolicyGroupsDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyGroupMutationEndpointParams = Field(
        default_factory=PolicyGroupMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.policy_group_id is None:
            raise ValueError("policy_group_id must be set before accessing path")
        base = f"{self._base_path}/{quote(self.policy_group_id, safe='')}"
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
