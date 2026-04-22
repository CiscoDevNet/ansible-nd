# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Policies endpoint models.

This module contains endpoint definitions for policy CRUD operations
in the ND Manage API.

Endpoints covered:
- GET    /fabrics/{fabricName}/policies              - List policies (with Lucene filtering)
- GET    /fabrics/{fabricName}/policies/{policyId}    - Get policy by ID
- POST   /fabrics/{fabricName}/policies              - Create policies in bulk
- PUT    /fabrics/{fabricName}/policies/{policyId}    - Update a policy
- DELETE /fabrics/{fabricName}/policies/{policyId}    - Delete a policy
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
    PolicyIdMixin,
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


class PoliciesGetEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for GET /policies.

    ## Description

    Per the ND API specification, the GET /policies endpoint accepts only ``clusterName``
    as a named query parameter.  Lucene filtering (filter, max, offset, sort)
    is handled separately via ``LuceneQueryParams``.

    ## Parameters

    - cluster_name → clusterName
    """

    model_config = ConfigDict(extra="forbid")

    # TODO: Move cluster_name to shared fields file once available.
    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )


class PolicyMutationEndpointParams(EndpointQueryParams):
    """
    # Summary

    Shared query parameters for policy mutation endpoints.

    ## Description

    Per the ND API specification, the following mutation endpoints accept
    ``clusterName`` and ``ticketId``:

    - POST   /policies
    - PUT    /policies/{policyId}
    - DELETE /policies/{policyId}

    ## Parameters

    - cluster_name → clusterName
    - ticket_id   → ticketId
    """

    model_config = ConfigDict(extra="forbid")

    # TODO: Move cluster_name to shared fields file once available.
    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )
    # TODO: Move ticket_id to shared fields file as a phase 2 cleanup effort.
    ticket_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z][a-zA-Z0-9_-]+$",
        description="Change Control Ticket Id",
    )


# ============================================================================
# Base class for /fabrics/{fabricName}/policies
# ============================================================================


class _EpManagePoliciesBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Policies endpoints.

    Provides the common base path for all HTTP methods on the
    ``/api/v1/manage/fabrics/{fabricName}/policies`` endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path (without policyId)."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "policies")


# ============================================================================
# GET /fabrics/{fabricName}/policies
# GET /fabrics/{fabricName}/policies/{policyId}
# ============================================================================


class EpManagePoliciesGet(PolicyIdMixin, _EpManagePoliciesBase):
    """
    # Summary

    ND Manage Policies GET Endpoint

    ## Description

    Retrieve policies from a fabric.  Supports querying all policies,
    a specific policy by ID, or filtered results via Lucene parameters.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policies
    - /api/v1/manage/fabrics/{fabricName}/policies/{policyId}

    ## Verb

    - GET

    ## Usage

    ```python
    # All policies for a fabric
    ep = EpManagePoliciesGet()
    ep.fabric_name = "my-fabric"
    path = ep.path    # /api/v1/manage/fabrics/my-fabric/policies
    verb = ep.verb    # GET

    # Specific policy by ID
    ep = EpManagePoliciesGet()
    ep.fabric_name = "my-fabric"
    ep.policy_id = "POLICY-12345"
    path = ep.path    # /api/v1/manage/fabrics/my-fabric/policies/POLICY-12345

    # Lucene-filtered query
    ep = EpManagePoliciesGet()
    ep.fabric_name = "my-fabric"
    ep.lucene_params.filter = "switchId:FDO123 AND templateName:switch_freeform"
    ep.lucene_params.max = 100
    path = ep.path
    ```
    """

    class_name: Literal["EpManagePoliciesGet"] = Field(
        default="EpManagePoliciesGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PoliciesGetEndpointParams = Field(
        default_factory=PoliciesGetEndpointParams,
        description="Endpoint-specific query parameters",
    )
    lucene_params: LuceneQueryParams = Field(
        default_factory=LuceneQueryParams,
        description="Lucene-style filtering parameters (max, offset, sort, filter)",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.policy_id:
            base = f"{self._base_path}/{self.policy_id}"
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


# ============================================================================
# POST /fabrics/{fabricName}/policies
# ============================================================================


class EpManagePoliciesPost(_EpManagePoliciesBase):
    """
    # Summary

    ND Manage Policies POST Endpoint

    ## Description

    Create one or more policies in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policies

    ## Verb

    - POST

    ## Usage

    ```python
    ep = EpManagePoliciesPost()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "policies": [
            {
                "switchId": "FDO25031SY4",
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

    class_name: Literal["EpManagePoliciesPost"] = Field(
        default="EpManagePoliciesPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyMutationEndpointParams = Field(
        default_factory=PolicyMutationEndpointParams,
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
# PUT /fabrics/{fabricName}/policies/{policyId}
# ============================================================================


class EpManagePoliciesPut(PolicyIdMixin, _EpManagePoliciesBase):
    """
    # Summary

    ND Manage Policies PUT Endpoint

    ## Description

    Update a specific policy in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policies/{policyId}

    ## Verb

    - PUT

    ## Usage

    ```python
    ep = EpManagePoliciesPut()
    ep.fabric_name = "my-fabric"
    ep.policy_id = "POLICY-12345"
    path = ep.path
    verb = ep.verb
    ```

    ## Request Body Example

    ```json
    {
        "switchId": "FDO25031SY4",
        "templateName": "feature_enable",
        "entityType": "switch",
        "entityName": "SWITCH",
        "templateInputs": {"featureName": "lacp"},
        "priority": 100
    }
    ```
    """

    class_name: Literal["EpManagePoliciesPut"] = Field(
        default="EpManagePoliciesPut",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyMutationEndpointParams = Field(
        default_factory=PolicyMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.policy_id is None:
            raise ValueError("policy_id must be set before accessing path")
        base = f"{self._base_path}/{self.policy_id}"
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


# ============================================================================
# DELETE /fabrics/{fabricName}/policies/{policyId}
# ============================================================================


class EpManagePoliciesDelete(PolicyIdMixin, _EpManagePoliciesBase):
    """
    # Summary

    ND Manage Policies DELETE Endpoint

    ## Description

    Delete a specific policy from a fabric by its policy ID.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/policies/{policyId}

    ## Verb

    - DELETE

    ## Usage

    ```python
    ep = EpManagePoliciesDelete()
    ep.fabric_name = "my-fabric"
    ep.policy_id = "POLICY-12345"
    path = ep.path
    verb = ep.verb
    ```
    """

    class_name: Literal["EpManagePoliciesDelete"] = Field(
        default="EpManagePoliciesDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: PolicyMutationEndpointParams = Field(
        default_factory=PolicyMutationEndpointParams,
        description="Query parameters: clusterName, ticketId",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.policy_id is None:
            raise ValueError("policy_id must be set before accessing path")
        base = f"{self._base_path}/{self.policy_id}"
        qs = self.endpoint_params.to_query_string()
        return f"{base}?{qs}" if qs else base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE
