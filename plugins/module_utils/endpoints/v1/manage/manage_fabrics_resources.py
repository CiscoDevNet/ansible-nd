# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Resources endpoint models.

This module contains endpoint definitions for resource management operations
in the ND Manage API.
"""

from __future__ import annotations

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    SwitchIdMixin,
    TenantNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
    LuceneQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class ResourcesQueryParams(ClusterNameMixin, SwitchIdMixin, TenantNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for resources endpoint.

    ## Parameters

    - cluster_name: Name of the cluster (optional)
    - switch_id: Serial Number or Id of the switch/leaf (optional)
    - pool_name: Name of the Pool (optional)

    ## Usage

    ```python
    params = ResourcesQueryParams(cluster_name="cluster1", switch_id="leaf-101", pool_name="networkVlan")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1&switchId=leaf-101&poolName=networkVlan"
    ```
    """

    pool_name: Optional[str] = Field(default=None, min_length=1, description="Name of the Pool")


# =============================================================================
# RESOURCES ENDPOINTS
# =============================================================================


class EpManageFabricResourcesGet(FabricNameMixin, ResourcesQueryParams, LuceneQueryParams, NDEndpointBaseModel):
    """
    # Summary

    ND Manage Fabrics Resources GET Endpoint

    ## Description

    Endpoint to retrieve all resources for the given fabric.
    Supports both endpoint-specific parameters (switch_id, pool_name) and
    Lucene-style filtering (filter, max, offset, sort).

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/resources
    - /api/v1/manage/fabrics/{fabricName}/resources?switchId=leaf-101
    - /api/v1/manage/fabrics/{fabricName}/resources?poolName=networkVlan
    - /api/v1/manage/fabrics/{fabricName}/resources?filter=isPreAllocated:true
    - /api/v1/manage/fabrics/{fabricName}/resources?max=10&offset=0&sort=poolName:asc

    ## Verb

    - GET

    ## Usage

    ```python
    # Get all resources in a fabric
    request = EpManageFabricResourcesGet()
    request.fabric_name = "fabric1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/resources

    # Get resources filtered by switch
    request = EpManageFabricResourcesGet()
    request.fabric_name = "fabric1"
    request.endpoint_params.switch_id = "leaf-101"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/resources?switchId=leaf-101

    # Get resources with pagination
    request = EpManageFabricResourcesGet()
    request.fabric_name = "fabric1"
    request.endpoint_params.pool_name = "networkVlan"
    request.lucene_params.max = 10
    request.lucene_params.offset = 0
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/resources?poolName=networkVlan&max=10&offset=0
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpManageFabricResourcesGet"] = Field(
        default="EpManageFabricResourcesGet", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """

        base_path = BasePath.path("fabrics", self.fabric_name, "resources")
        query_string = self.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageFabricResourcesPost(FabricNameMixin, ResourcesQueryParams, NDEndpointBaseModel):
    """
    # Summary

    ND Manage Fabrics Resources POST Endpoint

    ## Description

    Endpoint to allocate an ID or IP/Subnet resource from the specified pool.
    If a specific resource value is provided in the request, that exact value
    will be allocated. Otherwise, the next available resource will be
    automatically allocated.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/resources
    - /api/v1/manage/fabrics/{fabricName}/resources?tenantName=tenant1

    ## Verb

    - POST

    ## Usage

    ```python
    # Allocate resource
    request = EpManageFabricResourcesPost()
    request.fabric_name = "fabric1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/resources

    # Allocate resource with tenant
    request = EpManageFabricResourcesPost()
    request.fabric_name = "fabric1"
    request.endpoint_params.tenant_name = "tenant1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/resources?tenantName=tenant1
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpManageFabricResourcesPost"] = Field(
        default="EpManageFabricResourcesPost", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base_path = BasePath.path("fabrics", self.fabric_name, "resources")
        query_string = self.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# =============================================================================
# RESOURCES ACTIONS ENDPOINTS
# =============================================================================


class EpManageFabricResourcesActionsRemovePost(FabricNameMixin, ResourcesQueryParams, NDEndpointBaseModel):
    """
    # Summary

    ND Manage Fabrics Resources Actions Remove POST Endpoint

    ## Description

    Endpoint to release allocated resource IDs from the fabric, returning them
    to the available resource pool.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/resources/actions/remove

    ## Verb

    - POST

    ## Usage

    ```python
    # Release resource IDs
    request = EpManageFabricResourcesActionsRemovePost()
    request.fabric_name = "fabric1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/fabric1/resources/actions/remove
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpManageFabricResourcesActionsRemovePost"] = Field(
        default="EpManageFabricResourcesActionsRemovePost", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string
        """

        base_path = BasePath.path("fabrics", self.fabric_name, "resources", "actions", "remove")
        query_string = self.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
