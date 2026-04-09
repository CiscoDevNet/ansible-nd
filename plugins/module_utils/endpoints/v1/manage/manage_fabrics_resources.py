# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Resources endpoint models.

This module contains endpoint definitions for resource management operations
in the ND Manage API.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import logging
from typing import Optional

log = logging.getLogger(__name__)

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    CompositeQueryParams,
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


class ResourcesQueryParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for resources endpoint.

    ## Parameters

    - switch_id: Serial Number or Id of the switch/leaf (optional)
    - pool_name: Name of the Pool (optional)
    - tenant_name: Name of the tenant (optional, used for POST)

    ## Usage

    ```python
    params = ResourcesQueryParams(switch_id="leaf-101", pool_name="networkVlan")
    query_string = params.to_query_string()
    # Returns: "switchId=leaf-101&poolName=networkVlan"
    ```
    """

    switch_id: Optional[str] = Field(default=None, min_length=1, description="Serial Number or Id of the switch/leaf")
    pool_name: Optional[str] = Field(default=None, min_length=1, description="Name of the Pool")
    tenant_name: Optional[str] = Field(default=None, min_length=1, description="Name of the tenant")


# =============================================================================
# RESOURCES ENDPOINTS
# =============================================================================


class EpManageFabricResourcesGet(BaseModel):
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

    fabric_name: str = Field(
        min_length=1, max_length=64, description="Name of the fabric"
    )
    endpoint_params: ResourcesQueryParams = Field(
        default_factory=ResourcesQueryParams,
        description="Endpoint-specific query parameters",
    )
    lucene_params: LuceneQueryParams = Field(
        default_factory=LuceneQueryParams,
        description="Lucene-style filtering query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        log.debug(
            "Building path for EpManageFabricResourcesGet: fabric_name=%s, switch_id=%s, pool_name=%s",
            self.fabric_name,
            self.endpoint_params.switch_id,
            self.endpoint_params.pool_name,
        )
        base_path = BasePath.path("fabrics", self.fabric_name, "resources")

        # Build composite query string
        composite = CompositeQueryParams()
        composite.add(self.endpoint_params)
        composite.add(self.lucene_params)

        query_string = composite.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        log.debug(
            "Returning HTTP verb for EpManageFabricResourcesGet: verb=%s",
            HttpVerbEnum.GET,
        )
        return HttpVerbEnum.GET


class EpManageFabricResourcesPost(BaseModel):
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

    fabric_name: str = Field(
        min_length=1, max_length=64, description="Name of the fabric"
    )
    endpoint_params: ResourcesQueryParams = Field(
        default_factory=ResourcesQueryParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        log.debug(
            "Building path for EpManageFabricResourcesPost: fabric_name=%s, tenant_name=%s",
            self.fabric_name,
            self.endpoint_params.tenant_name,
        )
        base_path = BasePath.path("fabrics", self.fabric_name, "resources")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        log.debug(
            "Returning HTTP verb for EpManageFabricResourcesPost: verb=%s",
            HttpVerbEnum.POST,
        )
        return HttpVerbEnum.POST


# =============================================================================
# RESOURCES ACTIONS ENDPOINTS
# =============================================================================


class EpManageFabricResourcesActionsRemovePost(BaseModel):
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

    fabric_name: str = Field(min_length=1, max_length=64, description="Name of the fabric")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string
        """
        log.debug(
            "Building path for EpManageFabricResourcesActionsRemovePost: fabric_name=%s",
            self.fabric_name,
        )
        return BasePath.path("fabrics", self.fabric_name, "resources", "actions", "remove")
        
    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        log.debug(
            "Returning HTTP verb for EpManageFabricResourcesActionsRemovePost: verb=%s",
            HttpVerbEnum.POST,
        )
        return HttpVerbEnum.POST
