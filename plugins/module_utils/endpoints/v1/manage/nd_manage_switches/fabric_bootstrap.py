# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Bootstrap endpoint models.

This module contains endpoint definitions for switch bootstrap operations
within fabrics in the ND Manage API.

Endpoints covered:
- List bootstrap switches (POAP/PnP)
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
__author__ = "Akshayanat Chengam Saravanan"
# pylint: enable=invalid-name

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class FabricBootstrapEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for fabric bootstrap endpoint.

    ## Parameters

    - max: Maximum number of results to return (optional)
    - offset: Pagination offset (optional)
    - filter: Lucene filter expression (optional)

    ## Usage

    ```python
    params = FabricBootstrapEndpointParams(max=50, offset=0)
    query_string = params.to_query_string()
    # Returns: "max=50&offset=0"
    ```
    """

    max: Optional[int] = Field(default=None, ge=1, description="Maximum number of results")
    offset: Optional[int] = Field(default=None, ge=0, description="Pagination offset")
    filter: Optional[str] = Field(default=None, min_length=1, description="Lucene filter expression")


class _V1ManageFabricBootstrapBase(FabricNameMixin, BaseModel):
    """
    Base class for Fabric Bootstrap endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/bootstrap endpoint.
    """

    model_config = COMMON_CONFIG

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "bootstrap")


class V1ManageFabricBootstrapGet(_V1ManageFabricBootstrapBase):
    """
    # Summary

    List Bootstrap Switches Endpoint

    ## Description

    Endpoint to list switches currently going through bootstrap loop via POAP (NX-OS) or PnP (IOS-XE).

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/bootstrap
    - /api/v1/manage/fabrics/{fabricName}/bootstrap?max=50&offset=0

    ## Verb

    - GET

    ## Query Parameters

    - max: Maximum number of results (optional)
    - offset: Pagination offset (optional)
    - filter: Lucene filter expression (optional)

    ## Usage

    ```python
    # List all bootstrap switches
    request = V1ManageFabricBootstrapGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with pagination
    request = V1ManageFabricBootstrapGet()
    request.fabric_name = "MyFabric"
    request.endpoint_params.max = 50
    request.endpoint_params.offset = 0
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/bootstrap?max=50&offset=0
    ```
    """

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricBootstrapGet"] = Field(
        default="V1ManageFabricBootstrapGet", description="Class name for backward compatibility"
    )
    endpoint_params: FabricBootstrapEndpointParams = Field(
        default_factory=FabricBootstrapEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
