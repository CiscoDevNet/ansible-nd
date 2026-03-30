# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

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
__author__ = "Akshayanat C S"
# pylint: enable=invalid-name

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)


class FabricsBootstrapEndpointParams(
    FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams
):
    """
    # Summary

    Endpoint-specific query parameters for fabric bootstrap endpoint.

    ## Parameters

    - max: Maximum number of results to return (optional, from `MaxMixin`)
    - offset: Pagination offset (optional, from `OffsetMixin`)
    - filter: Lucene filter expression (optional, from `FilterMixin`)

    ## Usage

    ```python
    params = FabricsBootstrapEndpointParams(max=50, offset=0)
    query_string = params.to_query_string()
    # Returns: "max=50&offset=0"
    ```
    """


class _EpManageFabricsBootstrapBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Bootstrap endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/bootstrap endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "bootstrap")


class EpManageFabricsBootstrapGet(_EpManageFabricsBootstrapBase):
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
    request = EpManageFabricsBootstrapGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with pagination
    request = EpManageFabricsBootstrapGet()
    request.fabric_name = "MyFabric"
    request.endpoint_params.max = 50
    request.endpoint_params.offset = 0
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/bootstrap?max=50&offset=0
    ```
    """

    class_name: Literal["EpManageFabricsBootstrapGet"] = Field(
        default="EpManageFabricsBootstrapGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: FabricsBootstrapEndpointParams = Field(
        default_factory=FabricsBootstrapEndpointParams,
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
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
