# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Switches endpoint models.

This module contains endpoint definitions for switch CRUD operations
within fabrics in the ND Manage API.

Endpoints covered:
- List switches in a fabric
- Add switches to a fabric
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
__author__ = "Akshayanat Chengam Saravanan"
# pylint: enable=invalid-name

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
    TicketIdMixin,
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


class FabricSwitchesGetEndpointParams(FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for list fabric switches endpoint.

    ## Parameters

    - hostname: Filter by switch hostname (optional)
    - max: Maximum number of results (optional, from `MaxMixin`)
    - offset: Pagination offset (optional, from `OffsetMixin`)
    - filter: Lucene filter expression (optional, from `FilterMixin`)

    ## Usage

    ```python
    params = FabricSwitchesGetEndpointParams(hostname="leaf1", max=100)
    query_string = params.to_query_string()
    # Returns: "hostname=leaf1&max=100"
    ```
    """

    hostname: Optional[str] = Field(default=None, min_length=1, description="Filter by switch hostname")


class FabricSwitchesAddEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for add switches to fabric endpoint.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = FabricSwitchesAddEndpointParams(cluster_name="cluster1", ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1&ticketId=CHG12345"
    ```
    """


class _EpManageFabricSwitchesBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Switches endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/switches endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "switches")


class EpManageFabricSwitchesGet(_EpManageFabricSwitchesBase):
    """
    # Summary

    List Fabric Switches Endpoint

    ## Description

    Endpoint to list all switches in a specific fabric with optional filtering.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switches
    - /api/v1/manage/fabrics/{fabricName}/switches?hostname=leaf1&max=100

    ## Verb

    - GET

    ## Query Parameters

    - hostname: Filter by switch hostname (optional)
    - max: Maximum number of results (optional)
    - offset: Pagination offset (optional)
    - filter: Lucene filter expression (optional)

    ## Usage

    ```python
    # List all switches
    request = EpManageFabricSwitchesGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with filtering
    request = EpManageFabricSwitchesGet()
    request.fabric_name = "MyFabric"
    request.endpoint_params.hostname = "leaf1"
    request.endpoint_params.max = 100
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches?hostname=leaf1&max=100
    ```
    """

    class_name: Literal["EpManageFabricSwitchesGet"] = Field(
        default="EpManageFabricSwitchesGet", description="Class name for backward compatibility"
    )
    endpoint_params: FabricSwitchesGetEndpointParams = Field(
        default_factory=FabricSwitchesGetEndpointParams, description="Endpoint-specific query parameters"
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


class EpManageFabricSwitchesPost(_EpManageFabricSwitchesBase):
    """
    # Summary

    Add Switches to Fabric Endpoint

    ## Description

    Endpoint to add switches to a specific fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switches
    - /api/v1/manage/fabrics/{fabricName}/switches?clusterName=cluster1&ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional)
    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Add switches
    request = EpManageFabricSwitchesPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Add switches with cluster and ticket
    request = EpManageFabricSwitchesPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchesPost"] = Field(
        default="EpManageFabricSwitchesPost", description="Class name for backward compatibility"
    )
    endpoint_params: FabricSwitchesAddEndpointParams = Field(
        default_factory=FabricSwitchesAddEndpointParams, description="Endpoint-specific query parameters"
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
        return HttpVerbEnum.POST
