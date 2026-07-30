# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Route Maps endpoint models.

This module contains endpoint definitions for route-map-related operations
in the ND Manage API.

## Endpoints

- `EpManageRouteMapsGet` - Get a specific route map by name
  (GET /api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName})
- `EpManageRouteMapsListGet` - List all route maps for a fabric
  (GET /api/v1/manage/fabrics/{fabricName}/routeMaps)
- `EpManageRouteMapsPost` - Bulk-create route maps for a fabric
  (POST /api/v1/manage/fabrics/{fabricName}/routeMaps)
- `EpManageRouteMapsPut` - Update a specific route map
  (PUT /api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName})
- `EpManageRouteMapsDelete` - Delete a specific route map
  (DELETE /api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName})
- `EpManageRouteMapsBulkDelete` - Bulk-delete route maps by name
  (POST /api/v1/manage/fabrics/{fabricName}/routeMapActions/remove)
"""

from __future__ import annotations

from typing import ClassVar, Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, RouteMapNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import CompositeQueryParams, EndpointQueryParams, LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class RouteMapsEndpointParams(EndpointQueryParams):
    """
    # Summary

    Query parameters shared by single-item route map endpoints.

    ## Parameters

    - cluster_name: Name of the target Nexus Dashboard cluster (multi-cluster deployments)

    ## Usage

    ```python
    params = RouteMapsEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """

    model_config = ConfigDict(extra="forbid")

    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )


class RouteMapsListEndpointParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for the GET /fabrics/{fabricName}/routeMaps list endpoint.

    ## Parameters

    - cluster_name: Name of the target Nexus Dashboard cluster (multi-cluster deployments)

    Lucene filtering, pagination, and sorting are handled by the list endpoint's
    separate ``lucene_params`` field.

    ## Usage

    ```python
    params = RouteMapsListEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """

    model_config = ConfigDict(extra="forbid")

    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )


class _EpManageRouteMapsBase(RouteMapNameMixin, FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Route Maps endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/routeMaps endpoint.

    Subclasses may override:
    - ``_require_fabric_name``: set to ``False`` if fabric name is not required.
    - ``_require_route_map_name``: set to ``False`` for collection-level endpoints
      (list, bulk-create) that do not include a route map name in the path.
    """

    _require_fabric_name: ClassVar[bool] = True
    _require_route_map_name: ClassVar[bool] = True

    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams, description="Endpoint-specific query parameters")

    def set_identifiers(self, identifier: IdentifierKey = None) -> None:
        """Set the route_map_name from the identifier value."""
        self.route_map_name = identifier

    def _query_string(self) -> str:
        """Return endpoint-specific query parameters."""
        return self.endpoint_params.to_query_string()

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path for route maps.

        ## Returns

        - Complete endpoint path string including fabric name, optional route map name,
          and query string.

        ## Raises

        - ``ValueError`` if ``fabric_name`` is required but not set.
        - ``ValueError`` if ``route_map_name`` is required but not set.
        """
        if self._require_fabric_name and self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        if self._require_route_map_name and self.route_map_name is None:
            raise ValueError(f"{type(self).__name__}.path: route_map_name must be set before accessing path.")

        segments = ["fabrics"]
        if self.fabric_name is not None:
            segments.append(quote(self.fabric_name, safe=""))
        segments.append("routeMaps")
        if self.route_map_name is not None:
            segments.append(quote(self.route_map_name, safe=""))

        base_path = BasePath.path(*segments)
        query_string = self._query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageRouteMapsGet(_EpManageRouteMapsBase):
    """
    # Summary

    ND Manage Route Maps GET Endpoint

    ## Description

    Endpoint to retrieve a specific route map by name from a fabric.
    Both ``fabric_name`` and ``route_map_name`` are required path parameters.

    ## Path

    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName}``
    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName}?clusterName=cluster1``

    ## Verb

    - GET

    ## Raises

    - ``ValueError`` if ``fabric_name`` or ``route_map_name`` is not set when accessing ``path``

    ## Usage

    ```python
    ep = EpManageRouteMapsGet()
    ep.fabric_name = "my-fabric"
    ep.route_map_name = "my-route-map"
    path = ep.path
    verb = ep.verb
    ```
    """

    class_name: Literal["EpManageRouteMapsGet"] = Field(default="EpManageRouteMapsGet", description="Class name for backward compatibility")

    endpoint_params: RouteMapsEndpointParams = Field(default_factory=RouteMapsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageRouteMapsListGet(_EpManageRouteMapsBase):
    """
    # Summary

    ND Manage Route Maps List GET Endpoint

    ## Description

    Endpoint to list all route maps for a given fabric.
    Supports optional query parameters for filtering, pagination, and sorting.

    ## Path

    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps``
    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps?max=10&offset=0``

    ## Verb

    - GET

    ## Raises

    - ``ValueError`` if ``fabric_name`` is not set when accessing ``path``

    ## Usage

    ```python
    ep = EpManageRouteMapsListGet()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    ```
    """

    _require_route_map_name: ClassVar[bool] = False

    class_name: Literal["EpManageRouteMapsListGet"] = Field(default="EpManageRouteMapsListGet", description="Class name for backward compatibility")

    endpoint_params: RouteMapsListEndpointParams = Field(default_factory=RouteMapsListEndpointParams, description="Endpoint-specific query parameters")
    lucene_params: LuceneQueryParams = Field(default_factory=LuceneQueryParams, description="Lucene-style filtering parameters")

    def _query_string(self) -> str:
        """Return composed endpoint and Lucene query parameters."""
        return CompositeQueryParams().add(self.endpoint_params).add(self.lucene_params).to_query_string()

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageRouteMapsPost(_EpManageRouteMapsBase):
    """
    # Summary

    ND Manage Route Maps POST Endpoint

    ## Description

    Endpoint to bulk-create route maps for a given fabric.
    The request body must conform to the ``CreateRouteMapsRequest`` schema:
    ``{"routeMaps": [{"name": ..., "entries": [...]}, ...]}``.

    ## Path

    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps``

    ## Verb

    - POST

    ## Request Body

    ``CreateRouteMapsRequest`` schema -- ``{"routeMaps": [RouteMap, ...]}``.

    ## Raises

    - ``ValueError`` if ``fabric_name`` is not set when accessing ``path``

    ## Usage

    ```python
    ep = EpManageRouteMapsPost()
    ep.fabric_name = "my-fabric"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    rest_send.payload = {"routeMaps": [{"name": "rm1", "entries": [...]}]}
    ```
    """

    _require_route_map_name: ClassVar[bool] = False

    class_name: Literal["EpManageRouteMapsPost"] = Field(default="EpManageRouteMapsPost", description="Class name for backward compatibility")

    endpoint_params: RouteMapsEndpointParams = Field(default_factory=RouteMapsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageRouteMapsPut(_EpManageRouteMapsBase):
    """
    # Summary

    ND Manage Route Maps PUT Endpoint

    ## Description

    Endpoint to update a specific route map in a fabric.
    Both ``fabric_name`` and ``route_map_name`` are required path parameters.
    The request body must conform to the ``RouteMap`` schema.

    ## Path

    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName}``

    ## Verb

    - PUT

    ## Request Body

    ``RouteMap`` schema -- ``{"name": ..., "entries": [...]}``.

    ## Raises

    - ``ValueError`` if ``fabric_name`` or ``route_map_name`` is not set when accessing ``path``

    ## Usage

    ```python
    ep = EpManageRouteMapsPut()
    ep.fabric_name = "my-fabric"
    ep.route_map_name = "my-route-map"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    rest_send.payload = {"name": "my-route-map", "entries": [...]}
    ```
    """

    class_name: Literal["EpManageRouteMapsPut"] = Field(default="EpManageRouteMapsPut", description="Class name for backward compatibility")

    endpoint_params: RouteMapsEndpointParams = Field(default_factory=RouteMapsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpManageRouteMapsDelete(_EpManageRouteMapsBase):
    """
    # Summary

    ND Manage Route Maps DELETE Endpoint

    ## Description

    Endpoint to delete a specific route map from a fabric.
    Both ``fabric_name`` and ``route_map_name`` are required path parameters.

    ## Path

    - ``/api/v1/manage/fabrics/{fabricName}/routeMaps/{routeMapName}``

    ## Verb

    - DELETE

    ## Raises

    - ``ValueError`` if ``fabric_name`` or ``route_map_name`` is not set when accessing ``path``

    ## Usage

    ```python
    ep = EpManageRouteMapsDelete()
    ep.fabric_name = "my-fabric"
    ep.route_map_name = "my-route-map"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    ```
    """

    class_name: Literal["EpManageRouteMapsDelete"] = Field(default="EpManageRouteMapsDelete", description="Class name for backward compatibility")

    endpoint_params: RouteMapsEndpointParams = Field(default_factory=RouteMapsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE


class EpManageRouteMapsBulkDelete(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    ND Manage Route Maps Bulk DELETE Endpoint

    ## Description

    Endpoint to bulk-delete multiple route maps from a fabric using the
    ``routeMapActions/remove`` sub-resource.  The request body must conform to
    the ``RouteMapDeleteRequest`` schema:
    ``{"routeMapNames": ["rm1", "rm2", ...]}``.

    ## Path

    - ``/api/v1/manage/fabrics/{fabricName}/routeMapActions/remove``

    ## Verb

    - POST

    ## Request Body

    ``RouteMapDeleteRequest`` schema -- ``{"routeMapNames": [str, ...]}``.

    ## Raises

    - ``ValueError`` if ``fabric_name`` is not set when accessing ``path``

    ## Usage

    ```python
    ep = EpManageRouteMapsBulkDelete()
    ep.fabric_name = "my-fabric"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    rest_send.payload = {"routeMapNames": ["MY-BGP-ROUTEMAP-1", "MY-BGP-ROUTEMAP-2"]}
    ```
    """

    class_name: Literal["EpManageRouteMapsBulkDelete"] = Field(default="EpManageRouteMapsBulkDelete", description="Class name for backward compatibility")
    endpoint_params: RouteMapsEndpointParams = Field(default_factory=RouteMapsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def path(self) -> str:
        """
        Build the bulk-delete endpoint path.

        ## Raises

        - ``ValueError`` if ``fabric_name`` is not set.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        base_path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "routeMapActions", "remove")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
