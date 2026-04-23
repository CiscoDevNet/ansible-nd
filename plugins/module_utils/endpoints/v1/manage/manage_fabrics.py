# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabrics endpoint models.

This module contains endpoint definitions for fabric-related operations
in the ND Manage API.

## Endpoints

- `EpManageFabricsGet` - Get a specific fabric by name
  (GET /api/v1/manage/fabrics/{fabric_name})
- `EpManageFabricsListGet` - List all fabrics with optional filtering
  (GET /api/v1/manage/fabrics)
- `EpManageFabricsPost` - Create a new fabric
  (POST /api/v1/manage/fabrics)
- `EpManageFabricsPut` - Update a specific fabric
  (PUT /api/v1/manage/fabrics/{fabric_name})
- `EpManageFabricsDelete` - Delete a specific fabric
  (DELETE /api/v1/manage/fabrics/{fabric_name})
- `EpManageFabricsSummaryGet` - Get summary for a specific fabric
  (GET /api/v1/manage/fabrics/{fabric_name}/summary)
- `EpManageFabricConfigDeployPost` - Deploy pending config for a fabric
  (POST /api/v1/manage/fabrics/{fabric_name}/actions/configDeploy)
"""

from __future__ import annotations

__metaclass__ = type

from typing import ClassVar, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class FabricsEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the fabrics endpoint.

    ## Parameters

    - cluster_name: Name of the target Nexus Dashboard cluster to execute this API,
      in a multi-cluster deployment (optional)

    ## Usage

    ```python
    params = FabricsEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """

    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )


class FabricConfigDeployEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the fabric config deploy endpoint.

    ## Parameters

    - force_show_run: Force show running config before deploy (optional)
    - incl_all_msd_switches: Include all MSD fabric switches (optional)

    ## Usage

    ```python
    params = FabricConfigDeployEndpointParams(force_show_run=True)
    query_string = params.to_query_string()
    # Returns: "forceShowRun=true"
    ```
    """

    force_show_run: Optional[bool] = Field(default=None, description="Force show running config before deploy")
    incl_all_msd_switches: Optional[bool] = Field(default=None, description="Include all MSD fabric switches")


class _EpManageFabricsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for ND Manage Fabrics endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics endpoint.

    Subclasses may override:
    - ``_require_fabric_name``: set to ``False`` for collection-level endpoints
      (list, create) that do not include a fabric name in the path.
    - ``_path_suffix``: set to a non-empty string to append an extra segment
      after the fabric name (e.g. ``"summary"``).  Only used when
      ``_require_fabric_name`` is ``True``.
    """

    _require_fabric_name: ClassVar[bool] = True
    _path_suffix: ClassVar[Optional[str]] = None

    endpoint_params: EndpointQueryParams = Field(default_factory=EndpointQueryParams, description="Endpoint-specific query parameters")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional fabric name, path suffix, and
        query string.

        ## Returns

        - Complete endpoint path string

        ## Raises

        - `ValueError` if `fabric_name` is required but not set
        """
        if self._require_fabric_name and self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        segments = ["fabrics"]
        if self.fabric_name is not None:
            segments.append(self.fabric_name)
        if self._path_suffix:
            segments.append(self._path_suffix)
        base_path = BasePath.path(*segments)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class EpManageFabricsGet(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics GET Endpoint

    ## Description

    Endpoint to retrieve details for a specific named fabric from the ND Manage service.
    The fabric name is a required path parameter. Optionally filter by cluster name
    using the clusterName query parameter in multi-cluster deployments.

    ## Path

    - /api/v1/manage/fabrics/{fabric_name}
    - /api/v1/manage/fabrics/{fabric_name}?clusterName=cluster1

    ## Verb

    - GET

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    # Get details for a specific fabric
    request = EpManageFabricsGet()
    request.fabric_name = "my-fabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/my-fabric

    # Get fabric details targeting a specific cluster in a multi-cluster deployment
    request = EpManageFabricsGet()
    request.fabric_name = "my-fabric"
    request.endpoint_params.cluster_name = "cluster1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/my-fabric?clusterName=cluster1
    ```
    """

    class_name: Literal["EpManageFabricsGet"] = Field(default="EpManageFabricsGet", description="Class name for backward compatibility")

    endpoint_params: FabricsEndpointParams = Field(default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class FabricsListEndpointParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for the ``GET /api/v1/manage/fabrics`` list endpoint.

    ## Parameters

    - cluster_name: Name of the target Nexus Dashboard cluster (multi-cluster deployments)
    - category: Filter by fabric category (``"fabric"`` or ``"fabricGroup"``)
    - filter: Lucene-format filter string
    - max: Maximum number of records to return
    - offset: Number of records to skip for pagination
    - sort: Sort field with optional ``:desc`` suffix

    ## Usage

    ```python
    params = FabricsListEndpointParams(category="fabric", max=10, offset=0)
    query_string = params.to_query_string()
    # Returns: "category=fabric&max=10&offset=0"
    ```
    """

    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )

    category: Optional[str] = Field(
        default=None,
        description="Filter by category of fabric (fabric or fabricGroup)",
    )

    filter: Optional[str] = Field(
        default=None,
        description="Lucene format filter - Filter the response based on this filter field",
    )

    max: Optional[int] = Field(
        default=None,
        ge=1,
        description="Number of records to return",
    )

    offset: Optional[int] = Field(
        default=None,
        ge=0,
        description="Number of records to skip for pagination",
    )

    sort: Optional[str] = Field(
        default=None,
        description="Sort the records by the declared fields in either ascending (default) or descending (:desc) order",
    )


class EpManageFabricsListGet(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics List GET Endpoint

    ## Description

    Endpoint to list all fabrics from the ND Manage service.
    Supports optional query parameters for filtering, pagination, and sorting.

    ## Path

    - ``/api/v1/manage/fabrics``
    - ``/api/v1/manage/fabrics?category=fabric&max=10``

    ## Verb

    - GET

    ## Raises

    - None

    ## Usage

    ```python
    # List all fabrics
    ep = EpManageFabricsListGet()
    path = ep.path
    verb = ep.verb
    # Path: /api/v1/manage/fabrics

    # List fabrics with filtering and pagination
    ep = EpManageFabricsListGet()
    ep.endpoint_params.category = "fabric"
    ep.endpoint_params.max = 10
    path = ep.path
    # Path: /api/v1/manage/fabrics?category=fabric&max=10
    ```
    """

    _require_fabric_name: ClassVar[bool] = False

    class_name: Literal["EpManageFabricsListGet"] = Field(default="EpManageFabricsListGet", description="Class name for backward compatibility")

    endpoint_params: FabricsListEndpointParams = Field(default_factory=FabricsListEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageFabricsPost(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics POST Endpoint

    ## Description

    Endpoint to create a new fabric via the ND Manage service.
    The request body must conform to the ``baseFabric`` schema (discriminated
    by ``category``). For standard fabrics the category is ``"fabric"`` and
    the body includes ``name`` plus fabric-specific properties such as
    ``location``, ``licenseTier``, ``telemetryCollection``, etc.

    ## Path

    - ``/api/v1/manage/fabrics``
    - ``/api/v1/manage/fabrics?clusterName=cluster1``

    ## Verb

    - POST

    ## Request Body (application/json)

    ``baseFabric`` schema — for a standard fabric use ``category: "fabric"``
    with at minimum:

    - ``name`` (str, required): Name of the fabric
    - ``category`` (str, required): ``"fabric"``

    ## Raises

    - None

    ## Usage

    ```python
    ep = EpManageFabricsPost()
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    rest_send.payload = {
        "name": "my-fabric",
        "category": "fabric",
        "telemetryCollection": True,
        "telemetryCollectionType": "inBand",
    }
    ```
    """

    _require_fabric_name: ClassVar[bool] = False

    class_name: Literal["EpManageFabricsPost"] = Field(default="EpManageFabricsPost", description="Class name for backward compatibility")

    endpoint_params: FabricsEndpointParams = Field(default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageFabricsPut(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics PUT Endpoint

    ## Description

    Endpoint to update an existing fabric via the ND Manage service.
    The fabric name is a required path parameter.  The request body must
    conform to the ``baseFabric`` schema (same shape as POST/create).

    ## Path

    - ``/api/v1/manage/fabrics/{fabric_name}``
    - ``/api/v1/manage/fabrics/{fabric_name}?clusterName=cluster1``

    ## Verb

    - PUT

    ## Request Body (application/json)

    ``baseFabric`` schema — same as create (POST).

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    ep = EpManageFabricsPut()
    ep.fabric_name = "my-fabric"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    rest_send.payload = {
        "name": "my-fabric",
        "category": "fabric",
        "telemetryCollection": False,
    }
    ```
    """

    class_name: Literal["EpManageFabricsPut"] = Field(default="EpManageFabricsPut", description="Class name for backward compatibility")

    endpoint_params: FabricsEndpointParams = Field(default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpManageFabricsDelete(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics DELETE Endpoint

    ## Description

    Endpoint to delete a specific fabric from the ND Manage service.
    The fabric name is a required path parameter.

    ## Path

    - ``/api/v1/manage/fabrics/{fabric_name}``
    - ``/api/v1/manage/fabrics/{fabric_name}?clusterName=cluster1``

    ## Verb

    - DELETE

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    ep = EpManageFabricsDelete()
    ep.fabric_name = "my-fabric"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    ```
    """

    class_name: Literal["EpManageFabricsDelete"] = Field(default="EpManageFabricsDelete", description="Class name for backward compatibility")

    endpoint_params: FabricsEndpointParams = Field(default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE


class EpManageFabricsSummaryGet(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics Summary GET Endpoint

    ## Description

    Endpoint to retrieve summary information for a specific fabric from
    the ND Manage service.  The fabric name is a required path parameter.

    ## Path

    - ``/api/v1/manage/fabrics/{fabric_name}/summary``
    - ``/api/v1/manage/fabrics/{fabric_name}/summary?clusterName=cluster1``

    ## Verb

    - GET

    ## Raises

    - `ValueError` if `fabric_name` is not set when accessing `path`

    ## Usage

    ```python
    ep = EpManageFabricsSummaryGet()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    # Path: /api/v1/manage/fabrics/my-fabric/summary
    ```
    """

    class_name: Literal["EpManageFabricsSummaryGet"] = Field(default="EpManageFabricsSummaryGet", description="Class name for backward compatibility")

    _path_suffix: ClassVar[Optional[str]] = "summary"

    endpoint_params: FabricsEndpointParams = Field(default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpManageFabricConfigDeployPost(_EpManageFabricsBase):
    """
    # Summary

    Fabric Config Deploy Endpoint

    ## Description

    Endpoint to deploy pending configuration to all switches in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabric_name}/actions/configDeploy
    - /api/v1/manage/fabrics/{fabric_name}/actions/configDeploy?forceShowRun=true

    ## Verb

    - POST

    ## Query Parameters

    - force_show_run: Force show running config before deploy (optional)
    - incl_all_msd_switches: Include all MSD fabric switches (optional)

    ## Usage

    ```python
    ep = EpManageFabricConfigDeployPost()
    ep.fabric_name = "MyFabric"
    path = ep.path
    verb = ep.verb

    # With forceShowRun
    ep.endpoint_params.force_show_run = True
    path = ep.path
    # Path: /api/v1/manage/fabrics/MyFabric/actions/configDeploy?forceShowRun=true
    ```
    """

    class_name: Literal["EpManageFabricConfigDeployPost"] = Field(
        default="EpManageFabricConfigDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: FabricConfigDeployEndpointParams = Field(
        default_factory=FabricConfigDeployEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base = BasePath.path("fabrics", self.fabric_name, "actions", "configDeploy")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
