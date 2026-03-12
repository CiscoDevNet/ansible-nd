# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabrics endpoint models.

This module contains endpoint definitions for fabric-related operations
in the ND Manage API.

## Endpoints

- `EpApiV1ManageFabricsGet` - Get a specific fabric by name
  (GET /api/v1/manage/fabrics/{fabric_name})
- `EpApiV1ManageFabricsListGet` - List all fabrics with optional filtering
  (GET /api/v1/manage/fabrics)
- `EpApiV1ManageFabricsPost` - Create a new fabric
  (POST /api/v1/manage/fabrics)
- `EpApiV1ManageFabricsPut` - Update a specific fabric
  (PUT /api/v1/manage/fabrics/{fabric_name})
- `EpApiV1ManageFabricsDelete` - Delete a specific fabric
  (DELETE /api/v1/manage/fabrics/{fabric_name})
- `EpApiV1ManageFabricsSummaryGet` - Get summary for a specific fabric
  (GET /api/v1/manage/fabrics/{fabric_name}/summary)
"""

from __future__ import absolute_import, annotations, division, print_function

# from plugins.module_utils.endpoints.base import NDBaseEndpoint

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=inFinal, valid-name

from typing import Literal, Optional, Final

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base_paths_manage import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import BaseModel, ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


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


class _EpApiV1ManageFabricsBase(FabricNameMixin, BaseModel):
    """
    Base class for ND Manage Fabrics endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics endpoint.
    """

    # TODO: Remove it
    # base_path: Final = BasePath.nd_manage_fabrics()
    base_path: Final = BasePath.path("fabrics")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

class EpApiV1ManageFabricsGet(_EpApiV1ManageFabricsBase):
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
    request = EpApiV1ManageFabricsGet()
    request.fabric_name = "my-fabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/my-fabric

    # Get fabric details targeting a specific cluster in a multi-cluster deployment
    request = EpApiV1ManageFabricsGet()
    request.fabric_name = "my-fabric"
    request.endpoint_params.cluster_name = "cluster1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/my-fabric?clusterName=cluster1
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1ManageFabricsGet"] = Field(
        default="EpApiV1ManageFabricsGet", description="Class name for backward compatibility"
    )

    endpoint_params: FabricsEndpointParams = Field(
        default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with the fabric name and optional query string.

        ## Returns

        - Complete endpoint path string including fabric_name and optional query parameters

        ## Raises

        - `ValueError` if `fabric_name` is None
        """
        if self.fabric_name is None:
            raise ValueError(f"{self.class_name}.path: fabric_name must be set before accessing path.")
        # base_path = BasePath.nd_manage_fabrics(self.fabric_name)
        base_path = BasePath.path("fabrics", self.fabric_name)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

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


class EpApiV1ManageFabricsListGet(_EpApiV1ManageFabricsBase):
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
    ep = EpApiV1ManageFabricsListGet()
    path = ep.path
    verb = ep.verb
    # Path: /api/v1/manage/fabrics

    # List fabrics with filtering and pagination
    ep = EpApiV1ManageFabricsListGet()
    ep.endpoint_params.category = "fabric"
    ep.endpoint_params.max = 10
    path = ep.path
    # Path: /api/v1/manage/fabrics?category=fabric&max=10
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1ManageFabricsListGet"] = Field(
        default="EpApiV1ManageFabricsListGet", description="Class name for backward compatibility"
    )

    endpoint_params: FabricsListEndpointParams = Field(
        default_factory=FabricsListEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string including optional query parameters

        ## Raises

        - None
        """
        # base_path = BasePath.nd_manage_fabrics()
        base_path = BasePath.path("fabrics")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpApiV1ManageFabricsPost(BaseModel):
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
    ep = EpApiV1ManageFabricsPost()
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

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1ManageFabricsPost"] = Field(
        default="EpApiV1ManageFabricsPost", description="Class name for backward compatibility"
    )

    endpoint_params: FabricsEndpointParams = Field(
        default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string

        ## Raises

        - None
        """
        # base_path = BasePath.nd_manage_fabrics()
        base_path = BasePath.path("fabrics")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpApiV1ManageFabricsPut(_EpApiV1ManageFabricsBase):
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
    ep = EpApiV1ManageFabricsPut()
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

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1ManageFabricsPut"] = Field(
        default="EpApiV1ManageFabricsPut", description="Class name for backward compatibility"
    )

    endpoint_params: FabricsEndpointParams = Field(
        default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with the fabric name and optional query string.

        ## Returns

        - Complete endpoint path string

        ## Raises

        - `ValueError` if `fabric_name` is None
        """
        if self.fabric_name is None:
            raise ValueError(f"{self.class_name}.path: fabric_name must be set before accessing path.")
        # base_path = BasePath.nd_manage_fabrics(self.fabric_name)
        base_path = BasePath.path("fabrics", self.fabric_name)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.PUT


class EpApiV1ManageFabricsDelete(_EpApiV1ManageFabricsBase):
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
    ep = EpApiV1ManageFabricsDelete()
    ep.fabric_name = "my-fabric"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1ManageFabricsDelete"] = Field(
        default="EpApiV1ManageFabricsDelete", description="Class name for backward compatibility"
    )

    endpoint_params: FabricsEndpointParams = Field(
        default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with the fabric name and optional query string.

        ## Returns

        - Complete endpoint path string

        ## Raises

        - `ValueError` if `fabric_name` is None
        """
        if self.fabric_name is None:
            raise ValueError(f"{self.class_name}.path: fabric_name must be set before accessing path.")
        # base_path = BasePath.nd_manage_fabrics(self.fabric_name)
        base_path = BasePath.path("fabrics", self.fabric_name)
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.DELETE


class EpApiV1ManageFabricsSummaryGet(_EpApiV1ManageFabricsBase):
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
    ep = EpApiV1ManageFabricsSummaryGet()
    ep.fabric_name = "my-fabric"
    path = ep.path
    verb = ep.verb
    # Path: /api/v1/manage/fabrics/my-fabric/summary
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1ManageFabricsSummaryGet"] = Field(
        default="EpApiV1ManageFabricsSummaryGet", description="Class name for backward compatibility"
    )

    endpoint_params: FabricsEndpointParams = Field(
        default_factory=FabricsEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with the fabric name and optional query string.

        ## Returns

        - Complete endpoint path string

        ## Raises

        - `ValueError` if `fabric_name` is None
        """
        if self.fabric_name is None:
            raise ValueError(f"{self.class_name}.path: fabric_name must be set before accessing path.")
        # base_path = BasePath.nd_manage_fabrics(self.fabric_name, "summary")
        base_path = BasePath.path("fabrics", self.fabric_name, "summary")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
