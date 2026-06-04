# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric VRFs endpoint models.

This module contains endpoint definitions for VRF CRUD operations
within fabrics in the ND Manage API.

Endpoints covered:
- VRF pre-information (details required to create a new VRF)
- List VRFs in a fabric
- Create VRF(s) in a fabric
- Get a single VRF
- Replace a VRF
- Delete a single VRF
"""

__author__ = "Akshayanat C S"


from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
    TicketIdMixin,
    VrfNameMixin,
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

# ============================================================================
# Endpoint-specific query parameter classes
# ============================================================================


class VrfsNoParamsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF endpoints that accept no extra query parameters.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)

    ## Usage

    ```python
    params = VrfsNoParamsEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """


class VrfsTicketEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF endpoints that accept a ticket ID.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = VrfsTicketEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """


class VrfsGetEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the list VRFs endpoint.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - filter: Lucene filter expression (optional, from `FilterMixin`)
    - max: Maximum number of results (optional, from `MaxMixin`)
    - offset: Pagination offset (optional, from `OffsetMixin`)
    - sort: Sort field and direction, e.g. ``"vrfName:asc"`` (optional)

    ## Usage

    ```python
    params = VrfsGetEndpointParams(max=50, sort="vrfName:asc")
    query_string = params.to_query_string()
    # Returns: "max=50&sort=vrfName%3Aasc"
    ```
    """

    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction (e.g., 'vrfName:asc')")


class VrfGetEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the get single VRF endpoint.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - fetch_members_info: Fetch member fabric info for the VRF (optional)

    ## Usage

    ```python
    params = VrfGetEndpointParams(fetch_members_info=True)
    query_string = params.to_query_string()
    # Returns: "fetchMembersInfo=true"
    ```
    """

    fetch_members_info: bool | None = Field(default=None, description="Fetch member fabric info for the VRF")


# ============================================================================
# VRF Pre-Information Endpoint
# ============================================================================


class _EpManageFabricsVrfsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric VRFs endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/vrfs endpoint family.
    """

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "vrfs")


class EpManageFabricsVrfPreInformationGet(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    VRF Pre-Information Endpoint

    ## Description

    Endpoint to get the details required to create a new VRF, such as the
    next available VNI, VLAN ID, and VRF name prefix.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfPreInformation

    ## Verb

    - GET

    ## Usage

    ```python
    # Get VRF pre-information
    request = EpManageFabricsVrfPreInformationGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfPreInformation
    ```
    """

    class_name: Literal["EpManageFabricsVrfPreInformationGet"] = Field(
        default="EpManageFabricsVrfPreInformationGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsNoParamsEndpointParams = Field(
        default_factory=VrfsNoParamsEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path.

        ## Returns

        - Complete endpoint path string
        """
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "vrfPreInformation")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


# ============================================================================
# VRFs Collection Endpoints
# ============================================================================


class EpManageFabricsVrfsGet(_EpManageFabricsVrfsBase):
    """
    # Summary

    List VRFs Endpoint

    ## Description

    Endpoint to get details of all VRFs under the fabric with optional
    filtering, pagination, and sorting.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfs
    - /api/v1/manage/fabrics/{fabricName}/vrfs?max=50&sort=vrfName:asc

    ## Verb

    - GET

    ## Query Parameters

    - filter: Lucene filter expression (optional)
    - max: Maximum number of results (optional)
    - offset: Pagination offset (optional)
    - sort: Sort field and direction (optional)

    ## Usage

    ```python
    # List all VRFs
    request = EpManageFabricsVrfsGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with pagination and sorting
    request = EpManageFabricsVrfsGet()
    request.fabric_name = "MyFabric"
    request.endpoint_params.max = 50
    request.endpoint_params.sort = "vrfName:asc"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfs?max=50&sort=vrfName%3Aasc
    ```
    """

    class_name: Literal["EpManageFabricsVrfsGet"] = Field(
        default="EpManageFabricsVrfsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsGetEndpointParams = Field(
        default_factory=VrfsGetEndpointParams,
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


class EpManageFabricsVrfsPost(_EpManageFabricsVrfsBase):
    """
    # Summary

    Create VRF(s) Endpoint

    ## Description

    Endpoint to create one or more VRF(s) in the specified fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfs
    - /api/v1/manage/fabrics/{fabricName}/vrfs?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Create VRF(s)
    request = EpManageFabricsVrfsPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Create VRF(s) with change control ticket
    request = EpManageFabricsVrfsPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfs?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfsPost"] = Field(
        default="EpManageFabricsVrfsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsTicketEndpointParams = Field(
        default_factory=VrfsTicketEndpointParams,
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
        return HttpVerbEnum.POST


# ============================================================================
# VRF Single Resource Endpoints
# ============================================================================


class _EpManageFabricsVrfsVrfNameBase(FabricNameMixin, VrfNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric VRFs per-VRF endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName} endpoint.
    """

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.vrf_name is None:
            raise ValueError("vrf_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "vrfs", self.vrf_name)


class EpManageFabricsVrfsVrfNameGet(_EpManageFabricsVrfsVrfNameBase):
    """
    # Summary

    Get VRF Endpoint

    ## Description

    Endpoint to get details for a single VRF within the specified fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName}
    - /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName}?fetchMembersInfo=true

    ## Verb

    - GET

    ## Query Parameters

    - fetch_members_info: Fetch member fabric info for the VRF (optional)

    ## Usage

    ```python
    # Get a VRF
    request = EpManageFabricsVrfsVrfNameGet()
    request.fabric_name = "MyFabric"
    request.vrf_name = "MyVRF_50000"
    path = request.path
    verb = request.verb

    # Get a VRF with member info
    request = EpManageFabricsVrfsVrfNameGet()
    request.fabric_name = "MyFabric"
    request.vrf_name = "MyVRF_50000"
    request.endpoint_params.fetch_members_info = True
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfs/MyVRF_50000?fetchMembersInfo=true
    ```
    """

    class_name: Literal["EpManageFabricsVrfsVrfNameGet"] = Field(
        default="EpManageFabricsVrfsVrfNameGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfGetEndpointParams = Field(
        default_factory=VrfGetEndpointParams,
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


class EpManageFabricsVrfsVrfNamePut(_EpManageFabricsVrfsVrfNameBase):
    """
    # Summary

    Replace VRF Endpoint

    ## Description

    Endpoint to replace a VRF under the specified fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName}
    - /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName}?ticketId=CHG12345

    ## Verb

    - PUT

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Replace a VRF
    request = EpManageFabricsVrfsVrfNamePut()
    request.fabric_name = "MyFabric"
    request.vrf_name = "MyVRF_50000"
    path = request.path
    verb = request.verb

    # Replace with change control ticket
    request = EpManageFabricsVrfsVrfNamePut()
    request.fabric_name = "MyFabric"
    request.vrf_name = "MyVRF_50000"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfs/MyVRF_50000?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfsVrfNamePut"] = Field(
        default="EpManageFabricsVrfsVrfNamePut",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsTicketEndpointParams = Field(
        default_factory=VrfsTicketEndpointParams,
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
        return HttpVerbEnum.PUT


class EpManageFabricsVrfsVrfNameDelete(_EpManageFabricsVrfsVrfNameBase):
    """
    # Summary

    Delete VRF Endpoint

    ## Description

    Endpoint to delete a single VRF from the specified fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName}
    - /api/v1/manage/fabrics/{fabricName}/vrfs/{vrfName}?ticketId=CHG12345

    ## Verb

    - DELETE

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Delete a VRF
    request = EpManageFabricsVrfsVrfNameDelete()
    request.fabric_name = "MyFabric"
    request.vrf_name = "MyVRF_50000"
    path = request.path
    verb = request.verb

    # Delete with change control ticket
    request = EpManageFabricsVrfsVrfNameDelete()
    request.fabric_name = "MyFabric"
    request.vrf_name = "MyVRF_50000"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfs/MyVRF_50000?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfsVrfNameDelete"] = Field(
        default="EpManageFabricsVrfsVrfNameDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsTicketEndpointParams = Field(
        default_factory=VrfsTicketEndpointParams,
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
        return HttpVerbEnum.DELETE
