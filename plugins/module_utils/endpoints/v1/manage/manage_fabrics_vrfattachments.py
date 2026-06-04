# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric VRF Attachments endpoint models.

This module contains endpoint definitions for VRF attachment operations
within fabrics in the ND Manage API.

Endpoints covered:
- Attach/detach VRFs (bulk)
- Export VRF attachments via CSV
- Import VRF attachments via CSV
- List VRF attachments (query)
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


class VrfAttachmentsTicketEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF attachment endpoints that accept a ticket ID.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = VrfAttachmentsTicketEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """


class VrfAttachmentsNoParamsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF attachment endpoints that accept no extra query parameters.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)

    ## Usage

    ```python
    params = VrfAttachmentsNoParamsEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """


class VrfAttachmentsQueryEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the VRF attachments query endpoint.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - filter: Lucene filter expression (optional, from `FilterMixin`)
    - max: Maximum number of results (optional, from `MaxMixin`)
    - offset: Pagination offset (optional, from `OffsetMixin`)
    - sort: Sort field and direction, e.g. ``"vrfName:asc"`` (optional)
    - include_all: Include all attachment records regardless of status (optional)

    ## Usage

    ```python
    params = VrfAttachmentsQueryEndpointParams(max=100, offset=0, sort="vrfName:asc")
    query_string = params.to_query_string()
    # Returns: "max=100&offset=0&sort=vrfName%3Aasc"
    ```
    """

    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction (e.g., 'vrfName:asc')")
    include_all: bool | None = Field(default=None, description="Include all attachment records")


# ============================================================================
# VRF Attachments Endpoints
# ============================================================================


class _EpManageFabricsVrfAttachmentsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric VRF Attachments endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/vrfAttachments endpoint.
    """

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "vrfAttachments")


class EpManageFabricsVrfAttachmentsPost(_EpManageFabricsVrfAttachmentsBase):
    """
    # Summary

    Attach/Detach VRFs Endpoint

    ## Description

    Endpoint to execute attach or detach operations on a given list of VRF attachments.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments
    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Attach/detach VRFs
    request = EpManageFabricsVrfAttachmentsPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Attach/detach with change control ticket
    request = EpManageFabricsVrfAttachmentsPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfAttachments?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfAttachmentsPost"] = Field(
        default="EpManageFabricsVrfAttachmentsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsTicketEndpointParams = Field(
        default_factory=VrfAttachmentsTicketEndpointParams,
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


class EpManageFabricsVrfAttachmentsExportPost(_EpManageFabricsVrfAttachmentsBase):
    """
    # Summary

    Export VRF Attachments via CSV Endpoint

    ## Description

    Endpoint to export VRF attachments in CSV format for given VRFs and switches.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments/export

    ## Verb

    - POST

    ## Usage

    ```python
    # Export VRF attachments
    request = EpManageFabricsVrfAttachmentsExportPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfAttachments/export
    ```
    """

    class_name: Literal["EpManageFabricsVrfAttachmentsExportPost"] = Field(
        default="EpManageFabricsVrfAttachmentsExportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsNoParamsEndpointParams = Field(
        default_factory=VrfAttachmentsNoParamsEndpointParams,
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
        return f"{self._base_path}/export"

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageFabricsVrfAttachmentsImportPost(_EpManageFabricsVrfAttachmentsBase):
    """
    # Summary

    Import VRF Attachments via CSV Endpoint

    ## Description

    Endpoint to execute attach or detach operations on VRF attachments using CSV format.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments/import
    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments/import?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Import VRF attachments
    request = EpManageFabricsVrfAttachmentsImportPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Import with change control ticket
    request = EpManageFabricsVrfAttachmentsImportPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfAttachments/import?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfAttachmentsImportPost"] = Field(
        default="EpManageFabricsVrfAttachmentsImportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsTicketEndpointParams = Field(
        default_factory=VrfAttachmentsTicketEndpointParams,
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
        base = f"{self._base_path}/import"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# VRF Attachments Query Endpoint
# ============================================================================


class EpManageFabricsVrfAttachmentsQueryPost(_EpManageFabricsVrfAttachmentsBase):
    """
    # Summary

    List VRF Attachments Endpoint

    ## Description

    Endpoint to list all VRF attachments of the given switch VRF combinations.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments/query
    - /api/v1/manage/fabrics/{fabricName}/vrfAttachments/query?max=100&offset=0&sort=vrfName:asc

    ## Verb

    - POST

    ## Query Parameters

    - filter: Lucene filter expression (optional)
    - max: Maximum number of results (optional)
    - offset: Pagination offset (optional)
    - sort: Sort field and direction (optional)
    - include_all: Include all attachment records regardless of status (optional)

    ## Usage

    ```python
    # List VRF attachments
    request = EpManageFabricsVrfAttachmentsQueryPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with pagination and sorting
    request = EpManageFabricsVrfAttachmentsQueryPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.max = 100
    request.endpoint_params.offset = 0
    request.endpoint_params.sort = "vrfName:asc"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfAttachments/query?max=100&offset=0&sort=vrfName%3Aasc
    ```
    """

    class_name: Literal["EpManageFabricsVrfAttachmentsQueryPost"] = Field(
        default="EpManageFabricsVrfAttachmentsQueryPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsQueryEndpointParams = Field(
        default_factory=VrfAttachmentsQueryEndpointParams,
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
        base = f"{self._base_path}/query"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
