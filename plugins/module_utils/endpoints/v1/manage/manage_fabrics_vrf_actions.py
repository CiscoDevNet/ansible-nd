# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric VRF Actions endpoint models.

This module contains endpoint definitions for VRF action operations
within fabrics in the ND Manage API.

Endpoints covered:
- Deploy VRF configuration (bulk)
- Export fabric VRF list
- Import fabric VRF list
- Preview pending VRF configuration
- Bulk delete VRFs
- Stretch VRFs to border gateways
"""

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
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


class VrfActionsTicketEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF action endpoints that accept a ticket ID.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = VrfActionsTicketEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """


class VrfActionsNoParamsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for VRF action endpoints that accept no extra query parameters.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)

    ## Usage

    ```python
    params = VrfActionsNoParamsEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """


# ============================================================================
# VRF Actions Endpoints
# ============================================================================


class _EpManageFabricsVrfActionsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric VRF Actions endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/vrfActions endpoint.
    """

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "vrfActions")


class EpManageFabricsVrfActionsDeployPost(_EpManageFabricsVrfActionsBase):
    """
    # Summary

    Deploy VRF Configuration Endpoint

    ## Description

    Endpoint to deploy the pending configuration of VRFs to specified switches under the fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfActions/deploy
    - /api/v1/manage/fabrics/{fabricName}/vrfActions/deploy?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Deploy VRF configuration
    request = EpManageFabricsVrfActionsDeployPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Deploy with change control ticket
    request = EpManageFabricsVrfActionsDeployPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfActions/deploy?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfActionsDeployPost"] = Field(
        default="EpManageFabricsVrfActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfActionsTicketEndpointParams = Field(
        default_factory=VrfActionsTicketEndpointParams,
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
        base = f"{self._base_path}/deploy"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageFabricsVrfActionsExportPost(_EpManageFabricsVrfActionsBase):
    """
    # Summary

    Export Fabric VRF List Endpoint

    ## Description

    Endpoint to export a list of all VRFs for the specified fabric in file format for download.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfActions/export

    ## Verb

    - POST

    ## Usage

    ```python
    # Export VRF list
    request = EpManageFabricsVrfActionsExportPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfActions/export
    ```
    """

    class_name: Literal["EpManageFabricsVrfActionsExportPost"] = Field(
        default="EpManageFabricsVrfActionsExportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfActionsNoParamsEndpointParams = Field(
        default_factory=VrfActionsNoParamsEndpointParams,
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


class EpManageFabricsVrfActionsImportPost(_EpManageFabricsVrfActionsBase):
    """
    # Summary

    Import Fabric VRF List Endpoint

    ## Description

    Endpoint to import a list of VRFs for the specified fabric from an uploaded file,
    allowing bulk configuration updates.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfActions/import
    - /api/v1/manage/fabrics/{fabricName}/vrfActions/import?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Import VRF list
    request = EpManageFabricsVrfActionsImportPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Import with change control ticket
    request = EpManageFabricsVrfActionsImportPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfActions/import?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfActionsImportPost"] = Field(
        default="EpManageFabricsVrfActionsImportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfActionsTicketEndpointParams = Field(
        default_factory=VrfActionsTicketEndpointParams,
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


class EpManageFabricsVrfActionsPreviewPost(_EpManageFabricsVrfActionsBase):
    """
    # Summary

    Preview Pending VRF Configuration Endpoint

    ## Description

    Endpoint to preview the pending config of specified switch and VRF combinations in the fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfActions/preview

    ## Verb

    - POST

    ## Usage

    ```python
    # Preview pending VRF configuration
    request = EpManageFabricsVrfActionsPreviewPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfActions/preview
    ```
    """

    class_name: Literal["EpManageFabricsVrfActionsPreviewPost"] = Field(
        default="EpManageFabricsVrfActionsPreviewPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfActionsNoParamsEndpointParams = Field(
        default_factory=VrfActionsNoParamsEndpointParams,
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
        return f"{self._base_path}/preview"

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# VRF Remove Endpoint
# ============================================================================


class EpManageFabricsVrfActionsRemovePost(_EpManageFabricsVrfActionsBase):
    """
    # Summary

    Bulk Delete VRFs Endpoint

    ## Description

    Endpoint to delete VRFs in bulk from the specified fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfActions/remove
    - /api/v1/manage/fabrics/{fabricName}/vrfActions/remove?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Bulk delete VRFs
    request = EpManageFabricsVrfActionsRemovePost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Bulk delete with change control ticket
    request = EpManageFabricsVrfActionsRemovePost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfActions/remove?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsVrfActionsRemovePost"] = Field(
        default="EpManageFabricsVrfActionsRemovePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfActionsTicketEndpointParams = Field(
        default_factory=VrfActionsTicketEndpointParams,
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
        base = f"{self._base_path}/remove"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# VRF Stretch Endpoint
# ============================================================================


class EpManageFabricsVrfActionsStretchPost(_EpManageFabricsVrfActionsBase):
    """
    # Summary

    Stretch VRFs to Border Gateways Endpoint

    ## Description

    Endpoint to execute stretch or unstretch operations on one or more VRFs
    across all border gateway switches in the fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/vrfActions/stretch

    ## Verb

    - POST

    ## Usage

    ```python
    # Stretch VRFs
    request = EpManageFabricsVrfActionsStretchPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/vrfActions/stretch
    ```
    """

    class_name: Literal["EpManageFabricsVrfActionsStretchPost"] = Field(
        default="EpManageFabricsVrfActionsStretchPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfActionsNoParamsEndpointParams = Field(
        default_factory=VrfActionsNoParamsEndpointParams,
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
        return f"{self._base_path}/stretch"

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
