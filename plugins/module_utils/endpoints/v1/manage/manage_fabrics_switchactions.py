# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Switch Actions endpoint models.

This module contains endpoint definitions for switch action operations
within fabrics in the ND Manage API.

Endpoints covered:
- Remove switches (bulk delete)
- Change switch roles (bulk)
- Import bootstrap (POAP)
- Pre-provision switches
- Rediscover switches
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
__author__ = "Akshayanat C S"
# pylint: enable=invalid-name

from typing import Literal, Optional

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


class SwitchActionsRemoveEndpointParams(TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch actions remove endpoint.

    ## Parameters

    - force: Force removal even if switches have pending operations (optional)
    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    params = SwitchActionsRemoveEndpointParams(force=True, ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "force=true&ticketId=CHG12345"
    ```
    """

    force: Optional[bool] = Field(default=None, description="Force removal of switches")


class SwitchActionsTicketEndpointParams(TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch action endpoints that accept a ticket ID.

    ## Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    params = SwitchActionsTicketEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """


class SwitchActionsImportEndpointParams(
    ClusterNameMixin, TicketIdMixin, EndpointQueryParams
):
    """
    # Summary

    Endpoint-specific query parameters for switch import/provision endpoints.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)
    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = SwitchActionsImportEndpointParams(cluster_name="cluster1", ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1&ticketId=CHG12345"
    ```
    """


# ============================================================================
# Switch Actions Endpoints
# ============================================================================


class _EpManageFabricsSwitchActionsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Fabric Switch Actions endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/switchActions endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "switchActions")


class EpManageFabricsSwitchActionsRemovePost(_EpManageFabricsSwitchActionsBase):
    """
    # Summary

    Remove Switches Endpoint (Bulk Delete)

    ## Description

    Endpoint to delete multiple switches from a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switchActions/remove
    - /api/v1/manage/fabrics/{fabricName}/switchActions/remove?force=true&ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - force: Force removal even if switches have pending operations (optional)
    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Remove switches
    request = EpManageFabricsSwitchActionsRemovePost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Remove switches with force and ticket
    request = EpManageFabricsSwitchActionsRemovePost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.force = True
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/remove?force=true&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchActionsRemovePost"] = Field(
        default="EpManageFabricsSwitchActionsRemovePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsRemoveEndpointParams = Field(
        default_factory=SwitchActionsRemoveEndpointParams,
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


class EpManageFabricsSwitchActionsChangeRolesPost(_EpManageFabricsSwitchActionsBase):
    """
    # Summary

    Change Switch Roles Endpoint (Bulk)

    ## Description

    Endpoint to change the role of multiple switches in a single request.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switchActions/changeRoles
    - /api/v1/manage/fabrics/{fabricName}/switchActions/changeRoles?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Change roles
    request = EpManageFabricsSwitchActionsChangeRolesPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Change roles with change control ticket
    request = EpManageFabricsSwitchActionsChangeRolesPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/changeRoles?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchActionsChangeRolesPost"] = Field(
        default="EpManageFabricsSwitchActionsChangeRolesPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsTicketEndpointParams = Field(
        default_factory=SwitchActionsTicketEndpointParams,
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
        base = f"{self._base_path}/changeRoles"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageFabricsSwitchActionsImportBootstrapPost(
    _EpManageFabricsSwitchActionsBase
):
    """
    # Summary

    Import Bootstrap Switches Endpoint

    ## Description

    Endpoint to import and bootstrap preprovision or bootstrap switches to a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switchActions/importBootstrap
    - /api/v1/manage/fabrics/{fabricName}/switchActions/importBootstrap?clusterName=cluster1&ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional)
    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Import bootstrap switches
    request = EpManageFabricsSwitchActionsImportBootstrapPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Import with cluster and ticket
    request = EpManageFabricsSwitchActionsImportBootstrapPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/importBootstrap?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchActionsImportBootstrapPost"] = Field(
        default="EpManageFabricsSwitchActionsImportBootstrapPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsImportEndpointParams = Field(
        default_factory=SwitchActionsImportEndpointParams,
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
        base = f"{self._base_path}/importBootstrap"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# Pre-Provision Endpoints
# ============================================================================


class EpManageFabricsSwitchActionsPreProvisionPost(_EpManageFabricsSwitchActionsBase):
    """
    # Summary

    Pre-Provision Switches Endpoint

    ## Description

    Endpoint to pre-provision switches in a fabric. Pre-provisioning allows
    you to define switch parameters (serial, IP, model, etc.) ahead of time
    so that when the physical device boots it is automatically absorbed into
    the fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switchActions/preProvision
    - /api/v1/manage/fabrics/{fabricName}/switchActions/preProvision?clusterName=cluster1&ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional)
    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Pre-provision switches
    request = EpManageFabricsSwitchActionsPreProvisionPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Pre-provision with cluster and ticket
    request = EpManageFabricsSwitchActionsPreProvisionPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/preProvision?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchActionsPreProvisionPost"] = Field(
        default="EpManageFabricsSwitchActionsPreProvisionPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsImportEndpointParams = Field(
        default_factory=SwitchActionsImportEndpointParams,
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
        base = f"{self._base_path}/preProvision"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# Rediscover Endpoints
# ============================================================================


class EpManageFabricsSwitchActionsRediscoverPost(_EpManageFabricsSwitchActionsBase):
    """
    # Summary

    Rediscover Switches Endpoint

    ## Description

    Endpoint to trigger rediscovery for one or more switches in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switchActions/rediscover
    - /api/v1/manage/fabrics/{fabricName}/switchActions/rediscover?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Rediscover switches
    request = EpManageFabricsSwitchActionsRediscoverPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Rediscover switches with change control ticket
    request = EpManageFabricsSwitchActionsRediscoverPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/rediscover?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchActionsRediscoverPost"] = Field(
        default="EpManageFabricsSwitchActionsRediscoverPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsTicketEndpointParams = Field(
        default_factory=SwitchActionsTicketEndpointParams,
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
        base = f"{self._base_path}/rediscover"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
