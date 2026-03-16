# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

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
- Provision RMA
- Change switch serial number
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
    SwitchSerialNumberMixin,
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


class SwitchActionsImportEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
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


class _EpManageFabricSwitchActionsBase(FabricNameMixin, NDEndpointBaseModel):
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


class EpManageFabricSwitchActionsRemovePost(_EpManageFabricSwitchActionsBase):
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
    request = EpManageFabricSwitchActionsRemovePost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Remove switches with force and ticket
    request = EpManageFabricSwitchActionsRemovePost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.force = True
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/remove?force=true&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchActionsRemovePost"] = Field(
        default="EpManageFabricSwitchActionsRemovePost", description="Class name for backward compatibility"
    )
    endpoint_params: SwitchActionsRemoveEndpointParams = Field(
        default_factory=SwitchActionsRemoveEndpointParams, description="Endpoint-specific query parameters"
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


class EpManageFabricSwitchActionsChangeRolesPost(_EpManageFabricSwitchActionsBase):
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
    request = EpManageFabricSwitchActionsChangeRolesPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Change roles with change control ticket
    request = EpManageFabricSwitchActionsChangeRolesPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/changeRoles?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchActionsChangeRolesPost"] = Field(
        default="EpManageFabricSwitchActionsChangeRolesPost",
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsTicketEndpointParams = Field(
        default_factory=SwitchActionsTicketEndpointParams, description="Endpoint-specific query parameters"
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


class EpManageFabricSwitchActionsImportBootstrapPost(_EpManageFabricSwitchActionsBase):
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
    request = EpManageFabricSwitchActionsImportBootstrapPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Import with cluster and ticket
    request = EpManageFabricSwitchActionsImportBootstrapPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/importBootstrap?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchActionsImportBootstrapPost"] = Field(
        default="EpManageFabricSwitchActionsImportBootstrapPost", description="Class name for backward compatibility"
    )
    endpoint_params: SwitchActionsImportEndpointParams = Field(
        default_factory=SwitchActionsImportEndpointParams, description="Endpoint-specific query parameters"
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


class EpManageFabricSwitchActionsPreProvisionPost(_EpManageFabricSwitchActionsBase):
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
    request = EpManageFabricSwitchActionsPreProvisionPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Pre-provision with cluster and ticket
    request = EpManageFabricSwitchActionsPreProvisionPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/preProvision?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchActionsPreProvisionPost"] = Field(
        default="EpManageFabricSwitchActionsPreProvisionPost",
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsImportEndpointParams = Field(
        default_factory=SwitchActionsImportEndpointParams, description="Endpoint-specific query parameters"
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
# RMA (Return Material Authorization) Endpoints
# ============================================================================


class _EpManageFabricSwitchActionsPerSwitchBase(FabricNameMixin, SwitchSerialNumberMixin, NDEndpointBaseModel):
    """
    Base class for per-switch action endpoints.

    Provides common functionality for all HTTP methods on the
    /api/v1/manage/fabrics/{fabricName}/switches/{switchSn}/actions endpoint.
    """

    @property
    def _base_path(self) -> str:
        """Build the base endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.switch_sn is None:
            raise ValueError("switch_sn must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "switches", self.switch_sn, "actions")


class EpManageFabricSwitchProvisionRMAPost(_EpManageFabricSwitchActionsPerSwitchBase):
    """
    # Summary

    Provision RMA for Switch Endpoint

    ## Description

    Endpoint to RMA (Return Material Authorization) an existing switch with a new bootstrapped switch.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switches/{switchSn}/actions/provisionRMA
    - /api/v1/manage/fabrics/{fabricName}/switches/{switchSn}/actions/provisionRMA?ticketId=CHG12345

    ## Verb

    - POST

    ## Query Parameters

    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    # Provision RMA
    request = EpManageFabricSwitchProvisionRMAPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    path = request.path
    verb = request.verb

    # Provision RMA with change control ticket
    request = EpManageFabricSwitchProvisionRMAPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/provisionRMA?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchProvisionRMAPost"] = Field(
        default="EpManageFabricSwitchProvisionRMAPost", description="Class name for backward compatibility"
    )
    endpoint_params: SwitchActionsTicketEndpointParams = Field(
        default_factory=SwitchActionsTicketEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base = f"{self._base_path}/provisionRMA"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# Change Switch Serial Number Endpoints
# ============================================================================


class SwitchActionsClusterEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch action endpoints that accept only a cluster name.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional, from `ClusterNameMixin`)

    ## Usage

    ```python
    params = SwitchActionsClusterEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """


class EpManageFabricSwitchChangeSerialNumberPost(_EpManageFabricSwitchActionsPerSwitchBase):
    """
    # Summary

    Change Switch Serial Number Endpoint

    ## Description

    Endpoint to change the serial number for a pre-provisioned switch.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/switches/{switchSn}/actions/changeSwitchSerialNumber
    - /api/v1/manage/fabrics/{fabricName}/switches/{switchSn}/actions/changeSwitchSerialNumber?clusterName=cluster1

    ## Verb

    - POST

    ## Query Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional)

    ## Usage

    ```python
    # Change serial number
    request = EpManageFabricSwitchChangeSerialNumberPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    path = request.path
    verb = request.verb

    # Change serial number with cluster name
    request = EpManageFabricSwitchChangeSerialNumberPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    request.endpoint_params.cluster_name = "cluster1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/changeSwitchSerialNumber?clusterName=cluster1
    ```
    """

    class_name: Literal["EpManageFabricSwitchChangeSerialNumberPost"] = Field(
        default="EpManageFabricSwitchChangeSerialNumberPost", description="Class name for backward compatibility"
    )
    endpoint_params: SwitchActionsClusterEndpointParams = Field(
        default_factory=SwitchActionsClusterEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base = f"{self._base_path}/changeSwitchSerialNumber"
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


class EpManageFabricSwitchActionsRediscoverPost(_EpManageFabricSwitchActionsBase):
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
    request = EpManageFabricSwitchActionsRediscoverPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Rediscover switches with change control ticket
    request = EpManageFabricSwitchActionsRediscoverPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/rediscover?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricSwitchActionsRediscoverPost"] = Field(
        default="EpManageFabricSwitchActionsRediscoverPost",
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsTicketEndpointParams = Field(
        default_factory=SwitchActionsTicketEndpointParams, description="Endpoint-specific query parameters"
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
