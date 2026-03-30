# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

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
__author__ = "Akshayanat C S"
# pylint: enable=invalid-name

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
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


class FabricSwitchesGetEndpointParams(
    FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams
):
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

    hostname: Optional[str] = Field(
        default=None, min_length=1, description="Filter by switch hostname"
    )


class FabricSwitchesAddEndpointParams(
    ClusterNameMixin, TicketIdMixin, EndpointQueryParams
):
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


class _EpManageFabricsSwitchesBase(FabricNameMixin, NDEndpointBaseModel):
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


class EpManageFabricsSwitchesGet(_EpManageFabricsSwitchesBase):
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
    request = EpManageFabricsSwitchesGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # List with filtering
    request = EpManageFabricsSwitchesGet()
    request.fabric_name = "MyFabric"
    request.endpoint_params.hostname = "leaf1"
    request.endpoint_params.max = 100
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches?hostname=leaf1&max=100
    ```
    """

    class_name: Literal["EpManageFabricsSwitchesGet"] = Field(
        default="EpManageFabricsSwitchesGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: FabricSwitchesGetEndpointParams = Field(
        default_factory=FabricSwitchesGetEndpointParams,
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


class EpManageFabricsSwitchesPost(_EpManageFabricsSwitchesBase):
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
    request = EpManageFabricsSwitchesPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Add switches with cluster and ticket
    request = EpManageFabricsSwitchesPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchesPost"] = Field(
        default="EpManageFabricsSwitchesPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: FabricSwitchesAddEndpointParams = Field(
        default_factory=FabricSwitchesAddEndpointParams,
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
# Per-Switch Action Endpoints
# ============================================================================


class SwitchActionsTicketEndpointParams(TicketIdMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch action endpoints that accept a ticket ID.

    ## Parameters

    - ticket_id: Change control ticket ID (optional, from `TicketIdMixin`)

    ## Usage

    ```python
    params = SwitchActionsTicketEndpointParams(ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "ticketId=CHG12345"
    ```
    """


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


class _EpManageFabricsSwitchActionsPerSwitchBase(
    FabricNameMixin, SwitchSerialNumberMixin, NDEndpointBaseModel
):
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
        return BasePath.path(
            "fabrics", self.fabric_name, "switches", self.switch_sn, "actions"
        )


class EpManageFabricsSwitchProvisionRMAPost(_EpManageFabricsSwitchActionsPerSwitchBase):
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
    request = EpManageFabricsSwitchProvisionRMAPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    path = request.path
    verb = request.verb

    # Provision RMA with change control ticket
    request = EpManageFabricsSwitchProvisionRMAPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/provisionRMA?ticketId=CHG12345
    ```
    """

    class_name: Literal["EpManageFabricsSwitchProvisionRMAPost"] = Field(
        default="EpManageFabricsSwitchProvisionRMAPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsTicketEndpointParams = Field(
        default_factory=SwitchActionsTicketEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        base = f"{self._base_path}/provisionRMA"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class EpManageFabricsSwitchChangeSerialNumberPost(
    _EpManageFabricsSwitchActionsPerSwitchBase
):
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
    request = EpManageFabricsSwitchChangeSerialNumberPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    path = request.path
    verb = request.verb

    # Change serial number with cluster name
    request = EpManageFabricsSwitchChangeSerialNumberPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    request.endpoint_params.cluster_name = "cluster1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/changeSwitchSerialNumber?clusterName=cluster1
    ```
    """

    class_name: Literal["EpManageFabricsSwitchChangeSerialNumberPost"] = Field(
        default="EpManageFabricsSwitchChangeSerialNumberPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchActionsClusterEndpointParams = Field(
        default_factory=SwitchActionsClusterEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """Build the endpoint path with optional query string."""
        base = f"{self._base_path}/changeSwitchSerialNumber"
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
