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
    FabricNameMixin,
    SwitchSerialNumberMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.base_paths_manage import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
    Field,
)

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


# ============================================================================
# Endpoint-specific query parameter classes
# ============================================================================


class SwitchActionsRemoveEndpointParams(EndpointQueryParams):
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
    ticket_id: Optional[str] = Field(default=None, min_length=1, description="Change control ticket ID")


class SwitchActionsTicketEndpointParams(EndpointQueryParams):
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

    ticket_id: Optional[str] = Field(default=None, min_length=1, description="Change control ticket ID")


class SwitchActionsImportEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch import/provision endpoints.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional)
    - ticket_id: Change control ticket ID (optional)

    ## Usage

    ```python
    params = SwitchActionsImportEndpointParams(cluster_name="cluster1", ticket_id="CHG12345")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1&ticketId=CHG12345"
    ```
    """

    cluster_name: Optional[str] = Field(default=None, min_length=1, description="Target cluster name")
    ticket_id: Optional[str] = Field(default=None, min_length=1, description="Change control ticket ID")


# ============================================================================
# Switch Actions Endpoints
# ============================================================================


class V1ManageFabricSwitchActionsRemovePost(FabricNameMixin, BaseModel):
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
    request = V1ManageFabricSwitchActionsRemovePost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Remove switches with force and ticket
    request = V1ManageFabricSwitchActionsRemovePost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.force = True
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/remove?force=true&ticketId=CHG12345
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchActionsRemovePost"] = Field(
        default="V1ManageFabricSwitchActionsRemovePost", description="Class name for backward compatibility"
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base_path = BasePath.nd_manage("fabrics", self.fabric_name, "switchActions", "remove")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class V1ManageFabricSwitchActionsChangeRolesPost(FabricNameMixin, BaseModel):
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
    request = V1ManageFabricSwitchActionsChangeRolesPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Change roles with change control ticket
    request = V1ManageFabricSwitchActionsChangeRolesPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/changeRoles?ticketId=CHG12345
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchActionsChangeRolesPost"] = Field(
        default="V1ManageFabricSwitchActionsChangeRolesPost",
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base_path = BasePath.nd_manage("fabrics", self.fabric_name, "switchActions", "changeRoles")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class V1ManageFabricSwitchActionsImportBootstrapPost(FabricNameMixin, BaseModel):
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
    request = V1ManageFabricSwitchActionsImportBootstrapPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Import with cluster and ticket
    request = V1ManageFabricSwitchActionsImportBootstrapPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/importBootstrap?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchActionsImportBootstrapPost"] = Field(
        default="V1ManageFabricSwitchActionsImportBootstrapPost", description="Class name for backward compatibility"
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base_path = BasePath.nd_manage("fabrics", self.fabric_name, "switchActions", "importBootstrap")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# Pre-Provision Endpoints
# ============================================================================


class V1ManageFabricSwitchActionsPreProvisionPost(FabricNameMixin, BaseModel):
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
    request = V1ManageFabricSwitchActionsPreProvisionPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Pre-provision with cluster and ticket
    request = V1ManageFabricSwitchActionsPreProvisionPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.cluster_name = "cluster1"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/preProvision?clusterName=cluster1&ticketId=CHG12345
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchActionsPreProvisionPost"] = Field(
        default="V1ManageFabricSwitchActionsPreProvisionPost",
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base_path = BasePath.nd_manage("fabrics", self.fabric_name, "switchActions", "preProvision")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# RMA (Return Material Authorization) Endpoints
# ============================================================================


class V1ManageFabricSwitchProvisionRMAPost(FabricNameMixin, SwitchSerialNumberMixin, BaseModel):
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
    request = V1ManageFabricSwitchProvisionRMAPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    path = request.path
    verb = request.verb

    # Provision RMA with change control ticket
    request = V1ManageFabricSwitchProvisionRMAPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/provisionRMA?ticketId=CHG12345
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchProvisionRMAPost"] = Field(
        default="V1ManageFabricSwitchProvisionRMAPost", description="Class name for backward compatibility"
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.switch_sn is None:
            raise ValueError("switch_sn must be set before accessing path")
        base_path = BasePath.nd_manage(
            "fabrics", self.fabric_name, "switches", self.switch_sn, "actions", "provisionRMA"
        )
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# Change Switch Serial Number Endpoints
# ============================================================================


class SwitchActionsClusterEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for switch action endpoints that accept only a cluster name.

    ## Parameters

    - cluster_name: Target cluster name for multi-cluster deployments (optional)

    ## Usage

    ```python
    params = SwitchActionsClusterEndpointParams(cluster_name="cluster1")
    query_string = params.to_query_string()
    # Returns: "clusterName=cluster1"
    ```
    """

    cluster_name: Optional[str] = Field(default=None, min_length=1, description="Target cluster name")


class V1ManageFabricSwitchChangeSerialNumberPost(FabricNameMixin, SwitchSerialNumberMixin, BaseModel):
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
    request = V1ManageFabricSwitchChangeSerialNumberPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    path = request.path
    verb = request.verb

    # Change serial number with cluster name
    request = V1ManageFabricSwitchChangeSerialNumberPost()
    request.fabric_name = "MyFabric"
    request.switch_sn = "SAL1948TRTT"
    request.endpoint_params.cluster_name = "cluster1"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/changeSwitchSerialNumber?clusterName=cluster1
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchChangeSerialNumberPost"] = Field(
        default="V1ManageFabricSwitchChangeSerialNumberPost", description="Class name for backward compatibility"
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.switch_sn is None:
            raise ValueError("switch_sn must be set before accessing path")
        base_path = BasePath.nd_manage(
            "fabrics", self.fabric_name, "switches", self.switch_sn, "actions", "changeSwitchSerialNumber"
        )
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# Rediscover Endpoints
# ============================================================================


class V1ManageFabricSwitchActionsRediscoverPost(FabricNameMixin, BaseModel):
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
    request = V1ManageFabricSwitchActionsRediscoverPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Rediscover switches with change control ticket
    request = V1ManageFabricSwitchActionsRediscoverPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.ticket_id = "CHG12345"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/switchActions/rediscover?ticketId=CHG12345
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricSwitchActionsRediscoverPost"] = Field(
        default="V1ManageFabricSwitchActionsRediscoverPost",
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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base_path = BasePath.nd_manage("fabrics", self.fabric_name, "switchActions", "rediscover")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST
