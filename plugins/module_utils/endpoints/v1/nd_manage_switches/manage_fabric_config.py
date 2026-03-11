# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Config endpoint models.

This module contains endpoint definitions for fabric configuration operations
in the ND Manage API.

Endpoints covered:
- Config save (recalculate)
- Config deploy
- Get fabric info
- Inventory discover status
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


class FabricConfigDeployEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for fabric config deploy endpoint.

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


class V1ManageFabricConfigSavePost(FabricNameMixin, BaseModel):
    """
    # Summary

    Fabric Config Save Endpoint

    ## Description

    Endpoint to save (recalculate) fabric configuration.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/actions/configSave

    ## Verb

    - POST

    ## Usage

    ```python
    request = V1ManageFabricConfigSavePost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricConfigSavePost"] = Field(
        default="V1ManageFabricConfigSavePost", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """Build the endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.nd_manage("fabrics", self.fabric_name, "actions", "configSave")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class V1ManageFabricConfigDeployPost(FabricNameMixin, BaseModel):
    """
    # Summary

    Fabric Config Deploy Endpoint

    ## Description

    Endpoint to deploy pending configuration to switches in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/actions/configDeploy
    - /api/v1/manage/fabrics/{fabricName}/actions/configDeploy?forceShowRun=true

    ## Verb

    - POST

    ## Query Parameters

    - force_show_run: Force show running config before deploy (optional)
    - incl_all_msd_switches: Include all MSD fabric switches (optional)

    ## Usage

    ```python
    # Deploy with defaults
    request = V1ManageFabricConfigDeployPost()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb

    # Deploy forcing show run
    request = V1ManageFabricConfigDeployPost()
    request.fabric_name = "MyFabric"
    request.endpoint_params.force_show_run = True
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/manage/fabrics/MyFabric/actions/configDeploy?forceShowRun=true
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricConfigDeployPost"] = Field(
        default="V1ManageFabricConfigDeployPost", description="Class name for backward compatibility"
    )
    endpoint_params: FabricConfigDeployEndpointParams = Field(
        default_factory=FabricConfigDeployEndpointParams, description="Endpoint-specific query parameters"
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
        base_path = BasePath.nd_manage("fabrics", self.fabric_name, "actions", "configDeploy")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


class V1ManageFabricGet(FabricNameMixin, BaseModel):
    """
    # Summary

    Get Fabric Info Endpoint

    ## Description

    Endpoint to retrieve fabric information.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}

    ## Verb

    - GET

    ## Usage

    ```python
    request = V1ManageFabricGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricGet"] = Field(
        default="V1ManageFabricGet", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """Build the endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.nd_manage("fabrics", self.fabric_name)

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class V1ManageFabricInventoryDiscoverGet(FabricNameMixin, BaseModel):
    """
    # Summary

    Fabric Inventory Discover Endpoint

    ## Description

    Endpoint to get discovery status for switches in a fabric.

    ## Path

    - /api/v1/manage/fabrics/{fabricName}/inventory/discover

    ## Verb

    - GET

    ## Usage

    ```python
    request = V1ManageFabricInventoryDiscoverGet()
    request.fabric_name = "MyFabric"
    path = request.path
    verb = request.verb
    ```
    """

    model_config = COMMON_CONFIG

    # Version metadata
    api_version: Literal["v1"] = Field(default="v1", description="ND API version for this endpoint")
    min_controller_version: str = Field(default="3.0.0", description="Minimum ND version supporting this endpoint")

    class_name: Literal["V1ManageFabricInventoryDiscoverGet"] = Field(
        default="V1ManageFabricInventoryDiscoverGet", description="Class name for backward compatibility"
    )

    @property
    def path(self) -> str:
        """Build the endpoint path."""
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.nd_manage("fabrics", self.fabric_name, "inventory", "discover")

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
