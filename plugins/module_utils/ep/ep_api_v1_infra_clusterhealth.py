# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra ClusterHealth endpoint models.

This module contains endpoint definitions for clusterhealth-related operations
in the ND Infra API.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.base_paths_infra import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.ep.endpoint_query_params import (
    ClusterHealthConfigQueryParams,
    ClusterHealthStatusQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.pydantic_compat import BaseModel, ConfigDict, Field

# Common config for basic validation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class EpApiV1InfraClusterhealthConfigGet(BaseModel):
    """
    # Summary

    ND Infra ClusterHealth Config GET Endpoint

    ## Description

    Endpoint to retrieve cluster health configuration from the ND Infra service.
    Optionally filter by cluster name using the clusterName query parameter.

    ## Path

    - /api/v1/infra/clusterhealth/config
    - /api/v1/infra/clusterhealth/config?clusterName=foo

    ## Verb

    - GET

    ## Usage

    ```python
    # Get cluster health config for all clusters
    request = EpApiV1InfraClusterhealthConfigGet()
    path = request.path
    verb = request.verb

    # Get cluster health config for specific cluster
    request = EpApiV1InfraClusterhealthConfigGet()
    request.query_params.cluster_name = "foo"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/infra/clusterhealth/config?clusterName=foo
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1InfraClusterhealthConfigGet"] = Field(
        default="EpApiV1InfraClusterhealthConfigGet", description="Class name for backward compatibility"
    )

    query_params: ClusterHealthConfigQueryParams = Field(default_factory=ClusterHealthConfigQueryParams, description="Query parameters for this endpoint")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base_path = BasePath.nd_infra_clusterhealth("config")
        query_string = self.query_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET


class EpApiV1InfraClusterhealthStatusGet(BaseModel):
    """
    # Summary

    ND Infra ClusterHealth Status GET Endpoint

    ## Description

    Endpoint to retrieve cluster health status from the ND Infra service.
    Optionally filter by cluster name, health category, and/or node name using query parameters.

    ## Path

    - /api/v1/infra/clusterhealth/status
    - /api/v1/infra/clusterhealth/status?clusterName=foo
    - /api/v1/infra/clusterhealth/status?clusterName=foo&healthCategory=bar&nodeName=baz

    ## Verb

    - GET

    ## Usage

    ```python
    # Get cluster health status for all clusters
    request = EpApiV1InfraClusterhealthStatusGet()
    path = request.path
    verb = request.verb

    # Get cluster health status for specific cluster
    request = EpApiV1InfraClusterhealthStatusGet()
    request.query_params.cluster_name = "foo"
    path = request.path
    verb = request.verb

    # Get cluster health status with all filters
    request = EpApiV1InfraClusterhealthStatusGet()
    request.query_params.cluster_name = "foo"
    request.query_params.health_category = "bar"
    request.query_params.node_name = "baz"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/infra/clusterhealth/status?clusterName=foo&healthCategory=bar&nodeName=baz
    ```
    """

    model_config = COMMON_CONFIG

    class_name: Literal["EpApiV1InfraClusterhealthStatusGet"] = Field(
        default="EpApiV1InfraClusterhealthStatusGet", description="Class name for backward compatibility"
    )

    query_params: ClusterHealthStatusQueryParams = Field(default_factory=ClusterHealthStatusQueryParams, description="Query parameters for this endpoint")

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base_path = BasePath.nd_infra_clusterhealth("status")
        query_string = self.query_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
