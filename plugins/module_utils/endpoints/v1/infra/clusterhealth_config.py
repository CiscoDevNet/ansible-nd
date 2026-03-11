# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Infra ClusterHealth endpoint models.

This module contains endpoint definitions for clusterhealth-related operations
in the ND Infra API.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import ClusterNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class ClusterHealthConfigEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for cluster health config endpoint.

    ## Parameters

    - cluster_name: Cluster name (optional, from `ClusterNameMixin`)

    ## Usage

    ```python
    params = ClusterHealthConfigEndpointParams(cluster_name="my-cluster")
    query_string = params.to_query_string()
    # Returns: "clusterName=my-cluster"
    ```
    """


class EpInfraClusterhealthConfigGet(NDEndpointBaseModel):
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
    request.endpoint_params.cluster_name = "foo"
    path = request.path
    verb = request.verb
    # Path will be: /api/v1/infra/clusterhealth/config?clusterName=foo
    ```
    """

    class_name: Literal["EpInfraClusterhealthConfigGet"] = Field(
        default="EpInfraClusterhealthConfigGet", frozen=True, description="Class name for backward compatibility"
    )

    endpoint_params: ClusterHealthConfigEndpointParams = Field(
        default_factory=ClusterHealthConfigEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        - Complete endpoint path string, optionally including query parameters
        """
        base_path = BasePath.path("clusterhealth", "config")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
