# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Switch Actions endpoint models.

This module contains endpoint definitions for switch-level action
operations in the ND Manage API.

Endpoints covered:
- POST /fabrics/{fabricName}/switchActions/deploy  - Deploy config to switches
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

__author__ = "L Nikhil Sri Krishna"

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)


# ============================================================================
# Query parameter classes
# ============================================================================


class SwitchDeployEndpointParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for the switchActions/deploy endpoint.

    ## Description

    Per the ND API specification, ``POST /fabrics/{fabricName}/switchActions/deploy``
    accepts ``forceShowRun`` and ``clusterName`` as optional query params.

    ## Parameters

    - force_show_run → forceShowRun (boolean)
    - cluster_name  → clusterName  (string)
    """

    model_config = ConfigDict(extra="forbid")

    force_show_run: Optional[bool] = Field(
        default=None,
        description=(
            "If true, Config compliance fetches the latest running config "
            "from the device. If false, uses the cached version."
        ),
    )
    cluster_name: Optional[str] = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )


# ============================================================================
# Base class for /fabrics/{fabricName}/switchActions/{action}
# ============================================================================


class _EpManageSwitchActionsBase(FabricNameMixin, NDEndpointBaseModel):
    """
    Base class for Switch Actions endpoints.

    Provides the shared path prefix:
    ``/api/v1/manage/fabrics/{fabricName}/switchActions``
    """

    model_config = ConfigDict(extra="forbid")

    @property
    def _base_path(self) -> str:
        if not self.fabric_name:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "switchActions")


# ============================================================================
# POST /fabrics/{fabricName}/switchActions/deploy
# ============================================================================


class EpManageSwitchActionsDeployPost(_EpManageSwitchActionsBase):
    """
    # Summary

    Switch Config Deploy Endpoint

    ## Description

    Deploy the fabric configuration to specific switches.

    Unlike ``/actions/configDeploy`` (which deploys to ALL switches in
    a fabric), this endpoint targets only the switches whose serial
    numbers are provided in the request body.

    ## Path

    ``/api/v1/manage/fabrics/{fabricName}/switchActions/deploy``

    ## Verb

    POST

    ## Query Parameters

    - ``forceShowRun`` (bool, optional) — Fetch latest running config first
    - ``clusterName`` (str, optional) — Target cluster in multi-cluster setups

    ## Request Body

    ```json
    {
        "switchIds": ["FOC21373AFA", "FVT93126SKE"]
    }
    ```

    ## Response

    207 Multi-Status on success:
    ```json
    {
        "status": "Configuration deployment completed for [FOC21373AFA]."
    }
    ```

    ## Usage

    ```python
    ep = EpManageSwitchActionsDeployPost()
    ep.fabric_name = "MyFabric"
    path = ep.path   # /api/v1/manage/.../switchActions/deploy
    verb = ep.verb   # POST
    # body: {"switchIds": ["serial1", "serial2"]}
    ```
    """

    class_name: Literal["EpManageSwitchActionsDeployPost"] = Field(
        default="EpManageSwitchActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: SwitchDeployEndpointParams = Field(
        default_factory=SwitchDeployEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the endpoint path with optional query string.

        ## Returns

        Complete endpoint path string, optionally including query parameters.
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
