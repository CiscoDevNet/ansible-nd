# Copyright: (c) 2026, Allen Robel (@allenrobel)
# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ND Manage Fabric switchActions endpoint models.

This module contains endpoint definitions for fabric-scoped switch action operations
in the ND Manage API.

## Endpoints

- ``EpManageSwitchActionsDeployPost`` - Deploy config to specific switches
  (POST ``/api/v1/manage/fabrics/{fabric_name}/switchActions/deploy``)
- ``EpManageFabricsSwitchActionsChangeSystemModePost`` - Change the system mode of one or more switches
  (POST ``/api/v1/manage/fabrics/{fabric_name}/switchActions/changeSystemMode``)
"""

from __future__ import annotations

from typing import Literal, Optional
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

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

    force_show_run: bool | None = Field(
        default=None,
        description=("If true, Config compliance fetches the latest running config from the device. If false, uses the cached version."),
    )
    # TODO: Move cluster_name to shared fields file once available.
    cluster_name: str | None = Field(
        default=None,
        min_length=1,
        description="Target cluster name for multi-cluster deployments",
    )


class ChangeSystemModeEndpointParams(EndpointQueryParams):
    """
    # Summary

    Query parameters for the changeSystemMode switchAction endpoint.

    ## Parameters

    - `deploy`: If `True`, the new system mode is deployed to the switches. Default `False` updates ND intent only.
    - `blocking`: When `deploy` is `True`, block until the deploy operation completes or the server-configured timeout expires.
    - `ticket_id`: Optional Change Control ticket ID associated with the mode change. Serialized as `ticketId`.
    - `cluster_name`: Target cluster name in a multi-cluster deployment. Serialized as `clusterName`.

    ## Raises

    None
    """

    deploy: Optional[bool] = Field(
        default=None,
        description="If true, the new system mode is deployed to the switches",
    )

    blocking: Optional[bool] = Field(
        default=None,
        description="When deploy is true, block until the deploy completes or the server timeout expires",
    )

    ticket_id: Optional[str] = Field(
        default=None,
        alias="ticketId",
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z][a-zA-Z0-9_-]+$",
        description="Change Control ticket ID associated with the mode change",
    )

    cluster_name: Optional[str] = Field(
        default=None,
        alias="clusterName",
        min_length=1,
        description="Name of the target Nexus Dashboard cluster to execute this API, in a multi-cluster deployment",
    )


# ============================================================================
# POST /fabrics/{fabricName}/switchActions/deploy
# ============================================================================


class EpManageSwitchActionsDeployPost(FabricNameMixin, NDEndpointBaseModel):
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

    ## Raises

    ### ValueError

    - If `fabric_name` is not set when accessing `path`.

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

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        base_path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "switchActions", "deploy")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.POST


# ============================================================================
# POST /fabrics/{fabricName}/switchActions/changeSystemMode
# ============================================================================


class EpManageFabricsSwitchActionsChangeSystemModePost(FabricNameMixin, NDEndpointBaseModel):
    """
    # Summary

    Change the system mode of one or more switches in a fabric.

    ## Description

    Sets the system mode (`normal` or `maintenance`) for one or more switches in the named fabric. The request body must
    include a single `mode` value plus a non-empty `switchIds` array of switch serial numbers. The response is HTTP 207
    multi-status with a per-switch `items` array; see the ND API documentation for details.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/switchActions/changeSystemMode`
    - `/api/v1/manage/fabrics/{fabric_name}/switchActions/changeSystemMode?deploy=true&blocking=true`

    ## Verb

    - POST

    ## Request Body (application/json)

    - `mode` (str, required): One of `"normal"` or `"maintenance"`.
    - `switchIds` (list[str], required, minItems=1): Switch serial numbers (the `switchId` field returned by switch GET endpoints).

    ## Raises

    ### ValueError

    - If `fabric_name` is not set when accessing `path`.

    ## Usage

    ```python
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    ep.fabric_name = "SITE1"
    ep.endpoint_params.deploy = True
    ep.endpoint_params.blocking = True
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    rest_send.payload = {"mode": "maintenance", "switchIds": ["9UOJ3E8A6O9", "9ASNKH8T9DJ"]}
    ```
    """

    class_name: Literal["EpManageFabricsSwitchActionsChangeSystemModePost"] = Field(
        default="EpManageFabricsSwitchActionsChangeSystemModePost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    endpoint_params: ChangeSystemModeEndpointParams = Field(
        default_factory=ChangeSystemModeEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Build the changeSystemMode endpoint path with optional query string.

        ## Raises

        ### ValueError

        - If `fabric_name` is not set before accessing `path`.
        """
        if self.fabric_name is None:
            raise ValueError(f"{type(self).__name__}.path: fabric_name must be set before accessing path.")
        base_path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "switchActions", "changeSystemMode")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Return `HttpVerbEnum.POST`.

        ## Raises

        None
        """
        return HttpVerbEnum.POST
