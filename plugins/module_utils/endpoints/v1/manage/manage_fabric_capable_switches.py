# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabrics capableSwitches endpoint model.

Endpoint definition for the unpublished but stable
``GET /api/v1/manage/fabrics/{fabric_name}/capableSwitches`` resource.

## Endpoints

- ``EpManageFabricsCapableSwitchesGet`` - Get switches in a fabric capable of hosting a given
  ``interfaceType`` and ``mode``
  (``GET /api/v1/manage/fabrics/{fabric_name}/capableSwitches?interfaceType={type}&mode={mode}``)

This endpoint is not present in the ND OpenAPI spec. Cisco ND developers have confirmed it is
stable for the lifetime of ND 4.2.x. See GitHub issue #273 for context and risk discussion.
"""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import _EpManageFabricsBase
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class CapableSwitchesEndpointParams(EndpointQueryParams):
    """
    # Summary

    Endpoint-specific query parameters for the capableSwitches endpoint.

    ## Parameters

    - interface_type: Interface type to query for capable switches (e.g. `loopback`, `ethernet`, `portChannel`, `svi`, `tunnel`).
      Sent to the API as `interfaceType` (camelCase).
    - mode: Mode for the given interface type (e.g. `managed`, `trunk`, `access`, `routed`).

    Valid `(interface_type, mode)` pairs are enforced by `InterfaceCapabilityPreflight`, not by this model — the endpoint layer
    is intentionally a thin wire-format adapter.

    ## Usage

    ```python
    params = CapableSwitchesEndpointParams(interface_type="loopback", mode="managed")
    query_string = params.to_query_string()
    # Returns: "interfaceType=loopback&mode=managed"
    ```

    ## Raises

    None
    """

    interface_type: str | None = Field(
        default=None,
        min_length=1,
        description="Interface type (e.g. loopback, ethernet, portChannel, svi, tunnel). Sent as interfaceType.",
    )
    mode: str | None = Field(
        default=None,
        min_length=1,
        description="Interface mode (e.g. managed, trunk, access, routed).",
    )


class EpManageFabricsCapableSwitchesGet(_EpManageFabricsBase):
    """
    # Summary

    ND Manage Fabrics capableSwitches GET Endpoint

    ## Description

    Endpoint to retrieve the list of switches in a fabric that are capable of hosting interfaces of a given `interface_type` and
    `mode`. Used by `InterfaceCapabilityPreflight` to fail fast with a clear aggregate error before per-switch configuration calls.

    ## Path

    - `/api/v1/manage/fabrics/{fabric_name}/capableSwitches?interfaceType={type}&mode={mode}`

    ## Verb

    - GET

    ## Raises

    ### ValueError

    - If `fabric_name`, `interface_type`, or `mode` is not set when accessing `path`

    ## Usage

    ```python
    ep = EpManageFabricsCapableSwitchesGet()
    ep.fabric_name = "my-fabric"
    ep.endpoint_params.interface_type = "loopback"
    ep.endpoint_params.mode = "managed"
    rest_send.path = ep.path
    rest_send.verb = ep.verb
    # Path: /api/v1/manage/fabrics/my-fabric/capableSwitches?interfaceType=loopback&mode=managed
    ```
    """

    class_name: Literal["EpManageFabricsCapableSwitchesGet"] = Field(
        default="EpManageFabricsCapableSwitchesGet",
        description="Class name for backward compatibility",
    )

    _path_suffix: ClassVar[str | None] = "capableSwitches"

    endpoint_params: CapableSwitchesEndpointParams = Field(
        default_factory=CapableSwitchesEndpointParams,
        description="Endpoint-specific query parameters (interface_type, mode).",
    )

    @property
    def path(self) -> str:
        """
        # Summary

        Validate the required query parameters, then delegate to `_EpManageFabricsBase.path` to build the path with the
        fabric name, `capableSwitches` suffix, and query string.

        ## Raises

        ### ValueError

        - If `interface_type` is not set
        - If `mode` is not set
        - If `fabric_name` is not set
        """
        if self.endpoint_params.interface_type is None:
            raise ValueError(f"{type(self).__name__}.path: endpoint_params.interface_type must be set before accessing path.")
        if self.endpoint_params.mode is None:
            raise ValueError(f"{type(self).__name__}.path: endpoint_params.mode must be set before accessing path.")
        return super().path

    @property
    def verb(self) -> HttpVerbEnum:
        """Return the HTTP verb for this endpoint."""
        return HttpVerbEnum.GET
