# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Networks endpoint models.

Endpoints covered:
- Network pre-information
- List networks in a fabric
- Create network(s) in a fabric
- Get a single network
- Replace a network
- Delete a single network
"""

from __future__ import annotations

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    NetworkNameMixin,
    OffsetMixin,
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class NetworksNoParamsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters for network endpoints with only optional clusterName."""


class NetworksTicketEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """Query parameters for network mutation endpoints with optional ticketId."""


class NetworksGetEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """Query parameters for listing networks."""

    sort: str | None = Field(default=None, min_length=1, description="Sort field and direction")
    service_network: bool | None = Field(
        default=None,
        alias="serviceNetwork",
        description="Filter service networks when set",
    )


class NetworkGetEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters for retrieving a single network."""

    fetch_members: bool | None = Field(
        default=None,
        alias="fetchMembers",
        description="Fetch member fabric information",
    )


class _EpManageFabricsNetworksBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for /api/v1/manage/fabrics/{fabricName}/networks."""

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "networks")


class EpManageFabricsNetworkPreInformationGet(FabricNameMixin, NDEndpointBaseModel):
    """GET /fabrics/{fabricName}/networkPreInformation."""

    class_name: Literal["EpManageFabricsNetworkPreInformationGet"] = Field(
        default="EpManageFabricsNetworkPreInformationGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworksNoParamsEndpointParams = Field(default_factory=NetworksNoParamsEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        path = BasePath.path("fabrics", self.fabric_name, "networkPreInformation")
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageFabricsNetworksGet(_EpManageFabricsNetworksBase):
    """GET /fabrics/{fabricName}/networks."""

    class_name: Literal["EpManageFabricsNetworksGet"] = Field(
        default="EpManageFabricsNetworksGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworksGetEndpointParams = Field(default_factory=NetworksGetEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageFabricsNetworksPost(_EpManageFabricsNetworksBase):
    """POST /fabrics/{fabricName}/networks."""

    class_name: Literal["EpManageFabricsNetworksPost"] = Field(
        default="EpManageFabricsNetworksPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworksTicketEndpointParams = Field(default_factory=NetworksTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class _EpManageFabricsNetworksNetworkNameBase(FabricNameMixin, NetworkNameMixin, NDEndpointBaseModel):
    """Base class for /api/v1/manage/fabrics/{fabricName}/networks/{networkName}."""

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.network_name is None:
            raise ValueError("network_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "networks", self.network_name)


class EpManageFabricsNetworksNetworkNameGet(_EpManageFabricsNetworksNetworkNameBase):
    """GET /fabrics/{fabricName}/networks/{networkName}."""

    class_name: Literal["EpManageFabricsNetworksNetworkNameGet"] = Field(
        default="EpManageFabricsNetworksNetworkNameGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkGetEndpointParams = Field(default_factory=NetworkGetEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageFabricsNetworksNetworkNamePut(_EpManageFabricsNetworksNetworkNameBase):
    """PUT /fabrics/{fabricName}/networks/{networkName}."""

    class_name: Literal["EpManageFabricsNetworksNetworkNamePut"] = Field(
        default="EpManageFabricsNetworksNetworkNamePut",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworksTicketEndpointParams = Field(default_factory=NetworksTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpManageFabricsNetworksNetworkNameDelete(_EpManageFabricsNetworksNetworkNameBase):
    """DELETE /fabrics/{fabricName}/networks/{networkName}."""

    class_name: Literal["EpManageFabricsNetworksNetworkNameDelete"] = Field(
        default="EpManageFabricsNetworksNetworkNameDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworksTicketEndpointParams = Field(default_factory=NetworksTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE
