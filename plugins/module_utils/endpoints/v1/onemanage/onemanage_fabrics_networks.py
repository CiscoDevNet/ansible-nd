# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND onemanage fabric network endpoint models.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, NetworkNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_actions import (
    NetworkActionsNoParamsEndpointParams,
    NetworkActionsTicketEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    NetworkGetEndpointParams,
    NetworksGetEndpointParams,
    NetworksTicketEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class _EpOneManageFabricsNetworksBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for onemanage fabric network endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.top_down_fabrics(self.fabric_name, "networks", proxy_path=self.proxy_path)


class EpOneManageFabricsNetworksGet(_EpOneManageFabricsNetworksBase):
    """GET /onemanage/manage/fabrics/{fabricName}/networks."""

    class_name: Literal["EpOneManageFabricsNetworksGet"] = Field(
        default="EpOneManageFabricsNetworksGet",
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


class EpOneManageFabricsNetworksPost(_EpOneManageFabricsNetworksBase):
    """POST /onemanage/manage/fabrics/{fabricName}/networks."""

    class_name: Literal["EpOneManageFabricsNetworksPost"] = Field(
        default="EpOneManageFabricsNetworksPost",
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


class _EpOneManageFabricsNetworksNetworkNameBase(FabricNameMixin, NetworkNameMixin, NDEndpointBaseModel):
    """Base class for onemanage single network endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.network_name is None:
            raise ValueError("network_name must be set before accessing path")
        return BasePath.top_down_fabrics(self.fabric_name, "networks", self.network_name, proxy_path=self.proxy_path)


class EpOneManageFabricsNetworksNetworkNameGet(_EpOneManageFabricsNetworksNetworkNameBase):
    """GET /onemanage/manage/fabrics/{fabricName}/networks/{networkName}."""

    class_name: Literal["EpOneManageFabricsNetworksNetworkNameGet"] = Field(
        default="EpOneManageFabricsNetworksNetworkNameGet",
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


class EpOneManageFabricsNetworksNetworkNamePut(_EpOneManageFabricsNetworksNetworkNameBase):
    """PUT /onemanage/manage/fabrics/{fabricName}/networks/{networkName}."""

    class_name: Literal["EpOneManageFabricsNetworksNetworkNamePut"] = Field(
        default="EpOneManageFabricsNetworksNetworkNamePut",
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


class EpOneManageFabricsNetworksNetworkNameDelete(_EpOneManageFabricsNetworksNetworkNameBase):
    """DELETE /onemanage/manage/fabrics/{fabricName}/networks/{networkName}."""

    class_name: Literal["EpOneManageFabricsNetworksNetworkNameDelete"] = Field(
        default="EpOneManageFabricsNetworksNetworkNameDelete",
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


class OneManageNetworkBulkDeleteQueryParams(EndpointQueryParams):
    """Query parameters for onemanage network bulk delete."""

    network_names: str | None = Field(default=None, min_length=1, description="Comma-separated network names")

    def to_query_string(self) -> str:
        if not self.network_names:
            return ""
        return f"network-names={quote(self.network_names, safe=',')}"


class EpOneManageFabricsNetworksBulkDelete(_EpOneManageFabricsNetworksBase):
    """DELETE /onemanage/top-down/fabrics/{fabricName}/bulk-delete/networks."""

    class_name: Literal["EpOneManageFabricsNetworksBulkDelete"] = Field(
        default="EpOneManageFabricsNetworksBulkDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    query_params: OneManageNetworkBulkDeleteQueryParams = Field(default_factory=OneManageNetworkBulkDeleteQueryParams)

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        path = BasePath.top_down_fabrics(self.fabric_name, "bulk-delete", "networks", proxy_path=self.proxy_path)
        query_string = self.query_params.to_query_string()
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class _OneManageNetworkActionsPostBase(FabricNameMixin, NDEndpointBaseModel):
    """Shared POST action path handling for onemanage network actions."""

    class_name: Literal["_OneManageNetworkActionsPostBase"] = Field(
        default="_OneManageNetworkActionsPostBase",
        frozen=True,
        description="Internal helper class name",
    )
    endpoint_params: NetworkActionsNoParamsEndpointParams | NetworkActionsTicketEndpointParams
    proxy_path: str = Field(default="", description="Optional ND proxy prefix")
    action_name: str

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = BasePath.top_down("networks", self.action_name, proxy_path=self.proxy_path)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsNetworkActionsDeployPost(_OneManageNetworkActionsPostBase):
    """POST /onemanage/top-down/networks/deploy."""

    class_name: Literal["EpOneManageFabricsNetworkActionsDeployPost"] = Field(
        default="EpOneManageFabricsNetworkActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["deploy"] = Field(default="deploy", frozen=True)
    endpoint_params: NetworkActionsTicketEndpointParams = Field(default_factory=NetworkActionsTicketEndpointParams)
