# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Network Actions endpoint models.

Endpoints covered:
- Deploy networks
- Export networks
- Import networks
- Preview networks
- Propose multicast IP
- Remove networks
- Stretch networks
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
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class NetworkActionsTicketEndpointParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """Query parameters for network actions with optional ticketId."""


class NetworkActionsNoParamsEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Query parameters for network actions with only optional clusterName."""


class _EpManageFabricsNetworkActionsBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for /api/v1/manage/fabrics/{fabricName}/networkActions."""

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.path("fabrics", self.fabric_name, "networkActions")

    def _action_path(self, action: str) -> str:
        return BasePath.path("fabrics", self.fabric_name, "networkActions", action)


class _NetworkActionsPostBase(_EpManageFabricsNetworkActionsBase):
    """Shared POST action path handling."""

    class_name: Literal["_NetworkActionsPostBase"] = Field(
        default="_NetworkActionsPostBase",
        frozen=True,
        description="Internal helper class name",
    )
    endpoint_params: NetworkActionsNoParamsEndpointParams | NetworkActionsTicketEndpointParams
    action_name: str

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = self._action_path(self.action_name)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageFabricsNetworkActionsDeployPost(_NetworkActionsPostBase):
    """POST /fabrics/{fabricName}/networkActions/deploy."""

    class_name: Literal["EpManageFabricsNetworkActionsDeployPost"] = Field(
        default="EpManageFabricsNetworkActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["deploy"] = Field(default="deploy", frozen=True)
    endpoint_params: NetworkActionsTicketEndpointParams = Field(default_factory=NetworkActionsTicketEndpointParams)


class EpManageFabricsNetworkActionsExportPost(_NetworkActionsPostBase):
    """POST /fabrics/{fabricName}/networkActions/export."""

    class_name: Literal["EpManageFabricsNetworkActionsExportPost"] = Field(
        default="EpManageFabricsNetworkActionsExportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["export"] = Field(default="export", frozen=True)
    endpoint_params: NetworkActionsNoParamsEndpointParams = Field(default_factory=NetworkActionsNoParamsEndpointParams)


class EpManageFabricsNetworkActionsImportPost(_NetworkActionsPostBase):
    """POST /fabrics/{fabricName}/networkActions/import."""

    class_name: Literal["EpManageFabricsNetworkActionsImportPost"] = Field(
        default="EpManageFabricsNetworkActionsImportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["import"] = Field(default="import", frozen=True)
    endpoint_params: NetworkActionsTicketEndpointParams = Field(default_factory=NetworkActionsTicketEndpointParams)


class EpManageFabricsNetworkActionsPreviewPost(_NetworkActionsPostBase):
    """POST /fabrics/{fabricName}/networkActions/preview."""

    class_name: Literal["EpManageFabricsNetworkActionsPreviewPost"] = Field(
        default="EpManageFabricsNetworkActionsPreviewPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["preview"] = Field(default="preview", frozen=True)
    endpoint_params: NetworkActionsNoParamsEndpointParams = Field(default_factory=NetworkActionsNoParamsEndpointParams)


class EpManageFabricsNetworkActionsProposeMulticastIpGet(_EpManageFabricsNetworkActionsBase):
    """GET /fabrics/{fabricName}/networkActions/proposeMulticastIp."""

    class_name: Literal["EpManageFabricsNetworkActionsProposeMulticastIpGet"] = Field(
        default="EpManageFabricsNetworkActionsProposeMulticastIpGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkActionsNoParamsEndpointParams = Field(default_factory=NetworkActionsNoParamsEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = self._action_path("proposeMulticastIp")
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageFabricsNetworkActionsRemovePost(_NetworkActionsPostBase):
    """POST /fabrics/{fabricName}/networkActions/remove."""

    class_name: Literal["EpManageFabricsNetworkActionsRemovePost"] = Field(
        default="EpManageFabricsNetworkActionsRemovePost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["remove"] = Field(default="remove", frozen=True)
    endpoint_params: NetworkActionsTicketEndpointParams = Field(default_factory=NetworkActionsTicketEndpointParams)


class EpManageFabricsNetworkActionsStretchPost(_NetworkActionsPostBase):
    """POST /fabrics/{fabricName}/networkActions/stretch."""

    class_name: Literal["EpManageFabricsNetworkActionsStretchPost"] = Field(
        default="EpManageFabricsNetworkActionsStretchPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["stretch"] = Field(default="stretch", frozen=True)
    endpoint_params: NetworkActionsNoParamsEndpointParams = Field(default_factory=NetworkActionsNoParamsEndpointParams)
