# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND onemanage fabric network endpoint models.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, NetworkNameMixin, TicketIdMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_actions import (
    NetworkActionsNoParamsEndpointParams,
    NetworkActionsTicketEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_attachments import (
    NetworkAttachmentsNoParamsEndpointParams,
    NetworkAttachmentsQueryEndpointParams,
    NetworkAttachmentsTicketEndpointParams,
    NetworkAttachmentsValidateInterfacesEndpointParams,
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
        return BasePath.manage_fabrics(self.fabric_name, "networks", proxy_path=self.proxy_path)


class EpOneManageFabricsNetworksGet(_EpOneManageFabricsNetworksBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}/networks."""

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
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networks."""

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
        return BasePath.manage_fabrics(self.fabric_name, "networks", self.network_name, proxy_path=self.proxy_path)


class EpOneManageFabricsNetworksNetworkNameGet(_EpOneManageFabricsNetworksNetworkNameBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}/networks/{networkName}."""

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
    """PUT /api/v1/oneManage/manage/fabrics/{fabricName}/networks/{networkName}."""

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
    """DELETE /api/v1/oneManage/manage/fabrics/{fabricName}/networks/{networkName}."""

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


class _EpOneManageFabricsNetworkAttachmentsBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for OneManage network attachment endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.manage_fabrics(self.fabric_name, "networkAttachments", proxy_path=self.proxy_path)


class EpOneManageFabricsNetworkAttachmentsPost(_EpOneManageFabricsNetworkAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkAttachments."""

    class_name: Literal["EpOneManageFabricsNetworkAttachmentsPost"] = Field(
        default="EpOneManageFabricsNetworkAttachmentsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsTicketEndpointParams = Field(default_factory=NetworkAttachmentsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost(_EpOneManageFabricsNetworkAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkAttachments/validateInterfaces."""

    class_name: Literal["EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost"] = Field(
        default="EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsValidateInterfacesEndpointParams = Field(default_factory=NetworkAttachmentsValidateInterfacesEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = f"{self._base_path}/validateInterfaces"
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsNetworkAttachmentsExportPost(_EpOneManageFabricsNetworkAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkAttachment/export."""

    class_name: Literal["EpOneManageFabricsNetworkAttachmentsExportPost"] = Field(
        default="EpOneManageFabricsNetworkAttachmentsExportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsNoParamsEndpointParams = Field(default_factory=NetworkAttachmentsNoParamsEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        path = BasePath.manage_fabrics(self.fabric_name, "networkAttachment", "export", proxy_path=self.proxy_path)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsNetworkAttachmentsImportPost(_EpOneManageFabricsNetworkAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkAttachments/import."""

    class_name: Literal["EpOneManageFabricsNetworkAttachmentsImportPost"] = Field(
        default="EpOneManageFabricsNetworkAttachmentsImportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsTicketEndpointParams = Field(default_factory=NetworkAttachmentsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = f"{self._base_path}/import"
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsNetworkAttachmentsQueryPost(_EpOneManageFabricsNetworkAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkAttachments/query."""

    class_name: Literal["EpOneManageFabricsNetworkAttachmentsQueryPost"] = Field(
        default="EpOneManageFabricsNetworkAttachmentsQueryPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworkAttachmentsQueryEndpointParams = Field(default_factory=NetworkAttachmentsQueryEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = f"{self._base_path}/query"
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


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
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        query_string = self.endpoint_params.to_query_string()
        path = BasePath.manage_fabrics(self.fabric_name, "networkActions", self.action_name, proxy_path=self.proxy_path)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsNetworkActionsRemovePost(_OneManageNetworkActionsPostBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkActions/remove."""

    class_name: Literal["EpOneManageFabricsNetworkActionsRemovePost"] = Field(
        default="EpOneManageFabricsNetworkActionsRemovePost",
        frozen=True,
        description="Class name",
    )
    action_name: Literal["remove"] = Field(default="remove", frozen=True)
    endpoint_params: NetworkActionsTicketEndpointParams = Field(default_factory=NetworkActionsTicketEndpointParams)


class EpOneManageFabricsNetworkActionsDeployPost(_OneManageNetworkActionsPostBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/networkActions/deploy."""

    class_name: Literal["EpOneManageFabricsNetworkActionsDeployPost"] = Field(
        default="EpOneManageFabricsNetworkActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["deploy"] = Field(default="deploy", frozen=True)
    endpoint_params: NetworkActionsTicketEndpointParams = Field(default_factory=NetworkActionsTicketEndpointParams)


class OneManageSwitchActionsDeployEndpointParams(TicketIdMixin, EndpointQueryParams):
    """Query parameters for OneManage switch deploy."""

    force_show_run: bool = Field(default=False, description="Force show running config before deploy")


class EpOneManageFabricsSwitchActionsDeployPost(FabricNameMixin, NDEndpointBaseModel):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/switchActions/deploy."""

    class_name: Literal["EpOneManageFabricsSwitchActionsDeployPost"] = Field(
        default="EpOneManageFabricsSwitchActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: OneManageSwitchActionsDeployEndpointParams = Field(default_factory=OneManageSwitchActionsDeployEndpointParams)
    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        query_string = self.endpoint_params.to_query_string()
        path = BasePath.manage_fabrics(self.fabric_name, "switchActions", "deploy", proxy_path=self.proxy_path)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
