# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND onemanage fabric VRF endpoint models.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, VrfNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
    VrfActionsNoParamsEndpointParams,
    VrfActionsTicketEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_attachments import (
    VrfAttachmentsNoParamsEndpointParams,
    VrfAttachmentsQueryEndpointParams,
    VrfAttachmentsTicketEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    VrfGetEndpointParams,
    VrfsGetEndpointParams,
    VrfsTicketEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class _EpOneManageFabricsVrfsBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for onemanage fabric VRF endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.manage_fabrics(self.fabric_name, "vrfs", proxy_path=self.proxy_path)


class EpOneManageFabricsVrfsGet(_EpOneManageFabricsVrfsBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}/vrfs."""

    class_name: Literal["EpOneManageFabricsVrfsGet"] = Field(
        default="EpOneManageFabricsVrfsGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsGetEndpointParams = Field(default_factory=VrfsGetEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpOneManageFabricsVrfsPost(_EpOneManageFabricsVrfsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfs."""

    class_name: Literal["EpOneManageFabricsVrfsPost"] = Field(
        default="EpOneManageFabricsVrfsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsTicketEndpointParams = Field(default_factory=VrfsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class _EpOneManageFabricsVrfsVrfNameBase(FabricNameMixin, VrfNameMixin, NDEndpointBaseModel):
    """Base class for onemanage single VRF endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        if self.vrf_name is None:
            raise ValueError("vrf_name must be set before accessing path")
        return BasePath.manage_fabrics(self.fabric_name, "vrfs", self.vrf_name, proxy_path=self.proxy_path)


class EpOneManageFabricsVrfsVrfNameGet(_EpOneManageFabricsVrfsVrfNameBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}/vrfs/{vrfName}."""

    class_name: Literal["EpOneManageFabricsVrfsVrfNameGet"] = Field(
        default="EpOneManageFabricsVrfsVrfNameGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfGetEndpointParams = Field(default_factory=VrfGetEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpOneManageFabricsVrfsVrfNamePut(_EpOneManageFabricsVrfsVrfNameBase):
    """PUT /api/v1/oneManage/manage/fabrics/{fabricName}/vrfs/{vrfName}."""

    class_name: Literal["EpOneManageFabricsVrfsVrfNamePut"] = Field(
        default="EpOneManageFabricsVrfsVrfNamePut",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsTicketEndpointParams = Field(default_factory=VrfsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpOneManageFabricsVrfsVrfNameDelete(_EpOneManageFabricsVrfsVrfNameBase):
    """DELETE /api/v1/oneManage/manage/fabrics/{fabricName}/vrfs/{vrfName}."""

    class_name: Literal["EpOneManageFabricsVrfsVrfNameDelete"] = Field(
        default="EpOneManageFabricsVrfsVrfNameDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfsTicketEndpointParams = Field(default_factory=VrfsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class _EpOneManageFabricsVrfAttachmentsBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for OneManage VRF attachment endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.manage_fabrics(self.fabric_name, "vrfAttachments", proxy_path=self.proxy_path)


class EpOneManageFabricsVrfAttachmentsPost(_EpOneManageFabricsVrfAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfAttachments."""

    class_name: Literal["EpOneManageFabricsVrfAttachmentsPost"] = Field(
        default="EpOneManageFabricsVrfAttachmentsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsTicketEndpointParams = Field(default_factory=VrfAttachmentsTicketEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{self._base_path}?{query_string}"
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsVrfAttachmentsExportPost(_EpOneManageFabricsVrfAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfAttachments/export."""

    class_name: Literal["EpOneManageFabricsVrfAttachmentsExportPost"] = Field(
        default="EpOneManageFabricsVrfAttachmentsExportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsNoParamsEndpointParams = Field(default_factory=VrfAttachmentsNoParamsEndpointParams)

    @property
    def path(self) -> str:
        query_string = self.endpoint_params.to_query_string()
        path = f"{self._base_path}/export"
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsVrfAttachmentsImportPost(_EpOneManageFabricsVrfAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfAttachments/import."""

    class_name: Literal["EpOneManageFabricsVrfAttachmentsImportPost"] = Field(
        default="EpOneManageFabricsVrfAttachmentsImportPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsTicketEndpointParams = Field(default_factory=VrfAttachmentsTicketEndpointParams)

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


class EpOneManageFabricsVrfAttachmentsQueryPost(_EpOneManageFabricsVrfAttachmentsBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfAttachments/query."""

    class_name: Literal["EpOneManageFabricsVrfAttachmentsQueryPost"] = Field(
        default="EpOneManageFabricsVrfAttachmentsQueryPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: VrfAttachmentsQueryEndpointParams = Field(default_factory=VrfAttachmentsQueryEndpointParams)

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


class _OneManageVrfActionsPostBase(FabricNameMixin, NDEndpointBaseModel):
    """Shared POST action path handling for onemanage VRF actions."""

    class_name: Literal["_OneManageVrfActionsPostBase"] = Field(
        default="_OneManageVrfActionsPostBase",
        frozen=True,
        description="Internal helper class name",
    )
    endpoint_params: VrfActionsNoParamsEndpointParams | VrfActionsTicketEndpointParams
    proxy_path: str = Field(default="", description="Optional ND proxy prefix")
    action_name: str

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        query_string = self.endpoint_params.to_query_string()
        path = BasePath.manage_fabrics(self.fabric_name, "vrfActions", self.action_name, proxy_path=self.proxy_path)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsVrfActionsDeployPost(_OneManageVrfActionsPostBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfActions/deploy."""

    class_name: Literal["EpOneManageFabricsVrfActionsDeployPost"] = Field(
        default="EpOneManageFabricsVrfActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["deploy"] = Field(default="deploy", frozen=True)
    endpoint_params: VrfActionsTicketEndpointParams = Field(default_factory=VrfActionsTicketEndpointParams)


class EpOneManageFabricsVrfActionsRemovePost(_OneManageVrfActionsPostBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/vrfActions/remove."""

    class_name: Literal["EpOneManageFabricsVrfActionsRemovePost"] = Field(
        default="EpOneManageFabricsVrfActionsRemovePost",
        frozen=True,
        description="Class name",
    )
    action_name: Literal["remove"] = Field(default="remove", frozen=True)
    endpoint_params: VrfActionsTicketEndpointParams = Field(default_factory=VrfActionsTicketEndpointParams)
