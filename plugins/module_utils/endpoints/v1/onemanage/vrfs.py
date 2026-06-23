# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND onemanage fabric VRF endpoint models.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin, VrfNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
    VrfActionsNoParamsEndpointParams,
    VrfActionsTicketEndpointParams,
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
        return BasePath.top_down_fabrics(self.fabric_name, "vrfs", proxy_path=self.proxy_path)


class EpOneManageFabricsVrfsGet(_EpOneManageFabricsVrfsBase):
    """GET /onemanage/manage/fabrics/{fabricName}/vrfs."""

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
    """POST /onemanage/manage/fabrics/{fabricName}/vrfs."""

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
        return BasePath.top_down_fabrics(self.fabric_name, "vrfs", self.vrf_name, proxy_path=self.proxy_path)


class EpOneManageFabricsVrfsVrfNameGet(_EpOneManageFabricsVrfsVrfNameBase):
    """GET /onemanage/manage/fabrics/{fabricName}/vrfs/{vrfName}."""

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
    """PUT /onemanage/manage/fabrics/{fabricName}/vrfs/{vrfName}."""

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
    """DELETE /onemanage/manage/fabrics/{fabricName}/vrfs/{vrfName}."""

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


class OneManageVrfBulkDeleteQueryParams(EndpointQueryParams):
    """Query parameters for onemanage VRF bulk delete."""

    vrf_names: str | None = Field(default=None, min_length=1, description="Comma-separated VRF names")

    def to_query_string(self) -> str:
        if not self.vrf_names:
            return ""
        return f"vrf-names={quote(self.vrf_names, safe=',')}"


class EpOneManageFabricsVrfsBulkDelete(_EpOneManageFabricsVrfsBase):
    """DELETE /onemanage/top-down/fabrics/{fabricName}/bulk-delete/vrfs."""

    class_name: Literal["EpOneManageFabricsVrfsBulkDelete"] = Field(
        default="EpOneManageFabricsVrfsBulkDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )
    query_params: OneManageVrfBulkDeleteQueryParams = Field(default_factory=OneManageVrfBulkDeleteQueryParams)

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        path = BasePath.top_down_fabrics(self.fabric_name, "bulk-delete", "vrfs", proxy_path=self.proxy_path)
        query_string = self.query_params.to_query_string()
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


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
        query_string = self.endpoint_params.to_query_string()
        path = BasePath.top_down("vrfs", self.action_name, proxy_path=self.proxy_path)
        if query_string:
            return f"{path}?{query_string}"
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsVrfActionsDeployPost(_OneManageVrfActionsPostBase):
    """POST /onemanage/top-down/vrfs/deploy."""

    class_name: Literal["EpOneManageFabricsVrfActionsDeployPost"] = Field(
        default="EpOneManageFabricsVrfActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )
    action_name: Literal["deploy"] = Field(default="deploy", frozen=True)
    endpoint_params: VrfActionsTicketEndpointParams = Field(default_factory=VrfActionsTicketEndpointParams)
