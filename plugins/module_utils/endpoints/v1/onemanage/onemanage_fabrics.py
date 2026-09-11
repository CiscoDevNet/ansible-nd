# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND OneManage fabric endpoint models.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class _EpOneManageFabricsFabricNameBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for OneManage fabric endpoints."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    def set_identifiers(self, identifier: IdentifierKey = None):
        self.fabric_name = identifier

    @property
    def _base_path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        return BasePath.manage_fabrics(self.fabric_name, proxy_path=self.proxy_path)


class EpOneManageFabricsFabricNameGet(_EpOneManageFabricsFabricNameBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}."""

    class_name: Literal["EpOneManageFabricsFabricNameGet"] = Field(
        default="EpOneManageFabricsFabricNameGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpOneManageFabricsMembersGet(_EpOneManageFabricsFabricNameBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}/members."""

    class_name: Literal["EpOneManageFabricsMembersGet"] = Field(
        default="EpOneManageFabricsMembersGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/members"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpOneManageFabricsMembersAddPost(_EpOneManageFabricsFabricNameBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/actions/addMembers."""

    class_name: Literal["EpOneManageFabricsMembersAddPost"] = Field(
        default="EpOneManageFabricsMembersAddPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/actions/addMembers"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsMembersRemovePost(_EpOneManageFabricsFabricNameBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/actions/removeMembers."""

    class_name: Literal["EpOneManageFabricsMembersRemovePost"] = Field(
        default="EpOneManageFabricsMembersRemovePost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/actions/removeMembers"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsConfigSavePost(_EpOneManageFabricsFabricNameBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/actions/configSave."""

    class_name: Literal["EpOneManageFabricsConfigSavePost"] = Field(
        default="EpOneManageFabricsConfigSavePost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/actions/configSave"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsDeployPost(_EpOneManageFabricsFabricNameBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/actions/deploy."""

    class_name: Literal["EpOneManageFabricsDeployPost"] = Field(
        default="EpOneManageFabricsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/actions/deploy"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsSwitchesGet(_EpOneManageFabricsFabricNameBase):
    """GET /api/v1/oneManage/manage/fabrics/{fabricName}/switches."""

    class_name: Literal["EpOneManageFabricsSwitchesGet"] = Field(
        default="EpOneManageFabricsSwitchesGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/switches"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpOneManageFabricsSwitchActionsDeployPost(_EpOneManageFabricsFabricNameBase):
    """POST /api/v1/oneManage/manage/fabrics/{fabricName}/switchActions/deploy."""

    class_name: Literal["EpOneManageFabricsSwitchActionsDeployPost"] = Field(
        default="EpOneManageFabricsSwitchActionsDeployPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return f"{self._base_path}/switchActions/deploy"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsPut(_EpOneManageFabricsFabricNameBase):
    """PUT /api/v1/oneManage/manage/fabrics/{fabricName}."""

    class_name: Literal["EpOneManageFabricsPut"] = Field(
        default="EpOneManageFabricsPut",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


class EpOneManageFabricsDelete(_EpOneManageFabricsFabricNameBase):
    """DELETE /api/v1/oneManage/manage/fabrics/{fabricName}."""

    class_name: Literal["EpOneManageFabricsDelete"] = Field(
        default="EpOneManageFabricsDelete",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE


class _EpOneManageFabricsCollectionBase(NDEndpointBaseModel):
    """Base class for OneManage collection-level fabric endpoints (no fabric name)."""

    proxy_path: str = Field(default="", description="Optional ND proxy prefix")

    @property
    def _collection_path(self) -> str:
        return BasePath.manage_fabrics(proxy_path=self.proxy_path)


class EpOneManageFabricsPost(_EpOneManageFabricsCollectionBase):
    """POST /api/v1/oneManage/manage/fabrics."""

    class_name: Literal["EpOneManageFabricsPost"] = Field(
        default="EpOneManageFabricsPost",
        frozen=True,
        description="Class name for backward compatibility",
    )

    @property
    def path(self) -> str:
        return self._collection_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpOneManageFabricsListGet(_EpOneManageFabricsCollectionBase):
    """GET /api/v1/oneManage/manage/fabrics with optional category filter."""

    class_name: Literal["EpOneManageFabricsListGet"] = Field(
        default="EpOneManageFabricsListGet",
        frozen=True,
        description="Class name for backward compatibility",
    )

    category: str | None = Field(default=None, description="Filter by fabric category")

    @property
    def path(self) -> str:
        if self.category:
            return f"{self._collection_path}?category={self.category}"
        return self._collection_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET
