# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND OneManage fabric network endpoint models used by VRF dependency checks.
"""

from __future__ import absolute_import, annotations, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import FabricNameMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    NetworksGetEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class _EpOneManageFabricsNetworksBase(FabricNameMixin, NDEndpointBaseModel):
    """Base class for OneManage fabric network endpoints."""

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
