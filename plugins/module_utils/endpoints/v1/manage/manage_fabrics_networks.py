# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
ND Manage Fabric Networks endpoint models.

This module contains the endpoint definition needed by the VRF workflow to
check whether networks still reference a VRF before attempting deletion.
"""

from __future__ import annotations

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class NetworksGetEndpointParams(ClusterNameMixin, FilterMixin, MaxMixin, OffsetMixin, EndpointQueryParams):
    """
    Endpoint-specific query parameters for the list networks endpoint.
    """

    service_network: Optional[bool] = Field(default=None, description="Whether to include service networks")
    sort: Optional[str] = Field(default=None, min_length=1, description="Sort field and direction (e.g. 'networkName:asc')")


class EpManageFabricsNetworksGet(FabricNameMixin, NDEndpointBaseModel):
    """
    List Networks Endpoint.

    Path:
    - /api/v1/manage/fabrics/{fabricName}/networks
    """

    class_name: Literal["EpManageFabricsNetworksGet"] = Field(
        default="EpManageFabricsNetworksGet",
        frozen=True,
        description="Class name for backward compatibility",
    )
    endpoint_params: NetworksGetEndpointParams = Field(
        default_factory=NetworksGetEndpointParams,
        description="Endpoint-specific query parameters",
    )

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set before accessing path")
        base = BasePath.path("fabrics", self.fabric_name, "networks")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET
