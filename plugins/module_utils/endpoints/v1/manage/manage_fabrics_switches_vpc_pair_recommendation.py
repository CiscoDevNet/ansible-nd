# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from typing import Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    FabricNameMixin,
    FromClusterMixin,
    SwitchIdMixin,
    UseVirtualPeerLinkMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairRecommendation
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class VpcPairRecommendationEndpointParams(
    FromClusterMixin,
    UseVirtualPeerLinkMixin,
    EndpointQueryParams,
):
    """Endpoint-specific query parameters for vPC pair recommendation endpoint."""

    # Keep this optional for this endpoint so query param is omitted unless explicitly set.
    use_virtual_peer_link: Optional[bool] = Field(default=None, description="Optional virtual peer link flag")


class EpVpcPairRecommendationGet(
    FabricNameMixin,
    SwitchIdMixin,
    NDEndpointBaseModel,
):
    """
    GET /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairRecommendation
    """

    model_config = COMMON_CONFIG
    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpVpcPairRecommendationGet"] = Field(
        default="EpVpcPairRecommendationGet", frozen=True, description="Class name for backward compatibility"
    )
    endpoint_params: VpcPairRecommendationEndpointParams = Field(
        default_factory=VpcPairRecommendationEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def path(self) -> str:
        if self.fabric_name is None or self.switch_id is None:
            raise ValueError("fabric_name and switch_id are required")
        base_path = BasePath.path(
            "fabrics",
            self.fabric_name,
            "switches",
            self.switch_id,
            "vpcPairRecommendation",
        )
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


__all__ = ["EpVpcPairRecommendationGet", "VpcPairRecommendationEndpointParams"]
