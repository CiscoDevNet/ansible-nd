# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from typing import Literal

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
    ViewMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    CompositeQueryParams,
    EndpointQueryParams,
    LuceneQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/switches
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class FabricSwitchesEndpointParams(FromClusterMixin, ViewMixin, EndpointQueryParams):
    """Endpoint-specific query parameters for fabric switches endpoint."""


class EpFabricSwitchesGet(
    FabricNameMixin,
    NDEndpointBaseModel,
):
    """
    GET /api/v1/manage/fabrics/{fabricName}/switches
    """

    model_config = COMMON_CONFIG
    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpFabricSwitchesGet"] = Field(default="EpFabricSwitchesGet")
    endpoint_params: FabricSwitchesEndpointParams = Field(default_factory=FabricSwitchesEndpointParams, description="Endpoint-specific query parameters")
    lucene_params: LuceneQueryParams = Field(default_factory=LuceneQueryParams, description="Lucene query parameters")

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name is required")
        base_path = BasePath.path("fabrics", self.fabric_name, "switches")
        query_params = CompositeQueryParams().add(self.endpoint_params).add(self.lucene_params)
        query_string = query_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET
