# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FromClusterMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

COMMON_CONFIG = ConfigDict(validate_assignment=True)


# Config save query parameters


class FabricConfigSaveQueryParams(ClusterNameMixin, EndpointQueryParams):
    """Cluster routing for the fabric recalculation endpoint."""

    model_config = COMMON_CONFIG


# Fabric config save action


class EpFabricConfigSavePost(
    FabricNameMixin,
    FromClusterMixin,
    NDEndpointBaseModel,
):
    """
    POST /api/v1/manage/fabrics/{fabricName}/actions/configSave
    """

    model_config = COMMON_CONFIG
    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpFabricConfigSavePost"] = Field(default="EpFabricConfigSavePost")
    endpoint_params: FabricConfigSaveQueryParams = Field(default_factory=FabricConfigSaveQueryParams)

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name is required")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "actions", "configSave")
        query_string = self.endpoint_params.to_query_string()
        return f"{path}?{query_string}" if query_string else path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
