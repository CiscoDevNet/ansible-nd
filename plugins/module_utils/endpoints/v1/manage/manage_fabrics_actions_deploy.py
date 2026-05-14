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
    FabricNameMixin,
    FromClusterMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/actions/deploy
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class EpFabricDeployPost(
    FabricNameMixin,
    FromClusterMixin,
    NDEndpointBaseModel,
):
    """
    POST /api/v1/manage/fabrics/{fabricName}/actions/deploy
    """

    model_config = COMMON_CONFIG
    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpFabricDeployPost"] = Field(default="EpFabricDeployPost")
    force_show_run: bool = Field(default=False, description="Include forceShowRun=true in the deploy query string.")

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name is required")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "actions", "deploy")
        if self.force_show_run:
            return "{0}?forceShowRun=true".format(path)
        return path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


EpManageFabricsActionsDeployPost = EpFabricDeployPost
