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
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/actions/deploy
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class FabricDeployQueryParams(EndpointQueryParams):
    """
    Query parameters for the fabric config deploy endpoint.

    ``inclAllFabricGroupsSwitches`` defaults to ``false`` in the Manage API, which
    does not deploy pending changes to a fabric group's member-fabric switches.
    Setting it to ``true`` makes a fabric group ``global`` deploy reach every
    member-fabric switch.
    """

    incl_all_fabric_groups_switches: bool = False

    def to_query_string(self) -> str:
        # Emit the flag only when enabled so ordinary single-fabric deploy URLs
        # stay unchanged (no query string).
        if not self.incl_all_fabric_groups_switches:
            return ""
        return "inclAllFabricGroupsSwitches=true"


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
    endpoint_params: FabricDeployQueryParams = Field(default_factory=FabricDeployQueryParams)

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name is required")
        base = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "actions", "deploy")
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base}?{query_string}"
        return base

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST
