# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

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
    FilterMixin,
    FromClusterMixin,
    PaginationMixin,
    SortMixin,
    ViewMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/vpcPairs
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class EpVpcPairsListGet(
    FabricNameMixin,
    FromClusterMixin,
    FilterMixin,
    PaginationMixin,
    SortMixin,
    ViewMixin,
    NDEndpointBaseModel,
):
    """
    GET /api/v1/manage/fabrics/{fabricName}/vpcPairs
    """

    model_config = COMMON_CONFIG
    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpVpcPairsListGet"] = Field(default="EpVpcPairsListGet")

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name is required")
        return BasePath.path("fabrics", self.fabric_name, "vpcPairs")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


__all__ = ["EpVpcPairsListGet"]
