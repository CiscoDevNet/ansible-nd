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
    ComponentTypeMixin,
    FabricNameMixin,
    FromClusterMixin,
    SwitchIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.vpc_pair_base_paths import (
    VpcPairBasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairOverview
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class EpVpcPairOverviewGet(
    FabricNameMixin,
    SwitchIdMixin,
    FromClusterMixin,
    ComponentTypeMixin,
    NDEndpointBaseModel,
):
    """
    GET /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairOverview
    """

    model_config = COMMON_CONFIG
    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpVpcPairOverviewGet"] = Field(default="EpVpcPairOverviewGet")

    @property
    def path(self) -> str:
        if self.fabric_name is None or self.switch_id is None:
            raise ValueError("fabric_name and switch_id are required")
        return VpcPairBasePath.vpc_pair_overview(self.fabric_name, self.switch_id)

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


__all__ = ["EpVpcPairOverviewGet"]
