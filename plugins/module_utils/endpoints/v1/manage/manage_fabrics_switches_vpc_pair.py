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
    FromClusterMixin,
    SwitchIdMixin,
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
COMMON_CONFIG = ConfigDict(validate_assignment=True)


class _EpVpcPairBase(
    FabricNameMixin,
    SwitchIdMixin,
    FromClusterMixin,
    NDEndpointBaseModel,
):
    model_config = COMMON_CONFIG

    @property
    def path(self) -> str:
        if self.fabric_name is None or self.switch_id is None:
            raise ValueError("fabric_name and switch_id are required")
        return BasePath.path(
            "fabrics",
            self.fabric_name,
            "switches",
            self.switch_id,
            "vpcPair",
        )


class EpVpcPairGet(_EpVpcPairBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
    """

    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpVpcPairGet"] = Field(default="EpVpcPairGet")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpVpcPairPut(_EpVpcPairBase, TicketIdMixin):
    """
    PUT /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
    """

    api_version: Literal["v1"] = Field(default="v1")
    min_controller_version: str = Field(default="3.0.0")
    class_name: Literal["EpVpcPairPut"] = Field(default="EpVpcPairPut")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT


__all__ = ["EpVpcPairGet", "EpVpcPairPut"]
