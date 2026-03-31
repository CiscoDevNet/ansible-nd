# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
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
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairSupport


class VpcPairSupportEndpointParams(
    FromClusterMixin,
    ComponentTypeMixin,
    EndpointQueryParams,
):
    """Endpoint-specific query parameters for vPC pair support endpoint."""


class EpVpcPairSupportGet(
    FabricNameMixin,
    SwitchIdMixin,
    NDEndpointBaseModel,
):
    """
    GET /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPairSupport
    """

    class_name: Literal["EpVpcPairSupportGet"] = Field(
        default="EpVpcPairSupportGet", frozen=True, description="Class name for backward compatibility"
    )
    endpoint_params: VpcPairSupportEndpointParams = Field(
        default_factory=VpcPairSupportEndpointParams, description="Endpoint-specific query parameters"
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
            "vpcPairSupport",
        )
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


__all__ = ["EpVpcPairSupportGet", "VpcPairSupportEndpointParams"]
