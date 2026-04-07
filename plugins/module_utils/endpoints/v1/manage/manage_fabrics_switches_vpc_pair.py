# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
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
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    EndpointQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# API path covered by this file:
# /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair


class _EpVpcPairBase(
    FabricNameMixin,
    SwitchIdMixin,
    NDEndpointBaseModel,
):
    @property
    def path(self) -> str:
        if self.fabric_name is None or self.switch_id is None:
            raise ValueError("fabric_name and switch_id are required")
        base_path = BasePath.path(
            "fabrics",
            self.fabric_name,
            "switches",
            self.switch_id,
            "vpcPair",
        )
        query_string = self.endpoint_params.to_query_string()
        if query_string:
            return f"{base_path}?{query_string}"
        return base_path


class VpcPairGetEndpointParams(FromClusterMixin, EndpointQueryParams):
    """Endpoint-specific query parameters for vPC pair GET endpoint."""


class VpcPairPutEndpointParams(VpcPairGetEndpointParams, TicketIdMixin):
    """Endpoint-specific query parameters for vPC pair PUT endpoint."""


class EpVpcPairGet(_EpVpcPairBase):
    """
    GET /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
    """

    class_name: Literal["EpVpcPairGet"] = Field(
        default="EpVpcPairGet", frozen=True, description="Class name for backward compatibility"
    )
    endpoint_params: VpcPairGetEndpointParams = Field(
        default_factory=VpcPairGetEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpVpcPairPut(_EpVpcPairBase):
    """
    PUT /api/v1/manage/fabrics/{fabricName}/switches/{switchId}/vpcPair
    """

    class_name: Literal["EpVpcPairPut"] = Field(
        default="EpVpcPairPut", frozen=True, description="Class name for backward compatibility"
    )
    endpoint_params: VpcPairPutEndpointParams = Field(
        default_factory=VpcPairPutEndpointParams, description="Endpoint-specific query parameters"
    )

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT
