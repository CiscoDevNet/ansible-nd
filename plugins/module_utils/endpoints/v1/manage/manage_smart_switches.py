# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Fabric-scoped Smart Switch onboarding and deboarding actions."""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import ClusterNameMixin, FabricNameMixin, SwitchIdMixin, TicketIdMixin
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class SmartSwitchActionParams(ClusterNameMixin, EndpointQueryParams):
    """Bulk action parameters: only cluster routing is documented."""


class SmartSwitchIndividualDeboardParams(ClusterNameMixin, TicketIdMixin, EndpointQueryParams):
    """The individual DELETE also supports a change-control ticket."""


class EpManageSmartSwitchesOnboardPost(FabricNameMixin, NDEndpointBaseModel):
    """POST one bulk onboarding request; expect a keyed HTTP 202 result body."""

    class_name: Literal["EpManageSmartSwitchesOnboardPost"] = Field(default="EpManageSmartSwitchesOnboardPost", frozen=True)
    min_controller_version: str = "4.2.1"
    endpoint_params: SmartSwitchActionParams = Field(default_factory=SmartSwitchActionParams)

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "smartSwitches", "actions", "updateSecureTenant")
        query = self.endpoint_params.to_query_string()
        return f"{path}?{query}" if query else path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSmartSwitchesDeboardPost(FabricNameMixin, NDEndpointBaseModel):
    """POST one identifier-only bulk deboarding request; expect bodyless 202."""

    class_name: Literal["EpManageSmartSwitchesDeboardPost"] = Field(default="EpManageSmartSwitchesDeboardPost", frozen=True)
    min_controller_version: str = "4.2.1"
    endpoint_params: SmartSwitchActionParams = Field(default_factory=SmartSwitchActionParams)

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "smartSwitch", "actions", "remove")
        query = self.endpoint_params.to_query_string()
        return f"{path}?{query}" if query else path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSmartSwitchesDeboardDelete(FabricNameMixin, SwitchIdMixin, NDEndpointBaseModel):
    """DELETE one association; a 204 proves the individual deboarding effect."""

    class_name: Literal["EpManageSmartSwitchesDeboardDelete"] = Field(default="EpManageSmartSwitchesDeboardDelete", frozen=True)
    min_controller_version: str = "4.2.1"
    endpoint_params: SmartSwitchIndividualDeboardParams = Field(default_factory=SmartSwitchIndividualDeboardParams)

    def set_identifiers(self, identifier=None) -> None:
        self.switch_id = identifier

    @property
    def path(self) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set")
        if self.switch_id is None:
            raise ValueError("switch_id must be set")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "smartSwitches", quote(self.switch_id, safe=""), "actions", "deboard")
        query = self.endpoint_params.to_query_string()
        return f"{path}?{query}" if query else path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE
