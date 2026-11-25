# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Fabric-scoped Smart Switch onboarding, deboarding, and HA pairing."""

from __future__ import annotations

from typing import Literal
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict, Field
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.mixins import (
    ClusterNameMixin,
    FabricNameMixin,
    FilterMixin,
    MaxMixin,
    OffsetMixin,
    SwitchIdMixin,
    TicketIdMixin,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import EndpointQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


# Smart Switch onboarding and deboarding


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


# HA endpoint query parameters


class SmartSwitchHaEndpointParams(ClusterNameMixin, EndpointQueryParams):
    """Target-cluster routing for the Smart Switch HA endpoints."""

    model_config = ConfigDict(validate_assignment=True)


class SmartSwitchHaListParams(FilterMixin, MaxMixin, OffsetMixin, SmartSwitchHaEndpointParams):
    """Filters, sorting, and pagination for the HA inventory."""

    sort: str | None = Field(default=None, min_length=1, description="Sort fields and directions")


# Shared HA endpoint path


class _EpManageSmartSwitchHaBase(FabricNameMixin, NDEndpointBaseModel):
    """Build fabric-scoped HA routes and append encoded query parameters."""

    min_controller_version: str = "4.3.1"
    endpoint_params: SmartSwitchHaEndpointParams = Field(default_factory=SmartSwitchHaEndpointParams)

    def _build_ha_path(self, *endpoint_segments: str) -> str:
        if self.fabric_name is None:
            raise ValueError("fabric_name must be set")
        path = BasePath.path("fabrics", quote(self.fabric_name, safe=""), "smartSwitches", *endpoint_segments)
        query_string = self.endpoint_params.to_query_string()
        return f"{path}?{query_string}" if query_string else path


# HA inventory and peer recommendations


class EpManageSmartSwitchesHaPairsGet(_EpManageSmartSwitchHaBase):
    """List HA associations and candidate switches in a fabric."""

    class_name: Literal["EpManageSmartSwitchesHaPairsGet"] = Field(default="EpManageSmartSwitchesHaPairsGet", frozen=True)
    endpoint_params: SmartSwitchHaListParams = Field(default_factory=SmartSwitchHaListParams)

    @property
    def path(self) -> str:
        return self._build_ha_path("haPairs")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class EpManageSmartSwitchHaRecommendationsGet(SwitchIdMixin, _EpManageSmartSwitchHaBase):
    """Read the eligible peers for one Smart Switch."""

    class_name: Literal["EpManageSmartSwitchHaRecommendationsGet"] = Field(default="EpManageSmartSwitchHaRecommendationsGet", frozen=True)

    def set_identifiers(self, identifier: IdentifierKey | None = None) -> None:
        """Set the switch whose eligible peers will be queried."""
        self.switch_id = identifier

    @property
    def path(self) -> str:
        if self.switch_id is None:
            raise ValueError("switch_id must be set")
        return self._build_ha_path(quote(self.switch_id, safe=""), "haPairRecommendations")

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


# HA pair and unpair actions


class _EpManageSmartSwitchHaActionBase(_EpManageSmartSwitchHaBase):
    """Share the POST verb for the concrete HA actions."""

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class EpManageSmartSwitchesHaPairPost(_EpManageSmartSwitchHaActionBase):
    """Stage a Smart Switch HA pair."""

    class_name: Literal["EpManageSmartSwitchesHaPairPost"] = Field(default="EpManageSmartSwitchesHaPairPost", frozen=True)

    @property
    def path(self) -> str:
        return self._build_ha_path("actions", "haPair")


class EpManageSmartSwitchesHaUnpairPost(_EpManageSmartSwitchHaActionBase):
    """Stage removal of one or more Smart Switch HA pairs."""

    class_name: Literal["EpManageSmartSwitchesHaUnpairPost"] = Field(default="EpManageSmartSwitchesHaUnpairPost", frozen=True)

    @property
    def path(self) -> str:
        return self._build_ha_path("actions", "haUnpair")
