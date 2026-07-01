# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network action models for Nexus Dashboard Manage APIs."""

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    ConfigurationStatus,
    OperationStatus,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.validators import (
    NetworkValidators,
)


class MultiStatusBaseModel(NDNestedModel):
    """Common status fields returned in network 207 responses."""

    identifiers: ClassVar[list[str]] = []
    network_name: str | None = Field(default=None, alias="networkName")
    display_name: str | None = Field(default=None, alias="displayName")
    status: OperationStatus | None = Field(default=None)
    message: str | None = Field(default=None)


class NetworkSwitchesListModel(NDBaseModel):
    """Request body shared by network deploy, preview, and attachment export."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    network_names: list[str] | None = Field(default=None, alias="networkNames", min_length=1)
    switch_fabric_names: list[str] | None = Field(default=None, alias="switchFabricNames")
    switch_ids: list[str] | None = Field(default=None, alias="switchIds")

    @field_validator("network_names", mode="before")
    @classmethod
    def validate_network_names(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return [NetworkValidators.validate_network_name(item) for item in v]


class NetworkExportRequestModel(NDBaseModel):
    """Request body for POST /fabrics/{fabricName}/networkActions/export."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    network_names: list[str] | None = Field(default=None, alias="networkNames")

    @field_validator("network_names", mode="before")
    @classmethod
    def validate_network_names(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return [NetworkValidators.validate_network_name(item) for item in v]


class NetworkRemoveRequestModel(NDBaseModel):
    """Request body for POST /fabrics/{fabricName}/networkActions/remove."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    network_names: list[str] = Field(default=..., alias="networkNames", min_length=1)

    @field_validator("network_names", mode="before")
    @classmethod
    def validate_network_names(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return [NetworkValidators.validate_network_name(item) for item in v]


class DeploymentStatusModel(NDBaseModel):
    """Response for network deploy operations."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    status: str | None = Field(default=None, description="Deployment status message")


class NetworkRemoveResponseModel(NDBaseModel):
    """Response body for network remove operations."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    results: list[MultiStatusBaseModel] | None = Field(default=None)


class VrfOrNetworkPreviewModel(NDNestedModel):
    """Common pending config preview fields for VRF or network attachment."""

    identifiers: ClassVar[list[str]] = []
    fabric_name: str | None = Field(default=None, alias="fabricName")
    switch_id: str | None = Field(default=None, alias="switchId")
    switch_ip: str | None = Field(default=None, alias="switchIp")
    switch_name: str | None = Field(default=None, alias="switchName")
    switch_role: SwitchRole | None = Field(default=None, alias="switchRole")
    status: ConfigurationStatus | None = Field(default=None)
    pending_configs: list[str] | None = Field(default=None, alias="pendingConfigs")


class NetworkPreviewModel(VrfOrNetworkPreviewModel):
    """Preview of pending network configuration for one switch/network pair."""

    display_name: str | None = Field(default=None, alias="displayName")
    network_name: str = Field(default=..., alias="networkName", max_length=128)
    vrf_status: ConfigurationStatus | None = Field(default=None, alias="vrfStatus")


class NetworkPreviewResponseModel(NDBaseModel):
    """Response body for POST /fabrics/{fabricName}/networkActions/preview."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    attachments: list[NetworkPreviewModel] | None = Field(default=None)


class MulticastIpResponseModel(NDBaseModel):
    """Response body for GET /fabrics/{fabricName}/networkActions/proposeMulticastIp."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    multicast_ip: str | None = Field(default=None, alias="multicastIp")

    @field_validator("multicast_ip", mode="before")
    @classmethod
    def validate_multicast_ip(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_multicast_ipv4(v)


class NetworkStretchItemModel(NDNestedModel):
    """Network name/stretch target pair for stretch operations."""

    identifiers: ClassVar[list[str]] = []
    network_name: str = Field(default=..., alias="networkName", max_length=128)
    stretch: str = Field(default=..., description="Border gateway list name, allBgwList, or none")

    @field_validator("network_name", mode="before")
    @classmethod
    def validate_network_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_network_name(v)


class NetworkStretchPayloadModel(NDBaseModel):
    """Request body for POST /fabrics/{fabricName}/networkActions/stretch."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    attachments: list[NetworkStretchItemModel] | None = Field(default=None)


class NetworkStretchResultModel(MultiStatusBaseModel):
    """Result entry returned for network stretch operations."""

    stretch: str | None = Field(default=None)


class NetworkStretchResponseModel(NDBaseModel):
    """Response body for network stretch operations."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    results: list[NetworkStretchResultModel] | None = Field(default=None)
