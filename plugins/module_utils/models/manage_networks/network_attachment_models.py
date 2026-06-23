# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network attachment models for Nexus Dashboard Manage APIs."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

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
    DpuAffinity,
    MappingType,
    NetworkAttachmentMode,
    OperationStatus,
    SwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import (
    Metadata,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.validators import (
    NetworkValidators,
)


class DpuInstanceValuesModel(NDNestedModel):
    """DPU instance values common to smart switch attachments."""

    identifiers: ClassVar[list[str]] = []
    dpu_secure: bool | None = Field(default=False, alias="dpuSecure")
    dpu_affinity: DpuAffinity | None = Field(default=None, alias="dpuAffinity")


class NetworkAttachmentInstanceValuesModel(DpuInstanceValuesModel):
    """Per-network attachment instance values."""

    svi_enabled: bool | None = Field(default=None, alias="sviEnabled")
    switch_route_target_import: list[str] | None = Field(default=None, alias="switchRouteTargetImport")
    switch_route_target_export: list[str] | None = Field(default=None, alias="switchRouteTargetExport")
    is_active: bool | None = Field(default=None, alias="isActive")


class NoneMappingModel(NDNestedModel):
    """No VLAN mapping configuration."""

    identifiers: ClassVar[list[str]] = []
    mapping_type: Literal[MappingType.NONE] = Field(default=MappingType.NONE, alias="mappingType")


class SingleMappingModel(NDNestedModel):
    """Single VLAN mapping configuration."""

    identifiers: ClassVar[list[str]] = []
    mapping_type: Literal[MappingType.SINGLE] = Field(default=MappingType.SINGLE, alias="mappingType")
    customer_vlan: int = Field(default=..., alias="customerVlan", ge=2, le=4094)

    @field_validator("customer_vlan", mode="before")
    @classmethod
    def validate_customer_vlan(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)


class NetworkAttachmentInterfaceModel(NDNestedModel):
    """Generic network attachment interface model."""

    identifiers: ClassVar[list[str]] = []
    mode: NetworkAttachmentMode | str = Field(default=..., description="Interface mode discriminator")
    interface_range: str | None = Field(default=None, alias="interfaceRange")
    interface_group_name: str | None = Field(default=None, alias="interfaceGroupName")
    native_vlan: bool | None = Field(default=False, alias="nativeVlan")
    mapping: NoneMappingModel | SingleMappingModel | dict[str, Any] | None = Field(default=None)

    @field_validator("interface_range", mode="before")
    @classmethod
    def validate_interface_range(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_interface_range(v)


class AccessInterfaceModel(NetworkAttachmentInterfaceModel):
    """Access interface attachment."""

    mode: Literal[NetworkAttachmentMode.ACCESS] = Field(default=NetworkAttachmentMode.ACCESS)
    interface_range: str = Field(default=..., alias="interfaceRange")


class Dot1qTunnelInterfaceModel(NetworkAttachmentInterfaceModel):
    """dot1q tunnel interface attachment."""

    mode: Literal[NetworkAttachmentMode.DOT1Q_TUNNEL] = Field(default=NetworkAttachmentMode.DOT1Q_TUNNEL)
    interface_range: str = Field(default=..., alias="interfaceRange")


class TrunkInterfaceModel(NetworkAttachmentInterfaceModel):
    """Trunk interface attachment."""

    mode: Literal[NetworkAttachmentMode.TRUNK] = Field(default=NetworkAttachmentMode.TRUNK)
    interface_range: str = Field(default=..., alias="interfaceRange")


class PromiscuousInterfaceModel(NetworkAttachmentInterfaceModel):
    """Promiscuous interface attachment."""

    mode: Literal[NetworkAttachmentMode.PROMISCUOUS] = Field(default=NetworkAttachmentMode.PROMISCUOUS)
    interface_range: str = Field(default=..., alias="interfaceRange")


class TrunkPromiscuousInterfaceModel(NetworkAttachmentInterfaceModel):
    """Trunk promiscuous interface attachment."""

    mode: Literal[NetworkAttachmentMode.TRUNK_PROMISCUOUS] = Field(default=NetworkAttachmentMode.TRUNK_PROMISCUOUS)
    interface_range: str = Field(default=..., alias="interfaceRange")


class HostInterfaceModel(NetworkAttachmentInterfaceModel):
    """Host interface attachment."""

    mode: Literal[NetworkAttachmentMode.HOST] = Field(default=NetworkAttachmentMode.HOST)
    interface_range: str = Field(default=..., alias="interfaceRange")


class TrunkSecondaryInterfaceModel(NetworkAttachmentInterfaceModel):
    """Trunk secondary interface attachment."""

    mode: Literal[NetworkAttachmentMode.TRUNK_SECONDARY] = Field(default=NetworkAttachmentMode.TRUNK_SECONDARY)
    interface_range: str = Field(default=..., alias="interfaceRange")


class NetworkAttachmentModel(NDNestedModel):
    """A single network attach/detach operation entry."""

    identifiers: ClassVar[list[str]] = []
    network_name: str = Field(default=..., alias="networkName", max_length=128)
    switch_id: str | None = Field(default=None, alias="switchId")
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=2, le=4094)
    switch_fabric_name: str | None = Field(default=None, alias="switchFabricName")
    instance_values: NetworkAttachmentInstanceValuesModel | dict[str, Any] | None = Field(default=None, alias="instanceValues")
    interfaces: list[NetworkAttachmentInterfaceModel] | None = Field(default=None)
    extra_config: str | None = Field(default=None, alias="extraConfig")
    attach: bool = Field(default=..., description="True to attach, false to detach")

    @field_validator("network_name", mode="before")
    @classmethod
    def validate_network_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_network_name(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)


class NetworkAttachDetachPayloadModel(NDBaseModel):
    """Request body for POST /fabrics/{fabricName}/networkAttachments."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    attachments: list[NetworkAttachmentModel] | None = Field(default=None)


class NetworkAttachmentResultModel(NDNestedModel):
    """Result entry returned by network attachment operations."""

    identifiers: ClassVar[list[str]] = []
    network_name: str | None = Field(default=None, alias="networkName")
    display_name: str | None = Field(default=None, alias="displayName")
    status: OperationStatus | None = Field(default=None)
    message: str | None = Field(default=None)
    switch_id: str | None = Field(default=None, alias="switchId")
    switch_name: str | None = Field(default=None, alias="switchName")


class NetworkAttachmentResponseModel(NDBaseModel):
    """Response body for network attachment/import operations."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    results: list[NetworkAttachmentResultModel] | None = Field(default=None)


class NetworkAttachmentDetailModel(NDNestedModel):
    """Complete details of a network attachment returned by query."""

    identifiers: ClassVar[list[str]] = []
    network_name: str = Field(default=..., alias="networkName", max_length=128)
    switch_id: str | None = Field(default=None, alias="switchId")
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=2, le=4094)
    switch_fabric_name: str | None = Field(default=None, alias="switchFabricName")
    instance_values: NetworkAttachmentInstanceValuesModel | dict[str, Any] | None = Field(default=None, alias="instanceValues")
    interfaces: list[NetworkAttachmentInterfaceModel] | None = Field(default=None)
    extra_config: str | None = Field(default=None, alias="extraConfig")
    switch_name: str | None = Field(default=None, alias="switchName")
    status: ConfigurationStatus | None = Field(default=None)
    attach: bool | None = Field(default=False)
    switch_role: SwitchRole | None = Field(default=None, alias="switchRole")
    peer_switch_id: str | None = Field(default=None, alias="peerSwitchId")
    network_id: int | None = Field(default=None, alias="networkId", ge=1, le=16777214)

    @field_validator("network_name", mode="before")
    @classmethod
    def validate_network_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_network_name(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)

    @field_validator("network_id", mode="before")
    @classmethod
    def validate_network_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_network_id(v)


class NetworkAttachmentExportRequestModel(NDBaseModel):
    """Request body for POST /fabrics/{fabricName}/networkAttachment/export."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    network_names: list[str] | None = Field(default=None, alias="networkNames", min_length=1)
    switch_fabric_names: list[str] | None = Field(default=None, alias="switchFabricNames")
    switch_ids: list[str] | None = Field(default=None, alias="switchIds")


class NetworkAttachmentQueryRequestModel(NetworkAttachmentExportRequestModel):
    """Request body for POST /fabrics/{fabricName}/networkAttachments/query."""


class NetworkAttachmentQueryResponseModel(NDBaseModel):
    """Response body for network attachment query."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    attachments: list[NetworkAttachmentDetailModel] | None = Field(default=None)
    meta: Metadata | None = Field(default=None)
