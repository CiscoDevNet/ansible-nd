# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Playbook-facing Pydantic models for network configuration."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    DpuAffinity,
    MappingType,
    NetworkAttachmentMode,
    NetworkType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.validators import (
    NetworkValidators,
)

_CUSTOM_NETWORK_TEMPLATE_FIELDS = (
    "network_template_name",
    "network_extension_template_name",
    "service_network_template_name",
    "network_template_config",
)

_VLAN_NETWORK_TYPE_ALIASES = {
    "normal": "normal",
    "private_primary": "privatePrimary",
    "privatePrimary": "privatePrimary",
    "private_secondary_community": "privateSecondaryCommunity",
    "privateSecondaryCommunity": "privateSecondaryCommunity",
    "private_secondary_isolated": "privateSecondaryIsolated",
    "privateSecondaryIsolated": "privateSecondaryIsolated",
    "child": "child",
}

_NORMAL_NETWORK_INTERFACE_MODES = frozenset(
    {
        NetworkAttachmentMode.ACCESS.value,
        NetworkAttachmentMode.DOT1Q_TUNNEL.value,
        NetworkAttachmentMode.TRUNK.value,
    }
)
_PRIVATE_PRIMARY_INTERFACE_MODES = frozenset(
    {
        NetworkAttachmentMode.PROMISCUOUS.value,
        NetworkAttachmentMode.TRUNK_PROMISCUOUS.value,
    }
)
_PRIVATE_SECONDARY_INTERFACE_MODES = frozenset(
    {
        NetworkAttachmentMode.HOST.value,
        NetworkAttachmentMode.TRUNK_SECONDARY.value,
    }
)
_INTERFACE_MODES_WITH_INTERFACE_GROUP = frozenset(
    {
        NetworkAttachmentMode.ACCESS.value,
        NetworkAttachmentMode.TRUNK.value,
    }
)


class NetworkInterfaceConfigModel(NDNestedModel):
    """Playbook-facing network interface attachment entry."""

    model_config = ConfigDict(extra="forbid")

    identifiers: ClassVar[list[str]] = []

    mode: str = Field(default=...)
    interface_range: str = Field(default=...)
    interface_group_name: str | None = Field(default=None)
    native_vlan: bool | None = Field(default=False)
    mapping_type: str | None = Field(default=None)
    customer_vlan: int | None = Field(default=None)

    @field_validator("mode", mode="before")
    @classmethod
    def _validate_mode(cls, v: str | None) -> str | None:
        if v not in NetworkAttachmentMode.choices():
            raise ValueError("mode must be one of: " + ", ".join(NetworkAttachmentMode.choices()))
        return v

    @field_validator("mapping_type", mode="before")
    @classmethod
    def _validate_mapping_type(cls, v: str | None) -> str | None:
        if v is not None and v not in MappingType.choices():
            raise ValueError("mapping_type must be one of: " + ", ".join(MappingType.choices()))
        return v

    @field_validator("interface_range", "interface_group_name", mode="before")
    @classmethod
    def _validate_interface_text(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_interface_range(v)

    @field_validator("customer_vlan", mode="before")
    @classmethod
    def _validate_customer_vlan(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)

    @model_validator(mode="after")
    def _check_interface_target(self):
        if self.native_vlan and self.mode != NetworkAttachmentMode.TRUNK.value:
            raise ValueError("native_vlan can only be used when mode=trunk")
        if self.interface_group_name is not None and self.mode not in _INTERFACE_MODES_WITH_INTERFACE_GROUP:
            raise ValueError("interface_group_name can only be used when mode is access or trunk")
        if self.mapping_type is not None and self.mode != NetworkAttachmentMode.TRUNK.value:
            raise ValueError("mapping_type can only be used when mode=trunk")
        if self.customer_vlan is not None and self.mapping_type != MappingType.SINGLE.value:
            raise ValueError("customer_vlan can only be used when mapping_type=single")
        if self.mapping_type == MappingType.SINGLE.value and self.customer_vlan is None:
            raise ValueError("customer_vlan is required when mapping_type=single")
        if self.native_vlan and self.mapping_type == MappingType.SINGLE.value:
            raise ValueError("native_vlan cannot be true when mapping_type=single")
        return self


class NetworkAttachmentOptionsConfigModel(NDNestedModel):
    """Playbook-facing network attachment instance values."""

    model_config = ConfigDict(extra="forbid")

    identifiers: ClassVar[list[str]] = []

    dpu_secure: bool | None = Field(default=None)
    dpu_affinity: DpuAffinity | None = Field(default=None)
    svi_enabled: bool | None = Field(default=None)
    switch_route_target_import: list[str] | None = Field(default=None)
    switch_route_target_export: list[str] | None = Field(default=None)
    is_active: bool | None = Field(default=None)


class NetworkAttachmentConfigModel(NDNestedModel):
    """Playbook-facing switch attachment entry."""

    model_config = ConfigDict(extra="forbid")

    identifiers: ClassVar[list[str]] = []

    ip_address: str
    vlan_id: int | None = Field(default=None)
    interfaces: list[NetworkInterfaceConfigModel] = Field(default=...)
    deploy: bool | None = True
    attachment_options: NetworkAttachmentOptionsConfigModel | None = Field(default=None)
    freeform_config: str | None = Field(default=None)

    @field_validator("ip_address", mode="before")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_ipv4_address(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def _validate_vlan(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)

    @model_validator(mode="after")
    def _check_interfaces(self):
        if not self.interfaces:
            raise ValueError("interfaces is required for network attachments")
        return self


class NetworkChildConfigModel(NDNestedModel):
    """Per-child-fabric override entry for MSD/MFD parent workflows."""

    identifiers: ClassVar[list[str]] = []

    fabric_name: str
    multicast_group_address: str | None = Field(default=None, alias="multicastGroup")
    ds_vni: int | None = Field(default=None, alias="dsVni")
    dhcp_servers: list[dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    loopback_id: int | None = Field(default=None, alias="loopbackId")
    igmp_version: int | None = Field(default=None, alias="igmpVersion")
    trm_enable: bool | None = Field(default=None, alias="trmEnable")
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm")
    netflow_enable: bool | None = Field(default=None, alias="netflowEnable")
    l2_netflow_monitor: str | None = Field(default=None, alias="l2NetflowMonitor")
    l3_netflow_monitor: str | None = Field(default=None, alias="l3NetflowMonitor")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler")
    gateway_on_border: bool | None = Field(default=None, alias="gatewayOnBorder")

    @model_validator(mode="before")
    @classmethod
    def _normalize_child_keys(cls, data):
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        if "l2_fabric_data" in normalized or "l2FabricData" in normalized:
            raise ValueError("l2_fabric_data is not supported; use explicit L2 fabric fields such as multicast_group_address and ds_vni")

        normalized["dhcp_servers"] = NetworkConfigModel._normalize_dhcp_servers(normalized)
        return normalized

    @field_validator("multicast_group_address", mode="before")
    @classmethod
    def _validate_multicast_group(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_multicast_ipv4(v)

    @field_validator("igmp_version", mode="before")
    @classmethod
    def _validate_igmp(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_igmp_version(v)


class NetworkConfigModel(NDBaseModel):
    """Playbook-facing network config for standalone fabrics."""

    identifiers: ClassVar[list[str]] = ["network_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    network_name: str = Field(alias="networkName")
    network_id: int | None = Field(default=None, alias="networkId")
    network_type: str | None = Field(default=None, alias="networkType")
    display_name: str | None = Field(default=None, alias="displayName")
    vrf_name: str | None = Field(default=None, alias="vrfName", max_length=32)
    vlan_id: int | None = Field(default=None, alias="vlanId")
    vlan_network_type: str | None = Field(default=None, alias="vlanNetworkType")
    primary_network_id: int | None = Field(default=None, alias="primaryNetworkId")
    tenant_name: str | None = Field(default=None, alias="tenantName")
    layer: str | None = None
    vlan_name: str | None = Field(default=None, alias="vlanName")
    x_connect: bool | None = Field(default=None, alias="xConnect")
    multicast_group_address: str | None = Field(default=None, alias="multicastGroup")
    ds_vni: int | None = Field(default=None, alias="dsVni")
    gateway_ipv4_address: str | None = Field(default=None, alias="gatewayIpv4Address")
    gateway_ipv6_address: str | None = Field(default=None, alias="gatewayIpv6Address")
    secondary_gateway_ipv4_collection: list[str] | None = Field(default=None, alias="secondaryGatewayIpv4Collection")
    secondary_gateway_ipv6_collection: list[str] | None = Field(default=None, alias="secondaryGatewayIpv6Collection")
    vlan_intf_desc: str | None = Field(default=None, alias="vlanIntfDesc")
    mtu: int | None = Field(default=9216)
    arp_suppression: bool | None = Field(default=False, alias="arpSuppression")
    routing_tag: int | None = Field(default=None, alias="routingTag")
    dhcp_servers: list[dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    loopback_id: int | None = Field(default=None, alias="loopbackId")
    igmp_version: int | None = Field(default=None, alias="igmpVersion")
    trm_enable: bool | None = Field(default=None, alias="trmEnable")
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm")
    netflow_enable: bool | None = Field(default=False, alias="netflowEnable")
    l2_netflow_monitor: str | None = Field(default=None, alias="l2NetflowMonitor")
    l3_netflow_monitor: str | None = Field(default=None, alias="l3NetflowMonitor")
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler")
    gateway_on_border: bool | None = Field(default=None, alias="gatewayOnBorder")
    network_template_name: str | None = Field(default=None, alias="networkTemplateName")
    network_extension_template_name: str | None = Field(default=None, alias="networkExtensionTemplateName")
    service_network_template_name: str | None = Field(default=None, alias="serviceNetworkTemplateName")
    network_template_config: dict[str, str] | None = Field(default=None, alias="networkTemplateConfig")
    deploy: bool = True
    deploy_type: str = Field(default="switch", alias="deployType")
    attach: list[NetworkAttachmentConfigModel] | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_network_keys(cls, data):
        """Normalize canonical nested structures before model validation."""
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        if "l2_fabric_data" in normalized or "l2FabricData" in normalized:
            raise ValueError("l2_fabric_data is not supported; use explicit L2 fabric fields such as multicast_group_address and ds_vni")

        normalized["dhcp_servers"] = cls._normalize_dhcp_servers(normalized)

        has_custom_template_fields = any(normalized.get(field) is not None for field in _CUSTOM_NETWORK_TEMPLATE_FIELDS)
        if has_custom_template_fields and not (normalized.get("network_type") or normalized.get("networkType")):
            normalized["network_type"] = NetworkType.USER_DEFINED.value

        return normalized

    @staticmethod
    def _normalize_dhcp_servers(data: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Normalize DHCP server keys into API serverAddress/serverVrf shape."""
        normalized_servers: list[dict[str, Any]] = []
        for server in data.get("dhcp_servers") or data.get("dhcpServers") or []:
            if not isinstance(server, dict):
                continue
            address = server.get("server_address") or server.get("serverAddress")
            vrf = server.get("server_vrf") or server.get("serverVrf")
            if address:
                item = {"server_address": address}
                if vrf:
                    item["server_vrf"] = vrf
                normalized_servers.append(item)
        return normalized_servers or None

    @field_validator("network_name", mode="before")
    @classmethod
    def _validate_network_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_network_name(v)

    @field_validator("tenant_name", mode="before")
    @classmethod
    def _validate_tenant_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_tenant_name(v)

    @field_validator("network_id", mode="before")
    @classmethod
    def _validate_network_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_network_id(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def _validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)

    @field_validator("vlan_network_type", mode="before")
    @classmethod
    def _validate_vlan_network_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v not in _VLAN_NETWORK_TYPE_ALIASES:
            raise ValueError("vlan_network_type must be one of: " + ", ".join(sorted(_VLAN_NETWORK_TYPE_ALIASES)))
        return _VLAN_NETWORK_TYPE_ALIASES[v]

    @field_validator("primary_network_id", mode="before")
    @classmethod
    def _validate_primary_network_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_network_id(v)

    @field_validator("gateway_ipv4_address", mode="before")
    @classmethod
    def _validate_ipv4_cidr(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv4(v)

    @field_validator("multicast_group_address", mode="before")
    @classmethod
    def _validate_multicast_group(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_multicast_ipv4(v)

    @field_validator("gateway_ipv6_address", mode="before")
    @classmethod
    def _validate_ipv6_cidr(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv6(v)

    @field_validator("secondary_gateway_ipv4_collection", mode="before")
    @classmethod
    def _validate_ipv4_collection(cls, v: list[str] | None) -> list[str] | None:
        return [NetworkValidators.validate_cidrv4(item) for item in v] if v is not None else None

    @field_validator("secondary_gateway_ipv6_collection", mode="before")
    @classmethod
    def _validate_ipv6_collection(cls, v: list[str] | None) -> list[str] | None:
        return [NetworkValidators.validate_cidrv6(item) for item in v] if v is not None else None

    @field_validator("mtu", mode="before")
    @classmethod
    def _validate_mtu(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_mtu(v)

    @field_validator("igmp_version", mode="before")
    @classmethod
    def _validate_igmp(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_igmp_version(v)

    @model_validator(mode="after")
    def _check_cross_field_rules(self):
        network_type = self.network_type
        custom_fields = {field: getattr(self, field) for field in _CUSTOM_NETWORK_TEMPLATE_FIELDS}
        set_custom_fields = [field for field, value in custom_fields.items() if value is not None]
        if set_custom_fields and network_type != NetworkType.USER_DEFINED.value:
            raise ValueError("network template fields require network_type=userDefined: " + ", ".join(set_custom_fields))
        if self.deploy_type not in ("switch", "network"):
            raise ValueError("deploy_type must be either 'switch' or 'network'")
        if self.layer == "layer3" and not self.vrf_name:
            raise ValueError("vrf_name is required for layer3 networks")
        self._check_attachment_interface_modes()
        return self

    def _check_attachment_interface_modes(self) -> None:
        vlan_network_type = self.vlan_network_type or "normal"
        if vlan_network_type in ("normal", "child"):
            allowed_modes = _NORMAL_NETWORK_INTERFACE_MODES
        elif vlan_network_type == "privatePrimary":
            allowed_modes = _PRIVATE_PRIMARY_INTERFACE_MODES
        elif vlan_network_type in ("privateSecondaryCommunity", "privateSecondaryIsolated"):
            allowed_modes = _PRIVATE_SECONDARY_INTERFACE_MODES
        else:
            return

        for attachment in self.attach or []:
            for interface in attachment.interfaces or []:
                if interface.mode not in allowed_modes:
                    raise ValueError(
                        f"mode={interface.mode} is not valid for vlan_network_type={vlan_network_type}; " f"allowed modes: {', '.join(sorted(allowed_modes))}"
                    )


class NetworkParentConfigModel(NetworkConfigModel):
    """Parent-fabric network config with child overrides."""

    child_fabric_config: list[NetworkChildConfigModel] | None = Field(default=None, alias="childFabricConfig")
