# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Playbook-facing Pydantic models for network configuration."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
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
    "network_template_config",
)


class NetworkInterfaceConfigModel(NDNestedModel):
    """Playbook-facing network interface attachment entry."""

    identifiers: ClassVar[list[str]] = []

    mode: str = Field(default=NetworkAttachmentMode.ACCESS.value)
    interface_range: str | None = Field(default=None, alias="interfaceRange")
    interface_group_name: str | None = Field(default=None, alias="interfaceGroupName")
    native_vlan: bool | None = Field(default=False, alias="nativeVlan")
    mapping_type: str | None = Field(default=None, alias="mappingType")
    customer_vlan: int | None = Field(default=None, alias="customerVlan")

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
        if not self.interface_range and not self.interface_group_name:
            raise ValueError("Either interface_range or interface_group_name is required")
        if self.mapping_type == MappingType.SINGLE.value and self.customer_vlan is None:
            raise ValueError("customer_vlan is required when mapping_type=single")
        return self


class NetworkTorPortConfigModel(NDNestedModel):
    """Compatibility model for legacy tor_ports entries."""

    identifiers: ClassVar[list[str]] = []

    ip_address: str = Field(alias="ipAddress")
    ports: list[str] | None = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_ipv4_address(v)

    @field_validator("ports", mode="before")
    @classmethod
    def _normalize_ports(cls, v: str | list[str] | None) -> list[str] | None:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return v


class NetworkAttachmentConfigModel(NDNestedModel):
    """Playbook-facing switch attachment entry."""

    identifiers: ClassVar[list[str]] = []

    ip_address: str = Field(alias="ipAddress")
    vlan_id: int | None = Field(default=None, alias="vlanId")
    interfaces: list[NetworkInterfaceConfigModel] | None = None
    ports: list[str] | None = None
    deploy: bool | None = True
    tor_ports: list[NetworkTorPortConfigModel] | None = Field(default=None, alias="torPorts")
    attachment_options: dict[str, Any] | None = None
    extra_config: str | None = Field(default=None, alias="extraConfig")

    @field_validator("ip_address", mode="before")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_ipv4_address(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def _validate_vlan(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)

    @field_validator("ports", mode="before")
    @classmethod
    def _normalize_ports(cls, v: str | list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if isinstance(v, str):
            return [v]
        return v

    @model_validator(mode="after")
    def _check_interfaces_or_ports(self):
        if self.tor_ports:
            raise ValueError("tor_ports is not supported by the Network attachment API. Use interfaces[] for attachment interfaces.")
        if not self.interfaces and not self.ports:
            raise ValueError("Either interfaces or ports is required for network attachments")
        return self


class NetworkChildConfigModel(NDNestedModel):
    """Per-child-fabric override entry for MSD/MFD parent workflows."""

    identifiers: ClassVar[list[str]] = []

    fabric: str
    network_id: int | None = Field(default=None, alias="networkId")
    vlan_id: int | None = Field(default=None, alias="vlanId")
    vlan_name: str | None = Field(default=None, alias="vlanName")
    gateway_ipv4_address: str | None = Field(default=None, alias="gatewayIpv4Address")
    gateway_ipv6_address: str | None = Field(default=None, alias="gatewayIpv6Address")
    secondary_gateway_ipv4_collection: list[str] | None = Field(default=None, alias="secondaryGatewayIpv4Collection")
    secondary_gateway_ipv6_collection: list[str] | None = Field(default=None, alias="secondaryGatewayIpv6Collection")
    vlan_intf_desc: str | None = Field(default=None, alias="vlanIntfDesc")
    mtu: int | None = Field(default=9216)
    arp_suppression: bool | None = Field(default=None, alias="arpSuppression")
    routing_tag: int | None = Field(default=None, alias="routingTag")
    dhcp_servers: list[dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    loopback_id: int | None = Field(default=None, alias="loopbackId")
    igmp_version: int | None = Field(default=None, alias="igmpVersion")
    trm_enable: bool | None = Field(default=None, alias="trmEnable")
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm")
    netflow_enable: bool | None = Field(default=None, alias="netflowEnable")
    gateway_on_border: bool | None = Field(default=None, alias="gatewayOnBorder")

    @field_validator("network_id", mode="before")
    @classmethod
    def _validate_network_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_network_id(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def _validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)

    @field_validator("gateway_ipv4_address", mode="before")
    @classmethod
    def _validate_ipv4_cidr(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv4(v)

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


class NetworkConfigModel(NDBaseModel):
    """Playbook-facing network config for standalone fabrics."""

    identifiers: ClassVar[list[str]] = ["network_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"

    network_name: str = Field(alias="networkName")
    net_template: str | None = None
    net_extension_template: str | None = None
    network_id: int | None = Field(default=None, alias="networkId")
    network_type: str | None = Field(default=None, alias="networkType")
    display_name: str | None = Field(default=None, alias="displayName")
    vrf_name: str | None = Field(default=None, alias="vrfName", max_length=32)
    vlan_id: int | None = Field(default=None, alias="vlanId")
    tenant_name: str | None = Field(default=None, alias="tenantName")
    layer: str | None = None
    is_l2only: bool | None = Field(default=None, alias="isL2Only")
    vlan_name: str | None = Field(default=None, alias="vlanName")
    rt_auto: bool | None = Field(default=None, alias="rtAuto")
    x_connect: bool | None = Field(default=None, alias="xConnect")
    l2_fabric_data: dict[str, Any] | None = Field(default=None, alias="l2FabricData")
    stretch: str | None = None
    enable_ir: bool | None = Field(default=False, alias="enableIr")
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
    gateway_on_border: bool | None = Field(default=None, alias="gatewayOnBorder")
    network_template_name: str | None = Field(default=None, alias="networkTemplateName")
    network_extension_template_name: str | None = Field(default=None, alias="networkExtensionTemplateName")
    network_template_config: dict[str, str] | None = Field(default=None, alias="networkTemplateConfig")
    deploy: bool = True
    deploy_type: str = Field(default="switch", alias="deployType")
    attach: list[NetworkAttachmentConfigModel] | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_legacy_network_keys(cls, data):
        """Accept legacy playbook names as aliases."""
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        aliases = {
            "net_name": "network_name",
            "net_id": "network_id",
            "gw_ip_subnet": "gateway_ipv4_address",
            "gw_ipv6_subnet": "gateway_ipv6_address",
            "int_desc": "vlan_intf_desc",
            "mtu_l3intf": "mtu",
            "arp_suppress": "arp_suppression",
            "dhcp_loopback_id": "loopback_id",
            "l3gw_on_border": "gateway_on_border",
            "route_target_both": "rt_auto",
        }
        for legacy, current in aliases.items():
            if legacy in normalized and current not in normalized:
                normalized[current] = normalized[legacy]

        if normalized.get("deploy_type") == "resource":
            normalized["deploy_type"] = "network"
        if normalized.get("deployType") == "resource":
            normalized["deployType"] = "network"

        secondary = normalized.get("secondary_gateway_ipv4_collection")
        if secondary is None:
            secondary = normalized.get("secondaryGatewayIpv4Collection")
        if secondary is None:
            secondary = [normalized[key] for key in ("secondary_ip_gw1", "secondary_ip_gw2", "secondary_ip_gw3", "secondary_ip_gw4") if normalized.get(key)]
            if secondary:
                normalized["secondary_gateway_ipv4_collection"] = secondary

        normalized["dhcp_servers"] = cls._normalize_legacy_dhcp_servers(normalized)

        network_type = normalized.get("network_type") or normalized.get("networkType")
        if network_type == NetworkType.USER_DEFINED.value:
            if normalized.get("net_template") and not normalized.get("network_template_name"):
                normalized["network_template_name"] = normalized["net_template"]
            if normalized.get("net_extension_template") and not normalized.get("network_extension_template_name"):
                normalized["network_extension_template_name"] = normalized["net_extension_template"]

        return normalized

    @staticmethod
    def _normalize_legacy_dhcp_servers(data: dict[str, Any]) -> list[dict[str, Any]] | None:
        """Normalize old DHCP server keys into API serverAddress/serverVrf shape."""
        normalized_servers: list[dict[str, Any]] = []
        for server in data.get("dhcp_servers") or data.get("dhcpServers") or []:
            if not isinstance(server, dict):
                continue
            address = server.get("server_address") or server.get("serverAddress") or server.get("srvr_ip")
            vrf = server.get("server_vrf") or server.get("serverVrf") or server.get("srvr_vrf")
            if address:
                item = {"server_address": address}
                if vrf:
                    item["server_vrf"] = vrf
                normalized_servers.append(item)

        for index in range(1, 4):
            address = data.get(f"dhcp_srvr{index}_ip")
            vrf = data.get(f"dhcp_srvr{index}_vrf")
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
        if self.is_l2only is False and not self.vrf_name:
            raise ValueError("vrf_name is required for layer3 networks")
        return self


class NetworkParentConfigModel(NetworkConfigModel):
    """Parent-fabric network config with child overrides."""

    child_fabric_config: list[NetworkChildConfigModel] | None = Field(default=None, alias="childFabricConfig")
