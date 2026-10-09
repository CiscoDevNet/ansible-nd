# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network data models for Nexus Dashboard Manage network CRUD APIs."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    AciVlanNetworkType,
    ClassicNetworkLayer,
    ConfigurationStatus,
    FabricType,
    NetworkLayer,
    NetworkType,
    OperationStatus,
    VlanNetworkType,
    VlanPoolDomainType,
    public_vlan_network_type,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.validators import (
    NetworkValidators,
)


class MetadataCounts(NDNestedModel):
    """Pagination counts embedded in list API responses."""

    identifiers: ClassVar[list[str]] = []
    total: int = Field(default=..., description="Total number of records")
    remaining: int = Field(default=..., description="Remaining number of records")


class MetadataLinks(NDNestedModel):
    """Pagination links embedded in list API responses."""

    identifiers: ClassVar[list[str]] = []
    next: str | None = Field(default=None, description="Next page link")
    previous: str | None = Field(default=None, description="Previous page link")


class Metadata(NDNestedModel):
    """Pagination metadata returned by list API calls."""

    identifiers: ClassVar[list[str]] = []
    counts: MetadataCounts | None = Field(default=None, description="Pagination counts")
    links: MetadataLinks | None = Field(default=None, description="Pagination links")


class DhcpServerModel(NDNestedModel):
    """DHCP relay server entry."""

    identifiers: ClassVar[list[str]] = []
    server_address: str = Field(default=..., alias="serverAddress", description="DHCP server address")
    server_vrf: str | None = Field(default=None, alias="serverVrf", max_length=32, description="DHCP server VRF")


class VlanPoolDomainModel(NDNestedModel):
    """ACI VLAN pool domain entry."""

    identifiers: ClassVar[list[str]] = []
    domain_type: VlanPoolDomainType = Field(default=..., alias="domainType", description="Domain type")
    domain_name: str = Field(default=..., alias="domainName", description="Domain name")
    vlan_pool: str | None = Field(default=None, alias="vlanPool", description="VLAN pool")


class L4L7ServiceDataModel(NDNestedModel):
    """L4-L7 service data for a VXLAN network."""

    identifiers: ClassVar[list[str]] = []
    service_config: dict[str, str] | None = Field(default=None, alias="serviceConfig")
    service_epbr_config: dict[str, str] | None = Field(default=None, alias="serviceEpbrConfig")


class AciFabricDataModel(NDNestedModel):
    """ACI fabric-specific data nested under aciData.fabricData."""

    identifiers: ClassVar[list[str]] = []
    vlan_pool_domains: list[VlanPoolDomainModel] | None = Field(default=None, alias="vlanPoolDomains")


class AciDataModel(NDNestedModel):
    """ACI data associated with a network."""

    identifiers: ClassVar[list[str]] = []
    epg_name: str | None = Field(default=None, alias="epgName", description="EPG name")
    application_profile_name: str | None = Field(default=None, alias="applicationProfileName", description="Application profile name")
    fabric_data: AciFabricDataModel | dict[str, Any] | None = Field(default=None, alias="fabricData")


class DefaultL2FabricDataModel(NDNestedModel):
    """Fabric-specific configuration for default VXLAN L2 data."""

    model_config = ConfigDict(
        str_strip_whitespace=True, use_enum_values=True, validate_assignment=True, populate_by_name=True, arbitrary_types_allowed=True, extra="allow"
    )

    identifiers: ClassVar[list[str]] = []
    stretch: str | None = Field(default=None, description="Stretch border gateway list name")
    multicast_group: str | None = Field(default=None, alias="multicastGroup")
    ds_vni: int | None = Field(default=None, alias="dsVni")

    @field_validator("multicast_group", mode="before")
    @classmethod
    def validate_multicast_group(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_multicast_ipv4(v)


class DefaultL2DataModel(NDNestedModel):
    """Default L2 network data."""

    identifiers: ClassVar[list[str]] = []

    vlan_name: str | None = Field(default=None, alias="vlanName", description="VLAN name")
    x_connect: bool | None = Field(default=False, alias="xConnect", description="Enable xConnect")
    fabric_data: DefaultL2FabricDataModel | None = Field(default=None, alias="fabricData")


class VxlanL3FabricDataModel(NDNestedModel):
    """VXLAN L3 fabric-specific data."""

    identifiers: ClassVar[list[str]] = []

    dhcp_servers: list[DhcpServerModel | dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    loopback_id: int | None = Field(default=None, alias="loopbackId")
    igmp_version: int | None = Field(default=None, alias="igmpVersion", ge=1, le=3)
    netflow: bool | None = Field(default=False, description="Enable netflow")
    vlan_netflow_monitor: str | None = Field(default=None, alias="l2NetflowMonitor")
    interface_netflow_monitor: str | None = Field(default=None, alias="l3NetflowMonitor")
    gateway_on_border: bool | None = Field(default=False, alias="gatewayOnBorder")
    ipv4_trm: bool | None = Field(default=False, alias="ipv4Trm")
    ipv6_trm: bool | None = Field(default=False, alias="ipv6Trm")

    @field_validator("igmp_version", mode="before")
    @classmethod
    def validate_igmp_version(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_igmp_version(v)


class DefaultL3FabricDataModel(NDNestedModel):
    """Default L3 fabric-specific data."""

    identifiers: ClassVar[list[str]] = []
    dhcp_servers: list[DhcpServerModel | dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    loopback_id: int | None = Field(default=None, alias="loopbackId")
    igmp_version: int | None = Field(default=None, alias="igmpVersion", ge=1, le=3)
    netflow: bool | None = Field(default=False, description="Enable netflow")
    vlan_netflow_monitor: str | None = Field(default=None, alias="l2NetflowMonitor")
    interface_netflow_monitor: str | None = Field(default=None, alias="l3NetflowMonitor")
    gateway_on_border: bool | None = Field(default=False, alias="gatewayOnBorder")

    @field_validator("igmp_version", mode="before")
    @classmethod
    def validate_igmp_version(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_igmp_version(v)


class DefaultL3DataModel(NDNestedModel):
    """Default L3 network data."""

    identifiers: ClassVar[list[str]] = []
    gateway_ipv4_address: str | None = Field(default=None, alias="gatewayIpv4Address")
    gateway_ipv6_address: str | None = Field(default=None, alias="gatewayIpv6Address")
    secondary_gateway_ipv4_collection: list[str] | None = Field(default=None, alias="secondaryGatewayIpv4Collection")
    secondary_gateway_ipv6_collection: list[str] | None = Field(default=None, alias="secondaryGatewayIpv6Collection")
    vlan_interface_description: str | None = Field(default=None, alias="vlanInterfaceDescription")
    mtu: int | None = Field(default=9216, ge=68, le=9216)
    arp_suppression: bool | None = Field(default=False, alias="arpSuppression")
    routing_tag: int | None = Field(default=None, alias="routingTag")
    fabric_data: VxlanL3FabricDataModel | None = Field(default=None, alias="fabricData")

    @field_validator("gateway_ipv4_address", mode="before")
    @classmethod
    def validate_gateway_ipv4_address(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv4(v)

    @field_validator("gateway_ipv6_address", mode="before")
    @classmethod
    def validate_gateway_ipv6_address(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv6(v)

    @field_validator("secondary_gateway_ipv4_collection", mode="before")
    @classmethod
    def validate_secondary_gateway_ipv4_collection(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return [NetworkValidators.validate_cidrv4(item) for item in v]

    @field_validator("secondary_gateway_ipv6_collection", mode="before")
    @classmethod
    def validate_secondary_gateway_ipv6_collection(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        return [NetworkValidators.validate_cidrv6(item) for item in v]

    @field_validator("mtu", mode="before")
    @classmethod
    def validate_mtu(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_mtu(v)

    def to_layer2_payload(self, **kwargs) -> dict[str, Any]:
        """
        # Summary

        Export VLAN NetFlow settings without Layer-3-only properties.

        ## Raises

        None
        """
        if self.fabric_data is None:
            return {}
        fabric_data = self.fabric_data.to_payload(**kwargs)
        applicable = {key: fabric_data[key] for key in ("netflow", "l2NetflowMonitor") if key in fabric_data}
        return {"fabricData": applicable} if applicable else {}


class ClassicOrRoutedL2FabricDataModel(NDNestedModel):
    """Fabric-specific configuration for classic/routed L2 data."""

    identifiers: ClassVar[list[str]] = []
    redundancy_type: Literal["hsrp", "vrrp"] | None = Field(default=None, alias="redundancyType")


class ClassicOrRoutedL2DataModel(NDNestedModel):
    """L2 data used by routed/classic network schemas."""

    identifiers: ClassVar[list[str]] = []
    vlan_name: str | None = Field(default=None, alias="vlanName")
    fabric_data: ClassicOrRoutedL2FabricDataModel | None = Field(default=None, alias="fabricData")


class ClassicOrRoutedL3DataModel(NDNestedModel):
    """L3 data used by routed/classic network schemas."""

    identifiers: ClassVar[list[str]] = []
    ignore_fhrp_priority: bool | None = Field(default=False, alias="ignoreFhrpPriority")
    preempt_delay_minimum_time: int | None = Field(default=0, alias="preemptDelayMinimumTime")
    preempt_delay_after_reload_time: int | None = Field(default=0, alias="preemptDelayAfterReloadTime")
    preempt_delay_sync_time: int | None = Field(default=0, alias="preemptDelaySyncTime")
    hsrp_version: int | None = Field(default=2, alias="hsrpVersion")
    hsrp_vrrp_group_number_v6: dict[str, Any] | None = Field(default=None, alias="hsrpVrrpGroupNumberV6")
    ip_redirects: bool | None = Field(default=False, alias="ipRedirects")
    pim_sparse_mode: bool | None = Field(default=False, alias="pimSparseMode")
    pim_dr_priority: int | None = Field(default=1, alias="pimDrPriority")
    md5_authentication_key: str | None = Field(default=None, alias="md5AuthenticationKey")
    dhcp_servers: list[DhcpServerModel | dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    ospf_authentication: bool | None = Field(default=False, alias="ospfAuthentication")
    ospf_authentication_key_id: int | None = Field(default=127, alias="ospfAuthenticationKeyId")
    ospf_authentication_key: str | None = Field(default=None, alias="ospfAuthenticationKey")
    ospf_passive_interface: bool | None = Field(default=True, alias="ospfPassiveInterface")
    ospfv3_passive_interface: bool | None = Field(default=True, alias="ospfv3PassiveInterface")
    gateway_ipv4_address: str | None = Field(default=None, alias="gatewayIpv4Address")
    active_primary_interface_ipv4: str | None = Field(default=None, alias="activePrimaryInterfaceIpv4")
    standby_backup_interface_ipv4: str | None = Field(default=None, alias="standbyBackupInterfaceIpv4")
    gateway_ipv6_address: str | None = Field(default=None, alias="gatewayIpv6Address")
    active_primary_interface_ipv6: str | None = Field(default=None, alias="activePrimaryInterfaceIpv6")
    standby_backup_interface_ipv6: str | None = Field(default=None, alias="standbyBackupInterfaceIpv6")
    virtual_primary_link_local_ipv6: str | None = Field(default=None, alias="virtualPrimaryLinkLocalIpv6")
    vlan_interface_description: str | None = Field(default=None, alias="vlanInterfaceDescription")
    standby_vlan_interface_description: str | None = Field(default=None, alias="standbyVlanInterfaceDescription")
    mtu: int | None = Field(default=9216, ge=68, le=9216)
    routing_tag: int | None = Field(default=12345, alias="routingTag")
    active_primary_switch_priority: int | None = Field(default=120, alias="activePrimarySwitchPriority")
    standby_backup_switch_priority: int | None = Field(default=100, alias="standbyBackupSwitchPriority")
    preempt: bool | None = Field(default=True)
    hsrp_vrrp_group_number: dict[str, Any] | None = Field(default=None, alias="hsrpVrrpGroupNumber")
    virtual_mac_address: str | None = Field(default=None, alias="virtualMacAddress")
    vrrp_group: bool | None = Field(default=True, alias="vrrpGroup")
    netflow: bool | None = Field(default=False)
    vlan_netflow_monitor: str | None = Field(default=None, alias="l2NetflowMonitor")
    interface_netflow_monitor: str | None = Field(default=None, alias="l3NetflowMonitor")

    @field_validator(
        "gateway_ipv4_address",
        "active_primary_interface_ipv4",
        "standby_backup_interface_ipv4",
        mode="before",
    )
    @classmethod
    def validate_ipv4_cidr_fields(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv4(v)

    @field_validator(
        "gateway_ipv6_address",
        "active_primary_interface_ipv6",
        "standby_backup_interface_ipv6",
        "virtual_primary_link_local_ipv6",
        mode="before",
    )
    @classmethod
    def validate_ipv6_cidr_fields(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_cidrv6(v)

    @field_validator("mtu", mode="before")
    @classmethod
    def validate_mtu(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_mtu(v)


class MemberFabricNetworkInfoModel(NDNestedModel):
    """Network information for a member fabric."""

    identifiers: ClassVar[list[str]] = []
    fabric_name: str | None = Field(default=None, alias="fabricName")
    fabric_type: FabricType | None = Field(default=None, alias="fabricType")
    network_name: str | None = Field(default=None, alias="networkName", max_length=128)
    network_status: ConfigurationStatus | None = Field(default=None, alias="networkStatus")
    stretch: str | None = Field(default=None)
    local_l2_vni: int | None = Field(default=None, alias="localL2Vni")


class GetMemberFabricsNetworksModel(NDNestedModel):
    """Response wrapper for member fabric network information."""

    identifiers: ClassVar[list[str]] = []
    member_fabric_network_info: list[MemberFabricNetworkInfoModel] | None = Field(default=None, alias="memberFabricNetworkInfo")


class NetworkCommonModel(NDBaseModel):
    """Common fields shared across network types."""

    identifiers: ClassVar[list[str]] = ["network_name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "single"
    exclude_from_diff: ClassVar[set[str]] = {"network_status"}
    payload_exclude_fields: ClassVar[set[str]] = {"network_status"}
    reverse_diff_exclude: ClassVar[set[str]] = {"displayName", "primaryNetworkName", "normalNetworkName"}

    fabric_name: str | None = Field(default=None, alias="fabricName")
    network_name: str = Field(default=..., alias="networkName", max_length=128)
    network_status: ConfigurationStatus | None = Field(default=None, alias="networkStatus")
    display_name: str | None = Field(default=None, alias="displayName")
    vrf_name: str | None = Field(default=None, alias="vrfName", max_length=32)
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=2, le=4094)
    layer: NetworkLayer | None = Field(default=None, alias="networkMode")

    @field_validator("network_name", mode="before")
    @classmethod
    def validate_network_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_network_name(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)


class NetworkBaseModel(NetworkCommonModel):
    """Generic model for components/schemas/networkBase discriminator payloads."""

    network_type: NetworkType | str | None = Field(default=None, alias="networkType")
    vlan_network_type: VlanNetworkType | str | None = Field(default=VlanNetworkType.NORMAL, alias="vlanNetworkType")
    primary_network_id: int | None = Field(default=None, alias="primaryNetworkId")
    primary_network_name: str | None = Field(default=None, alias="primaryNetworkName")
    normal_network_id: int | None = Field(default=None, alias="normalNetworkId")
    normal_network_name: str | None = Field(default=None, alias="normalNetworkName")
    network_id: int | None = Field(default=None, alias="networkId", ge=1, le=16777214)
    l2_data: DefaultL2DataModel | ClassicOrRoutedL2DataModel | dict[str, Any] | None = Field(default=None, alias="l2Data")
    l3_data: DefaultL3DataModel | ClassicOrRoutedL3DataModel | dict[str, Any] | None = Field(default=None, alias="l3Data")
    aci_data: AciDataModel | dict[str, Any] | None = Field(default=None, alias="aciData")
    service_data: L4L7ServiceDataModel | dict[str, Any] | None = Field(default=None, alias="serviceData")
    member_fabric_network_info: list[MemberFabricNetworkInfoModel] | None = Field(default=None, alias="memberFabricNetworkInfo")
    network_template_name: str | None = Field(default=None, alias="networkTemplateName")
    network_extension_template_name: str | None = Field(default=None, alias="networkExtensionTemplateName")
    service_network_template_name: str | None = Field(default=None, alias="serviceNetworkTemplateName")
    network_template_config: dict[str, str] | None = Field(default=None, alias="networkTemplateConfig")
    interface_group_names: list[str] | None = Field(default=None, alias="interfaceGroupNames")

    @classmethod
    def from_config(cls, ansible_config: dict[str, Any], **kwargs) -> "NetworkBaseModel":
        """
        # Summary

        Construct the concrete Network model selected by the prepared configuration's Network type.

        ## Raises

        ### ValidationError

        - If the configuration does not satisfy the selected Network schema.
        """
        if cls is NetworkBaseModel:
            model_cls = _NETWORK_MODEL_BY_TYPE.get(ansible_config.get("network_type") or ansible_config.get("networkType"))
            if model_cls is not None:
                return model_cls.from_config(ansible_config, **kwargs)
        return super().from_config(ansible_config, **kwargs)

    @field_validator("network_id", "primary_network_id", "normal_network_id", mode="before")
    @classmethod
    def validate_network_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_network_id(v)

    @classmethod
    def get_argument_spec(cls) -> dict[str, Any]:
        """Return the Ansible argument spec for gathered-output pruning."""
        from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
            network_parent_argument_spec,
        )

        return dict(config=dict(type="list", elements="dict", options=network_parent_argument_spec()))

    def to_config(self, **kwargs) -> dict[str, Any]:
        data = super().to_config(**kwargs)
        if "vlan_network_type" in data:
            data["vlan_network_type"] = public_vlan_network_type(data["vlan_network_type"])
        return data

    def to_gathered_config(self, **kwargs) -> dict[str, Any]:
        """Return a replay-safe public config shape for gathered output."""
        data = self.to_config(**kwargs)
        l2_data = data.pop("l2_data", None)
        l3_data = data.pop("l3_data", None)
        for key in (
            "fabric_name",
            "network_status",
            "aci_data",
            "service_data",
            "member_fabric_network_info",
            "normal_network_id",
            "normal_network_name",
            "primary_network_name",
            "network_type",
            "interface_group_names",
        ):
            data.pop(key, None)

        self._flatten_l2_data(data, l2_data)
        if self.vlan_network_type in (VlanNetworkType.PRIVATE_SECONDARY_COMMUNITY.value, VlanNetworkType.PRIVATE_SECONDARY_ISOLATED.value):
            for key in (
                "vrf_name",
                "x_connect",
                "ds_vni",
                "network_template_name",
                "network_extension_template_name",
                "service_network_template_name",
                "network_template_config",
            ):
                data.pop(key, None)
        elif self.layer == NetworkLayer.LAYER2.value and isinstance(self.l3_data, DefaultL3DataModel):
            applicable = self.l3_data.to_layer2_payload(exclude_unset=True)
            self._flatten_l3_data(data, applicable)
        elif self.layer != NetworkLayer.LAYER2.value or self.network_type == NetworkType.USER_DEFINED.value:
            self._flatten_l3_data(data, l3_data)
        return data

    @classmethod
    def _flatten_l2_data(cls, data: dict[str, Any], l2_data: Any) -> None:
        l2 = cls._nested_config(l2_data)
        if not l2:
            return
        cls._copy_if_present(data, l2, "vlan_name", "vlan_name", "vlanName")
        cls._copy_if_present(data, l2, "x_connect", "x_connect", "xConnect")
        fabric_data = cls._nested_config(l2.get("fabric_data") or l2.get("fabricData"))
        cls._copy_if_present(data, fabric_data, "multicast_group_address", "multicast_group", "multicastGroup")
        cls._copy_if_present(data, fabric_data, "ds_vni", "ds_vni", "dsVni")

    @classmethod
    def _flatten_l3_data(cls, data: dict[str, Any], l3_data: Any) -> None:
        l3 = cls._nested_config(l3_data)
        if not l3:
            return
        for target, *source in (
            ("gateway_ipv4_address", "gateway_ipv4_address", "gatewayIpv4Address"),
            ("gateway_ipv6_address", "gateway_ipv6_address", "gatewayIpv6Address"),
            ("secondary_gateway_ipv4_collection", "secondary_gateway_ipv4_collection", "secondaryGatewayIpv4Collection"),
            ("secondary_gateway_ipv6_collection", "secondary_gateway_ipv6_collection", "secondaryGatewayIpv6Collection"),
            ("vlan_intf_desc", "vlan_interface_description", "vlanInterfaceDescription"),
            ("mtu", "mtu"),
            ("arp_suppression", "arp_suppression", "arpSuppression"),
            ("routing_tag", "routing_tag", "routingTag"),
        ):
            cls._copy_if_present(data, l3, target, *source)

        fabric_data = cls._nested_config(l3.get("fabric_data") or l3.get("fabricData"))
        for target, *source in (
            ("dhcp_servers", "dhcp_servers", "dhcpServers"),
            ("loopback_id", "loopback_id", "loopbackId"),
            ("igmp_version", "igmp_version", "igmpVersion"),
            ("netflow_enable", "netflow"),
            ("vlan_netflow_monitor", "vlan_netflow_monitor", "l2NetflowMonitor"),
            ("interface_netflow_monitor", "interface_netflow_monitor", "l3NetflowMonitor"),
            ("gateway_on_border", "gateway_on_border", "gatewayOnBorder"),
            ("trm_enable", "ipv4_trm", "ipv4Trm"),
            ("ipv6_trm", "ipv6_trm", "ipv6Trm"),
        ):
            cls._copy_if_present(data, fabric_data, target, *source)

    @staticmethod
    def _nested_config(value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if hasattr(value, "to_config"):
            return value.to_config()
        if isinstance(value, dict):
            return dict(value)
        return {}

    @staticmethod
    def _copy_if_present(target: dict[str, Any], source: dict[str, Any], target_key: str, *source_keys: str) -> None:
        for source_key in source_keys:
            if source_key in source and source[source_key] is not None:
                target[target_key] = source[source_key]
                return

    @classmethod
    def from_response(cls, response: dict[str, Any], **kwargs) -> "NetworkBaseModel":
        """
        # Summary

        Select the concrete Network schema and normalize controller-only response fields.

        ## Raises

        ### ValidationError

        - If the response does not satisfy the selected Network schema.
        """
        if cls is NetworkBaseModel:
            model_cls = _NETWORK_MODEL_BY_TYPE.get(response.get("networkType") or response.get("network_type"))
            if model_cls is not None:
                return model_cls.from_response(response, **kwargs)
        normalized = dict(response)
        if "layer" not in normalized and "networkMode" in normalized:
            normalized["layer"] = normalized["networkMode"]
        l2_data = normalized.get("l2Data")
        if isinstance(l2_data, dict):
            l2_data = dict(l2_data)
            l2_data.pop("disableRtAuto", None)
            fabric_data = l2_data.get("fabricData")
            if isinstance(fabric_data, dict):
                fabric_data = dict(fabric_data)
                fabric_data.pop("enableIr", None)
                l2_data["fabricData"] = fabric_data
            normalized["l2Data"] = l2_data
        if (
            normalized.get("layer") == NetworkLayer.LAYER2.value
            and normalized.get("vlanNetworkType") == VlanNetworkType.PRIVATE_PRIMARY.value
            and cls._is_layer2_default_l3_data(normalized.get("l3Data"))
        ):
            normalized.pop("l3Data", None)
        return super().from_response(normalized, **kwargs)

    @staticmethod
    def _is_layer2_default_l3_data(l3_data: Any) -> bool:
        """
        # Summary

        Return True when an L2 network readback contains only controller-supplied L3 defaults.

        ## Raises

        None
        """
        if not isinstance(l3_data, dict):
            return False
        defaults = dict(l3_data)
        fabric_data = defaults.pop("fabricData", None)
        if isinstance(fabric_data, dict):
            fabric_defaults = dict(fabric_data)
            for key in ("gatewayOnBorder", "ipv4Trm", "ipv6Trm", "netflow"):
                if fabric_defaults.get(key) is False:
                    fabric_defaults.pop(key)
            for key in ("dhcpServers", "loopbackId", "igmpVersion", "l2NetflowMonitor", "l3NetflowMonitor"):
                if fabric_defaults.get(key) in (None, "", [], {}):
                    fabric_defaults.pop(key, None)
            if fabric_defaults:
                return False
        elif fabric_data not in (None, "", [], {}):
            return False

        for key, value in {
            "arpSuppression": False,
            "mtu": 9216,
        }.items():
            if defaults.get(key) == value:
                defaults.pop(key)
        for key in (
            "gatewayIpv4Address",
            "gatewayIpv6Address",
            "secondaryGatewayIpv4Collection",
            "secondaryGatewayIpv6Collection",
            "vlanInterfaceDescription",
            "routingTag",
        ):
            if defaults.get(key) in (None, "", [], {}):
                defaults.pop(key, None)
        return not defaults


class VxlanNetworkModel(NetworkBaseModel):
    """VXLAN network model."""

    network_type: Literal[NetworkType.VXLAN] = Field(default=NetworkType.VXLAN, alias="networkType")
    l2_data: DefaultL2DataModel | None = Field(default=None, alias="l2Data")
    l3_data: DefaultL3DataModel | None = Field(default=None, alias="l3Data")

    def to_diff_dict(self, **kwargs) -> dict[str, Any]:
        """
        # Summary

        Compare only mode-applicable VXLAN data without changing payloads or sparse input intent.

        Plain Layer 2 retains VLAN NetFlow settings but ignores Layer-3-only readback.
        ND omits cleared DHCP and secondary gateway collections from GET responses. Full comparison
        exports represent them as empty lists; sparse proposed exports retain only supplied fields.

        ## Raises

        None
        """
        data = super().to_diff_dict(**kwargs)
        if self.layer == NetworkLayer.LAYER2.value:
            l3_data = self.l3_data.to_layer2_payload(exclude_unset=kwargs.get("exclude_unset", False)) if self.l3_data is not None else {}
            if not kwargs.get("exclude_unset", False):
                l3_data.setdefault("fabricData", {}).setdefault("netflow", False)
            if l3_data:
                data["l3Data"] = l3_data
            else:
                data.pop("l3Data", None)
            return data
        if not kwargs.get("exclude_unset", False):
            l3_data = data.setdefault("l3Data", {})
            l3_data.setdefault("secondaryGatewayIpv4Collection", [])
            l3_data.setdefault("secondaryGatewayIpv6Collection", [])
            l3_data.setdefault("fabricData", {}).setdefault("dhcpServers", [])
        return data


class VxlanIbgpNetworkModel(VxlanNetworkModel):
    """VXLAN iBGP network model."""

    network_type: Literal[NetworkType.VXLAN_IBGP] = Field(default=NetworkType.VXLAN_IBGP, alias="networkType")


class VxlanEbgpNetworkModel(VxlanNetworkModel):
    """VXLAN eBGP network model."""

    network_type: Literal[NetworkType.VXLAN_EBGP] = Field(default=NetworkType.VXLAN_EBGP, alias="networkType")


class VxlanCampusNetworkModel(VxlanNetworkModel):
    """VXLAN campus network model."""

    network_type: Literal[NetworkType.VXLAN_CAMPUS] = Field(default=NetworkType.VXLAN_CAMPUS, alias="networkType")


class AimlVxlanIbgpNetworkModel(VxlanNetworkModel):
    """AIML VXLAN iBGP network model."""

    network_type: Literal[NetworkType.AIML_VXLAN_IBGP] = Field(default=NetworkType.AIML_VXLAN_IBGP, alias="networkType")


class AimlVxlanEbgpNetworkModel(VxlanNetworkModel):
    """AIML VXLAN eBGP network model."""

    network_type: Literal[NetworkType.AIML_VXLAN_EBGP] = Field(default=NetworkType.AIML_VXLAN_EBGP, alias="networkType")


class RoutedNetworkModel(NetworkBaseModel):
    """Routed network model."""

    network_type: Literal[NetworkType.ROUTED] = Field(default=NetworkType.ROUTED, alias="networkType")
    layer: ClassicNetworkLayer | None = Field(default=None)
    l2_data: ClassicOrRoutedL2DataModel | None = Field(default=None, alias="l2Data")
    l3_data: ClassicOrRoutedL3DataModel | None = Field(default=None, alias="l3Data")


class AimlRoutedNetworkModel(RoutedNetworkModel):
    """AIML routed network model."""

    network_type: Literal[NetworkType.AIML_ROUTED] = Field(default=NetworkType.AIML_ROUTED, alias="networkType")


class ClassicLanEnhancedNetworkModel(RoutedNetworkModel):
    """Classic LAN enhanced network model."""

    network_type: Literal[NetworkType.CLASSIC_LAN_ENHANCED] = Field(default=NetworkType.CLASSIC_LAN_ENHANCED, alias="networkType")


class CustomNetworkModel(NetworkBaseModel):
    """User-defined/custom network model."""

    network_type: Literal[NetworkType.USER_DEFINED] = Field(default=NetworkType.USER_DEFINED, alias="networkType")
    l2_data: dict[str, Any] | None = Field(default=None, alias="l2Data")
    l3_data: dict[str, Any] | None = Field(default=None, alias="l3Data")


class VxlanAciNetworkModel(NetworkBaseModel):
    """VXLAN ACI network model."""

    network_type: Literal[NetworkType.VXLAN_ACI] = Field(default=NetworkType.VXLAN_ACI, alias="networkType")
    vlan_network_type: AciVlanNetworkType | str | None = Field(default=None, alias="vlanNetworkType")


class AciNetworkModel(VxlanAciNetworkModel):
    """ACI network model."""

    network_type: Literal[NetworkType.ACI] = Field(default=NetworkType.ACI, alias="networkType")


class ExternalConnectivityNetworkModel(NetworkBaseModel):
    """External connectivity network model."""

    network_type: Literal[NetworkType.EXTERNAL_CONNECTIVITY] = Field(default=NetworkType.EXTERNAL_CONNECTIVITY, alias="networkType")


class VxlanExternalNetworkModel(NetworkBaseModel):
    """VXLAN external network model."""

    network_type: Literal[NetworkType.VXLAN_EXTERNAL] = Field(default=NetworkType.VXLAN_EXTERNAL, alias="networkType")


_NETWORK_MODEL_BY_TYPE = {
    NetworkType.VXLAN.value: VxlanNetworkModel,
    NetworkType.VXLAN_IBGP.value: VxlanIbgpNetworkModel,
    NetworkType.VXLAN_EBGP.value: VxlanEbgpNetworkModel,
    NetworkType.VXLAN_CAMPUS.value: VxlanCampusNetworkModel,
    NetworkType.AIML_VXLAN_IBGP.value: AimlVxlanIbgpNetworkModel,
    NetworkType.AIML_VXLAN_EBGP.value: AimlVxlanEbgpNetworkModel,
    NetworkType.ROUTED.value: RoutedNetworkModel,
    NetworkType.AIML_ROUTED.value: AimlRoutedNetworkModel,
    NetworkType.CLASSIC_LAN_ENHANCED.value: ClassicLanEnhancedNetworkModel,
    NetworkType.USER_DEFINED.value: CustomNetworkModel,
}


class NetworkCreateRequestModel(NDBaseModel):
    """Request body for POST /fabrics/{fabricName}/networks."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    networks: list[NetworkBaseModel] | None = Field(default=None, description="List of networks to create")


class NetworkCreateSingleResponseModel(NDNestedModel):
    """Status entry returned for a single network create/import operation."""

    identifiers: ClassVar[list[str]] = []
    network_name: str | None = Field(default=None, alias="networkName")
    display_name: str | None = Field(default=None, alias="displayName")
    status: OperationStatus | None = Field(default=None)
    message: str | None = Field(default=None)
    network_id: int | None = Field(default=None, alias="networkId")


class NetworkCreateResponseModel(NDBaseModel):
    """Response body for network create/import operations."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    results: list[NetworkCreateSingleResponseModel] | None = Field(default=None)


class NetworkListResponseModel(NDBaseModel):
    """Response body for GET /fabrics/{fabricName}/networks."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    meta: Metadata | None = Field(default=None)
    networks: list[NetworkBaseModel] | None = Field(default=None)


class NetworkPreInformationResponseModel(NDBaseModel):
    """Response body for GET /fabrics/{fabricName}/networkPreInformation."""

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"] | None] = "singleton"

    multicast_ip: str | None = Field(default=None, alias="multicastIp")
    l2_vni: int | None = Field(default=None, alias="l2Vni")
    network_prefix: str | None = Field(default=None, alias="networkPrefix")
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=2, le=4094)

    @field_validator("multicast_ip", mode="before")
    @classmethod
    def validate_multicast_ip(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_multicast_ipv4(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)
