# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network data models for Nexus Dashboard Manage network CRUD APIs."""

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
    AciVlanNetworkType,
    ClassicNetworkLayer,
    ConfigurationStatus,
    FabricType,
    NetworkLayer,
    NetworkType,
    OperationStatus,
    VlanNetworkType,
    VlanPoolDomainType,
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

    identifiers: ClassVar[list[str]] = []
    stretch: str | None = Field(default=None, description="Stretch border gateway list name")
    enable_ir: bool | None = Field(default=False, alias="enableIr")
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
    rt_auto: bool | None = Field(default=None, alias="rtAuto", description="Enable automatic route-target")
    x_connect: bool | None = Field(default=None, alias="xConnect", description="Enable xConnect")
    fabric_data: DefaultL2FabricDataModel | dict[str, Any] | None = Field(default=None, alias="fabricData")


class VxlanL3FabricDataModel(NDNestedModel):
    """VXLAN L3 fabric-specific data."""

    identifiers: ClassVar[list[str]] = []
    dhcp_servers: list[DhcpServerModel | dict[str, Any]] | None = Field(default=None, alias="dhcpServers")
    loopback_id: int | None = Field(default=None, alias="loopbackId")
    igmp_version: int | None = Field(default=None, alias="igmpVersion", ge=1, le=3)
    netflow: bool | None = Field(default=False, description="Enable netflow")
    gateway_on_border: bool | None = Field(default=None, alias="gatewayOnBorder")
    ipv4_trm: bool | None = Field(default=None, alias="ipv4Trm")
    ipv6_trm: bool | None = Field(default=None, alias="ipv6Trm")

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
    gateway_on_border: bool | None = Field(default=None, alias="gatewayOnBorder")

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
    fabric_data: VxlanL3FabricDataModel | DefaultL3FabricDataModel | dict[str, Any] | None = Field(default=None, alias="fabricData")

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


class ClassicOrRoutedL2FabricDataModel(NDNestedModel):
    """Fabric-specific configuration for classic/routed L2 data."""

    identifiers: ClassVar[list[str]] = []
    redundancy_type: Literal["hsrp", "vrrp"] | None = Field(default=None, alias="redundancyType")


class ClassicOrRoutedL2DataModel(NDNestedModel):
    """L2 data used by routed/classic network schemas."""

    identifiers: ClassVar[list[str]] = []
    vlan_name: str | None = Field(default=None, alias="vlanName")
    fabric_data: ClassicOrRoutedL2FabricDataModel | dict[str, Any] | None = Field(default=None, alias="fabricData")


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
    netflow_sampler: str | None = Field(default=None, alias="netflowSampler")
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
    l2_netflow_monitor: str | None = Field(default=None, alias="l2NetflowMonitor")
    l3_netflow_monitor: str | None = Field(default=None, alias="l3NetflowMonitor")

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

    fabric_name: str | None = Field(default=None, alias="fabricName")
    network_name: str = Field(default=..., alias="networkName", max_length=128)
    network_status: ConfigurationStatus | None = Field(default=None, alias="networkStatus")
    display_name: str | None = Field(default=None, alias="displayName")
    vrf_name: str | None = Field(default=None, alias="vrfName", max_length=32)
    vlan_id: int | None = Field(default=None, alias="vlanId", ge=2, le=4094)
    tenant_name: str | None = Field(default=None, alias="tenantName", max_length=63)
    layer: NetworkLayer | None = Field(default=None)

    @field_validator("network_name", mode="before")
    @classmethod
    def validate_network_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_network_name(v)

    @field_validator("tenant_name", mode="before")
    @classmethod
    def validate_tenant_name(cls, v: str | None) -> str | None:
        return NetworkValidators.validate_tenant_name(v)

    @field_validator("vlan_id", mode="before")
    @classmethod
    def validate_vlan_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_vlan_id(v)


class NetworkBaseModel(NetworkCommonModel):
    """Generic model for components/schemas/networkBase discriminator payloads."""

    network_type: NetworkType | str | None = Field(default=None, alias="networkType")
    vlan_network_type: VlanNetworkType | str | None = Field(default=None, alias="vlanNetworkType")
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
    network_template_config: dict[str, str] | None = Field(default=None, alias="networkTemplateConfig")
    interface_group_names: list[str] | None = Field(default=None, alias="interfaceGroupNames")

    @field_validator("network_id", "primary_network_id", "normal_network_id", mode="before")
    @classmethod
    def validate_network_id(cls, v: int | None) -> int | None:
        return NetworkValidators.validate_network_id(v)

    @classmethod
    def from_response(cls, response: dict[str, Any], **kwargs) -> "NetworkBaseModel":
        normalized = dict(response)
        if "layer" not in normalized and "networkMode" in normalized:
            normalized["layer"] = normalized["networkMode"]
        l2_data = normalized.get("l2Data")
        if isinstance(l2_data, dict) and "rtAuto" not in l2_data and "disableRtAuto" in l2_data:
            l2_data = dict(l2_data)
            l2_data["rtAuto"] = not l2_data["disableRtAuto"]
            normalized["l2Data"] = l2_data
        return super().from_response(normalized, **kwargs)


class VxlanNetworkModel(NetworkBaseModel):
    """VXLAN network model."""

    network_type: Literal[NetworkType.VXLAN] = Field(default=NetworkType.VXLAN, alias="networkType")


class VxlanIbgpNetworkModel(NetworkBaseModel):
    """VXLAN iBGP network model."""

    network_type: Literal[NetworkType.VXLAN_IBGP] = Field(default=NetworkType.VXLAN_IBGP, alias="networkType")


class VxlanEbgpNetworkModel(NetworkBaseModel):
    """VXLAN eBGP network model."""

    network_type: Literal[NetworkType.VXLAN_EBGP] = Field(default=NetworkType.VXLAN_EBGP, alias="networkType")


class VxlanCampusNetworkModel(NetworkBaseModel):
    """VXLAN campus network model."""

    network_type: Literal[NetworkType.VXLAN_CAMPUS] = Field(default=NetworkType.VXLAN_CAMPUS, alias="networkType")


class AimlVxlanIbgpNetworkModel(NetworkBaseModel):
    """AIML VXLAN iBGP network model."""

    network_type: Literal[NetworkType.AIML_VXLAN_IBGP] = Field(default=NetworkType.AIML_VXLAN_IBGP, alias="networkType")


class AimlVxlanEbgpNetworkModel(NetworkBaseModel):
    """AIML VXLAN eBGP network model."""

    network_type: Literal[NetworkType.AIML_VXLAN_EBGP] = Field(default=NetworkType.AIML_VXLAN_EBGP, alias="networkType")


class RoutedNetworkModel(NetworkBaseModel):
    """Routed network model."""

    network_type: Literal[NetworkType.ROUTED] = Field(default=NetworkType.ROUTED, alias="networkType")
    layer: ClassicNetworkLayer | None = Field(default=None)


class AimlRoutedNetworkModel(RoutedNetworkModel):
    """AIML routed network model."""

    network_type: Literal[NetworkType.AIML_ROUTED] = Field(default=NetworkType.AIML_ROUTED, alias="networkType")


class ClassicLanEnhancedNetworkModel(RoutedNetworkModel):
    """Classic LAN enhanced network model."""

    network_type: Literal[NetworkType.CLASSIC_LAN_ENHANCED] = Field(default=NetworkType.CLASSIC_LAN_ENHANCED, alias="networkType")


class CustomNetworkModel(NetworkBaseModel):
    """User-defined/custom network model."""

    network_type: Literal[NetworkType.USER_DEFINED] = Field(default=NetworkType.USER_DEFINED, alias="networkType")


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
