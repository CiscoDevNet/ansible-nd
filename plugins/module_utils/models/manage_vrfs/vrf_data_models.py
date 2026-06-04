# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF data models (API request/response representations for CRUD operations).

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.

Covers:
- GET /fabrics/{fabricName}/vrfPreInformation
- GET /fabrics/{fabricName}/vrfs
- POST /fabrics/{fabricName}/vrfs
- GET /fabrics/{fabricName}/vrfs/{vrfName}
- PUT /fabrics/{fabricName}/vrfs/{vrfName}
"""

from typing import Any, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
    field_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import (
    NDNestedModel,
)

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.enums import (
    ConfigurationStatus,
    OperationStatus,
    VrfType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.validators import (
    VrfValidators,
)


# =============================================================================
# Nested / shared nested models
# =============================================================================


class MetadataCounts(NDNestedModel):
    """
    Pagination counts embedded in a list API response.

    Based on: components/schemas/MetadataCounts
    """

    identifiers: ClassVar[list[str]] = []
    total: int = Field(
        default=...,
        description="The total number of records",
    )
    remaining: int = Field(
        default=...,
        description="The remaining number of records",
    )


class Metadata(NDNestedModel):
    """
    Pagination metadata returned by list API calls.

    Based on: components/schemas/Metadata
    """

    identifiers: ClassVar[list[str]] = []
    counts: MetadataCounts | None = Field(
        default=None,
        description="Count information including total and remaining",
    )
    links: dict[str, str] | None = Field(
        default=None,
        description="Pagination link URLs (next, previous)",
    )


class TrmData(NDNestedModel):
    """
    TRM (Tenant Routed Multicast) configuration data.

    Based on: components/schemas/trmData (allOf: trmCommonFields,
    trmV4Fields, trmV6Fields, trmFlags)
    """

    identifiers: ClassVar[list[str]] = []
    # trmCommonFields
    mvpn_route_target_import: list[str] | None = Field(
        default=None,
        alias="mvpnRouteTargetImport",
        description="List of MVPN routes imports, NX-OS specific",
    )
    mvpn_route_target_export: list[str] | None = Field(
        default=None,
        alias="mvpnRouteTargetExport",
        description="List of MVPN routes exports, NX-OS specific",
    )
    mvpn_inter_as: bool | None = Field(
        default=False,
        alias="mvpnInterAs",
        description=(
            "Use the inter-as keyword for MVPN address family routes "
            "to cross BGP AS boundaries. IOS XE specific"
        ),
    )
    l3_vni_multicast_group: str | None = Field(
        default=None,
        alias="l3VniMulticastGroup",
        description="Underlay multicast address",
    )
    trm_on_bgw: bool | None = Field(
        default=False,
        alias="trmOnBgw",
        description="Enable TRM on border gateway multisite",
    )
    loopback_number: int | None = Field(
        default=None,
        alias="loopbackNumber",
        ge=0,
        le=1023,
        description="Identifier for the loopback interface",
    )
    # trmV4Fields
    v4_rp_absent: bool | None = Field(
        default=False,
        alias="v4RpAbsent",
        description=(
            "There is no RP in TRMv4 as only SSM is used"
        ),
    )
    v4_rp_external: bool | None = Field(
        default=False,
        alias="v4RpExternal",
        description="Is TRMv4 RP external to the fabric?",
    )
    v4_rp_address: str | None = Field(
        default=None,
        alias="v4RpAddress",
        description="IPv4 address for the RP",
    )
    v4_multicast_group: str | None = Field(
        default=None,
        alias="v4MulticastGroup",
        description="Multicast group for TRMv4",
    )
    # trmV6Fields
    v6_rp_absent: bool | None = Field(
        default=False,
        alias="v6RpAbsent",
        description=(
            "There is no RP in TRMv6 as only SSM is used. NX-OS specific"
        ),
    )
    v6_rp_external: bool | None = Field(
        default=False,
        alias="v6RpExternal",
        description=(
            "Is RP external to the fabric in TRMv6? NX-OS specific"
        ),
    )
    v6_rp_address: str | None = Field(
        default=None,
        alias="v6RpAddress",
        description="IPv6 address. NX-OS specific",
    )
    v6_multicast_group: str | None = Field(
        default=None,
        alias="v6MulticastGroup",
        description="Multicast group for TRMv6. NX-OS specific",
    )
    # trmFlags
    ipv4_trm: bool | None = Field(
        default=None,
        alias="ipv4Trm",
        description="Enable IPv4 tenant routed multicast",
    )
    ipv6_trm: bool | None = Field(
        default=None,
        alias="ipv6Trm",
        description="Enable IPv6 tenant routed multicast",
    )

    @field_validator("v4_rp_address", mode="before")
    @classmethod
    def validate_v4_rp_address(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("l3_vni_multicast_group", "v4_multicast_group", mode="before")
    @classmethod
    def validate_ipv4_fields(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("v6_rp_address", mode="before")
    @classmethod
    def validate_v6_rp_address(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv6_address(v)

    @field_validator("v6_multicast_group", mode="before")
    @classmethod
    def validate_v6_multicast(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv6(v)


class VxlanCoreData(NDNestedModel):
    """
    VXLAN VRF core configuration data.

    Based on: components/schemas/vxlanCoreData
    """

    identifiers: ClassVar[list[str]] = []
    vrf_vlan_name: str | None = Field(
        default=None,
        alias="vrfVlanName",
        description="Name associated with the VLAN for the VRF",
    )
    vrf_interface_description: str | None = Field(
        default=None,
        alias="vrfInterfaceDescription",
        description="Description of the interface associated with the VRF",
    )
    vrf_description: str | None = Field(
        default=None,
        alias="vrfDescription",
        max_length=255,
        description="Description of the VRF",
    )
    mtu: int | None = Field(
        default=9216,
        ge=68,
        le=9216,
        description="MTU associated with the interface",
    )
    routing_tag: int | None = Field(
        default=12345,
        alias="routingTag",
        ge=0,
        le=4294967295,
        description="NX-OS specific",
    )
    vrf_route_map: str | None = Field(
        default="FABRIC-RMAP-REDIST-SUBNET",
        alias="vrfRouteMap",
        description=(
            "Name of the route map applied to the VRF for controlling "
            "route redistribution"
        ),
    )
    v6_vrf_route_map: str | None = Field(
        default="FABRIC-RMAP-REDIST-SUBNET",
        alias="v6VrfRouteMap",
        description=(
            "If not set, redistribute direct route map will be used"
        ),
    )
    max_bgp_paths: int | None = Field(
        default=1,
        alias="maxBgpPaths",
        ge=1,
        le=64,
        description="1-64 for NX-OS, 1-32 for IOS XE",
    )
    max_ibgp_paths: int | None = Field(
        default=2,
        alias="maxIbgpPaths",
        ge=1,
        le=64,
        description="1-64 for NX-OS, 1-32 for IOS XE",
    )
    ipv6_link_local: bool | None = Field(
        default=True,
        alias="ipv6LinkLocal",
        description=(
            "Enables IPv6 link-local option under VRF SVI. "
            "Not applicable to L3VNI without VLAN config. NX-OS specific"
        ),
    )
    disable_rt_auto: bool | None = Field(
        default=False,
        alias="disableRtAuto",
        description=(
            "Applicable to IPv4, IPv6 VPN/EVPN/MVPN. RtAuto automatically "
            "assigns route targets to VPNs"
        ),
    )
    route_target_import: list[str] | None = Field(
        default=None,
        alias="routeTargetImport",
        description="List of VPN import route targets",
    )
    route_target_export: list[str] | None = Field(
        default=None,
        alias="routeTargetExport",
        description="List of VPN export route targets",
    )
    evpn_route_target_import: list[str] | None = Field(
        default=None,
        alias="evpnRouteTargetImport",
        description="List of EVPN import route targets",
    )
    evpn_route_target_export: list[str] | None = Field(
        default=None,
        alias="evpnRouteTargetExport",
        description="List of EVPN export route targets",
    )


class VxlanFabricInstance(NDNestedModel):
    """
    Fabric instance fields for a VXLAN VRF.

    Based on: components/schemas/vxlanFabricInstance
    These fields are not applicable to fabric groups.
    """

    identifiers: ClassVar[list[str]] = []
    l3_vni_without_vlan: bool | None = Field(
        default=False,
        alias="l3VniWithoutVlan",
        description=(
            "L3 VNI configuration without VLAN configuration. "
            "NX-OS specific"
        ),
    )
    bgp_best_path_relax: bool | None = Field(
        default=False,
        alias="bgpBestPathRelax",
        description=(
            "Allow multipath when remote BGP peers have different ASN. "
            "NX-OS specific"
        ),
    )
    bgp_log_neighbor_change: bool | None = Field(
        default=False,
        alias="bgpLogNeighborChange",
        description="Log messages for BGP neighbor up/down event",
    )
    bgp_allow_as_in: bool | None = Field(
        default=False,
        alias="bgpAllowAsIn",
        description=(
            "Accept AS-path even if it contains ASN configured on this "
            "border switch. VRF Lite specific."
        ),
    )
    bgp_allow_as_in_num: int | None = Field(
        default=3,
        alias="bgpAllowAsInNum",
        ge=1,
        le=10,
        description=(
            "Number of occurrences of ASN allowed in the AS-path. "
            "VRF Lite specific."
        ),
    )
    bgp_as_override: bool | None = Field(
        default=False,
        alias="bgpAsOverride",
        description=(
            "Override matching ASN while sending a BGP update. "
            "VRF Lite specific."
        ),
    )
    bgp_disable_peer_as_check: bool | None = Field(
        default=False,
        alias="bgpDisablePeerAsCheck",
        description=(
            "Disable checking of peer ASN while advertising route to that "
            "BGP peer. NX-OS specific. VRF Lite specific."
        ),
    )
    bgp_soft_reconfig_always: bool | None = Field(
        default=False,
        alias="bgpSoftReconfigAlways",
        description=(
            "Allow inbound soft reconfiguration always. VRF Lite specific."
        ),
    )
    advertise_host_route: bool | None = Field(
        default=False,
        alias="advertiseHostRoute",
        description=(
            "Flag to control advertisement of /32 and /128 routes "
            "to edge routers"
        ),
    )
    advertise_default_route: bool | None = Field(
        default=True,
        alias="advertiseDefaultRoute",
        description=(
            "Flag to control advertisement of default route internally"
        ),
    )
    configure_static_default_route: bool | None = Field(
        default=True,
        alias="configureStaticDefaultRoute",
        description="Flag to control static default route configuration",
    )
    bgp_password: str | None = Field(
        default=None,
        alias="bgpPassword",
        min_length=4,
        max_length=32,
        description="VRF Lite BGP neighbor password",
    )
    bgp_password_key_type: int | None = Field(
        default=3,
        alias="bgpPasswordKeyType",
        description=(
            "Represents the BGP password key type. "
            "Required if BGP authentication is enabled"
        ),
    )
    netflow: bool | None = Field(
        default=False,
        description=(
            "For netflow on VRF-LITE sub-interface. "
            "Supported only if netflow is enabled on fabric"
        ),
    )
    netflow_monitor: str | None = Field(
        default=None,
        alias="netflowMonitor",
        description=(
            "For NX-OS only. Required when netflow is enabled"
        ),
    )
    stretch: str | None = Field(
        default=None,
        description="Border gateway list name",
    )
    trm_data: TrmData | None = Field(
        default=None,
        alias="trmData",
        description="TRM configuration data",
    )

    @field_validator("bgp_password_key_type", mode="before")
    @classmethod
    def validate_bgp_key_type(
        cls, v: int | None
    ) -> int | None:
        if v is not None and v not in (3, 7):
            raise ValueError(
                f"bgpPasswordKeyType must be 3 or 7, got: {v}"
            )
        return v


class SecurityGroupData(NDNestedModel):
    """
    Security group configuration within a VRF.

    Based on: components/schemas/securityGroupData
    """

    identifiers: ClassVar[list[str]] = []
    default_security_action: Literal[
        "unenforcedOrNone", "enforcedPermit", "enforcedDeny"
    ] | None = Field(
        default=None,
        alias="defaultSecurityAction",
        description=(
            "Type of enforcement. Use 'unenforcedOrNone' if security "
            "groups are not enabled for the fabric. Only applicable to "
            "vxlan type fabrics."
        ),
    )
    default_security_group_tag: int | None = Field(
        default=None,
        alias="defaultSecurityGroupTag",
        ge=16,
        le=65535,
        description=(
            "Tag ID for the default security group. Applicable only if "
            "security groups are enabled and enforced."
        ),
    )


class L4l7ServiceData(NDNestedModel):
    """
    L4L7 service configuration schema.

    Based on: components/schemas/l4l7ServiceData
    """

    identifiers: ClassVar[list[str]] = []
    service_config: dict[str, str] | None = Field(
        default=None,
        alias="serviceConfig",
        description="Service configuration in JSON format",
    )
    service_epbr_config: dict[str, str] | None = Field(
        default=None,
        alias="serviceEpbrConfig",
        description="ePBR service configuration in JSON format",
    )


# =============================================================================
# Top-level VRF data models
# =============================================================================


class VrfDataModel(NDBaseModel):
    """
    Schema for a VRF object as returned/sent by list, get, create, and
    replace VRF endpoints.

    Based on: components/schemas/vrfCommon + vxlanVrfBase +
              securityGroupData + vxlanVrfProperties
    Path: GET/POST /fabrics/{fabricName}/vrfs
          GET/PUT  /fabrics/{fabricName}/vrfs/{vrfName}

    Note: ``vrfSchema`` is a discriminated oneOf over 12 VRF types
    (discriminator: ``vrfType``). This model covers the common fields
    shared across all types (``vrfCommon``) plus the VXLAN-specific base
    fields (``vxlanVrfBase`` + ``securityGroupData``).  The type-specific
    ``coreData`` and ``fabricData`` are captured as typed nested models
    (``VxlanCoreData``, ``VxlanFabricInstance``) for the standard VXLAN
    variant; for other types they are accepted as free-form dicts.
    """

    identifiers: ClassVar[list[str]] = ["vrf_name", "fabric_name"]
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "composite"

    # vrfCommon required fields
    fabric_name: str = Field(
        default=...,
        alias="fabricName",
        description="Name of the fabric",
    )
    vrf_name: str = Field(
        default=...,
        alias="vrfName",
        max_length=94,
        description=(
            "Name of the VRF. For multi-tenant environments, use the "
            "format tenantName~vrfName."
        ),
    )
    # vrfCommon optional fields
    vrf_status: ConfigurationStatus | None = Field(
        default=None,
        alias="vrfStatus",
        description="Configuration deployment status (read-only)",
    )
    tenant_name: str | None = Field(
        default=None,
        alias="tenantName",
        description="Name of the tenant (multi-tenant)",
    )
    # vxlanVrfBase fields
    vrf_id: int | None = Field(
        default=None,
        alias="vrfId",
        ge=1,
        le=16777214,
        description="ID of the VRF",
    )
    vlan_id: int | None = Field(
        default=None,
        alias="vlanId",
        ge=2,
        le=4094,
        description="VLAN identifier. Must be between 2 and 4094.",
    )
    vrf_type: str | None = Field(
        default=VrfType.VXLAN_IBGP.value,
        alias="vrfType",
        description="Type of VRF (discriminator for vrfSchema)",
    )
    service_vrf_template_name: str | None = Field(
        default=None,
        alias="serviceVrfTemplateName",
        description="Service VRF template name for userDefined VRFs",
    )
    vrf_template_name: str | None = Field(
        default=None,
        alias="vrfTemplateName",
        description="VRF template name for userDefined VRFs",
    )
    vrf_extension_template_name: str | None = Field(
        default=None,
        alias="vrfExtensionTemplateName",
        description="VRF extension template name for userDefined VRFs",
    )
    vrf_template_config: dict[str, str] | None = Field(
        default=None,
        alias="vrfTemplateConfig",
        description=(
            "Template parameter values for userDefined VRFs. Schema requires "
            "a JSON object with string values"
        ),
    )
    core_data: Any | None = Field(
        default=None,
        alias="coreData",
        description=(
            "VRF core data. For VXLAN VRFs this is ``VxlanCoreData``; "
            "for other types this is a free-form object."
        ),
    )
    fabric_data: Any | None = Field(
        default=None,
        alias="fabricData",
        description=(
            "Fabric-instance data. For VXLAN VRFs this is "
            "``VxlanFabricInstance``; for other types a free-form object."
        ),
    )
    service_data: L4l7ServiceData | None = Field(
        default=None,
        alias="serviceData",
        description="L4L7 service configuration",
    )
    # securityGroupData fields
    default_security_action: Literal[
        "unenforcedOrNone", "enforcedPermit", "enforcedDeny"
    ] | None = Field(
        default=None,
        alias="defaultSecurityAction",
        description=(
            "Type of enforcement. Use 'unenforcedOrNone' if security "
            "groups are not enabled for the fabric. Only applicable to "
            "vxlan type fabrics."
        ),
    )
    default_security_group_tag: int | None = Field(
        default=None,
        alias="defaultSecurityGroupTag",
        ge=16,
        le=65535,
        description=(
            "Tag ID for the default security group. Applicable only if "
            "security groups are enabled and enforced."
        ),
    )

    @field_validator("vrf_name", mode="before")
    @classmethod
    def validate_vrf_name(cls, v: str) -> str:
        return VrfValidators.require_vrf_name(v)

    @field_validator("vrf_type", mode="before")
    @classmethod
    def validate_vrf_type(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = str(v).strip()
        if v not in VrfType.choices():
            raise ValueError(
                f"vrfType must be one of {VrfType.choices()}, got: {v}"
            )
        return v

    @field_validator("vrf_template_config", mode="before")
    @classmethod
    def validate_vrf_template_config(
        cls, v: dict[str, str] | None
    ) -> dict[str, str] | None:
        if v is None:
            return None
        if not isinstance(v, dict):
            raise ValueError("vrfTemplateConfig must be a dictionary")
        bad = [key for key, value in v.items() if not isinstance(value, str)]
        if bad:
            raise ValueError(
                "vrfTemplateConfig values must be strings for keys: "
                f"{', '.join(str(key) for key in bad)}"
            )
        return v


class VrfCreateRequestModel(NDBaseModel):
    """
    Request body for creating one or more VRFs in the specified fabric.

    Based on: POST /fabrics/{fabricName}/vrfs request body
    Schema: ``{ vrfs: vrfSchema[] }``
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    vrfs: list[VrfDataModel] = Field(
        default=...,
        min_length=1,
        description="List of VRFs to be created",
    )


class VrfCreate207StatusModel(NDNestedModel):
    """
    Status of a single VRF creation in a 207 multi-status response.

    Based on: components/schemas/vrfCreate207Status
    (allOf: schemas-multiStatusBase + vrfId)
    """

    identifiers: ClassVar[list[str]] = []
    vrf_name: str | None = Field(
        default=None,
        alias="vrfName",
        description="Name of the VRF",
    )
    status: OperationStatus | None = Field(
        default=None,
        description="Status of the VRF creation",
    )
    message: str | None = Field(
        default=None,
        description="Error message in case of VRF operation failure",
    )
    vrf_id: int | None = Field(
        default=None,
        alias="vrfId",
        description="The unique ID of the created VRF",
    )


class VrfCreateResponseModel(NDBaseModel):
    """
    207 multi-status response for bulk VRF creation.

    Based on: POST /fabrics/{fabricName}/vrfs response
    Schema: ``{ results: vrfCreate207Status[] }``
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    results: list[VrfCreate207StatusModel] | None = Field(
        default=None,
        description="List of statuses for each VRF creation request",
    )


class VrfListResponseModel(NDBaseModel):
    """
    Response body for listing VRFs.

    Based on: GET /fabrics/{fabricName}/vrfs response
    Schema: ``{ vrfs: vrfSchema[], meta: Metadata }``
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    vrfs: list[VrfDataModel] | None = Field(
        default=None,
        description="List of all VRFs under the given fabric",
    )
    meta: Metadata | None = Field(
        default=None,
        description="Pagination and result-count metadata",
    )


class VrfPreInformationResponseModel(NDBaseModel):
    """
    Response body for the VRF pre-information endpoint.

    Based on: components/schemas/vrfInfoGet
    Path: GET /fabrics/{fabricName}/vrfPreInformation
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    l3_vni: int | None = Field(
        default=None,
        alias="l3Vni",
        description="Layer 3 VNI (Virtual Network Identifier)",
    )
    vrf_name_prefix: str | None = Field(
        default=None,
        alias="vrfNamePrefix",
        description="Prefix for the VRF name",
    )
    vlan_id: int | None = Field(
        default=None,
        alias="vlanId",
        description="VLAN ID for the VRF",
    )
    default_security_group_tag: int | None = Field(
        default=None,
        alias="defaultSecurityGroupTag",
        description=(
            "Tag ID for the default security group. Applicable only if "
            "security groups are enabled and enforced."
        ),
    )


__all__ = [
    "L4l7ServiceData",
    "Metadata",
    "MetadataCounts",
    "SecurityGroupData",
    "TrmData",
    "VrfCreate207StatusModel",
    "VrfCreateRequestModel",
    "VrfCreateResponseModel",
    "VrfDataModel",
    "VrfListResponseModel",
    "VrfPreInformationResponseModel",
    "VxlanCoreData",
    "VxlanFabricInstance",
]
