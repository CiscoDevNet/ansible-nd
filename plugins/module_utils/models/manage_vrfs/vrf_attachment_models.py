# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF attachment models (API request/response representations for attachments).

Based on OpenAPI schema for Nexus Dashboard Manage APIs v1.1.332.

Covers:
- POST /fabrics/{fabricName}/vrfAttachments
- POST /fabrics/{fabricName}/vrfAttachments/export
- POST /fabrics/{fabricName}/vrfAttachments/import  (response only)
- POST /fabrics/{fabricName}/vrfAttachments/query
- GET  /fabrics/{fabricName}/vrfFlowRules/tenants
- GET  /fabrics/{fabricName}/vrfFlowRules/vrfs
"""

from typing import ClassVar, Literal

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
    DpuAffinity,
    OperationStatus,
    VrfAttachmentSwitchRole,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.validators import (
    VrfValidators,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import (
    Metadata,
)


# =============================================================================
# Instance value nested models
# =============================================================================


class DpuInstanceValuesModel(NDNestedModel):
    """
    DPU (Data Processing Unit) instance configuration values.

    Based on: components/schemas/dpuInstanceValues
    """

    identifiers: ClassVar[list[str]] = []
    dpu_secure: bool | None = Field(
        default=False,
        alias="dpuSecure",
        description=(
            "Enable DPU secure mode for communication between the DPU "
            "and the host switch"
        ),
    )
    dpu_affinity: DpuAffinity | None = Field(
        default=None,
        alias="dpuAffinity",
        description="Affinity of the VRF attachment to a specific DPU",
    )


class VrfAttachmentInstanceValuesModel(NDNestedModel):
    """
    Per-attachment instance values for a VRF on a specific switch.

    Based on: components/schemas/vrfAttachmentInstanceValues
    (allOf: dpuInstanceValues + additional fields)
    """

    identifiers: ClassVar[list[str]] = []
    # dpuInstanceValues fields
    dpu_secure: bool | None = Field(
        default=False,
        alias="dpuSecure",
        description=(
            "Enable DPU secure mode for communication between the DPU "
            "and the host switch"
        ),
    )
    dpu_affinity: DpuAffinity | None = Field(
        default=None,
        alias="dpuAffinity",
        description="Affinity of the VRF attachment to a specific DPU",
    )
    # vrfAttachmentInstanceValues additional fields
    loopback_id: int | None = Field(
        default=None,
        alias="loopbackId",
        ge=0,
        le=1023,
        description="Loopback interface identifier (0-1023)",
    )
    loopback_ipv4_address: str | None = Field(
        default=None,
        alias="loopbackIpv4Address",
        description="IPv4 address of the loopback interface",
    )
    loopback_ipv6_address: str | None = Field(
        default=None,
        alias="loopbackIpv6Address",
        description="IPv6 address of the loopback interface",
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
    vrf_vlan_name: str | None = Field(
        default=None,
        alias="vrfVlanName",
        max_length=128,
        description=(
            "Name of the VLAN used for the VRF SVI. "
            "Must not contain ?, \\, or whitespace."
        ),
    )
    svi_ipv4_address: str | None = Field(
        default=None,
        alias="sviIpv4Address",
        description=(
            "IPv4 address with prefix in CIDR notation for the SVI. "
            "Applicable for classic LAN VRFs only."
        ),
    )
    svi_neighbor_ipv4_address: str | None = Field(
        default=None,
        alias="sviNeighborIpv4Address",
        description="IPv4 address of the SVI neighbor",
    )
    svi_ipv6_address: str | None = Field(
        default=None,
        alias="sviIpv6Address",
        description=(
            "IPv6 address with prefix in CIDR notation for the SVI"
        ),
    )
    svi_neighbor_ipv6_address: str | None = Field(
        default=None,
        alias="sviNeighborIpv6Address",
        description="IPv6 address of the SVI neighbor",
    )
    vrf_interface_description: str | None = Field(
        default=None,
        alias="vrfInterfaceDescription",
        min_length=1,
        max_length=255,
        description="Description of the VRF interface",
    )

    @field_validator("loopback_ipv4_address", "svi_neighbor_ipv4_address", mode="before")
    @classmethod
    def validate_ipv4_fields(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("loopback_ipv6_address", "svi_neighbor_ipv6_address", mode="before")
    @classmethod
    def validate_ipv6_fields(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv6_address(v)

    @field_validator("svi_ipv4_address", mode="before")
    @classmethod
    def validate_svi_ipv4(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv4(v)

    @field_validator("svi_ipv6_address", mode="before")
    @classmethod
    def validate_svi_ipv6(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv6(v)

    @field_validator("vrf_vlan_name", mode="before")
    @classmethod
    def validate_vrf_vlan_name(cls, v: str | None) -> str | None:
        return VrfValidators.validate_vrf_vlan_name(v)


# =============================================================================
# VRF extension nested models
# =============================================================================


class VrfExtensionModel(NDNestedModel):
    """
    VRF-Lite extension configuration for a specific interface on a switch.

    Based on: components/schemas/vrfExtension
    (allOf: vrfExtensionCommon + additional fields)
    """

    identifiers: ClassVar[list[str]] = []
    # vrfExtensionCommon required fields
    interface_name: str = Field(
        default=...,
        alias="interfaceName",
        description="Name of the interface used for the VRF-Lite extension",
    )
    dot1q_id: int = Field(
        default=...,
        alias="dot1qId",
        ge=2,
        le=4094,
        description="802.1Q VLAN ID (2-4094)",
    )
    neighbor_asn: str = Field(
        default=...,
        alias="neighborAsn",
        description="ASN of the BGP neighbor on this extension",
    )
    # vrfExtensionCommon optional fields
    ipv4_address: str | None = Field(
        default=None,
        alias="ipv4Address",
        description=(
            "IPv4 address with prefix in CIDR notation for the extension "
            "interface"
        ),
    )
    neighbor_ipv4_address: str | None = Field(
        default=None,
        alias="neighborIpv4Address",
        description="IPv4 address of the BGP neighbor",
    )
    ipv6_address: str | None = Field(
        default=None,
        alias="ipv6Address",
        description=(
            "IPv6 address with prefix in CIDR notation for the extension "
            "interface"
        ),
    )
    neighbor_ipv6_address: str | None = Field(
        default=None,
        alias="neighborIpv6Address",
        description="IPv6 address of the BGP neighbor",
    )
    # vrfExtension additional fields
    mtu: int | None = Field(
        default=None,
        ge=68,
        le=9216,
        description="MTU for the extension interface (68-9216)",
    )
    route_tag: int | None = Field(
        default=None,
        alias="routeTag",
        ge=0,
        le=4294967295,
        description="Route tag applied to this extension",
    )
    netflow: bool | None = Field(
        default=False,
        description=(
            "Enable netflow on the VRF-Lite sub-interface. "
            "Supported only if netflow is enabled on the fabric."
        ),
    )
    auto_peer_config: bool | None = Field(
        default=False,
        alias="autoPeerConfig",
        description=(
            "Indicates if the peer configuration is auto-generated "
            "(read-only)"
        ),
    )
    peer_vrf_name: str | None = Field(
        default=None,
        alias="peerVrfName",
        description=(
            "Name of the peer VRF associated with this extension "
            "on the neighbor switch"
        ),
    )
    route_map_in: str | None = Field(
        default=None,
        alias="routeMapIn",
        description="Name of the inbound IPv4 route map",
    )
    route_map_out: str | None = Field(
        default=None,
        alias="routeMapOut",
        description="Name of the outbound IPv4 route map",
    )
    ipv6_route_map_in: str | None = Field(
        default=None,
        alias="ipv6RouteMapIn",
        description="Name of the inbound IPv6 route map",
    )
    ipv6_route_map_out: str | None = Field(
        default=None,
        alias="ipv6RouteMapOut",
        description="Name of the outbound IPv6 route map",
    )

    @field_validator("ipv4_address", mode="before")
    @classmethod
    def validate_ipv4_address_cidr(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv4(v)

    @field_validator("neighbor_ipv4_address", mode="before")
    @classmethod
    def validate_neighbor_ipv4(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv4_address(v)

    @field_validator("ipv6_address", mode="before")
    @classmethod
    def validate_ipv6_address_cidr(cls, v: str | None) -> str | None:
        return VrfValidators.validate_cidrv6(v)

    @field_validator("neighbor_ipv6_address", mode="before")
    @classmethod
    def validate_neighbor_ipv6(cls, v: str | None) -> str | None:
        return VrfValidators.validate_ipv6_address(v)


# =============================================================================
# VRF attachment nested models
# =============================================================================


class VrfAttachmentModel(NDNestedModel):
    """
    A single VRF attach or detach operation entry.

    Based on: components/schemas/vrfAttachment
    (allOf: vrfAttachmentCommon + attach field)
    """

    identifiers: ClassVar[list[str]] = []
    # vrfAttachmentCommon required fields
    vrf_name: str = Field(
        default=...,
        alias="vrfName",
        max_length=94,
        description="Name of the VRF to attach or detach",
    )
    switch_id: str = Field(
        default=...,
        alias="switchId",
        description="Serial number of the target switch",
    )
    # vrfAttachmentCommon optional fields
    vlan_id: int | None = Field(
        default=None,
        alias="vlanId",
        ge=2,
        le=4094,
        description="VLAN ID (2-4094) to use for the VRF attachment",
    )
    instance_values: VrfAttachmentInstanceValuesModel | None = Field(
        default=None,
        alias="instanceValues",
        description=(
            "Per-attachment instance configuration overrides. "
            "Set to null to remove all instance values."
        ),
    )
    extension_values: list[VrfExtensionModel] | None = Field(
        default=None,
        alias="extensionValues",
        description=(
            "List of VRF-Lite extension configurations for this attachment"
        ),
    )
    extra_config: str | None = Field(
        default=None,
        alias="extraConfig",
        description=(
            "Additional CLI configuration to append to this attachment"
        ),
    )
    # vrfAttachment additional field
    attach: bool = Field(
        default=...,
        description=(
            "True to attach the VRF to the switch; "
            "False to detach it."
        ),
    )


class VrfAttachDetachRequestModel(NDBaseModel):
    """
    Request body for attaching or detaching VRFs to/from switches.

    Based on: components/schemas/vrfAttachDetachPayload
    Path: POST /fabrics/{fabricName}/vrfAttachments
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    attachments: list[VrfAttachmentModel] | None = Field(
        default=None,
        description="List of VRF attach or detach operations",
    )


class VrfAttachmentStatusModel(NDNestedModel):
    """
    Status of a single VRF attachment in a 207 multi-status response.

    Based on: components/schemas/vrfAttachmentStatus
    (allOf: schemas-multiStatusBase + switchId + switchName)
    """

    identifiers: ClassVar[list[str]] = []
    vrf_name: str | None = Field(
        default=None,
        alias="vrfName",
        description="Name of the VRF",
    )
    status: OperationStatus | None = Field(
        default=None,
        description="Outcome of the attach or detach operation",
    )
    message: str | None = Field(
        default=None,
        description="Error message in case of operation failure",
    )
    switch_id: str | None = Field(
        default=None,
        alias="switchId",
        description="Serial number of the switch",
    )
    switch_name: str | None = Field(
        default=None,
        alias="switchName",
        description="Name of the switch",
    )


class VrfAttach207ResponseModel(NDBaseModel):
    """
    207 multi-status response for VRF attach/detach or attachment import.

    Based on: components/schemas/vrfAttach207Status
    Path: POST /fabrics/{fabricName}/vrfAttachments response
          POST /fabrics/{fabricName}/vrfAttachments/import response
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    results: list[VrfAttachmentStatusModel] | None = Field(
        default=None,
        description=(
            "Status of each attachment operation. Contains only entries "
            "with failure status in case of partial success."
        ),
    )


class VrfAttachmentDetailModel(NDNestedModel):
    """
    Detailed attachment information for a single VRF / switch pair.

    Based on: components/schemas/vrfAttachmentDetail
    (allOf: vrfAttachmentCommon + vrfAttachmentQueryCommon + additional)
    """

    identifiers: ClassVar[list[str]] = []
    # vrfAttachmentCommon fields
    vrf_name: str | None = Field(
        default=None,
        alias="vrfName",
        max_length=94,
        description="Name of the VRF",
    )
    switch_id: str | None = Field(
        default=None,
        alias="switchId",
        description="Serial number of the switch",
    )
    vlan_id: int | None = Field(
        default=None,
        alias="vlanId",
        ge=2,
        le=4094,
        description="VLAN ID for the VRF attachment",
    )
    instance_values: VrfAttachmentInstanceValuesModel | None = Field(
        default=None,
        alias="instanceValues",
        description="Per-attachment instance configuration",
    )
    extension_values: list[VrfExtensionModel] | None = Field(
        default=None,
        alias="extensionValues",
        description="VRF-Lite extension configurations",
    )
    extra_config: str | None = Field(
        default=None,
        alias="extraConfig",
        description="Additional CLI configuration for this attachment",
    )
    # vrfAttachmentQueryCommon fields
    switch_name: str | None = Field(
        default=None,
        alias="switchName",
        description="Name of the switch",
    )
    status: ConfigurationStatus | None = Field(
        default=None,
        description="Deployment status of the VRF on the switch",
    )
    attach: bool | None = Field(
        default=None,
        description=(
            "True if the VRF is attached / should be attached "
            "to the switch"
        ),
    )
    switch_role: VrfAttachmentSwitchRole | None = Field(
        default=None,
        alias="switchRole",
        description="Role of the switch in the fabric",
    )
    # vrfAttachmentDetail extra fields
    peer_switch_id: str | None = Field(
        default=None,
        alias="peerSwitchId",
        description="Serial number of the vPC peer switch (if applicable)",
    )
    error_message: str | None = Field(
        default=None,
        alias="errorMessage",
        description="Error message associated with a failed deployment",
    )
    show_vlan: bool | None = Field(
        default=None,
        alias="showVlan",
        description=(
            "Flag indicating whether the VLAN field is relevant for "
            "this attachment entry"
        ),
    )
    vrf_id: int | None = Field(
        default=None,
        alias="vrfId",
        description="Unique identifier of the VRF",
    )
    switch_fabric_name: str | None = Field(
        default=None,
        alias="switchFabricName",
        description=(
            "Name of the fabric that the switch is a member of"
        ),
    )


# =============================================================================
# Request + response models for attachment sub-resources
# =============================================================================


class VrfAttachmentExportRequestModel(NDBaseModel):
    """
    Request body for exporting VRF attachment data as CSV.

    Based on: components/schemas/exportVrfAttachments
    Path: POST /fabrics/{fabricName}/vrfAttachments/export
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    switch_ids: list[str] | None = Field(
        default=None,
        alias="switchIds",
        description=(
            "Serial numbers of the switches to filter by. "
            "If null or empty, all switches are included."
        ),
    )
    vrf_names: list[str] | None = Field(
        default=None,
        alias="vrfNames",
        description=(
            "Names of the VRFs to filter by. "
            "If null or empty, all VRFs are included."
        ),
    )


class VrfAttachmentQueryRequestModel(NDBaseModel):
    """
    Request body for querying VRF attachment details.

    Based on: components/schemas/attachmentQuery
    Path: POST /fabrics/{fabricName}/vrfAttachments/query
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    switch_ids: list[str] | None = Field(
        default=None,
        alias="switchIds",
        description=(
            "Serial numbers of the switches to filter by. "
            "If null or empty, all switches are included."
        ),
    )
    vrf_names: list[str] | None = Field(
        default=None,
        alias="vrfNames",
        description=(
            "Names of the VRFs to filter by. "
            "If null or empty, all VRFs are included."
        ),
    )


class VrfAttachmentQueryResponseModel(NDBaseModel):
    """
    Response body for a VRF attachment query.

    Based on: POST /fabrics/{fabricName}/vrfAttachments/query response
    Schema: ``{ attachments: vrfAttachmentDetail[], meta: Metadata }``
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    attachments: list[VrfAttachmentDetailModel] | None = Field(
        default=None,
        description="List of detailed VRF attachment records",
    )
    meta: Metadata | None = Field(
        default=None,
        description="Pagination and result-count metadata",
    )


# =============================================================================
# Flow rules response models
# =============================================================================


class VrfFlowRulesTenantsResponseModel(NDBaseModel):
    """
    Response body for the VRF flow rules tenants endpoint.

    Based on: components/schemas/VrfFlowRulesTenants
    Path: GET /fabrics/{fabricName}/vrfFlowRules/tenants
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    tenants: list[str] | None = Field(
        default=None,
        description=(
            "List of tenant names that have VRF flow rules configured"
        ),
    )


class VrfFlowRulesVrfsResponseModel(NDBaseModel):
    """
    Response body for the VRF flow rules VRFs endpoint.

    Based on: components/schemas/VrfFlowRulesVrfs
    Path: GET /fabrics/{fabricName}/vrfFlowRules/vrfs
    """

    identifiers: ClassVar[list[str]] = []
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "singleton"

    vrfs: list[str] | None = Field(
        default=None,
        description=(
            "List of VRF names that have flow rules configured"
        ),
    )


__all__ = [
    "DpuInstanceValuesModel",
    "Metadata",
    "VrfAttach207ResponseModel",
    "VrfAttachDetachRequestModel",
    "VrfAttachmentDetailModel",
    "VrfAttachmentExportRequestModel",
    "VrfAttachmentInstanceValuesModel",
    "VrfAttachmentModel",
    "VrfAttachmentQueryRequestModel",
    "VrfAttachmentQueryResponseModel",
    "VrfAttachmentStatusModel",
    "VrfExtensionModel",
    "VrfFlowRulesTenantsResponseModel",
    "VrfFlowRulesVrfsResponseModel",
]
