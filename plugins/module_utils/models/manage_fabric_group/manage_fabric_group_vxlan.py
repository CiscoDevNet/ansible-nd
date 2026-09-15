# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import List, Dict, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import IPv4CIDR, IPv6CIDR, NdFabricName
from ansible_collections.cisco.nd.plugins.module_utils.common.validators import validate_ip_address
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    FieldSerializationInfo,
    SecretStr,
    field_serializer,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.enums import (
    CloudSecAlgorithmEnum,
    CloudSecEnforcementEnum,
    FabricGroupTypeEnum,
    MultisiteOverlayInterConnectTypeEnum,
    SecurityGroupTagEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    BgpAuthenticationKeyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import (
    _build_options_from_model,
    serialize_secret_value,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    BGP_ASN_RE,
)

"""
# Pydantic models for VXLAN Fabric Group (MSD) management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
VXLAN Fabric Groups (MSD - Multi-Site Domain) through the Nexus Dashboard (ND) API.

## Models Overview

- `RouteServerModel` - Route server configuration for multi-site overlay
- `VxlanFabricGroupManagementModel` - VXLAN fabric group management settings
- `FabricGroupVxlanModel` - Complete fabric group creation model

## Usage

```python
fabric_group_data = {
    "name": "MyFabricGroup",
    "category": "fabricGroup",
    "management": {
        "type": "vxlan",
        "l2VniRange": "30000-49000",
        "l3VniRange": "50000-59000",
        "anycastGatewayMac": "2020.0000.00aa",
    }
}
fabric_group = FabricGroupVxlanModel(**fabric_group_data)
```
"""


class RouteServerModel(NDNestedModel):
    """
    # Summary

    Route server configuration for multi-site overlay interconnect.

    ## Raises

    - `ValueError` - If IP address or ASN format is invalid
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow", hide_input_in_errors=True)

    route_server_ip: str = Field(alias="routeServerIp", description="Route Server IP Address")
    route_server_asn: str = Field(alias="routeServerAsn", description="Autonomous system number 1-4294967295 | 1-65535[.0-65535]")

    @field_validator("route_server_ip")
    @classmethod
    def validate_route_server_ip(cls, value: str) -> str:
        # Schema format "ip": accepts IPv4 or IPv6.
        validate_ip_address(value)
        return value

    @field_validator("route_server_asn")
    @classmethod
    def validate_asn(cls, value: str) -> str:
        if not BGP_ASN_RE.match(value):
            raise ValueError(f"Invalid BGP ASN format: {value}")
        return value


class VxlanFabricGroupManagementModel(NDNestedModel):
    """
    # Summary

    VXLAN Fabric Group (MSD) management configuration.

    This model contains all settings specific to VXLAN fabric group types including
    multi-site overlay/underlay configuration, CloudSec, and security group settings.

    ## Raises

    - `ValueError` - If VNI ranges, IP ranges, or MAC addresses are invalid
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow", hide_input_in_errors=True)

    # Fabric Group Type (required for discriminated union)
    type: Literal[FabricGroupTypeEnum.VXLAN] = Field(description="Type of the fabric group", default=FabricGroupTypeEnum.VXLAN)

    # VNI Ranges
    l2_vni_range: str = Field(
        alias="l2VniRange",
        description="Overlay network identifier range (minimum: 1, maximum: 16777214)",
        default="30000-49000",
    )
    l3_vni_range: str = Field(
        alias="l3VniRange",
        description="Overlay VRF identifier range (minimum: 1, maximum: 16777214)",
        default="50000-59000",
    )
    downstream_vni: bool = Field(
        alias="downstreamVni",
        description="Enable unique per-fabric virtual network identifier (VNI)",
        default=False,
    )
    downstream_l2_vni_range: str = Field(
        alias="downstreamL2VniRange",
        description="Unique Range for L2VNI when downstream VNI is enabled (min: 1, max: 16777214)",
        default="10030000-10049000",
    )
    downstream_l3_vni_range: str = Field(
        alias="downstreamL3VniRange",
        description="Unique Range for L3VNI when downstream VNI is enabled (min: 1, max: 16777214)",
        default="10050000-10059000",
    )

    # Underlay
    underlay_ipv6: bool = Field(
        alias="underlayIpv6",
        description="If not enabled, IPv4 underlay is used",
        default=False,
    )

    # Templates
    vrf_template: str = Field(
        alias="vrfTemplate",
        description="Default overlay VRF template for leafs",
        default="Default_VRF_Universal",
    )
    network_template: str = Field(
        alias="networkTemplate",
        description="Default overlay network template for leafs",
        default="Default_Network_Universal",
    )
    vrf_extension_template: str = Field(
        alias="vrfExtensionTemplate",
        description="Default overlay VRF template for borders",
        default="Default_VRF_Extension_Universal",
    )
    network_extension_template: str = Field(
        alias="networkExtensionTemplate",
        description="Default overlay network template for borders",
        default="Default_Network_Extension_Universal",
    )

    # PVLAN
    private_vlan: bool = Field(
        alias="privateVlan",
        description="Enable PVLAN on switches except spines and super spines",
        default=False,
    )
    default_private_vlan_secondary_network_template: str = Field(
        alias="defaultPrivateVlanSecondaryNetworkTemplate",
        description="Default PVLAN secondary network template",
        default="Pvlan_Secondary_Network",
    )

    # Anycast Gateway
    anycast_gateway_mac: str = Field(
        alias="anycastGatewayMac",
        description="Shared anycast gateway MAC address for all VTEPs",
        default="2020.0000.00aa",
    )

    # Multi-Site Overlay
    multisite_overlay_inter_connect_type: MultisiteOverlayInterConnectTypeEnum = Field(
        alias="multisiteOverlayInterConnectType",
        description="Type of Multi-Site Overlay Interconnect",
        default=MultisiteOverlayInterConnectTypeEnum.MANUAL,
    )
    route_server_collection: Optional[List[RouteServerModel]] = Field(
        alias="routeServerCollection",
        description="Multi-Site Route-Servers",
        default=None,
    )
    route_server_redistribute_direct_route_map: bool = Field(
        alias="routeServerRedistributeDirectRouteMap",
        description="Redistribute direct on route servers for auto-created Multi-Site overlay IFC links",
        default=False,
    )
    route_server_routing_tag: int = Field(
        alias="routeServerRoutingTag",
        description="Routing tag associated with Route Server IP for redistribute direct (0-4294967295)",
        ge=0,
        le=4294967295,
        default=54321,
    )
    enable_ms_overlay_ifc_bgp_desc: bool = Field(
        alias="enableMsOverlayIfcBgpDesc",
        description="Generate BGP neighbor description for auto-created Multi-Site overlay IFC links",
        default=True,
    )

    # Multi-Site Underlay
    auto_multisite_underlay_inter_connect: bool = Field(
        alias="autoMultisiteUnderlayInterConnect",
        description="Auto-configures Multi-Site underlay Inter-Fabric links",
        default=False,
    )
    bgp_send_community: bool = Field(
        alias="bgpSendCommunity",
        description="For auto-created Multi-Site Underlay Inter-Fabric links",
        default=False,
    )
    bgp_log_neighbor_change: bool = Field(
        alias="bgpLogNeighborChange",
        description="For auto-created Multi-Site Underlay Inter-Fabric links",
        default=False,
    )
    bgp_bfd: bool = Field(
        alias="bgpBfd",
        description="For auto-created Multi-Site Underlay Inter-Fabric links",
        default=False,
    )
    multisite_delay_restore: int = Field(
        alias="multisiteDelayRestore",
        description="Multi-Site underlay and overlay control plane convergence time in seconds",
        ge=30,
        le=1000,
        default=300,
    )
    multisite_inter_connect_bgp_authentication: bool = Field(
        alias="multisiteInterConnectBgpAuthentication",
        description="Enables or disables the BGP authentication for inter-site links",
        default=False,
    )
    multisite_inter_connect_bgp_auth_key_type: BgpAuthenticationKeyTypeEnum = Field(
        alias="multisiteInterConnectBgpAuthKeyType",
        description="BGP key encryption type: 3 - 3DES, 6 - Cisco type 6, 7 - Cisco type 7",
        default=BgpAuthenticationKeyTypeEnum.THREE_DES,
    )
    multisite_inter_connect_bgp_key: Optional[SecretStr] = Field(
        alias="multisiteInterConnectBgpKey",
        description="Encrypted BGP authentication key based on type",
        default=None,
        json_schema_extra={"secret": True},
    )
    multisite_loopback_id: int = Field(
        alias="multisiteLoopbackId",
        description="Loopback ID for multi-site (typically Loopback100)",
        ge=0,
        le=1023,
        default=100,
    )
    border_gateway_routing_tag: int = Field(
        alias="borderGatewayRoutingTag",
        description="Routing tag associated with IP address of loopback and DCI interfaces (0-4294967295)",
        ge=0,
        le=4294967295,
        default=54321,
    )

    # Multi-Site IP Ranges
    multisite_loopback_ip_range: IPv4CIDR = Field(
        alias="multisiteLoopbackIpRange",
        description="Typically Loopback100 IP Address Range",
        default="10.10.0.0/24",
    )
    multisite_underlay_subnet_range: IPv4CIDR = Field(
        alias="multisiteUnderlaySubnetRange",
        description="Address range to assign P2P DCI Links",
        default="10.10.1.0/24",
    )
    multisite_underlay_subnet_target_mask: int = Field(
        alias="multisiteUnderlaySubnetTargetMask",
        description="Target Mask for Subnet Range",
        ge=8,
        le=31,
        default=30,
    )
    multisite_loopback_ipv6_range: IPv6CIDR = Field(
        alias="multisiteLoopbackIpv6Range",
        description="Typically Loopback100 IPv6 Address Range",
        default="fd00::a10:0/120",
    )
    multisite_underlay_ipv6_subnet_range: IPv6CIDR = Field(
        alias="multisiteUnderlayIpv6SubnetRange",
        description="Address range to assign P2P DCI IPv6 Links",
        default="fd00::a11:0/120",
    )
    multisite_underlay_ipv6_subnet_target_mask: int = Field(
        alias="multisiteUnderlayIpv6SubnetTargetMask",
        description="Target IPv6 Mask for Subnet Range",
        ge=120,
        le=127,
        default=126,
    )

    # Tenant Routed Multicast
    tenant_routed_multicast_v4_v6: bool = Field(
        alias="tenantRoutedMulticastV4V6",
        description="If enabled, MVPN VRI IDs are tracked in MSD fabric to ensure uniqueness within MSD",
        default=False,
    )

    # Security Groups
    security_group_tag: SecurityGroupTagEnum = Field(
        alias="securityGroupTag",
        description="If set to strict, only security groups enabled child fabrics will be allowed",
        default=SecurityGroupTagEnum.OFF,
    )
    security_group_tag_prefix: str = Field(
        alias="securityGroupTagPrefix",
        description="Prefix to be used when a new security group is created",
        min_length=1,
        max_length=10,
        pattern=r"^[a-zA-Z0-9-_]*$",
        default="SG_",
    )
    security_group_tag_mac_segmentation: bool = Field(
        alias="securityGroupTagMacSegmentation",
        description="Enable MAC based segmentation for security groups",
        default=False,
    )
    security_group_tag_id_range: str = Field(
        alias="securityGroupTagIdRange",
        description="Security group tag (SGT) identifier range (min: 16, max: 65535)",
        default="10000-14000",
    )
    security_group_tag_preprovision: bool = Field(
        alias="securityGroupTagPreprovision",
        description="Generate security groups configuration for non-enforced VRFs",
        default=False,
    )

    # CloudSec
    auto_configure_cloud_sec: bool = Field(
        alias="autoConfigureCloudSec",
        description="Auto Config CloudSec on Border Gateways",
        default=False,
    )
    cloud_sec_key: Optional[SecretStr] = Field(
        alias="cloudSecKey",
        description="Cisco Type 7 Encrypted Octet String",
        default=None,
        json_schema_extra={"secret": True},
    )
    cloud_sec_algorithm: CloudSecAlgorithmEnum = Field(
        alias="cloudSecAlgorithm",
        description="CloudSec Encryption Algorithm",
        default=CloudSecAlgorithmEnum.AES_128_CMAC,
    )
    cloud_sec_enforcement: CloudSecEnforcementEnum = Field(
        alias="cloudSecEnforcement",
        description="Enforcement type. If set strict, data across site must be encrypted",
        default=CloudSecEnforcementEnum.STRICT,
    )
    cloud_sec_report_timer: int = Field(
        alias="cloudSecReportTimer",
        description="CloudSec Operational Status periodic report timer in minutes",
        ge=5,
        le=60,
        default=5,
    )

    # Configuration Backup
    scheduled_backup: Optional[bool] = Field(
        alias="scheduledBackup",
        description="Enable backup at the specified time daily",
        default=None,
    )
    scheduled_backup_time: Optional[str] = Field(
        alias="scheduledBackupTime",
        description="Time (UTC) in 24 hour format to take a daily backup (00:00 to 23:59)",
        pattern=r"^([01]\d|2[0-3]):([0-5]\d)$",
        default=None,
    )

    @field_validator("anycast_gateway_mac")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        if not re.match(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$", value):
            raise ValueError(f"Invalid MAC address format, expected xxxx.xxxx.xxxx, got: {value}")
        return value.lower()

    @field_validator("cloud_sec_key")
    @classmethod
    def validate_cloud_sec_key(cls, value: Optional[SecretStr]) -> Optional[SecretStr]:
        # Generic message only; never echo the secret value.
        if value is None:
            return value
        raw = value.get_secret_value()
        if raw == "":
            return value
        if not re.match(r"^[a-fA-F0-9]{1,130}$", raw):
            raise ValueError("cloud_sec_key must be a hexadecimal string of 1-130 characters ([a-fA-F0-9]).")
        return value

    @model_validator(mode="after")
    def validate_cloud_sec_key_length(self) -> "VxlanFabricGroupManagementModel":
        # ND enforces an exact key length per algorithm; fail fast without echoing the secret.
        if self.cloud_sec_key is None:
            return self
        raw = self.cloud_sec_key.get_secret_value()
        if raw == "":
            return self
        algo = self.cloud_sec_algorithm
        algo_str = algo.value if hasattr(algo, "value") else str(algo)
        expected = {"AES_128_CMAC": 66, "AES_256_CMAC": 130}.get(algo_str)
        if expected is not None and len(raw) != expected:
            raise ValueError(f"cloud_sec_key must be exactly {expected} hexadecimal characters for {algo_str}.")
        return self

    @field_serializer("multisite_inter_connect_bgp_key", "cloud_sec_key")
    def serialize_secret_key(self, value: Optional[SecretStr], info: FieldSerializationInfo) -> Optional[str]:
        """Real value only for the API payload; masked in config/diff/gathered/error output."""
        return serialize_secret_value(value, info)


class FabricGroupVxlanModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a VXLAN Fabric Group (MSD).

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow", hide_input_in_errors=True)

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Group Properties
    category: Literal["fabricGroup"] = Field(description="Resource category", default="fabricGroup")
    fabric_name: NdFabricName

    # Core Management Configuration
    management: VxlanFabricGroupManagementModel = Field(
        description="VXLAN fabric group management configuration", default_factory=VxlanFabricGroupManagementModel
    )

    @model_validator(mode="after")
    def validate_fabric_group_consistency(self) -> "FabricGroupVxlanModel":
        if self.management.type != FabricGroupTypeEnum.VXLAN:
            raise ValueError(f"Management type must be {FabricGroupTypeEnum.VXLAN}")
        # Propagate fabric name into the management model so payloads carry it.
        self.management.name = self.fabric_name
        return self

    @classmethod
    def get_argument_spec(cls) -> Dict:
        """Auto-generate the Ansible argument spec from the pydantic model fields.

        Mirrors ``FabricBaseModel.get_argument_spec`` so the module exposes the
        full nested management option tree (types, choices, defaults) and the
        shared ``config_actions`` save/deploy controls. Single-value Literal
        fields (``category``, ``management.type``) are auto-excluded.
        """
        config_options = _build_options_from_model(cls)
        return dict(
            state={
                "type": "str",
                "default": "merged",
                "choices": ["merged", "replaced", "deleted", "overridden"],
            },
            config={
                "required": False,
                "type": "list",
                "elements": "dict",
                "options": config_options,
            },
            config_actions={
                "type": "dict",
                "required": False,
                "options": {
                    "save": {"type": "bool", "default": False},
                    "deploy": {"type": "bool", "default": False},
                    "type": {"type": "str", "default": "switch", "choices": ["switch", "global"]},
                },
            },
        )


# Export all models for external use
__all__ = [
    "FabricGroupVxlanModel",
    "RouteServerModel",
    "VxlanFabricGroupManagementModel",
]
