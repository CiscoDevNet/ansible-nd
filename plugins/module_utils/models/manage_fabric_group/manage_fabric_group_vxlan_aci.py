# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import Any, Dict, List, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import NdFabricName
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.enums import (
    FabricGroupTypeEnum,
    VxlanAciOverlayInterConnectTypeEnum,
    VxlanAciSecurityGroupTagEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    BgpAuthenticationKeyTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import (
    _build_options_from_model,
)

"""
# Pydantic models for VXLAN-to-ACI Fabric Group management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
VXLAN-to-ACI Fabric Groups through the Nexus Dashboard (ND) API.

A VXLAN-to-ACI fabric group (``category=fabricGroup``, ``management.type=vxlanAci``)
is a Multi-Site domain that contains both ACI and VXLAN EVPN fabrics. Its
management schema is a focused subset of the standard VXLAN fabric group,
centered on multi-site overlay/underlay interconnect and security group tags.

## Models Overview

- `VxlanAciFabricGroupManagementModel` - VXLAN-to-ACI fabric group management settings
- `FabricGroupVxlanAciModel` - Complete VXLAN-to-ACI fabric group creation model

## Usage

```python
fabric_group_data = {
    "fabric_name": "MyVxlanAciGroup",
    "category": "fabricGroup",
    "management": {
        "type": "vxlanAci",
        "l2VniRange": "30000-49000",
        "l3VniRange": "50000-59000",
    },
}
fabric_group = FabricGroupVxlanAciModel(**fabric_group_data)
```
"""


class VxlanAciFabricGroupManagementModel(NDNestedModel):
    """
    # Summary

    VXLAN-to-ACI Fabric Group management configuration.

    Contains the settings specific to the ``vxlanAci`` fabric group type,
    including multi-site overlay/underlay interconnect and security group tag
    configuration used to bridge ACI and VXLAN EVPN fabrics.

    ## Raises

    - `ValueError` - If VNI ranges, IP ranges, or MAC addresses are invalid
    - `TypeError` - If required string fields are not provided
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # securityGroupStatus is a read-only status returned by ND; keep it out of
    # the argspec and diff comparisons.
    _argspec_exclude_fields: ClassVar[set[str]] = {"name", "security_group_status"}

    # Fabric Group Type (required for discriminated union)
    type: Literal[FabricGroupTypeEnum.VXLAN_ACI] = Field(description="Type of the fabric group", default=FabricGroupTypeEnum.VXLAN_ACI)

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

    # Anycast Gateway
    anycast_gateway_mac: str = Field(
        alias="anycastGatewayMac",
        description="Shared anycast gateway MAC address for all VTEPs; should be set to APIC's default BD MAC",
        default="0022.bdf8.19ff",
    )

    # Multi-Site Overlay
    multisite_overlay_inter_connect_type: VxlanAciOverlayInterConnectTypeEnum = Field(
        alias="multisiteOverlayInterConnectType",
        description="Type of Multi-Site Overlay Interconnect",
        default=VxlanAciOverlayInterConnectTypeEnum.DIRECT_PEERING,
    )

    # Multi-Site Underlay
    auto_multisite_underlay_inter_connect: bool = Field(
        alias="autoMultisiteUnderlayInterConnect",
        description="Auto-configures Multi-Site underlay Inter-Fabric links",
        default=True,
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
    multisite_inter_connect_bgp_key: Optional[str] = Field(
        alias="multisiteInterConnectBgpKey",
        description="Encrypted BGP authentication key based on type",
        min_length=1,
        max_length=256,
        default=None,
    )
    multisite_loopback_id: int = Field(
        alias="multisiteLoopbackId",
        description="Loopback ID for multi-site (typically Loopback100); only applicable for NX fabric",
        ge=0,
        le=1023,
        default=100,
    )
    border_gateway_routing_tag: int = Field(
        alias="borderGatewayRoutingTag",
        description="Routing tag associated with IP address of loopback and DCI interfaces; only applicable for NX fabric (0-4294967295)",
        ge=0,
        le=4294967295,
        default=54321,
    )

    # Multi-Site IP Ranges
    multisite_loopback_ip_range: str = Field(
        alias="multisiteLoopbackIpRange",
        description="Typically Loopback100 IP Address Range",
        default="10.10.0.0/24",
    )
    multisite_underlay_subnet_range: str = Field(
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

    # Security Groups
    security_group_tag: VxlanAciSecurityGroupTagEnum = Field(
        alias="securityGroupTag",
        description="If set to strict, only security groups enabled child fabrics will be allowed",
        default=VxlanAciSecurityGroupTagEnum.STRICT,
    )
    security_group_tag_prefix: str = Field(
        alias="securityGroupTagPrefix",
        description="Prefix to be used when a new security group is created",
        min_length=1,
        max_length=10,
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
        default=True,
    )
    security_group_status: Optional[str] = Field(
        alias="securityGroupStatus",
        description="Read-only security group status reported by Nexus Dashboard",
        default=None,
    )

    @field_validator("anycast_gateway_mac")
    @classmethod
    def validate_mac(cls, value: str) -> str:
        if not re.match(r"^[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}$", value):
            raise ValueError(f"Invalid MAC address format, expected xxxx.xxxx.xxxx, got: {value}")
        return value.lower()


class FabricGroupVxlanAciModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a VXLAN-to-ACI Fabric Group.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Group Properties
    category: Literal["fabricGroup"] = Field(description="Resource category", default="fabricGroup")
    fabric_name: NdFabricName

    # Core Management Configuration
    management: VxlanAciFabricGroupManagementModel = Field(
        description="VXLAN-to-ACI fabric group management configuration",
        default_factory=VxlanAciFabricGroupManagementModel,
    )

    @model_validator(mode="after")
    def validate_fabric_group_consistency(self) -> "FabricGroupVxlanAciModel":
        if self.management.type != FabricGroupTypeEnum.VXLAN_ACI:
            raise ValueError(f"Management type must be {FabricGroupTypeEnum.VXLAN_ACI}")
        # Propagate fabric name into the management model so payloads carry it.
        self.management.name = self.fabric_name
        return self

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, excluding read-only fields ND populates."""
        d = super().to_diff_dict(**kwargs)
        if "management" in d:
            d["management"].pop("securityGroupStatus", None)
        return d

    @classmethod
    def get_argument_spec(cls) -> Dict:
        """Auto-generate the Ansible argument spec from the pydantic model fields.

        Mirrors ``FabricGroupVxlanModel.get_argument_spec`` so the module exposes
        the full nested management option tree (types, choices, defaults) and the
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
    "FabricGroupVxlanAciModel",
    "VxlanAciFabricGroupManagementModel",
]
