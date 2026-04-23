# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import Any, List, Dict, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    AlertSuspendEnum,
    FabricTypeEnum,
    LicenseTierEnum,
    TelemetryCollectionTypeEnum,
    TelemetryStreamingProtocolEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp import (
    VxlanEbgpManagementModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    ExternalStreamingSettingsModel,
    LocationModel,
    TelemetrySettingsModel,
)

"""
# Pydantic models for AI eBGP VXLAN fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
AI eBGP VXLAN fabrics through the Nexus Dashboard (ND) API.

The AI eBGP VXLAN fabric type (aimlVxlanEbgp) is structurally identical to
the standard eBGP VXLAN fabric type (vxlanEbgp) — they share the same
management properties. The only difference is the type discriminator value.

## Models

- `AimlVxlanEbgpManagementModel` - AI eBGP VXLAN specific management settings
- `FabricAiEbgpVxlanModel` - Complete AI eBGP VXLAN fabric creation model
"""


class AimlVxlanEbgpManagementModel(VxlanEbgpManagementModel):
    """
    # Summary

    AI eBGP VXLAN fabric management configuration.

    Inherits all properties from VxlanEbgpManagementModel and overrides
    the type discriminator to `aimlVxlanEbgp`.

    ## Raises

    - `ValueError` - If BGP ASN, VLAN ranges, or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    type: Literal[FabricTypeEnum.AIML_VXLAN_EBGP] = Field(description="Type of the fabric", default=FabricTypeEnum.AIML_VXLAN_EBGP)


class FabricAiEbgpVxlanModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a new AI eBGP VXLAN fabric.

    This model combines all necessary components for AI eBGP VXLAN fabric creation
    including basic fabric properties, management settings, telemetry, and streaming
    configuration.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Properties
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    fabric_name: str = Field(alias="name", description="Fabric name", min_length=1, max_length=64)
    location: Optional[LocationModel] = Field(description="Geographic location of the fabric", default=None)

    # License, Telemetry, and Operations
    license_tier: LicenseTierEnum = Field(alias="licenseTier", description="License Tier for fabric.", default=LicenseTierEnum.ESSENTIALS)
    alert_suspend: AlertSuspendEnum = Field(
        alias="alertSuspend", description="Alert Suspend state configured on the fabric.", default=AlertSuspendEnum.DISABLED
    )
    telemetry_collection: bool = Field(alias="telemetryCollection", description="Enable telemetry collection.", default=True)
    telemetry_collection_type: TelemetryCollectionTypeEnum = Field(
        alias="telemetryCollectionType", description="Telemetry collection method.", default=TelemetryCollectionTypeEnum.IN_BAND
    )
    telemetry_streaming_protocol: TelemetryStreamingProtocolEnum = Field(
        alias="telemetryStreamingProtocol", description="Telemetry Streaming Protocol.", default=TelemetryStreamingProtocolEnum.IPV4
    )
    telemetry_source_interface: str = Field(
        alias="telemetrySourceInterface",
        description="Telemetry Source Interface Loopback ID, only valid if Telemetry Collection is set to inBand.",
        default="loopback0",
    )
    telemetry_source_vrf: str = Field(
        alias="telemetrySourceVrf", description="VRF over which telemetry is streamed, valid only if Telemetry Collection is set to inBand.", default="default"
    )
    security_domain: str = Field(alias="securityDomain", description="Security Domain associated with the fabric.", default="all")

    # Core Management Configuration
    management: Optional[AimlVxlanEbgpManagementModel] = Field(description="AI eBGP VXLAN management configuration", default=None)

    # Optional Advanced Settings
    telemetry_settings: Optional[TelemetrySettingsModel] = Field(alias="telemetrySettings", description="Telemetry configuration", default=None)
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings", description="External streaming settings", default_factory=ExternalStreamingSettingsModel
    )

    @field_validator("fabric_name")
    @classmethod
    def validate_fabric_name(cls, value: str) -> str:
        """
        # Summary

        Validate fabric name format and characters.

        ## Raises

        - `ValueError` - If name contains invalid characters or format
        """
        if not re.match(r"^[a-zA-Z0-9_-]+$", value):
            raise ValueError(f"Fabric name can only contain letters, numbers, underscores, and hyphens, got: {value}")
        return value

    @model_validator(mode="after")
    def validate_fabric_consistency(self) -> "FabricAiEbgpVxlanModel":
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        # Ensure management type matches model type
        if self.management is not None and self.management.type != FabricTypeEnum.AIML_VXLAN_EBGP:
            raise ValueError(f"Management type must be {FabricTypeEnum.AIML_VXLAN_EBGP}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.fabric_name

        # Propagate BGP ASN to site_id if both are set and site_id is empty
        if self.management is not None and self.management.site_id == "" and self.management.bgp_asn is not None:
            bgp_asn = self.management.bgp_asn
            if "." in bgp_asn:
                high, low = bgp_asn.split(".")
                self.management.site_id = str(int(high) * 65536 + int(low))
            else:
                self.management.site_id = bgp_asn

        # Auto-create default telemetry settings if collection is enabled
        if self.telemetry_collection and self.telemetry_settings is None:
            self.telemetry_settings = TelemetrySettingsModel()

        return self

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, excluding fields that ND overrides for eBGP fabrics."""
        d = super().to_diff_dict(**kwargs)
        # ND always returns nxapiHttp=True for eBGP fabrics regardless of the configured value,
        # so exclude it from diff comparison to prevent a persistent false-positive diff.
        if "management" in d:
            d["management"].pop("nxapiHttp", None)
        return d

    @classmethod
    def get_argument_spec(cls) -> Dict:
        return dict(
            state={
                "type": "str",
                "default": "merged",
                "choices": ["merged", "replaced", "deleted", "overridden"],
            },
            config={"required": False, "type": "list", "elements": "dict"},
        )


__all__ = [
    "AimlVxlanEbgpManagementModel",
    "FabricAiEbgpVxlanModel",
]
