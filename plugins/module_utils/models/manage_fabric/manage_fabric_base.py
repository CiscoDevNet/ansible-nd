# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Abstract base class for all fabric models.

Provides the shared field definitions, validators, ClassVars, and argument spec
that are identical across eBGP, iBGP, External Connectivity, and Campus fabrics.
Subclasses only need to define:

- `_fabric_type` — the `FabricTypeEnum` value for this fabric kind
- `management` field — typed to the specific management model

Optionally override `_post_validate_consistency()` for type-specific logic
(e.g. site_id propagation from BGP ASN).
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import Dict, List, Optional, ClassVar, Literal

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
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    ExternalStreamingSettingsModel,
    LocationModel,
    TelemetrySettingsModel,
)


class FabricBaseModel(NDBaseModel):
    """
    # Summary

    Abstract base for all fabric models (eBGP, iBGP, External, Campus, etc.).

    Subclasses **must** define:
    - ``_fabric_type: ClassVar[FabricTypeEnum]`` — discriminator value
    - ``management`` field typed to the concrete management model

    Subclasses **may** override:
    - ``_post_validate_consistency()`` — for extra post-validation logic
    - ``to_diff_dict()`` — for custom diff exclusions

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # ── ClassVars (shared across all fabric models) ──
    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Subclass must set this to the appropriate FabricTypeEnum member
    _fabric_type: ClassVar[FabricTypeEnum]

    # ── Basic Fabric Properties ──
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    fabric_name: str = Field(alias="name", description="Fabric name", min_length=1, max_length=64)
    location: Optional[LocationModel] = Field(description="Geographic location of the fabric", default=None)

    # ── License, Telemetry, and Operations ──
    license_tier: LicenseTierEnum = Field(alias="licenseTier", description="License Tier for ffabric.", default=LicenseTierEnum.ESSENTIALS)
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

    # ── Optional Advanced Settings ──
    # NOTE: `management` is intentionally NOT defined here — subclasses define it
    # with their specific management model type.
    telemetry_settings: Optional[TelemetrySettingsModel] = Field(alias="telemetrySettings", description="Telemetry configuration", default=None)
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings", description="External streaming settings", default_factory=ExternalStreamingSettingsModel
    )

    # ── Validators ──

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
    def validate_fabric_consistency(self):
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        Checks the management type matches ``_fabric_type``, propagates fabric_name
        into the management model, auto-creates telemetry settings, then delegates
        to ``_post_validate_consistency()`` for subclass-specific logic.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        if self.management is not None and self.management.type != self._fabric_type:
            raise ValueError(f"Management type must be {self._fabric_type}")

        # Propagate fabric name to management model
        if self.management is not None:
            self.management.name = self.fabric_name

        # Auto-create default telemetry settings if collection is enabled
        if self.telemetry_collection and self.telemetry_settings is None:
            self.telemetry_settings = TelemetrySettingsModel()

        # Subclass hook for additional validation
        self._post_validate_consistency()

        return self

    def _post_validate_consistency(self) -> None:
        """Hook for subclass-specific post-validation logic. Default is a no-op."""
        pass

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
