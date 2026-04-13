# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import Dict, List, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import (
    FabricTypeEnum,
    AlertSuspendEnum,
    LicenseTierEnum,
    TelemetryCollectionTypeEnum,
    TelemetryStreamingProtocolEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    LocationModel,
    TelemetrySettingsModel,
    ExternalStreamingSettingsModel,
)

"""
# Pydantic models for Data Broker (NDB) fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
Data Broker (Nexus Dashboard Data Broker) fabrics through the Nexus Dashboard
Fabric Controller (NDFC) API.

## Models Overview

- `DataBrokerManagementModel` - Data Broker specific management settings (minimal — type only)
- `FabricDataBrokerModel` - Complete fabric creation model

## Usage

```python
fabric_data = {
    "name": "MyNdbFabric",
    "management": {
        "type": "dataBroker",
    }
}
fabric = FabricDataBrokerModel(**fabric_data)
```
"""


class DataBrokerManagementModel(NDNestedModel):
    """
    # Summary

    Data Broker fabric management configuration.

    The dataBroker management schema is minimal — it contains only the type
    discriminator field. Unlike eBGP/iBGP fabrics, there are no additional
    fabric-level management parameters.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.DATA_BROKER] = Field(
        description="Fabric management type",
        default=FabricTypeEnum.DATA_BROKER,
    )


class FabricDataBrokerModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a new Data Broker (NDB) fabric.

    This model combines all necessary components for fabric creation including
    basic fabric properties, the minimal dataBroker management settings,
    telemetry, and streaming configuration.

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

    # License and Operations
    license_tier: LicenseTierEnum = Field(
        alias="licenseTier",
        description="License Tier value of a fabric.",
        default=LicenseTierEnum.PREMIER,
    )
    alert_suspend: AlertSuspendEnum = Field(
        alias="alertSuspend",
        description="Alert Suspend state configured on the fabric",
        default=AlertSuspendEnum.DISABLED,
    )
    telemetry_collection: bool = Field(
        alias="telemetryCollection",
        description="Enable telemetry collection",
        default=False,
    )
    telemetry_collection_type: TelemetryCollectionTypeEnum = Field(
        alias="telemetryCollectionType",
        description="Telemetry collection method.",
        default=TelemetryCollectionTypeEnum.OUT_OF_BAND,
    )
    telemetry_streaming_protocol: TelemetryStreamingProtocolEnum = Field(
        alias="telemetryStreamingProtocol",
        description="Telemetry Streaming Protocol.",
        default=TelemetryStreamingProtocolEnum.IPV4,
    )
    telemetry_source_interface: str = Field(
        alias="telemetrySourceInterface",
        description="Telemetry Source Interface (VLAN id or Loopback id) only valid if Telemetry Collection is set to inBand",
        default="",
    )
    telemetry_source_vrf: str = Field(
        alias="telemetrySourceVrf",
        description="VRF over which telemetry is streamed, valid only if telemetry collection is set to inband",
        default="",
    )
    security_domain: str = Field(
        alias="securityDomain",
        description="Security Domain associated with the fabric",
        default="all",
    )

    # Core Management Configuration (minimal for dataBroker)
    management: Optional[DataBrokerManagementModel] = Field(
        description="Data Broker management configuration",
        default=None,
    )

    # Optional Advanced Settings
    telemetry_settings: Optional[TelemetrySettingsModel] = Field(
        alias="telemetrySettings",
        description="Telemetry configuration",
        default=None,
    )
    external_streaming_settings: ExternalStreamingSettingsModel = Field(
        alias="externalStreamingSettings",
        description="External streaming settings",
        default_factory=ExternalStreamingSettingsModel,
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
    def validate_fabric_consistency(self) -> "FabricDataBrokerModel":
        """
        # Summary

        Validate consistency between fabric settings and management configuration.

        ## Raises

        - `ValueError` - If fabric settings are inconsistent
        """
        # Ensure management type matches model type
        if self.management is not None and self.management.type != FabricTypeEnum.DATA_BROKER:
            raise ValueError(f"Management type must be {FabricTypeEnum.DATA_BROKER}")

        # Validate telemetry consistency
        if self.telemetry_collection and self.telemetry_settings is None:
            self.telemetry_settings = TelemetrySettingsModel()

        return self

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
    "DataBrokerManagementModel",
    "FabricDataBrokerModel",
]
