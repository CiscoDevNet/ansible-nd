# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
from typing import Dict, List, Optional, ClassVar, Literal, Set

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
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_common import (
    LocationModel,
)

"""
# Pydantic models for Data Broker (NDB) fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
Data Broker (Nexus Dashboard Data Broker) fabrics through the Nexus Dashboard (ND) API.

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
    discriminator field, supportes only essential license tier, and an auto ISL deployment option.
    Unlike eBGP/iBGP fabrics, there are no additional fabric-level management parameters.

    ## Raises

    None
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    # Fabric Type (required for discriminated union)
    type: Literal[FabricTypeEnum.DATA_BROKER] = Field(
        description="Fabric management type",
        default=FabricTypeEnum.DATA_BROKER,
    )
    auto_isl_deploy: Optional[bool] = Field(
        alias="autoISLDeploy",
        description="Enable automatic ISL deployment.",
        default=True,
    )


class FabricDataBrokerModel(NDBaseModel):
    """
    # Summary

    Complete model for managing a Nexus Data Broker (NDB) fabric.

    This model combines all necessary components for fabric management including
    basic fabric properties and the minimal dataBroker management settings.

    ## Raises

    - `ValueError` - If fabric name contains invalid characters or management type is not dataBroker
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"
    config_exclude_fields: ClassVar[Set[str]] = {"telemetry_collection"}
    exclude_from_diff: ClassVar[Set[str]] = {"telemetry_collection"}

    # Basic Fabric Properties
    category: Literal["fabric"] = Field(description="Resource category", default="fabric")
    fabric_name: str = Field(alias="name", description="Fabric name", min_length=1, max_length=64)

    # License and Operations
    license_tier: Literal["essentials"] = Field(alias="licenseTier", description="License Tier for fabric.", default="essentials")
    security_domain: str = Field(alias="securityDomain", description="Security Domain associated with the fabric.", default="all")

    # Core Management Configuration (minimal for dataBroker)
    management: DataBrokerManagementModel = Field(
        description="Data Broker management configuration",
        default_factory=DataBrokerManagementModel,
    )

    # Location
    location: Optional[LocationModel] = Field(description="Geographic location of the fabric", default=None)

    # Internal fields — always included in API payload, never exposed to users
    telemetry_collection: bool = Field(alias="telemetryCollection", description="Telemetry collection setting", default=False)

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
