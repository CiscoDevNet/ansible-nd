# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_routed import (
    FabricRoutedModel,
    RoutedManagementModel,
)

"""
# Pydantic models for AI Routed fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
AI Routed fabrics through the Nexus Dashboard (ND) API.

The AI Routed fabric type (aimlRouted) shares the standard Routed management
contract and adds fixed AI QoS and NX-API HTTP invariants alongside its type
discriminator.

## Models

- `AimlRoutedManagementModel` - AI Routed specific management settings
- `FabricAiRoutedModel` - Complete AI Routed fabric creation model
"""


class AimlRoutedManagementModel(RoutedManagementModel):
    """
    # Summary

    AI Routed fabric management configuration.

    Inherits all properties from RoutedManagementModel, changes the type
    discriminator to `aimlRouted`, and fixes AI QoS and NX-API HTTP on.

    ## Raises

    - `ValueError` - If BGP ASN, VLAN ranges, or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    _argspec_exclude_fields: ClassVar[set[str]] = {"name", "aiml_qos"}

    type: Literal["aimlRouted"] = Field(description="Type of the fabric", default="aimlRouted")
    aiml_qos: Literal[True] = Field(
        alias="aimlQos",
        description="Always enabled for AI Routed fabrics.",
        default=True,
        frozen=True,
    )
    nxapi_http: Literal[True] = Field(
        alias="nxapiHttp",
        description="NX-API over HTTP is always enabled for AI Routed fabrics.",
        default=True,
        frozen=True,
    )


class FabricAiRoutedModel(FabricRoutedModel):
    """
    # Summary

    Complete model for creating a new AI Routed fabric.

    This model combines all necessary components for AI Routed fabric creation
    including basic fabric properties, management settings, telemetry, and streaming
    configuration.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    _fabric_type: ClassVar[FabricTypeEnum] = FabricTypeEnum.AIML_ROUTED

    # Core Management Configuration
    management: AimlRoutedManagementModel | None = Field(description="AI Routed management configuration", default=None)
