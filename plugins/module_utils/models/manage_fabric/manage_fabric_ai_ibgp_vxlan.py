# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function, annotations

__metaclass__ = type

from typing import ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ibgp_vxlan import (
    FabricIbgpModel,
    VxlanIbgpManagementModel,
)

"""
# Pydantic models for AI iBGP VXLAN fabric management via Nexus Dashboard

This module provides Pydantic models for creating, updating, and deleting
AI iBGP VXLAN fabrics through the Nexus Dashboard (ND) API.

The AI iBGP VXLAN fabric type (aimlVxlanIbgp) is structurally identical to
the standard iBGP VXLAN fabric type (vxlanIbgp) — they share the same
management properties. The only difference is the type discriminator value.

## Models

- `AimlVxlanIbgpManagementModel` - AI iBGP VXLAN specific management settings
- `FabricAiIbgpVxlanModel` - Complete AI iBGP VXLAN fabric creation model
"""


class AimlVxlanIbgpManagementModel(VxlanIbgpManagementModel):
    """
    # Summary

    AI iBGP VXLAN fabric management configuration.

    Inherits all properties from VxlanIbgpManagementModel and overrides
    the type discriminator to `aimlVxlanIbgp`.

    ## Raises

    - `ValueError` - If BGP ASN, VLAN ranges, or IP ranges are invalid
    - `TypeError` - If required string fields are not provided
    """

    _argspec_exclude_fields: ClassVar[set[str]] = {"name", "aiml_qos"}

    type: Literal["aimlVxlanIbgp"] = Field(description="Type of the fabric", default="aimlVxlanIbgp")
    aiml_qos: Literal[True] = Field(
        alias="aimlQos",
        description="Always enabled for AI iBGP VXLAN fabrics.",
        default=True,
        frozen=True,
    )


class FabricAiIbgpVxlanModel(FabricIbgpModel):
    """
    # Summary

    Complete model for creating a new AI iBGP VXLAN fabric.

    This model combines all necessary components for AI iBGP VXLAN fabric creation
    including basic fabric properties, management settings, telemetry, and streaming
    configuration.

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    _fabric_type: ClassVar[FabricTypeEnum] = FabricTypeEnum.AIML_VXLAN_IBGP

    # Core Management Configuration
    management: AimlVxlanIbgpManagementModel | None = Field(description="AI iBGP VXLAN management configuration", default=None)
