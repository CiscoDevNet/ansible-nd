# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function, annotations

__metaclass__ = type

import re
from typing import Any, Dict, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import Field, field_validator
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.enums import FabricTypeEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_ebgp_vxlan import (
    FabricEbgpModel,
    VxlanEbgpManagementModel,
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

    type: Literal["aimlVxlanEbgp"] = Field(description="Type of the fabric", default="aimlVxlanEbgp")
    aiml_qos: bool = Field(
        alias="aimlQos",
        description="Always enabled for AI eBGP VXLAN fabrics.",
        default=True,
    )


class FabricAiEbgpVxlanModel(FabricEbgpModel):
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

    _fabric_type: ClassVar[FabricTypeEnum] = FabricTypeEnum.AIML_VXLAN_EBGP

    # Core Management Configuration
    management: Optional[AimlVxlanEbgpManagementModel] = Field(description="AI eBGP VXLAN management configuration", default=None)

    @classmethod
    def get_argument_spec(cls) -> Dict:
        spec = super().get_argument_spec()

        def remove_option(node: Dict, key: str) -> None:
            if not isinstance(node, dict):
                return
            options = node.get("options")
            if isinstance(options, dict):
                options.pop(key, None)
                for child in options.values():
                    if isinstance(child, dict):
                        remove_option(child, key)
            elements = node.get("elements")
            if isinstance(elements, dict):
                remove_option(elements, key)

        remove_option(spec, "aiml_qos")
        return spec

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

    def to_diff_dict(self, **kwargs) -> Dict[str, Any]:
        """Export for diff comparison, excluding fields that ND overrides for eBGP fabrics."""
        d = super().to_diff_dict(**kwargs)
        # ND always returns nxapiHttp=True for eBGP fabrics regardless of the configured value,
        # so exclude it from diff comparison to prevent a persistent false-positive diff.
        if "management" in d:
            d["management"].pop("nxapiHttp", None)
        return d


__all__ = [
    "AimlVxlanEbgpManagementModel",
    "FabricAiEbgpVxlanModel",
]
