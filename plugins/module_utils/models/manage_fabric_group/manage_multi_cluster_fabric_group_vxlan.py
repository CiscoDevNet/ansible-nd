# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import List, Dict, Optional, ClassVar, Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.types import NdFabricName
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ConfigDict,
    Field,
    model_validator,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.enums import (
    FabricGroupTypeEnum,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric.manage_fabric_base import (
    _build_options_from_model,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_fabric_group.manage_fabric_group_vxlan import (
    VxlanFabricGroupManagementModel,
)

"""
# Pydantic model for OneManage multi-cluster VXLAN Fabric Group (MCFG)

This module provides the Pydantic model for creating, updating, and deleting
OneManage multi-cluster VXLAN Fabric Groups (MCFG) through the Nexus Dashboard (ND)
OneManage API.

The multi-cluster fabric group management settings are identical to the Manage
VXLAN fabric group (both use the ``fabricGroupTypeVxlan`` schema), so the shared
``VxlanFabricGroupManagementModel`` is reused verbatim. Only the top-level
``category`` discriminator differs (``multiClusterFabricGroup`` vs ``fabricGroup``).
"""


class MultiClusterFabricGroupVxlanModel(NDBaseModel):
    """
    # Summary

    Complete model for creating a OneManage multi-cluster VXLAN Fabric Group (MCFG).

    ## Raises

    - `ValueError` - If required fields are missing or invalid
    - `TypeError` - If field types don't match expected types
    """

    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, populate_by_name=True, extra="allow")

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name"]
    identifier_strategy: ClassVar[Optional[Literal["single", "composite", "hierarchical", "singleton"]]] = "single"

    # Basic Fabric Group Properties
    category: Literal["multiClusterFabricGroup"] = Field(description="Resource category", default="multiClusterFabricGroup")
    fabric_name: NdFabricName

    # Core Management Configuration (identical fabricGroupTypeVxlan schema as the Manage fabric group)
    management: VxlanFabricGroupManagementModel = Field(
        description="VXLAN multi-cluster fabric group management configuration", default_factory=VxlanFabricGroupManagementModel
    )

    @model_validator(mode="after")
    def validate_fabric_group_consistency(self) -> "MultiClusterFabricGroupVxlanModel":
        if self.management.type != FabricGroupTypeEnum.VXLAN:
            raise ValueError(f"Management type must be {FabricGroupTypeEnum.VXLAN}")
        # Propagate fabric name into the management model so payloads carry it.
        self.management.name = self.fabric_name
        return self

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
    "MultiClusterFabricGroupVxlanModel",
]
