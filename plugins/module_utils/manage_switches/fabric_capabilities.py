# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fabric capability validation for nd_manage_switches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.config_models import SwitchConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_switches.enums import SwitchRole


class SwitchFabricCapabilityError(ValueError):
    """Raised when a switch config is unsupported by the target fabric type."""


@dataclass(frozen=True)
class FabricSwitchCapability:
    """Supported switch capabilities for one fabric family."""

    family: str
    fabric_types: frozenset[str]
    platform_types: frozenset[PlatformType]
    roles: frozenset[SwitchRole]
    preserve_config_values: frozenset[bool]


ROUTED_ROLES = frozenset(
    {
        SwitchRole.LEAF,
        SwitchRole.SPINE,
        SwitchRole.BORDER,
        SwitchRole.SUPER_SPINE,
        SwitchRole.BORDER_SUPER_SPINE,
    }
)

BROAD_FABRIC_ROLES = frozenset(
    {
        SwitchRole.LEAF,
        SwitchRole.SPINE,
        SwitchRole.BORDER,
        SwitchRole.BORDER_SPINE,
        SwitchRole.BORDER_GATEWAY,
        SwitchRole.BORDER_GATEWAY_SPINE,
        SwitchRole.SUPER_SPINE,
        SwitchRole.BORDER_SUPER_SPINE,
        SwitchRole.BORDER_GATEWAY_SUPER_SPINE,
        SwitchRole.ACCESS,
        SwitchRole.AGGREGATION,
        SwitchRole.EDGE_ROUTER,
        SwitchRole.CORE_ROUTER,
        SwitchRole.TOR,
    }
)

CAMPUS_VXLAN_ROLES = frozenset(
    {
        SwitchRole.BORDER_GATEWAY,
        SwitchRole.BORDER_GATEWAY_SPINE,
        SwitchRole.BORDER_GATEWAY_SUPER_SPINE,
    }
)

ENHANCED_CLASSIC_LAN_ROLES = frozenset({SwitchRole.ACCESS, SwitchRole.AGGREGATION})

AI_VXLAN_ROLES = frozenset(
    {
        SwitchRole.LEAF,
        SwitchRole.SPINE,
        SwitchRole.BORDER,
        SwitchRole.BORDER_GATEWAY,
        SwitchRole.BORDER_GATEWAY_SPINE,
        SwitchRole.SUPER_SPINE,
        SwitchRole.BORDER_SUPER_SPINE,
        SwitchRole.BORDER_GATEWAY_SUPER_SPINE,
        SwitchRole.TOR,
    }
)

IPFM_ROLES = frozenset({SwitchRole.LEAF, SwitchRole.SPINE, SwitchRole.TIER2_LEAF})

CAPABILITIES = (
    FabricSwitchCapability(
        family="Routed",
        fabric_types=frozenset({"routed"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=ROUTED_ROLES,
        preserve_config_values=frozenset({False}),
    ),
    FabricSwitchCapability(
        family="External",
        fabric_types=frozenset({"external", "externalconnectivity"}),
        platform_types=frozenset({PlatformType.NX_OS, PlatformType.IOS_XE, PlatformType.IOS_XR, PlatformType.OTHER}),
        roles=BROAD_FABRIC_ROLES,
        preserve_config_values=frozenset({True}),
    ),
    FabricSwitchCapability(
        family="DataCenter VXLAN",
        fabric_types=frozenset({"vxlan", "vxlanibgp", "vxlanebgp"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=BROAD_FABRIC_ROLES,
        preserve_config_values=frozenset({False, True}),
    ),
    FabricSwitchCapability(
        family="Campus VXLAN",
        fabric_types=frozenset({"vxlancampus"}),
        platform_types=frozenset({PlatformType.NX_OS, PlatformType.IOS_XE}),
        roles=CAMPUS_VXLAN_ROLES,
        preserve_config_values=frozenset({False}),
    ),
    FabricSwitchCapability(
        family="Enhanced Classic LAN",
        fabric_types=frozenset({"classiclanenhanced", "enhancedclassiclan"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=ENHANCED_CLASSIC_LAN_ROLES,
        preserve_config_values=frozenset({False, True}),
    ),
    FabricSwitchCapability(
        family="AI VXLAN",
        fabric_types=frozenset({"aimlvxlan", "aimlvxlanibgp", "aimlvxlanebgp"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=AI_VXLAN_ROLES,
        preserve_config_values=frozenset({False}),
    ),
    FabricSwitchCapability(
        family="AI Routed",
        fabric_types=frozenset({"aimlrouted"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=ROUTED_ROLES,
        preserve_config_values=frozenset({False}),
    ),
    FabricSwitchCapability(
        family="IPFM",
        fabric_types=frozenset({"ipfm", "ipfmenhanced"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=IPFM_ROLES,
        preserve_config_values=frozenset({False}),
    ),
)

CAPABILITY_BY_FABRIC_TYPE = {fabric_type.lower(): capability for capability in CAPABILITIES for fabric_type in capability.fabric_types}


def _enum_values(values: frozenset[PlatformType] | frozenset[SwitchRole]) -> str:
    """Return a stable comma-separated list of enum values."""
    return ", ".join(sorted(value.value for value in values))


def _bool_values(values: frozenset[bool]) -> str:
    """Return a stable comma-separated list of bool values."""
    return ", ".join(str(value).lower() for value in sorted(values))


def _enum_value(value: Any) -> str:
    """Return a stable display value for enum or string inputs."""
    return value.value if hasattr(value, "value") else str(value)


def _normalize_fabric_type(value: str) -> str:
    """Normalize fabric type aliases for lookup."""
    return value.replace("-", "").replace("_", "").replace(" ", "").lower()


def _first_string_value(source: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the first non-empty string-ish value for keys in source."""
    for key in keys:
        value = source.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def fabric_type_from_details(fabric_details: dict[str, Any]) -> str | None:
    """Extract the controller fabric type from a Manage fabric GET response."""
    if not isinstance(fabric_details, dict):
        return None

    keys = ("type", "fabricType", "fabric_type", "nvPairs.FABRIC_TYPE")
    management = fabric_details.get("management")
    if isinstance(management, dict):
        fabric_type = _first_string_value(management, keys)
        if fabric_type:
            return fabric_type

    fabric_type = _first_string_value(fabric_details, keys)
    if fabric_type:
        return fabric_type

    nv_pairs = fabric_details.get("nvPairs")
    if isinstance(nv_pairs, dict):
        return _first_string_value(nv_pairs, ("FABRIC_TYPE", "fabricType", "type"))
    return None


def capability_for_fabric_type(fabric_type: str) -> FabricSwitchCapability:
    """Return the capability matrix entry for a fabric type."""
    normalized = _normalize_fabric_type(fabric_type)
    capability = CAPABILITY_BY_FABRIC_TYPE.get(normalized)
    if capability is None:
        supported = ", ".join(sorted(capability.family for capability in CAPABILITIES))
        raise SwitchFabricCapabilityError(
            f"Switch capability validation does not support fabric type '{fabric_type}'. Supported fabric families: {supported}."
        )
    return capability


def validate_switch_configs_for_fabric(
    fabric_name: str,
    fabric_details: dict[str, Any],
    configs: list[SwitchConfigModel],
) -> FabricSwitchCapability:
    """Validate switch configs against the target fabric's support matrix."""
    fabric_type = fabric_type_from_details(fabric_details)
    if not fabric_type:
        raise SwitchFabricCapabilityError(f"Unable to determine fabric type for fabric '{fabric_name}' from controller fabric details.")

    return validate_switch_configs_for_fabric_type(fabric_name, fabric_type, configs)


def validate_switch_configs_for_fabric_type(
    fabric_name: str,
    fabric_type: str,
    configs: list[SwitchConfigModel],
) -> FabricSwitchCapability:
    """Validate switch configs against the support matrix for a canonical fabric type."""
    capability = capability_for_fabric_type(fabric_type)
    errors: list[str] = []
    for cfg in configs:
        prefix = f"{cfg.seed_ip}"
        platform_type = cfg.platform_type
        role = SwitchRole.normalize(cfg.role) if cfg.role else None
        if platform_type not in capability.platform_types:
            errors.append(
                f"{prefix}: platform_type '{_enum_value(cfg.platform_type)}' is not supported for {capability.family} fabric "
                f"'{fabric_name}' (type '{fabric_type}'). Supported platform_type values: {_enum_values(capability.platform_types)}."
            )
        if role not in capability.roles:
            role_display = _enum_value(cfg.role) if cfg.role else "<unspecified>"
            errors.append(
                f"{prefix}: role '{role_display}' is not supported for {capability.family} fabric '{fabric_name}' "
                f"(type '{fabric_type}'). Supported role values: {_enum_values(capability.roles)}."
            )
        if cfg.preserve_config not in capability.preserve_config_values:
            errors.append(
                f"{prefix}: preserve_config '{str(cfg.preserve_config).lower()}' is not supported for {capability.family} fabric "
                f"'{fabric_name}' (type '{fabric_type}'). Supported preserve_config values: {_bool_values(capability.preserve_config_values)}."
            )

    if errors:
        detail = "\n- ".join(errors)
        raise SwitchFabricCapabilityError(f"Switch capability validation failed for fabric '{fabric_name}':\n- {detail}")
    return capability
