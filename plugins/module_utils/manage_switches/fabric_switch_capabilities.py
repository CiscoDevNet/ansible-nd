# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fabric switch capability validation for nd_manage_switches."""

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
    default_preserve_config: bool
    roles_by_platform: dict[PlatformType, frozenset[SwitchRole]] | None = None


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

CAMPUS_VXLAN_IOS_XE_ROLES = frozenset({SwitchRole.LEAF, SwitchRole.SPINE})

CAMPUS_VXLAN_NX_OS_ROLES = frozenset(
    {
        SwitchRole.BORDER_GATEWAY,
        SwitchRole.BORDER_GATEWAY_SPINE,
        SwitchRole.BORDER_GATEWAY_SUPER_SPINE,
    }
)

CAMPUS_VXLAN_ROLES = CAMPUS_VXLAN_IOS_XE_ROLES | CAMPUS_VXLAN_NX_OS_ROLES

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

FABRIC_SWITCH_CAPABILITY_MATRIX = (
    FabricSwitchCapability(
        family="Routed",
        fabric_types=frozenset({"routed"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=ROUTED_ROLES,
        preserve_config_values=frozenset({False}),
        default_preserve_config=False,
    ),
    FabricSwitchCapability(
        family="External",
        fabric_types=frozenset({"external", "externalconnectivity"}),
        platform_types=frozenset({PlatformType.NX_OS, PlatformType.IOS_XE, PlatformType.IOS_XR, PlatformType.OTHER}),
        roles=BROAD_FABRIC_ROLES,
        preserve_config_values=frozenset({True}),
        default_preserve_config=True,
    ),
    FabricSwitchCapability(
        family="Data Center VXLAN iBGP",
        fabric_types=frozenset({"vxlanibgp"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=BROAD_FABRIC_ROLES,
        preserve_config_values=frozenset({False, True}),
        default_preserve_config=True,
    ),
    FabricSwitchCapability(
        family="Data Center VXLAN eBGP",
        fabric_types=frozenset({"vxlanebgp"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=BROAD_FABRIC_ROLES,
        preserve_config_values=frozenset({False}),
        default_preserve_config=False,
    ),
    FabricSwitchCapability(
        family="Campus VXLAN",
        fabric_types=frozenset({"vxlancampus"}),
        platform_types=frozenset({PlatformType.NX_OS, PlatformType.IOS_XE}),
        roles=CAMPUS_VXLAN_ROLES,
        preserve_config_values=frozenset({False}),
        default_preserve_config=False,
        roles_by_platform={
            PlatformType.IOS_XE: CAMPUS_VXLAN_IOS_XE_ROLES,
            PlatformType.NX_OS: CAMPUS_VXLAN_NX_OS_ROLES,
        },
    ),
    FabricSwitchCapability(
        family="Enhanced Classic LAN",
        fabric_types=frozenset({"classiclanenhanced", "enhancedclassiclan"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=ENHANCED_CLASSIC_LAN_ROLES,
        preserve_config_values=frozenset({False, True}),
        default_preserve_config=True,
    ),
    FabricSwitchCapability(
        family="AI VXLAN iBGP",
        fabric_types=frozenset({"aimlvxlanibgp"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=AI_VXLAN_ROLES,
        preserve_config_values=frozenset({False, True}),
        default_preserve_config=True,
    ),
    FabricSwitchCapability(
        family="AI VXLAN eBGP",
        fabric_types=frozenset({"aimlvxlanebgp"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=AI_VXLAN_ROLES,
        preserve_config_values=frozenset({False}),
        default_preserve_config=False,
    ),
    FabricSwitchCapability(
        family="AI Routed",
        fabric_types=frozenset({"aimlrouted"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=ROUTED_ROLES,
        preserve_config_values=frozenset({False}),
        default_preserve_config=False,
    ),
    FabricSwitchCapability(
        family="IPFM",
        fabric_types=frozenset({"ipfm", "ipfmenhanced"}),
        platform_types=frozenset({PlatformType.NX_OS}),
        roles=IPFM_ROLES,
        preserve_config_values=frozenset({False}),
        default_preserve_config=False,
    ),
)

CAPABILITY_BY_FABRIC_TYPE = {fabric_type.lower(): capability for capability in FABRIC_SWITCH_CAPABILITY_MATRIX for fabric_type in capability.fabric_types}

# This set is the exposure gate for nd_manage_switches switch onboarding.
# The matrix above may know about future fabric families, but they must not
# become module-supported just because their constraints are recorded. Add a
# fabric type here only when that family is intentionally documented, tested,
# and supported end-to-end.
SUPPORTED_SWITCH_ONBOARDING_FABRIC_TYPES = frozenset(
    {
        "vxlanibgp",
        "vxlanebgp",
        "vxlancampus",
        "external",
        "externalconnectivity",
    }
)


def _enum_values(values: frozenset[PlatformType] | frozenset[SwitchRole]) -> str:
    """Return a stable comma-separated list of enum values."""
    return ", ".join(sorted(value.value for value in values))


def _bool_values(values: frozenset[bool]) -> str:
    """Return a stable comma-separated list of bool values."""
    return ", ".join(str(value).lower() for value in sorted(values))


def _enum_value(value: Any) -> str:
    """Return a stable display value for enum or string inputs."""
    return value.value if hasattr(value, "value") else str(value)


def _supported_roles_for_platform(capability: FabricSwitchCapability, platform_type: PlatformType) -> frozenset[SwitchRole]:
    """Return supported roles for the supplied platform within a fabric family."""
    if capability.roles_by_platform is None:
        return capability.roles
    return capability.roles_by_platform.get(platform_type, capability.roles)


def _resolve_preserve_config(capability: FabricSwitchCapability, preserve_config: bool | None) -> bool:
    """Return explicit preserve_config or the fabric-derived default."""
    return capability.default_preserve_config if preserve_config is None else preserve_config


def _resolve_platform_type(platform_type: PlatformType | None) -> PlatformType:
    """Return explicit platform_type or the add-operation default."""
    return PlatformType.NX_OS if platform_type is None else platform_type


def _normalize_fabric_type(value: str) -> str:
    """Normalize fabric type aliases for lookup."""
    return value.replace("-", "").replace("_", "").replace(" ", "").lower()


def capability_for_fabric_type(fabric_type: str) -> FabricSwitchCapability:
    """
    # Summary

    Return the switch capability matrix entry for a fabric type.

    ## Raises

    - `SwitchFabricCapabilityError`: Raised when the fabric type is not represented
        in the switch support matrix.
    """
    normalized = _normalize_fabric_type(fabric_type)
    capability = CAPABILITY_BY_FABRIC_TYPE.get(normalized)
    supported_capabilities = [item for item in FABRIC_SWITCH_CAPABILITY_MATRIX if item.fabric_types & SUPPORTED_SWITCH_ONBOARDING_FABRIC_TYPES]
    if normalized not in SUPPORTED_SWITCH_ONBOARDING_FABRIC_TYPES:
        supported = ", ".join(sorted(capability.family for capability in supported_capabilities))
        raise SwitchFabricCapabilityError(
            f"nd_manage_switches currently supports switch onboarding only for these fabric families: {supported}. "
            f"Fabric type '{fabric_type}' is not supported."
        )
    if capability is None:
        supported_types = ", ".join(sorted(SUPPORTED_SWITCH_ONBOARDING_FABRIC_TYPES))
        raise SwitchFabricCapabilityError(
            f"Switch capability validation does not have a matrix entry for supported fabric type '{fabric_type}'. "
            f"Supported fabric type values: {supported_types}."
        )
    return capability


def validate_switch_configs_for_fabric_type(
    fabric_name: str,
    fabric_type: str,
    configs: list[SwitchConfigModel],
) -> FabricSwitchCapability:
    """
    # Summary

    Validate switch configs against the support matrix for a canonical fabric
    type.

    ## Raises

    - `SwitchFabricCapabilityError`: Raised when the fabric type is unsupported, or
        when any provided platform, role, or preserve_config value is invalid
        for the target fabric family.
    """
    capability = capability_for_fabric_type(fabric_type)
    errors: list[str] = []
    for cfg in configs:
        prefix = f"{cfg.seed_ip}"
        cfg.platform_type = _resolve_platform_type(cfg.platform_type)
        platform_type = cfg.platform_type
        role = SwitchRole.normalize(cfg.role) if cfg.role else None
        if platform_type not in capability.platform_types:
            errors.append(
                f"{prefix}: platform_type '{_enum_value(cfg.platform_type)}' is not supported for {capability.family} fabric "
                f"'{fabric_name}' (type '{fabric_type}'). Supported platform_type values: {_enum_values(capability.platform_types)}."
            )
        supported_roles = _supported_roles_for_platform(capability, platform_type)
        if role is not None and role not in supported_roles:
            role_display = _enum_value(cfg.role) if cfg.role else "<unspecified>"
            errors.append(
                f"{prefix}: role '{role_display}' is not supported for platform_type '{_enum_value(cfg.platform_type)}' in "
                f"{capability.family} fabric '{fabric_name}' (type '{fabric_type}'). Supported role values: {_enum_values(supported_roles)}."
            )
        cfg.preserve_config = _resolve_preserve_config(capability, cfg.preserve_config)
        if cfg.preserve_config not in capability.preserve_config_values:
            errors.append(
                f"{prefix}: preserve_config '{str(cfg.preserve_config).lower()}' is not supported for {capability.family} fabric "
                f"'{fabric_name}' (type '{fabric_type}'). Supported preserve_config values: {_bool_values(capability.preserve_config_values)}."
            )

    if errors:
        detail = "\n- ".join(errors)
        raise SwitchFabricCapabilityError(f"Switch capability validation failed for fabric '{fabric_name}':\n- {detail}")
    return capability
