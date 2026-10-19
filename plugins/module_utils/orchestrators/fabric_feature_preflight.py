# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Fabric-setting prerequisites for actionable VRF and Network writes."""

from __future__ import annotations

from typing import Any, Callable

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import VlanNetworkType


_DC_VXLAN_TYPES = frozenset({"vxlanIbgp", "vxlanEbgp"})
_CAMPUS_TYPE = "vxlanCampus"
_PVLAN_TYPES = frozenset(
    {
        VlanNetworkType.PRIVATE_PRIMARY.value,
        VlanNetworkType.PRIVATE_SECONDARY_COMMUNITY.value,
        VlanNetworkType.PRIVATE_SECONDARY_ISOLATED.value,
        "primary",
        "community",
        "isolated",
    }
)


def validate_fabric_features(details: dict[str, Any], config: dict[str, Any], resource: str, index: int, fabric_name: str) -> None:
    """
    # Summary

    Validate proven fabric prerequisites for one actionable resource write.

    ## Raises

    ### ValueError

    - If a requested PVLAN, IPv4 TRM, or NetFlow feature cannot be used on the fabric.
    """
    management = details.get("management") if isinstance(details, dict) else None
    if not isinstance(management, dict):
        raise ValueError(f"Cannot validate {resource} features for fabric '{fabric_name}': full fabric management details are unavailable.")

    fabric_type = management.get("type") or details.get("type")
    prefix = f"config[{index}] on fabric '{fabric_name}'"
    vlan_type = config.get("vlan_network_type")
    if resource == "Network" and vlan_type in _PVLAN_TYPES:
        if fabric_type not in _DC_VXLAN_TYPES:
            raise ValueError(f"{prefix}: vlan_network_type '{vlan_type}' is supported only on Data Center VXLAN fabrics.")
        if "privateVlan" not in management:
            raise ValueError(f"{prefix}: cannot verify private VLAN support because the fabric setting is absent.")
        if management.get("privateVlan") is not True:
            raise ValueError(f"{prefix}: vlan_network_type '{vlan_type}' requires private VLAN to be enabled in fabric settings.")

    if fabric_type in _DC_VXLAN_TYPES | {_CAMPUS_TYPE}:
        if config.get("trm_enable") is True:
            if "tenantRoutedMulticast" not in management:
                raise ValueError(f"{prefix}: cannot verify IPv4 TRM support because the fabric setting is absent.")
            if management["tenantRoutedMulticast"] is not True:
                raise ValueError(f"{prefix}: trm_enable=true requires IPv4 Tenant Routed Multicast to be enabled in fabric settings.")
        netflow = management.get("netflowSettings")
        if config.get("netflow_enable") is True:
            if not isinstance(netflow, dict) or "netflow" not in netflow:
                raise ValueError(f"{prefix}: cannot verify NetFlow support because the fabric setting is absent.")
            if netflow["netflow"] is not True:
                raise ValueError(f"{prefix}: netflow_enable=true requires NetFlow to be enabled in fabric settings.")


def preflight_feature_changes(
    sm: Any,
    state: str,
    get_details: Callable[[], dict[str, Any]],
    resource: str,
    fabric_name: str,
    *,
    attachment_names: set[str] | None = None,
) -> None:
    """
    # Summary

    Check changed definitions against fabric settings using the state machine's inventory snapshot.

    ## Raises

    ### ValueError

    - If an actionable definition or attachment requests a feature unavailable on its fabric.
    """
    if state in ("gathered", "deleted"):
        return
    for index, proposed in enumerate(sm.proposed):
        name = getattr(proposed, "network_name", None) if resource == "Network" else getattr(proposed, "vrf_name", None)
        if sm.existing.get_diff_config(proposed, exclude_unset=state == "merged") == "no_diff" and name not in (attachment_names or ()):
            continue
        current = sm.existing.get(proposed.get_identifier_value())
        effective = current.model_copy(deep=True).merge(proposed) if current is not None and state == "merged" else proposed
        config = effective.to_gathered_config()
        if (
            (resource == "Network" and config.get("vlan_network_type") in _PVLAN_TYPES)
            or config.get("trm_enable") is True
            or config.get("netflow_enable") is True
        ):
            validate_fabric_features(get_details(), config, resource, index, fabric_name)


def preflight_workflow_features(
    coordinator: Any,
    sm: Any,
    module_args: dict[str, Any],
    strategy: Any,
    resource: str,
    *,
    current_attachments: dict | None = None,
    desired_attachments: dict | None = None,
) -> None:
    """
    # Summary

    Validate actionable resource and attachment writes on the effective fabric.

    ## Raises

    ### ValueError

    - If a requested feature is unavailable on the owning fabric.
    """
    target_key = "networkName" if resource == "Network" else "vrfName"
    attach_names = {payload[target_key] for payload in coordinator.attachments.planned_attach_payloads(current_attachments or {}, desired_attachments or {})}
    resolver = getattr(coordinator, "_fabric_resolver", None)
    state = module_args.get("state", "merged")

    def details_for(name: str, fabric_data: dict[str, Any]) -> dict[str, Any]:
        cached = fabric_data.get("manageFabricDetails")
        if cached:
            return cached
        return resolver.get_fabric_details(name, fabric_data.get("clusterName")) if resolver else {}

    if strategy.is_parent and strategy.child_fabric_members():
        members = {item["fabricName"]: item for item in strategy.fabric_data.get("members", []) if item.get("fabricName")}
        for child_name in strategy.child_fabric_members():
            child_data = members.get(child_name, {})
            preflight_feature_changes(
                sm,
                state,
                lambda name=child_name, data=child_data: details_for(name, data),
                resource,
                child_name,
                attachment_names=attach_names,
            )
    else:
        preflight_feature_changes(
            sm, state, lambda: details_for(strategy.fabric_name, strategy.fabric_data), resource, strategy.fabric_name, attachment_names=attach_names
        )


def preflight_child_feature_tasks(
    child_tasks: dict[str, dict],
    state: str,
    new_state_machine: Callable[[dict, Any], tuple[Any, Any, Any]],
    preflight: Callable[[Any, dict, Any], None],
    restore_params: Callable[[Any, Any], None],
) -> None:
    """
    # Summary

    Check child writes before parent mutation and retain their inventory snapshot for reuse.

    ## Raises

    ### ValueError

    - If a child feature requires a disabled fabric setting.
    """
    if state in ("gathered", "deleted"):
        return
    for child_task in child_tasks.values():
        child_args = child_task["module_args"]
        child_strategy = child_task["strategy"]
        sm, original_config, original_state = new_state_machine(child_args, child_strategy)
        try:
            preflight(sm, child_args, child_strategy)
            child_task["preflight_state_machine"] = sm
        finally:
            restore_params(original_config, original_state)
