# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared input normalization for interface resource modules and workflows."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def validate_ethernet_interface_names(
    config_list: list[dict[str, Any]],
    *,
    require_interface_names: bool = True,
) -> None:
    """Validate grouped Ethernet names, optionally allowing gathered filters to omit them."""
    for item_index, group in enumerate(config_list):
        if not isinstance(group, dict):
            raise ValueError(f"Ethernet config item {item_index} must be a mapping.")
        switch_ip = group.get("switch_ip")
        if "interface_names" not in group:
            if require_interface_names:
                raise ValueError(f"interface_names is required for Ethernet config item {item_index} on switch '{switch_ip}'.")
            continue
        interface_names = group["interface_names"]
        if not isinstance(interface_names, list):
            raise ValueError(f"interface_names for Ethernet config item {item_index} on switch '{switch_ip}' must be a list.")
        for entry_index, name in enumerate(interface_names):
            if isinstance(name, str) and name.strip():
                continue
            if name is None:
                reason = "null"
            elif not isinstance(name, str):
                reason = f"not a string (got {type(name).__name__})"
            else:
                reason = "empty"
            raise ValueError(
                f"interface_names[{entry_index}] for switch '{switch_ip}' (config item {item_index}) is "
                f"{reason}. Every entry must be a non-empty interface name."
            )


def expand_ethernet_gathered_filters(
    config_list: list[dict[str, Any]] | None,
    *,
    raw_config_list: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]] | None:
    """Normalize and expand optional gathered Ethernet filters."""
    if not config_list:
        return config_list

    normalized = deepcopy(config_list)

    if isinstance(raw_config_list, list):
        for item_index, item in enumerate(normalized):
            raw_item = raw_config_list[item_index] if item_index < len(raw_config_list) else None

            if isinstance(item, dict) and isinstance(raw_item, dict) and "interface_names" not in raw_item and item.get("interface_names") is None:
                item.pop("interface_names", None)

    validate_ethernet_interface_names(
        normalized,
        require_interface_names=False,
    )

    expanded: list[dict[str, Any]] = []

    for item in normalized:
        interface_names = item.get("interface_names") or []

        if interface_names:
            for interface_name in interface_names:
                expanded_item = deepcopy(item)
                expanded_item.pop("interface_names", None)
                expanded_item["interface_name"] = interface_name
                expanded.append(expanded_item)
        else:
            expanded.append(deepcopy(item))

    return expanded


def validate_ethernet_within_item_duplicates(config_list: list[dict[str, Any]]) -> None:
    """Reject a repeated case-insensitive name within one Ethernet group."""
    for item_index, group in enumerate(config_list):
        switch_ip = group.get("switch_ip")
        interface_names = group["interface_names"]
        seen: set[str] = set()
        for name in interface_names:
            key = name.lower()
            if key in seen:
                raise ValueError(
                    f"Duplicate interface '{name}' in interface_names for switch '{switch_ip}' "
                    f"(config item {item_index}). Each interface may appear only once per config item."
                )
            seen.add(key)


def validate_ethernet_across_item_duplicates(config_list: list[dict[str, Any]]) -> None:
    """Reject a repeated case-insensitive switch/name identity across groups."""
    seen: dict[tuple[Any, str], int] = {}
    for item_index, group in enumerate(config_list):
        switch_ip = group.get("switch_ip")
        interface_names = group["interface_names"]
        for name in interface_names:
            key = (switch_ip, name.lower())
            if key in seen:
                raise ValueError(
                    f"Interface '{name}' on switch '{switch_ip}' is specified in multiple config items "
                    f"({seen[key]} and {item_index}). Each switch/interface pair may appear only once."
                )
            seen[key] = item_index


def expand_ethernet_config(
    config_list: list[dict[str, Any]],
    *,
    allow_empty_interface_names: bool = False,
) -> list[dict[str, Any]]:
    """Expand grouped Ethernet config, optionally preserving overridden reset-all semantics."""
    for item_index, group in enumerate(config_list):
        if not isinstance(group, dict):
            raise ValueError(f"Ethernet config item {item_index} must be a mapping.")
        switch_ip = group.get("switch_ip")
        if not isinstance(switch_ip, str) or not switch_ip.strip():
            raise ValueError(f"switch_ip is required and must be a non-empty string for config item {item_index}.")
        if "interface_names" not in group:
            raise ValueError(f"interface_names is required and must contain at least one interface for switch " f"'{switch_ip}' (config item {item_index}).")
        interface_names = group["interface_names"]
        if not isinstance(interface_names, list):
            if interface_names is None and not allow_empty_interface_names:
                raise ValueError(
                    f"interface_names is required and must contain at least one interface for switch " f"'{switch_ip}' (config item {item_index})."
                )
            raise ValueError(f"interface_names for Ethernet config item {item_index} on switch '{switch_ip}' must be a list.")
        if not interface_names and not allow_empty_interface_names:
            raise ValueError(f"interface_names is required and must contain at least one interface for switch " f"'{switch_ip}' (config item {item_index}).")

    validate_ethernet_interface_names(config_list)
    validate_ethernet_within_item_duplicates(config_list)
    validate_ethernet_across_item_duplicates(config_list)

    expanded: list[dict[str, Any]] = []
    for group in config_list:
        for name in group["interface_names"]:
            item = deepcopy(group)
            item.pop("interface_names", None)
            item["interface_name"] = name
            expanded.append(item)
    return expanded


def expand_ethernet_dot1q_tunnel_host_config(config_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Require named dot1q groups while retaining explicit top-level reset-all."""
    for index, group in enumerate(config_list):
        if isinstance(group, dict) and group.get("interface_names") == []:
            raise ValueError(
                f"interface_names for dot1q config item {index} must name at least one interface. "
                "Use top-level config: [] with state: overridden for an intentional fabric-wide reset."
            )
    return expand_ethernet_config(config_list)
