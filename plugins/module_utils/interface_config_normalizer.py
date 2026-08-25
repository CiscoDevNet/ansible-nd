# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared input normalization for interface resource modules and workflows."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def validate_ethernet_interface_names(config_list: list[dict[str, Any]]) -> None:
    """Reject null, non-string, and empty entries in grouped Ethernet input."""
    for item_index, group in enumerate(config_list):
        switch_ip = group.get("switch_ip")
        interface_names = group.get("interface_names") or []
        for entry_index, name in enumerate(interface_names):
            if isinstance(name, str) and name:
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


def validate_ethernet_within_item_duplicates(config_list: list[dict[str, Any]]) -> None:
    """Reject a repeated case-insensitive name within one Ethernet group."""
    for item_index, group in enumerate(config_list):
        switch_ip = group.get("switch_ip")
        interface_names = group.get("interface_names") or []
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
        interface_names = group.get("interface_names") or []
        for name in interface_names:
            key = (switch_ip, name.lower())
            if key in seen:
                raise ValueError(
                    f"Interface '{name}' on switch '{switch_ip}' is specified in multiple config items "
                    f"({seen[key]} and {item_index}). Each switch/interface pair may appear only once."
                )
            seen[key] = item_index


def expand_ethernet_config(config_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand standalone-style ``interface_names`` groups into model items."""
    validate_ethernet_interface_names(config_list)
    validate_ethernet_within_item_duplicates(config_list)
    validate_ethernet_across_item_duplicates(config_list)

    expanded: list[dict[str, Any]] = []
    for group in config_list:
        for name in group.get("interface_names") or []:
            item = deepcopy(group)
            item.pop("interface_names", None)
            item["interface_name"] = name
            expanded.append(item)
    return expanded
