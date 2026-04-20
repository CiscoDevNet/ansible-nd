# -*- coding: utf-8 -*-
#
# Copyright: (c) 2026, Sivakami S <sivakasi@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.enums import (
    VpcFieldNames,
)


def validate_non_empty_switch_id(value: str) -> str:
    """Validate and normalize switch identifier input."""
    if not value or not value.strip():
        raise ValueError("Switch ID cannot be empty or whitespace")
    return value.strip()


def validate_distinct_switches(
    first_switch_id: str,
    second_switch_id: str,
    first_label: str,
    second_label: str,
) -> None:
    """Ensure two switch identifiers are not equal."""
    if first_switch_id == second_switch_id:
        raise ValueError(f"{first_label} and {second_label} must be different: {first_switch_id}")


def normalize_vpc_pair_aliases(ansible_config: dict[str, Any]) -> dict[str, Any]:
    """
    Accept both snake_case playbook keys and camelCase API aliases.

    Returns a normalized dict keyed with API aliases where needed.
    """
    data = dict(ansible_config or {})

    if VpcFieldNames.SWITCH_ID not in data and "switch_id" in data:
        data[VpcFieldNames.SWITCH_ID] = data.get("switch_id")
    if VpcFieldNames.PEER_SWITCH_ID not in data and "peer_switch_id" in data:
        data[VpcFieldNames.PEER_SWITCH_ID] = data.get("peer_switch_id")
    if VpcFieldNames.USE_VIRTUAL_PEER_LINK not in data and "use_virtual_peer_link" in data:
        data[VpcFieldNames.USE_VIRTUAL_PEER_LINK] = data.get("use_virtual_peer_link")
    if VpcFieldNames.VPC_PAIR_DETAILS not in data and "vpc_pair_details" in data:
        data[VpcFieldNames.VPC_PAIR_DETAILS] = data.get("vpc_pair_details")

    return data


def serialize_vpc_pair_details(vpc_pair_details: Any) -> Optional[dict[str, Any]]:
    """Serialize optional details object to alias-based dict."""
    if vpc_pair_details is None:
        return None

    if hasattr(vpc_pair_details, "model_dump"):
        return vpc_pair_details.model_dump(by_alias=True, exclude_none=True)

    if isinstance(vpc_pair_details, dict):
        return dict(vpc_pair_details)

    return None
