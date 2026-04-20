# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations

from typing import Any, Annotated
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BeforeValidator,
)


def coerce_str_to_int(data: Any) -> Any:
    """
    Convert string to int, handle None.

    Args:
        data: Value to coerce (str, int, or None)

    Returns:
        Integer value, or None if input is None.

    Raises:
        ValueError: If string cannot be converted to int
    """
    if data is None:
        return None
    if isinstance(data, str):
        if data.strip() and data.lstrip("-").isdigit():
            return int(data)
        raise ValueError(f"Cannot convert '{data}' to int")
    return int(data)


def coerce_to_bool(data: Any) -> Any:
    """
    Convert various formats to bool.

    Args:
        data: Value to coerce (str, bool, int, or None)

    Returns:
        Boolean value, or None if input is None.
        Strings 'true', '1', 'yes', 'on' map to True.
    """
    if data is None:
        return None
    if isinstance(data, str):
        return data.lower() in ("true", "1", "yes", "on")
    return bool(data)


def coerce_list_of_str(data: Any) -> Any:
    """
    Ensure data is a list of strings.

    Args:
        data: Value to coerce (str, list, or None)

    Returns:
        List of strings, or None if input is None.
        Comma-separated strings are split into list items.
    """
    if data is None:
        return None
    if isinstance(data, str):
        return [item.strip() for item in data.split(",") if item.strip()]
    if isinstance(data, list):
        return [str(item) for item in data]
    return data


FlexibleInt = Annotated[int, BeforeValidator(coerce_str_to_int)]
FlexibleBool = Annotated[bool, BeforeValidator(coerce_to_bool)]
FlexibleListStr = Annotated[list[str], BeforeValidator(coerce_list_of_str)]


class SwitchPairKeyMixin:
    """
    Helper for switch-pair identifier formatting.

    Keeps a deterministic key regardless of switch order.
    """

    def get_switch_pair_key(self) -> str:
        identifiers = getattr(self, "identifiers", []) or []
        if len(identifiers) != 2:
            raise ValueError("get_switch_pair_key only works with exactly 2 identifier fields")

        values = []
        for field in identifiers:
            value = getattr(self, field, None)
            if value is None:
                raise ValueError(f"Identifier field '{field}' is None")
            values.append(value)

        sorted_ids = sorted(str(v) for v in values)
        return f"{sorted_ids[0]}-{sorted_ids[1]}"
