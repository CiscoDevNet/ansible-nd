# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import ast
import json
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

Parser = Callable[[str], Any]
DEFAULT_VALUE_PARSERS: tuple[Parser, ...] = (json.loads, ast.literal_eval)


def get_params(source: Any) -> dict[str, Any]:
    """Return a mutable params mapping from either module.params or a raw params dict."""
    if isinstance(source, dict):
        return source

    params = getattr(source, "params", None)
    if isinstance(params, dict):
        return params

    return {}


def parse_value(value: Any, parsers: Sequence[Parser] = DEFAULT_VALUE_PARSERS, default: Any = None) -> Any:
    """Parse a serialized value with the first parser that accepts it.

    Dicts and lists are returned unchanged because callers often pass values
    that were already decoded by the controller client. Empty, invalid, or
    unprintable values return ``default``.
    """
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return default

    try:
        text = str(value).strip()
    except Exception:
        return default

    if not text:
        return default

    for parser in parsers:
        try:
            return parser(text)
        except Exception:
            continue

    return default


def coerce_dict_list(data: Any, list_keys: Sequence[str] = ("DATA", "data", "items")) -> list[dict[str, Any]]:
    """Return dict items from common shallow controller response shapes.

    This intentionally checks only the top-level value or one configured
    top-level wrapper key. Deeper response shapes should be handled by the
    caller because those paths are resource-specific.
    """
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for key in list_keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def copy_dict_items(items: Optional[Iterable[Any]]) -> list[dict[str, Any]]:
    """Copy a list of dict-like or pydantic-like objects into plain dicts."""
    copied = []
    for item in items or []:
        if isinstance(item, Mapping):
            copied.append(dict(item))
        elif hasattr(item, "model_dump"):
            copied.append(item.model_dump(by_alias=False, exclude_none=True))
    return copied


def try_int(value: Any) -> Optional[int]:
    """Best-effort integer conversion."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
