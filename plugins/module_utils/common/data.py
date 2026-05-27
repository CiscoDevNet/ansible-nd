# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import ast
import json
from typing import Any


def get_params(source: Any) -> dict[str, Any]:
    """Return a mutable params mapping from either module.params or a raw params dict."""
    if isinstance(source, dict):
        return source

    params = getattr(source, "params", None)
    if isinstance(params, dict):
        return params

    return {}


def loads_maybe_json(value: Any) -> Any:
    """Parse JSON or Python-literal strings while leaving parsed values unchanged."""
    if isinstance(value, (dict, list)):
        return value
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        return json.loads(text)
    except Exception:
        try:
            return ast.literal_eval(text)
        except Exception:
            return None


def coerce_dict_list(data: Any, list_keys: tuple[str, ...] = ("DATA", "data", "items")) -> list[dict[str, Any]]:
    """Return a list containing only dict items from common controller response shapes."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for key in list_keys:
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def copy_dict_items(items: Any) -> list[dict[str, Any]]:
    """Copy a list of dict-like or pydantic-like objects into plain dicts."""
    copied = []
    for item in items or []:
        if isinstance(item, dict):
            copied.append(dict(item))
        elif hasattr(item, "model_dump"):
            copied.append(item.model_dump(by_alias=False, exclude_none=True))
    return copied


def try_int(value: Any) -> int | None:
    """Best-effort integer conversion."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
