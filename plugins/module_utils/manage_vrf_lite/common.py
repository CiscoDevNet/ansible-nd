# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import json
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)

DEFAULT_VERIFY_TIMEOUT = 10
DEFAULT_VERIFY_RETRIES = 5
DEFAULT_CONFIG_ACTION_TYPE = "switch"
CONFIG_ACTION_TYPE_CHOICES = ("switch", "global")


def _raise_vrf_lite_error(msg: str, **details: Any) -> None:
    raise VrfLiteResourceError(msg=msg, **details)


def _get_params(source: Any) -> dict[str, Any]:
    """Return a mutable params mapping from either module.params or a raw params dict."""
    if isinstance(source, dict):
        return source

    params = getattr(source, "params", None)
    if isinstance(params, dict):
        return params

    return {}


def append_runtime_warning(source: Any, message: str) -> None:
    """Collect runtime warnings without requiring direct Ansible dependencies."""
    params = _get_params(source)
    warnings = params.get("_warnings")
    if not isinstance(warnings, list):
        warnings = []
    warnings.append(str(message))
    params["_warnings"] = warnings


def get_runtime_warnings(source: Any) -> list[str]:
    params = _get_params(source)
    warnings = params.get("_warnings")
    if not isinstance(warnings, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for warning in warnings:
        text = str(warning)
        if text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


def _canonicalize_for_compare(value: Any) -> Any:
    """Normalize nested structures for deterministic comparison."""
    if isinstance(value, dict):
        return {key: _canonicalize_for_compare(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        normalized_items = [_canonicalize_for_compare(item) for item in value]
        return sorted(normalized_items, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return value


def _is_update_needed(want: dict[str, Any], have: dict[str, Any]) -> bool:
    return _canonicalize_for_compare(want) != _canonicalize_for_compare(have)


def get_verify_settings(source: Any) -> dict[str, Any]:
    params = _get_params(source)
    raw_verify = params.get("verify")
    if isinstance(raw_verify, dict):
        return {
            "enabled": raw_verify.get("enabled", True),
            "retries": raw_verify.get("retries", DEFAULT_VERIFY_RETRIES),
            "timeout": raw_verify.get("timeout", DEFAULT_VERIFY_TIMEOUT),
        }

    return {
        "enabled": True,
        "retries": DEFAULT_VERIFY_RETRIES,
        "timeout": DEFAULT_VERIFY_TIMEOUT,
    }


def get_verify_timeout(source: Any) -> int:
    return get_verify_settings(source).get("timeout", DEFAULT_VERIFY_TIMEOUT)


def request_with_verify_settings(module: Any, nd_v2: Any, path: str, verb: Any) -> Any:
    """Run a controller read using the configured verify timeout/retry policy."""
    settings = get_verify_settings(module.params)
    timeout = settings.get("timeout", DEFAULT_VERIFY_TIMEOUT)
    retries = settings.get("retries", DEFAULT_VERIFY_RETRIES)
    try:
        retries = max(1, int(retries))
    except (TypeError, ValueError):
        retries = DEFAULT_VERIFY_RETRIES

    last_error = None
    for attempt in range(retries):
        rest_send = nd_v2._get_rest_send()
        rest_send.save_settings()
        rest_send.timeout = timeout
        try:
            return nd_v2.request(path, verb)
        except Exception as error:
            last_error = error
            if attempt + 1 >= retries:
                raise
        finally:
            rest_send.restore_settings()

    if last_error is not None:
        raise last_error
    return None


def get_config_actions(source: Any) -> dict[str, Any]:
    params = _get_params(source)
    raw_actions = params.get("config_actions")
    if isinstance(raw_actions, dict):
        action_type_raw = raw_actions.get("type", DEFAULT_CONFIG_ACTION_TYPE)
        action_type = str(action_type_raw).strip().lower() if action_type_raw is not None else DEFAULT_CONFIG_ACTION_TYPE
        if action_type not in CONFIG_ACTION_TYPE_CHOICES:
            action_type = DEFAULT_CONFIG_ACTION_TYPE

        return {
            "save": raw_actions.get("save", True),
            "deploy": raw_actions.get("deploy", True),
            "type": action_type,
        }

    return {
        "save": True,
        "deploy": True,
        "type": DEFAULT_CONFIG_ACTION_TYPE,
    }


def normalize_config_list(source: Any, state: str) -> list:
    params = _get_params(source)
    if state == "gathered":
        return list(params.get("_gather_filter_config") or [])
    return list(params.get("config") or [])
