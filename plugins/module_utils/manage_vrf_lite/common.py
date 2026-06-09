# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import ipaddress
from typing import Any, NoReturn

from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)

DEFAULT_VERIFY_TIMEOUT = 10
DEFAULT_VERIFY_RETRIES = 5
DEFAULT_CONFIG_ACTION_TYPE = "switch"
CONFIG_ACTION_TYPE_CHOICES = ("switch", "global")


def _params(source: Any) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    params = getattr(source, "params", None)
    return params if isinstance(params, dict) else {}


def _raise_vrf_lite_error(msg: str, **details: Any) -> NoReturn:
    raise VrfLiteResourceError(msg=msg, **details)


def _is_ip_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False

    text = value.strip()
    if not text:
        return False

    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _resolve_serial(module: Any, switch_identifier: Any) -> str:
    """Resolve a switch management IP to serial when the query cache has it."""
    if switch_identifier is None:
        return ""

    text = str(switch_identifier).strip()
    if not text:
        return ""

    mapping = module.params.get("_ip_to_sn_mapping") or {}
    if text in mapping:
        return mapping[text]

    if _is_ip_literal(text):
        _raise_vrf_lite_error(
            msg=(
                "Switch identifier '{0}' appears to be an IP, but it could not "
                "be resolved to a fabric switch serial number."
            ).format(text),
            switch_id=text,
        )

    return text


def vrf_name_from_config_item(item: Any) -> str:
    """Return a normalized VRF name from public or controller-style keys."""
    if not isinstance(item, dict):
        return ""

    vrf_name = item.get("vrf_name") or item.get("vrfName")
    return str(vrf_name).strip() if vrf_name else ""


def append_runtime_warning(source: Any, message: str) -> None:
    """Collect runtime warnings without requiring direct Ansible dependencies."""
    params = _params(source)
    warnings = params.get("_warnings")
    if not isinstance(warnings, list):
        warnings = []
    warnings.append(str(message))
    params["_warnings"] = warnings


def get_runtime_warnings(source: Any) -> list[str]:
    params = _params(source)
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


def get_verify_settings(source: Any) -> dict[str, Any]:
    params = _params(source)
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


def request_with_verify_settings(module: Any, nd_v2: Any, path: str, verb: Any, data: Any = None) -> Any:
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
            return nd_v2.request(path, verb, data)
        except Exception as error:
            last_error = error
            if attempt + 1 >= retries:
                raise
        finally:
            rest_send.restore_settings()


def get_config_actions(source: Any) -> dict[str, Any]:
    params = _params(source)
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
