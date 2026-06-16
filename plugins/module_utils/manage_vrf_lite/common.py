# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import ipaddress
from typing import Any, NoReturn

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender

DEFAULT_VERIFY_TIMEOUT = 10
DEFAULT_VERIFY_RETRIES = 5
DEFAULT_CONFIG_ACTION_TYPE = "switch"
CONFIG_ACTION_TYPE_CHOICES = ("switch", "global")


class _VrfLiteListPayloadRestSend(RestSend):
    """RestSend variant for the ND VRF attachment API's top-level list body."""

    @property
    def payload(self) -> Any:
        return self._payload

    @payload.setter
    def payload(self, value: Any) -> None:
        if not isinstance(value, (dict, list)):
            msg = "{0}.payload: payload must be a dict or list. ".format(self.class_name)
            msg += "Got {0}.".format(value)
            raise TypeError(msg)
        self._payload = value


class _VrfLiteListPayloadSender(Sender):
    """Sender variant for the ND VRF attachment API's top-level list body."""

    @property
    def payload(self) -> Any:
        return self._payload

    @payload.setter
    def payload(self, value: Any) -> None:
        if value is not None and not isinstance(value, (dict, list)):
            msg = "{0}.payload: payload must be a dict, list, or None. ".format(self.class_name)
            msg += "Got type {0}, value {1}.".format(type(value).__name__, value)
            raise TypeError(msg)
        self._payload = value


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
            msg=("Switch identifier '{0}' appears to be an IP, but it could not " "be resolved to a fabric switch serial number.").format(text),
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


def _list_payload_rest_send(module: Any, base_rest_send: RestSend) -> RestSend:
    rest_send = _VrfLiteListPayloadRestSend(
        {
            "check_mode": module.check_mode,
            "state": module.params.get("state"),
        }
    )
    rest_send.timeout = base_rest_send.timeout
    rest_send.send_interval = base_rest_send.send_interval
    rest_send.unit_test = base_rest_send.unit_test

    sender = _VrfLiteListPayloadSender()
    sender.ansible_module = module
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    return rest_send


def request_with_rest_send(
    module: Any,
    rest_send: RestSend,
    path: str,
    verb: HttpVerbEnum,
    data: Any = None,
    timeout: int | None = None,
    force_check_mode: bool = False,
) -> Any:
    """Run a controller request through the orchestrator's RestSend path."""
    active_rest_send = _list_payload_rest_send(module, rest_send) if isinstance(data, list) else rest_send

    active_rest_send.save_settings()
    if timeout is not None:
        active_rest_send.timeout = timeout
    if force_check_mode:
        active_rest_send.check_mode = False

    try:
        active_rest_send.path = path
        active_rest_send.verb = verb
        if data is not None:
            active_rest_send.payload = data
        active_rest_send.commit()
    except (TypeError, ValueError) as error:
        raise ValueError("Error in request: {0}".format(error)) from error
    finally:
        active_rest_send.restore_settings()

    response = active_rest_send.response_current
    result = active_rest_send.result_current

    if not result.get("success", False):
        response_data = response.get("DATA")
        raw = None
        payload = None

        if isinstance(response_data, dict):
            if "raw_response" in response_data:
                raw = response_data["raw_response"]
            else:
                payload = response_data

        error_msg = active_rest_send.response_handler.error_message if active_rest_send.response_handler else "Unknown error"
        raise NDModuleError(
            msg=error_msg or "Unknown error",
            status=response.get("RETURN_CODE", -1),
            request_payload=data if isinstance(data, dict) else None,
            response_payload=payload,
            raw=raw,
        )

    return response.get("DATA", {})


def request_with_verify_settings(module: Any, rest_send: RestSend, path: str, verb: HttpVerbEnum, data: Any = None) -> Any:
    """Run a controller read using the configured verify timeout/retry policy."""
    settings = get_verify_settings(module.params)
    timeout = settings.get("timeout", DEFAULT_VERIFY_TIMEOUT)
    retries = settings.get("retries", DEFAULT_VERIFY_RETRIES)
    try:
        retries = max(1, int(retries))
    except (TypeError, ValueError):
        retries = DEFAULT_VERIFY_RETRIES

    for attempt in range(retries):
        try:
            return request_with_rest_send(
                module=module,
                rest_send=rest_send,
                path=path,
                verb=verb,
                data=data,
                timeout=timeout,
                force_check_mode=True,
            )
        except Exception:
            if attempt + 1 >= retries:
                raise


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
