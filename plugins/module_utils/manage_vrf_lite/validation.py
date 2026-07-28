# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    append_runtime_warning,
    request_with_verify_settings,
    _raise_vrf_lite_error,
    _resolve_serial,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)


def _coerce_switch_list(response: Any) -> list[dict[str, Any]]:
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]

    if isinstance(response, dict):
        switches = response.get("switches")
        if isinstance(switches, list):
            return [item for item in switches if isinstance(item, dict)]

    return []


def _normalize_role(switch_data: dict[str, Any]) -> str:
    role_value = switch_data.get("switchRole") or switch_data.get("role") or switch_data.get("switch_role") or ""
    return str(role_value).strip().lower()


def _is_border_role(role: str) -> bool:
    if not role:
        return False
    keywords = (
        "border",
        "bgw",
    )
    return any(keyword in role for keyword in keywords)


def _is_external_connectivity_switch(switch_data: dict[str, Any]) -> bool:
    # TODO(#405): source the fabric type from the shared fabric_details_cache utility
    # once #405 merges, instead of re-deriving it from the raw switch payload here.
    raw = switch_data.get("raw")
    fabric_type = switch_data.get("fabric_type")
    if not fabric_type and isinstance(raw, dict):
        fabric_type = raw.get("fabricType") or raw.get("fabric_type")

    return str(fabric_type or "").strip().lower() == "externalconnectivity"


def _normalize_switch_inventory(response: Any) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}

    if isinstance(response, dict) and "switches" not in response:
        switch_items = response.items()
    else:
        switch_items = [(None, switch) for switch in _coerce_switch_list(response)]

    for key, switch in switch_items:
        if not isinstance(switch, dict):
            continue

        raw = switch.get("raw") if isinstance(switch.get("raw"), dict) and switch.get("raw") else switch
        serial = switch.get("serialNumber") or switch.get("switchId") or raw.get("serialNumber") or raw.get("switchId") or key
        if not serial:
            continue

        serial_text = str(serial).strip()
        if not serial_text:
            continue

        inventory[serial_text] = {
            "role": _normalize_role(switch),
            # TODO(#405): source fabric_type from the shared fabric_details_cache utility
            # (added in #405) instead of re-deriving it from the raw switch payload here,
            # so every module resolves the fabric type consistently.
            "fabric_type": switch.get("fabricType") or switch.get("fabric_type") or raw.get("fabricType") or raw.get("fabric_type"),
            "ip_address": switch.get("fabricManagementIp") or switch.get("ip_address") or raw.get("fabricManagementIp"),
            "raw": raw,
        }
    return inventory


def _load_switch_inventory(module: Any, fabric_name: str, rest_send: Any) -> dict[str, dict[str, Any]]:
    cached = module.params.get("_fabric_switch_inventory")
    if isinstance(cached, dict) and cached:
        inventory = _normalize_switch_inventory(cached)
        module.params["_fabric_switch_inventory"] = inventory
        return inventory

    fabric_context = FabricContext(rest_send=rest_send, fabric_name=fabric_name)
    inventory = _normalize_switch_inventory(fabric_context.switch_inventory_by_id)

    module.params["_fabric_switch_inventory"] = inventory
    return inventory


def _extract_support_flag(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value

    if isinstance(value, dict):
        for key in (
            "isVrfLiteSupported",
            "vrfLiteSupported",
            "isVrfLiteCapable",
            "vrfLiteCapable",
            "supported",
        ):
            if key in value and isinstance(value.get(key), bool):
                return value.get(key)

    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            support = _extract_support_flag(item)
            if support is not None:
                return support

    return None


def _query_vrf_lite_support(module: Any, rest_send: Any, fabric_name: str, vrf_name: str, serial_number: str) -> bool | None:
    cache = module.params.get("_vrf_lite_support_cache")
    if not isinstance(cache, dict):
        cache = {}
        module.params["_vrf_lite_support_cache"] = cache

    cache_key = "{0}\0{1}\0{2}".format(fabric_name, vrf_name, serial_number)
    if cache_key in cache:
        return cache[cache_key]

    response = request_with_verify_settings(
        module,
        rest_send,
        VrfLiteEndpoints.vrf_switch(fabric_name, vrf_name, serial_number),
        HttpVerbEnum.GET,
    )

    support = _extract_support_flag(response)
    cache[cache_key] = support
    return support


def _warn_on_uncertain_role(module: Any, serial_number: str, role: str, switch_data: dict[str, Any]) -> None:
    if role and not _is_border_role(role) and not _is_external_connectivity_switch(switch_data):
        append_runtime_warning(
            module.params,
            (
                "Switch '{0}' has role '{1}', but the controller did not return an explicit VRF Lite "
                "support flag. Proceeding with controller-side validation."
            ).format(serial_number, role),
        )
    if not role:
        append_runtime_warning(
            module.params,
            "Unable to determine switch role for '{0}'. VRF Lite border-role validation was skipped.".format(serial_number),
        )


def validate_vrf_lite_write_guardrails(module: Any, model_instance: Any, rest_send: Any) -> None:
    """
    Validate switch existence, role suitability, and platform support hints.
    """
    if hasattr(model_instance, "switch_ip"):
        attachments = [model_instance]
    else:
        attachments = model_instance.attach or []
    if not attachments:
        return

    fabric_name = module.params.get("fabric_name")
    vrf_name = model_instance.vrf_name
    inventory = _load_switch_inventory(module, fabric_name, rest_send)

    for attach in attachments:
        switch_identifier = getattr(attach, "switch_ip", None) or getattr(attach, "ip_address", None)
        serial_number = _resolve_serial(module, switch_identifier)
        if not serial_number:
            continue

        if serial_number not in inventory:
            _raise_vrf_lite_error(
                msg=("Switch '{0}' is not present in fabric '{1}'.").format(serial_number, fabric_name),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
            )

        vrf_lite_entries = getattr(attach, "extensions", None) or getattr(attach, "vrf_lite", None)
        if not vrf_lite_entries:
            continue

        switch_data = inventory[serial_number]
        role = switch_data.get("role", "")
        support = None
        try:
            support = _query_vrf_lite_support(module, rest_send, fabric_name, vrf_name, serial_number)
        except NDModuleError as error:
            append_runtime_warning(
                module.params,
                "Unable to query VRF Lite support for switch '{0}': {1}".format(
                    serial_number,
                    error.msg,
                ),
            )
            _warn_on_uncertain_role(module, serial_number, role, switch_data)
            continue
        except Exception as error:
            append_runtime_warning(
                module.params,
                "Unable to query VRF Lite support for switch '{0}': {1}".format(
                    serial_number,
                    str(error),
                ),
            )
            _warn_on_uncertain_role(module, serial_number, role, switch_data)
            continue

        if support is False:
            _raise_vrf_lite_error(
                msg=("Switch '{0}' does not report VRF Lite support in fabric '{1}'.").format(serial_number, fabric_name),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
            )

        if support is True:
            continue

        _warn_on_uncertain_role(module, serial_number, role, switch_data)
