# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import ast
import json
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _raise_vrf_lite_error,
    _resolve_serial,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    _query_vrf_switch_details,
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
        for child in value.values():
            if not isinstance(child, (dict, list)):
                continue
            support = _extract_support_flag(child)
            if support is not None:
                return support

    if isinstance(value, list):
        for item in value:
            if not isinstance(item, (dict, list)):
                continue
            support = _extract_support_flag(item)
            if support is not None:
                return support

    return None


def _vrf_lite_cache_key(fabric_name: str, vrf_name: str, serial_number: str) -> str:
    return "{0}\0{1}\0{2}".format(fabric_name, vrf_name, serial_number)


def _parse_prototype_extension_values(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return None
    return dict(parsed) if isinstance(parsed, dict) else None


def _extract_vrf_lite_prototypes(response: Any, serial_number: str) -> dict[str, dict[str, Any]] | None:
    """Return controller-owned prototypes, or ``None`` if the field is absent."""
    prototypes: dict[str, dict[str, Any]] = {}
    prototype_field_seen = False

    def _visit(value: Any) -> None:
        nonlocal prototype_field_seen
        if isinstance(value, list):
            for item in value:
                _visit(item)
            return
        if not isinstance(value, dict):
            return

        has_prototype_field = "extensionPrototypeValues" in value
        prototype_rows = value.get("extensionPrototypeValues")
        detail_serial = value.get("serialNumber") or value.get("switchId")
        serial_matches = not detail_serial or str(detail_serial).strip() == str(serial_number).strip()
        if has_prototype_field and serial_matches:
            prototype_field_seen = True
        if isinstance(prototype_rows, list) and serial_matches:
            for prototype in prototype_rows:
                if not isinstance(prototype, dict):
                    continue
                extension_type = str(prototype.get("extensionType") or "").strip().upper()
                if extension_type != "VRF_LITE":
                    continue
                parsed_extension_values = _parse_prototype_extension_values(prototype.get("extensionValues"))
                extension_values = dict(parsed_extension_values or {})
                interface = extension_values.get("IF_NAME") or prototype.get("interfaceName")
                if not interface:
                    continue
                interface_text = str(interface).strip()
                if not interface_text:
                    continue
                extension_values["IF_NAME"] = interface_text
                prototypes[interface_text] = extension_values

        for child in value.values():
            if child is not prototype_rows:
                _visit(child)

    _visit(response)
    return prototypes if prototype_field_seen else None


def get_cached_vrf_lite_prototypes(
    module: Any,
    fabric_name: str,
    vrf_name: str,
    serial_number: str,
) -> dict[str, dict[str, Any]] | None:
    """Return cached prototypes, or ``None`` when no prototype query ran."""
    cache = module.params.get("_vrf_lite_prototype_cache")
    if not isinstance(cache, dict):
        return None
    return cache.get(_vrf_lite_cache_key(fabric_name, vrf_name, serial_number))


def _query_vrf_lite_support(module: Any, rest_send: Any, fabric_name: str, vrf_name: str, serial_number: str) -> bool | None:
    cache = module.params.get("_vrf_lite_support_cache")
    if not isinstance(cache, dict):
        cache = {}
        module.params["_vrf_lite_support_cache"] = cache

    prototype_cache = module.params.get("_vrf_lite_prototype_cache")
    if not isinstance(prototype_cache, dict):
        prototype_cache = {}
        module.params["_vrf_lite_prototype_cache"] = prototype_cache

    cache_key = _vrf_lite_cache_key(fabric_name, vrf_name, serial_number)
    if cache_key in cache and cache_key in prototype_cache:
        return cache[cache_key]

    response = _query_vrf_switch_details(
        module=module,
        rest_send=rest_send,
        fabric_name=fabric_name,
        vrf_name=vrf_name,
        serial_numbers=[serial_number],
    ).get(serial_number, {})

    prototypes = _extract_vrf_lite_prototypes(response, serial_number)
    prototype_cache[cache_key] = prototypes
    support = _extract_support_flag(response)
    if support is None and prototypes:
        support = True
    cache[cache_key] = support
    return support


def _configured_interface(item: Any) -> str:
    value = getattr(item, "interface", None)
    if value is None and isinstance(item, dict):
        value = item.get("interface")
    return str(value or "").strip()


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

        support = _query_vrf_lite_support(module, rest_send, fabric_name, vrf_name, serial_number)

        if support is False:
            _raise_vrf_lite_error(
                msg=("Switch '{0}' does not report VRF Lite support in fabric '{1}'.").format(serial_number, fabric_name),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
            )

        prototypes = get_cached_vrf_lite_prototypes(module, fabric_name, vrf_name, serial_number)
        if prototypes is None:
            _raise_vrf_lite_error(
                msg=("The controller did not return VRF Lite interface prototype metadata " "for switch '{0}' in fabric '{1}'.").format(
                    serial_number, fabric_name
                ),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
            )
        if not prototypes:
            _raise_vrf_lite_error(
                msg=("No VRF Lite-capable interfaces were reported for switch '{0}' in fabric '{1}'.").format(serial_number, fabric_name),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
            )

        requested_interfaces = sorted({_configured_interface(item) for item in vrf_lite_entries if _configured_interface(item)})
        available_by_normalized_name = {name.casefold(): name for name in prototypes}
        missing_interfaces = [name for name in requested_interfaces if name.casefold() not in available_by_normalized_name]
        if missing_interfaces:
            _raise_vrf_lite_error(
                msg=(
                    "No matching VRF Lite interface prototype was found on switch '{0}'. " "Requested interface(s): {1}. Available interface(s): {2}."
                ).format(
                    serial_number,
                    ", ".join(missing_interfaces),
                    ", ".join(sorted(prototypes)),
                ),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
                requested_interfaces=missing_interfaces,
                available_interfaces=sorted(prototypes),
            )

        unusable_interfaces = []
        for interface in requested_interfaces:
            prototype = prototypes[available_by_normalized_name[interface.casefold()]]
            missing_fields = [field for field in ("NEIGHBOR_ASN", "AUTO_VRF_LITE_FLAG") if field not in prototype or prototype.get(field) in (None, "")]
            if missing_fields:
                unusable_interfaces.append("{0} (missing {1})".format(interface, ", ".join(missing_fields)))

        if unusable_interfaces:
            _raise_vrf_lite_error(
                msg=("The controller returned unusable VRF Lite prototype metadata " "for switch '{0}': {1}.").format(
                    serial_number, "; ".join(unusable_interfaces)
                ),
                fabric=fabric_name,
                serial_number=serial_number,
                vrf_name=vrf_name,
                unusable_interfaces=unusable_interfaces,
            )
