# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import json
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _raise_vrf_lite_error,
    _resolve_serial,
    request_with_rest_send,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    query_vrf_lite_state,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_payloads import (
    build_instance_values_api,
    build_vrf_lite_extension_values_api,
    parse_instance_values,
    vrf_lite_items_to_config,
)


def _request_vrf_lite_payload(module: Any, rest_send: Any, path: str, verb: HttpVerbEnum, payload: Any) -> Any:
    """Send VRF Lite payloads without widening the shared REST sender contract."""
    try:
        return request_with_rest_send(
            module=module,
            rest_send=rest_send,
            path=path,
            verb=verb,
            data=payload,
        )
    except Exception as error:
        _raise_vrf_lite_error(
            msg="{0}; request_payload={1}".format(error, json.dumps(payload, sort_keys=True)),
            request_payload=payload,
        )


def _ensure_vrf_exists(module: Any, rest_send: Any, vrf_name: str) -> None:
    known_vrfs = module.params.get("_known_vrfs") or []
    if vrf_name in known_vrfs:
        return

    fabric_name = module.params.get("fabric_name")
    # The normalized state can legitimately be empty for an existing VRF that
    # has no managed VRF Lite attachment rows. ``query_vrf_lite_state`` records
    # the authoritative VRF inventory in ``_known_vrfs`` independently of the
    # attachment result, so use that inventory for the existence decision.
    query_vrf_lite_state(module=module, rest_send=rest_send, fabric_name=fabric_name, filter_vrfs={vrf_name})
    known_vrfs = module.params.get("_known_vrfs") or []
    if vrf_name not in known_vrfs:
        _raise_vrf_lite_error(
            msg="VRF '{0}' does not exist in fabric '{1}'.".format(vrf_name, fabric_name),
            fabric=fabric_name,
            vrf_name=vrf_name,
        )


def _reserve_dot1q_if_needed(module: Any, rest_send: Any, fabric_name: str, vrf_name: str, serial_number: str, lite_item: dict[str, Any]) -> dict[str, Any]:
    if lite_item.get("dot1q") not in (None, ""):
        return lite_item

    interface = lite_item.get("interface")
    if not interface:
        return lite_item

    payload = {
        "scopeType": "DeviceInterface",
        "usageType": "TOP_DOWN_L3_DOT1Q",
        "serialNumber": serial_number,
        "switchId": serial_number,
        "ifName": interface,
        "allocatedTo": vrf_name,
    }

    response = request_with_rest_send(module, rest_send, VrfLiteEndpoints.reserve_id(fabric_name), HttpVerbEnum.POST, payload)

    dot1q_value = None
    if isinstance(response, dict):
        # Different controller versions return either a scalar DATA-equivalent
        # or a dict-like body for reserve-id.
        for key in ("dot1q", "id", "value", "allocatedId"):
            if response.get(key) not in (None, ""):
                dot1q_value = response.get(key)
                break
    else:
        dot1q_value = response

    if dot1q_value in (None, ""):
        _raise_vrf_lite_error(
            msg="Failed to reserve dot1q for VRF Lite interface '{0}' on switch '{1}'.".format(interface, serial_number),
            vrf_name=vrf_name,
            serial_number=serial_number,
            reserve_response=response,
        )

    updated = dict(lite_item)
    updated["dot1q"] = dot1q_value
    return updated


def _raw_attachment_entry(module: Any, vrf_name: str, serial_number: str) -> dict[str, Any]:
    raw_vrf_attachment_map = module.params.get("_raw_vrf_attachment_map") or {}
    raw_attachment_map = raw_vrf_attachment_map.get(vrf_name, {}) if isinstance(raw_vrf_attachment_map, dict) else {}
    raw_attach = raw_attachment_map.get(serial_number) if isinstance(raw_attachment_map, dict) else None
    return raw_attach if isinstance(raw_attach, dict) else {}


def _entry_extensions(entry: Any) -> list[dict[str, Any]]:
    return entry.to_config().get("extensions", []) if hasattr(entry, "to_config") else list(getattr(entry, "extensions", None) or [])


def _entry_vlan_id(module: Any, entry: Any, raw_attach: dict[str, Any] | None = None) -> int:
    if getattr(entry, "vlan_id", None) is not None:
        return int(entry.vlan_id)

    vlan_map = module.params.get("_vrf_lite_vrf_vlan_map") or {}
    mapped_vlan = vlan_map.get(entry.vrf_name)
    if mapped_vlan not in (None, ""):
        try:
            return int(mapped_vlan)
        except (TypeError, ValueError):
            pass

    if isinstance(raw_attach, dict) and raw_attach.get("vlan") not in (None, ""):
        try:
            return int(raw_attach.get("vlan"))
        except (TypeError, ValueError):
            pass

    _raise_vrf_lite_error(
        msg=("vlan_id is required for VRF '{0}' because the current VRF VLAN " "could not be determined from the controller.").format(entry.vrf_name),
        vrf_name=entry.vrf_name,
        switch_ip=entry.switch_ip,
    )


def build_attach_payload_for_entry(module: Any, rest_send: Any, entry: Any) -> dict[str, Any]:
    """Build one ND attachment row for one flat VRF Lite entry."""
    serial_number = _resolve_serial(module, entry.switch_ip)
    raw_attach = _raw_attachment_entry(module, entry.vrf_name, serial_number)
    vlan_id = _entry_vlan_id(module, entry, raw_attach)

    resolved_extensions = []
    for lite_item in vrf_lite_items_to_config(_entry_extensions(entry)):
        resolved_extensions.append(_reserve_dot1q_if_needed(module, rest_send, module.params.get("fabric_name"), entry.vrf_name, serial_number, lite_item))

    instance_values = build_instance_values_api(
        getattr(entry, "import_evpn_rt", None),
        getattr(entry, "export_evpn_rt", None),
        raw_attach.get("instance_values") if isinstance(raw_attach, dict) else None,
    )

    payload = {
        "vrfName": entry.vrf_name,
        "switchId": serial_number,
        "vlanId": vlan_id,
        "attach": True,
        "extensionValues": build_vrf_lite_extension_values_api(resolved_extensions),
    }
    if any(value not in (None, "") for value in instance_values.values()):
        payload["instanceValues"] = instance_values
    return payload


def _build_detach_payload(
    module: Any,
    vrf_name: str,
    serial_number: str,
    vlan_id: Any,
    instance_values: Any = None,
) -> dict[str, Any]:
    payload = {
        "vrfName": vrf_name,
        "switchId": serial_number,
        "vlanId": vlan_id if vlan_id is not None else 0,
        "attach": True,
        "extensionValues": [],
    }
    parsed_instance_values = parse_instance_values(instance_values)
    if parsed_instance_values:
        payload["instanceValues"] = parsed_instance_values
    return payload


def build_detach_payload_for_entry(module: Any, entry: Any) -> dict[str, Any]:
    """Build one ND row that removes VRF Lite data for one flat entry."""
    serial_number = _resolve_serial(module, entry.switch_ip)
    raw_attach = _raw_attachment_entry(module, entry.vrf_name, serial_number)
    vlan_id = getattr(entry, "vlan_id", None)
    if vlan_id in (None, ""):
        vlan_id = raw_attach.get("vlan")
    if vlan_id in (None, ""):
        vlan_id = (module.params.get("_vrf_lite_vrf_vlan_map") or {}).get(entry.vrf_name)

    return _build_detach_payload(
        module=module,
        vrf_name=entry.vrf_name,
        serial_number=serial_number,
        vlan_id=vlan_id,
        instance_values=raw_attach.get("instance_values"),
    )


def _collect_attachment_failures(response: Any) -> list[str]:
    failures: list[str] = []

    if isinstance(response, str):
        if "failed" in response.lower():
            failures.append(response)
        return failures

    if isinstance(response, dict):
        for value in response.values():
            failures.extend(_collect_attachment_failures(value))
        return failures

    if isinstance(response, list):
        for item in response:
            failures.extend(_collect_attachment_failures(item))

    return failures


def _post_attachment_payload(module: Any, rest_send: Any, fabric_name: str, vrf_name: str, lan_attach_list: list[dict[str, Any]]) -> dict[str, Any]:
    if not lan_attach_list:
        return {}

    path = VrfLiteEndpoints.vrf_attachments_post(fabric_name)
    payload = {"attachments": lan_attach_list}
    try:
        response = _request_vrf_lite_payload(module, rest_send, path, HttpVerbEnum.POST, payload)
    except Exception as error:
        _raise_vrf_lite_error(
            msg="{0}; request_path={1}; request_payload={2}".format(error, path, json.dumps(payload, sort_keys=True)),
            request_path=path,
            request_payload=payload,
        )
    failures = _collect_attachment_failures(response)
    if failures:
        _raise_vrf_lite_error(
            msg="VRF Lite attachment API reported failure: {0}".format("; ".join(failures)),
            fabric=fabric_name,
            vrf_name=vrf_name,
            controller_failures=failures,
            response=response,
        )
    return response
