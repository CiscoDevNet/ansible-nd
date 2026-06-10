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
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender as NDSender


class _VrfLiteListPayloadRestSend(RestSend):
    """RestSend variant for the NDFC VRF attachment API's top-level list body."""

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


class _VrfLiteListPayloadSender(NDSender):
    """Sender variant for the NDFC VRF attachment API's top-level list body."""

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


def _request_vrf_lite_payload(nd_v2: Any, path: str, verb: HttpVerbEnum, payload: Any) -> Any:
    """Send VRF Lite payloads without widening the shared REST sender contract."""
    if not isinstance(payload, list):
        return nd_v2.request(path, verb, payload)

    if not hasattr(nd_v2, "_get_rest_send") or not hasattr(nd_v2, "module"):
        return nd_v2.request(path, verb, payload)

    base_rest_send = nd_v2._get_rest_send()
    rest_send = _VrfLiteListPayloadRestSend(
        {
            "check_mode": nd_v2.module.check_mode,
            "state": nd_v2.params.get("state"),
        }
    )
    rest_send.timeout = base_rest_send.timeout
    rest_send.send_interval = base_rest_send.send_interval
    rest_send.unit_test = base_rest_send.unit_test

    sender = _VrfLiteListPayloadSender()
    sender.ansible_module = nd_v2.module
    rest_send.sender = sender
    response_handler = ResponseHandler()
    rest_send.response_handler = response_handler

    try:
        rest_send.path = path
        rest_send.verb = verb
        rest_send.payload = payload
        rest_send.commit()
    except (TypeError, ValueError) as error:
        raise ValueError("Error in VRF Lite request: {0}".format(error)) from error

    response = rest_send.response_current
    result = rest_send.result_current

    nd_v2.method = verb.value
    nd_v2.path = path
    nd_v2.response = response.get("MESSAGE")
    nd_v2.status = response.get("RETURN_CODE", -1)
    nd_v2.url = response.get("REQUEST_PATH")

    if not result.get("success", False):
        response_data = response.get("DATA")
        raw = None
        response_payload = None
        if isinstance(response_data, dict):
            if "raw_response" in response_data:
                raw = response_data["raw_response"]
            else:
                response_payload = response_data

        error_msg = response_handler.error_message or "Unknown error"

        _raise_vrf_lite_error(
            msg="{0}; request_payload={1}".format(error_msg, json.dumps(payload, sort_keys=True)),
            status=nd_v2.status,
            request_payload=payload,
            response_payload=response_payload,
            raw=raw,
        )

    return response.get("DATA", {})


def _ensure_vrf_exists(module: Any, vrf_name: str) -> None:
    known_vrfs = module.params.get("_known_vrfs") or []
    if vrf_name in known_vrfs:
        return

    fabric_name = module.params.get("fabric_name")
    refreshed = query_vrf_lite_state(module=module, fabric_name=fabric_name, filter_vrfs={vrf_name})
    if not refreshed:
        _raise_vrf_lite_error(
            msg="VRF '{0}' does not exist in fabric '{1}'.".format(vrf_name, fabric_name),
            fabric=fabric_name,
            vrf_name=vrf_name,
        )


def _reserve_dot1q_if_needed(nd_v2: Any, fabric_name: str, vrf_name: str, serial_number: str, lite_item: dict[str, Any]) -> dict[str, Any]:
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

    response = nd_v2.request(VrfLiteEndpoints.reserve_id(fabric_name), HttpVerbEnum.POST, payload)

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


def build_attach_payload_for_entry(module: Any, nd_v2: Any, entry: Any) -> dict[str, Any]:
    """Build one NDFC attachment row for one flat VRF Lite entry."""
    serial_number = _resolve_serial(module, entry.switch_ip)
    raw_attach = _raw_attachment_entry(module, entry.vrf_name, serial_number)
    vlan_id = _entry_vlan_id(module, entry, raw_attach)

    resolved_extensions = []
    for lite_item in vrf_lite_items_to_config(_entry_extensions(entry)):
        resolved_extensions.append(_reserve_dot1q_if_needed(nd_v2, module.params.get("fabric_name"), entry.vrf_name, serial_number, lite_item))

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
    """Build one NDFC row that removes VRF Lite data for one flat entry."""
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


def _post_attachment_payload(nd_v2: Any, fabric_name: str, vrf_name: str, lan_attach_list: list[dict[str, Any]]) -> dict[str, Any]:
    if not lan_attach_list:
        return {}

    path = VrfLiteEndpoints.vrf_attachments_post(fabric_name)
    payload = {"attachments": lan_attach_list}
    try:
        response = _request_vrf_lite_payload(nd_v2, path, HttpVerbEnum.POST, payload)
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
