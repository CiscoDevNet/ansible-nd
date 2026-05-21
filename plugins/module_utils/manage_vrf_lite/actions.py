# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import ipaddress
from collections.abc import Callable
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _is_update_needed,
    _raise_vrf_lite_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.query import (
    query_vrf_lite_state,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_payloads import (
    build_instance_values,
    build_vrf_lite_extension_values,
    normalize_vrf_lite_list,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.validation import (
    validate_vrf_lite_write_guardrails,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule as NDModuleV2
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

        error_msg = "Unknown error"
        error_msg = response_handler.error_message or error_msg

        _raise_vrf_lite_error(
            msg=error_msg,
            status=nd_v2.status,
            request_payload=payload,
            response_payload=response_payload,
            raw=raw,
        )

    return response.get("DATA", {})


def _is_ip_literal(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    candidate = value.strip()
    if not candidate:
        return False
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _resolve_serial(module: Any, switch_identifier: str) -> str:
    """Resolve management IP to serial when mapping is available."""
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
            msg="Switch identifier '{0}' appears to be an IP, but it could not be resolved to a serial number.".format(text),
            switch_id=text,
        )

    return text


def _mark_changed_vrf(module: Any, vrf_name: str) -> None:
    changed_vrfs = module.params.get("_changed_vrfs")
    if not isinstance(changed_vrfs, list):
        changed_vrfs = []

    if vrf_name not in changed_vrfs:
        changed_vrfs.append(vrf_name)

    module.params["_changed_vrfs"] = changed_vrfs


def _ensure_vrf_exists(module: Any, vrf_name: str) -> None:
    known_vrfs = module.params.get("_known_vrfs") or []
    if vrf_name in known_vrfs:
        return

    fabric_name = module.params.get("fabric_name")
    refreshed = query_vrf_lite_state(module=module, fabric_name=fabric_name, filter_vrfs=set([vrf_name]))
    if not refreshed:
        _raise_vrf_lite_error(
            msg="VRF '{0}' does not exist in fabric '{1}'.".format(vrf_name, fabric_name),
            fabric=fabric_name,
            vrf_name=vrf_name,
        )


def _reserve_dot1q_if_needed(nd_v2: Any, vrf_name: str, serial_number: str, lite_item: dict[str, Any]) -> dict[str, Any]:
    if lite_item.get("dot1q") not in (None, ""):
        return lite_item

    interface = lite_item.get("interface")
    if not interface:
        return lite_item

    payload = {
        "scopeType": "DeviceInterface",
        "usageType": "TOP_DOWN_L3_DOT1Q",
        "serialNumber": serial_number,
        "ifName": interface,
        "allocatedTo": vrf_name,
    }

    response = nd_v2.request(VrfLiteEndpoints.reserve_id(), HttpVerbEnum.POST, payload)

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


def _get_current_vrf_entry(module: Any, fabric_name: str, vrf_name: str) -> dict[str, Any] | None:
    current = query_vrf_lite_state(module=module, fabric_name=fabric_name, filter_vrfs=set([vrf_name]))
    if not current:
        return None
    return current[0]


def _build_have_attachment_map(module: Any, current_vrf: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    have_map: dict[str, dict[str, Any]] = {}

    if not current_vrf:
        return have_map

    vlan_id = current_vrf.get("vlan_id")
    for attach in current_vrf.get("attach", []) or []:
        switch_identifier = attach.get("ip_address")
        serial_number = _resolve_serial(module, switch_identifier)
        if not serial_number:
            continue

        have_map[serial_number] = {
            "vlan_id": vlan_id,
            "import_evpn_rt": attach.get("import_evpn_rt") or "",
            "export_evpn_rt": attach.get("export_evpn_rt") or "",
            "vrf_lite": normalize_vrf_lite_list(attach.get("vrf_lite") or []),
        }

    return have_map


def _get_delete_config_for_vrf(module: Any, vrf_name: str) -> dict[str, Any] | None:
    """Return the user's delete intent for this VRF, when state is deleted."""
    if module.params.get("state") != "deleted":
        return None

    for item in module.params.get("config") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("vrf_name", "")).strip() == vrf_name:
            return item

    return None


def _attachment_serials(module: Any, attachments: Any, have_map: dict[str, dict[str, Any]]) -> list[str]:
    serials: list[str] = []
    seen: set[str] = set()

    for attach in attachments or []:
        switch_identifier = attach.get("ip_address") if isinstance(attach, dict) else getattr(attach, "ip_address", None)
        serial_number = _resolve_serial(module, switch_identifier)
        if serial_number in have_map and serial_number not in seen:
            serials.append(serial_number)
            seen.add(serial_number)

    return serials


def _serials_to_detach_for_delete(module: Any, vrf_name: str, model_instance: Any, have_map: dict[str, dict[str, Any]]) -> list[str]:
    delete_config = _get_delete_config_for_vrf(module, vrf_name)
    if delete_config is not None:
        attachments = delete_config.get("attach") or []
        if attachments:
            return _attachment_serials(module, attachments, have_map)
        return sorted(have_map.keys())

    if model_instance.attach:
        return _attachment_serials(module, model_instance.attach, have_map)

    return sorted(have_map.keys())


def _resolve_vrf_vlan_id(model_instance: Any, current_vrf: dict[str, Any] | None) -> int:
    if model_instance.vlan_id is not None:
        return int(model_instance.vlan_id)

    if isinstance(current_vrf, dict):
        current_vlan = current_vrf.get("vlan_id")
        if current_vlan not in (None, ""):
            try:
                return int(current_vlan)
            except (TypeError, ValueError):
                pass

    _raise_vrf_lite_error(
        msg=("vlan_id is required for VRF '{0}' because the current VRF VLAN " "could not be determined from the controller.").format(model_instance.vrf_name),
        vrf_name=model_instance.vrf_name,
    )


def _build_want_attachment_maps(
    module: Any,
    nd_v2: Any,
    model_instance: Any,
    current_vrf: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Return (want_normalized_map, want_payload_map) keyed by serial number."""

    want_normalized: dict[str, dict[str, Any]] = {}
    want_payloads: dict[str, dict[str, Any]] = {}

    vrf_name = model_instance.vrf_name
    raw_vrf_attachment_map = module.params.get("_raw_vrf_attachment_map") or {}
    raw_attachment_map = raw_vrf_attachment_map.get(vrf_name, {}) if isinstance(raw_vrf_attachment_map, dict) else {}

    attachments = model_instance.attach or []
    vlan_id = None
    if attachments:
        vlan_id = _resolve_vrf_vlan_id(model_instance=model_instance, current_vrf=current_vrf)

    for attach in attachments:
        serial_number = _resolve_serial(module, attach.ip_address)
        if not serial_number:
            continue

        lite_items = [item.model_dump(by_alias=False, exclude_none=True) for item in (attach.vrf_lite or [])]
        lite_items = normalize_vrf_lite_list(lite_items)
        resolved_lite_items: list[dict[str, Any]] = []
        for lite_item in lite_items:
            resolved_lite_items.append(_reserve_dot1q_if_needed(nd_v2, vrf_name, serial_number, lite_item))

        raw_attach = raw_attachment_map.get(serial_number) if isinstance(raw_attachment_map, dict) else None
        extension_values = build_vrf_lite_extension_values(
            resolved_lite_items,
            existing_extension_values=raw_attach.get("extension_values") if isinstance(raw_attach, dict) else None,
        )
        instance_values = build_instance_values(attach.import_evpn_rt, attach.export_evpn_rt)

        want_normalized[serial_number] = {
            "vlan_id": vlan_id,
            "import_evpn_rt": attach.import_evpn_rt or "",
            "export_evpn_rt": attach.export_evpn_rt or "",
            "vrf_lite": normalize_vrf_lite_list(resolved_lite_items),
        }

        want_payloads[serial_number] = {
            "fabric": module.params.get("fabric_name"),
            "vrfName": vrf_name,
            "serialNumber": serial_number,
            "vlan": vlan_id if vlan_id is not None else 0,
            "deployment": model_instance.deploy is not False and attach.deploy is not False,
            "isAttached": True,
            "extensionValues": extension_values,
            "instanceValues": instance_values,
            "freeformConfig": "",
        }

    return want_normalized, want_payloads


def _build_detach_payload(module: Any, vrf_name: str, serial_number: str, vlan_id: int | None) -> dict[str, Any]:
    return {
        "fabric": module.params.get("fabric_name"),
        "vrfName": vrf_name,
        "serialNumber": serial_number,
        "vlan": vlan_id if vlan_id is not None else 0,
        "deployment": False,
        "isAttached": False,
        "extensionValues": "",
        "instanceValues": build_instance_values("", ""),
        "freeformConfig": "",
    }


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
    payload = [{"vrfName": vrf_name, "lanAttachList": lan_attach_list}]
    response = _request_vrf_lite_payload(nd_v2, path, HttpVerbEnum.POST, payload)
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


class AttachmentReconciler:
    """Build the attachment POST payloads needed to reconcile one VRF."""

    def __init__(self, module: Any, nd_v2: Any, model_instance: Any, current_vrf: dict[str, Any] | None) -> None:
        self.module = module
        self.nd_v2 = nd_v2
        self.model_instance = model_instance
        self.current_vrf = current_vrf
        self.vrf_name = model_instance.vrf_name
        self.have_map = _build_have_attachment_map(module, current_vrf)

    def sync_payloads(self, replace_mode: bool) -> list[dict[str, Any]]:
        changes: list[dict[str, Any]] = []
        want_map, want_payloads = _build_want_attachment_maps(self.module, self.nd_v2, self.model_instance, self.current_vrf)

        for serial_number, want_cfg in want_map.items():
            have_cfg = self.have_map.get(serial_number)
            if have_cfg is None or _is_update_needed(want_cfg, have_cfg):
                changes.append(want_payloads[serial_number])

        if replace_mode:
            vlan_for_detach = self.current_vrf.get("vlan_id") if self.current_vrf else None
            for serial_number in sorted(self.have_map.keys()):
                if serial_number in want_map:
                    continue
                changes.append(_build_detach_payload(self.module, self.vrf_name, serial_number, vlan_for_detach))

        return changes

    def detach_payloads(self) -> list[dict[str, Any]]:
        if not self.have_map:
            return []

        serials_to_detach = _serials_to_detach_for_delete(self.module, self.vrf_name, self.model_instance, self.have_map)
        vlan_for_detach = self.current_vrf.get("vlan_id") if self.current_vrf else None
        return [_build_detach_payload(self.module, self.vrf_name, serial, vlan_for_detach) for serial in serials_to_detach]


def _sync_vrf_attachments(module: Any, model_instance: Any, replace_mode: bool) -> dict[str, Any]:
    fabric_name = module.params.get("fabric_name")
    vrf_name = model_instance.vrf_name

    _ensure_vrf_exists(module, vrf_name)
    validate_vrf_lite_write_guardrails(module=module, model_instance=model_instance)

    nd_v2 = NDModuleV2(module)
    current_vrf = _get_current_vrf_entry(module, fabric_name, vrf_name)

    reconciler = AttachmentReconciler(module=module, nd_v2=nd_v2, model_instance=model_instance, current_vrf=current_vrf)
    changes = reconciler.sync_payloads(replace_mode=replace_mode)

    if not changes:
        return current_vrf or {}

    response = _post_attachment_payload(nd_v2, fabric_name, vrf_name, changes)
    _mark_changed_vrf(module, vrf_name)
    return response


def custom_vrf_lite_create(model_instance: Any, module: Any) -> dict[str, Any]:
    if module.check_mode:
        return model_instance.to_config()

    return _sync_vrf_attachments(module=module, model_instance=model_instance, replace_mode=False)


def custom_vrf_lite_update(model_instance: Any, module: Any) -> dict[str, Any]:
    if module.check_mode:
        return model_instance.to_config()

    state = module.params.get("state")
    replace_mode = state in ("replaced", "overridden")
    return _sync_vrf_attachments(module=module, model_instance=model_instance, replace_mode=replace_mode)


def custom_vrf_lite_delete(model_instance: Any, module: Any) -> bool:
    if module.check_mode:
        return True

    fabric_name = module.params.get("fabric_name")
    vrf_name = model_instance.vrf_name

    current_vrf = _get_current_vrf_entry(module, fabric_name, vrf_name)
    if not current_vrf:
        return False

    nd_v2 = NDModuleV2(module)
    reconciler = AttachmentReconciler(module=module, nd_v2=nd_v2, model_instance=model_instance, current_vrf=current_vrf)
    if not reconciler.have_map:
        return False

    detach_payloads = reconciler.detach_payloads()
    if not detach_payloads:
        return False

    _post_attachment_payload(nd_v2, fabric_name, vrf_name, detach_payloads)

    _mark_changed_vrf(module, vrf_name)
    return True


def _wrap_action_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except NDModuleError as error:
            error_dict = error.to_dict()
            if "msg" in error_dict:
                error_dict["api_error_msg"] = error_dict.pop("msg")
            _raise_vrf_lite_error(msg=error.msg, **error_dict)
        except VrfLiteResourceError:
            raise
        except Exception as error:
            _raise_vrf_lite_error(msg=str(error), exception_type=type(error).__name__)

    return wrapper


custom_vrf_lite_create = _wrap_action_errors(custom_vrf_lite_create)
custom_vrf_lite_update = _wrap_action_errors(custom_vrf_lite_update)
custom_vrf_lite_delete = _wrap_action_errors(custom_vrf_lite_delete)
