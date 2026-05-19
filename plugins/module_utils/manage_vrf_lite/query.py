# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import json
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    request_with_verify_settings,
    _raise_vrf_lite_error,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.exceptions import (
    VrfLiteResourceError,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_payloads import (
    parse_instance_values,
    parse_vrf_lite_extension_values,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule as NDModuleV2
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError


def _coerce_list(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for key in ("DATA", "data", "vrfs", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def _parse_vrf_template_vlan(vrf_object: dict[str, Any]) -> int | None:
    template_cfg = vrf_object.get("vrfTemplateConfig")
    if not template_cfg:
        return None

    if isinstance(template_cfg, dict):
        parsed = template_cfg
    else:
        try:
            parsed = json.loads(str(template_cfg))
        except Exception:
            return None

    vlan = parsed.get("vrfVlanId")
    if vlan in (None, "", 0):
        return None

    try:
        return int(vlan)
    except Exception:
        return None


def _query_fabric_switches(module: Any, nd_v2: Any, fabric_name: str) -> dict[str, str]:
    """Return serial->mgmt-ip mapping from fabric switch inventory."""
    # TODO: Use a shared FabricContext/fabric inventory helper when available.
    path = VrfLiteEndpoints.fabric_switches(fabric_name)
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.GET)

    switches = _coerce_list(response if not isinstance(response, dict) else response.get("switches", response))

    sn_to_ip = {}
    for switch in switches:
        serial = switch.get("serialNumber")
        mgmt_ip = switch.get("fabricManagementIp")
        if serial and mgmt_ip:
            sn_to_ip[str(serial).strip()] = str(mgmt_ip).strip()

    return sn_to_ip


def _build_filter_set(config: list[dict[str, Any]]) -> set[str]:
    filters: set[str] = set()
    for item in config or []:
        if not isinstance(item, dict):
            continue
        vrf_name = item.get("vrf_name") or item.get("vrfName")
        if vrf_name:
            filters.add(str(vrf_name).strip())
    return filters


def _query_vrfs(module: Any, nd_v2: Any, fabric_name: str) -> list[dict[str, Any]]:
    path = VrfLiteEndpoints.vrfs(fabric_name)
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.GET)

    return _coerce_list(response)


def _query_vrf_attachments(module: Any, nd_v2: Any, fabric_name: str, vrf_names: list[str]) -> list[dict[str, Any]]:
    if not vrf_names:
        return []

    path = VrfLiteEndpoints.vrf_attachments_query(fabric_name, ",".join(vrf_names))
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.GET)

    return _coerce_list(response)


def query_vrf_lite_state(module: Any, fabric_name: str, filter_vrfs: set[str] | None = None) -> list[dict[str, Any]]:
    """
    Query controller state and return normalized vrf-lite config shape.
    """
    nd_v2 = NDModuleV2(module)

    sn_to_ip = _query_fabric_switches(module, nd_v2, fabric_name)
    ip_to_sn = {ip: sn for sn, ip in sn_to_ip.items()}

    vrf_objects = _query_vrfs(module, nd_v2, fabric_name)

    result_map: dict[str, dict[str, Any]] = {}
    known_vrfs: set[str] = set()
    for vrf in vrf_objects:
        vrf_name = vrf.get("vrfName") or vrf.get("vrf_name")
        if not vrf_name:
            continue

        vrf_name = str(vrf_name).strip()
        known_vrfs.add(vrf_name)

        if filter_vrfs and vrf_name not in filter_vrfs:
            continue

        result_map[vrf_name] = {
            "vrf_name": vrf_name,
            "vlan_id": _parse_vrf_template_vlan(vrf),
            "deploy": False,
            "attach": [],
        }

    attachment_objects = _query_vrf_attachments(
        module=module,
        nd_v2=nd_v2,
        fabric_name=fabric_name,
        vrf_names=sorted(result_map.keys()),
    )

    not_in_sync_vrfs: set[str] = set()
    raw_vrf_attachment_map: dict[str, dict[str, dict[str, Any]]] = {}

    for vrf_attach in attachment_objects:
        vrf_name = vrf_attach.get("vrfName")
        if not vrf_name:
            continue

        vrf_name = str(vrf_name).strip()
        if filter_vrfs and vrf_name not in filter_vrfs:
            continue

        entry = result_map.get(vrf_name)
        if entry is None:
            entry = {
                "vrf_name": vrf_name,
                "vlan_id": None,
                "deploy": False,
                "attach": [],
            }
            result_map[vrf_name] = entry

        attach_list = vrf_attach.get("lanAttachList") or []
        if not isinstance(attach_list, list):
            continue

        for attach in attach_list:
            if not isinstance(attach, dict):
                continue

            serial_number = attach.get("switchSerialNo") or attach.get("serialNumber")
            serial_number = str(serial_number).strip() if serial_number else ""

            ip_address = attach.get("ipAddress")
            if ip_address:
                ip_address = str(ip_address).strip()
            elif serial_number:
                ip_address = sn_to_ip.get(serial_number, serial_number)
            else:
                continue

            attach_state = str(attach.get("lanAttachState") or "").upper()
            attached_value = attach.get("isLanAttached", attach.get("isAttached", False))
            is_attached = attached_value is True or str(attached_value).strip().lower() in ("true", "1", "yes")
            # For VRF Lite, include entries that have extension values even if
            # not yet lan-attached (pending save/deploy state).
            has_extension_values = bool(
                attach.get("extensionValues") and str(attach.get("extensionValues")).strip()
                and str(attach.get("extensionValues")).strip() != "[]"
            )
            if not is_attached and not has_extension_values:
                continue

            if serial_number:
                raw_vrf_attachment_map.setdefault(vrf_name, {})[serial_number] = {
                    "extension_values": attach.get("extensionValues"),
                    "instance_values": attach.get("instanceValues"),
                    "vlan": attach.get("vlanId") if attach.get("vlanId") not in (None, "") else attach.get("vlan"),
                }

            instance_values = parse_instance_values(attach.get("instanceValues"))
            import_evpn_rt = instance_values.get("switchRouteTargetImportEvpn")
            export_evpn_rt = instance_values.get("switchRouteTargetExportEvpn")

            vrf_lite_list = parse_vrf_lite_extension_values(attach.get("extensionValues"))
            managed_fields_present = bool(vrf_lite_list) or import_evpn_rt not in (None, "") or export_evpn_rt not in (None, "")
            if not managed_fields_present:
                continue

            deployed = attach_state not in ("OUT-OF-SYNC", "PENDING", "FAILED")
            if not deployed:
                not_in_sync_vrfs.add(vrf_name)
            else:
                entry["deploy"] = True

            if entry.get("vlan_id") is None:
                vlan = attach.get("vlanId")
                if vlan in (None, ""):
                    vlan = attach.get("vlan")
                try:
                    if vlan not in (None, ""):
                        entry["vlan_id"] = int(vlan)
                except Exception:
                    pass

            attach_item = {
                "ip_address": ip_address,
                "deploy": deployed,
            }
            if import_evpn_rt not in (None, ""):
                attach_item["import_evpn_rt"] = import_evpn_rt
            if export_evpn_rt not in (None, ""):
                attach_item["export_evpn_rt"] = export_evpn_rt

            if vrf_lite_list:
                attach_item["vrf_lite"] = vrf_lite_list

            entry["attach"].append(attach_item)

    result = sorted(result_map.values(), key=lambda item: item.get("vrf_name", ""))
    for entry in result:
        entry["attach"] = sorted(entry.get("attach", []), key=lambda item: item.get("ip_address", ""))

    module.params["_ip_to_sn_mapping"] = ip_to_sn
    module.params["_sn_to_ip_mapping"] = sn_to_ip
    module.params["_not_in_sync_vrfs"] = sorted(not_in_sync_vrfs)
    module.params["_known_vrfs"] = sorted(known_vrfs)
    module.params["_raw_vrf_attachment_map"] = raw_vrf_attachment_map

    return result


def custom_vrf_lite_query_all(nrm: Any) -> list[dict[str, Any]]:
    """Query all normalized VRF Lite state for reconciliation workflows."""
    module = nrm.module
    fabric_name = module.params.get("fabric_name")
    state = module.params.get("state", "merged")

    if not fabric_name:
        raise ValueError("fabric_name must be set")

    if state == "gathered":
        config = module.params.get("_gather_filter_config") or []
    else:
        config = module.params.get("config") or []

    filter_vrfs = _build_filter_set(config)
    try:
        have = query_vrf_lite_state(
            module=module,
            fabric_name=fabric_name,
            filter_vrfs=(filter_vrfs if filter_vrfs else None),
        )
    except NDModuleError as error:
        error_dict = error.to_dict()
        if "msg" in error_dict:
            error_dict["api_error_msg"] = error_dict.pop("msg")
        _raise_vrf_lite_error(msg="Failed to query VRF Lite state: {0}".format(error.msg), fabric=fabric_name, **error_dict)
    except VrfLiteResourceError:
        raise
    except Exception as error:
        _raise_vrf_lite_error(
            msg="Failed to query VRF Lite state: {0}".format(str(error)),
            fabric=fabric_name,
            exception_type=type(error).__name__,
        )

    module.params["_have"] = have
    if state in ("deleted", "overridden"):
        have = [item for item in have if item.get("attach")]
        module.params["_have"] = have

    return have
