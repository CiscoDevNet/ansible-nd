# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import json
from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    request_with_verify_settings,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_endpoints import (
    VrfLiteEndpoints,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.runtime_payloads import (
    parse_instance_values,
    parse_vrf_lite_extension_values,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule as NDModuleV2


def _parse_vrf_template_vlan(vrf_object: dict[str, Any]) -> Optional[int]:
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


def _result_list(data: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _query_fabric_switches(module: Any, nd_v2: Any, fabric_name: str) -> dict[str, str]:
    """Return serial->mgmt-ip mapping from fabric switch inventory."""
    # TODO: Use a shared FabricContext/fabric inventory helper when available.
    path = VrfLiteEndpoints.fabric_switches(fabric_name)
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.GET)

    switches = _result_list(
        response if not isinstance(response, dict) else response.get("switches", response),
        ("switches", "DATA", "data", "items"),
    )

    sn_to_ip = {}
    for switch in switches:
        if not isinstance(switch, dict):
            continue
        serial = switch.get("serialNumber")
        mgmt_ip = switch.get("fabricManagementIp")
        if serial and mgmt_ip:
            sn_to_ip[str(serial).strip()] = str(mgmt_ip).strip()

    return sn_to_ip


def _query_vrfs(module: Any, nd_v2: Any, fabric_name: str) -> list[dict[str, Any]]:
    path = VrfLiteEndpoints.vrfs(fabric_name)
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.GET)

    return [item for item in _result_list(response, ("DATA", "data", "vrfs", "items")) if isinstance(item, dict)]


def _query_vrf_attachments(module: Any, nd_v2: Any, fabric_name: str, vrf_names: list[str]) -> list[dict[str, Any]]:
    if not vrf_names:
        return []

    path = VrfLiteEndpoints.vrf_attachments_query(fabric_name)
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.POST, {"vrfNames": vrf_names})

    return [item for item in _result_list(response, ("DATA", "data", "vrfs", "items")) if isinstance(item, dict)]


def _query_vrf_switch_details(
    module: Any,
    nd_v2: Any,
    fabric_name: str,
    vrf_name: str,
    serial_numbers: list[str],
) -> dict[str, dict[str, Any]]:
    """Return per-switch VRF attachment details keyed by serial number.

    This makes one additional API call per VRF that has attachments lacking
    ``extensionValues`` in the bulk list response (e.g. PENDING state rows).
    On fabrics with many VRFs this may add latency; it is skipped entirely
    when all attachments already carry ``extensionValues``.
    """
    if not serial_numbers:
        return {}

    path = VrfLiteEndpoints.vrf_switch(fabric_name, vrf_name, ",".join(serial_numbers))
    response = request_with_verify_settings(module, nd_v2, path, HttpVerbEnum.GET)

    detail_map: dict[str, dict[str, Any]] = {}
    for vrf_switch in _result_list(response, ("DATA", "data", "vrfs", "items")):
        if not isinstance(vrf_switch, dict):
            continue
        for switch_detail in vrf_switch.get("switchDetailsList") or []:
            if not isinstance(switch_detail, dict):
                continue

            serial_number = switch_detail.get("serialNumber")
            if not serial_number:
                continue

            detail_map[str(serial_number).strip()] = switch_detail

    return detail_map


def _value_from_attachment_or_detail(attach: dict[str, Any], detail: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in attach:
            value = attach.get(key)
            if value is not None:
                return value

    for key in keys:
        value = detail.get(key)
        if value is not None:
            return value

    return None


def _flatten_to_entries(nested: list[dict[str, Any]], module: Any = None) -> list[dict[str, Any]]:
    """Convert nested VRF list into a flat list of per-(vrf, switch) entries.

    Each entry has the shape expected by ``VrfLiteAttachmentEntry``:
    ``vrf_name``, ``switch_ip``, ``vlan_id``, ``deploy``, ``import_evpn_rt``,
    ``export_evpn_rt``, and ``extensions``. VRFs without attachments produce
    no entries; the state machine handles their absence via diff identifiers.
    """
    entries: list[dict[str, Any]] = []
    for vrf in nested or []:
        if not isinstance(vrf, dict):
            continue
        vrf_name = vrf.get("vrf_name")
        if not vrf_name:
            continue
        vrf_level_vlan = vrf.get("vlan_id")
        for attach in vrf.get("attach") or []:
            if not isinstance(attach, dict):
                continue
            switch_identifier = attach.get("ip_address")
            if not switch_identifier:
                continue
            switch_ip = switch_identifier
            mapping = {}
            if module is not None and isinstance(getattr(module, "params", None), dict):
                mapping = module.params.get("_ip_to_sn_mapping") or {}
            if switch_identifier in mapping:
                switch_ip = mapping[switch_identifier]
            entry: dict[str, Any] = {
                "vrf_name": vrf_name,
                "switch_ip": switch_ip,
                "vlan_id": vrf_level_vlan,
                "deploy": attach.get("deploy"),
                "import_evpn_rt": attach.get("import_evpn_rt"),
                "export_evpn_rt": attach.get("export_evpn_rt"),
            }
            extensions = attach.get("vrf_lite")
            if extensions:
                entry["extensions"] = extensions
            entries.append({k: v for k, v in entry.items() if v is not None})

    entries.sort(key=lambda item: (item.get("vrf_name", ""), item.get("switch_ip", "")))
    return entries


def query_vrf_lite_state(
    module: Any,
    fabric_name: str,
    filter_vrfs: Optional[set[str]] = None,
    flat: bool = False,
) -> list[dict[str, Any]]:
    """
    Query controller state and return normalized vrf-lite config shape.

    When ``flat=True`` returns a flat list of per-(vrf_name, switch_ip)
    attachment entries shaped for ``VrfLiteAttachmentEntry``. When
    ``flat=False`` (default) returns the legacy nested list of VRFs with an
    ``attach`` sub-list per VRF.
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
    switch_detail_map: dict[tuple[str, str], dict[str, Any]] = {}

    for vrf_attach in attachment_objects:
        vrf_name = vrf_attach.get("vrfName")
        if not vrf_name:
            continue

        vrf_name = str(vrf_name).strip()
        if filter_vrfs and vrf_name not in filter_vrfs:
            continue

        serials_to_enrich: list[str] = []
        for attach in vrf_attach.get("lanAttachList") or []:
            if not isinstance(attach, dict):
                continue

            if "extensionValues" in attach:
                continue

            attach_state = str(attach.get("lanAttachState") or attach.get("lanAttachedState") or "").upper()
            attached_value = attach.get("isLanAttached", attach.get("isAttached", False))
            is_attached = attached_value is True or str(attached_value).strip().lower() in ("true", "1", "yes")
            if not is_attached and attach_state not in ("PENDING", "OUT-OF-SYNC", "FAILED"):
                continue

            serial_number = attach.get("switchSerialNo") or attach.get("serialNumber")
            if serial_number:
                serials_to_enrich.append(str(serial_number).strip())

        for serial_number, switch_detail in _query_vrf_switch_details(
            module=module,
            nd_v2=nd_v2,
            fabric_name=fabric_name,
            vrf_name=vrf_name,
            serial_numbers=sorted(set(serials_to_enrich)),
        ).items():
            switch_detail_map[(vrf_name, serial_number)] = switch_detail

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
            switch_detail = switch_detail_map.get((vrf_name, serial_number), {})

            ip_address = attach.get("ipAddress")
            if ip_address:
                ip_address = str(ip_address).strip()
            elif serial_number:
                ip_address = sn_to_ip.get(serial_number, serial_number)
            else:
                continue

            attach_state = str(
                _value_from_attachment_or_detail(attach, switch_detail, "lanAttachState", "lanAttachedState") or ""
            ).upper()
            attached_value = attach.get(
                "isLanAttached",
                attach.get("isAttached", switch_detail.get("islanAttached", switch_detail.get("isLanAttached", False))),
            )
            is_attached = attached_value is True or str(attached_value).strip().lower() in ("true", "1", "yes")
            extension_values = _value_from_attachment_or_detail(attach, switch_detail, "extensionValues")
            # For VRF Lite, include entries that have extension values even if
            # not yet lan-attached (pending save/deploy state).
            has_extension_values = bool(
                extension_values and str(extension_values).strip()
                and str(extension_values).strip() != "[]"
            )
            if not is_attached and not has_extension_values:
                continue

            instance_values_raw = _value_from_attachment_or_detail(attach, switch_detail, "instanceValues")
            vrf_vlan_raw = _value_from_attachment_or_detail(attach, switch_detail, "vlanId", "vlan")
            attachment_vlan_raw = _value_from_attachment_or_detail(switch_detail, attach, "vlan", "vlanId")

            if serial_number:
                raw_vrf_attachment_map.setdefault(vrf_name, {})[serial_number] = {
                    "extension_values": extension_values,
                    "instance_values": instance_values_raw,
                    "vlan": attachment_vlan_raw,
                }

            instance_values = parse_instance_values(instance_values_raw)
            import_evpn_rt = instance_values.get("switchRouteTargetImportEvpn")
            export_evpn_rt = instance_values.get("switchRouteTargetExportEvpn")

            vrf_lite_list = parse_vrf_lite_extension_values(extension_values)
            managed_fields_present = bool(vrf_lite_list) or import_evpn_rt not in (None, "") or export_evpn_rt not in (None, "")
            if not managed_fields_present:
                continue

            deployed = attach_state not in ("OUT-OF-SYNC", "PENDING", "FAILED")
            if not deployed:
                not_in_sync_vrfs.add(vrf_name)
            else:
                entry["deploy"] = True

            if entry.get("vlan_id") is None:
                try:
                    if vrf_vlan_raw not in (None, ""):
                        entry["vlan_id"] = int(vrf_vlan_raw)
                except Exception:
                    pass

            attach_item = {
                "ip_address": ip_address,
                "deploy": deployed,
                "import_evpn_rt": import_evpn_rt if import_evpn_rt is not None else "",
                "export_evpn_rt": export_evpn_rt if export_evpn_rt is not None else "",
            }

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
    module.params["_vrf_lite_vrf_vlan_map"] = {
        item.get("vrf_name"): item.get("vlan_id")
        for item in result
        if item.get("vrf_name") and item.get("vlan_id") is not None
    }

    if flat:
        return _flatten_to_entries(result, module=module)
    return result
