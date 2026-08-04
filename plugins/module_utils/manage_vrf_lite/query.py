# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import json
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
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


def _coerce_vlan(value: Any) -> int | None:
    if value in (None, "", 0):
        return None
    try:
        return int(value)
    except Exception:
        return None


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

    return _coerce_vlan(parsed.get("vrfVlanId"))


def _resolve_vrf_vlan(vrf_object: dict[str, Any]) -> int | None:
    """Resolve the VRF VLAN id from a controller VRF object.

    Prefer the current top-level ``vlanId`` field returned by the OpenAPI VRF
    object and fall back to the legacy serialized ``vrfTemplateConfig.vrfVlanId``
    for older controller response shapes. Without this, a VRF returned in the
    current shape (``vlanId`` set, ``vrfTemplateConfig`` empty) would resolve to
    a ``None`` VLAN and break otherwise-valid attach/detach payloads.
    """
    top_level = _coerce_vlan(vrf_object.get("vlanId"))
    if top_level is not None:
        return top_level
    # TODO(4.2.1) vrf-lite-vlan-shape-drift: fall back to the legacy serialized
    # ``vrfTemplateConfig.vrfVlanId`` for older controller response shapes.
    # Remove once all supported controllers return the top-level ``vlanId``
    # (see bug-tracker vault note).
    return _parse_vrf_template_vlan(vrf_object)


def _result_list(data: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _query_fabric_switches(module: Any, rest_send: Any, fabric_name: str) -> dict[str, str]:
    """Return serial->mgmt-ip mapping from fabric switch inventory."""
    fabric_context = FabricContext(rest_send=rest_send, fabric_name=fabric_name)
    inventory = fabric_context.switch_inventory_by_id
    module.params["_fabric_switch_inventory"] = inventory
    # Keep an explicit loaded marker because an empty fabric inventory is a
    # valid, authoritative result.  Truthiness alone cannot distinguish that
    # result from an inventory that has not been queried yet.
    module.params["_fabric_switch_inventory_loaded"] = True
    module.params["_fabric_switch_inventory_normalized"] = False
    return {str(serial).strip(): str(switch.get("fabricManagementIp")).strip() for serial, switch in inventory.items() if switch.get("fabricManagementIp")}


def _query_vrfs(module: Any, rest_send: Any, fabric_name: str) -> list[dict[str, Any]]:
    path = VrfLiteEndpoints.vrfs(fabric_name)
    response = request_with_verify_settings(module, rest_send, path, HttpVerbEnum.GET)

    return [item for item in _result_list(response, ("DATA", "data", "vrfs", "items")) if isinstance(item, dict)]


def _query_vrf_attachments(module: Any, rest_send: Any, fabric_name: str, vrf_names: list[str]) -> list[dict[str, Any]]:
    if not vrf_names:
        return []

    path = VrfLiteEndpoints.vrf_attachments_query(fabric_name, ",".join(vrf_names))
    response = request_with_verify_settings(module, rest_send, path, HttpVerbEnum.GET)
    attachments = _result_list(response, ("attachments", "DATA", "data", "items"))
    # TODO(4.2.1) vrf-lite-attachments-flat-shape-drift: some controller versions
    # return a flat per-switch attachment list without the ``lanAttachList``
    # grouping, so rows are regrouped by ``vrfName`` here. Remove once the
    # response shape is stable (see bug-tracker vault note).
    if attachments and all(isinstance(item, dict) and "vrfName" in item and "lanAttachList" not in item for item in attachments):
        grouped: dict[str, list[dict[str, Any]]] = {}
        for item in attachments:
            vrf_name = str(item.get("vrfName") or "").strip()
            if vrf_name:
                grouped.setdefault(vrf_name, []).append(item)
        return [{"vrfName": vrf_name, "lanAttachList": items} for vrf_name, items in sorted(grouped.items())]

    return [item for item in _result_list(response, ("DATA", "data", "vrfs", "items", "attachments")) if isinstance(item, dict)]


def _vrf_lite_switch_detail_cache_key(fabric_name: str, vrf_name: str, serial_number: str) -> str:
    return "{0}\0{1}\0{2}".format(fabric_name, vrf_name, serial_number)


def _query_vrf_switch_details_bulk(
    module: Any,
    rest_send: Any,
    fabric_name: str,
    serials_by_vrf: dict[str, list[str]],
) -> dict[tuple[str, str], dict[str, Any]]:
    """Return per-(vrf, switch) attachment details from a single batched request.

    The ``vrf-names`` and ``serial-numbers`` query params are both plural, so
    every VRF that has attachments lacking ``extensionValues`` in the bulk list
    response (e.g. PENDING state rows) is enriched with ONE cross-VRF GET rather
    than one request per VRF -- mirroring how the write-path validation prefetch
    batches serial numbers. Each returned object is attributed to its VRF by the
    ``vrfName`` it carries and keyed by ``(vrf_name, serial_number)``. Results
    are memoized in the shared ``_vrf_lite_switch_detail_cache`` so repeated
    queries never re-fetch the same pair. The request is skipped entirely when
    every requested pair is already cached.
    """
    normalized: dict[str, list[str]] = {}
    for vrf_name, serial_numbers in serials_by_vrf.items():
        serials = sorted({str(serial_number).strip() for serial_number in serial_numbers if str(serial_number).strip()})
        if serials:
            normalized[str(vrf_name).strip()] = serials
    if not normalized:
        return {}

    cache = module.params.get("_vrf_lite_switch_detail_cache")
    if not isinstance(cache, dict):
        cache = {}
        module.params["_vrf_lite_switch_detail_cache"] = cache

    missing_by_vrf: dict[str, list[str]] = {}
    for vrf_name, serials in normalized.items():
        missing = [serial_number for serial_number in serials if _vrf_lite_switch_detail_cache_key(fabric_name, vrf_name, serial_number) not in cache]
        if missing:
            missing_by_vrf[vrf_name] = missing

    if missing_by_vrf:
        vrf_names = sorted(missing_by_vrf)
        union_serials = sorted({serial_number for serials in missing_by_vrf.values() for serial_number in serials})
        path = VrfLiteEndpoints.vrf_switch(fabric_name, ",".join(vrf_names), ",".join(union_serials))
        response = request_with_verify_settings(module, rest_send, path, HttpVerbEnum.GET)

        returned: dict[tuple[str, str], dict[str, Any]] = {}
        for vrf_switch in _result_list(response, ("DATA", "data", "vrfs", "items")):
            if not isinstance(vrf_switch, dict):
                continue
            # Attribute each switch detail to its VRF via the returned ``vrfName``;
            # fall back to the sole requested VRF only when the response omits it.
            returned_vrf = str(vrf_switch.get("vrfName") or "").strip()
            if not returned_vrf and len(vrf_names) == 1:
                returned_vrf = vrf_names[0]
            if not returned_vrf:
                continue
            for switch_detail in vrf_switch.get("switchDetailsList") or []:
                if not isinstance(switch_detail, dict):
                    continue

                serial_number = switch_detail.get("serialNumber")
                if not serial_number:
                    continue

                returned[(returned_vrf, str(serial_number).strip())] = switch_detail

        for vrf_name, serials in missing_by_vrf.items():
            for serial_number in serials:
                cache[_vrf_lite_switch_detail_cache_key(fabric_name, vrf_name, serial_number)] = returned.get((vrf_name, serial_number), {})

    detail_map: dict[tuple[str, str], dict[str, Any]] = {}
    for vrf_name, serials in normalized.items():
        for serial_number in serials:
            cached_detail = cache.get(_vrf_lite_switch_detail_cache_key(fabric_name, vrf_name, serial_number))
            if isinstance(cached_detail, dict) and cached_detail:
                detail_map[(vrf_name, serial_number)] = cached_detail
    return detail_map


def _query_vrf_switch_details(
    module: Any,
    rest_send: Any,
    fabric_name: str,
    vrf_name: str,
    serial_numbers: list[str],
) -> dict[str, dict[str, Any]]:
    """Return per-switch VRF attachment details keyed by serial number.

    Thin single-VRF wrapper over :func:`_query_vrf_switch_details_bulk` used by
    the write-path validation prefetch, which resolves one VRF group at a time.
    Returns an entry for every requested serial (``{}`` when the controller has
    no detail for it), preserving the original per-VRF contract.
    """
    vrf_key = str(vrf_name).strip()
    normalized_serials = sorted({str(serial_number).strip() for serial_number in serial_numbers if str(serial_number).strip()})
    if not normalized_serials:
        return {}

    bulk = _query_vrf_switch_details_bulk(
        module=module,
        rest_send=rest_send,
        fabric_name=fabric_name,
        serials_by_vrf={vrf_key: normalized_serials},
    )

    detail_map: dict[str, dict[str, Any]] = {}
    for serial_number in normalized_serials:
        detail = bulk.get((vrf_key, serial_number))
        detail_map[serial_number] = detail if isinstance(detail, dict) else {}
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
    rest_send: Any,
    fabric_name: str,
    filter_vrfs: set[str] | None = None,
    flat: bool = False,
) -> list[dict[str, Any]]:
    """
    Query controller state and return normalized vrf-lite config shape.

    When ``flat=True`` returns a flat list of per-(vrf_name, switch_ip)
    attachment entries shaped for ``VrfLiteAttachmentEntry``. When
    ``flat=False`` (default) returns the legacy nested list of VRFs with an
    ``attach`` sub-list per VRF.
    """
    sn_to_ip = _query_fabric_switches(module, rest_send, fabric_name)
    ip_to_sn = {ip: sn for sn, ip in sn_to_ip.items()}

    vrf_objects = _query_vrfs(module, rest_send, fabric_name)

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
            "vlan_id": _resolve_vrf_vlan(vrf),
            "deploy": False,
            "attach": [],
        }

    attachment_objects = _query_vrf_attachments(
        module=module,
        rest_send=rest_send,
        fabric_name=fabric_name,
        vrf_names=sorted(result_map.keys()),
    )

    not_in_sync_vrfs: set[str] = set()
    raw_vrf_attachment_map: dict[str, dict[str, dict[str, Any]]] = {}

    # First pass: collect, across every VRF, the switches whose attachment rows
    # arrived without ``extensionValues`` so they can be enriched together. The
    # ``vrf-names`` query param is plural, so these are fetched with one batched
    # cross-VRF request below instead of one GET per VRF (PR #281 review).
    serials_by_vrf: dict[str, list[str]] = {}
    for vrf_attach in attachment_objects:
        vrf_name = vrf_attach.get("vrfName")
        if not vrf_name:
            continue

        vrf_name = str(vrf_name).strip()
        if filter_vrfs and vrf_name not in filter_vrfs:
            continue

        # TODO(4.2.1) vrf-lite-pending-extensionvalues-dropped: the bulk
        # attachment list omits ``extensionValues`` for PENDING rows, so each
        # affected switch is enriched with the batched switch-detail GET below.
        # Remove the enrichment once the bulk list returns extensionValues for
        # all states (see bug-tracker vault note).
        for attach in vrf_attach.get("lanAttachList") or []:
            if not isinstance(attach, dict):
                continue

            if "extensionValues" in attach:
                continue

            # TODO(4.2.1) vrf-lite-attach-key-spelling-drift: controller versions
            # disagree on attachment key spellings, so several are probed here and
            # in the main loop below. Remove once the keys are stable (see vault note).
            attach_state = str(attach.get("lanAttachState") or attach.get("lanAttachedState") or "").upper()
            attached_value = attach.get("isLanAttached", attach.get("isAttached", attach.get("attach", False)))
            is_attached = attached_value is True or str(attached_value).strip().lower() in ("true", "1", "yes")
            if not is_attached and attach_state not in ("PENDING", "OUT-OF-SYNC", "FAILED"):
                continue

            serial_number = attach.get("switchSerialNo") or attach.get("serialNumber") or attach.get("switchId")
            if serial_number:
                serials_by_vrf.setdefault(vrf_name, []).append(str(serial_number).strip())

    switch_detail_map = _query_vrf_switch_details_bulk(
        module=module,
        rest_send=rest_send,
        fabric_name=fabric_name,
        serials_by_vrf=serials_by_vrf,
    )

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

            serial_number = attach.get("switchSerialNo") or attach.get("serialNumber") or attach.get("switchId")
            serial_number = str(serial_number).strip() if serial_number else ""
            switch_detail = switch_detail_map.get((vrf_name, serial_number), {})

            ip_address = attach.get("ipAddress")
            if ip_address:
                ip_address = str(ip_address).strip()
            elif serial_number:
                ip_address = sn_to_ip.get(serial_number, serial_number)
            else:
                continue

            # TODO(4.2.1) vrf-lite-attach-key-spelling-drift: see note in the
            # enrichment loop; also probes the lowercase-l ``islanAttached``
            # variant from the switch-detail response.
            attach_state = str(_value_from_attachment_or_detail(attach, switch_detail, "lanAttachState", "lanAttachedState") or "").upper()
            attached_value = attach.get(
                "isLanAttached",
                attach.get(
                    "isAttached",
                    attach.get("attach", switch_detail.get("islanAttached", switch_detail.get("isLanAttached", False))),
                ),
            )
            is_attached = attached_value is True or str(attached_value).strip().lower() in ("true", "1", "yes")
            extension_values = _value_from_attachment_or_detail(attach, switch_detail, "extensionValues")
            # For VRF Lite, include entries that have extension values even if
            # not yet lan-attached (pending save/deploy state).
            has_extension_values = bool(extension_values and str(extension_values).strip() and str(extension_values).strip() != "[]")
            if not is_attached and not has_extension_values:
                continue

            instance_values_raw = _value_from_attachment_or_detail(attach, switch_detail, "instanceValues")
            freeform_config = _value_from_attachment_or_detail(attach, switch_detail, "freeformConfig")
            vrf_vlan_raw = _value_from_attachment_or_detail(attach, switch_detail, "vlanId", "vlan")
            attachment_vlan_raw = _value_from_attachment_or_detail(switch_detail, attach, "vlan", "vlanId")

            if serial_number:
                raw_vrf_attachment_map.setdefault(vrf_name, {})[serial_number] = {
                    "extension_values": extension_values,
                    "instance_values": instance_values_raw,
                    "freeform_config": freeform_config,
                    "vlan": attachment_vlan_raw,
                }

            instance_values = parse_instance_values(instance_values_raw)
            import_evpn_rt = instance_values.get("switchRouteTargetImportEvpn") or instance_values.get("evpnRouteTargetImport")
            export_evpn_rt = instance_values.get("switchRouteTargetExportEvpn") or instance_values.get("evpnRouteTargetExport")

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
    module.params["_known_vrfs_loaded"] = True
    module.params["_raw_vrf_attachment_map"] = raw_vrf_attachment_map
    module.params["_vrf_lite_vrf_vlan_map"] = {
        item.get("vrf_name"): item.get("vlan_id") for item in result if item.get("vrf_name") and item.get("vlan_id") is not None
    }

    if flat:
        return _flatten_to_entries(result, module=module)
    return result
