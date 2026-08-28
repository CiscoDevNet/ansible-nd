# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import json
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrf_lite.vrf_lite_model import (
    VrfLiteConnectionModel,
)


def vrf_lite_items_to_config(vrf_lite_items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in vrf_lite_items or []:
        try:
            model = VrfLiteConnectionModel.model_validate(item, by_alias=True, by_name=True)
        except ValidationError:
            continue
        data = model.model_dump(by_alias=False, exclude_none=True)
        items.append({key: value for key, value in data.items() if value != ""})
    return sorted(items, key=lambda i: (str(i.get("interface", "")).lower(), int(i.get("dot1q") or 0)))


def _json_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value in (None, ""):
        return None
    try:
        return json.loads(str(value))
    except Exception:
        return None


def build_vrf_lite_extension_values(
    vrf_lite_items: list[dict[str, Any]] | None,
    existing_extension_values: Any = None,
    prototype_values_by_interface: dict[str, dict[str, Any]] | None = None,
) -> str:
    """
    Build extensionValues string expected by top-down VRF attachment APIs.
    """
    existing_outer = _json_value(existing_extension_values)
    if isinstance(existing_outer, dict):
        existing_outer = dict(existing_outer)
    else:
        existing_outer = {}

    configured_items = vrf_lite_items_to_config(vrf_lite_items)
    if not configured_items:
        if "VRF_LITE_CONN" in existing_outer:
            existing_outer["VRF_LITE_CONN"] = json.dumps(
                {"VRF_LITE_CONN": []},
                separators=(",", ":"),
            )

        if not existing_outer:
            return ""
        return json.dumps(existing_outer, separators=(",", ":"))

    existing_rows_by_interface: dict[str, list[dict[str, Any]]] = {}
    existing_inner = _json_value(existing_outer.get("VRF_LITE_CONN"))
    if isinstance(existing_inner, dict):
        existing_rows = existing_inner.get("VRF_LITE_CONN")
        if isinstance(existing_rows, list):
            for existing_row in existing_rows:
                if not isinstance(existing_row, dict) or not existing_row.get("IF_NAME"):
                    continue
                interface_key = str(existing_row["IF_NAME"]).strip().casefold()
                existing_rows_by_interface.setdefault(interface_key, []).append(dict(existing_row))

    prototypes_by_interface = {
        str(interface).strip().casefold(): dict(values) for interface, values in (prototype_values_by_interface or {}).items() if isinstance(values, dict)
    }

    connection_rows: list[dict[str, Any]] = []
    for item in configured_items:
        interface = str(item.get("interface", "")).strip()
        interface_key = interface.casefold()
        prototype = prototypes_by_interface.get(interface_key, {})
        prototype_fields = (
            "IF_NAME",
            "DOT1Q_ID",
            "IP_MASK",
            "NEIGHBOR_IP",
            "NEIGHBOR_ASN",
            "IPV6_MASK",
            "IPV6_NEIGHBOR",
            "AUTO_VRF_LITE_FLAG",
            "PEER_VRF_NAME",
            "VRF_LITE_JYTHON_TEMPLATE",
        )
        row = {key: prototype[key] for key in prototype_fields if key in prototype}

        existing_candidates = existing_rows_by_interface.get(interface_key, [])
        existing_row = {}
        requested_dot1q = item.get("dot1q")
        if requested_dot1q not in (None, ""):
            existing_row = next(
                (candidate for candidate in existing_candidates if str(candidate.get("DOT1Q_ID") or "") == str(requested_dot1q)),
                {},
            )
        if not existing_row and existing_candidates:
            existing_row = existing_candidates[0]
        row.update(existing_row)

        canonical_interface = prototype.get("IF_NAME") or existing_row.get("IF_NAME") or interface
        row["IF_NAME"] = str(canonical_interface).strip()

        field_map = {
            "ipv4_addr": "IP_MASK",
            "ipv6_addr": "IPV6_MASK",
            "neighbor_ipv6": "IPV6_NEIGHBOR",
            "neighbor_ipv4": "NEIGHBOR_IP",
            "peer_vrf": "PEER_VRF_NAME",
        }
        for config_key, payload_key in field_map.items():
            configured_value = item.get(config_key)
            if configured_value not in (None, ""):
                row[payload_key] = configured_value
            else:
                row.setdefault(payload_key, "")

        if item.get("dot1q") is not None and item.get("dot1q") != "":
            row["DOT1Q_ID"] = str(item.get("dot1q"))
        else:
            row["DOT1Q_ID"] = str(row.get("DOT1Q_ID") or "")
        row["VRF_LITE_JYTHON_TEMPLATE"] = "Ext_VRF_Lite_Jython"
        connection_rows.append(row)

    vrf_lite_conn = {"VRF_LITE_CONN": connection_rows}
    extension_values = dict(existing_outer)
    extension_values["VRF_LITE_CONN"] = json.dumps(vrf_lite_conn, separators=(",", ":"))
    if "MULTISITE_CONN" not in extension_values:
        extension_values["MULTISITE_CONN"] = json.dumps({"MULTISITE_CONN": []}, separators=(",", ":"))

    return json.dumps(extension_values, separators=(",", ":"))


def parse_vrf_lite_extension_values(extension_values: Any) -> list[dict[str, Any]]:
    """
    Parse controller extensionValues into playbook-style vrf_lite list.
    """
    if isinstance(extension_values, list):
        parsed_api_rows: list[dict[str, Any]] = []
        for row in extension_values:
            if not isinstance(row, dict):
                continue
            item = {
                "interface": row.get("interfaceName"),
                "dot1q": row.get("dot1qId"),
                "ipv4_addr": row.get("ipv4Address"),
                "neighbor_ipv4": row.get("neighborIpv4Address"),
                "ipv6_addr": row.get("ipv6Address"),
                "neighbor_ipv6": row.get("neighborIpv6Address"),
                "peer_vrf": row.get("peerVrfName"),
            }
            if item.get("interface"):
                parsed_api_rows.append({k: v for k, v in item.items() if v is not None and v != ""})
        return vrf_lite_items_to_config(parsed_api_rows)

    outer = _json_value(extension_values)
    if not isinstance(outer, dict):
        return []

    inner = outer.get("VRF_LITE_CONN")
    inner = _json_value(inner)
    if not isinstance(inner, dict):
        return []

    rows = inner.get("VRF_LITE_CONN")
    if not isinstance(rows, list):
        return []

    parsed: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue

        item = {
            "interface": row.get("IF_NAME"),
            "dot1q": None,
            "ipv4_addr": row.get("IP_MASK") or None,
            "neighbor_ipv4": row.get("NEIGHBOR_IP") or None,
            "ipv6_addr": row.get("IPV6_MASK") or None,
            "neighbor_ipv6": row.get("IPV6_NEIGHBOR") or None,
            "peer_vrf": row.get("PEER_VRF_NAME") or None,
        }

        dot1q = row.get("DOT1Q_ID")
        if dot1q not in (None, ""):
            try:
                item["dot1q"] = int(dot1q)
            except Exception:
                item["dot1q"] = dot1q

        if item.get("interface"):
            parsed.append({k: v for k, v in item.items() if v is not None and v != ""})

    return vrf_lite_items_to_config(parsed)


def build_instance_values(import_evpn_rt: str | None, export_evpn_rt: str | None) -> str:
    values = {
        "loopbackId": "",
        "loopbackIpAddress": "",
        "loopbackIpV6Address": "",
        "switchRouteTargetImportEvpn": import_evpn_rt or "",
        "switchRouteTargetExportEvpn": export_evpn_rt or "",
    }
    return json.dumps(values, separators=(",", ":"))


def parse_instance_values(instance_values: Any) -> dict[str, Any]:
    parsed = _json_value(instance_values)
    if isinstance(parsed, dict):
        return parsed
    return {}
