# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

import json
from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.data import (
    parse_value,
)


def normalize_vrf_lite_list(vrf_lite_items: Optional[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in vrf_lite_items or []:
        interface = item.get("interface")
        if not interface:
            continue

        normalized_item = {
            "interface": str(interface).strip(),
            "dot1q": item.get("dot1q"),
            "ipv4_addr": item.get("ipv4_addr"),
            "neighbor_ipv4": item.get("neighbor_ipv4"),
            "ipv6_addr": item.get("ipv6_addr"),
            "neighbor_ipv6": item.get("neighbor_ipv6"),
            "peer_vrf": item.get("peer_vrf"),
        }
        normalized.append({k: v for k, v in normalized_item.items() if v is not None and v != ""})

    normalized.sort(key=lambda i: i.get("interface", ""))
    return normalized


def build_vrf_lite_extension_values(
    vrf_lite_items: Optional[list[dict[str, Any]]],
    existing_extension_values: Any = None,
) -> str:
    """
    Build extensionValues string expected by top-down VRF attachment APIs.
    """
    existing_outer = parse_value(existing_extension_values)
    if isinstance(existing_outer, dict):
        existing_outer = dict(existing_outer)
    else:
        existing_outer = {}

    normalized = normalize_vrf_lite_list(vrf_lite_items)
    if not normalized:
        if "VRF_LITE_CONN" in existing_outer:
            existing_outer["VRF_LITE_CONN"] = json.dumps(
                {"VRF_LITE_CONN": []},
                separators=(",", ":"),
            )

        if not existing_outer:
            return ""
        return json.dumps(existing_outer, separators=(",", ":"))

    connection_rows: list[dict[str, Any]] = []
    for item in normalized:
        row = {
            "DOT1Q_ID": "",
            "IF_NAME": item.get("interface", ""),
            "IP_MASK": item.get("ipv4_addr", ""),
            "IPV6_MASK": item.get("ipv6_addr", ""),
            "IPV6_NEIGHBOR": item.get("neighbor_ipv6", ""),
            "NEIGHBOR_IP": item.get("neighbor_ipv4", ""),
            "PEER_VRF_NAME": item.get("peer_vrf", ""),
            "VRF_LITE_JYTHON_TEMPLATE": "Ext_VRF_Lite_Jython",
        }
        if item.get("dot1q") is not None and item.get("dot1q") != "":
            row["DOT1Q_ID"] = str(item.get("dot1q"))
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
    outer = parse_value(extension_values)
    if not isinstance(outer, dict):
        return []

    inner = outer.get("VRF_LITE_CONN")
    inner = parse_value(inner)
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

    return normalize_vrf_lite_list(parsed)


def build_instance_values(import_evpn_rt: Optional[str], export_evpn_rt: Optional[str]) -> str:
    values = {
        "loopbackId": "",
        "loopbackIpAddress": "",
        "loopbackIpV6Address": "",
        "switchRouteTargetImportEvpn": import_evpn_rt or "",
        "switchRouteTargetExportEvpn": export_evpn_rt or "",
    }
    return json.dumps(values, separators=(",", ":"))


def parse_instance_values(instance_values: Any) -> dict[str, Any]:
    parsed = parse_value(instance_values)
    if isinstance(parsed, dict):
        return parsed
    return {}
