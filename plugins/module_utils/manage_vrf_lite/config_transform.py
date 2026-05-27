# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.common.data import (
    copy_dict_items,
)
from ansible_collections.cisco.nd.plugins.module_utils.manage_vrf_lite.common import (
    _resolve_serial,
    append_runtime_warning,
    vrf_name_from_config_item,
)


def _canonical_switch_id(module: Any, switch_identifier: Any) -> str:
    if switch_identifier is None:
        return ""
    if module is None:
        return str(switch_identifier).strip()
    return _resolve_serial(module, switch_identifier)


def _entry_from_attach(module: Any, vrf_item: dict[str, Any], attach: dict[str, Any]) -> dict[str, Any]:
    vrf_name = vrf_name_from_config_item(vrf_item)
    switch_identifier = attach.get("ip_address") or attach.get("switch_ip") or attach.get("serial_number")
    switch_ip = _canonical_switch_id(module, switch_identifier)

    entry: dict[str, Any] = {
        "vrf_name": vrf_name,
        "switch_ip": switch_ip,
    }

    vlan_id = attach.get("vlan_id", vrf_item.get("vlan_id"))
    if vlan_id is not None:
        entry["vlan_id"] = vlan_id

    if "deploy" in attach:
        entry["deploy"] = attach.get("deploy")
    elif "deploy" in vrf_item:
        entry["deploy"] = vrf_item.get("deploy")

    for key in ("import_evpn_rt", "export_evpn_rt"):
        if attach.get(key) is not None:
            entry[key] = attach.get(key)

    extensions = attach.get("extensions", attach.get("vrf_lite"))
    if extensions is not None:
        entry["extensions"] = copy_dict_items(extensions)

    return {key: value for key, value in entry.items() if value is not None}


def explode_playbook_to_entries(
    config: list[dict[str, Any]],
    module: Any,
    state: str,
    current_entries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Flatten nested playbook config into attachment-level state-machine entries."""
    entries: list[dict[str, Any]] = []
    current_entries = current_entries or []
    current_keys = {(item.get("vrf_name"), item.get("switch_ip")) for item in current_entries}
    for vrf_item in config or []:
        if not isinstance(vrf_item, dict):
            continue

        vrf_name = vrf_name_from_config_item(vrf_item)
        if not vrf_name:
            continue

        attachments = vrf_item.get("attach")

        if state == "deleted" and not attachments:
            entries.extend([dict(item) for item in current_entries if item.get("vrf_name") == vrf_name])
            continue

        if not isinstance(attachments, list):
            continue

        for attach in attachments:
            if not isinstance(attach, dict):
                continue
            entry = _entry_from_attach(module, vrf_item, attach)
            if not entry.get("switch_ip") or not entry.get("vrf_name"):
                continue
            entries.append(entry)

            if state == "deleted" and (entry.get("vrf_name"), entry.get("switch_ip")) not in current_keys:
                append_runtime_warning(
                    module.params,
                    "No matching VRF Lite attachment found to delete for VRF '{0}' switch '{1}'. "
                    "No detach payload was sent.".format(entry.get("vrf_name"), entry.get("switch_ip")),
                )

    return sorted(entries, key=lambda item: (item.get("vrf_name", ""), item.get("switch_ip", "")))


def config_vrf_names(config: list[dict[str, Any]]) -> list[str]:
    """Return unique VRF names from playbook-style config."""
    vrfs = []
    for item in config or []:
        if not isinstance(item, dict):
            continue
        vrf_name = vrf_name_from_config_item(item)
        if vrf_name:
            vrfs.append(vrf_name)
    return sorted(set(vrfs))


def replacement_scope_vrfs(config: list[dict[str, Any]]) -> list[str]:
    """Return VRF names whose attachment set is managed by replaced state."""
    return config_vrf_names(config)


def group_attachment_entries_to_vrfs(
    entries: list[Any],
    module: Any = None,
    include_vrfs: list[str] | set[str] | None = None,
) -> list[dict[str, Any]]:
    """Convert flat state-machine entries back to the public nested VRF shape."""
    sn_to_ip = {}
    vlan_map = {}
    known_vrfs = set()
    if module is not None and isinstance(getattr(module, "params", None), dict):
        sn_to_ip = module.params.get("_sn_to_ip_mapping") or {}
        vlan_map = module.params.get("_vrf_lite_vrf_vlan_map") or {}
        known_vrfs = set(module.params.get("_known_vrfs") or [])

    grouped: dict[str, dict[str, Any]] = {}
    for raw_vrf_name in include_vrfs or []:
        if not raw_vrf_name:
            continue
        vrf_name = str(raw_vrf_name).strip()
        if known_vrfs and vrf_name not in known_vrfs:
            continue
        grouped.setdefault(vrf_name, {"vrf_name": vrf_name, "attach": []})
        if vlan_map.get(vrf_name) is not None:
            grouped[vrf_name]["vlan_id"] = vlan_map.get(vrf_name)

    for entry in entries or []:
        data = entry.to_config() if hasattr(entry, "to_config") else dict(entry)
        vrf_name = data.get("vrf_name")
        if not vrf_name:
            continue

        vrf = grouped.setdefault(str(vrf_name), {"vrf_name": str(vrf_name), "attach": []})
        if data.get("vlan_id") is not None and vrf.get("vlan_id") is None:
            vrf["vlan_id"] = data.get("vlan_id")

        if data.get("deploy") is True:
            vrf["deploy"] = True
        elif data.get("deploy") is not None and "deploy" not in vrf:
            vrf["deploy"] = data.get("deploy")

        switch_id = data.get("switch_ip")
        attach: dict[str, Any] = {
            "ip_address": sn_to_ip.get(switch_id, switch_id),
        }
        for key in ("deploy", "import_evpn_rt", "export_evpn_rt"):
            if data.get(key) is not None:
                attach[key] = data.get(key)
        if data.get("extensions") is not None:
            attach["vrf_lite"] = data.get("extensions")

        vrf["attach"].append(attach)

    result = []
    for vrf_name in sorted(grouped):
        vrf = grouped[vrf_name]
        vrf["attach"] = sorted(vrf.get("attach", []), key=lambda item: item.get("ip_address", ""))
        result.append(vrf)
    return result
