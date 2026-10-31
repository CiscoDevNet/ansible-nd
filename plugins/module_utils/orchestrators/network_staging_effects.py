# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Compact observations of the existing staged Network workflow.

This observer never supplies authority, changes payloads or queries ND.  It
retains switch identities and pagination facts from reads already required by
the workflow, then bounds successful writes to whole switches. Unknown effects
invalidate the optimization rather than narrowing reconciliation by guesswork.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_staging_request import network_staging_request_digest

NETWORK_STAGING_EFFECTS_VERSION = 1


def staging_observer(coordinator: Any) -> NetworkStagingEffects | None:
    """Return an actual observer, ignoring absent or mocked coordinator state."""
    observer = getattr(coordinator, "_network_staging_effects", None)
    return observer if isinstance(observer, NetworkStagingEffects) else None


class NetworkStagingEffects:
    """Observe native attachment/definition effects without retaining row copies."""

    def __init__(self, args: dict, strategy: Any, check_mode: bool, request_sha256: str | None = None):
        self.fabric_name = strategy.fabric_name
        self.request_sha256 = request_sha256 or network_staging_request_digest(self.fabric_name, "staged", args.get("config"), args.get("config_actions"))
        self.check_mode = check_mode
        self.unknown: set[str] = set()
        self.switch_ips: dict[str, str] = {}
        self.affected: set[str] = set()
        self.written_keys: set[tuple[str, str]] = set()
        self.pending_keys: set[tuple[str, str]] = set()
        self.attachment_scopes: set[str] = set()
        self.definitions_observed = False
        self.definition_risks: dict[str, set[str]] = {}
        self.deployment_attempts = 0
        self._pages: dict[str, dict] = {}
        if strategy.is_parent or strategy.is_child or strategy.is_multicluster or strategy.is_multisite:
            self.unknown.add("unsupported_fabric_topology")

    @staticmethod
    def _value(row: Any, *keys: str) -> Any:
        for key in keys:
            value = row.get(key) if isinstance(row, Mapping) else getattr(row, key, None)
            if value is not None:
                return getattr(value, "value", value)
        return None

    @staticmethod
    def _count(value: Any) -> int | None:
        if isinstance(value, str) and value.isdecimal():
            value = int(value)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    def observe_page(self, kind: str, data: Any, rows: list, offset: int, page_size: int, more: bool, names: list[str] | None = None) -> None:
        """Validate existing pagination; never alter the reader's continuation."""
        if offset == 0:
            self._pages[kind] = {"seen": set(), "total": None, "offset": 0}
        cursor = self._pages.get(kind)
        if cursor is None or cursor["offset"] != offset or not isinstance(data, Mapping):
            self.unknown.add(kind + "_pagination_unproven")
            return
        key = "networks" if kind == "definitions" else "attachments"
        collections = [candidate for candidate in (key, "items") if candidate in data]
        if len(collections) != 1 or not isinstance(data[collections[0]], list) or len(data[collections[0]]) != len(rows):
            self.unknown.add(kind + "_collection_unproven")
        for row in rows:
            if not isinstance(row, Mapping):
                self.unknown.add(kind + "_identity_or_intent_unproven")
                continue
            name = self._value(row, "networkName", "network_name")
            identity = name if kind == "definitions" else (name, self._value(row, "switchId"))
            if not isinstance(name, str) or not name or kind != "definitions" and (not isinstance(identity[1], str) or not identity[1]):
                self.unknown.add(kind + "_identity_or_intent_unproven")
                continue
            if kind != "definitions" and not isinstance(row.get("attach"), bool):
                self.unknown.add(kind + "_identity_or_intent_unproven")
            if identity in cursor["seen"]:
                self.unknown.add(kind + "_duplicate_identity")
            cursor["seen"].add(identity)
            if kind == "definitions" and isinstance(name, str):
                self.definition_risks[name] = self._definition_effects(row)
            elif kind != "definitions":
                self.remember_switch(row)
                statuses = [str(row[key]).lower() for key in ("status", "configStatus", "deploymentStatus", "networkStatus", "attachmentStatus") if key in row]
                terminal = {"insync", "deployed", "success", "notapplicable", "notdeployed", "na", "deleted"}
                pending = {"pending", "outofsync", "failed"}
                if not statuses or any(status not in terminal | pending for status in statuses):
                    self.unknown.add("attachment_deployment_state_unproven")
                if (
                    any(status in pending for status in statuses)
                    or row.get("attach") is True
                    and any(status in {"notapplicable", "notdeployed", "na"} for status in statuses)
                ):
                    self.pending_keys.add(identity)
        metadata = data.get("metadata", data.get("meta", {}))
        if "metadata" in data and "meta" in data:
            self.unknown.add(kind + "_pagination_unproven")
        if not isinstance(metadata, Mapping):
            self.unknown.add(kind + "_pagination_unproven")
            return
        counts = metadata.get("counts", {})
        if not isinstance(counts, Mapping):
            self.unknown.add(kind + "_pagination_unproven")
            return
        after = offset + len(rows)
        for field in ("total", "remaining"):
            raw = counts.get(field)
            if raw is None:
                continue
            value = self._count(raw)
            total = value if field == "total" else after + value if value is not None else None
            if total is None or total < after or cursor["total"] is not None and total != cursor["total"]:
                self.unknown.add(kind + "_pagination_unproven")
            else:
                cursor["total"] = total
        if cursor["total"] is not None and more != (after < cursor["total"]):
            self.unknown.add(kind + "_pagination_incomplete")
        if more and not rows or not more and cursor["total"] is None and len(rows) >= page_size:
            self.unknown.add(kind + "_pagination_incomplete")
        links = metadata.get("links", {})
        if not isinstance(links, Mapping):
            self.unknown.add(kind + "_pagination_unproven")
        else:
            next_link = links.get("next")
            if next_link:
                offsets = parse_qs(urlsplit(next_link).query).get("offset", []) if isinstance(next_link, str) else []
                if not more or len(offsets) != 1 or not offsets[0].isdecimal() or int(offsets[0]) != after:
                    self.unknown.add(kind + "_pagination_incomplete")
            elif "next" in links and more:
                self.unknown.add(kind + "_pagination_incomplete")
        cursor["offset"] = after
        if not more:
            if kind == "definitions":
                self.definitions_observed = True
            elif names is not None:
                self.attachment_scopes.update(names)

    def remember_switch(self, row: Any) -> None:
        """Keep only identity/IP fields from existing switch or attachment reads."""
        serial = self._value(row, "switchId", "switch_id", "serialNumber")
        ip = self._value(row, "ipAddress", "ip_address", "managementIpAddress", "fabricManagementIp", "switchIp", "managementIp")
        if isinstance(serial, str) and isinstance(ip, str) and serial and ip:
            previous = self.switch_ips.get(serial)
            if previous is not None and previous != ip:
                self.unknown.add("ambiguous_switch_management_ip")
            self.switch_ips[serial] = ip

    def record_payloads(self, payloads: list[dict]) -> None:
        """Observe only attachment payloads accepted by the ordinary writer."""
        for row in payloads:
            name, serial = row.get("networkName"), row.get("switchId")
            if not isinstance(name, str) or not isinstance(serial, str) or not name or not serial:
                self.unknown.add("attachment_write_identity_unproven")
                continue
            self.written_keys.add((name, serial))
            self.affected.add(serial)
            self._attachment_effects(row)

    def _attachment_effects(self, row: Mapping) -> None:
        values = row.get("instanceValues")
        # Native per-switch SVI enable/disable is bounded by this whole-switch
        # scope. DPU and arbitrary free-form instance values are not assumed safe.
        bounded = {"svi_enabled", "sviEnabled", "is_active", "isActive"}
        if isinstance(values, Mapping):
            unbounded = any(
                (key not in bounded or not isinstance(value, bool)) and not (key in {"dpuSecure", "dpu_secure"} and value is False)
                for key, value in values.items()
            )
        else:
            unbounded = values is not None
        if row.get("extraConfig") or row.get("extra_config") or unbounded:
            self.unknown.add("custom_attachment_effects")
        for interface in row.get("interfaces") or []:
            if not isinstance(interface, Mapping) or interface.get("interfaceGroupName") or interface.get("interface_group_name"):
                self.unknown.add("dynamic_attachment_interface_group")

    def _definition_effects(self, row: Any) -> set[str]:
        risks = set()
        for key, alias in (("network_template_name", "networkTemplateName"), ("network_extension_template_name", "networkExtensionTemplateName")):
            value = self._value(row, key, alias)
            standard = "Default_Network_Universal" if key == "network_template_name" else "Default_Network_Extension_Universal"
            if value and value != standard:
                risks.add("custom_network_template")
        if self._value(row, "network_template_config", "networkTemplateConfig"):
            risks.add("custom_network_template_config")
        network_type = self._value(row, "network_type", "networkType")
        if network_type not in (None, "vxlanIbgp", "vxlan"):
            risks.add("unsupported_network_type")

        # Read nested model fields without dumping/copying all controller rows.
        def inspect(value: Any) -> None:
            if isinstance(value, Mapping):
                items = value.items()
            elif hasattr(type(value), "model_fields"):
                items = ((name, getattr(value, name)) for name in type(value).model_fields)
            else:
                return
            for name, child in items:
                token = name.replace("_", "").lower()
                # An explicit multicast-group address is ordinary VXLAN intent
                # on these same attached switches. TRM/DHCP/service workflows
                # can introduce additional targets and remain conservative.
                if child not in (None, False, "", [], {}) and any(marker in token for marker in ("dhcp", "trm", "xconnect", "service", "aci")):
                    risks.add("dynamic_network_effects")
                if isinstance(child, Mapping) or hasattr(type(child), "model_fields"):
                    inspect(child)

        inspect(row)
        return risks

    def finish(self, result: dict, sm: Any, current: list[dict], desired: dict, post_details: list[dict]) -> dict:
        """Produce an O(affected switches) receipt, independent of output verbosity."""
        changed_models = getattr(sm, "sent", None)
        before_models = getattr(sm, "before", None)
        if changed_models is None or before_models is None:
            self.unknown.add("definition_diff_unavailable")
            changed_models, before_models = [], []
        changed_names = {self._value(row, "network_name", "networkName") for row in changed_models}
        before_names = {self._value(row, "network_name", "networkName") for row in before_models}
        if not self.definitions_observed or not before_names.issubset(self.attachment_scopes):
            self.unknown.add("global_native_snapshot_unproven")
        effect_keys = self.written_keys | self.pending_keys
        touched_names = changed_names | {name for name, _serial in effect_keys}
        for name in touched_names:
            self.unknown.update(self.definition_risks.get(name, ()))
        for row in changed_models:
            self.unknown.update(self._definition_effects(row))
        for row in before_models:
            if self._value(row, "network_name", "networkName") in touched_names:
                self.unknown.update(self._definition_effects(row))
        # Scan existing references; never copy or serialize attachment collections.
        for rows in (current, post_details, desired.values()):
            for row in rows:
                name, serial = row.get("networkName"), row.get("switchId")
                if name in changed_names and row.get("attach") is True or (name, serial) in effect_keys:
                    if serial:
                        self.affected.add(serial)
                    else:
                        self.unknown.add("affected_switch_identity_unproven")
                    peer = row.get("peerSwitchId")
                    if peer:
                        self.affected.add(peer)
                    self._attachment_effects(row)
        for serial in self.affected:
            if serial not in self.switch_ips:
                self.unknown.add("affected_switch_management_ip_unproven")
        observed = not self.check_mode and not result.get("failed", False)
        return {
            "version": NETWORK_STAGING_EFFECTS_VERSION,
            "source": "cisco.nd.nd_manage_networks",
            "fabric_name": self.fabric_name,
            "state": "staged",
            "request_sha256": self.request_sha256,
            "complete": observed and not self.unknown and self.deployment_attempts == 0,
            "observed": observed,
            "observed_scope": "all_staged_attachments",
            "affected_switches": [{"switch_id": serial, "management_ip": self.switch_ips.get(serial)} for serial in sorted(self.affected)],
            "unknown_effects": sorted(self.unknown),
            "deployment_attempts": self.deployment_attempts,
        }
