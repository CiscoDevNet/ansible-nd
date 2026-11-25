# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Breakout-specific validation and tracing around the shared inventory cache."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from ipaddress import ip_address

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class BreakoutFabricContext(FabricContext):
    """Reuse shared switch lookups without changing other modules' inventory behavior.

    Raw inventory records retain duplicate identities that the shared maps collapse.
    Breakout checks selected identities against those records before using the
    existing IP translator or accepting platform metadata.
    """

    def __init__(
        self,
        rest_send: RestSend,
        fabric_name: str,
        query_observer: Callable[[str], None] | None = None,
        query_error_observer: Callable[[str, Exception, bool], None] | None = None,
    ):
        super().__init__(rest_send, fabric_name)
        self._query_observer = query_observer
        self._query_error_observer = query_error_observer
        self._last_query_elapsed_seconds = 0.0
        self._records_by_ip: dict[str, list[dict]] | None = None
        self._records_by_id: dict[str, list[dict]] | None = None

    @property
    def last_query_elapsed_seconds(self) -> float:
        """Return GET timing before its breakout observer records the response."""
        return self._last_query_elapsed_seconds

    def _query_get(self, path: str) -> dict:
        """Retain shared GET semantics while recording breakout's request evidence."""
        self._rest_send.path = path
        self._rest_send.verb = HttpVerbEnum.GET
        response_count = self._rest_send.response_count
        started = time.monotonic()
        try:
            self._rest_send.commit()
        except Exception as error:  # pylint: disable=broad-except
            self._last_query_elapsed_seconds = round(time.monotonic() - started, 3)
            if self._query_error_observer is not None:
                try:
                    self._query_error_observer(path, error, self._rest_send.response_count > response_count)
                except Exception:  # pylint: disable=broad-except
                    # Reporting must not replace the original transport error.
                    pass
            raise
        self._last_query_elapsed_seconds = round(time.monotonic() - started, 3)
        if self._query_observer is not None:
            self._query_observer(path)
        if self._rest_send.return_code == 404:
            return {}
        if not self._rest_send.success:
            raise RuntimeError(f"GET {path} failed {self._rest_send.error_summary}")
        result = self._rest_send.response_current.get("DATA", {})
        if path.endswith("/switches"):
            self._validate_inventory(result)
        return result

    @staticmethod
    def _validate_inventory(result) -> None:
        """Reject malformed records before shared dictionary construction can fail."""
        if not isinstance(result, dict):
            raise RuntimeError("Switch inventory returned a malformed switches list.")
        records = result.get("switches")
        if records is None:
            return
        if not isinstance(records, list):
            raise RuntimeError("Switch inventory returned a malformed switches list.")
        for record in records:
            if not isinstance(record, dict):
                raise RuntimeError("Switch inventory returned a malformed switch record.")
            if any(record.get(key) is not None and not isinstance(record[key], str) for key in ("switchId", "fabricManagementIp")):
                raise RuntimeError("Switch inventory returned a malformed switch identity.")
            if record.get("additionalData") is not None and not isinstance(record["additionalData"], dict):
                raise RuntimeError("Switch inventory returned malformed platform metadata.")

    def invalidate(self) -> None:
        """Clear breakout indexes together with the shared inventory snapshot."""
        super().invalidate()
        self._records_by_ip = None
        self._records_by_id = None

    @staticmethod
    def _selectors(values: Iterable[str], label: str) -> dict[str, str]:
        """Validate the complete input before any inventory read."""
        if isinstance(values, (str, bytes)):
            raise ValueError(f"{label} must be an iterable of nonblank strings")
        selected = {}
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} must be nonblank strings")
            normalized = value.strip()
            if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
                raise ValueError(f"{label} cannot contain control characters")
            selected[value] = normalized
        return selected

    @staticmethod
    def _record_ip(record: dict) -> str | None:
        """Canonicalize a management IP when one is available."""
        value = record.get("fabricManagementIp")
        if not isinstance(value, str):
            return None
        try:
            return str(ip_address(value.strip()))
        except ValueError:
            return None

    def _index_inventory(self) -> None:
        """Index the existing snapshot once for all selected IPs and serials."""
        if self._records_by_id is not None:
            return
        by_ip: dict[str, list[dict]] = {}
        by_id: dict[str, list[dict]] = {}
        for record in self.switches:
            switch_ip = self._record_ip(record)
            if switch_ip is not None:
                by_ip.setdefault(switch_ip, []).append(record)
            serial = record.get("switchId")
            if isinstance(serial, str) and serial.strip():
                by_id.setdefault(serial.strip(), []).append(record)
        self._records_by_ip = by_ip
        self._records_by_id = by_id

    def resolve_switch_identifiers(self, identifiers: Iterable[str]) -> dict[str, str]:
        """Translate IPs through the shared resolver; serials pass through unchanged."""
        selected = self._selectors(identifiers, "switch identifiers")
        resolved = {}
        for original, selector in selected.items():
            try:
                switch_ip = str(ip_address(selector))
            except ValueError:
                resolved[original] = selector
                continue
            self._index_inventory()
            matches = self._records_by_ip.get(switch_ip, [])
            if not matches:
                raise RuntimeError(f"No switch found with fabricManagementIp '{switch_ip}' in fabric '{self.fabric_name}'.")
            if len(matches) != 1:
                raise RuntimeError(f"Multiple switches match fabricManagementIp '{switch_ip}' in fabric '{self.fabric_name}'.")
            serial = matches[0].get("switchId")
            if not isinstance(serial, str) or not serial.strip():
                raise RuntimeError(f"Switch with fabricManagementIp '{switch_ip}' has no nonblank switchId in fabric '{self.fabric_name}'.")
            resolved[original] = self.get_switch_id(matches[0]["fabricManagementIp"]).strip()
        return resolved

    def get_switch_platform_types(self, switch_ids: Iterable[str]) -> dict[str, PlatformType | None]:
        """Validate platform evidence from the same cached inventory, without GETs per switch."""
        selected = dict.fromkeys(self._selectors(switch_ids, "switch IDs").values())
        if not selected:
            return {}
        self._index_inventory()
        platforms = {}
        for serial in selected:
            records = self._records_by_id.get(serial, [])
            if not records:
                raise RuntimeError(f"No switch found with switchId '{serial}' in fabric '{self.fabric_name}'.")
            platform = self._parse_platform_type((records[0].get("additionalData") or {}).get("platformType"))
            seen_ips = set()
            for record in records:
                candidate = self._parse_platform_type((record.get("additionalData") or {}).get("platformType"))
                if candidate != platform:
                    raise RuntimeError(f"Conflicting platform metadata for switchId '{serial}' in fabric '{self.fabric_name}'.")
                switch_ip = self._record_ip(record)
                if len(records) > 1 and (switch_ip is None or switch_ip in seen_ips):
                    raise RuntimeError(f"Multiple cached switches match switchId '{serial}' in fabric '{self.fabric_name}'.")
                seen_ips.add(switch_ip)
            platforms[serial] = platform
        return platforms
