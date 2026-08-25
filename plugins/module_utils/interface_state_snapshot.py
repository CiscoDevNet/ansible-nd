# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared, execution-scoped interface inventory for Nexus Dashboard.

``InterfaceStateSnapshot`` owns the expensive per-switch interface-list reads
used by the interface resource orchestrators. A standalone orchestrator creates
one lazily, while the aggregate interface workflow can inject one instance into
several orchestrators so every family observes the same initial state.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from copy import deepcopy
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import EpManageInterfacesListGet
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext


class InterfaceStateSnapshot:
    """Cache and index interface state for one fabric and module execution.

    The provider intentionally returns deep copies of cached records. Several
    existing family orchestrators enrich selected records with ``switchIp``;
    isolating those working copies keeps one family from changing the shared
    source observed by another family.
    """

    def __init__(
        self,
        *,
        fabric_name: str,
        fabric_context: FabricContext,
        request: Callable[..., Any],
        page_size: int | None = 500,
    ) -> None:
        if not fabric_name:
            raise ValueError("InterfaceStateSnapshot requires a non-empty fabric_name.")
        if fabric_context.fabric_name != fabric_name:
            raise ValueError(f"InterfaceStateSnapshot fabric '{fabric_name}' does not match FabricContext fabric " f"'{fabric_context.fabric_name}'.")
        if page_size is not None and page_size < 1:
            raise ValueError("InterfaceStateSnapshot page_size must be at least 1 or None.")

        self.fabric_name = fabric_name
        self.fabric_context = fabric_context
        self._request = request
        self.page_size = page_size
        self._interfaces_by_switch: dict[str, dict[str, dict]] = {}
        self._original_interfaces_by_switch: dict[str, dict[str, dict]] = {}
        self._dirty_switches: set[str] = set()
        self._requested_switches: set[str] = set()
        self._interface_inventory_gets = 0
        self._interface_inventory_pages = 0
        self._cache_hits = 0
        self._interface_inventory_refreshes = 0
        self._dirty_refetches = 0
        self._snapshot_overlays = 0

    @staticmethod
    def _normalise_switch_ids(switch_ids: str | Iterable[str]) -> list[str]:
        """Return de-duplicated switch IDs while preserving caller order."""
        values = [switch_ids] if isinstance(switch_ids, str) else list(switch_ids)
        return list(dict.fromkeys(values))

    @staticmethod
    def _interface_key(interface: dict) -> str | None:
        """Return the case-insensitive interface-name cache key, if present."""
        interface_name = interface.get("interfaceName")
        if not isinstance(interface_name, str) or not interface_name:
            return None
        return interface_name.lower()

    @staticmethod
    def policy_type(interface: dict) -> str | None:
        """Return an interface's policy type while tolerating null API fields."""
        config_data = interface.get("configData") or {}
        network_os = config_data.get("networkOS") or {}
        policy = network_os.get("policy") or {}
        return policy.get("policyType")

    def _fetch_switch(self, switch_id: str) -> dict[str, dict]:
        """Fetch all pages for ``switch_id`` and key records by interface name."""
        interfaces_by_name: dict[str, dict] = {}
        offset = 0
        seen_full_pages: set[tuple[str, ...]] = set()

        while True:
            endpoint = EpManageInterfacesListGet()
            endpoint.fabric_name = self.fabric_name
            endpoint.switch_sn = switch_id
            if self.page_size is not None:
                endpoint.endpoint_params.max = self.page_size
                endpoint.endpoint_params.offset = offset

            self._interface_inventory_gets += 1
            self._interface_inventory_pages += 1
            result = self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True)
            page = result.get("interfaces", []) or [] if isinstance(result, dict) else []
            if not isinstance(page, list):
                page = []

            keyed_page: list[tuple[str, dict]] = []
            for interface in page:
                if not isinstance(interface, dict):
                    continue
                key = self._interface_key(interface)
                if key is not None:
                    keyed_page.append((key, interface))

            if self.page_size is not None and len(page) >= self.page_size:
                signature = tuple(key for key, _interface in keyed_page)
                if signature in seen_full_pages:
                    raise RuntimeError(f"Interface inventory pagination repeated a full page for switch '{switch_id}' " f"at offset {offset}.")
                seen_full_pages.add(signature)

            for key, interface in keyed_page:
                interfaces_by_name[key] = deepcopy(interface)

            if self.page_size is None or len(page) < self.page_size:
                break
            offset += len(page)

        return interfaces_by_name

    def load_switch(self, switch_id: str) -> dict[str, dict]:
        """Return current state, automatically refetching a dirty switch."""
        if not switch_id:
            raise ValueError("InterfaceStateSnapshot.load_switch requires a non-empty switch_id.")
        if switch_id in self._interfaces_by_switch and switch_id not in self._dirty_switches:
            self._cache_hits += 1
            return deepcopy(self._interfaces_by_switch[switch_id])

        if switch_id in self._dirty_switches:
            self._dirty_refetches += 1
        interfaces = self._fetch_switch(switch_id)
        self._interfaces_by_switch[switch_id] = interfaces
        self._original_interfaces_by_switch.setdefault(switch_id, deepcopy(interfaces))
        self._requested_switches.add(switch_id)
        self._dirty_switches.discard(switch_id)
        return deepcopy(interfaces)

    def load_switches(self, switch_ids: Iterable[str]) -> dict[str, dict[str, dict]]:
        """Load several switches, de-duplicating IDs supplied by the caller."""
        return {switch_id: self.load_switch(switch_id) for switch_id in self._normalise_switch_ids(switch_ids)}

    @property
    def interfaces_by_switch(self) -> dict[str, dict[str, dict]]:
        """Return current cached state keyed by switch ID and interface name."""
        return deepcopy(self._interfaces_by_switch)

    @property
    def interfaces_by_switch_ip(self) -> dict[str, dict[str, dict]]:
        """Return current cached state keyed by switch management IP."""
        return {self.fabric_context.get_switch_ip(switch_id): deepcopy(interfaces) for switch_id, interfaces in self._interfaces_by_switch.items()}

    @property
    def original_interfaces_by_switch(self) -> dict[str, dict[str, dict]]:
        """Return an isolated copy of the immutable, initially fetched state."""
        return deepcopy(self._original_interfaces_by_switch)

    @property
    def interfaces_by_identity(self) -> dict[tuple[str, str], dict]:
        """Return cached records keyed by ``(switch_id, interface_name)``."""
        return {
            (switch_id, interface_name): deepcopy(interface)
            for switch_id, interfaces in self._interfaces_by_switch.items()
            for interface_name, interface in interfaces.items()
        }

    @property
    def interfaces_by_type(self) -> dict[str, dict[tuple[str, str], dict]]:
        """Return cached records partitioned by API ``interfaceType``."""
        index: dict[str, dict[tuple[str, str], dict]] = {}
        for identity, interface in self.interfaces_by_identity.items():
            interface_type = interface.get("interfaceType")
            if interface_type:
                index.setdefault(interface_type, {})[identity] = interface
        return index

    @property
    def interfaces_by_policy_type(self) -> dict[str, dict[tuple[str, str], dict]]:
        """Return cached records partitioned by API policy type."""
        index: dict[str, dict[tuple[str, str], dict]] = {}
        for identity, interface in self.interfaces_by_identity.items():
            policy_type = self.policy_type(interface)
            if policy_type:
                index.setdefault(policy_type, {})[identity] = interface
        return index

    @property
    def dirty_switches(self) -> set[str]:
        """Return switches whose cached state may no longer match the controller."""
        return set(self._dirty_switches)

    def apply_overlay(
        self,
        switch_id: str,
        *,
        upserts: Iterable[dict[str, Any]] = (),
        deletes: Iterable[str] = (),
    ) -> dict[str, dict]:
        """Atomically apply known successful changes to a clean loaded switch."""
        if switch_id not in self._interfaces_by_switch:
            raise ValueError(f"Cannot apply an overlay before switch '{switch_id}' has been loaded.")
        if switch_id in self._dirty_switches:
            raise RuntimeError(f"Cannot apply an overlay to dirty switch '{switch_id}'; refetch it first.")

        prepared_upserts: dict[str, dict] = {}
        for interface in upserts:
            if not isinstance(interface, dict):
                raise ValueError("InterfaceStateSnapshot overlay upserts must be dictionaries.")
            key = self._interface_key(interface)
            if key is None:
                raise ValueError("InterfaceStateSnapshot overlay upserts require a non-empty interfaceName.")
            if key in prepared_upserts:
                raise ValueError(f"InterfaceStateSnapshot overlay contains duplicate upsert '{interface.get('interfaceName')}'.")
            prepared_upserts[key] = deepcopy(interface)

        prepared_deletes: set[str] = set()
        for interface_name in deletes:
            if not isinstance(interface_name, str) or not interface_name:
                raise ValueError("InterfaceStateSnapshot overlay deletes require non-empty interface names.")
            prepared_deletes.add(interface_name.lower())

        overlap = set(prepared_upserts) & prepared_deletes
        if overlap:
            raise ValueError(f"InterfaceStateSnapshot overlay cannot upsert and delete the same interface(s): {sorted(overlap)}.")

        candidate = deepcopy(self._interfaces_by_switch[switch_id])
        for interface_name in prepared_deletes:
            candidate.pop(interface_name, None)
        candidate.update(prepared_upserts)
        self._interfaces_by_switch[switch_id] = candidate
        self._snapshot_overlays += 1
        return deepcopy(candidate)

    def mark_dirty(self, switch_ids: str | Iterable[str]) -> None:
        """Mark one or more switches as stale after an uncertain mutation."""
        self._dirty_switches.update(self._normalise_switch_ids(switch_ids))

    def invalidate(self, switch_ids: str | Iterable[str]) -> None:
        """Discard current cached state for switches while retaining originals."""
        for switch_id in self._normalise_switch_ids(switch_ids):
            self._interfaces_by_switch.pop(switch_id, None)
            self._dirty_switches.add(switch_id)

    def refresh(self, switch_ids: str | Iterable[str]) -> dict[str, dict[str, dict]]:
        """Refetch one or more switches and clear their dirty markers."""
        normalised = self._normalise_switch_ids(switch_ids)
        self._interface_inventory_refreshes += len(normalised)
        self.invalidate(normalised)
        return self.load_switches(normalised)

    @property
    def request_stats(self) -> dict[str, int]:
        """Return interface-inventory and snapshot lifecycle counts."""
        return {
            "switches": len(self._requested_switches),
            "interface_inventory_gets": self._interface_inventory_gets,
            "interface_inventory_pages": self._interface_inventory_pages,
            "interface_inventory_cache_hits": self._cache_hits,
            "interface_inventory_refreshes": self._interface_inventory_refreshes,
            "interface_inventory_dirty_refetches": self._dirty_refetches,
            "snapshot_overlays": self._snapshot_overlays,
        }
