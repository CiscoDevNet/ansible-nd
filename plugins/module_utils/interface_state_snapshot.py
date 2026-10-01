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

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesListGet,
    EpManageInterfacesSummaryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.interface_pagination import InterfaceOffsetPaginator
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext


class InterfaceStateSnapshot:
    """Cache and index interface state for one fabric and module execution.

    The provider intentionally returns deep copies of cached records. Several
    existing family orchestrators enrich selected records with ``switchIp``;
    isolating those working copies keeps one family from changing the shared
    source observed by another family.

    A dirty switch means only that this execution-scoped local cache may be
    stale. It is unrelated to controller configuration synchronization status.
    Loading a dirty switch increments ``_dirty_refetches`` once before
    fetching its inventory; pagination is counted separately by
    ``_interface_inventory_gets``. An explicit refresh invalidates the local
    entry first, so it increments both the refresh and dirty-refetch counters.
    """

    def __init__(
        self,
        *,
        fabric_name: str,
        fabric_context: FabricContext,
        request: Callable[..., Any],
        page_size: int = InterfaceOffsetPaginator.DEFAULT_PAGE_SIZE,
        max_pages: int = InterfaceOffsetPaginator.DEFAULT_MAX_PAGES,
    ) -> None:
        if not fabric_name:
            raise ValueError("InterfaceStateSnapshot requires a non-empty fabric_name.")
        if fabric_context.fabric_name != fabric_name:
            raise ValueError(f"InterfaceStateSnapshot fabric '{fabric_name}' does not match FabricContext fabric " f"'{fabric_context.fabric_name}'.")
        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
            raise ValueError("InterfaceStateSnapshot page_size must be a positive integer.")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
            raise ValueError("InterfaceStateSnapshot max_pages must be a positive integer.")

        self.fabric_name = fabric_name
        self.fabric_context = fabric_context
        self._request = request
        self.page_size = page_size
        self.max_pages = max_pages
        self._paginator = InterfaceOffsetPaginator(page_size=page_size, max_pages=max_pages)
        self._interfaces_by_switch: dict[str, dict[str, dict]] = {}
        self._original_interfaces_by_switch: dict[str, dict[str, dict]] = {}
        self._interface_summaries_by_switch: dict[str, dict[str, dict]] = {}
        self._dirty_switches: set[str] = set()
        self._requested_switches: set[str] = set()
        self._requested_summary_switches: set[str] = set()
        self._interface_inventory_gets = 0
        self._interface_inventory_pages = 0
        self._cache_hits = 0
        self._interface_summary_gets = 0
        self._interface_summary_pages = 0
        self._interface_summary_cache_hits = 0
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
        """Fetch every page for ``switch_id`` and publish only a complete result."""

        def fetch_page(offset: int, page_size: int) -> Any:
            endpoint = EpManageInterfacesListGet()
            endpoint.fabric_name = self.fabric_name
            endpoint.switch_sn = switch_id
            endpoint.endpoint_params.sort = "interfaceName:asc"
            endpoint.endpoint_params.max = page_size
            endpoint.endpoint_params.offset = offset

            self._interface_inventory_gets += 1
            self._interface_inventory_pages += 1
            return self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True)

        def identity(interface: dict[str, Any]) -> tuple[str, str]:
            interface_name = interface.get("interfaceName")
            if not isinstance(interface_name, str) or not interface_name:
                raise ValueError("interfaceName must be a non-empty string")
            returned_switch_id = interface.get("switchId")
            if returned_switch_id is not None and (not isinstance(returned_switch_id, str) or not returned_switch_id):
                raise ValueError(f"switchId must be a non-empty string, received {returned_switch_id!r}")
            if returned_switch_id is not None and returned_switch_id != switch_id:
                raise ValueError(f"switchId {returned_switch_id!r} does not match requested switch {switch_id!r}")
            return switch_id, interface_name.lower()

        interfaces = self._paginator.collect(
            fetch_page=fetch_page,
            identity=identity,
            context=f"interface inventory for switch '{switch_id}'",
        )
        return {interface["interfaceName"].lower(): deepcopy(interface) for interface in interfaces}

    def _fetch_interface_summary_switch(self, switch_id: str) -> dict[str, dict]:
        """Fetch every summary page and select the requested switch afterwards."""

        def fetch_page(offset: int, page_size: int) -> Any:
            endpoint = EpManageInterfacesSummaryGet()
            endpoint.fabric_name = self.fabric_name
            # Some ND releases treat switchId as advisory and return fabric-wide rows. The Lucene filter keeps those
            # responses small where supported; exact client-side switch selection below remains authoritative.
            endpoint.endpoint_params.switch_id = switch_id
            endpoint.endpoint_params.filter = f"switchId:{switch_id}"
            endpoint.endpoint_params.sort = "interfaceName:asc"
            endpoint.endpoint_params.max = page_size
            endpoint.endpoint_params.offset = offset

            self._interface_summary_gets += 1
            self._interface_summary_pages += 1
            return self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True)

        def identity(summary: dict[str, Any]) -> tuple[str, str]:
            returned_switch_id = summary.get("switchId")
            if not isinstance(returned_switch_id, str) or not returned_switch_id:
                raise ValueError(f"switchId must be a non-empty string, received {returned_switch_id!r}")
            interface_name = summary.get("interfaceName")
            if not isinstance(interface_name, str) or not interface_name:
                raise ValueError("interfaceName must be a non-empty string")
            return returned_switch_id, interface_name.lower()

        summaries = self._paginator.collect(
            fetch_page=fetch_page,
            identity=identity,
            context=f"interface summary for requested switch '{switch_id}'",
        )
        return {summary["interfaceName"].lower(): deepcopy(summary) for summary in summaries if summary["switchId"] == switch_id}

    def load_switch(self, switch_id: str) -> dict[str, dict]:
        """Return current state, automatically refetching a locally dirty switch.

        A clean cached inventory is returned without a request. A dirty marker
        causes one logical refetch attempt and increments ``_dirty_refetches``
        before ``_fetch_switch`` runs. Any paginated HTTP requests made by that
        fetch are tracked independently by ``_interface_inventory_gets``.
        """
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

    def cached_interface(
        self,
        switch_id: str,
        interface_name: str,
        *,
        original: bool = False,
    ) -> dict | None:
        """Return one cached interface without loading, refetching, or copying the full inventory."""
        if not isinstance(switch_id, str) or not switch_id:
            raise ValueError("InterfaceStateSnapshot.cached_interface requires a non-empty switch_id.")
        if not isinstance(interface_name, str) or not interface_name:
            raise ValueError("InterfaceStateSnapshot.cached_interface requires a non-empty interface_name.")
        inventory = self._original_interfaces_by_switch if original else self._interfaces_by_switch
        current = inventory.get(switch_id, {}).get(interface_name.lower())
        return deepcopy(current) if current is not None else None

    def has_switch(self, switch_id: str) -> bool:
        """Return whether a complete, clean current inventory is cached."""
        return switch_id in self._interfaces_by_switch and switch_id not in self._dirty_switches

    def cached_switch(self, switch_id: str) -> dict[str, dict] | None:
        """Return a clean cached inventory without triggering an API request."""
        if not self.has_switch(switch_id):
            return None
        return deepcopy(self._interfaces_by_switch[switch_id])

    @property
    def cached_switch_ids(self) -> frozenset[str]:
        """Return switch IDs whose complete current inventories are safe to consume."""
        return frozenset(switch_id for switch_id in self._interfaces_by_switch if switch_id not in self._dirty_switches)

    @property
    def clean_interfaces_by_switch(self) -> dict[str, dict[str, dict]]:
        """Return isolated copies of all complete, non-dirty current inventories."""
        return {switch_id: deepcopy(interfaces) for switch_id, interfaces in self._interfaces_by_switch.items() if switch_id not in self._dirty_switches}

    def load_interface_summaries(
        self,
        identities: Iterable[tuple[str, str]],
    ) -> dict[tuple[str, str], dict]:
        """Return requested summary rows after one lazy, cached fetch per switch."""
        requested_by_switch: dict[str, set[str]] = {}
        for identity in identities:
            if not isinstance(identity, tuple) or len(identity) != 2:
                raise ValueError("Interface summary identities must be (switch_id, interface_name) tuples.")
            switch_id, interface_name = identity
            if not isinstance(switch_id, str) or not switch_id:
                raise ValueError("Interface summary identities require a non-empty switch_id.")
            if not isinstance(interface_name, str) or not interface_name:
                raise ValueError("Interface summary identities require a non-empty interface_name.")
            requested_by_switch.setdefault(switch_id, set()).add(interface_name.lower())

        for switch_id in requested_by_switch:
            if switch_id in self._interface_summaries_by_switch:
                self._interface_summary_cache_hits += 1
                continue
            self._interface_summaries_by_switch[switch_id] = self._fetch_interface_summary_switch(switch_id)
            self._requested_summary_switches.add(switch_id)

        return {
            (switch_id, interface_name): deepcopy(summary)
            for switch_id, interface_names in requested_by_switch.items()
            for interface_name in sorted(interface_names)
            if (summary := self._interface_summaries_by_switch[switch_id].get(interface_name)) is not None
        }

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
    def interface_summaries_by_identity(self) -> dict[tuple[str, str], dict]:
        """Return all cached summary rows keyed by switch ID and interface name."""
        return {
            (switch_id, interface_name): deepcopy(summary)
            for switch_id, summaries in self._interface_summaries_by_switch.items()
            for interface_name, summary in summaries.items()
        }

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
        # Summary rows describe the same controller intent through a different
        # endpoint.  A raw-state overlay makes any previously cached summary for
        # this switch stale even though the raw cache itself remains clean.
        self._interface_summaries_by_switch.pop(switch_id, None)
        self._snapshot_overlays += 1
        return deepcopy(candidate)

    def mark_dirty(self, switch_ids: str | Iterable[str]) -> None:
        """Mark local switch inventories stale without issuing a request.

        This is used after mutation requests, or any other event that can make
        cached controller intent unreliable. It does not inspect or change the
        controller configuration synchronization status.
        """
        for switch_id in self._normalise_switch_ids(switch_ids):
            self._interface_summaries_by_switch.pop(switch_id, None)
            self._dirty_switches.add(switch_id)

    def invalidate(self, switch_ids: str | Iterable[str]) -> None:
        """Discard current switch caches, retain originals, and mark locally dirty."""
        for switch_id in self._normalise_switch_ids(switch_ids):
            self._interfaces_by_switch.pop(switch_id, None)
            self._interface_summaries_by_switch.pop(switch_id, None)
            self._dirty_switches.add(switch_id)

    def refresh(self, switch_ids: str | Iterable[str]) -> dict[str, dict[str, dict]]:
        """Explicitly refetch unique switches and clear their local dirty markers.

        Each switch increments ``_interface_inventory_refreshes`` before the
        attempt. ``invalidate`` then marks it dirty and ``load_switch`` increments
        ``_dirty_refetches`` before fetching. Therefore one explicit refresh
        normally contributes one to both counters; HTTP pages are counted by
        ``_interface_inventory_gets``.
        """
        normalised = self._normalise_switch_ids(switch_ids)
        self._interface_inventory_refreshes += len(normalised)
        self.invalidate(normalised)
        return self.load_switches(normalised)

    @property
    def request_stats(self) -> dict[str, int]:
        """Return logical snapshot lifecycle counts and separate HTTP request counts."""
        return {
            "switches": len(self._requested_switches),
            "interface_inventory_gets": self._interface_inventory_gets,
            "interface_inventory_pages": self._interface_inventory_pages,
            "interface_inventory_cache_hits": self._cache_hits,
            "interface_summary_switches": len(self._requested_summary_switches),
            "interface_summary_gets": self._interface_summary_gets,
            "interface_summary_pages": self._interface_summary_pages,
            "interface_summary_cache_hits": self._interface_summary_cache_hits,
            "interface_inventory_refreshes": self._interface_inventory_refreshes,
            "interface_inventory_dirty_refetches": self._dirty_refetches,
            "snapshot_overlays": self._snapshot_overlays,
        }
