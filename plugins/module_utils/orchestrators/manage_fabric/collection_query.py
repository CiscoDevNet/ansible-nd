# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared, ownership-safe inventory reads for ND Manage fabric modules."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)


class ManageFabricCollectionQueryMixin:
    """Read one fabric family without truncation or cross-family ownership.

    ``GET /manage/fabrics`` is paginated explicitly so exact states receive a
    complete family inventory.  Configured names are then reconciled through
    the name-addressed endpoint.  The latter is authoritative for those names:
    it protects state classification from the list endpoint's read-after-write
    cache while also detecting a name already owned by another fabric family.
    """

    fabric_inventory_category: ClassVar[str]
    fabric_inventory_management_type: ClassVar[str]
    fabric_inventory_page_size: ClassVar[int] = 100
    fabric_inventory_max_pages: ClassVar[int] = 1000

    @staticmethod
    def _inventory_int(value: Any) -> int | None:
        """Return a non-negative pagination integer, excluding booleans."""
        if isinstance(value, bool):
            return None
        try:
            converted = int(value)
        except (TypeError, ValueError):
            return None
        return converted if converted >= 0 else None

    @classmethod
    def _inventory_has_next_page(cls, response: Mapping[str, Any], page_count: int, offset: int) -> bool:
        """Interpret ND metadata, falling back to the requested page length."""
        metadata = response.get("meta") or response.get("metadata") or {}
        if not isinstance(metadata, Mapping):
            metadata = {}
        counts = metadata.get("counts") or {}
        if not isinstance(counts, Mapping):
            counts = {}

        total = cls._inventory_int(metadata.get("total"))
        if total is None:
            total = cls._inventory_int(counts.get("total"))
        if total is not None:
            return offset + page_count < total

        remaining = cls._inventory_int(metadata.get("remaining"))
        if remaining is None:
            remaining = cls._inventory_int(counts.get("remaining"))
        if remaining is not None:
            return remaining > 0

        return page_count == cls.fabric_inventory_page_size

    def _inventory_item_matches(self, item: Any) -> bool:
        """Return whether a response row belongs to this module's family."""
        if not isinstance(item, Mapping):
            return False
        management = item.get("management")
        return (
            item.get("category") == self.fabric_inventory_category
            and isinstance(management, Mapping)
            and management.get("type") == self.fabric_inventory_management_type
        )

    def _configured_fabric_names(self) -> list[str]:
        """Return stable, de-duplicated identifiers from public module config."""
        config = self.rest_send.params.get("config") or []
        if not isinstance(config, list):
            return []

        names: list[str] = []
        seen: set[str] = set()
        for item in config:
            if not isinstance(item, Mapping):
                continue
            name = item.get("fabric_name")
            if not isinstance(name, str) or not name or name in seen:
                continue
            names.append(name)
            seen.add(name)
        return names

    def _query_fabric_inventory_pages(self) -> dict[str, dict[str, Any]]:
        """Return the complete owned inventory, keyed and de-duplicated by name."""
        page_size = self.fabric_inventory_page_size
        max_pages = self.fabric_inventory_max_pages
        if page_size <= 0 or max_pages <= 0:
            raise RuntimeError("Fabric inventory pagination limits must be positive.")

        inventory: dict[str, dict[str, Any]] = {}
        seen_page_names: set[str] = set()
        offset = 0

        for page_number in range(max_pages):
            endpoint = self.query_all_endpoint()
            endpoint.endpoint_params.category = self.fabric_inventory_category
            endpoint.endpoint_params.max = page_size
            endpoint.endpoint_params.offset = offset
            endpoint.endpoint_params.sort = "name"
            response = self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True)
            if not response:
                return inventory
            if not isinstance(response, Mapping):
                raise RuntimeError("Fabric inventory list response must be an object.")

            page = response.get("fabrics", []) or []
            if not isinstance(page, list):
                raise RuntimeError("Fabric inventory response field 'fabrics' must be a list.")

            page_names: set[str] = set()
            for item in page:
                if not isinstance(item, Mapping):
                    continue
                name = item.get("name")
                if not isinstance(name, str) or not name:
                    continue
                page_names.add(name)
                if self._inventory_item_matches(item) and name not in inventory:
                    inventory[name] = dict(item)

            new_page_names = page_names - seen_page_names
            if page_number > 0 and page and not new_page_names:
                raise RuntimeError("Fabric inventory pagination made no progress " f"at offset {offset}; refusing to repeat a page.")

            has_next_page = self._inventory_has_next_page(response, len(page), offset)
            if not has_next_page:
                return inventory
            if not page or not new_page_names:
                raise RuntimeError("Fabric inventory pagination made no progress " f"at offset {offset}; refusing to repeat a page.")
            seen_page_names.update(page_names)
            offset += len(page)

            if page_number + 1 == max_pages:
                raise RuntimeError(f"Fabric inventory pagination exceeded the {max_pages}-page safety limit.")

        raise RuntimeError(f"Fabric inventory pagination exceeded the {max_pages}-page safety limit.")

    def _reconcile_configured_fabrics(self, inventory: dict[str, dict[str, Any]]) -> None:
        """Overlay authoritative per-name reads for every configured identifier."""
        for requested_name in self._configured_fabric_names():
            endpoint = self.query_one_endpoint()
            endpoint.set_identifiers(requested_name)
            response = self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True)

            # A name-addressed 404 is authoritative over a stale list row.
            if not response:
                inventory.pop(requested_name, None)
                continue
            if not isinstance(response, Mapping):
                raise RuntimeError(f"Fabric lookup for {requested_name!r} must return an object.")

            response_name = response.get("name")
            if response_name != requested_name:
                raise RuntimeError(f"Fabric lookup for {requested_name!r} returned unexpected name {response_name!r}.")
            if not self._inventory_item_matches(response):
                management = response.get("management")
                actual_type = management.get("type") if isinstance(management, Mapping) else None
                raise RuntimeError(
                    f"Fabric name collision for {requested_name!r}: controller object has "
                    f"category={response.get('category')!r}, management.type={actual_type!r}; "
                    f"this module owns category={self.fabric_inventory_category!r}, "
                    f"management.type={self.fabric_inventory_management_type!r}."
                )

            inventory[requested_name] = dict(response)

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """Return the complete, reconciled inventory owned by this module."""
        del model_instance, kwargs
        try:
            inventory = self._query_fabric_inventory_pages()
            self._reconcile_configured_fabrics(inventory)
            return list(inventory.values())
        except Exception as error:
            raise Exception(f"Query all failed: {error}") from error
