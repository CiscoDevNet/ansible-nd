# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import Optional, List, Dict, Any, Literal
from copy import deepcopy
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.types import IdentifierKey


class NDConfigCollection:
    """
    Nexus Dashboard configuration collection for NDBaseModel instances.
    """

    def __init__(self, model_class: NDBaseModel, items: Optional[List[NDBaseModel]] = None):
        """
        Initialize collection.
        """
        self._model_class: NDBaseModel = model_class

        # Dual storage
        self._items: List[NDBaseModel] = []
        self._index: Dict[IdentifierKey, int] = {}

        if items:
            for item in items:
                self.add(item)

    def _extract_key(self, item: NDBaseModel) -> IdentifierKey:
        """
        Extract identifier key from item.
        """
        try:
            return item.get_identifier_value()
        except Exception as e:
            raise ValueError(f"Failed to extract identifier: {e}") from e

    def _rebuild_index(self) -> None:
        """Rebuild index from scratch (O(n) operation)."""
        self._index.clear()
        for index, item in enumerate(self._items):
            key = self._extract_key(item)
            self._index[key] = index

    # Core Operations

    def add(self, item: NDBaseModel) -> IdentifierKey:
        """
        Add item to collection (O(1) operation).
        """
        if not isinstance(item, self._model_class):
            raise TypeError(f"Item must be instance of {self._model_class.__name__}, " f"got {type(item).__name__}")

        key = self._extract_key(item)

        if key in self._index:
            raise ValueError(f"Item with identifier {key} already exists. Use replace() to update")

        position = len(self._items)
        self._items.append(item)
        self._index[key] = position

        return key

    def get(self, key: IdentifierKey) -> Optional[NDBaseModel]:
        """
        Get item by identifier key (O(1) operation).
        """
        index = self._index.get(key)
        return self._items[index] if index is not None else None

    def replace(self, item: NDBaseModel) -> bool:
        """
        Replace existing item with same identifier (O(1) operation).
        """
        if not isinstance(item, self._model_class):
            raise TypeError(f"Item must be instance of {self._model_class.__name__}, " f"got {type(item).__name__}")

        key = self._extract_key(item)
        index = self._index.get(key)

        if index is None:
            return False

        self._items[index] = item
        return True

    def merge(self, item: NDBaseModel) -> NDBaseModel:
        """
        Merge item with existing, or add if not present.
        """
        key = self._extract_key(item)
        existing = self.get(key)

        if existing is None:
            self.add(item)
            return item
        else:
            merged = existing.merge(item)
        self.replace(merged)
        return merged

    def delete(self, key: IdentifierKey) -> bool:
        """
        Delete item by identifier (O(n) operation due to index rebuild)
        """
        index = self._index.get(key)

        if index is None:
            return False

        del self._items[index]
        self._rebuild_index()

        return True

    # Diff Operations

    def get_diff_config(self, new_item: NDBaseModel, only_set_fields: bool = False) -> Literal["new", "no_diff", "changed"]:
        """
        Compare single item against collection.

        Args:
            new_item: The proposed configuration item.
            only_set_fields: When True, only compare fields explicitly set in
                ``new_item``. Useful for merge operations where unspecified
                fields should not trigger a diff.
        """
        try:
            key = self._extract_key(new_item)
        except ValueError:
            return "new"

        existing = self.get(key)

        if existing is None:
            return "new"

        is_subset = existing.get_diff(new_item, only_set_fields=only_set_fields)

        return "no_diff" if is_subset else "changed"

    def get_diff_collection(self, other: "NDConfigCollection") -> bool:
        """
        Check if two collections differ.
        """
        if not isinstance(other, NDConfigCollection):
            raise TypeError("Argument must be NDConfigCollection")

        if len(self) != len(other):
            return True

        for item in other:
            if self.get_diff_config(item) != "no_diff":
                return True

        for key in self.keys():
            if other.get(key) is None:
                return True

        return False

    def get_diff_identifiers(self, other: "NDConfigCollection") -> List[IdentifierKey]:
        """
        Get identifiers in self but not in other.
        """
        current_keys = set(self.keys())
        other_keys = set(other.keys())
        return list(current_keys - other_keys)

    # Collection Operations

    def __len__(self) -> int:
        """Return number of items."""
        return len(self._items)

    def __iter__(self):
        """Iterate over items."""
        return iter(self._items)

    def keys(self) -> List[IdentifierKey]:
        """Get all identifier keys."""
        return list(self._index.keys())

    def copy(self) -> "NDConfigCollection":
        """Create deep copy of collection."""
        return NDConfigCollection(model_class=self._model_class, items=deepcopy(self._items))

    # Collection Serialization

    def to_ansible_config(self, **kwargs) -> List[Dict]:
        """
        Export as an Ansible config.
        """
        return [item.to_config(**kwargs) for item in self._items]

    def to_payload_list(self, **kwargs) -> List[Dict[str, Any]]:
        """
        Export as list of API payloads.
        """
        return [item.to_payload(**kwargs) for item in self._items]

    @staticmethod
    def from_ansible_config(data: List[Dict], model_class: type[NDBaseModel], **kwargs) -> "NDConfigCollection":
        """
        Create collection from Ansible config.
        """
        items = [model_class.from_config(item_data, **kwargs) for item_data in data]
        return NDConfigCollection(model_class=model_class, items=items)

    @staticmethod
    def from_api_response(response_data: List[Dict[str, Any]], model_class: type[NDBaseModel], **kwargs) -> "NDConfigCollection":
        """
        Create collection from API response.
        """
        items = [model_class.from_response(item_data, **kwargs) for item_data in response_data]
        return NDConfigCollection(model_class=model_class, items=items)
