# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import TypeVar, Generic, Optional, List, Dict, Any, Union, Tuple, Literal, Callable
from copy import deepcopy

# TODO: To be replaced with: from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from .models.base import NDBaseModel
from .utils import issubset

# Type aliases
# NOTE: Maybe add more type aliases in the future if needed
ModelType = TypeVar('ModelType', bound=NDBaseModel)
# TODO: Defined the same acros multiple files -> maybe move to constants.py
IdentifierKey = Union[str, int, Tuple[Any, ...]]

# TODO:Might make it a Pydantic RootModel (low priority but medium impact on NDNetworkResourceModule)
class NDConfigCollection(Generic[ModelType]):
    """
    Nexus Dashboard configuration collection for NDBaseModel instances.
    """
    
    def __init__(self, model_class: ModelType, items: Optional[List[ModelType]] = None):
        """
        Initialize collection.
        """
        self._model_class: ModelType = model_class
        
        # Dual storage
        self._items: List[ModelType] = []
        self._index: Dict[IdentifierKey, int] = {}

        if items:
            for item in items:
                self.add(item)
    
    # TODO: might not be necessary
    def _extract_key(self, item: ModelType) -> IdentifierKey:
        """
        Extract identifier key from item.
        """
        try:
            return item.get_identifier_value()
        except Exception as e:
            raise ValueError(f"Failed to extract identifier: {e}") from e
    
    # TODO: optimize it -> only needed for delete method (low priority)
    def _rebuild_index(self) -> None:
        """Rebuild index from scratch (O(n) operation)."""
        self._index.clear()
        for index, item in enumerate(self._items):
            key = self._extract_key(item)
            self._index[key] = index
    
    # Core CRUD Operations
    
    def add(self, item: ModelType) -> IdentifierKey:
        """
        Add item to collection (O(1) operation).
        """
        if not isinstance(item, self._model_class):
            raise TypeError(
                f"Item must be instance of {self._model_class.__name__}, "
                f"got {type(item).__name__}"
            )
        
        key = self._extract_key(item)
        
        if key in self._index:
            raise ValueError(
                f"Item with identifier {key} already exists. Use replace() to update"
            )
        
        position = len(self._items)
        self._items.append(item)
        self._index[key] = position
        
        return key
    
    def get(self, key: IdentifierKey) -> Optional[ModelType]:
        """
        Get item by identifier key (O(1) operation).
        """
        index = self._index.get(key)
        return self._items[index] if index is not None else None
    
    def replace(self, item: ModelType) -> bool:
        """
        Replace existing item with same identifier (O(1) operation).
        """
        if not isinstance(item, self._model_class):
            raise TypeError(
                f"Item must be instance of {self._model_class.__name__}, "
                f"got {type(item).__name__}"
            )
        
        key = self._extract_key(item)
        index = self._index.get(key)
        
        if index is None:
            return False
        
        self._items[index] = item
        return True

    def merge(self, item: ModelType) -> ModelType:
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
    
    # NOTE: Maybe add a similar one in the NDBaseModel (-> but is it necessary?)
    def get_diff_config(self, new_item: ModelType, unwanted_keys: Optional[List[Union[str, List[str]]]] = None) -> Literal["new", "no_diff", "changed"]:
        """
        Compare single item against collection.
        """
        try:
            key = self._extract_key(new_item)
        except ValueError:
            return "new"
        
        existing = self.get(key)
        
        if existing is None:
            return "new"

        existing_data = existing.to_diff_dict()
        new_data = new_item.to_diff_dict()
        
        if unwanted_keys:
            existing_data = self._remove_unwanted_keys(existing_data, unwanted_keys)
            new_data = self._remove_unwanted_keys(new_data, unwanted_keys)

        is_subset = issubset(new_data, existing_data)
        
        return "no_diff" if is_subset else "changed"
    
    def get_diff_collection(self, other: "NDConfigCollection[ModelType]", unwanted_keys: Optional[List[Union[str, List[str]]]] = None) -> bool:
        """
        Check if two collections differ.
        """
        if not isinstance(other, NDConfigCollection):
            raise TypeError("Argument must be NDConfigCollection")
        
        if len(self) != len(other):
            return True

        for item in other:
            if self.get_diff_config(item, unwanted_keys) != "no_diff":
                return True

        for key in self.keys():
            if other.get(key) is None:
                return True
        
        return False
    
    def get_diff_identifiers(self, other: "NDConfigCollection[ModelType]") -> List[IdentifierKey]:
        """
        Get identifiers in self but not in other.
        """
        current_keys = set(self.keys())
        other_keys = set(other.keys())
        return list(current_keys - other_keys)

    # TODO: Maybe not necessary
    def _remove_unwanted_keys(self, data: Dict, unwanted_keys: List[Union[str, List[str]]]) -> Dict:
        """Remove unwanted keys from dict (supports nested paths)."""
        data = deepcopy(data)
        
        for key in unwanted_keys:
            if isinstance(key, str):
                if key in data:
                    del data[key]
            
            elif isinstance(key, list) and len(key) > 0:
                try:
                    parent = data
                    for k in key[:-1]:
                        if isinstance(parent, dict) and k in parent:
                            parent = parent[k]
                        else:
                            break
                    else:
                        if isinstance(parent, dict) and key[-1] in parent:
                            del parent[key[-1]]
                except (KeyError, TypeError, IndexError):
                    pass
        
        return data
 
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

    def copy(self) -> "NDConfigCollection[ModelType]":
        """Create deep copy of collection."""
        return NDConfigCollection(
            model_class=self._model_class,
            items=deepcopy(self._items)
        )

    # Collection Serialization

    def to_list(self, **kwargs) -> List[Dict]:
        """
        Export as list of dicts (with aliases).
        """
        return [item.model_dump(by_alias=True, exclude_none=True, **kwargs) for item in self._items]
    
    def to_payload_list(self) -> List[Dict[str, Any]]:
        """
        Export as list of API payloads.
        """
        return [item.to_payload() for item in self._items]
    
    @classmethod
    def from_list(cls, data: List[Dict], model_class: type[ModelType]) -> "NDConfigCollection[ModelType]":
        """
        Create collection from list of dicts.
        """
        items = [model_class.model_validate(item_data, by_name=True) for item_data in data]
        return cls(model_class=model_class, items=items)
    
    @classmethod
    def from_api_response(cls, response_data: List[Dict[str, Any]], model_class: type[ModelType]) -> "NDConfigCollection[ModelType]":
        """
        Create collection from API response.
        """
        items = [model_class.from_response(item_data) for item_data in response_data]
        return cls(model_class=model_class, items=items)
