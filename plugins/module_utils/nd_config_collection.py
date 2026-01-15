# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import sys
from copy import deepcopy
from functools import reduce

# Python 2 and 3 compatibility (To be removed in the future)
if sys.version_info[0] >= 3:
    from collections.abc import MutableMapping
    iteritems = lambda d: d.items()
else:
    from collections import MutableMapping
    iteritems = lambda d: d.iteritems()

# TODO: Adapt to Pydantic Models
# NOTE: Single-Index Hybrid Collection for ND Network Resource Module
class NDConfigCollection(MutableMapping):

    def __init__(self, identifier_keys, data=None, use_composite_keys=False):
        self.identifier_keys = identifier_keys
        self.use_composite_keys = use_composite_keys
        
        # Dual Storage
        self._list = []
        self._map = {}
        
        if data:
            for item in data:
                self.add(item)
    
    # TODO: add a method to get nested keys, ex: get("spec", {}).get("onboardUrl")
    def _get_identifier_value(self, config):
        """Generates the internal map key based on the selected mode."""
        if self.use_composite_keys:
            # Mode: Composite (Tuple of ALL keys)
            values = []
            for key in self.identifier_keys:
                val = config.get(key)
                if val is None:
                    return None # Missing a required part
                values.append(val)
            return tuple(values)
        else:
            # Mode: Priority (First available key)
            for key in self.identifier_keys:
                if key in config:
                    return config[key]
            return None

    # Magic Methods
    def __getitem__(self, key):
        return self._map[key]

    def __setitem__(self, key, value):
        if key in self._map:
            old_ref = self._map[key]
            try:
                idx = self._list.index(old_ref)
                self._list[idx] = value
                self._map[key] = value
            except ValueError:
                pass 
        else:
            # Add new
            self._list.append(value)
            self._map[key] = value

    def __delitem__(self, key):
        if key in self._map:
            obj_ref = self._map[key]
            del self._map[key]
            self._list.remove(obj_ref)
        else:
            raise KeyError(key)

    def __iter__(self):
        return iter(self._map)

    def __len__(self):
        return len(self._list)
    
    def __eq__(self, other):
        if isinstance(other, NDConfigCollection):
            return self._list == other._list
        elif isinstance(other, list):
            return self._list == other
        elif isinstance(other, dict):
            return self._map == other
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return str(self._list)

    # Helper Methods
    def _filter_dict(self, data, ignore_keys):
        return {k: v for k, v in iteritems(data) if k not in ignore_keys}

    def _issubset(self, subset, superset):
        if type(subset) is not type(superset):
            return False

        if not isinstance(subset, dict):
            if isinstance(subset, list):
                return all(item in superset for item in subset)
            return subset == superset

        for key, value in iteritems(subset):
            if value is None:
                continue

            if key not in superset:
                return False

            superset_value = superset.get(key)

            if not self._issubset(value, superset_value):
                return False
        return True

    def _remove_unwanted_keys(self, data, unwanted_keys):
        for key in unwanted_keys:
            if isinstance(key, str):
                if key in data:
                    del data[key]
            elif isinstance(key, list) and len(key) > 0:
                key_path, last = key[:-1], key[-1]
                try:
                    parent = reduce(lambda d, k: d.get(k) if isinstance(d, dict) else None, key_path, data)
                    if isinstance(parent, dict) and last in parent:
                        del parent[last]
                except (KeyError, TypeError):
                    pass
        return data

    # Core Operations
    def to_list(self):
        return self._list
    
    def to_dict(self):
        return self._map

    def copy(self):
        return NDConfigCollection(self.identifier_keys, deepcopy(self._list), self.use_composite_keys)

    def add(self, config):
        ident = self._get_identifier_value(config)
        if ident is None:
            mode = "Composite" if self.use_composite_keys else "Priority"
            raise ValueError("[{0} Mode] Config missing required keys: {1}".format(mode, self.identifier_keys))
        
        if ident in self._map:
            self.__setitem__(ident, config)
        else:
            self._list.append(config)
            self._map[ident] = config

    def merge(self, new_config):
        ident = self._get_identifier_value(new_config)
        if ident and ident in self._map:
            self._map[ident].update(new_config)
        else:
            self.add(new_config)

    def replace(self, new_config):
        ident = self._get_identifier_value(new_config)
        if ident:
            self[ident] = new_config
        else:
            self.add(new_config)

    def remove(self, identifiers):
        # Try Map Removal
        try:
            target_key = self._get_identifier_value(identifiers)
            if target_key and target_key in self._map:
                self.__delitem__(target_key)
                return
        except Exception:
            pass

        # Fallback: Linear Removal
        to_remove = []
        for config in self._list:
            match = True
            for k, v in iteritems(identifiers):
                if config.get(k) != v:
                    match = False
                    break
            if match:
                to_remove.append(self._get_identifier_value(config))
        
        for ident in to_remove:
            if ident in self._map:
                self.__delitem__(ident)

    def get_by_key(self, key, default=None):
        return self._map.get(key, default)

    def get_by_idenfiers(self, identifiers, default=None):
        # Try Map Lookup
        target_key = self._get_identifier_value(identifiers)
        if target_key and target_key in self._map:
            return self._map[target_key]

        # Fallback: Linear Lookup
        valid_search_keys = [k for k in identifiers if k in self.identifier_keys]
        if not valid_search_keys:
            return default

        for config in self._list:
            match = True
            for k in valid_search_keys:
                if config.get(k) != identifiers[k]:
                    match = False
                    break
            if match:
                return config
        return default

    # Diff logic
    def get_diff_config(self, new_config, unwanted_keys=None):
        unwanted_keys = unwanted_keys or []

        ident = self._get_identifier_value(new_config)
        
        if not ident or ident not in self._map:
            return "new"

        existing = deepcopy(self._map[ident])
        sent = deepcopy(new_config)

        self._remove_unwanted_keys(existing, unwanted_keys)
        self._remove_unwanted_keys(sent, unwanted_keys)

        is_subset = self._issubset(sent, existing)

        if is_subset:
            return "no_diff"
        else:
            return "changed"

    def get_diff_collection(self, new_collection, unwanted_keys=None):
        if not isinstance(new_collection, NDConfigCollection):
            raise TypeError("Argument must be an NDConfigCollection")

        if len(self) != len(new_collection):
            return True

        for item in new_collection.to_list():
            if self.get_diff_config(item, unwanted_keys) != "no_diff":
                return True

        for ident in self._map:
            if ident not in new_collection._map:
                return True

        return False

    def get_diff_identifiers(self, new_collection):
        current_identifiers = set(self.config_collection.keys())
        other_identifiers = set(new_collection.config_collection.keys())

        return list(current_identifiers - other_identifiers)

    # Sanitize Operations
    def sanitize(self, keys_to_remove=None, values_to_remove=None, remove_none_values=False):
        keys_to_remove = keys_to_remove or []
        values_to_remove = values_to_remove or []

        def recursive_clean(obj):
            if isinstance(obj, dict):
                keys = list(obj.keys())
                for k in keys:
                    v = obj[k]
                    if k in keys_to_remove or v in values_to_remove or (remove_none_values and v is None):
                        del obj[k]
                        continue
                    if isinstance(v, (dict, list)):
                        recursive_clean(v)
            elif isinstance(obj, list):
                for item in obj:
                    recursive_clean(item)

        for item in self._list:
            recursive_clean(item)
