# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy


# Custom NDConfigCollection Exceptions
class NDConfigCollectionError(Exception):
    """Base exception for NDConfigCollection errors."""
    pass


class NDConfigNotFoundError(NDConfigCollectionError, KeyError):
    """Raised when a configuration is not found by its identifier."""
    pass


class NDIdentifierMismatchError(NDConfigCollectionError, ValueError):
    """Raised when an identifier in a config does not match the expected key."""
    pass


class InvalidNDConfigError(NDConfigCollectionError, TypeError):
    """Raised when a provided config is not a dictionary or is missing the identifier key."""
    pass


# TODO: Maybe add a get_diff_config function
# TODO: Handle multiple identifiers
# TODO: Add descriptions
# NOTE: New data structure for ND Network Resource Module
class NDConfigCollection:
    def __init__(self, identifier_key, data=None):
        if not isinstance(identifier_key, str):
            raise TypeError("identifier_key must be a string.")
        self.identifier_key = identifier_key
        self.config_collection = {}

        if data is not None:
            if isinstance(data, list):
                self.list_view = data
            elif isinstance(data, dict):
                self.config_collection = data
            else:
                raise TypeError("data must be a list of dicts or dict of configs.")

    @property
    def list_view(self):
        return [v.copy() for v in self.config_collection.values()]

    @list_view.setter
    def list_view(self, new_list):
        if not isinstance(new_list, list):
            raise TypeError("list_view must be set to a list.")

        new_dict = {}
        for item in new_list:
            if not isinstance(item, dict):
                raise TypeError("All items in list_view must be dicts.")
            if self.identifier_key not in item:
                raise InvalidNDConfigError(f"Missing '{self.identifier_key}' in item: {item}")

            key = item[self.identifier_key]
            new_dict[key] = item.copy()
        self.config_collection = new_dict

    # Basic Operations
    def replace(self, config):
        if not isinstance(config, dict):
            raise InvalidNDConfigError("Config must be a dict.")
        if self.identifier_key not in config:
            raise InvalidNDConfigError(f"Missing '{self.identifier_key}' in config: {config}")

        key = config[self.identifier_key]
        self.config_collection[key] = config.copy()

    def merge(self, config):
        if not isinstance(config, dict):
            raise InvalidNDConfigError("Config must be a dict.")
        if self.identifier_key not in config:
            raise InvalidNDConfigError(f"Missing '{self.identifier_key}' in config: {config}")

        key = config[self.identifier_key]
        if key in self.config_collection:
            self.config_collection[key].update(config.copy())
        else:
            self.config_collection[key] = config.copy()

    def remove(self, identifier):
        if identifier not in self.config_collection:
            raise NDConfigNotFoundError(f"Configuration with identifier '{identifier}' not found.")
        del self.config_collection[identifier]

    def get(self, identifier):
        config = self.config_collection.get(identifier)
        if config is None:
            raise NDConfigNotFoundError(f"Configuration with identifier '{identifier}' not found.")
        return config.copy()

    # Magic Methods
    def __len__(self):
        return len(self.config_collection)

    def __contains__(self, identifier):
        return identifier in self.config_collection

    def __iter__(self):
        for config in self.config_collection.values():
            yield config.copy()

    def __getitem__(self, identifier):
        return self.get(identifier)

    def __setitem__(self, identifier, config):
        if not isinstance(config, dict):
            raise InvalidNDConfigError("Config must be a dict when setting via __setitem__.")
        if self.identifier_key not in config:
            raise InvalidNDConfigError(f"Config must contain '{self.identifier_key}' when setting via __setitem__.")
        if config[self.identifier_key] != identifier:
            raise NDIdentifierMismatchError(
                f"Identifier '{identifier}' in key does not match '{self.identifier_key}' value "
f"'{config[self.identifier_key]}' in config."
            )
        self.replace(config)

    def __delitem__(self, identifier):
        self.remove(identifier)

    def __eq__(self, other):
        if not isinstance(other, NDConfigCollection):
            # TODO: Make it works for list and dict as well. For now just raise an error.
            raise InvalidNDConfigError("Can only do __eq__ with another NDConfigCollection instance.")

        if self.identifier_key != other.identifier_key:
            return False

        return self.config_collection == other.config_collection

    def __repr__(self):
        return f"NDConfigCollection(identifier_key='{self.identifier_key}', count={len(self)})"

    def __ne__(self, other):
        return not self.__eq__(other)

    # Standard Dictionary-like Views
    def keys(self):
        return self.config_collection.keys()

    def values(self):
        for v in self.config_collection.values():
            yield v.copy()

    def items(self):
        for k, v in self.config_collection.items():
            yield k, v.copy()

    # Utility/Convenience Functions
    def clear(self):
        self.config_collection.clear()

    def find_by_attribute(self, attribute_name, attribute_value):
        matching_configs = []
        for config in self.values():
            if config.get(attribute_name) == attribute_value:
                matching_configs.append(config.copy())
        return matching_configs

    def copy(self):
        return NDConfigCollection(self.identifier_key, data=deepcopy(self.config_collection))

    def sanitize(self, keys_to_remove=None, values_to_remove=None, recursive=True, remove_none_values=True):
        if keys_to_remove is None:
            keys_to_remove = []
        if values_to_remove is None:
            values_to_remove = []

        sanitized_collection = self.copy()
        for k, v in self.items():
            if k in keys_to_remove:
                del sanitized_collection[k]
            elif v in values_to_remove or (v is None and remove_none_values):
                del sanitized_collection[k]
            elif isinstance(v, dict) and recursive:
                sanitized_collection[k] = self.sanitize(v, keys_to_remove, values_to_remove)
            elif isinstance(v, list) and recursive:
                for index, item in enumerate(v):
                    if isinstance(item, dict):
                        sanitized_collection[k][index] = self.sanitize(item, keys_to_remove, values_to_remove)
        return sanitized_collection

    def get_diff_identifiers(self, other_collection):
        if not isinstance(other_collection, NDConfigCollection):
            raise InvalidNDConfigError("Can only do get_removed_identifiers with another NDConfigCollection instance.")

        if self.identifier_key != other_collection.identifier_key:
            raise NDIdentifierMismatchError(
                f"Cannot do get_removed_identifiers with another NDConfigCollection with different identifier_key. " 
f"Expected '{self.identifier_key}', got '{other_collection.identifier_key}'."
            )
        current_identifiers = set(self.config_collection.keys())
        other_identifiers = set(other_collection.config_collection.keys())

        return list(current_identifiers - other_identifiers)
