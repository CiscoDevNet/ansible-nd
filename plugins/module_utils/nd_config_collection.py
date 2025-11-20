# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy


# TODO: move it to utils.py
def sanitize_dict(dict_to_sanitize, keys=None, values=None, recursive=True, remove_none_values=True):
    if keys is None:
        keys = []
    if values is None:
        values = []

    result = deepcopy(dict_to_sanitize)
    for k, v in dict_to_sanitize.items():
        if k in keys:
            del result[k]
        elif v in values or (v is None and remove_none_values):
            del result[k]
        elif isinstance(v, dict) and recursive:
            result[k] = sanitize_dict(v, keys, values)
        elif isinstance(v, list) and recursive:
            for index, item in enumerate(v):
                if isinstance(item, dict):
                    result[k][index] = sanitize_dict(item, keys, values)
    return result


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


# TODO: Add a get_diff_config function
# TODO: Handle multiple identifiers
# TODO: Add descriptions
# TODO: Maybe leverage MutableMapping, MutableSequence from collections.abc
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
                raise InvalidNDConfigError("Missing '{0}' in item: {1}".format(self.identifier_key, item))

            key = item[self.identifier_key]
            new_dict[key] = item.copy()
        self.config_collection = new_dict

    # Basic Operations
    def replace(self, config):
        if not isinstance(config, dict):
            raise InvalidNDConfigError("Config must be a dict.")
        if self.identifier_key not in config:
            raise InvalidNDConfigError("Missing '{0}' in config: {1}".format(self.identifier_key, config))

        key = config[self.identifier_key]
        self.config_collection[key] = config.copy()

    def merge(self, config):
        if not isinstance(config, dict):
            raise InvalidNDConfigError("Config must be a dict.")
        if self.identifier_key not in config:
            raise InvalidNDConfigError("Missing '{0}' in config: {1}".format(self.identifier_key, config))

        key = config[self.identifier_key]
        if key in self.config_collection:
            self.config_collection[key].update(config.copy())
        else:
            self.config_collection[key] = config.copy()

    def remove(self, identifier):
        if identifier not in self.config_collection:
            raise NDConfigNotFoundError("Configuration with identifier '{0}' not found.".format(identifier))
        del self.config_collection[identifier]

    def get(self, identifier):
        config = self.config_collection.get(identifier)
        if config is None:
            raise NDConfigNotFoundError("Configuration with identifier '{0}' not found.".format(identifier))
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
            raise InvalidNDConfigError("Config must contain '{0}' when setting via __setitem__.".format(self.identifier_key))
        if config[self.identifier_key] != identifier:
            raise NDIdentifierMismatchError(
                "Identifier '{0}' in key does not match '{1}' value '{2}' in config.".format(identifier, self.identifier_key, config[self.identifier_key])
            )
        self.replace(config)

    def __delitem__(self, identifier):
        self.remove(identifier)

    def __eq__(self, other):
        if not isinstance(other, NDConfigCollection):
            # TODO: Make it works for list and dict as well. For now just raise an error
            raise InvalidNDConfigError("Can only do __eq__ with another NDConfigCollection instance.")

        if self.identifier_key != other.identifier_key:
            return False

        return self.config_collection == other.config_collection

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return "NDConfigCollection(identifier_key='{0}', count={1})".format(self.identifier_key, len(self))

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
        sanitized_config_collection = sanitize_dict(self.config_collection, keys_to_remove, values_to_remove, recursive, remove_none_values)
        return NDConfigCollection(self.identifier_key, data=sanitized_config_collection)

    def get_diff_identifiers(self, other_collection):
        if not isinstance(other_collection, NDConfigCollection):
            raise InvalidNDConfigError("Can only do get_removed_identifiers with another NDConfigCollection instance.")

        if self.identifier_key != other_collection.identifier_key:
            raise NDIdentifierMismatchError(
                "Cannot do get_removed_identifiers with another NDConfigCollection with different identifier_key. "
                "Expected '{0}', got '{1}'.".format(self.identifier_key, other_collection.identifier_key)
            )
        current_identifiers = set(self.config_collection.keys())
        other_identifiers = set(other_collection.config_collection.keys())

        return list(current_identifiers - other_identifiers)
