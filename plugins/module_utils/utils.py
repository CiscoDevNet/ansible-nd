# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


def snake_to_camel(snake_str, upper_case_components=None):
    if snake_str is not None and "_" in snake_str:
        if upper_case_components is None:
            upper_case_components = []
        components = snake_str.split("_")
        camel_case_str = components[0]

        for component in components[1:]:
            if component in upper_case_components:
                camel_case_str += component.upper()
            else:
                camel_case_str += component.title()

        return camel_case_str
    else:
        return snake_str


def check_if_all_elements_are_none(values):
    """
    Checks if all elements in the provided iterable are None

    :param values: An iterable containing values to be checked -> Iterable[Any]
    :return: True if all elements are None, False otherwise -> Bool
    """
    return all(value is None for value in values)


def delete_none_values(obj_to_sanitize, recursive=True):
    """
    Removes keys with None values from a Python object, which can be either a list or a dictionary.
    Optionally performs the operation recursively on nested structures.

    :param obj_to_sanitize: The Python object to sanitize from None values. -> List or Dict
    :param recursive: A boolean flag indicating whether to recursively sanitize nested objects. Defaults to True. -> bool
    :return: A sanitized copy of the original Python object, with all keys with None values removed. -> List or Dict
    """
    if isinstance(obj_to_sanitize, dict):
        sanitized_dict = {}
        for item_key, item_value in obj_to_sanitize.items():
            if recursive and isinstance(item_value, (dict, list)):
                sanitized_dict[item_key] = delete_none_values(item_value, recursive)
            elif item_value is not None:
                sanitized_dict[item_key] = item_value
        return sanitized_dict

    elif isinstance(obj_to_sanitize, list):
        sanitized_list = []
        for item in obj_to_sanitize:
            if recursive and isinstance(item, (dict, list)):
                sanitized_list.append(delete_none_values(item, recursive))
            elif item is not None:
                sanitized_list.append(item)
        return sanitized_list

    else:
        raise TypeError("Object to sanitize must be of type list or dict. Got {}".format(type(obj_to_sanitize)))
