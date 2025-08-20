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


def compare_config_and_remote_objects(remote_objects, config_objects, key="name"):
    remote_object_names = {obj[key] for obj in remote_objects}
    config_object_names = {obj[key] for obj in config_objects}

    # Common objects from Config (name in both remote and config data)
    update = [obj for obj in config_objects if obj[key] in remote_object_names]

    # Unmatched objects from Remote (name not in Config)
    delete = [obj for obj in remote_objects if obj[key] not in config_object_names]

    # Unmatched objects from Config (name not in Remote)
    create = [obj for obj in config_objects if obj[key] not in remote_object_names]

    return {
        "config_data_update": update,
        "remote_data_delete": delete,  # Only when state is overridden
        "config_data_create": create,
    }


def compare_unordered_list_of_dicts(list1, list2):
    if (not isinstance(list1, list) or not isinstance(list2, list)) or (len(list1) != len(list2)):
        return False

    for dict1 in list1:
        found_match = False
        for i, dict2 in enumerate(list2):
            if dict1 == dict2:
                list2.pop(i)
                found_match = True
                break
        if not found_match:
            return False

    return True


def wrap_objects_by_key(object_list, key="name"):
    return {obj.get(key): obj for obj in object_list}
