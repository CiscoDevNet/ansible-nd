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
