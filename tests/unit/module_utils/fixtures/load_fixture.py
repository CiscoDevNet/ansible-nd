# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Function to load test inputs from JSON files.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import json
import os
import sys

fixture_path = os.path.join(os.path.dirname(__file__), "fixture_data")


def load_fixture(filename):
    """
    load test inputs from json files
    """
    path = os.path.join(fixture_path, f"{filename}.json")

    try:
        with open(path, encoding="utf-8") as file_handle:
            data = file_handle.read()
    except IOError as exception:
        msg = f"Exception opening test input file {filename}.json : "
        msg += f"Exception detail: {exception}"
        print(msg)
        sys.exit(1)

    try:
        fixture = json.loads(data)
    except json.JSONDecodeError as exception:
        msg = "Exception reading JSON contents in "
        msg += f"test input file {filename}.json : "
        msg += f"Exception detail: {exception}"
        print(msg)
        sys.exit(1)

    return fixture
