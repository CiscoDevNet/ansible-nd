# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for base_paths_manage.py

Tests the BasePath class methods for building ND Manage API paths
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base_path import (
    ND_MANAGE_API,
    ApiPath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.base_paths_manage import (
    BasePath,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: BasePath.API constant
# =============================================================================


def test_base_paths_manage_00010():
    """
    # Summary

    Verify API constant equals ND_MANAGE_API and ApiPath.MANAGE

    ## Test

    - BasePath.API equals "/api/v1/manage"
    - BasePath.API uses ApiPath.MANAGE.value
    - Backward compat constant still works

    ## Classes and Methods

    - BasePath.API
    - ApiPath.MANAGE
    """
    with does_not_raise():
        result = BasePath.API
    assert result == ND_MANAGE_API
    assert result == ApiPath.MANAGE.value
    assert result == "/api/v1/manage"


# =============================================================================
# Test: nd_manage() method
# =============================================================================


def test_base_paths_manage_00100():
    """
    # Summary

    Verify nd_manage() with no segments returns API root

    ## Test

    - nd_manage() returns "/api/v1/manage"

    ## Classes and Methods

    - BasePath.nd_manage()
    """
    with does_not_raise():
        result = BasePath.nd_manage()
    assert result == "/api/v1/manage"


def test_base_paths_manage_00110():
    """
    # Summary

    Verify nd_manage() with single segment

    ## Test

    - nd_manage("inventory") returns "/api/v1/manage/inventory"

    ## Classes and Methods

    - BasePath.nd_manage()
    """
    with does_not_raise():
        result = BasePath.nd_manage("inventory")
    assert result == "/api/v1/manage/inventory"


def test_base_paths_manage_00120():
    """
    # Summary

    Verify nd_manage() with multiple segments

    ## Test

    - nd_manage("inventory", "switches") returns "/api/v1/manage/inventory/switches"

    ## Classes and Methods

    - BasePath.nd_manage()
    """
    with does_not_raise():
        result = BasePath.nd_manage("inventory", "switches")
    assert result == "/api/v1/manage/inventory/switches"


def test_base_paths_manage_00130():
    """
    # Summary

    Verify nd_manage() with three segments

    ## Test

    - nd_manage("inventory", "switches", "fabric1") returns correct path

    ## Classes and Methods

    - BasePath.nd_manage()
    """
    with does_not_raise():
        result = BasePath.nd_manage("inventory", "switches", "fabric1")
    assert result == "/api/v1/manage/inventory/switches/fabric1"


# =============================================================================
# Test: nd_manage_inventory() method
# =============================================================================


def test_base_paths_manage_00200():
    """
    # Summary

    Verify nd_manage_inventory() with no segments

    ## Test

    - nd_manage_inventory() returns "/api/v1/manage/inventory"

    ## Classes and Methods

    - BasePath.nd_manage_inventory()
    """
    with does_not_raise():
        result = BasePath.nd_manage_inventory()
    assert result == "/api/v1/manage/inventory"


def test_base_paths_manage_00210():
    """
    # Summary

    Verify nd_manage_inventory() with single segment

    ## Test

    - nd_manage_inventory("switches") returns "/api/v1/manage/inventory/switches"

    ## Classes and Methods

    - BasePath.nd_manage_inventory()
    """
    with does_not_raise():
        result = BasePath.nd_manage_inventory("switches")
    assert result == "/api/v1/manage/inventory/switches"


def test_base_paths_manage_00220():
    """
    # Summary

    Verify nd_manage_inventory() with multiple segments

    ## Test

    - nd_manage_inventory("switches", "fabric1") returns correct path

    ## Classes and Methods

    - BasePath.nd_manage_inventory()
    """
    with does_not_raise():
        result = BasePath.nd_manage_inventory("switches", "fabric1")
    assert result == "/api/v1/manage/inventory/switches/fabric1"


# =============================================================================
# Test: Method composition
# =============================================================================


def test_base_paths_manage_00300():
    """
    # Summary

    Verify nd_manage_inventory() uses nd_manage() internally

    ## Test

    - nd_manage_inventory("switches") equals nd_manage("inventory", "switches")

    ## Classes and Methods

    - BasePath.nd_manage()
    - BasePath.nd_manage_inventory()
    """
    with does_not_raise():
        result1 = BasePath.nd_manage_inventory("switches")
        result2 = BasePath.nd_manage("inventory", "switches")
    assert result1 == result2


def test_base_paths_manage_00310():
    """
    # Summary

    Verify method composition with multiple segments

    ## Test

    - nd_manage_inventory("switches", "summary") equals nd_manage("inventory", "switches", "summary")

    ## Classes and Methods

    - BasePath.nd_manage()
    - BasePath.nd_manage_inventory()
    """
    with does_not_raise():
        result1 = BasePath.nd_manage_inventory("switches", "summary")
        result2 = BasePath.nd_manage("inventory", "switches", "summary")
    assert result1 == result2


# =============================================================================
# Test: Edge cases
# =============================================================================


def test_base_paths_manage_00400():
    """
    # Summary

    Verify empty string segment is handled

    ## Test

    - nd_manage("inventory", "", "switches") creates path with empty segment
    - This creates double slashes (expected behavior)

    ## Classes and Methods

    - BasePath.nd_manage()
    """
    with does_not_raise():
        result = BasePath.nd_manage("inventory", "", "switches")
    assert result == "/api/v1/manage/inventory//switches"


def test_base_paths_manage_00410():
    """
    # Summary

    Verify segments with special characters

    ## Test

    - nd_manage_inventory("fabric-name_123") handles hyphens and underscores

    ## Classes and Methods

    - BasePath.nd_manage_inventory()
    """
    with does_not_raise():
        result = BasePath.nd_manage_inventory("fabric-name_123")
    assert result == "/api/v1/manage/inventory/fabric-name_123"


def test_base_paths_manage_00420():
    """
    # Summary

    Verify segments with spaces (no URL encoding)

    ## Test

    - BasePath does not URL-encode spaces
    - URL encoding is caller's responsibility

    ## Classes and Methods

    - BasePath.nd_manage()
    """
    with does_not_raise():
        result = BasePath.nd_manage("my path")
    assert result == "/api/v1/manage/my path"
