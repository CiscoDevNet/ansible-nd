# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for base_paths_infra.py

Tests the BasePath class methods for building ND Infra API paths
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra.base_path import (
    BasePath,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: BasePath.API constant
# =============================================================================


def test_base_paths_infra_00010():
    """
    # Summary

    Verify API constant equals "/api/v1/infra"

    ## Test

    - BasePath.API equals "/api/v1/infra"

    ## Classes and Methods

    - BasePath.API
    """
    with does_not_raise():
        result = BasePath.API
    assert result == "/api/v1/infra"


# =============================================================================
# Test: path() method
# =============================================================================


def test_base_paths_infra_00100():
    """
    # Summary

    Verify path() with no segments returns API root

    ## Test

    - path() returns "/api/v1/infra"

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path()
    assert result == "/api/v1/infra"


def test_base_paths_infra_00110():
    """
    # Summary

    Verify path() with single segment

    ## Test

    - path("aaa") returns "/api/v1/infra/aaa"

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("aaa")
    assert result == "/api/v1/infra/aaa"


def test_base_paths_infra_00120():
    """
    # Summary

    Verify path() with multiple segments

    ## Test

    - path("aaa", "localUsers") returns "/api/v1/infra/aaa/localUsers"

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("aaa", "localUsers")
    assert result == "/api/v1/infra/aaa/localUsers"


def test_base_paths_infra_00130():
    """
    # Summary

    Verify path() with three segments

    ## Test

    - path("aaa", "localUsers", "user1") returns correct path

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("aaa", "localUsers", "user1")
    assert result == "/api/v1/infra/aaa/localUsers/user1"


def test_base_paths_infra_00140():
    """
    # Summary

    Verify path() builds clusterhealth paths

    ## Test

    - path("clusterhealth") returns "/api/v1/infra/clusterhealth"

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("clusterhealth")
    assert result == "/api/v1/infra/clusterhealth"


def test_base_paths_infra_00150():
    """
    # Summary

    Verify path() builds clusterhealth config path

    ## Test

    - path("clusterhealth", "config") returns "/api/v1/infra/clusterhealth/config"

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("clusterhealth", "config")
    assert result == "/api/v1/infra/clusterhealth/config"


def test_base_paths_infra_00160():
    """
    # Summary

    Verify path() builds clusterhealth status path

    ## Test

    - path("clusterhealth", "status") returns "/api/v1/infra/clusterhealth/status"

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("clusterhealth", "status")
    assert result == "/api/v1/infra/clusterhealth/status"


def test_base_paths_infra_00170():
    """
    # Summary

    Verify path() builds clusterhealth path with multiple segments

    ## Test

    - path("clusterhealth", "config", "cluster1") returns correct path

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("clusterhealth", "config", "cluster1")
    assert result == "/api/v1/infra/clusterhealth/config/cluster1"


# =============================================================================
# Test: Edge cases
# =============================================================================


def test_base_paths_infra_00500():
    """
    # Summary

    Verify empty string segment is handled

    ## Test

    - path("aaa", "", "localUsers") creates path with empty segment
    - This creates double slashes (expected behavior)

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("aaa", "", "localUsers")
    assert result == "/api/v1/infra/aaa//localUsers"


def test_base_paths_infra_00510():
    """
    # Summary

    Verify segments with special characters

    ## Test

    - path("aaa", "user-name_123") handles hyphens and underscores

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("aaa", "user-name_123")
    assert result == "/api/v1/infra/aaa/user-name_123"


def test_base_paths_infra_00520():
    """
    # Summary

    Verify segments with spaces (no URL encoding)

    ## Test

    - BasePath does not URL-encode spaces
    - URL encoding is caller's responsibility

    ## Classes and Methods

    - BasePath.path()
    """
    with does_not_raise():
        result = BasePath.path("my path")
    assert result == "/api/v1/infra/my path"
