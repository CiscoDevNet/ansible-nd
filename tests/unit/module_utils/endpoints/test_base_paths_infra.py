# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for base_paths_infra.py

Tests the BasePath class methods for building ND Infra API paths
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base_path import (
    ND_INFRA_API,
    ApiPath,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.base_paths_infra import (
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

    Verify API constant equals ND_INFRA_API and ApiPath.INFRA

    ## Test

    - BasePath.API equals "/api/v1/infra"
    - BasePath.API uses ApiPath.INFRA.value
    - Backward compat constant still works

    ## Classes and Methods

    - BasePath.API
    - ApiPath.INFRA
    """
    with does_not_raise():
        result = BasePath.API
    assert result == ND_INFRA_API
    assert result == ApiPath.INFRA.value
    assert result == "/api/v1/infra"


# =============================================================================
# Test: nd_infra() method
# =============================================================================


def test_base_paths_infra_00100():
    """
    # Summary

    Verify nd_infra() with no segments returns API root

    ## Test

    - nd_infra() returns "/api/v1/infra"

    ## Classes and Methods

    - BasePath.nd_infra()
    """
    with does_not_raise():
        result = BasePath.nd_infra()
    assert result == "/api/v1/infra"


def test_base_paths_infra_00110():
    """
    # Summary

    Verify nd_infra() with single segment

    ## Test

    - nd_infra("aaa") returns "/api/v1/infra/aaa"

    ## Classes and Methods

    - BasePath.nd_infra()
    """
    with does_not_raise():
        result = BasePath.nd_infra("aaa")
    assert result == "/api/v1/infra/aaa"


def test_base_paths_infra_00120():
    """
    # Summary

    Verify nd_infra() with multiple segments

    ## Test

    - nd_infra("aaa", "localUsers") returns "/api/v1/infra/aaa/localUsers"

    ## Classes and Methods

    - BasePath.nd_infra()
    """
    with does_not_raise():
        result = BasePath.nd_infra("aaa", "localUsers")
    assert result == "/api/v1/infra/aaa/localUsers"


def test_base_paths_infra_00130():
    """
    # Summary

    Verify nd_infra() with three segments

    ## Test

    - nd_infra("aaa", "localUsers", "user1") returns correct path

    ## Classes and Methods

    - BasePath.nd_infra()
    """
    with does_not_raise():
        result = BasePath.nd_infra("aaa", "localUsers", "user1")
    assert result == "/api/v1/infra/aaa/localUsers/user1"


# =============================================================================
# Test: nd_infra_aaa() method
# =============================================================================


def test_base_paths_infra_00200():
    """
    # Summary

    Verify nd_infra_aaa() with no segments

    ## Test

    - nd_infra_aaa() returns "/api/v1/infra/aaa"

    ## Classes and Methods

    - BasePath.nd_infra_aaa()
    """
    with does_not_raise():
        result = BasePath.nd_infra_aaa()
    assert result == "/api/v1/infra/aaa"


def test_base_paths_infra_00210():
    """
    # Summary

    Verify nd_infra_aaa() with single segment

    ## Test

    - nd_infra_aaa("localUsers") returns "/api/v1/infra/aaa/localUsers"

    ## Classes and Methods

    - BasePath.nd_infra_aaa()
    """
    with does_not_raise():
        result = BasePath.nd_infra_aaa("localUsers")
    assert result == "/api/v1/infra/aaa/localUsers"


def test_base_paths_infra_00220():
    """
    # Summary

    Verify nd_infra_aaa() with multiple segments

    ## Test

    - nd_infra_aaa("localUsers", "user1") returns correct path

    ## Classes and Methods

    - BasePath.nd_infra_aaa()
    """
    with does_not_raise():
        result = BasePath.nd_infra_aaa("localUsers", "user1")
    assert result == "/api/v1/infra/aaa/localUsers/user1"


# =============================================================================
# Test: nd_infra_clusterhealth() method
# =============================================================================


def test_base_paths_infra_00300():
    """
    # Summary

    Verify nd_infra_clusterhealth() with no segments

    ## Test

    - nd_infra_clusterhealth() returns "/api/v1/infra/clusterhealth"

    ## Classes and Methods

    - BasePath.nd_infra_clusterhealth()
    """
    with does_not_raise():
        result = BasePath.nd_infra_clusterhealth()
    assert result == "/api/v1/infra/clusterhealth"


def test_base_paths_infra_00310():
    """
    # Summary

    Verify nd_infra_clusterhealth() with "config" segment

    ## Test

    - nd_infra_clusterhealth("config") returns "/api/v1/infra/clusterhealth/config"

    ## Classes and Methods

    - BasePath.nd_infra_clusterhealth()
    """
    with does_not_raise():
        result = BasePath.nd_infra_clusterhealth("config")
    assert result == "/api/v1/infra/clusterhealth/config"


def test_base_paths_infra_00320():
    """
    # Summary

    Verify nd_infra_clusterhealth() with "status" segment

    ## Test

    - nd_infra_clusterhealth("status") returns "/api/v1/infra/clusterhealth/status"

    ## Classes and Methods

    - BasePath.nd_infra_clusterhealth()
    """
    with does_not_raise():
        result = BasePath.nd_infra_clusterhealth("status")
    assert result == "/api/v1/infra/clusterhealth/status"


def test_base_paths_infra_00330():
    """
    # Summary

    Verify nd_infra_clusterhealth() with multiple segments

    ## Test

    - nd_infra_clusterhealth("config", "cluster1") returns correct path

    ## Classes and Methods

    - BasePath.nd_infra_clusterhealth()
    """
    with does_not_raise():
        result = BasePath.nd_infra_clusterhealth("config", "cluster1")
    assert result == "/api/v1/infra/clusterhealth/config/cluster1"


# =============================================================================
# Test: Method composition
# =============================================================================


def test_base_paths_infra_00400():
    """
    # Summary

    Verify nd_infra_aaa() uses nd_infra() internally

    ## Test

    - nd_infra_aaa("localUsers") equals nd_infra("aaa", "localUsers")

    ## Classes and Methods

    - BasePath.nd_infra()
    - BasePath.nd_infra_aaa()
    """
    with does_not_raise():
        result1 = BasePath.nd_infra_aaa("localUsers")
        result2 = BasePath.nd_infra("aaa", "localUsers")
    assert result1 == result2


def test_base_paths_infra_00410():
    """
    # Summary

    Verify nd_infra_clusterhealth() uses nd_infra() internally

    ## Test

    - nd_infra_clusterhealth("config") equals nd_infra("clusterhealth", "config")

    ## Classes and Methods

    - BasePath.nd_infra()
    - BasePath.nd_infra_clusterhealth()
    """
    with does_not_raise():
        result1 = BasePath.nd_infra_clusterhealth("config")
        result2 = BasePath.nd_infra("clusterhealth", "config")
    assert result1 == result2


# =============================================================================
# Test: Edge cases
# =============================================================================


def test_base_paths_infra_00500():
    """
    # Summary

    Verify empty string segment is handled

    ## Test

    - nd_infra("aaa", "", "localUsers") creates path with empty segment
    - This creates double slashes (expected behavior)

    ## Classes and Methods

    - BasePath.nd_infra()
    """
    with does_not_raise():
        result = BasePath.nd_infra("aaa", "", "localUsers")
    assert result == "/api/v1/infra/aaa//localUsers"


def test_base_paths_infra_00510():
    """
    # Summary

    Verify segments with special characters

    ## Test

    - nd_infra_aaa("user-name_123") handles hyphens and underscores

    ## Classes and Methods

    - BasePath.nd_infra_aaa()
    """
    with does_not_raise():
        result = BasePath.nd_infra_aaa("user-name_123")
    assert result == "/api/v1/infra/aaa/user-name_123"


def test_base_paths_infra_00520():
    """
    # Summary

    Verify segments with spaces (no URL encoding)

    ## Test

    - BasePath does not URL-encode spaces
    - URL encoding is caller's responsibility

    ## Classes and Methods

    - BasePath.nd_infra()
    """
    with does_not_raise():
        result = BasePath.nd_infra("my path")
    assert result == "/api/v1/infra/my path"
