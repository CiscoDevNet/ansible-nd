# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for base_path.py

Tests the root API path constants defined in base_path.py
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.ep.base_path import (
    LOGIN,
    ND_ANALYZE_API,
    ND_INFRA_API,
    ND_MANAGE_API,
    ND_MSO_API,
    ND_ONEMANAGE_API,
    NDFC_API,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: Root API Path Constants
# =============================================================================


def test_base_path_00010():
    """
    # Summary

    Verify ND_ANALYZE_API constant value

    ## Test

    - ND_ANALYZE_API equals "/api/v1/analyze"

    ## Classes and Methods

    - base_path.ND_ANALYZE_API
    """
    with does_not_raise():
        result = ND_ANALYZE_API
    assert result == "/api/v1/analyze"


def test_base_path_00020():
    """
    # Summary

    Verify ND_INFRA_API constant value

    ## Test

    - ND_INFRA_API equals "/api/v1/infra"

    ## Classes and Methods

    - base_path.ND_INFRA_API
    """
    with does_not_raise():
        result = ND_INFRA_API
    assert result == "/api/v1/infra"


def test_base_path_00030():
    """
    # Summary

    Verify ND_MANAGE_API constant value

    ## Test

    - ND_MANAGE_API equals "/api/v1/manage"

    ## Classes and Methods

    - base_path.ND_MANAGE_API
    """
    with does_not_raise():
        result = ND_MANAGE_API
    assert result == "/api/v1/manage"


def test_base_path_00040():
    """
    # Summary

    Verify ND_ONEMANAGE_API constant value

    ## Test

    - ND_ONEMANAGE_API equals "/api/v1/onemanage"

    ## Classes and Methods

    - base_path.ND_ONEMANAGE_API
    """
    with does_not_raise():
        result = ND_ONEMANAGE_API
    assert result == "/api/v1/onemanage"


def test_base_path_00050():
    """
    # Summary

    Verify ND_MSO_API constant value

    ## Test

    - ND_MSO_API equals "/mso"

    ## Classes and Methods

    - base_path.ND_MSO_API
    """
    with does_not_raise():
        result = ND_MSO_API
    assert result == "/mso"


def test_base_path_00060():
    """
    # Summary

    Verify NDFC_API constant value

    ## Test

    - NDFC_API equals "/appcenter/cisco/ndfc/api"

    ## Classes and Methods

    - base_path.NDFC_API
    """
    with does_not_raise():
        result = NDFC_API
    assert result == "/appcenter/cisco/ndfc/api"


def test_base_path_00070():
    """
    # Summary

    Verify LOGIN constant value

    ## Test

    - LOGIN equals "/login"

    ## Classes and Methods

    - base_path.LOGIN
    """
    with does_not_raise():
        result = LOGIN
    assert result == "/login"


# =============================================================================
# Test: Constant Immutability (Final types)
# =============================================================================


def test_base_path_00100():
    """
    # Summary

    Verify constants are strings

    ## Test

    - All constants are string types
    - This ensures they can be used in path building

    ## Classes and Methods

    - base_path.ND_ANALYZE_API
    - base_path.ND_INFRA_API
    - base_path.ND_MANAGE_API
    - base_path.ND_ONEMANAGE_API
    - base_path.ND_MSO_API
    - base_path.NDFC_API
    - base_path.LOGIN
    """
    with does_not_raise():
        assert isinstance(ND_ANALYZE_API, str)
        assert isinstance(ND_INFRA_API, str)
        assert isinstance(ND_MANAGE_API, str)
        assert isinstance(ND_ONEMANAGE_API, str)
        assert isinstance(ND_MSO_API, str)
        assert isinstance(NDFC_API, str)
        assert isinstance(LOGIN, str)


def test_base_path_00110():
    """
    # Summary

    Verify all API paths start with forward slash

    ## Test

    - All API path constants start with "/"
    - This ensures proper path concatenation

    ## Classes and Methods

    - base_path.ND_ANALYZE_API
    - base_path.ND_INFRA_API
    - base_path.ND_MANAGE_API
    - base_path.ND_ONEMANAGE_API
    - base_path.ND_MSO_API
    - base_path.NDFC_API
    - base_path.LOGIN
    """
    with does_not_raise():
        assert ND_ANALYZE_API.startswith("/")
        assert ND_INFRA_API.startswith("/")
        assert ND_MANAGE_API.startswith("/")
        assert ND_ONEMANAGE_API.startswith("/")
        assert ND_MSO_API.startswith("/")
        assert NDFC_API.startswith("/")
        assert LOGIN.startswith("/")


def test_base_path_00120():
    """
    # Summary

    Verify no API paths end with trailing slash

    ## Test

    - No API path constants end with "/"
    - This prevents double slashes when building paths

    ## Classes and Methods

    - base_path.ND_ANALYZE_API
    - base_path.ND_INFRA_API
    - base_path.ND_MANAGE_API
    - base_path.ND_ONEMANAGE_API
    - base_path.ND_MSO_API
    - base_path.NDFC_API
    - base_path.LOGIN
    """
    with does_not_raise():
        assert not ND_ANALYZE_API.endswith("/")
        assert not ND_INFRA_API.endswith("/")
        assert not ND_MANAGE_API.endswith("/")
        assert not ND_ONEMANAGE_API.endswith("/")
        assert not ND_MSO_API.endswith("/")
        assert not NDFC_API.endswith("/")
        assert not LOGIN.endswith("/")


# =============================================================================
# Test: ND API Path Structure
# =============================================================================


def test_base_path_00200():
    """
    # Summary

    Verify ND API paths follow /api/v1/<service> pattern

    ## Test

    - ND_ANALYZE_API follows the pattern
    - ND_INFRA_API follows the pattern
    - ND_MANAGE_API follows the pattern
    - ND_ONEMANAGE_API follows the pattern

    ## Classes and Methods

    - base_path.ND_ANALYZE_API
    - base_path.ND_INFRA_API
    - base_path.ND_MANAGE_API
    - base_path.ND_ONEMANAGE_API
    """
    with does_not_raise():
        assert ND_ANALYZE_API.startswith("/api/v1/")
        assert ND_INFRA_API.startswith("/api/v1/")
        assert ND_MANAGE_API.startswith("/api/v1/")
        assert ND_ONEMANAGE_API.startswith("/api/v1/")


def test_base_path_00210():
    """
    # Summary

    Verify non-ND API paths have different structure

    ## Test

    - ND_MSO_API does not follow /api/v1/ pattern
    - NDFC_API does not follow /api/v1/ pattern
    - LOGIN does not follow /api/v1/ pattern

    ## Classes and Methods

    - base_path.ND_MSO_API
    - base_path.NDFC_API
    - base_path.LOGIN
    """
    with does_not_raise():
        assert not ND_MSO_API.startswith("/api/v1/")
        assert not NDFC_API.startswith("/api/v1/")
        assert not LOGIN.startswith("/api/v1/")


# =============================================================================
# Test: Path Uniqueness
# =============================================================================


def test_base_path_00300():
    """
    # Summary

    Verify all API path constants are unique

    ## Test

    - Each constant has a different value
    - No duplicate paths exist

    ## Classes and Methods

    - base_path.ND_ANALYZE_API
    - base_path.ND_INFRA_API
    - base_path.ND_MANAGE_API
    - base_path.ND_ONEMANAGE_API
    - base_path.ND_MSO_API
    - base_path.NDFC_API
    - base_path.LOGIN
    """
    with does_not_raise():
        paths = [
            ND_ANALYZE_API,
            ND_INFRA_API,
            ND_MANAGE_API,
            ND_ONEMANAGE_API,
            ND_MSO_API,
            NDFC_API,
            LOGIN,
        ]
        # Convert to set and check length matches
        assert len(paths) == len(set(paths)), "Duplicate paths found"
