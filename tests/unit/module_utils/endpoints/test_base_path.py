# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for base_path.py

Tests the ApiPath enum defined in base_path.py
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base_path import (
    ApiPath,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: ApiPath Enum Values
# =============================================================================


def test_base_path_00010():
    """
    # Summary

    Verify ApiPath.ANALYZE value

    ## Test

    - ApiPath.ANALYZE equals "/api/v1/analyze"

    ## Classes and Methods

    - ApiPath.ANALYZE
    """
    with does_not_raise():
        result = ApiPath.ANALYZE.value
    assert result == "/api/v1/analyze"


def test_base_path_00020():
    """
    # Summary

    Verify ApiPath.INFRA value

    ## Test

    - ApiPath.INFRA equals "/api/v1/infra"

    ## Classes and Methods

    - ApiPath.INFRA
    """
    with does_not_raise():
        result = ApiPath.INFRA.value
    assert result == "/api/v1/infra"


def test_base_path_00030():
    """
    # Summary

    Verify ApiPath.MANAGE value

    ## Test

    - ApiPath.MANAGE equals "/api/v1/manage"

    ## Classes and Methods

    - ApiPath.MANAGE
    """
    with does_not_raise():
        result = ApiPath.MANAGE.value
    assert result == "/api/v1/manage"


def test_base_path_00040():
    """
    # Summary

    Verify ApiPath.ONEMANAGE value

    ## Test

    - ApiPath.ONEMANAGE equals "/api/v1/onemanage"

    ## Classes and Methods

    - ApiPath.ONEMANAGE
    """
    with does_not_raise():
        result = ApiPath.ONEMANAGE.value
    assert result == "/api/v1/onemanage"


# =============================================================================
# Test: ApiPath Enum Properties
# =============================================================================


def test_base_path_00100():
    """
    # Summary

    Verify ApiPath enum members are strings

    ## Test

    - ApiPath enum extends str
    - Enum members can be used directly in string operations

    ## Classes and Methods

    - ApiPath
    """
    with does_not_raise():
        assert isinstance(ApiPath.INFRA, str)
        assert isinstance(ApiPath.MANAGE, str)
        assert isinstance(ApiPath.ANALYZE, str)
        assert isinstance(ApiPath.ONEMANAGE, str)


def test_base_path_00110():
    """
    # Summary

    Verify all API paths start with forward slash

    ## Test

    - All ApiPath values start with "/"
    - This ensures proper path concatenation

    ## Classes and Methods

    - ApiPath
    """
    with does_not_raise():
        for member in ApiPath:
            assert member.value.startswith("/"), f"{member.name} does not start with /"


def test_base_path_00120():
    """
    # Summary

    Verify no API paths end with trailing slash

    ## Test

    - No ApiPath values end with "/"
    - This prevents double slashes when building paths

    ## Classes and Methods

    - ApiPath
    """
    with does_not_raise():
        for member in ApiPath:
            assert not member.value.endswith("/"), f"{member.name} ends with /"


def test_base_path_00130():
    """
    # Summary

    Verify ApiPath enum provides all expected members

    ## Test

    - All 4 API paths available as enum members
    - Enum is iterable

    ## Classes and Methods

    - ApiPath
    """
    with does_not_raise():
        paths = list(ApiPath)

    assert len(paths) == 4
    assert ApiPath.ANALYZE in paths
    assert ApiPath.INFRA in paths
    assert ApiPath.MANAGE in paths
    assert ApiPath.ONEMANAGE in paths


# =============================================================================
# Test: Path Uniqueness
# =============================================================================


def test_base_path_00200():
    """
    # Summary

    Verify all ApiPath values are unique

    ## Test

    - Each enum member has a different value
    - No duplicate paths exist

    ## Classes and Methods

    - ApiPath
    """
    with does_not_raise():
        values = [member.value for member in ApiPath]
        assert len(values) == len(set(values)), "Duplicate paths found"


# =============================================================================
# Test: ND API Path Structure
# =============================================================================


def test_base_path_00300():
    """
    # Summary

    Verify all ApiPath members follow /api/v1/<service> pattern

    ## Test

    - All ApiPath values start with "/api/v1/"

    ## Classes and Methods

    - ApiPath
    """
    with does_not_raise():
        for member in ApiPath:
            assert member.value.startswith("/api/v1/"), f"{member.name} does not follow /api/v1/<service> pattern"
