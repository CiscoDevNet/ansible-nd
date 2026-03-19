# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_bootstrap.py

Tests the ND Manage Fabrics Bootstrap endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_bootstrap import (
    EpManageFabricsBootstrapGet,
    FabricsBootstrapEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: FabricsBootstrapEndpointParams
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_bootstrap_00010():
    """
    # Summary

    Verify FabricsBootstrapEndpointParams default values

    ## Test

    - max defaults to None
    - offset defaults to None
    - filter defaults to None

    ## Classes and Methods

    - FabricsBootstrapEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricsBootstrapEndpointParams()
    assert params.max is None
    assert params.offset is None
    assert params.filter is None


def test_endpoints_api_v1_manage_fabrics_bootstrap_00020():
    """
    # Summary

    Verify FabricsBootstrapEndpointParams max can be set

    ## Test

    - max can be set to an integer value

    ## Classes and Methods

    - FabricsBootstrapEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricsBootstrapEndpointParams(max=50)
    assert params.max == 50


def test_endpoints_api_v1_manage_fabrics_bootstrap_00030():
    """
    # Summary

    Verify FabricsBootstrapEndpointParams generates query string with pagination

    ## Test

    - to_query_string() returns correct format with max and offset

    ## Classes and Methods

    - FabricsBootstrapEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = FabricsBootstrapEndpointParams(max=50, offset=0)
        result = params.to_query_string()
    assert "max=50" in result
    assert "offset=0" in result


def test_endpoints_api_v1_manage_fabrics_bootstrap_00040():
    """
    # Summary

    Verify FabricsBootstrapEndpointParams returns empty query string when no params set

    ## Test

    - to_query_string() returns empty string when no params set

    ## Classes and Methods

    - FabricsBootstrapEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = FabricsBootstrapEndpointParams()
        result = params.to_query_string()
    assert result == ""


# =============================================================================
# Test: EpManageFabricsBootstrapGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_bootstrap_00100():
    """
    # Summary

    Verify EpManageFabricsBootstrapGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricsBootstrapGet.__init__()
    - EpManageFabricsBootstrapGet.class_name
    - EpManageFabricsBootstrapGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricsBootstrapGet()
    assert instance.class_name == "EpManageFabricsBootstrapGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_bootstrap_00110():
    """
    # Summary

    Verify EpManageFabricsBootstrapGet raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsBootstrapGet.path
    """
    instance = EpManageFabricsBootstrapGet()
    with pytest.raises(ValueError):
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_bootstrap_00120():
    """
    # Summary

    Verify EpManageFabricsBootstrapGet path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsBootstrapGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsBootstrapGet()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/bootstrap"


def test_endpoints_api_v1_manage_fabrics_bootstrap_00130():
    """
    # Summary

    Verify EpManageFabricsBootstrapGet path with pagination params

    ## Test

    - path includes max and offset in query string when set

    ## Classes and Methods

    - EpManageFabricsBootstrapGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsBootstrapGet()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.max = 50
        instance.endpoint_params.offset = 0
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/MyFabric/bootstrap?")
    assert "max=50" in result
    assert "offset=0" in result
