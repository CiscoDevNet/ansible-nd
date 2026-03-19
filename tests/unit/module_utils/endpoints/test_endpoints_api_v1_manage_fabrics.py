# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics.py

Tests the ND Manage Fabrics endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricConfigDeployPost,
    EpManageFabricGet,
    FabricConfigDeployEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: FabricConfigDeployEndpointParams
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00010():
    """
    # Summary

    Verify FabricConfigDeployEndpointParams default values

    ## Test

    - force_show_run defaults to None
    - incl_all_msd_switches defaults to None

    ## Classes and Methods

    - FabricConfigDeployEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricConfigDeployEndpointParams()
    assert params.force_show_run is None
    assert params.incl_all_msd_switches is None


def test_endpoints_api_v1_manage_fabrics_00020():
    """
    # Summary

    Verify FabricConfigDeployEndpointParams force_show_run can be set

    ## Test

    - force_show_run can be set to True

    ## Classes and Methods

    - FabricConfigDeployEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricConfigDeployEndpointParams(force_show_run=True)
    assert params.force_show_run is True


def test_endpoints_api_v1_manage_fabrics_00030():
    """
    # Summary

    Verify FabricConfigDeployEndpointParams generates query string with both params

    ## Test

    - to_query_string() includes forceShowRun and inclAllMsdSwitches when both are set

    ## Classes and Methods

    - FabricConfigDeployEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = FabricConfigDeployEndpointParams(force_show_run=True, incl_all_msd_switches=True)
        result = params.to_query_string()
    assert "forceShowRun=true" in result
    assert "inclAllMsdSwitches=true" in result


def test_endpoints_api_v1_manage_fabrics_00040():
    """
    # Summary

    Verify FabricConfigDeployEndpointParams returns empty query string when no params set

    ## Test

    - to_query_string() returns empty string when no params set

    ## Classes and Methods

    - FabricConfigDeployEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = FabricConfigDeployEndpointParams()
        result = params.to_query_string()
    assert result == ""


# =============================================================================
# Test: EpManageFabricConfigDeployPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00100():
    """
    # Summary

    Verify EpManageFabricConfigDeployPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricConfigDeployPost.__init__()
    - EpManageFabricConfigDeployPost.class_name
    - EpManageFabricConfigDeployPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricConfigDeployPost()
    assert instance.class_name == "EpManageFabricConfigDeployPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_00110():
    """
    # Summary

    Verify EpManageFabricConfigDeployPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricConfigDeployPost.path
    """
    instance = EpManageFabricConfigDeployPost()
    with pytest.raises(ValueError):
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_00120():
    """
    # Summary

    Verify EpManageFabricConfigDeployPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricConfigDeployPost.path
    """
    with does_not_raise():
        instance = EpManageFabricConfigDeployPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/actions/configDeploy"


def test_endpoints_api_v1_manage_fabrics_00130():
    """
    # Summary

    Verify EpManageFabricConfigDeployPost path with force_show_run

    ## Test

    - path includes forceShowRun in query string when set to True

    ## Classes and Methods

    - EpManageFabricConfigDeployPost.path
    """
    with does_not_raise():
        instance = EpManageFabricConfigDeployPost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.force_show_run = True
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/actions/configDeploy?forceShowRun=true"


# =============================================================================
# Test: EpManageFabricGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00200():
    """
    # Summary

    Verify EpManageFabricGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricGet.__init__()
    - EpManageFabricGet.class_name
    - EpManageFabricGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricGet()
    assert instance.class_name == "EpManageFabricGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_00210():
    """
    # Summary

    Verify EpManageFabricGet raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricGet.path
    """
    instance = EpManageFabricGet()
    with pytest.raises(ValueError):
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_00220():
    """
    # Summary

    Verify EpManageFabricGet path

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricGet.path
    """
    with does_not_raise():
        instance = EpManageFabricGet()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric"
