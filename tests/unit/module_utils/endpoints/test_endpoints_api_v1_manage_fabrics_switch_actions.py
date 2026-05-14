# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_switch_actions.py

Tests the ND Manage Switch Actions endpoint classes.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
    SwitchDeployEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: SwitchDeployEndpointParams
# =============================================================================


def test_manage_switch_actions_00010():
    """
    # Summary

    Verify SwitchDeployEndpointParams default values

    ## Test

    - force_show_run defaults to None
    - cluster_name defaults to None

    ## Classes and Methods

    - SwitchDeployEndpointParams.__init__()
    """
    with does_not_raise():
        params = SwitchDeployEndpointParams()
    assert params.force_show_run is None
    assert params.cluster_name is None


def test_manage_switch_actions_00020():
    """
    # Summary

    Verify SwitchDeployEndpointParams generates query string with both params

    ## Test

    - to_query_string() includes forceShowRun and clusterName when both are set

    ## Classes and Methods

    - SwitchDeployEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchDeployEndpointParams(force_show_run=True, cluster_name="cluster1")
        result = params.to_query_string()
    assert "forceShowRun=true" in result or "forceShowRun=True" in result
    assert "clusterName=cluster1" in result


def test_manage_switch_actions_00030():
    """
    # Summary

    Verify SwitchDeployEndpointParams returns empty string when no params set

    ## Test

    - to_query_string() returns empty string when all params are None

    ## Classes and Methods

    - SwitchDeployEndpointParams.to_query_string()
    """
    params = SwitchDeployEndpointParams()
    assert params.to_query_string() == ""


def test_manage_switch_actions_00040():
    """
    # Summary

    Verify SwitchDeployEndpointParams with only force_show_run set

    ## Test

    - to_query_string() includes only forceShowRun when cluster_name is None

    ## Classes and Methods

    - SwitchDeployEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchDeployEndpointParams(force_show_run=False)
        result = params.to_query_string()
    assert "forceShowRun" in result
    assert "clusterName" not in result


def test_manage_switch_actions_00050():
    """
    # Summary

    Verify SwitchDeployEndpointParams with only cluster_name set

    ## Test

    - to_query_string() includes only clusterName when force_show_run is None

    ## Classes and Methods

    - SwitchDeployEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchDeployEndpointParams(cluster_name="myCluster")
        result = params.to_query_string()
    assert "clusterName=myCluster" in result
    assert "forceShowRun" not in result


def test_manage_switch_actions_00060():
    """
    # Summary

    Verify SwitchDeployEndpointParams rejects extra fields

    ## Test

    - Extra fields cause validation error (extra="forbid")

    ## Classes and Methods

    - SwitchDeployEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        SwitchDeployEndpointParams(bogus="bad")


def test_manage_switch_actions_00070():
    """
    # Summary

    Verify SwitchDeployEndpointParams rejects empty cluster_name

    ## Test

    - cluster_name with empty string fails min_length=1 validation

    ## Classes and Methods

    - SwitchDeployEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        SwitchDeployEndpointParams(cluster_name="")


# =============================================================================
# Test: EpManageSwitchActionsDeployPost
# =============================================================================


def test_manage_switch_actions_00100():
    """
    # Summary

    Verify EpManageSwitchActionsDeployPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageSwitchActionsDeployPost.__init__()
    - EpManageSwitchActionsDeployPost.class_name
    - EpManageSwitchActionsDeployPost.verb
    """
    with does_not_raise():
        instance = EpManageSwitchActionsDeployPost()
    assert instance.class_name == "EpManageSwitchActionsDeployPost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_switch_actions_00110():
    """
    # Summary

    Verify EpManageSwitchActionsDeployPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageSwitchActionsDeployPost.path
    """
    instance = EpManageSwitchActionsDeployPost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_switch_actions_00120():
    """
    # Summary

    Verify EpManageSwitchActionsDeployPost path without query params

    ## Test

    - path returns correct deploy endpoint path

    ## Classes and Methods

    - EpManageSwitchActionsDeployPost.path
    """
    with does_not_raise():
        instance = EpManageSwitchActionsDeployPost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/switchActions/deploy"


def test_manage_switch_actions_00130():
    """
    # Summary

    Verify EpManageSwitchActionsDeployPost path with query params

    ## Test

    - path includes forceShowRun and clusterName in query string

    ## Classes and Methods

    - EpManageSwitchActionsDeployPost.path
    """
    with does_not_raise():
        instance = EpManageSwitchActionsDeployPost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.force_show_run = True
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/switchActions/deploy?")
    assert "clusterName=cluster1" in result
    assert "forceShowRun" in result


def test_manage_switch_actions_00140():
    """
    # Summary

    Verify EpManageSwitchActionsDeployPost path with only cluster_name query param

    ## Test

    - path includes only clusterName when force_show_run is not set

    ## Classes and Methods

    - EpManageSwitchActionsDeployPost.path
    """
    with does_not_raise():
        instance = EpManageSwitchActionsDeployPost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/switchActions/deploy?clusterName=cluster1"


def test_manage_switch_actions_00150():
    """
    # Summary

    Verify EpManageSwitchActionsDeployPost endpoint_params default

    ## Test

    - endpoint_params is a SwitchDeployEndpointParams instance by default

    ## Classes and Methods

    - EpManageSwitchActionsDeployPost.endpoint_params
    """
    with does_not_raise():
        instance = EpManageSwitchActionsDeployPost()
    assert isinstance(instance.endpoint_params, SwitchDeployEndpointParams)
    assert instance.endpoint_params.force_show_run is None
    assert instance.endpoint_params.cluster_name is None
