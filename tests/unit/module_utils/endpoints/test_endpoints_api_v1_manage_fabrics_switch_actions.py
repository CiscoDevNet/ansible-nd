# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)
# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_switch_actions.py

Tests the ND Manage Switch Actions endpoint classes:
- EpManageSwitchActionsDeployPost / SwitchDeployEndpointParams
- EpManageFabricsSwitchActionsChangeSystemModePost / ChangeSystemModeEndpointParams
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    ChangeSystemModeEndpointParams,
    EpManageFabricsSwitchActionsChangeSystemModePost,
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


# =============================================================================
# Test: EpManageFabricsSwitchActionsChangeSystemModePost
# =============================================================================


def test_change_system_mode_endpoint_00010() -> None:
    """
    # Summary

    Verify path defaults: with only fabric_name set, no query string is appended.

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeSystemModePost.path
    - EpManageFabricsSwitchActionsChangeSystemModePost.verb
    """
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    ep.fabric_name = "SITE1"
    assert ep.path == "/api/v1/manage/fabrics/SITE1/switchActions/changeSystemMode"
    assert ep.verb == HttpVerbEnum.POST


def test_change_system_mode_endpoint_00020() -> None:
    """
    # Summary

    Verify all query params serialize correctly with camelCase aliases.

    ## Classes and Methods

    - ChangeSystemModeEndpointParams.to_query_string
    """
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    ep.fabric_name = "SITE1"
    ep.endpoint_params.deploy = True
    ep.endpoint_params.blocking = True
    ep.endpoint_params.ticket_id = "CHG-INT-1"
    ep.endpoint_params.cluster_name = "cluster_a"

    assert "deploy=true" in ep.path
    assert "blocking=true" in ep.path
    assert "ticketId=CHG-INT-1" in ep.path
    assert "clusterName=cluster_a" in ep.path


def test_change_system_mode_endpoint_00030() -> None:
    """
    # Summary

    Verify that the path raises ValueError when fabric_name is unset.

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeSystemModePost.path
    """
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    match = r"fabric_name must be set"
    with pytest.raises(ValueError, match=match):
        result = ep.path  # pylint: disable=unused-variable


def test_change_system_mode_endpoint_00040() -> None:
    """
    # Summary

    Verify class_name field is frozen.

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeSystemModePost.class_name
    """
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    assert ep.class_name == "EpManageFabricsSwitchActionsChangeSystemModePost"


@pytest.mark.parametrize(
    "deploy,blocking,expected",
    [
        (True, False, "deploy=true"),
        (False, True, "blocking=true"),
        (False, False, ""),
    ],
    ids=["deploy-only", "blocking-only", "neither"],
)
def test_change_system_mode_endpoint_00050(deploy: bool, blocking: bool, expected: str) -> None:
    """
    # Summary

    Verify selective query-param emission.

    ## Classes and Methods

    - ChangeSystemModeEndpointParams.to_query_string
    """
    params = ChangeSystemModeEndpointParams()
    if deploy:
        params.deploy = True
    if blocking:
        params.blocking = True
    qs = params.to_query_string()
    if expected:
        assert expected in qs
    else:
        assert qs == ""


def test_change_system_mode_endpoint_00060() -> None:
    """
    # Summary

    Verify ticket_id accepts valid identifiers and round-trips into the path query string.

    ## Classes and Methods

    - ChangeSystemModeEndpointParams.ticket_id
    """
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    ep.fabric_name = "SITE1"
    ep.endpoint_params.ticket_id = "CHG-INT_42"
    assert "ticketId=CHG-INT_42" in ep.path


def test_change_system_mode_endpoint_00070() -> None:
    """
    # Summary

    Verify `fabric_name` is URL-encoded in the path so reserved characters do not break the route.

    ## Classes and Methods

    - EpManageFabricsSwitchActionsChangeSystemModePost.path
    """
    ep = EpManageFabricsSwitchActionsChangeSystemModePost()
    ep.fabric_name = "SITE A/B"
    # Space encodes to %20, slash to %2F.
    assert "/fabrics/SITE%20A%2FB/switchActions/changeSystemMode" in ep.path
    assert " " not in ep.path
    assert "SITE A/B" not in ep.path
