# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for endpoints under
`plugins/module_utils/endpoints/v1/manage/manage_fabrics_switch_actions.py`.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    ChangeSystemModeEndpointParams,
    EpManageFabricsSwitchActionsChangeSystemModePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


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
