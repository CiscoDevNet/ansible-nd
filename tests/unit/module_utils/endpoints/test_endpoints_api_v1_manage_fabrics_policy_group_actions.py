# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_policy_group_actions.py

Tests the ND Manage Policy Group Actions endpoint classes.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_group_actions import (
    EpManagePolicyGroupActionsMarkDeletePost,
    PolicyGroupActionMutationEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: PolicyGroupActionMutationEndpointParams
# =============================================================================


def test_manage_policy_group_actions_00010():
    """
    # Summary

    Verify PolicyGroupActionMutationEndpointParams default values

    ## Test

    - cluster_name defaults to None
    - ticket_id defaults to None

    ## Classes and Methods

    - PolicyGroupActionMutationEndpointParams.__init__()
    """
    with does_not_raise():
        params = PolicyGroupActionMutationEndpointParams()
    assert params.cluster_name is None
    assert params.ticket_id is None


def test_manage_policy_group_actions_00020():
    """
    # Summary

    Verify PolicyGroupActionMutationEndpointParams generates query string with both params

    ## Test

    - to_query_string() includes clusterName and ticketId when both are set

    ## Classes and Methods

    - PolicyGroupActionMutationEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PolicyGroupActionMutationEndpointParams(cluster_name="cluster1", ticket_id="MyTicket1234")
        result = params.to_query_string()
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


def test_manage_policy_group_actions_00030():
    """
    # Summary

    Verify PolicyGroupActionMutationEndpointParams returns empty string when no params set

    ## Test

    - to_query_string() returns empty string when all params are None

    ## Classes and Methods

    - PolicyGroupActionMutationEndpointParams.to_query_string()
    """
    params = PolicyGroupActionMutationEndpointParams()
    assert params.to_query_string() == ""


def test_manage_policy_group_actions_00040():
    """
    # Summary

    Verify PolicyGroupActionMutationEndpointParams ticket_id pattern validation

    ## Test

    - ticket_id rejects values not matching ^[a-zA-Z][a-zA-Z0-9_-]+$

    ## Classes and Methods

    - PolicyGroupActionMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyGroupActionMutationEndpointParams(ticket_id="123-invalid")


def test_manage_policy_group_actions_00050():
    """
    # Summary

    Verify PolicyGroupActionMutationEndpointParams rejects extra fields

    ## Test

    - Extra fields cause validation error (extra="forbid")

    ## Classes and Methods

    - PolicyGroupActionMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyGroupActionMutationEndpointParams(bogus="bad")


# =============================================================================
# Test: EpManagePolicyGroupActionsMarkDeletePost
# =============================================================================


def test_manage_policy_group_actions_00100():
    """
    # Summary

    Verify EpManagePolicyGroupActionsMarkDeletePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManagePolicyGroupActionsMarkDeletePost.__init__()
    - EpManagePolicyGroupActionsMarkDeletePost.class_name
    - EpManagePolicyGroupActionsMarkDeletePost.verb
    """
    with does_not_raise():
        instance = EpManagePolicyGroupActionsMarkDeletePost()
    assert instance.class_name == "EpManagePolicyGroupActionsMarkDeletePost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_policy_group_actions_00110():
    """
    # Summary

    Verify EpManagePolicyGroupActionsMarkDeletePost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyGroupActionsMarkDeletePost.path
    """
    instance = EpManagePolicyGroupActionsMarkDeletePost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_group_actions_00120():
    """
    # Summary

    Verify EpManagePolicyGroupActionsMarkDeletePost path without query params

    ## Test

    - path returns correct markDelete endpoint path

    ## Classes and Methods

    - EpManagePolicyGroupActionsMarkDeletePost.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupActionsMarkDeletePost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyGroups/actions/markDelete"


def test_manage_policy_group_actions_00130():
    """
    # Summary

    Verify EpManagePolicyGroupActionsMarkDeletePost path with query params

    ## Test

    - path includes clusterName and ticketId in query string

    ## Classes and Methods

    - EpManagePolicyGroupActionsMarkDeletePost.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupActionsMarkDeletePost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyGroups/actions/markDelete?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result
