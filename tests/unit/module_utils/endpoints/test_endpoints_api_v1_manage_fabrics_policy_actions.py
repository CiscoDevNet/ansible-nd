# Copyright: (c) 2026, Cisco Systems

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_policy_actions.py

Tests the ND Manage Policy Actions endpoint classes.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_actions import (
    EpManagePolicyActionsMarkDeletePost,
    EpManagePolicyActionsPushConfigPost,
    EpManagePolicyActionsRemovePost,
    PolicyActionMutationEndpointParams,
    PolicyPushConfigEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: PolicyActionMutationEndpointParams
# =============================================================================


def test_manage_policy_actions_00010():
    """
    # Summary

    Verify PolicyActionMutationEndpointParams default values

    ## Test

    - cluster_name defaults to None
    - ticket_id defaults to None

    ## Classes and Methods

    - PolicyActionMutationEndpointParams.__init__()
    """
    with does_not_raise():
        params = PolicyActionMutationEndpointParams()
    assert params.cluster_name is None
    assert params.ticket_id is None


def test_manage_policy_actions_00020():
    """
    # Summary

    Verify PolicyActionMutationEndpointParams generates query string

    ## Test

    - to_query_string() includes clusterName and ticketId when both set

    ## Classes and Methods

    - PolicyActionMutationEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PolicyActionMutationEndpointParams(cluster_name="cluster1", ticket_id="MyTicket1234")
        result = params.to_query_string()
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


def test_manage_policy_actions_00030():
    """
    # Summary

    Verify PolicyActionMutationEndpointParams returns empty when no params set

    ## Test

    - to_query_string() returns empty string

    ## Classes and Methods

    - PolicyActionMutationEndpointParams.to_query_string()
    """
    params = PolicyActionMutationEndpointParams()
    assert params.to_query_string() == ""


# =============================================================================
# Test: PolicyPushConfigEndpointParams
# =============================================================================


def test_manage_policy_actions_00040():
    """
    # Summary

    Verify PolicyPushConfigEndpointParams default values

    ## Test

    - cluster_name defaults to None

    ## Classes and Methods

    - PolicyPushConfigEndpointParams.__init__()
    """
    with does_not_raise():
        params = PolicyPushConfigEndpointParams()
    assert params.cluster_name is None


def test_manage_policy_actions_00050():
    """
    # Summary

    Verify PolicyPushConfigEndpointParams generates query string

    ## Test

    - to_query_string() includes clusterName when set

    ## Classes and Methods

    - PolicyPushConfigEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PolicyPushConfigEndpointParams(cluster_name="cluster1")
        result = params.to_query_string()
    assert result == "clusterName=cluster1"


def test_manage_policy_actions_00055():
    """
    # Summary

    Verify PolicyPushConfigEndpointParams rejects extra fields (no ticketId)

    ## Test

    - Extra fields like ticket_id cause validation error (extra="forbid")

    ## Classes and Methods

    - PolicyPushConfigEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyPushConfigEndpointParams(ticket_id="ShouldFail")


# =============================================================================
# Test: EpManagePolicyActionsMarkDeletePost
# =============================================================================


def test_manage_policy_actions_00100():
    """
    # Summary

    Verify EpManagePolicyActionsMarkDeletePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManagePolicyActionsMarkDeletePost.__init__()
    - EpManagePolicyActionsMarkDeletePost.class_name
    - EpManagePolicyActionsMarkDeletePost.verb
    """
    with does_not_raise():
        instance = EpManagePolicyActionsMarkDeletePost()
    assert instance.class_name == "EpManagePolicyActionsMarkDeletePost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_policy_actions_00110():
    """
    # Summary

    Verify EpManagePolicyActionsMarkDeletePost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyActionsMarkDeletePost.path
    """
    instance = EpManagePolicyActionsMarkDeletePost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_actions_00120():
    """
    # Summary

    Verify EpManagePolicyActionsMarkDeletePost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManagePolicyActionsMarkDeletePost.path
    """
    with does_not_raise():
        instance = EpManagePolicyActionsMarkDeletePost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyActions/markDelete"


def test_manage_policy_actions_00130():
    """
    # Summary

    Verify EpManagePolicyActionsMarkDeletePost path with query params

    ## Test

    - path includes clusterName and ticketId in query string

    ## Classes and Methods

    - EpManagePolicyActionsMarkDeletePost.path
    """
    with does_not_raise():
        instance = EpManagePolicyActionsMarkDeletePost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyActions/markDelete?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


# =============================================================================
# Test: EpManagePolicyActionsPushConfigPost
# =============================================================================


def test_manage_policy_actions_00200():
    """
    # Summary

    Verify EpManagePolicyActionsPushConfigPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManagePolicyActionsPushConfigPost.__init__()
    - EpManagePolicyActionsPushConfigPost.class_name
    - EpManagePolicyActionsPushConfigPost.verb
    """
    with does_not_raise():
        instance = EpManagePolicyActionsPushConfigPost()
    assert instance.class_name == "EpManagePolicyActionsPushConfigPost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_policy_actions_00210():
    """
    # Summary

    Verify EpManagePolicyActionsPushConfigPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyActionsPushConfigPost.path
    """
    instance = EpManagePolicyActionsPushConfigPost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_actions_00220():
    """
    # Summary

    Verify EpManagePolicyActionsPushConfigPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManagePolicyActionsPushConfigPost.path
    """
    with does_not_raise():
        instance = EpManagePolicyActionsPushConfigPost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyActions/pushConfig"


def test_manage_policy_actions_00230():
    """
    # Summary

    Verify EpManagePolicyActionsPushConfigPost path with clusterName only

    ## Test

    - path includes only clusterName (no ticketId per ND API specification)

    ## Classes and Methods

    - EpManagePolicyActionsPushConfigPost.path
    """
    with does_not_raise():
        instance = EpManagePolicyActionsPushConfigPost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == ("/api/v1/manage/fabrics/my-fabric/policyActions/pushConfig?clusterName=cluster1")


# =============================================================================
# Test: EpManagePolicyActionsRemovePost
# =============================================================================


def test_manage_policy_actions_00300():
    """
    # Summary

    Verify EpManagePolicyActionsRemovePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManagePolicyActionsRemovePost.__init__()
    - EpManagePolicyActionsRemovePost.class_name
    - EpManagePolicyActionsRemovePost.verb
    """
    with does_not_raise():
        instance = EpManagePolicyActionsRemovePost()
    assert instance.class_name == "EpManagePolicyActionsRemovePost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_policy_actions_00310():
    """
    # Summary

    Verify EpManagePolicyActionsRemovePost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyActionsRemovePost.path
    """
    instance = EpManagePolicyActionsRemovePost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_actions_00320():
    """
    # Summary

    Verify EpManagePolicyActionsRemovePost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManagePolicyActionsRemovePost.path
    """
    with does_not_raise():
        instance = EpManagePolicyActionsRemovePost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyActions/remove"


def test_manage_policy_actions_00330():
    """
    # Summary

    Verify EpManagePolicyActionsRemovePost path with query params

    ## Test

    - path includes clusterName and ticketId in query string

    ## Classes and Methods

    - EpManagePolicyActionsRemovePost.path
    """
    with does_not_raise():
        instance = EpManagePolicyActionsRemovePost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyActions/remove?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result
