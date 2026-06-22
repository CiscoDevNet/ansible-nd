# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_policy_groups.py

Tests the ND Manage Policy Groups endpoint classes.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policy_groups import (
    EpManagePolicyGroupsDelete,
    EpManagePolicyGroupsGet,
    EpManagePolicyGroupsPost,
    EpManagePolicyGroupsPut,
    PolicyGroupMutationEndpointParams,
    PolicyGroupsGetEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: PolicyGroupsGetEndpointParams
# =============================================================================


def test_manage_policy_groups_00010():
    """
    # Summary

    Verify PolicyGroupsGetEndpointParams default values

    ## Test

    - cluster_name defaults to None

    ## Classes and Methods

    - PolicyGroupsGetEndpointParams.__init__()
    """
    with does_not_raise():
        params = PolicyGroupsGetEndpointParams()
    assert params.cluster_name is None


def test_manage_policy_groups_00020():
    """
    # Summary

    Verify PolicyGroupsGetEndpointParams generates query string with cluster_name

    ## Test

    - to_query_string() includes clusterName when set

    ## Classes and Methods

    - PolicyGroupsGetEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PolicyGroupsGetEndpointParams(cluster_name="cluster1")
        result = params.to_query_string()
    assert result == "clusterName=cluster1"


def test_manage_policy_groups_00030():
    """
    # Summary

    Verify PolicyGroupsGetEndpointParams returns empty string when no params set

    ## Test

    - to_query_string() returns empty string when cluster_name is None

    ## Classes and Methods

    - PolicyGroupsGetEndpointParams.to_query_string()
    """
    params = PolicyGroupsGetEndpointParams()
    assert params.to_query_string() == ""


def test_manage_policy_groups_00040():
    """
    # Summary

    Verify PolicyGroupsGetEndpointParams rejects extra fields

    ## Test

    - Extra fields cause validation error (extra="forbid")

    ## Classes and Methods

    - PolicyGroupsGetEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyGroupsGetEndpointParams(bogus="bad")


# =============================================================================
# Test: PolicyGroupMutationEndpointParams
# =============================================================================


def test_manage_policy_groups_00050():
    """
    # Summary

    Verify PolicyGroupMutationEndpointParams default values

    ## Test

    - cluster_name defaults to None
    - ticket_id defaults to None

    ## Classes and Methods

    - PolicyGroupMutationEndpointParams.__init__()
    """
    with does_not_raise():
        params = PolicyGroupMutationEndpointParams()
    assert params.cluster_name is None
    assert params.ticket_id is None


def test_manage_policy_groups_00060():
    """
    # Summary

    Verify PolicyGroupMutationEndpointParams generates query string with both params

    ## Test

    - to_query_string() includes clusterName and ticketId when both are set

    ## Classes and Methods

    - PolicyGroupMutationEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PolicyGroupMutationEndpointParams(cluster_name="cluster1", ticket_id="MyTicket1234")
        result = params.to_query_string()
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


def test_manage_policy_groups_00070():
    """
    # Summary

    Verify PolicyGroupMutationEndpointParams ticket_id pattern validation

    ## Test

    - ticket_id rejects values not matching ^[a-zA-Z][a-zA-Z0-9_-]+$

    ## Classes and Methods

    - PolicyGroupMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyGroupMutationEndpointParams(ticket_id="123-invalid")


def test_manage_policy_groups_00075():
    """
    # Summary

    Verify PolicyGroupMutationEndpointParams ticket_id max length validation

    ## Test

    - ticket_id rejects values longer than 64 characters

    ## Classes and Methods

    - PolicyGroupMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyGroupMutationEndpointParams(ticket_id="A" * 65)


# =============================================================================
# Test: EpManagePolicyGroupsGet
# =============================================================================


def test_manage_policy_groups_00100():
    """
    # Summary

    Verify EpManagePolicyGroupsGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManagePolicyGroupsGet.__init__()
    - EpManagePolicyGroupsGet.class_name
    - EpManagePolicyGroupsGet.verb
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
    assert instance.class_name == "EpManagePolicyGroupsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_manage_policy_groups_00110():
    """
    # Summary

    Verify EpManagePolicyGroupsGet raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    instance = EpManagePolicyGroupsGet()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_groups_00120():
    """
    # Summary

    Verify EpManagePolicyGroupsGet path without query params

    ## Test

    - path returns correct base endpoint path

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyGroups"


def test_manage_policy_groups_00130():
    """
    # Summary

    Verify EpManagePolicyGroupsGet path with policy_group_id returns single-resource path

    ## Test

    - path includes policyGroupId segment when policy_group_id is set

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
        instance.fabric_name = "my-fabric"
        instance.policy_group_id = "POLICY-GROUP-143310"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyGroups/POLICY-GROUP-143310"


def test_manage_policy_groups_00140():
    """
    # Summary

    Verify EpManagePolicyGroupsGet path with Lucene filter parameters

    ## Test

    - path includes filter and max in query string when Lucene params are set

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
        instance.fabric_name = "my-fabric"
        instance.lucene_params.filter = "templateName:feature_enable"
        instance.lucene_params.max = 100
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyGroups?")
    assert "max=100" in result
    assert "filter=" in result


def test_manage_policy_groups_00150():
    """
    # Summary

    Verify EpManagePolicyGroupsGet path with clusterName query param

    ## Test

    - path includes clusterName in query string when set

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyGroups?")
    assert "clusterName=cluster1" in result


def test_manage_policy_groups_00160():
    """
    # Summary

    Verify EpManagePolicyGroupsGet path with combined endpoint and Lucene params

    ## Test

    - path includes both clusterName and Lucene params

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.lucene_params.max = 50
        instance.lucene_params.sort = "policyId:asc"
        result = instance.path
    assert "clusterName=cluster1" in result
    assert "max=50" in result
    assert "sort=" in result


def test_manage_policy_groups_00170():
    """
    # Summary

    Verify EpManagePolicyGroupsGet path with Lucene AND filter for gathered

    ## Test

    - path correctly encodes compound Lucene filter with AND operator

    ## Classes and Methods

    - EpManagePolicyGroupsGet.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsGet()
        instance.fabric_name = "my-fabric"
        instance.lucene_params.filter = "templateName:feature_enable AND description:Enable LACP"
        instance.lucene_params.max = 10000
        result = instance.path
    assert "filter=" in result
    assert "max=10000" in result


# =============================================================================
# Test: EpManagePolicyGroupsPost
# =============================================================================


def test_manage_policy_groups_00200():
    """
    # Summary

    Verify EpManagePolicyGroupsPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManagePolicyGroupsPost.__init__()
    - EpManagePolicyGroupsPost.class_name
    - EpManagePolicyGroupsPost.verb
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsPost()
    assert instance.class_name == "EpManagePolicyGroupsPost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_policy_groups_00210():
    """
    # Summary

    Verify EpManagePolicyGroupsPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyGroupsPost.path
    """
    instance = EpManagePolicyGroupsPost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_groups_00220():
    """
    # Summary

    Verify EpManagePolicyGroupsPost path without query params

    ## Test

    - path returns correct base endpoint path

    ## Classes and Methods

    - EpManagePolicyGroupsPost.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsPost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyGroups"


def test_manage_policy_groups_00230():
    """
    # Summary

    Verify EpManagePolicyGroupsPost path with clusterName and ticketId

    ## Test

    - path includes both clusterName and ticketId in query string

    ## Classes and Methods

    - EpManagePolicyGroupsPost.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsPost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyGroups?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


# =============================================================================
# Test: EpManagePolicyGroupsPut
# =============================================================================


def test_manage_policy_groups_00300():
    """
    # Summary

    Verify EpManagePolicyGroupsPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpManagePolicyGroupsPut.__init__()
    - EpManagePolicyGroupsPut.class_name
    - EpManagePolicyGroupsPut.verb
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsPut()
    assert instance.class_name == "EpManagePolicyGroupsPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_manage_policy_groups_00310():
    """
    # Summary

    Verify EpManagePolicyGroupsPut raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyGroupsPut.path
    """
    instance = EpManagePolicyGroupsPut()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_groups_00320():
    """
    # Summary

    Verify EpManagePolicyGroupsPut raises ValueError when policy_group_id is not set

    ## Test

    - Accessing path raises ValueError when policy_group_id is None

    ## Classes and Methods

    - EpManagePolicyGroupsPut.path
    """
    instance = EpManagePolicyGroupsPut()
    instance.fabric_name = "my-fabric"
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_groups_00330():
    """
    # Summary

    Verify EpManagePolicyGroupsPut path with fabric_name and policy_group_id

    ## Test

    - path returns correct endpoint path with policy group ID segment

    ## Classes and Methods

    - EpManagePolicyGroupsPut.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsPut()
        instance.fabric_name = "my-fabric"
        instance.policy_group_id = "POLICY-GROUP-143310"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyGroups/POLICY-GROUP-143310"


def test_manage_policy_groups_00340():
    """
    # Summary

    Verify EpManagePolicyGroupsPut path with query params

    ## Test

    - path includes clusterName and ticketId in query string

    ## Classes and Methods

    - EpManagePolicyGroupsPut.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsPut()
        instance.fabric_name = "my-fabric"
        instance.policy_group_id = "POLICY-GROUP-143310"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyGroups/POLICY-GROUP-143310?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


# =============================================================================
# Test: EpManagePolicyGroupsDelete
# =============================================================================


def test_manage_policy_groups_00400():
    """
    # Summary

    Verify EpManagePolicyGroupsDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpManagePolicyGroupsDelete.__init__()
    - EpManagePolicyGroupsDelete.class_name
    - EpManagePolicyGroupsDelete.verb
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsDelete()
    assert instance.class_name == "EpManagePolicyGroupsDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_manage_policy_groups_00410():
    """
    # Summary

    Verify EpManagePolicyGroupsDelete raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePolicyGroupsDelete.path
    """
    instance = EpManagePolicyGroupsDelete()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_groups_00420():
    """
    # Summary

    Verify EpManagePolicyGroupsDelete raises ValueError when policy_group_id is not set

    ## Test

    - Accessing path raises ValueError when policy_group_id is None

    ## Classes and Methods

    - EpManagePolicyGroupsDelete.path
    """
    instance = EpManagePolicyGroupsDelete()
    instance.fabric_name = "my-fabric"
    with pytest.raises(ValueError):
        instance.path


def test_manage_policy_groups_00430():
    """
    # Summary

    Verify EpManagePolicyGroupsDelete path with fabric_name and policy_group_id

    ## Test

    - path returns correct endpoint path with policy group ID segment

    ## Classes and Methods

    - EpManagePolicyGroupsDelete.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsDelete()
        instance.fabric_name = "my-fabric"
        instance.policy_group_id = "POLICY-GROUP-143310"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policyGroups/POLICY-GROUP-143310"


def test_manage_policy_groups_00440():
    """
    # Summary

    Verify EpManagePolicyGroupsDelete path with query params

    ## Test

    - path includes clusterName and ticketId in query string

    ## Classes and Methods

    - EpManagePolicyGroupsDelete.path
    """
    with does_not_raise():
        instance = EpManagePolicyGroupsDelete()
        instance.fabric_name = "my-fabric"
        instance.policy_group_id = "POLICY-GROUP-143310"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policyGroups/POLICY-GROUP-143310?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


# =============================================================================
# Test: URL-encoding of path segments
# =============================================================================


def test_manage_policy_groups_00450():
    """
    # Summary

    Verify `fabric_name` is URL-encoded in the path so reserved characters do not break the route.

    ## Test

    - Space encodes to %20 and slash encodes to %2F when fabric_name contains them
    - Raw `SITE A/B` does not appear in the rendered path

    ## Classes and Methods

    - EpManagePolicyGroupsPost.path
    """
    instance = EpManagePolicyGroupsPost()
    instance.fabric_name = "SITE A/B"
    # Space encodes to %20, slash to %2F.
    assert "/fabrics/SITE%20A%2FB/policyGroups" in instance.path
    assert " " not in instance.path
    assert "SITE A/B" not in instance.path


def test_manage_policy_groups_00460():
    """
    # Summary

    Verify `policy_group_id` is URL-encoded in the path so reserved characters do not break the route.

    ## Test

    - Space, `/`, `#`, and `?` in policy_group_id are percent-encoded
    - Raw reserved characters do not appear in the rendered path

    ## Classes and Methods

    - EpManagePolicyGroupsDelete.path
    """
    instance = EpManagePolicyGroupsDelete()
    instance.fabric_name = "SITE A/B"
    instance.policy_group_id = "POLICY-GROUP/143310 #foo?bar"
    # Space -> %20, slash -> %2F, # -> %23, ? -> %3F.
    assert "/fabrics/SITE%20A%2FB/policyGroups/POLICY-GROUP%2F143310%20%23foo%3Fbar" in instance.path
    assert " " not in instance.path
    assert "POLICY-GROUP/143310" not in instance.path
    assert "#foo" not in instance.path
    assert "?bar" not in instance.path
