# Copyright: (c) 2026, Cisco Systems

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_policies.py

Tests the ND Manage Policies endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_policies import (
    EpManagePoliciesDelete,
    EpManagePoliciesGet,
    EpManagePoliciesPost,
    EpManagePoliciesPut,
    PoliciesGetEndpointParams,
    PolicyMutationEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: PoliciesGetEndpointParams
# =============================================================================


def test_manage_policies_00010():
    """
    # Summary

    Verify PoliciesGetEndpointParams default values

    ## Test

    - cluster_name defaults to None

    ## Classes and Methods

    - PoliciesGetEndpointParams.__init__()
    """
    with does_not_raise():
        params = PoliciesGetEndpointParams()
    assert params.cluster_name is None


def test_manage_policies_00020():
    """
    # Summary

    Verify PoliciesGetEndpointParams generates query string with cluster_name

    ## Test

    - to_query_string() includes clusterName when set

    ## Classes and Methods

    - PoliciesGetEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PoliciesGetEndpointParams(cluster_name="cluster1")
        result = params.to_query_string()
    assert result == "clusterName=cluster1"


def test_manage_policies_00030():
    """
    # Summary

    Verify PoliciesGetEndpointParams returns empty string when no params set

    ## Test

    - to_query_string() returns empty string when cluster_name is None

    ## Classes and Methods

    - PoliciesGetEndpointParams.to_query_string()
    """
    params = PoliciesGetEndpointParams()
    assert params.to_query_string() == ""


def test_manage_policies_00040():
    """
    # Summary

    Verify PoliciesGetEndpointParams rejects extra fields

    ## Test

    - Extra fields cause validation error (extra="forbid")

    ## Classes and Methods

    - PoliciesGetEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PoliciesGetEndpointParams(bogus="bad")


# =============================================================================
# Test: PolicyMutationEndpointParams
# =============================================================================


def test_manage_policies_00050():
    """
    # Summary

    Verify PolicyMutationEndpointParams default values

    ## Test

    - cluster_name defaults to None
    - ticket_id defaults to None

    ## Classes and Methods

    - PolicyMutationEndpointParams.__init__()
    """
    with does_not_raise():
        params = PolicyMutationEndpointParams()
    assert params.cluster_name is None
    assert params.ticket_id is None


def test_manage_policies_00060():
    """
    # Summary

    Verify PolicyMutationEndpointParams generates query string with both params

    ## Test

    - to_query_string() includes clusterName and ticketId when both are set

    ## Classes and Methods

    - PolicyMutationEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = PolicyMutationEndpointParams(cluster_name="cluster1", ticket_id="MyTicket1234")
        result = params.to_query_string()
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


def test_manage_policies_00070():
    """
    # Summary

    Verify PolicyMutationEndpointParams ticket_id pattern validation

    ## Test

    - ticket_id rejects values not matching ^[a-zA-Z][a-zA-Z0-9_-]+$

    ## Classes and Methods

    - PolicyMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyMutationEndpointParams(ticket_id="123-invalid")


def test_manage_policies_00075():
    """
    # Summary

    Verify PolicyMutationEndpointParams ticket_id max length validation

    ## Test

    - ticket_id rejects values longer than 64 characters

    ## Classes and Methods

    - PolicyMutationEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        PolicyMutationEndpointParams(ticket_id="A" * 65)


# =============================================================================
# Test: EpManagePoliciesGet
# =============================================================================


def test_manage_policies_00100():
    """
    # Summary

    Verify EpManagePoliciesGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManagePoliciesGet.__init__()
    - EpManagePoliciesGet.class_name
    - EpManagePoliciesGet.verb
    """
    with does_not_raise():
        instance = EpManagePoliciesGet()
    assert instance.class_name == "EpManagePoliciesGet"
    assert instance.verb == HttpVerbEnum.GET


def test_manage_policies_00110():
    """
    # Summary

    Verify EpManagePoliciesGet raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePoliciesGet.path
    """
    instance = EpManagePoliciesGet()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policies_00120():
    """
    # Summary

    Verify EpManagePoliciesGet path without query params

    ## Test

    - path returns correct base endpoint path

    ## Classes and Methods

    - EpManagePoliciesGet.path
    """
    with does_not_raise():
        instance = EpManagePoliciesGet()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policies"


def test_manage_policies_00130():
    """
    # Summary

    Verify EpManagePoliciesGet path with policy_id returns single-policy path

    ## Test

    - path includes policyId segment when policy_id is set

    ## Classes and Methods

    - EpManagePoliciesGet.path
    """
    with does_not_raise():
        instance = EpManagePoliciesGet()
        instance.fabric_name = "my-fabric"
        instance.policy_id = "POLICY-12345"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policies/POLICY-12345"


def test_manage_policies_00140():
    """
    # Summary

    Verify EpManagePoliciesGet path with Lucene filter parameters

    ## Test

    - path includes filter and max in query string when Lucene params are set

    ## Classes and Methods

    - EpManagePoliciesGet.path
    """
    with does_not_raise():
        instance = EpManagePoliciesGet()
        instance.fabric_name = "my-fabric"
        instance.lucene_params.filter = "switchId:FDO123 AND templateName:switch_freeform"
        instance.lucene_params.max = 100
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policies?")
    assert "max=100" in result
    assert "filter=" in result


def test_manage_policies_00150():
    """
    # Summary

    Verify EpManagePoliciesGet path with clusterName query param

    ## Test

    - path includes clusterName in query string when set

    ## Classes and Methods

    - EpManagePoliciesGet.path
    """
    with does_not_raise():
        instance = EpManagePoliciesGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policies?")
    assert "clusterName=cluster1" in result


def test_manage_policies_00160():
    """
    # Summary

    Verify EpManagePoliciesGet path with combined endpoint and Lucene params

    ## Test

    - path includes both clusterName and Lucene params

    ## Classes and Methods

    - EpManagePoliciesGet.path
    """
    with does_not_raise():
        instance = EpManagePoliciesGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.lucene_params.max = 50
        instance.lucene_params.sort = "policyId:asc"
        result = instance.path
    assert "clusterName=cluster1" in result
    assert "max=50" in result
    assert "sort=" in result


# =============================================================================
# Test: EpManagePoliciesPost
# =============================================================================


def test_manage_policies_00200():
    """
    # Summary

    Verify EpManagePoliciesPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManagePoliciesPost.__init__()
    - EpManagePoliciesPost.class_name
    - EpManagePoliciesPost.verb
    """
    with does_not_raise():
        instance = EpManagePoliciesPost()
    assert instance.class_name == "EpManagePoliciesPost"
    assert instance.verb == HttpVerbEnum.POST


def test_manage_policies_00210():
    """
    # Summary

    Verify EpManagePoliciesPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePoliciesPost.path
    """
    instance = EpManagePoliciesPost()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policies_00220():
    """
    # Summary

    Verify EpManagePoliciesPost path without query params

    ## Test

    - path returns correct base endpoint path

    ## Classes and Methods

    - EpManagePoliciesPost.path
    """
    with does_not_raise():
        instance = EpManagePoliciesPost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policies"


def test_manage_policies_00230():
    """
    # Summary

    Verify EpManagePoliciesPost path with clusterName and ticketId

    ## Test

    - path includes clusterName and ticketId in query string when set

    ## Classes and Methods

    - EpManagePoliciesPost.path
    """
    with does_not_raise():
        instance = EpManagePoliciesPost()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policies?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


# =============================================================================
# Test: EpManagePoliciesPut
# =============================================================================


def test_manage_policies_00300():
    """
    # Summary

    Verify EpManagePoliciesPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpManagePoliciesPut.__init__()
    - EpManagePoliciesPut.class_name
    - EpManagePoliciesPut.verb
    """
    with does_not_raise():
        instance = EpManagePoliciesPut()
    assert instance.class_name == "EpManagePoliciesPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_manage_policies_00310():
    """
    # Summary

    Verify EpManagePoliciesPut raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePoliciesPut.path
    """
    instance = EpManagePoliciesPut()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policies_00320():
    """
    # Summary

    Verify EpManagePoliciesPut raises ValueError when policy_id is not set

    ## Test

    - Accessing path raises ValueError when policy_id is None

    ## Classes and Methods

    - EpManagePoliciesPut.path
    """
    instance = EpManagePoliciesPut()
    instance.fabric_name = "my-fabric"
    with pytest.raises(ValueError):
        instance.path


def test_manage_policies_00330():
    """
    # Summary

    Verify EpManagePoliciesPut path with fabric_name and policy_id

    ## Test

    - path returns correct endpoint path with policyId

    ## Classes and Methods

    - EpManagePoliciesPut.path
    """
    with does_not_raise():
        instance = EpManagePoliciesPut()
        instance.fabric_name = "my-fabric"
        instance.policy_id = "POLICY-12345"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policies/POLICY-12345"


def test_manage_policies_00340():
    """
    # Summary

    Verify EpManagePoliciesPut path with query params

    ## Test

    - path includes clusterName and ticketId in query string when set

    ## Classes and Methods

    - EpManagePoliciesPut.path
    """
    with does_not_raise():
        instance = EpManagePoliciesPut()
        instance.fabric_name = "my-fabric"
        instance.policy_id = "POLICY-12345"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policies/POLICY-12345?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result


# =============================================================================
# Test: EpManagePoliciesDelete
# =============================================================================


def test_manage_policies_00400():
    """
    # Summary

    Verify EpManagePoliciesDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpManagePoliciesDelete.__init__()
    - EpManagePoliciesDelete.class_name
    - EpManagePoliciesDelete.verb
    """
    with does_not_raise():
        instance = EpManagePoliciesDelete()
    assert instance.class_name == "EpManagePoliciesDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_manage_policies_00410():
    """
    # Summary

    Verify EpManagePoliciesDelete raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManagePoliciesDelete.path
    """
    instance = EpManagePoliciesDelete()
    with pytest.raises(ValueError):
        instance.path


def test_manage_policies_00420():
    """
    # Summary

    Verify EpManagePoliciesDelete raises ValueError when policy_id is not set

    ## Test

    - Accessing path raises ValueError when policy_id is None

    ## Classes and Methods

    - EpManagePoliciesDelete.path
    """
    instance = EpManagePoliciesDelete()
    instance.fabric_name = "my-fabric"
    with pytest.raises(ValueError):
        instance.path


def test_manage_policies_00430():
    """
    # Summary

    Verify EpManagePoliciesDelete path with fabric_name and policy_id

    ## Test

    - path returns correct endpoint path with policyId

    ## Classes and Methods

    - EpManagePoliciesDelete.path
    """
    with does_not_raise():
        instance = EpManagePoliciesDelete()
        instance.fabric_name = "my-fabric"
        instance.policy_id = "POLICY-12345"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/policies/POLICY-12345"


def test_manage_policies_00440():
    """
    # Summary

    Verify EpManagePoliciesDelete path with query params

    ## Test

    - path includes clusterName and ticketId in query string when set

    ## Classes and Methods

    - EpManagePoliciesDelete.path
    """
    with does_not_raise():
        instance = EpManagePoliciesDelete()
        instance.fabric_name = "my-fabric"
        instance.policy_id = "POLICY-12345"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "MyTicket1234"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/my-fabric/policies/POLICY-12345?")
    assert "clusterName=cluster1" in result
    assert "ticketId=MyTicket1234" in result
