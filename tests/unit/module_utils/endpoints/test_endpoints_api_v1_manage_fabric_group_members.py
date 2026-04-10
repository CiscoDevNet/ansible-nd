# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_group_members.py

Tests the ND Manage Fabric Group Members endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_group_members import (
    EpManageFabricGroupMembersGet,
    EpManageFabricGroupMembersAddPost,
    EpManageFabricGroupMembersRemovePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageFabricGroupMembersGet
# =============================================================================


def test_endpoints_manage_fabric_group_members_00010():
    """
    # Summary

    Verify EpManageFabricGroupMembersGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersGet()
    assert instance.class_name == "EpManageFabricGroupMembersGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_manage_fabric_group_members_00020():
    """
    # Summary

    Verify EpManageFabricGroupMembersGet path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-group/members" when fabric_name is set
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersGet()
        instance.fabric_name = "my-group"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-group/members"


def test_endpoints_manage_fabric_group_members_00030():
    """
    # Summary

    Verify EpManageFabricGroupMembersGet path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricGroupMembersGet()
        result = instance.path


def test_endpoints_manage_fabric_group_members_00040():
    """
    # Summary

    Verify EpManageFabricGroupMembersGet set_identifiers

    ## Test

    - set_identifiers sets fabric_name correctly
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersGet()
        instance.set_identifiers("my-group")
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-group/members"
    assert instance.fabric_name == "my-group"


# =============================================================================
# Test: EpManageFabricGroupMembersAddPost
# =============================================================================


def test_endpoints_manage_fabric_group_members_00100():
    """
    # Summary

    Verify EpManageFabricGroupMembersAddPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersAddPost()
    assert instance.class_name == "EpManageFabricGroupMembersAddPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_manage_fabric_group_members_00110():
    """
    # Summary

    Verify EpManageFabricGroupMembersAddPost path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-group/actions/addMembers"
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersAddPost()
        instance.fabric_name = "my-group"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-group/actions/addMembers"


def test_endpoints_manage_fabric_group_members_00120():
    """
    # Summary

    Verify EpManageFabricGroupMembersAddPost path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricGroupMembersAddPost()
        result = instance.path


def test_endpoints_manage_fabric_group_members_00130():
    """
    # Summary

    Verify EpManageFabricGroupMembersAddPost set_identifiers

    ## Test

    - set_identifiers sets fabric_name correctly
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersAddPost()
        instance.set_identifiers("my-group")
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-group/actions/addMembers"
    assert instance.fabric_name == "my-group"


# =============================================================================
# Test: EpManageFabricGroupMembersRemovePost
# =============================================================================


def test_endpoints_manage_fabric_group_members_00200():
    """
    # Summary

    Verify EpManageFabricGroupMembersRemovePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersRemovePost()
    assert instance.class_name == "EpManageFabricGroupMembersRemovePost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_manage_fabric_group_members_00210():
    """
    # Summary

    Verify EpManageFabricGroupMembersRemovePost path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-group/actions/removeMembers"
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersRemovePost()
        instance.fabric_name = "my-group"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-group/actions/removeMembers"


def test_endpoints_manage_fabric_group_members_00220():
    """
    # Summary

    Verify EpManageFabricGroupMembersRemovePost path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricGroupMembersRemovePost()
        result = instance.path


def test_endpoints_manage_fabric_group_members_00230():
    """
    # Summary

    Verify EpManageFabricGroupMembersRemovePost set_identifiers

    ## Test

    - set_identifiers sets fabric_name correctly
    """
    with does_not_raise():
        instance = EpManageFabricGroupMembersRemovePost()
        instance.set_identifiers("my-group")
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-group/actions/removeMembers"
    assert instance.fabric_name == "my-group"


# =============================================================================
# Test: Path with special characters in fabric group name
# =============================================================================


def test_endpoints_manage_fabric_group_members_00300():
    """
    # Summary

    Verify endpoints handle fabric group names with hyphens and underscores

    ## Test

    - All endpoints correctly build paths with complex fabric group names
    """
    complex_name = "my-fabric-group_v2"

    with does_not_raise():
        get_ep = EpManageFabricGroupMembersGet()
        get_ep.fabric_name = complex_name
        assert get_ep.path == f"/api/v1/manage/fabrics/{complex_name}/members"

        add_ep = EpManageFabricGroupMembersAddPost()
        add_ep.fabric_name = complex_name
        assert add_ep.path == f"/api/v1/manage/fabrics/{complex_name}/actions/addMembers"

        remove_ep = EpManageFabricGroupMembersRemovePost()
        remove_ep.fabric_name = complex_name
        assert remove_ep.path == f"/api/v1/manage/fabrics/{complex_name}/actions/removeMembers"
