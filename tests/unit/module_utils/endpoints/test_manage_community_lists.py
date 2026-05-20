# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for endpoints/v1/manage/manage_community_lists.py."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_community_lists import (
    EpManageCommunityListsBulkDelete,
    EpManageCommunityListsDelete,
    EpManageCommunityListsGet,
    EpManageCommunityListsListGet,
    EpManageCommunityListsPost,
    EpManageCommunityListsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


def test_manage_community_lists_00010() -> None:
    """
    # Summary

    Verify the list endpoint builds the collection path and supports Lucene query params.

    ## Classes and Methods

    - EpManageCommunityListsListGet.path
    """
    instance = EpManageCommunityListsListGet()
    instance.fabric_name = "SITE1"
    instance.lucene_params.max = 50
    instance.lucene_params.offset = 10

    assert instance.verb == HttpVerbEnum.GET
    assert instance.path == "/api/v1/manage/fabrics/SITE1/communityLists?max=50&offset=10"


def test_manage_community_lists_00020() -> None:
    """
    # Summary

    Verify dynamic path segments are percent-encoded.

    ## Classes and Methods

    - EpManageCommunityListsGet.path
    - EpManageCommunityListsGet.set_identifiers()
    """
    instance = EpManageCommunityListsGet()
    instance.fabric_name = "fab/one"
    instance.set_identifiers("tenantA~CL/one")

    assert instance.path == "/api/v1/manage/fabrics/fab%2Fone/communityLists/tenantA~CL%2Fone"


def test_manage_community_lists_00030() -> None:
    """
    # Summary

    Verify item endpoints reject missing required identifiers.

    ## Classes and Methods

    - EpManageCommunityListsGet.path
    """
    instance = EpManageCommunityListsGet()
    instance.fabric_name = "SITE1"

    with pytest.raises(ValueError, match="community_list_name must be set"):
        instance.path


def test_manage_community_lists_00040() -> None:
    """
    # Summary

    Verify all write endpoint verbs and paths.

    ## Classes and Methods

    - EpManageCommunityListsPost.path
    - EpManageCommunityListsPut.path
    - EpManageCommunityListsDelete.path
    - EpManageCommunityListsBulkDelete.path
    """
    post = EpManageCommunityListsPost()
    post.fabric_name = "SITE1"
    put = EpManageCommunityListsPut()
    put.fabric_name = "SITE1"
    put.set_identifiers("CL1")
    delete = EpManageCommunityListsDelete()
    delete.fabric_name = "SITE1"
    delete.set_identifiers("CL1")
    bulk_delete = EpManageCommunityListsBulkDelete()
    bulk_delete.fabric_name = "SITE1"

    assert post.verb == HttpVerbEnum.POST
    assert post.path == "/api/v1/manage/fabrics/SITE1/communityLists"
    assert put.verb == HttpVerbEnum.PUT
    assert put.path == "/api/v1/manage/fabrics/SITE1/communityLists/CL1"
    assert delete.verb == HttpVerbEnum.DELETE
    assert delete.path == "/api/v1/manage/fabrics/SITE1/communityLists/CL1"
    assert bulk_delete.verb == HttpVerbEnum.POST
    assert bulk_delete.path == "/api/v1/manage/fabrics/SITE1/communityListActions/remove"
