# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for endpoints/v1/manage/manage_extended_community_lists.py."""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_extended_community_lists import (
    EpManageExtendedCommunityListsBulkDelete,
    EpManageExtendedCommunityListsDelete,
    EpManageExtendedCommunityListsGet,
    EpManageExtendedCommunityListsListGet,
    EpManageExtendedCommunityListsPost,
    EpManageExtendedCommunityListsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


def test_manage_extended_community_lists_00010() -> None:
    """
    # Summary

    Verify the list endpoint builds the collection path and supports Lucene query params.

    ## Classes and Methods

    - EpManageExtendedCommunityListsListGet.path
    """
    instance = EpManageExtendedCommunityListsListGet()
    instance.fabric_name = "SITE1"
    instance.lucene_params.filter = "name:ECL*"
    instance.lucene_params.sort = "name:asc"

    assert instance.verb == HttpVerbEnum.GET
    assert instance.path == "/api/v1/manage/fabrics/SITE1/extendedCommunityLists?filter=name:ECL%2A&sort=name%3Aasc"


def test_manage_extended_community_lists_00020() -> None:
    """
    # Summary

    Verify dynamic path segments are percent-encoded.

    ## Classes and Methods

    - EpManageExtendedCommunityListsGet.path
    - EpManageExtendedCommunityListsGet.set_identifiers()
    """
    instance = EpManageExtendedCommunityListsGet()
    instance.fabric_name = "fab/one"
    instance.set_identifiers("tenantA~ECL/one")

    assert instance.path == "/api/v1/manage/fabrics/fab%2Fone/extendedCommunityLists/tenantA~ECL%2Fone"


def test_manage_extended_community_lists_00030() -> None:
    """
    # Summary

    Verify item endpoints reject missing required identifiers.

    ## Classes and Methods

    - EpManageExtendedCommunityListsGet.path
    """
    instance = EpManageExtendedCommunityListsGet()
    instance.fabric_name = "SITE1"

    with pytest.raises(ValueError, match="extended_community_list_name must be set"):
        instance.path


def test_manage_extended_community_lists_00040() -> None:
    """
    # Summary

    Verify all write endpoint verbs and paths.

    ## Classes and Methods

    - EpManageExtendedCommunityListsPost.path
    - EpManageExtendedCommunityListsPut.path
    - EpManageExtendedCommunityListsDelete.path
    - EpManageExtendedCommunityListsBulkDelete.path
    """
    post = EpManageExtendedCommunityListsPost()
    post.fabric_name = "SITE1"
    put = EpManageExtendedCommunityListsPut()
    put.fabric_name = "SITE1"
    put.set_identifiers("ECL1")
    delete = EpManageExtendedCommunityListsDelete()
    delete.fabric_name = "SITE1"
    delete.set_identifiers("ECL1")
    bulk_delete = EpManageExtendedCommunityListsBulkDelete()
    bulk_delete.fabric_name = "SITE1"

    assert post.verb == HttpVerbEnum.POST
    assert post.path == "/api/v1/manage/fabrics/SITE1/extendedCommunityLists"
    assert put.verb == HttpVerbEnum.PUT
    assert put.path == "/api/v1/manage/fabrics/SITE1/extendedCommunityLists/ECL1"
    assert delete.verb == HttpVerbEnum.DELETE
    assert delete.path == "/api/v1/manage/fabrics/SITE1/extendedCommunityLists/ECL1"
    assert bulk_delete.verb == HttpVerbEnum.POST
    assert bulk_delete.path == "/api/v1/manage/fabrics/SITE1/extendedCommunityListActions/remove"
