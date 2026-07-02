# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for endpoints/v1/manage/fabric_update_group.py

Tests the ND Manage Fabric Update Group endpoint classes, focusing on path construction and the
percent-encoding of the dynamic `fabric_name` / `update_group_name` path segments.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.fabric_update_group import (
    EpFabricUpdateGroupDelete,
    EpFabricUpdateGroupGet,
    EpFabricUpdateGroupListGet,
    EpFabricUpdateGroupPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test: EpFabricUpdateGroupListGet (collection-level, no update_group_name)
# =============================================================================


def test_ep_fabric_update_group_00010():
    """
    # Summary

    Verify EpFabricUpdateGroupListGet basic instantiation and verb.

    ## Test

    - Instance can be created
    - verb is GET
    - fabric_name defaults to None

    ## Classes and Methods

    - EpFabricUpdateGroupListGet.__init__()
    - EpFabricUpdateGroupListGet.verb
    """
    with does_not_raise():
        instance = EpFabricUpdateGroupListGet()
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None


def test_ep_fabric_update_group_00020():
    """
    # Summary

    Verify the list path raises ValueError when fabric_name is None.

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpFabricUpdateGroupListGet.path
    """
    instance = EpFabricUpdateGroupListGet()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_fabric_update_group_00030():
    """
    # Summary

    Verify the list path returns the collection URL (no update_group_name segment).

    ## Test

    - fabric_name is set
    - path returns /api/v1/manage/fabrics/SITE1/updateGroups

    ## Classes and Methods

    - EpFabricUpdateGroupListGet.path
    """
    with does_not_raise():
        instance = EpFabricUpdateGroupListGet()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/updateGroups"


def test_ep_fabric_update_group_00040():
    """
    # Summary

    Verify fabric_name is percent-encoded in the list path.

    ## Test

    - fabric_name = "fab/odd"
    - path encodes the slash

    ## Classes and Methods

    - EpFabricUpdateGroupListGet.path
    """
    instance = EpFabricUpdateGroupListGet()
    instance.fabric_name = "fab/odd"
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/updateGroups"


# =============================================================================
# Test: EpFabricUpdateGroupGet (per-name)
# =============================================================================


def test_ep_fabric_update_group_00100():
    """
    # Summary

    Verify the per-name GET path raises ValueError when update_group_name is required but unset.

    ## Test

    - fabric_name is set, update_group_name is not
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpFabricUpdateGroupGet.path
    """
    instance = EpFabricUpdateGroupGet()
    instance.fabric_name = "SITE1"
    with pytest.raises(ValueError, match="update_group_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_ep_fabric_update_group_00110():
    """
    # Summary

    Verify the per-name GET path returns the correct URL.

    ## Test

    - fabric_name and update_group_name are set
    - path returns /api/v1/manage/fabrics/SITE1/updateGroups/leaf_group

    ## Classes and Methods

    - EpFabricUpdateGroupGet.path
    - EpFabricUpdateGroupGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpFabricUpdateGroupGet()
        instance.fabric_name = "SITE1"
        instance.set_identifiers("leaf_group")
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE1/updateGroups/leaf_group"


def test_ep_fabric_update_group_00120():
    """
    # Summary

    Verify both fabric_name and update_group_name are percent-encoded in the per-name GET path.

    ## Test

    - fabric_name = "fab/odd", update_group_name = "grp/one"
    - path encodes the slash in both segments

    ## Classes and Methods

    - EpFabricUpdateGroupGet.path
    """
    instance = EpFabricUpdateGroupGet()
    instance.fabric_name = "fab/odd"
    instance.set_identifiers("grp/one")
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/updateGroups/grp%2Fone"


# =============================================================================
# Test: EpFabricUpdateGroupPut / EpFabricUpdateGroupDelete encoding parity
# =============================================================================


def test_ep_fabric_update_group_00200():
    """
    # Summary

    Verify the PUT path percent-encodes both dynamic segments and uses the PUT verb.

    ## Test

    - fabric_name = "fab/odd", update_group_name = "grp/one"
    - path encodes both, verb is PUT

    ## Classes and Methods

    - EpFabricUpdateGroupPut.path
    - EpFabricUpdateGroupPut.verb
    """
    instance = EpFabricUpdateGroupPut()
    instance.fabric_name = "fab/odd"
    instance.set_identifiers("grp/one")
    assert instance.verb == HttpVerbEnum.PUT
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/updateGroups/grp%2Fone"


def test_ep_fabric_update_group_00210():
    """
    # Summary

    Verify the DELETE path percent-encodes both dynamic segments and uses the DELETE verb.

    ## Test

    - fabric_name = "fab/odd", update_group_name = "grp/one"
    - path encodes both, verb is DELETE

    ## Classes and Methods

    - EpFabricUpdateGroupDelete.path
    - EpFabricUpdateGroupDelete.verb
    """
    instance = EpFabricUpdateGroupDelete()
    instance.fabric_name = "fab/odd"
    instance.set_identifiers("grp/one")
    assert instance.verb == HttpVerbEnum.DELETE
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/updateGroups/grp%2Fone"
