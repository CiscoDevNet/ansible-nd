# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_inventory.py

Tests the ND Manage Fabrics Inventory endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_inventory import (
    EpManageFabricsInventoryDiscoverGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageFabricsInventoryDiscoverGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_inventory_00010():
    """
    # Summary

    Verify EpManageFabricsInventoryDiscoverGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricsInventoryDiscoverGet.__init__()
    - EpManageFabricsInventoryDiscoverGet.class_name
    - EpManageFabricsInventoryDiscoverGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricsInventoryDiscoverGet()
    assert instance.class_name == "EpManageFabricsInventoryDiscoverGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_inventory_00020():
    """
    # Summary

    Verify EpManageFabricsInventoryDiscoverGet raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsInventoryDiscoverGet.path
    """
    instance = EpManageFabricsInventoryDiscoverGet()
    with pytest.raises(ValueError):
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_inventory_00030():
    """
    # Summary

    Verify EpManageFabricsInventoryDiscoverGet path

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsInventoryDiscoverGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsInventoryDiscoverGet()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/inventory/discover"
