# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_actions.py

Tests the ND Manage Fabrics Actions endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions import (
    EpManageFabricsActionsConfigSavePost,
    EpManageFabricsActionsShallowDiscoveryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageFabricsActionsShallowDiscoveryPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_actions_00100():
    """
    # Summary

    Verify EpManageFabricsActionsShallowDiscoveryPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsActionsShallowDiscoveryPost.__init__()
    - EpManageFabricsActionsShallowDiscoveryPost.class_name
    - EpManageFabricsActionsShallowDiscoveryPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsActionsShallowDiscoveryPost()
    assert instance.class_name == "EpManageFabricsActionsShallowDiscoveryPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_actions_00110():
    """
    # Summary

    Verify EpManageFabricsActionsShallowDiscoveryPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsActionsShallowDiscoveryPost.path
    """
    instance = EpManageFabricsActionsShallowDiscoveryPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_actions_00120():
    """
    # Summary

    Verify EpManageFabricsActionsShallowDiscoveryPost path

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsActionsShallowDiscoveryPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsActionsShallowDiscoveryPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/actions/shallowDiscovery"


# =============================================================================
# Test: EpManageFabricsActionsConfigSavePost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_actions_00200():
    """
    # Summary

    Verify EpManageFabricsActionsConfigSavePost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsActionsConfigSavePost.__init__()
    - EpManageFabricsActionsConfigSavePost.class_name
    - EpManageFabricsActionsConfigSavePost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsActionsConfigSavePost()
    assert instance.class_name == "EpManageFabricsActionsConfigSavePost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_actions_00210():
    """
    # Summary

    Verify EpManageFabricsActionsConfigSavePost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsActionsConfigSavePost.path
    """
    instance = EpManageFabricsActionsConfigSavePost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_actions_00220():
    """
    # Summary

    Verify EpManageFabricsActionsConfigSavePost path

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsActionsConfigSavePost.path
    """
    with does_not_raise():
        instance = EpManageFabricsActionsConfigSavePost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/actions/configSave"
