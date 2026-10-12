# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for schema-backed OneManage fabric endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics import (
    EpOneManageFabricsFabricNameGet,
    EpOneManageFabricsMembersGet,
    EpOneManageFabricsMembersAddPost,
    EpOneManageFabricsMembersRemovePost,
    EpOneManageFabricsConfigSavePost,
    EpOneManageFabricsDeployPost,
    EpOneManageFabricsSwitchesGet,
    EpOneManageFabricsSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def test_endpoints_api_v1_onemanage_fabrics_00010():
    """
    # Summary

    Verify OneManage fabric detail path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsFabricNameGet(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_fabrics_00020():
    """
    # Summary

    Verify OneManage fabric members path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsMembersGet(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/members"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_fabrics_00030():
    """
    # Summary

    Verify OneManage fabric addMembers action path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsMembersAddPost(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/actions/addMembers"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_fabrics_00040():
    """
    # Summary

    Verify OneManage fabric removeMembers action path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsMembersRemovePost(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/actions/removeMembers"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_fabrics_00050():
    """
    # Summary

    Verify OneManage fabric configSave action path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsConfigSavePost(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/actions/configSave"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_fabrics_00060():
    """
    # Summary

    Verify OneManage fabric deploy action path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsDeployPost(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/actions/deploy"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_fabrics_00070():
    """
    # Summary

    Verify OneManage fabric switches path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsSwitchesGet(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/switches"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_fabrics_00080():
    """
    # Summary

    Verify OneManage fabric switchActions/deploy path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsSwitchActionsDeployPost(fabric_name="MCFG_C")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_C/switchActions/deploy"
    assert endpoint.verb == HttpVerbEnum.POST
