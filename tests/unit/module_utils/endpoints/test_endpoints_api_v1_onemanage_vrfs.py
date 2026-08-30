# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for onemanage VRF endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_vrfs import (
    EpOneManageFabricsVrfActionsDeployPost,
    EpOneManageFabricsVrfActionsRemovePost,
    EpOneManageFabricsVrfAttachmentsExportPost,
    EpOneManageFabricsVrfAttachmentsImportPost,
    EpOneManageFabricsVrfAttachmentsPost,
    EpOneManageFabricsVrfAttachmentsQueryPost,
    EpOneManageFabricsVrfsGet,
    EpOneManageFabricsVrfsPost,
    EpOneManageFabricsVrfsVrfNameDelete,
    EpOneManageFabricsVrfsVrfNamePut,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworksGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def test_endpoints_api_v1_onemanage_vrfs_00010():
    """
    # Summary

    Verify list VRFs endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsVrfsGet(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfs"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_vrfs_00020():
    """
    # Summary

    Verify create VRFs endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsVrfsPost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfs"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_vrfs_00030():
    """
    # Summary

    Verify update VRF endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsVrfsVrfNamePut(fabric_name="MCFG_FAB", vrf_name="MyVRF_40001")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfs/MyVRF_40001"
    assert endpoint.verb == HttpVerbEnum.PUT


def test_endpoints_api_v1_onemanage_vrfs_00040():
    """
    # Summary

    Verify delete VRF endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsVrfsVrfNameDelete(fabric_name="MCFG_FAB", vrf_name="MyVRF_40001")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfs/MyVRF_40001"
    assert endpoint.verb == HttpVerbEnum.DELETE


def test_endpoints_api_v1_onemanage_vrfs_00050():
    """
    # Summary

    Verify deploy VRF action endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsVrfActionsDeployPost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfActions/deploy"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_vrfs_00060():
    """
    # Summary

    Verify remove VRF action endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsVrfActionsRemovePost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfActions/remove"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_vrfs_00070():
    """
    # Summary

    Verify VRF attachment endpoints match oneManage.json paths.
    """
    with does_not_raise():
        attach = EpOneManageFabricsVrfAttachmentsPost(fabric_name="MCFG_FAB")
        export = EpOneManageFabricsVrfAttachmentsExportPost(fabric_name="MCFG_FAB")
        import_ = EpOneManageFabricsVrfAttachmentsImportPost(fabric_name="MCFG_FAB")
        query = EpOneManageFabricsVrfAttachmentsQueryPost(fabric_name="MCFG_FAB")
        attach.endpoint_params.ticket_id = "CHG123"
        query.endpoint_params.max = 100
        query.endpoint_params.include_all = True

    assert attach.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfAttachments?ticketId=CHG123"
    assert export.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfAttachments/export"
    assert import_.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfAttachments/import"
    assert query.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfAttachments/query?max=100&includeAll=true"
    assert attach.verb == HttpVerbEnum.POST
    assert export.verb == HttpVerbEnum.POST
    assert import_.verb == HttpVerbEnum.POST
    assert query.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_vrfs_00080():
    """
    # Summary

    Verify OneManage networks GET path used by VRF dependency checks.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksGet(fabric_name="MCFG_FAB")
        endpoint.endpoint_params.max = 10000
        endpoint.endpoint_params.filter = "vrfName:MyVRF_50000"
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks?max=10000&filter=vrfName%3AMyVRF_50000"
    assert endpoint.verb == HttpVerbEnum.GET
