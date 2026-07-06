# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for onemanage network endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworkActionsDeployPost,
    EpOneManageFabricsNetworkActionsRemovePost,
    EpOneManageFabricsNetworkAttachmentsExportPost,
    EpOneManageFabricsNetworkAttachmentsImportPost,
    EpOneManageFabricsNetworkAttachmentsPost,
    EpOneManageFabricsNetworkAttachmentsQueryPost,
    EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost,
    EpOneManageFabricsNetworksGet,
    EpOneManageFabricsNetworksNetworkNameDelete,
    EpOneManageFabricsNetworksNetworkNamePut,
    EpOneManageFabricsNetworksPost,
    EpOneManageFabricsSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def test_endpoints_api_v1_onemanage_networks_00010():
    """
    # Summary

    Verify list networks endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksGet(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_networks_00020():
    """
    # Summary

    Verify create networks endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksPost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_networks_00030():
    """
    # Summary

    Verify update network endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksNetworkNamePut(fabric_name="MCFG_FAB", network_name="MyNetwork_40001")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks/MyNetwork_40001"
    assert endpoint.verb == HttpVerbEnum.PUT


def test_endpoints_api_v1_onemanage_networks_00040():
    """
    # Summary

    Verify delete network endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksNetworkNameDelete(
            fabric_name="MCFG_FAB",
            network_name="MyNetwork_40001",
        )
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networks/MyNetwork_40001"
    assert endpoint.verb == HttpVerbEnum.DELETE


def test_endpoints_api_v1_onemanage_networks_00050():
    """
    # Summary

    Verify deploy network action endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworkActionsDeployPost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkActions/deploy"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_networks_00060():
    """
    # Summary

    Verify remove network action endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworkActionsRemovePost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkActions/remove"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_networks_00070():
    """
    # Summary

    Verify network attachment endpoints match oneManage.json paths.
    """
    with does_not_raise():
        attach = EpOneManageFabricsNetworkAttachmentsPost(fabric_name="MCFG_FAB")
        export = EpOneManageFabricsNetworkAttachmentsExportPost(fabric_name="MCFG_FAB")
        import_ = EpOneManageFabricsNetworkAttachmentsImportPost(fabric_name="MCFG_FAB")
        query = EpOneManageFabricsNetworkAttachmentsQueryPost(fabric_name="MCFG_FAB")
        validate = EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost(fabric_name="MCFG_FAB")
        attach.endpoint_params.ticket_id = "CHG123"
        query.endpoint_params.max = 100
        query.endpoint_params.include_all = True

    assert attach.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments?ticketId=CHG123"
    assert validate.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments/validateInterfaces?strictModeValidation=false"
    assert export.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachment/export"
    assert import_.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments/import"
    assert query.path == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/networkAttachments/query?max=100&includeAll=true"
    assert attach.verb == HttpVerbEnum.POST
    assert validate.verb == HttpVerbEnum.POST
    assert export.verb == HttpVerbEnum.POST
    assert import_.verb == HttpVerbEnum.POST
    assert query.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_networks_00080():
    """
    # Summary

    Verify OneManage switch deploy endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsSwitchActionsDeployPost(fabric_name="MCFG_FAB")
        result = endpoint.path
    assert result == "/api/v1/oneManage/manage/fabrics/MCFG_FAB/switchActions/deploy?forceShowRun=false"
    assert endpoint.verb == HttpVerbEnum.POST
