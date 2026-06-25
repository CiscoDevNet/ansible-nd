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
    EpOneManageFabricsNetworksBulkDelete,
    EpOneManageFabricsNetworksGet,
    EpOneManageFabricsNetworksNetworkNameDelete,
    EpOneManageFabricsNetworksNetworkNamePut,
    EpOneManageFabricsNetworksPost,
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
        endpoint = EpOneManageFabricsNetworksGet(fabric_name="MCFG_FAB", proxy_path="/onemanage")
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/fabrics/MCFG_FAB/networks"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_networks_00020():
    """
    # Summary

    Verify create networks endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksPost(fabric_name="MCFG_FAB", proxy_path="/onemanage")
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/fabrics/MCFG_FAB/networks"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_networks_00030():
    """
    # Summary

    Verify update network endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksNetworkNamePut(fabric_name="MCFG_FAB", network_name="MyNetwork_40001", proxy_path="/onemanage")
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/fabrics/MCFG_FAB/networks/MyNetwork_40001"
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
            proxy_path="/onemanage",
        )
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/fabrics/MCFG_FAB/networks/MyNetwork_40001"
    assert endpoint.verb == HttpVerbEnum.DELETE


def test_endpoints_api_v1_onemanage_networks_00050():
    """
    # Summary

    Verify deploy network action endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworkActionsDeployPost(fabric_name="MCFG_FAB", proxy_path="/onemanage")
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/networks/deploy"
    assert endpoint.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_onemanage_networks_00060():
    """
    # Summary

    Verify bulk-delete network endpoint path and verb.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsNetworksBulkDelete(fabric_name="MCFG_FAB", proxy_path="/onemanage")
        endpoint.query_params.network_names = "NET1,NET2"
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/top-down/fabrics/MCFG_FAB/bulk-delete/networks?network-names=NET1,NET2"
    assert endpoint.verb == HttpVerbEnum.DELETE
