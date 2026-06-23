# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for onemanage fabrics endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.fabrics import (
    EpOneManageFabricsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)


def test_endpoints_api_v1_onemanage_fabrics_00010():
    """
    # Summary

    Verify EpOneManageFabricsGet basic instantiation.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsGet()
    assert endpoint.class_name == "EpOneManageFabricsGet"
    assert endpoint.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_onemanage_fabrics_00020():
    """
    # Summary

    Verify EpOneManageFabricsGet path without proxy prefix.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsGet()
        result = endpoint.path
    assert result == "/appcenter/cisco/ndfc/api/v1/onemanage/fabrics"


def test_endpoints_api_v1_onemanage_fabrics_00030():
    """
    # Summary

    Verify EpOneManageFabricsGet path with proxy prefix.
    """
    with does_not_raise():
        endpoint = EpOneManageFabricsGet(proxy_path="/onemanage")
        result = endpoint.path
    assert result == "/onemanage/appcenter/cisco/ndfc/api/v1/onemanage/fabrics"
