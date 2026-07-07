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
