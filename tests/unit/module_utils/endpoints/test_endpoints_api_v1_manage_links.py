# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_links.py

Tests the ND Manage Links endpoint classes.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_links import (
    EpManageLinksListGet,
    ManageLinksListEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_endpoints_api_v1_manage_links_00010():
    """
    # Summary

    Verify ManageLinksListEndpointParams default values

    ## Test

    - fabric_name, switch_id, max, offset, cluster_name all default to None
    - An all-default instance renders an empty query string

    ## Classes and Methods

    - ManageLinksListEndpointParams.__init__()
    - ManageLinksListEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ManageLinksListEndpointParams()
    assert params.fabric_name is None
    assert params.switch_id is None
    assert params.max is None
    assert params.offset is None
    assert params.cluster_name is None
    assert params.to_query_string() == ""


def test_endpoints_api_v1_manage_links_00020():
    """
    # Summary

    Verify EpManageLinksListGet.path raises when fabric_name is unset (the API requires it)

    ## Test

    - Accessing path without endpoint_params.fabric_name raises ValueError

    ## Classes and Methods

    - EpManageLinksListGet.path
    """
    endpoint = EpManageLinksListGet()
    with pytest.raises(ValueError, match=r"EpManageLinksListGet\.path: endpoint_params\.fabric_name must be set before accessing path\."):
        result = endpoint.path  # pylint: disable=pointless-statement
        assert result  # pragma: no cover


def test_endpoints_api_v1_manage_links_00030():
    """
    # Summary

    Verify EpManageLinksListGet.path with only fabric_name set

    ## Test

    - fabric_name is rendered as the camelCase `fabricName` query parameter

    ## Classes and Methods

    - EpManageLinksListGet.path
    """
    endpoint = EpManageLinksListGet()
    endpoint.endpoint_params.fabric_name = "SITE1"
    assert endpoint.path == "/api/v1/manage/links?fabricName=SITE1"


def test_endpoints_api_v1_manage_links_00040():
    """
    # Summary

    Verify EpManageLinksListGet.path with every query parameter set

    ## Test

    - fabric_name, switch_id, max, offset render as camelCase keys; the fabric name is URL-encoded

    ## Classes and Methods

    - EpManageLinksListGet.path
    - ManageLinksListEndpointParams.to_query_string()
    """
    endpoint = EpManageLinksListGet()
    endpoint.endpoint_params.fabric_name = "my fabric"
    endpoint.endpoint_params.switch_id = "FDO22222BBB"
    endpoint.endpoint_params.max = 100
    endpoint.endpoint_params.offset = 200
    assert endpoint.path == "/api/v1/manage/links?fabricName=my%20fabric&switchId=FDO22222BBB&max=100&offset=200"


def test_endpoints_api_v1_manage_links_00050():
    """
    # Summary

    Verify EpManageLinksListGet verb and class_name

    ## Test

    - verb is HttpVerbEnum.GET
    - class_name is "EpManageLinksListGet"

    ## Classes and Methods

    - EpManageLinksListGet.verb
    """
    endpoint = EpManageLinksListGet()
    assert endpoint.verb == HttpVerbEnum.GET
    assert endpoint.class_name == "EpManageLinksListGet"


def test_endpoints_api_v1_manage_links_00060():
    """
    # Summary

    Verify ManageLinksListEndpointParams rejects out-of-range paging values

    ## Test

    - max below 1 and offset below 0 raise a validation error

    ## Classes and Methods

    - ManageLinksListEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        ManageLinksListEndpointParams(max=0)
    with pytest.raises(ValueError):
        ManageLinksListEndpointParams(offset=-1)
