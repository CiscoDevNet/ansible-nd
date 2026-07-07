# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski (@skaszlik)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_acl.py

Tests the ND Manage Access Control List (ACL) endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_acl import (
    EpManageAclsBulkDelete,
    EpManageAclsDelete,
    EpManageAclsGet,
    EpManageAclsListGet,
    EpManageAclsPost,
    EpManageAclsPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

_BASE = "/api/v1/manage/fabrics"


# =============================================================================
# Test: EpManageAclsGet
# =============================================================================


def test_endpoints_api_v1_manage_acl_00010():
    """
    # Summary

    Verify EpManageAclsGet basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageAclsGet.__init__()
    - EpManageAclsGet.verb
    - EpManageAclsGet.class_name
    """
    with does_not_raise():
        instance = EpManageAclsGet()
    assert instance.class_name == "EpManageAclsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_acl_00020():
    """
    # Summary

    Verify EpManageAclsGet path with fabric_name and acl_name.

    ## Test

    - path returns ".../accessControlLists/my-acl" when both names are set

    ## Classes and Methods

    - EpManageAclsGet.path
    """
    with does_not_raise():
        instance = EpManageAclsGet()
        instance.fabric_name = "my-fabric"
        instance.acl_name = "my-acl"
        result = instance.path
    assert result == f"{_BASE}/my-fabric/accessControlLists/my-acl"


def test_endpoints_api_v1_manage_acl_00030():
    """
    # Summary

    Verify EpManageAclsGet path without fabric_name raises ValueError.

    ## Test

    - Accessing path without setting fabric_name raises ValueError

    ## Classes and Methods

    - EpManageAclsGet.path
    """
    with pytest.raises(ValueError, match="fabric_name must be set"):
        instance = EpManageAclsGet()
        instance.acl_name = "my-acl"
        result = instance.path  # noqa: F841


def test_endpoints_api_v1_manage_acl_00040():
    """
    # Summary

    Verify EpManageAclsGet path without acl_name raises ValueError.

    ## Test

    - Accessing path on an item endpoint without acl_name raises ValueError

    ## Classes and Methods

    - EpManageAclsGet.path
    """
    with pytest.raises(ValueError, match="acl_name must be set"):
        instance = EpManageAclsGet()
        instance.fabric_name = "my-fabric"
        result = instance.path  # noqa: F841


def test_endpoints_api_v1_manage_acl_00050():
    """
    # Summary

    Verify EpManageAclsGet URL-encodes fabric_name and acl_name path segments.

    ## Test

    - Reserved characters in fabric_name and acl_name are percent-encoded

    ## Classes and Methods

    - EpManageAclsGet.path
    """
    with does_not_raise():
        instance = EpManageAclsGet()
        instance.fabric_name = "fab/with space"
        instance.acl_name = "acl/name"
        result = instance.path
    assert result == f"{_BASE}/fab%2Fwith%20space/accessControlLists/acl%2Fname"


def test_endpoints_api_v1_manage_acl_00060():
    """
    # Summary

    Verify EpManageAclsGet path includes clusterName query parameter when set.

    ## Test

    - path appends ?clusterName=cluster1 when cluster_name is set

    ## Classes and Methods

    - EpManageAclsGet.path
    - AclsEndpointParams.cluster_name
    """
    with does_not_raise():
        instance = EpManageAclsGet()
        instance.fabric_name = "my-fabric"
        instance.acl_name = "my-acl"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == f"{_BASE}/my-fabric/accessControlLists/my-acl?clusterName=cluster1"


def test_endpoints_api_v1_manage_acl_00070():
    """
    # Summary

    Verify EpManageAclsGet.set_identifiers accepts a plain name and a tuple.

    ## Test

    - set_identifiers("acl1") assigns acl_name
    - set_identifiers(("acl2",)) assigns acl_name from tuple[0]

    ## Classes and Methods

    - EpManageAclsGet.set_identifiers
    """
    with does_not_raise():
        instance = EpManageAclsGet()
        instance.set_identifiers("acl1")
    assert instance.acl_name == "acl1"

    with does_not_raise():
        instance.set_identifiers(("acl2",))
    assert instance.acl_name == "acl2"


# =============================================================================
# Test: EpManageAclsListGet
# =============================================================================


def test_endpoints_api_v1_manage_acl_00100():
    """
    # Summary

    Verify EpManageAclsListGet instantiation, verb, and collection path.

    ## Test

    - class_name is EpManageAclsListGet
    - verb is GET
    - path requires only fabric_name (no acl_name) and targets the collection

    ## Classes and Methods

    - EpManageAclsListGet.__init__()
    - EpManageAclsListGet.path
    """
    with does_not_raise():
        instance = EpManageAclsListGet()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert instance.class_name == "EpManageAclsListGet"
    assert instance.verb == HttpVerbEnum.GET
    assert result == f"{_BASE}/my-fabric/accessControlLists"


def test_endpoints_api_v1_manage_acl_00110():
    """
    # Summary

    Verify EpManageAclsListGet path without fabric_name raises ValueError.

    ## Classes and Methods

    - EpManageAclsListGet.path
    """
    with pytest.raises(ValueError, match="fabric_name must be set"):
        instance = EpManageAclsListGet()
        result = instance.path  # noqa: F841


def test_endpoints_api_v1_manage_acl_00120():
    """
    # Summary

    Verify EpManageAclsListGet supports collection query parameters.

    ## Test

    - filter, max, offset, and sort are rendered into the query string

    ## Classes and Methods

    - EpManageAclsListGet.path
    - AclsListEndpointParams
    """
    with does_not_raise():
        instance = EpManageAclsListGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.max = 50
        instance.endpoint_params.offset = 10
        result = instance.path
    assert result.startswith(f"{_BASE}/my-fabric/accessControlLists?")
    assert "max=50" in result
    assert "offset=10" in result


# =============================================================================
# Test: EpManageAclsPost
# =============================================================================


def test_endpoints_api_v1_manage_acl_00200():
    """
    # Summary

    Verify EpManageAclsPost instantiation, verb, and collection path.

    ## Test

    - class_name is EpManageAclsPost
    - verb is POST
    - path is the collection endpoint (no acl_name required)

    ## Classes and Methods

    - EpManageAclsPost.__init__()
    - EpManageAclsPost.path
    """
    with does_not_raise():
        instance = EpManageAclsPost()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert instance.class_name == "EpManageAclsPost"
    assert instance.verb == HttpVerbEnum.POST
    assert result == f"{_BASE}/my-fabric/accessControlLists"


# =============================================================================
# Test: EpManageAclsPut
# =============================================================================


def test_endpoints_api_v1_manage_acl_00300():
    """
    # Summary

    Verify EpManageAclsPut instantiation, verb, and item path.

    ## Test

    - class_name is EpManageAclsPut
    - verb is PUT
    - path targets the item endpoint

    ## Classes and Methods

    - EpManageAclsPut.__init__()
    - EpManageAclsPut.path
    """
    with does_not_raise():
        instance = EpManageAclsPut()
        instance.fabric_name = "my-fabric"
        instance.acl_name = "my-acl"
        result = instance.path
    assert instance.class_name == "EpManageAclsPut"
    assert instance.verb == HttpVerbEnum.PUT
    assert result == f"{_BASE}/my-fabric/accessControlLists/my-acl"


# =============================================================================
# Test: EpManageAclsDelete
# =============================================================================


def test_endpoints_api_v1_manage_acl_00400():
    """
    # Summary

    Verify EpManageAclsDelete instantiation, verb, and item path.

    ## Test

    - class_name is EpManageAclsDelete
    - verb is DELETE
    - path targets the item endpoint

    ## Classes and Methods

    - EpManageAclsDelete.__init__()
    - EpManageAclsDelete.path
    """
    with does_not_raise():
        instance = EpManageAclsDelete()
        instance.fabric_name = "my-fabric"
        instance.acl_name = "my-acl"
        result = instance.path
    assert instance.class_name == "EpManageAclsDelete"
    assert instance.verb == HttpVerbEnum.DELETE
    assert result == f"{_BASE}/my-fabric/accessControlLists/my-acl"


# =============================================================================
# Test: EpManageAclsBulkDelete
# =============================================================================


def test_endpoints_api_v1_manage_acl_00500():
    """
    # Summary

    Verify EpManageAclsBulkDelete instantiation, verb, and action path.

    ## Test

    - class_name is EpManageAclsBulkDelete
    - verb is POST
    - path targets the accessControlListActions/remove action endpoint

    ## Classes and Methods

    - EpManageAclsBulkDelete.__init__()
    - EpManageAclsBulkDelete.path
    """
    with does_not_raise():
        instance = EpManageAclsBulkDelete()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert instance.class_name == "EpManageAclsBulkDelete"
    assert instance.verb == HttpVerbEnum.POST
    assert result == f"{_BASE}/my-fabric/accessControlListActions/remove"


def test_endpoints_api_v1_manage_acl_00510():
    """
    # Summary

    Verify EpManageAclsBulkDelete path without fabric_name raises ValueError.

    ## Classes and Methods

    - EpManageAclsBulkDelete.path
    """
    with pytest.raises(ValueError, match="fabric_name must be set"):
        instance = EpManageAclsBulkDelete()
        result = instance.path  # noqa: F841
