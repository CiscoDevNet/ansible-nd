# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_prefix_lists.py endpoint classes.

Tests the endpoint definitions for IPv4 and IPv6 prefix list API operations.
Verifies fabric_name and prefix_list_name requirements, path construction with URL encoding,
and query parameter handling.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_prefix_lists import (
    EpManageIpv4PrefixListsDelete,
    EpManageIpv4PrefixListsGet,
    EpManageIpv4PrefixListsListGet,
    EpManageIpv4PrefixListsPost,
    EpManageIpv4PrefixListsPut,
    EpManageIpv6PrefixListsDelete,
    EpManageIpv6PrefixListsGet,
    EpManageIpv6PrefixListsListGet,
    EpManageIpv6PrefixListsPost,
    EpManageIpv6PrefixListsPut,
    EpManageIpv4PrefixListsBulkDelete,
    EpManageIpv6PrefixListsBulkDelete,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test: IPv4 Endpoints
# =============================================================================


def test_endpoints_ipv4_prefix_lists_00010():
    """
    # Summary

    Verify EpManageIpv4PrefixListsGet instantiation and basic properties.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    - fabric_name and prefix_list_name default to None

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet.__init__()
    - EpManageIpv4PrefixListsGet.verb
    - EpManageIpv4PrefixListsGet.class_name
    """
    with does_not_raise():
        instance = EpManageIpv4PrefixListsGet()
    assert instance.class_name == "EpManageIpv4PrefixListsGet"
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None
    assert instance.prefix_list_name is None


def test_endpoints_ipv4_prefix_lists_00020():
    """
    # Summary

    Verify path raises ValueError when fabric_name is None (fail-fast requirement).

    ## Test

    - fabric_name is not set
    - Accessing path raises ValueError with descriptive message

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet.path
    """
    instance = EpManageIpv4PrefixListsGet()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        _ = instance.path


def test_endpoints_ipv4_prefix_lists_00030():
    """
    # Summary

    Verify path raises ValueError when prefix_list_name is None (fabric_name set).

    ## Test

    - fabric_name is set, prefix_list_name is not
    - Accessing path raises ValueError

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet.path
    """
    instance = EpManageIpv4PrefixListsGet()
    instance.fabric_name = "SITE1"
    with pytest.raises(ValueError, match="prefix_list_name must be set"):
        _ = instance.path


def test_endpoints_ipv4_prefix_lists_00040():
    """
    # Summary

    Verify path returns correct URL with all params set and special characters URL-encoded.

    ## Test

    - fabric_name and prefix_list_name are set
    - path returns expected URL with percent-encoded names

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet.path
    """
    with does_not_raise():
        instance = EpManageIpv4PrefixListsGet()
        instance.fabric_name = "SITE-1"
        instance.prefix_list_name = "PL-IPV4-BORDERS"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/SITE-1/ipv4PrefixLists/PL-IPV4-BORDERS"


def test_endpoints_ipv4_prefix_lists_00050():
    """
    # Summary

    Verify path URL-encodes special characters in fabric_name and prefix_list_name.

    ## Test

    - Spaces and special chars are percent-encoded
    - Path is correctly formed

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet.path (quote with safe="")
    """
    with does_not_raise():
        instance = EpManageIpv4PrefixListsGet()
        instance.fabric_name = "SITE 1/2"
        instance.prefix_list_name = "PL-NAME?"
        result = instance.path
    # quote with safe="" encodes everything including / and ?
    assert "SITE%201%2F2" in result
    assert "PL-NAME%3F" in result


def test_endpoints_ipv4_prefix_lists_00060():
    """
    # Summary

    Verify EpManageIpv4PrefixListsListGet requires only fabric_name (no prefix_list_name).

    ## Test

    - fabric_name is set, prefix_list_name is not required
    - path ends with /ipv4PrefixLists (list endpoint)
    - verb is GET

    ## Classes and Methods

    - EpManageIpv4PrefixListsListGet.path / .verb
    """
    with does_not_raise():
        instance = EpManageIpv4PrefixListsListGet()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result.endswith("/ipv4PrefixLists")
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_ipv4_prefix_lists_00070():
    """
    # Summary

    Verify set_identifiers sets prefix_list_name.

    ## Test

    - set_identifiers("PL-IPV4-BORDERS") sets prefix_list_name

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet.set_identifiers()
    """
    with does_not_raise():
        instance = EpManageIpv4PrefixListsGet()
        instance.set_identifiers("PL-IPV4-BORDERS")
    assert instance.prefix_list_name == "PL-IPV4-BORDERS"


def test_endpoints_ipv4_prefix_lists_00080():
    """
    # Summary

    Verify EpManageIpv4PrefixListsPost, Put, Delete verbs.

    ## Test

    - Post verb is POST
    - Put verb is PUT
    - Delete verb is DELETE

    ## Classes and Methods

    - EpManageIpv4PrefixListsPost.verb
    - EpManageIpv4PrefixListsPut.verb
    - EpManageIpv4PrefixListsDelete.verb
    """
    post = EpManageIpv4PrefixListsPost()
    assert post.verb == HttpVerbEnum.POST
    assert post.class_name == "EpManageIpv4PrefixListsPost"

    put = EpManageIpv4PrefixListsPut()
    assert put.verb == HttpVerbEnum.PUT
    assert put.class_name == "EpManageIpv4PrefixListsPut"

    delete = EpManageIpv4PrefixListsDelete()
    assert delete.verb == HttpVerbEnum.DELETE
    assert delete.class_name == "EpManageIpv4PrefixListsDelete"


def test_endpoints_ipv4_prefix_lists_00090():
    """
    # Summary

    Verify EpManageIpv4PrefixListsBulkDelete requires fabric_name and uses POST to action endpoint.

    ## Test

    - fabric_name must be set
    - prefix_list_name is not required (action endpoint)
    - verb is POST (not DELETE)
    - path ends with /remove (action endpoint)

    ## Classes and Methods

    - EpManageIpv4PrefixListsBulkDelete.path / .verb
    """
    instance = EpManageIpv4PrefixListsBulkDelete()
    with pytest.raises(ValueError, match="fabric_name must be set"):
        _ = instance.path

    instance.fabric_name = "SITE1"
    path = instance.path
    assert "ipv4PrefixListActions/remove" in path
    assert instance.verb == HttpVerbEnum.POST


# =============================================================================
# Test: IPv6 Endpoints
# =============================================================================


def test_endpoints_ipv6_prefix_lists_00010():
    """
    # Summary

    Verify EpManageIpv6PrefixListsGet instantiation and basic properties.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageIpv6PrefixListsGet.__init__()
    - EpManageIpv6PrefixListsGet.verb
    """
    with does_not_raise():
        instance = EpManageIpv6PrefixListsGet()
    assert instance.class_name == "EpManageIpv6PrefixListsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_ipv6_prefix_lists_00020():
    """
    # Summary

    Verify IPv6 path uses ipv6PrefixLists endpoint.

    ## Test

    - path contains "ipv6PrefixLists" not "ipv4PrefixLists"

    ## Classes and Methods

    - EpManageIpv6PrefixListsGet.path
    """
    with does_not_raise():
        instance = EpManageIpv6PrefixListsGet()
        instance.fabric_name = "SITE1"
        instance.prefix_list_name = "PL-IPV6-DATACENTER"
        result = instance.path
    assert "/ipv6PrefixLists/" in result
    assert "/ipv4PrefixLists" not in result


def test_endpoints_ipv6_prefix_lists_00030():
    """
    # Summary

    Verify EpManageIpv6PrefixListsListGet requires only fabric_name.

    ## Test

    - fabric_name is set, prefix_list_name is not required
    - path ends with /ipv6PrefixLists

    ## Classes and Methods

    - EpManageIpv6PrefixListsListGet.path
    """
    with does_not_raise():
        instance = EpManageIpv6PrefixListsListGet()
        instance.fabric_name = "SITE1"
        result = instance.path
    assert result.endswith("/ipv6PrefixLists")


def test_endpoints_ipv6_prefix_lists_00040():
    """
    # Summary

    Verify EpManageIpv6PrefixListsBulkDelete uses POST verb to action endpoint.

    ## Test

    - verb is POST (action endpoint, not DELETE)
    - class_name is correct
    - path contains /ipv6PrefixListActions/remove

    ## Classes and Methods

    - EpManageIpv6PrefixListsBulkDelete.verb / .path
    """
    instance = EpManageIpv6PrefixListsBulkDelete()
    assert instance.verb == HttpVerbEnum.POST
    assert instance.class_name == "EpManageIpv6PrefixListsBulkDelete"
    
    instance.fabric_name = "SITE1"
    path = instance.path
    assert "ipv6PrefixListActions/remove" in path


# =============================================================================
# Test: Query Parameters
# =============================================================================


def test_endpoints_prefix_lists_00050():
    """
    # Summary

    Verify list endpoint accepts optional query parameters (cluster_name, filter, max, offset, sort).

    ## Test

    - endpoint_params can be set with query parameters
    - path includes query string when params are present

    ## Classes and Methods

    - EpManageIpv4PrefixListsListGet.endpoint_params
    - EpManageIpv4PrefixListsListGet.path (with query string)
    """
    with does_not_raise():
        instance = EpManageIpv4PrefixListsListGet()
        instance.fabric_name = "SITE1"
        instance.endpoint_params.cluster_name = "CLUSTER-1"
        instance.endpoint_params.filter = "name=PL-*"
        instance.endpoint_params.max = 100
        path = instance.path
    # Query string should be present
    assert "?" in path
    assert "clusterName=CLUSTER-1" in path or "cluster_name=CLUSTER-1" in path


# =============================================================================
# Test: Mixin Composition
# =============================================================================


def test_endpoints_prefix_lists_00060():
    """
    # Summary

    Verify FabricNameMixin is properly composed.

    ## Test

    - Endpoints inherit from FabricNameMixin
    - fabric_name attribute is available and enforced

    ## Classes and Methods

    - EpManageIpv4PrefixListsGet (inherits FabricNameMixin)
    """
    instance = EpManageIpv4PrefixListsGet()
    # FabricNameMixin should provide fabric_name attribute
    assert hasattr(instance, "fabric_name")
    assert instance.fabric_name is None

    instance.fabric_name = "SITE1"
    assert instance.fabric_name == "SITE1"
