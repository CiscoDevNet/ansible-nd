# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for endpoints/v1/manage/manage_route_maps.py.

Tests route-map endpoint path construction, required path parameters, query parameters, and
percent-encoding of dynamic fabric / route-map path segments.
"""

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_route_maps import (
    EpManageRouteMapsBulkDelete,
    EpManageRouteMapsDelete,
    EpManageRouteMapsGet,
    EpManageRouteMapsListGet,
    EpManageRouteMapsPost,
    EpManageRouteMapsPut,
    RouteMapsEndpointParams,
    RouteMapsListEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_manage_route_maps_endpoint_00010() -> None:
    """
    # Summary

    Verify the collection list endpoint instantiates and exposes GET.

    ## Classes and Methods

    - EpManageRouteMapsListGet.__init__()
    - EpManageRouteMapsListGet.verb
    """
    with does_not_raise():
        instance = EpManageRouteMapsListGet()

    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None


def test_manage_route_maps_endpoint_00020() -> None:
    """
    # Summary

    Verify collection-level endpoints require fabric_name before path generation.

    ## Classes and Methods

    - EpManageRouteMapsListGet.path
    """
    instance = EpManageRouteMapsListGet()

    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_manage_route_maps_endpoint_00030() -> None:
    """
    # Summary

    Verify the list endpoint returns the routeMaps collection URL.

    ## Classes and Methods

    - EpManageRouteMapsListGet.path
    """
    instance = EpManageRouteMapsListGet()
    instance.fabric_name = "SITE1"

    assert instance.path == "/api/v1/manage/fabrics/SITE1/routeMaps"


def test_manage_route_maps_endpoint_00040() -> None:
    """
    # Summary

    Verify fabric_name is percent-encoded in collection paths.

    ## Classes and Methods

    - EpManageRouteMapsListGet.path
    """
    instance = EpManageRouteMapsListGet()
    instance.fabric_name = "fab/odd"

    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/routeMaps"


def test_manage_route_maps_endpoint_00050() -> None:
    """
    # Summary

    Verify list query params are appended to the collection URL.

    ## Classes and Methods

    - RouteMapsListEndpointParams.to_query_string()
    - EpManageRouteMapsListGet.path
    """
    instance = EpManageRouteMapsListGet(
        endpoint_params=RouteMapsListEndpointParams(cluster_name="cluster1"),
        lucene_params=LuceneQueryParams(max=50, offset=10, sort="name:desc"),
    )
    instance.fabric_name = "SITE1"

    assert instance.path == "/api/v1/manage/fabrics/SITE1/routeMaps?clusterName=cluster1&max=50&offset=10&sort=name%3Adesc"


def test_manage_route_maps_endpoint_00060() -> None:
    """
    # Summary

    Verify Lucene filters are composed separately from endpoint query params.

    ## Classes and Methods

    - LuceneQueryParams.to_query_string()
    - EpManageRouteMapsListGet.path
    """
    instance = EpManageRouteMapsListGet(
        endpoint_params=RouteMapsListEndpointParams(cluster_name="cluster1"),
        lucene_params=LuceneQueryParams(filter="name:RM SALES", max=100),
    )
    instance.fabric_name = "SITE1"

    assert instance.path == "/api/v1/manage/fabrics/SITE1/routeMaps?clusterName=cluster1&filter=name:RM%20SALES&max=100"


@pytest.mark.parametrize(
    "lucene_config, error",
    [
        ({"max": 10001}, "10000"),
        ({"sort": "name:sideways"}, "Sort direction"),
    ],
    ids=["max-upper-bound", "sort-direction"],
)
def test_manage_route_maps_endpoint_00070(lucene_config: dict, error: str) -> None:
    """
    # Summary

    Verify list endpoints use shared Lucene query parameter validation.

    ## Classes and Methods

    - LuceneQueryParams.model_validate()
    - EpManageRouteMapsListGet.__init__()
    """
    with pytest.raises(ValueError, match=error):
        EpManageRouteMapsListGet(lucene_params=LuceneQueryParams(**lucene_config))


def test_manage_route_maps_endpoint_00100() -> None:
    """
    # Summary

    Verify per-name endpoints require route_map_name before path generation.

    ## Classes and Methods

    - EpManageRouteMapsGet.path
    """
    instance = EpManageRouteMapsGet()
    instance.fabric_name = "SITE1"

    with pytest.raises(ValueError, match="route_map_name must be set"):
        result = instance.path  # pylint: disable=unused-variable


def test_manage_route_maps_endpoint_00110() -> None:
    """
    # Summary

    Verify the per-name GET path and identifier setter.

    ## Classes and Methods

    - EpManageRouteMapsGet.set_identifiers()
    - EpManageRouteMapsGet.path
    """
    instance = EpManageRouteMapsGet()
    instance.fabric_name = "SITE1"
    instance.set_identifiers("RM1")

    assert instance.path == "/api/v1/manage/fabrics/SITE1/routeMaps/RM1"


def test_manage_route_maps_endpoint_00120() -> None:
    """
    # Summary

    Verify fabric_name and route_map_name are percent-encoded in per-name paths.

    ## Classes and Methods

    - EpManageRouteMapsGet.path
    """
    instance = EpManageRouteMapsGet()
    instance.fabric_name = "fab/odd"
    instance.set_identifiers("tenant~rm/one")

    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/routeMaps/tenant~rm%2Fone"


def test_manage_route_maps_endpoint_00200() -> None:
    """
    # Summary

    Verify POST uses the collection path and POST verb.

    ## Classes and Methods

    - EpManageRouteMapsPost.path
    - EpManageRouteMapsPost.verb
    """
    instance = EpManageRouteMapsPost()
    instance.fabric_name = "SITE1"

    assert instance.verb == HttpVerbEnum.POST
    assert instance.path == "/api/v1/manage/fabrics/SITE1/routeMaps"


def test_manage_route_maps_endpoint_00210() -> None:
    """
    # Summary

    Verify PUT and DELETE paths use the encoded per-name route map URL.

    ## Classes and Methods

    - EpManageRouteMapsPut.path
    - EpManageRouteMapsDelete.path
    """
    for endpoint_class, expected_verb in ((EpManageRouteMapsPut, HttpVerbEnum.PUT), (EpManageRouteMapsDelete, HttpVerbEnum.DELETE)):
        instance = endpoint_class()
        instance.fabric_name = "fab/odd"
        instance.set_identifiers("rm/one")

        assert instance.verb == expected_verb
        assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/routeMaps/rm%2Fone"


def test_manage_route_maps_endpoint_00300() -> None:
    """
    # Summary

    Verify the bulk-delete action endpoint path, verb, encoding, and query params.

    ## Classes and Methods

    - EpManageRouteMapsBulkDelete.path
    - RouteMapsEndpointParams.to_query_string()
    """
    instance = EpManageRouteMapsBulkDelete(endpoint_params=RouteMapsEndpointParams(cluster_name="cluster1"))
    instance.fabric_name = "fab/odd"

    assert instance.verb == HttpVerbEnum.POST
    assert instance.path == "/api/v1/manage/fabrics/fab%2Fodd/routeMapActions/remove?clusterName=cluster1"


def test_manage_route_maps_endpoint_00310() -> None:
    """
    # Summary

    Verify the bulk-delete action endpoint requires fabric_name.

    ## Classes and Methods

    - EpManageRouteMapsBulkDelete.path
    """
    instance = EpManageRouteMapsBulkDelete()

    with pytest.raises(ValueError, match="fabric_name must be set"):
        result = instance.path  # pylint: disable=unused-variable
