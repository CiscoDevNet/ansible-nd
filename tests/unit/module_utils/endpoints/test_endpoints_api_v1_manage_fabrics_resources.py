# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for ND Manage fabric resource endpoints."""

from __future__ import absolute_import, annotations, division, print_function

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_resources import (
    EpManageFabricResourcesActionsRemovePost,
    EpManageFabricResourcesGet,
    EpManageFabricResourcesPost,
    ResourcesQueryParams,
)


def test_resources_query_params_url_encode_reserved_values():
    """Endpoint-specific values cannot add query parameters or fragments."""
    params = ResourcesQueryParams(pool_name="pool /?#&%")

    assert params.to_query_string() == "poolName=pool%20%2F%3F%23%26%25"


def test_manage_fabric_resources_get_url_encodes_fabric_and_pool_names():
    """Fabric names remain one path segment and pool names remain one query value."""
    endpoint = EpManageFabricResourcesGet(fabric_name="DCI /?#&% fabric")
    endpoint.endpoint_params.pool_name = "DCI subnet pool"

    assert endpoint.path == ("/api/v1/manage/fabrics/DCI%20%2F%3F%23%26%25%20fabric/resources" "?poolName=DCI%20subnet%20pool")


@pytest.mark.parametrize(
    ("endpoint_class", "suffix"),
    [
        (EpManageFabricResourcesGet, ""),
        (EpManageFabricResourcesPost, ""),
        (EpManageFabricResourcesActionsRemovePost, "/actions/remove"),
    ],
)
def test_manage_fabric_resource_paths_url_encode_fabric_name(endpoint_class, suffix):
    """All resource operations share the encoded fabric resource base path."""
    endpoint = endpoint_class(fabric_name="fabric /?#&%")

    assert endpoint.path == f"/api/v1/manage/fabrics/fabric%20%2F%3F%23%26%25/resources{suffix}"
