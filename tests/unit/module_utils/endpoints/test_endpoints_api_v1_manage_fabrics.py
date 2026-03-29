# Copyright: (c) 2026, Mike Wiebe (@mwiebe) <mwiebe@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics.py

Tests the ND Manage Fabrics endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics import (
    EpManageFabricsDelete,
    EpManageFabricsGet,
    EpManageFabricsListGet,
    EpManageFabricsPost,
    EpManageFabricsPut,
    EpManageFabricsSummaryGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: EpManageFabricsGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00010():
    """
    # Summary

    Verify EpManageFabricsGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricsGet.__init__()
    - EpManageFabricsGet.verb
    - EpManageFabricsGet.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsGet()
    assert instance.class_name == "EpApiV1ManageFabricsGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_00020():
    """
    # Summary

    Verify EpManageFabricsGet path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-fabric" when fabric_name is set

    ## Classes and Methods

    - EpManageFabricsGet.path
    - EpManageFabricsGet.fabric_name
    """
    with does_not_raise():
        instance = EpManageFabricsGet()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric"


def test_endpoints_api_v1_manage_fabrics_00030():
    """
    # Summary

    Verify EpManageFabricsGet path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError

    ## Classes and Methods

    - EpManageFabricsGet.path
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsGet()
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_00040():
    """
    # Summary

    Verify EpManageFabricsGet path with fabric_name and cluster_name query param

    ## Test

    - path includes clusterName query parameter when set

    ## Classes and Methods

    - EpManageFabricsGet.path
    - EpManageFabricsGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric?clusterName=cluster1"


# =============================================================================
# Test: EpManageFabricsListGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00100():
    """
    # Summary

    Verify EpManageFabricsListGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricsListGet.__init__()
    - EpManageFabricsListGet.verb
    - EpManageFabricsListGet.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsListGet()
    assert instance.class_name == "EpApiV1ManageFabricsListGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_00110():
    """
    # Summary

    Verify EpManageFabricsListGet path without fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics" when fabric_name is not set
      (no error since _require_fabric_name is False)

    ## Classes and Methods

    - EpManageFabricsListGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsListGet()
        result = instance.path
    assert result == "/api/v1/manage/fabrics"


def test_endpoints_api_v1_manage_fabrics_00120():
    """
    # Summary

    Verify EpManageFabricsListGet path with category and max query params

    ## Test

    - path includes category and max query parameters when set

    ## Classes and Methods

    - EpManageFabricsListGet.path
    - EpManageFabricsListGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsListGet()
        instance.endpoint_params.category = "fabric"
        instance.endpoint_params.max = 10
        result = instance.path
    assert "category=fabric" in result
    assert "max=10" in result
    assert result.startswith("/api/v1/manage/fabrics?")


def test_endpoints_api_v1_manage_fabrics_00130():
    """
    # Summary

    Verify EpManageFabricsListGet path with all query params

    ## Test

    - path includes all query parameters when set
      (cluster_name, category, filter, max, offset, sort)

    ## Classes and Methods

    - EpManageFabricsListGet.path
    - EpManageFabricsListGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsListGet()
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.category = "fabric"
        instance.endpoint_params.filter = "name:test"
        instance.endpoint_params.max = 25
        instance.endpoint_params.offset = 5
        instance.endpoint_params.sort = "name:desc"
        result = instance.path
    assert "clusterName=cluster1" in result
    assert "category=fabric" in result
    assert "max=25" in result
    assert "offset=5" in result
    assert "sort=name%3Adesc" in result or "sort=name:desc" in result
    assert result.startswith("/api/v1/manage/fabrics?")


def test_endpoints_api_v1_manage_fabrics_00140():
    """
    # Summary

    Verify EpManageFabricsListGet set_identifiers with None

    ## Test

    - set_identifiers(None) leaves fabric_name as None and path still works

    ## Classes and Methods

    - EpManageFabricsListGet.set_identifiers
    - EpManageFabricsListGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsListGet()
        instance.set_identifiers(None)
        result = instance.path
    assert instance.fabric_name is None
    assert result == "/api/v1/manage/fabrics"


def test_endpoints_api_v1_manage_fabrics_00150():
    """
    # Summary

    Verify Pydantic validation rejects max < 1

    ## Test

    - Setting max to 0 raises ValueError (ge=1 constraint)

    ## Classes and Methods

    - FabricsListEndpointParams.max
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsListGet()
        instance.endpoint_params = type(instance.endpoint_params)(max=0)


# =============================================================================
# Test: EpManageFabricsPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00200():
    """
    # Summary

    Verify EpManageFabricsPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsPost.__init__()
    - EpManageFabricsPost.verb
    - EpManageFabricsPost.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsPost()
    assert instance.class_name == "EpApiV1ManageFabricsPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_00210():
    """
    # Summary

    Verify EpManageFabricsPost path without fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics" when fabric_name is not set
      (no error since _require_fabric_name is False)

    ## Classes and Methods

    - EpManageFabricsPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsPost()
        result = instance.path
    assert result == "/api/v1/manage/fabrics"


def test_endpoints_api_v1_manage_fabrics_00220():
    """
    # Summary

    Verify EpManageFabricsPost path with cluster_name query param

    ## Test

    - path includes clusterName query parameter when set

    ## Classes and Methods

    - EpManageFabricsPost.path
    - EpManageFabricsPost.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsPost()
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics?clusterName=cluster1"


def test_endpoints_api_v1_manage_fabrics_00230():
    """
    # Summary

    Verify EpManageFabricsPost set_identifiers sets fabric_name

    ## Test

    - set_identifiers sets fabric_name (POST doesn't require it but allows it)

    ## Classes and Methods

    - EpManageFabricsPost.set_identifiers
    """
    with does_not_raise():
        instance = EpManageFabricsPost()
        instance.set_identifiers("test-fabric")
    assert instance.fabric_name == "test-fabric"


# =============================================================================
# Test: EpManageFabricsPut
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00300():
    """
    # Summary

    Verify EpManageFabricsPut basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is PUT

    ## Classes and Methods

    - EpManageFabricsPut.__init__()
    - EpManageFabricsPut.verb
    - EpManageFabricsPut.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsPut()
    assert instance.class_name == "EpApiV1ManageFabricsPut"
    assert instance.verb == HttpVerbEnum.PUT


def test_endpoints_api_v1_manage_fabrics_00310():
    """
    # Summary

    Verify EpManageFabricsPut path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-fabric" when fabric_name is set

    ## Classes and Methods

    - EpManageFabricsPut.path
    - EpManageFabricsPut.fabric_name
    """
    with does_not_raise():
        instance = EpManageFabricsPut()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric"


def test_endpoints_api_v1_manage_fabrics_00320():
    """
    # Summary

    Verify EpManageFabricsPut path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError

    ## Classes and Methods

    - EpManageFabricsPut.path
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsPut()
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_00340():
    """
    # Summary

    Verify EpManageFabricsPut path with fabric_name and cluster_name query param

    ## Test

    - path includes clusterName query parameter when set

    ## Classes and Methods

    - EpManageFabricsPut.path
    - EpManageFabricsPut.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsPut()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric?clusterName=cluster1"


# =============================================================================
# Test: EpManageFabricsDelete
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00400():
    """
    # Summary

    Verify EpManageFabricsDelete basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is DELETE

    ## Classes and Methods

    - EpManageFabricsDelete.__init__()
    - EpManageFabricsDelete.verb
    - EpManageFabricsDelete.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsDelete()
    assert instance.class_name == "EpApiV1ManageFabricsDelete"
    assert instance.verb == HttpVerbEnum.DELETE


def test_endpoints_api_v1_manage_fabrics_00410():
    """
    # Summary

    Verify EpManageFabricsDelete path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-fabric" when fabric_name is set

    ## Classes and Methods

    - EpManageFabricsDelete.path
    - EpManageFabricsDelete.fabric_name
    """
    with does_not_raise():
        instance = EpManageFabricsDelete()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric"


def test_endpoints_api_v1_manage_fabrics_00420():
    """
    # Summary

    Verify EpManageFabricsDelete path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError

    ## Classes and Methods

    - EpManageFabricsDelete.path
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsDelete()
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_00430():
    """
    # Summary

    Verify EpManageFabricsDelete path with fabric_name and cluster_name query param

    ## Test

    - path includes clusterName query parameter when set

    ## Classes and Methods

    - EpManageFabricsDelete.path
    - EpManageFabricsDelete.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsDelete()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric?clusterName=cluster1"


# =============================================================================
# Test: EpManageFabricsSummaryGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00500():
    """
    # Summary

    Verify EpManageFabricsSummaryGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricsSummaryGet.__init__()
    - EpManageFabricsSummaryGet.verb
    - EpManageFabricsSummaryGet.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsSummaryGet()
    assert instance.class_name == "EpApiV1ManageFabricsSummaryGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_00510():
    """
    # Summary

    Verify EpManageFabricsSummaryGet path with fabric_name

    ## Test

    - path returns "/api/v1/manage/fabrics/my-fabric/summary" when fabric_name is set

    ## Classes and Methods

    - EpManageFabricsSummaryGet.path
    - EpManageFabricsSummaryGet.fabric_name
    """
    with does_not_raise():
        instance = EpManageFabricsSummaryGet()
        instance.fabric_name = "my-fabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/summary"


def test_endpoints_api_v1_manage_fabrics_00520():
    """
    # Summary

    Verify EpManageFabricsSummaryGet path without fabric_name raises ValueError

    ## Test

    - Accessing path without setting fabric_name raises ValueError

    ## Classes and Methods

    - EpManageFabricsSummaryGet.path
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsSummaryGet()
        _ = instance.path


def test_endpoints_api_v1_manage_fabrics_00530():
    """
    # Summary

    Verify EpManageFabricsSummaryGet path with fabric_name and cluster_name query param

    ## Test

    - path includes clusterName query parameter when set

    ## Classes and Methods

    - EpManageFabricsSummaryGet.path
    - EpManageFabricsSummaryGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageFabricsSummaryGet()
        instance.fabric_name = "my-fabric"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/my-fabric/summary?clusterName=cluster1"


# =============================================================================
# Test: All HTTP methods on same endpoint
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00600():
    """
    # Summary

    Verify all HTTP verbs produce correct paths and verbs for the same fabric_name

    ## Test

    - GET, POST, PUT, DELETE all return correct paths for same fabric_name
    - Each endpoint returns the correct HTTP verb

    ## Classes and Methods

    - EpManageFabricsGet
    - EpManageFabricsPost
    - EpManageFabricsPut
    - EpManageFabricsDelete
    """
    fabric_name = "test-fabric"

    with does_not_raise():
        get_ep = EpManageFabricsGet()
        get_ep.fabric_name = fabric_name

        post_ep = EpManageFabricsPost()
        # POST is collection-level, but fabric_name can still be set
        post_ep.fabric_name = fabric_name

        put_ep = EpManageFabricsPut()
        put_ep.fabric_name = fabric_name

        delete_ep = EpManageFabricsDelete()
        delete_ep.fabric_name = fabric_name

    expected_path = "/api/v1/manage/fabrics/test-fabric"
    assert get_ep.path == expected_path
    assert post_ep.path == expected_path
    assert put_ep.path == expected_path
    assert delete_ep.path == expected_path

    assert get_ep.verb == HttpVerbEnum.GET
    assert post_ep.verb == HttpVerbEnum.POST
    assert put_ep.verb == HttpVerbEnum.PUT
    assert delete_ep.verb == HttpVerbEnum.DELETE


# =============================================================================
# Test: Pydantic validation
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_00610():
    """
    # Summary

    Verify Pydantic validation rejects empty string for fabric_name

    ## Test

    - Empty string is rejected for fabric_name (min_length=1)

    ## Classes and Methods

    - EpManageFabricsGet.__init__()
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsGet()
        instance.fabric_name = ""


def test_endpoints_api_v1_manage_fabrics_00620():
    """
    # Summary

    Verify Pydantic validation rejects fabric_name exceeding max_length

    ## Test

    - fabric_name longer than 64 characters is rejected (max_length=64)

    ## Classes and Methods

    - EpManageFabricsGet.__init__()
    """
    with pytest.raises(ValueError):
        instance = EpManageFabricsGet()
        instance.fabric_name = "a" * 65
