# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ep_api_v1_infra_clusterhealth.py

Tests the ND Infra ClusterHealth endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.infra_clusterhealth import (
    ClusterHealthConfigEndpointParams,
    ClusterHealthStatusEndpointParams,
    EpInfraClusterhealthConfigGet,
    EpInfraClusterhealthStatusGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: ClusterHealthConfigEndpointParams
# =============================================================================


def test_ep_clusterhealth_00010():
    """
    # Summary

    Verify ClusterHealthConfigEndpointParams default values

    ## Test

    - cluster_name defaults to None

    ## Classes and Methods

    - ClusterHealthConfigEndpointParams.__init__()
    """
    with does_not_raise():
        params = ClusterHealthConfigEndpointParams()
    assert params.cluster_name is None


def test_ep_clusterhealth_00020():
    """
    # Summary

    Verify ClusterHealthConfigEndpointParams cluster_name can be set

    ## Test

    - cluster_name can be set to a string value

    ## Classes and Methods

    - ClusterHealthConfigEndpointParams.__init__()
    """
    with does_not_raise():
        params = ClusterHealthConfigEndpointParams(cluster_name="my-cluster")
    assert params.cluster_name == "my-cluster"


def test_ep_clusterhealth_00030():
    """
    # Summary

    Verify ClusterHealthConfigEndpointParams generates correct query string

    ## Test

    - to_query_string() returns correct format with cluster_name

    ## Classes and Methods

    - ClusterHealthConfigEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ClusterHealthConfigEndpointParams(cluster_name="test-cluster")
        result = params.to_query_string()
    assert result == "clusterName=test-cluster"


def test_ep_clusterhealth_00040():
    """
    # Summary

    Verify ClusterHealthConfigEndpointParams empty query string

    ## Test

    - to_query_string() returns empty string when no params set

    ## Classes and Methods

    - ClusterHealthConfigEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ClusterHealthConfigEndpointParams()
        result = params.to_query_string()
    assert result == ""


# =============================================================================
# Test: ClusterHealthStatusEndpointParams
# =============================================================================


def test_ep_clusterhealth_00100():
    """
    # Summary

    Verify ClusterHealthStatusEndpointParams default values

    ## Test

    - All parameters default to None

    ## Classes and Methods

    - ClusterHealthStatusEndpointParams.__init__()
    """
    with does_not_raise():
        params = ClusterHealthStatusEndpointParams()
    assert params.cluster_name is None
    assert params.health_category is None
    assert params.node_name is None


def test_ep_clusterhealth_00110():
    """
    # Summary

    Verify ClusterHealthStatusEndpointParams all params can be set

    ## Test

    - All three parameters can be set

    ## Classes and Methods

    - ClusterHealthStatusEndpointParams.__init__()
    """
    with does_not_raise():
        params = ClusterHealthStatusEndpointParams(cluster_name="cluster1", health_category="cpu", node_name="node1")
    assert params.cluster_name == "cluster1"
    assert params.health_category == "cpu"
    assert params.node_name == "node1"


def test_ep_clusterhealth_00120():
    """
    # Summary

    Verify ClusterHealthStatusEndpointParams query string with all params

    ## Test

    - to_query_string() returns correct format with all parameters

    ## Classes and Methods

    - ClusterHealthStatusEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ClusterHealthStatusEndpointParams(cluster_name="foo", health_category="bar", node_name="baz")
        result = params.to_query_string()
    assert result == "clusterName=foo&healthCategory=bar&nodeName=baz"


def test_ep_clusterhealth_00130():
    """
    # Summary

    Verify ClusterHealthStatusEndpointParams query string with partial params

    ## Test

    - to_query_string() only includes set parameters

    ## Classes and Methods

    - ClusterHealthStatusEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ClusterHealthStatusEndpointParams(cluster_name="foo", node_name="baz")
        result = params.to_query_string()
    assert result == "clusterName=foo&nodeName=baz"


# =============================================================================
# Test: EpInfraClusterhealthConfigGet
# =============================================================================


def test_ep_clusterhealth_00200():
    """
    # Summary

    Verify EpInfraClusterhealthConfigGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpInfraClusterhealthConfigGet.__init__()
    - EpInfraClusterhealthConfigGet.verb
    - EpInfraClusterhealthConfigGet.class_name
    """
    with does_not_raise():
        instance = EpInfraClusterhealthConfigGet()
    assert instance.class_name == "EpInfraClusterhealthConfigGet"
    assert instance.verb == HttpVerbEnum.GET


def test_ep_clusterhealth_00210():
    """
    # Summary

    Verify EpInfraClusterhealthConfigGet path without params

    ## Test

    - path returns base path when no query params are set

    ## Classes and Methods

    - EpInfraClusterhealthConfigGet.path
    """
    with does_not_raise():
        instance = EpInfraClusterhealthConfigGet()
        result = instance.path
    assert result == "/api/v1/infra/clusterhealth/config"


def test_ep_clusterhealth_00220():
    """
    # Summary

    Verify EpInfraClusterhealthConfigGet path with cluster_name

    ## Test

    - path includes query string when cluster_name is set

    ## Classes and Methods

    - EpInfraClusterhealthConfigGet.path
    - EpInfraClusterhealthConfigGet.endpoint_params
    """
    with does_not_raise():
        instance = EpInfraClusterhealthConfigGet()
        instance.endpoint_params.cluster_name = "my-cluster"
        result = instance.path
    assert result == "/api/v1/infra/clusterhealth/config?clusterName=my-cluster"


def test_ep_clusterhealth_00230():
    """
    # Summary

    Verify EpInfraClusterhealthConfigGet params at instantiation

    ## Test

    - endpoint_params can be provided during instantiation

    ## Classes and Methods

    - EpInfraClusterhealthConfigGet.__init__()
    """
    with does_not_raise():
        params = ClusterHealthConfigEndpointParams(cluster_name="test-cluster")
        instance = EpInfraClusterhealthConfigGet(endpoint_params=params)
    assert instance.endpoint_params.cluster_name == "test-cluster"
    assert instance.path == "/api/v1/infra/clusterhealth/config?clusterName=test-cluster"


# =============================================================================
# Test: EpInfraClusterhealthStatusGet
# =============================================================================


def test_ep_clusterhealth_00300():
    """
    # Summary

    Verify EpInfraClusterhealthStatusGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpInfraClusterhealthStatusGet.__init__()
    - EpInfraClusterhealthStatusGet.verb
    - EpInfraClusterhealthStatusGet.class_name
    """
    with does_not_raise():
        instance = EpInfraClusterhealthStatusGet()
    assert instance.class_name == "EpInfraClusterhealthStatusGet"
    assert instance.verb == HttpVerbEnum.GET


def test_ep_clusterhealth_00310():
    """
    # Summary

    Verify EpInfraClusterhealthStatusGet path without params

    ## Test

    - path returns base path when no query params are set

    ## Classes and Methods

    - EpInfraClusterhealthStatusGet.path
    """
    with does_not_raise():
        instance = EpInfraClusterhealthStatusGet()
        result = instance.path
    assert result == "/api/v1/infra/clusterhealth/status"


def test_ep_clusterhealth_00320():
    """
    # Summary

    Verify EpInfraClusterhealthStatusGet path with single param

    ## Test

    - path includes query string with cluster_name

    ## Classes and Methods

    - EpInfraClusterhealthStatusGet.path
    - EpInfraClusterhealthStatusGet.endpoint_params
    """
    with does_not_raise():
        instance = EpInfraClusterhealthStatusGet()
        instance.endpoint_params.cluster_name = "foo"
        result = instance.path
    assert result == "/api/v1/infra/clusterhealth/status?clusterName=foo"


def test_ep_clusterhealth_00330():
    """
    # Summary

    Verify EpInfraClusterhealthStatusGet path with all params

    ## Test

    - path includes query string with all parameters

    ## Classes and Methods

    - EpInfraClusterhealthStatusGet.path
    - EpInfraClusterhealthStatusGet.endpoint_params
    """
    with does_not_raise():
        instance = EpInfraClusterhealthStatusGet()
        instance.endpoint_params.cluster_name = "foo"
        instance.endpoint_params.health_category = "bar"
        instance.endpoint_params.node_name = "baz"
        result = instance.path
    assert result == "/api/v1/infra/clusterhealth/status?clusterName=foo&healthCategory=bar&nodeName=baz"


def test_ep_clusterhealth_00340():
    """
    # Summary

    Verify EpInfraClusterhealthStatusGet with partial params

    ## Test

    - path only includes set parameters in query string

    ## Classes and Methods

    - EpInfraClusterhealthStatusGet.path
    """
    with does_not_raise():
        instance = EpInfraClusterhealthStatusGet()
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.node_name = "node1"
        result = instance.path
    assert result == "/api/v1/infra/clusterhealth/status?clusterName=cluster1&nodeName=node1"


# =============================================================================
# Test: Pydantic validation
# =============================================================================


def test_ep_clusterhealth_00400():
    """
    # Summary

    Verify Pydantic validation for empty string

    ## Test

    - Empty string is rejected for cluster_name (min_length=1)

    ## Classes and Methods

    - ClusterHealthConfigEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        ClusterHealthConfigEndpointParams(cluster_name="")


def test_ep_clusterhealth_00410():
    """
    # Summary

    Verify parameters can be modified after instantiation

    ## Test

    - endpoint_params can be changed after object creation

    ## Classes and Methods

    - EpInfraClusterhealthConfigGet.endpoint_params
    """
    with does_not_raise():
        instance = EpInfraClusterhealthConfigGet()
        assert instance.path == "/api/v1/infra/clusterhealth/config"

        instance.endpoint_params.cluster_name = "new-cluster"
        assert instance.path == "/api/v1/infra/clusterhealth/config?clusterName=new-cluster"


def test_ep_clusterhealth_00420():
    """
    # Summary

    Verify snake_case to camelCase conversion

    ## Test

    - cluster_name converts to clusterName in query string
    - health_category converts to healthCategory
    - node_name converts to nodeName

    ## Classes and Methods

    - ClusterHealthStatusEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = ClusterHealthStatusEndpointParams(cluster_name="test", health_category="cpu", node_name="node1")
        result = params.to_query_string()
    # Verify camelCase conversion
    assert "clusterName=" in result
    assert "healthCategory=" in result
    assert "nodeName=" in result
    # Verify no snake_case
    assert "cluster_name" not in result
    assert "health_category" not in result
    assert "node_name" not in result
