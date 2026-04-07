# Copyright: (c) 2026, Sivakami Sivaraman <sivakasi@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for vPC pair endpoint models under plugins/module_utils/endpoints/v1/manage.

Mirrors the style used in PR198 endpoint unit tests.
"""

from __future__ import annotations


from urllib.parse import parse_qsl, urlsplit

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair import (
    EpVpcPairGet,
    EpVpcPairPut,
    VpcPairGetEndpointParams,
    VpcPairPutEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_consistency import (
    EpVpcPairConsistencyGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_overview import (
    EpVpcPairOverviewGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_recommendation import (
    EpVpcPairRecommendationGet,
    VpcPairRecommendationEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_vpc_pair_support import (
    EpVpcPairSupportGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpFabricSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vpc_pairs import (
    EpVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import (
    LuceneQueryParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def _assert_path_with_query(path: str, expected_base_path: str, expected_query: dict[str, str]) -> None:
    parsed = urlsplit(path)
    assert parsed.path == expected_base_path
    assert dict(parse_qsl(parsed.query, keep_blank_values=True)) == expected_query


# =============================================================================
# Test: manage_fabrics_switches_vpc_pair.py
# =============================================================================


def test_endpoints_api_v1_manage_vpc_pair_00010() -> None:
    """Verify VpcPairGetEndpointParams query serialization."""
    with does_not_raise():
        params = VpcPairGetEndpointParams(from_cluster="cluster-a")
        result = params.to_query_string()
    assert result == "fromCluster=cluster-a"


def test_endpoints_api_v1_manage_vpc_pair_00020() -> None:
    """Verify VpcPairPutEndpointParams query serialization."""
    with does_not_raise():
        params = VpcPairPutEndpointParams(from_cluster="cluster-a", ticket_id="CHG123")
        result = params.to_query_string()
    parsed = dict(parse_qsl(result, keep_blank_values=True))
    assert parsed == {"fromCluster": "cluster-a", "ticketId": "CHG123"}


def test_endpoints_api_v1_manage_vpc_pair_00030() -> None:
    """Verify EpVpcPairGet basics."""
    with does_not_raise():
        instance = EpVpcPairGet()
    assert instance.class_name == "EpVpcPairGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_vpc_pair_00040() -> None:
    """Verify EpVpcPairGet path raises when required path fields are missing."""
    instance = EpVpcPairGet()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_vpc_pair_00050() -> None:
    """Verify EpVpcPairGet path without query params."""
    with does_not_raise():
        instance = EpVpcPairGet(fabric_name="fab1", switch_id="SN01")
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPair"


def test_endpoints_api_v1_manage_vpc_pair_00060() -> None:
    """Verify EpVpcPairGet path with query params."""
    with does_not_raise():
        instance = EpVpcPairGet(fabric_name="fab1", switch_id="SN01")
        instance.endpoint_params.from_cluster = "cluster-a"
        result = instance.path
    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPair",
        {"fromCluster": "cluster-a"},
    )


def test_endpoints_api_v1_manage_vpc_pair_00070() -> None:
    """Verify EpVpcPairPut basics and query path."""
    with does_not_raise():
        instance = EpVpcPairPut(fabric_name="fab1", switch_id="SN01")
        instance.endpoint_params.from_cluster = "cluster-a"
        instance.endpoint_params.ticket_id = "CHG1"
        result = instance.path
    assert instance.class_name == "EpVpcPairPut"
    assert instance.verb == HttpVerbEnum.PUT
    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPair",
        {"fromCluster": "cluster-a", "ticketId": "CHG1"},
    )


# =============================================================================
# Test: manage_fabrics_switches_vpc_pair_consistency.py
# =============================================================================


def test_endpoints_api_v1_manage_vpc_pair_00100() -> None:
    """Verify EpVpcPairConsistencyGet basics and path."""
    with does_not_raise():
        instance = EpVpcPairConsistencyGet(fabric_name="fab1", switch_id="SN01")
        result = instance.path
    assert instance.class_name == "EpVpcPairConsistencyGet"
    assert instance.verb == HttpVerbEnum.GET
    assert result == "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPairConsistency"


def test_endpoints_api_v1_manage_vpc_pair_00110() -> None:
    """Verify EpVpcPairConsistencyGet query params."""
    with does_not_raise():
        instance = EpVpcPairConsistencyGet(fabric_name="fab1", switch_id="SN01")
        instance.endpoint_params.from_cluster = "cluster-a"
        result = instance.path
    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPairConsistency",
        {"fromCluster": "cluster-a"},
    )


# =============================================================================
# Test: manage_fabrics_switches_vpc_pair_overview.py
# =============================================================================


def test_endpoints_api_v1_manage_vpc_pair_00200() -> None:
    """Verify EpVpcPairOverviewGet query params."""
    with does_not_raise():
        instance = EpVpcPairOverviewGet(fabric_name="fab1", switch_id="SN01")
        instance.endpoint_params.from_cluster = "cluster-a"
        instance.endpoint_params.component_type = "health"
        result = instance.path
    assert instance.class_name == "EpVpcPairOverviewGet"
    assert instance.verb == HttpVerbEnum.GET
    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPairOverview",
        {"fromCluster": "cluster-a", "componentType": "health"},
    )


# =============================================================================
# Test: manage_fabrics_switches_vpc_pair_recommendation.py
# =============================================================================


def test_endpoints_api_v1_manage_vpc_pair_00300() -> None:
    """Verify recommendation params keep use_virtual_peer_link optional."""
    with does_not_raise():
        params = VpcPairRecommendationEndpointParams()
    assert params.use_virtual_peer_link is None
    assert params.to_query_string() == ""


def test_endpoints_api_v1_manage_vpc_pair_00310() -> None:
    """Verify EpVpcPairRecommendationGet path with optional useVirtualPeerLink."""
    with does_not_raise():
        instance = EpVpcPairRecommendationGet(fabric_name="fab1", switch_id="SN01")
        instance.endpoint_params.use_virtual_peer_link = True
        result = instance.path
    assert instance.class_name == "EpVpcPairRecommendationGet"
    assert instance.verb == HttpVerbEnum.GET
    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPairRecommendation",
        {"useVirtualPeerLink": "true"},
    )


# =============================================================================
# Test: manage_fabrics_switches_vpc_pair_support.py
# =============================================================================


def test_endpoints_api_v1_manage_vpc_pair_00400() -> None:
    """Verify EpVpcPairSupportGet query params."""
    with does_not_raise():
        instance = EpVpcPairSupportGet(fabric_name="fab1", switch_id="SN01")
        instance.endpoint_params.from_cluster = "cluster-a"
        instance.endpoint_params.component_type = "checkPairing"
        result = instance.path
    assert instance.class_name == "EpVpcPairSupportGet"
    assert instance.verb == HttpVerbEnum.GET
    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches/SN01/vpcPairSupport",
        {"fromCluster": "cluster-a", "componentType": "checkPairing"},
    )


# =============================================================================
# Test: manage_fabrics_vpc_pairs.py
# =============================================================================


def test_endpoints_api_v1_manage_vpc_pair_00500() -> None:
    """Verify EpVpcPairsListGet basics."""
    with does_not_raise():
        instance = EpVpcPairsListGet()
    assert instance.class_name == "EpVpcPairsListGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_vpc_pair_00510() -> None:
    """Verify EpVpcPairsListGet raises when fabric_name is missing."""
    instance = EpVpcPairsListGet()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_vpc_pair_00520() -> None:
    """Verify EpVpcPairsListGet full query serialization."""
    with does_not_raise():
        instance = EpVpcPairsListGet(fabric_name="fab1")
        instance.endpoint_params.from_cluster = "cluster-a"
        instance.lucene_params.filter = "switchId:SN01"
        instance.lucene_params.max = 50
        instance.lucene_params.offset = 10
        instance.lucene_params.sort = "switchId:asc"
        instance.endpoint_params.view = "discoveredPairs"
        result = instance.path

    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/vpcPairs",
        {
            "fromCluster": "cluster-a",
            "filter": "switchId:SN01",
            "max": "50",
            "offset": "10",
            "sort": "switchId:asc",
            "view": "discoveredPairs",
        },
    )


def test_endpoints_api_v1_manage_vpc_pair_00530() -> None:
    """Verify Lucene sort validation is enforced for vpcPairs list."""
    with pytest.raises(ValueError):
        EpVpcPairsListGet(
            fabric_name="fab1",
            lucene_params=LuceneQueryParams(sort="switchId:up"),
        )


def test_endpoints_api_v1_manage_vpc_pair_00540() -> None:
    """Verify EpFabricSwitchesGet query serialization via composite params."""
    with does_not_raise():
        instance = EpFabricSwitchesGet(fabric_name="fab1")
        instance.endpoint_params.from_cluster = "cluster-a"
        instance.endpoint_params.view = "default"
        instance.lucene_params.filter = "name:leaf*"
        instance.lucene_params.sort = "name:asc"
        result = instance.path

    _assert_path_with_query(
        result,
        "/api/v1/manage/fabrics/fab1/switches",
        {
            "fromCluster": "cluster-a",
            "view": "default",
            "filter": "name:leaf*",
            "sort": "name:asc",
        },
    )
