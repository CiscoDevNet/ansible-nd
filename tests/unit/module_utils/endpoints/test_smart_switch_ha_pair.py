# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Endpoint contracts from the nd-4.3.1-manage catalog snapshot."""

from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import EpFabricConfigSavePost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import EpFabricDeployPost
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_smart_switches import (
    EpManageSmartSwitchHaRecommendationsGet,
    EpManageSmartSwitchesHaPairPost,
    EpManageSmartSwitchesHaPairsGet,
    EpManageSmartSwitchesHaUnpairPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

# HA paths and HTTP methods


@pytest.mark.parametrize(
    "endpoint_type, suffix, verb",
    [
        (EpManageSmartSwitchesHaPairsGet, "haPairs", HttpVerbEnum.GET),
        (EpManageSmartSwitchesHaPairPost, "actions/haPair", HttpVerbEnum.POST),
        (EpManageSmartSwitchesHaUnpairPost, "actions/haUnpair", HttpVerbEnum.POST),
        (EpManageSmartSwitchHaRecommendationsGet, "A%2FB/haPairRecommendations", HttpVerbEnum.GET),
    ],
)
def test_manage_ha_paths_methods_and_encoded_routing(endpoint_type, suffix, verb):
    endpoint = endpoint_type(fabric_name="a/b c")
    if endpoint_type is EpManageSmartSwitchHaRecommendationsGet:
        endpoint.set_identifiers("A/B")
    base = f"/api/v1/manage/fabrics/a%2Fb%20c/smartSwitches/{suffix}"
    assert endpoint.path == base
    endpoint.endpoint_params.cluster_name = "site / &+"
    assert endpoint.path == f"{base}?clusterName=site%20%2F%20%26%2B"
    assert endpoint.verb == verb
    assert endpoint.class_name == endpoint_type.__name__
    assert endpoint.min_controller_version == "4.3.1"


@pytest.mark.parametrize(
    "endpoint_type, scope, missing_field",
    [
        pytest.param(EpManageSmartSwitchesHaPairsGet, {}, "fabric_name", id="missing-fabric"),
        pytest.param(EpManageSmartSwitchHaRecommendationsGet, {"fabric_name": "site"}, "switch_id", id="missing-switch"),
    ],
)
def test_ha_paths_require_scope_identifiers(endpoint_type, scope, missing_field):
    endpoint = endpoint_type(**scope)
    with pytest.raises(ValueError, match=missing_field):
        _path = endpoint.path


# HA inventory query parameters


def test_list_exposes_pagination_and_query_parameters():
    endpoint = EpManageSmartSwitchesHaPairsGet(fabric_name="site")
    endpoint.endpoint_params.max = 50
    endpoint.endpoint_params.offset = 0
    endpoint.endpoint_params.filter = "haPaired:paired AND id:A"
    endpoint.endpoint_params.sort = "id:asc,haPaired:desc"
    assert parse_qs(urlsplit(endpoint.path).query) == {
        "max": ["50"],
        "offset": ["0"],
        "filter": ["haPaired:paired AND id:A"],
        "sort": ["id:asc,haPaired:desc"],
    }


@pytest.mark.parametrize("field, invalid_value", [("max", 0), ("offset", -1), ("sort", ""), ("filter", "")])
def test_ha_list_rejects_invalid_query_assignments(field, invalid_value):
    endpoint = EpManageSmartSwitchesHaPairsGet(fabric_name="site")
    with pytest.raises(ValidationError, match=field):
        setattr(endpoint.endpoint_params, field, invalid_value)


# Cluster routing for HA and fabric actions


@pytest.mark.parametrize("endpoint_type", [EpManageSmartSwitchesHaPairsGet, EpManageSmartSwitchesHaPairPost, EpFabricConfigSavePost, EpFabricDeployPost])
def test_ha_and_fabric_action_queries_reject_empty_cluster_assignments(endpoint_type):
    endpoint = endpoint_type(fabric_name="site")
    with pytest.raises(ValidationError, match="cluster_name"):
        endpoint.endpoint_params.cluster_name = ""


# Fabric save and deploy query serialization


@pytest.mark.parametrize("endpoint_type, suffix", [(EpFabricConfigSavePost, "configSave"), (EpFabricDeployPost, "deploy")])
def test_fabric_post_actions_keep_existing_paths_and_support_cluster(endpoint_type, suffix):
    endpoint = endpoint_type(fabric_name="a/b")
    base = f"/api/v1/manage/fabrics/a%2Fb/actions/{suffix}"
    assert endpoint.path == base
    endpoint.endpoint_params.cluster_name = "remote+west/east"
    assert endpoint.path == f"{base}?clusterName=remote%2Bwest%2Feast"


def test_routed_deploy_serializes_the_fabric_group_flag_only_when_enabled():
    endpoint = EpFabricDeployPost(fabric_name="site")
    endpoint.endpoint_params.cluster_name = "remote+west/east"
    endpoint.endpoint_params.incl_all_fabric_groups_switches = True
    assert parse_qs(urlsplit(endpoint.path).query) == {"clusterName": ["remote+west/east"], "inclAllFabricGroupsSwitches": ["true"]}
    endpoint.endpoint_params.incl_all_fabric_groups_switches = False
    assert parse_qs(urlsplit(endpoint.path).query) == {"clusterName": ["remote+west/east"]}
