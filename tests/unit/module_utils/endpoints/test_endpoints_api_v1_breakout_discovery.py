"""Breakout action and filtered discovery endpoint contracts."""

from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesBreakout,
    EpManageInterfacesSummaryGet,
    ManageInterfacesSummaryEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.query_params import LuceneQueryParams
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import EpManageSwitchesListGet
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@pytest.mark.parametrize("endpoint", [EpManageInterfacesBreakout, EpManageInterfacesSummaryGet])
def test_new_endpoints_require_fabric(endpoint):
    with pytest.raises(ValueError, match="fabric_name must be set"):
        _ = endpoint().path


def test_breakout_action_encodes_fabric_and_uses_post():
    endpoint = EpManageInterfacesBreakout(fabric_name="fab /one")
    assert endpoint.path == "/api/v1/manage/fabrics/fab%20%2Fone/interfaceActions/breakout"
    assert endpoint.verb == HttpVerbEnum.POST
    assert endpoint.class_name == "EpManageInterfacesBreakout"


def test_summary_has_no_query_by_default():
    endpoint = EpManageInterfacesSummaryGet(fabric_name="fab1")
    assert endpoint.path == "/api/v1/manage/fabrics/fab1/interfacesSummary"
    assert endpoint.verb == HttpVerbEnum.GET


def test_summary_builds_exact_scoped_encoded_query():
    endpoint = EpManageInterfacesSummaryGet(fabric_name="fab1")
    endpoint.endpoint_params = ManageInterfacesSummaryEndpointParams(
        switch_id="FDO123", include_all=True, filter="interfaceName:*Ethernet1/50*", max=1000, offset=0
    )
    assert parse_qs(urlsplit(endpoint.path).query) == {
        "switchId": ["FDO123"],
        "includeAll": ["true"],
        "filter": ["interfaceName:*Ethernet1/50*"],
        "max": ["1000"],
        "offset": ["0"],
    }


def test_false_include_all_is_not_omitted():
    endpoint = EpManageInterfacesSummaryGet(fabric_name="fab1")
    endpoint.endpoint_params.include_all = False
    assert parse_qs(urlsplit(endpoint.path).query) == {"includeAll": ["false"]}


def test_switch_list_exposes_filtered_pagination_without_legacy_query_changes():
    endpoint = EpManageSwitchesListGet(fabric_name="fab1")
    assert endpoint.path == "/api/v1/manage/fabrics/fab1/switches"
    endpoint.lucene_params = LuceneQueryParams(filter="fabricManagementIp:192.0.2.1", max=1000, offset=0)
    assert parse_qs(urlsplit(endpoint.path).query) == {"filter": ["fabricManagementIp:192.0.2.1"], "max": ["1000"], "offset": ["0"]}


@pytest.mark.parametrize(
    "params, values",
    [
        (ManageInterfacesSummaryEndpointParams, {"max": 0}),
        (ManageInterfacesSummaryEndpointParams, {"offset": -1}),
        (ManageInterfacesSummaryEndpointParams, {"filter": ""}),
        (LuceneQueryParams, {"max": 0}),
        (LuceneQueryParams, {"offset": -1}),
    ],
)
def test_discovery_query_params_validate_values(params, values):
    with pytest.raises(ValueError):
        params(**values)
