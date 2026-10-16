# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Smart Switch action paths retain exact, encoded scope identifiers."""

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_smart_switches import (
    EpManageSmartSwitchesOnboardPost,
    EpManageSmartSwitchesDeboardDelete,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


def test_onboard_path_and_query_encoding():
    endpoint = EpManageSmartSwitchesOnboardPost(fabric_name="fab/a &b")
    endpoint.endpoint_params.cluster_name = "cluster+a"
    assert endpoint.path == "/api/v1/manage/fabrics/fab%2Fa%20%26b/smartSwitches/actions/updateSecureTenant?clusterName=cluster%2Ba"
    assert endpoint.verb == HttpVerbEnum.POST
    assert "ticket_id" not in type(endpoint.endpoint_params).model_fields


def test_bulk_deboard_path_and_query_encoding():
    from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_smart_switches import EpManageSmartSwitchesDeboardPost

    endpoint = EpManageSmartSwitchesDeboardPost(fabric_name="fab/a &b")
    endpoint.endpoint_params.cluster_name = "cluster+a"
    assert endpoint.path == "/api/v1/manage/fabrics/fab%2Fa%20%26b/smartSwitch/actions/remove?clusterName=cluster%2Ba"
    assert endpoint.verb == HttpVerbEnum.POST
    assert "ticket_id" not in type(endpoint.endpoint_params).model_fields
    with pytest.raises(ValueError, match="fabric_name"):
        EpManageSmartSwitchesDeboardPost().path


def test_deboard_path_identifiers():
    endpoint = EpManageSmartSwitchesDeboardDelete(fabric_name="f/a")
    endpoint.set_identifiers("S/A +")
    assert endpoint.path == "/api/v1/manage/fabrics/f%2Fa/smartSwitches/S%2FA%20%2B/actions/deboard"
    assert endpoint.verb == HttpVerbEnum.DELETE


@pytest.mark.parametrize("endpoint", [EpManageSmartSwitchesOnboardPost, EpManageSmartSwitchesDeboardDelete])
def test_missing_scope_rejected(endpoint):
    with pytest.raises(ValueError, match="fabric_name"):
        endpoint().path
