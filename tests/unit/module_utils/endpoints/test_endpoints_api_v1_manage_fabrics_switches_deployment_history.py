# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_switches_deployment_history.py

Tests the ND Manage per-switch deployment-history endpoint class.
"""

# pylint: disable=unused-import
# pylint: disable=redefined-outer-name
# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=unused-variable
# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches_deployment_history import (
    EpManageFabricsSwitchesDeploymentHistoryGet,
    ManageDeploymentHistoryEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_ep_manage_fabrics_switches_deployment_history_00010():
    """
    # Summary

    Verify the path and verb of `EpManageFabricsSwitchesDeploymentHistoryGet` without query parameters.

    ## Test

    - `fabric_name` and `switch_sn` are set, no `endpoint_params`
    - `path` is `/api/v1/manage/fabrics/CAMPUS1/switches/CAT9KV1701/deploymentHistory` with no query string
    - `verb` is GET

    ## Classes and Methods

    - EpManageFabricsSwitchesDeploymentHistoryGet.path
    - EpManageFabricsSwitchesDeploymentHistoryGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesDeploymentHistoryGet()
        instance.fabric_name = "CAMPUS1"
        instance.switch_sn = "CAT9KV1701"
        result = instance.path
    assert instance.class_name == "EpManageFabricsSwitchesDeploymentHistoryGet"
    assert isinstance(instance.endpoint_params, ManageDeploymentHistoryEndpointParams)
    assert result == "/api/v1/manage/fabrics/CAMPUS1/switches/CAT9KV1701/deploymentHistory"
    assert instance.verb == HttpVerbEnum.GET


@pytest.mark.parametrize(
    "fabric_name, switch_sn, match",
    [
        (None, "CAT9KV1701", r"fabric_name must be set"),
        ("CAMPUS1", None, r"switch_sn must be set"),
    ],
)
def test_ep_manage_fabrics_switches_deployment_history_00020(fabric_name, switch_sn, match):
    """
    # Summary

    Verify `path` raises `ValueError` until both `fabric_name` and `switch_sn` are set.

    ## Test

    - One of the two path parameters is left unset
    - Accessing `path` raises `ValueError` naming the missing parameter

    ## Classes and Methods

    - EpManageFabricsSwitchesDeploymentHistoryGet.path
    """
    instance = EpManageFabricsSwitchesDeploymentHistoryGet()
    if fabric_name is not None:
        instance.fabric_name = fabric_name
    if switch_sn is not None:
        instance.switch_sn = switch_sn
    with pytest.raises(ValueError, match=match):
        result = instance.path  # pylint: disable=pointless-statement


def test_ep_manage_fabrics_switches_deployment_history_00030():
    """
    # Summary

    Verify the query string: every set parameter is emitted in camelCase with its value percent-encoded, so a Lucene filter on an
    interface name with `/` and `.` (`entityName:GigabitEthernet1/0/2.100`) reaches the controller intact (ND 4.2.1 does not match a
    quoted name containing `/`; the bare, percent-encoded form matches on 4.2.1 and 4.3.1, lab-verified 2026-09-22).

    ## Test

    - `filter`, `sort`, `max`, `offset` and `cluster_name` are set
    - The path part is unchanged and the query part holds exactly the five encoded pairs

    ## Classes and Methods

    - EpManageFabricsSwitchesDeploymentHistoryGet.path
    - ManageDeploymentHistoryEndpointParams.to_query_string
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesDeploymentHistoryGet()
        instance.fabric_name = "CAMPUS1"
        instance.switch_sn = "CAT9KV1701"
        instance.endpoint_params.filter = "entityName:GigabitEthernet1/0/2.100"
        instance.endpoint_params.sort = "completeTimestamp:desc"
        instance.endpoint_params.max = 10
        instance.endpoint_params.offset = 0
        instance.endpoint_params.cluster_name = "cluster-a"
        result = instance.path
    path, query = result.split("?", 1)
    assert path == "/api/v1/manage/fabrics/CAMPUS1/switches/CAT9KV1701/deploymentHistory"
    assert set(query.split("&")) == {
        "filter=entityName%3AGigabitEthernet1%2F0%2F2.100",
        "sort=completeTimestamp%3Adesc",
        "max=10",
        "offset=0",
        "clusterName=cluster-a",
    }
