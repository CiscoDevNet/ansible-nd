# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabrics_switches.py

Tests the ND Manage Fabrics Switches endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
    EpManageFabricsSwitchesPost,
    EpManageFabricsSwitchChangeSerialNumberPost,
    EpManageFabricsSwitchProvisionRMAPost,
    FabricSwitchesAddEndpointParams,
    FabricSwitchesGetEndpointParams,
    SwitchActionsClusterEndpointParams,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)

# =============================================================================
# Test: FabricSwitchesGetEndpointParams
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switches_00010():
    """
    # Summary

    Verify FabricSwitchesGetEndpointParams default values

    ## Test

    - hostname defaults to None
    - max defaults to None
    - offset defaults to None

    ## Classes and Methods

    - FabricSwitchesGetEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricSwitchesGetEndpointParams()
    assert params.hostname is None
    assert params.max is None
    assert params.offset is None


def test_endpoints_api_v1_manage_fabrics_switches_00020():
    """
    # Summary

    Verify FabricSwitchesGetEndpointParams hostname can be set

    ## Test

    - hostname can be set to a string value

    ## Classes and Methods

    - FabricSwitchesGetEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricSwitchesGetEndpointParams(hostname="leaf1")
    assert params.hostname == "leaf1"


def test_endpoints_api_v1_manage_fabrics_switches_00030():
    """
    # Summary

    Verify FabricSwitchesGetEndpointParams generates query string with hostname and max

    ## Test

    - to_query_string() includes hostname and max when both are set

    ## Classes and Methods

    - FabricSwitchesGetEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = FabricSwitchesGetEndpointParams(hostname="leaf1", max=100)
        result = params.to_query_string()
    assert "hostname=leaf1" in result
    assert "max=100" in result


def test_endpoints_api_v1_manage_fabrics_switches_00040():
    """
    # Summary

    Verify FabricSwitchesAddEndpointParams default values

    ## Test

    - cluster_name defaults to None
    - ticket_id defaults to None

    ## Classes and Methods

    - FabricSwitchesAddEndpointParams.__init__()
    """
    with does_not_raise():
        params = FabricSwitchesAddEndpointParams()
    assert params.cluster_name is None
    assert params.ticket_id is None


def test_endpoints_api_v1_manage_fabrics_switches_00050():
    """
    # Summary

    Verify FabricSwitchesAddEndpointParams generates query string with both params

    ## Test

    - to_query_string() includes clusterName and ticketId when both are set

    ## Classes and Methods

    - FabricSwitchesAddEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = FabricSwitchesAddEndpointParams(cluster_name="cluster1", ticket_id="CHG12345")
        result = params.to_query_string()
    assert "clusterName=cluster1" in result
    assert "ticketId=CHG12345" in result


# =============================================================================
# Test: EpManageFabricsSwitchesGet
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switches_00100():
    """
    # Summary

    Verify EpManageFabricsSwitchesGet basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET

    ## Classes and Methods

    - EpManageFabricsSwitchesGet.__init__()
    - EpManageFabricsSwitchesGet.class_name
    - EpManageFabricsSwitchesGet.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesGet()
    assert instance.class_name == "EpManageFabricsSwitchesGet"
    assert instance.verb == HttpVerbEnum.GET


def test_endpoints_api_v1_manage_fabrics_switches_00110():
    """
    # Summary

    Verify EpManageFabricsSwitchesGet raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchesGet.path
    """
    instance = EpManageFabricsSwitchesGet()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switches_00120():
    """
    # Summary

    Verify EpManageFabricsSwitchesGet path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchesGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesGet()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches"


def test_endpoints_api_v1_manage_fabrics_switches_00130():
    """
    # Summary

    Verify EpManageFabricsSwitchesGet path with hostname filter

    ## Test

    - path includes hostname in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchesGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesGet()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.hostname = "leaf1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches?hostname=leaf1"


# =============================================================================
# Test: EpManageFabricsSwitchesPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switches_00200():
    """
    # Summary

    Verify EpManageFabricsSwitchesPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchesPost.__init__()
    - EpManageFabricsSwitchesPost.class_name
    - EpManageFabricsSwitchesPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesPost()
    assert instance.class_name == "EpManageFabricsSwitchesPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switches_00210():
    """
    # Summary

    Verify EpManageFabricsSwitchesPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchesPost.path
    """
    instance = EpManageFabricsSwitchesPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switches_00220():
    """
    # Summary

    Verify EpManageFabricsSwitchesPost path without query params

    ## Test

    - path returns correct endpoint path

    ## Classes and Methods

    - EpManageFabricsSwitchesPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesPost()
        instance.fabric_name = "MyFabric"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches"


def test_endpoints_api_v1_manage_fabrics_switches_00230():
    """
    # Summary

    Verify EpManageFabricsSwitchesPost path with cluster_name and ticket_id

    ## Test

    - path includes clusterName and ticketId in query string when set

    ## Classes and Methods

    - EpManageFabricsSwitchesPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchesPost()
        instance.fabric_name = "MyFabric"
        instance.endpoint_params.cluster_name = "cluster1"
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result.startswith("/api/v1/manage/fabrics/MyFabric/switches?")
    assert "clusterName=cluster1" in result
    assert "ticketId=CHG12345" in result


# =============================================================================
# Test: SwitchActionsClusterEndpointParams
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switches_00300():
    """
    # Summary

    Verify SwitchActionsClusterEndpointParams basic instantiation

    ## Test

    - Instance can be created with defaults
    - cluster_name defaults to None

    ## Classes and Methods

    - SwitchActionsClusterEndpointParams.__init__()
    """
    with does_not_raise():
        instance = SwitchActionsClusterEndpointParams()
    assert instance.cluster_name is None


def test_endpoints_api_v1_manage_fabrics_switches_00310():
    """
    # Summary

    Verify SwitchActionsClusterEndpointParams to_query_string returns empty when no params set

    ## Test

    - to_query_string() returns empty string when cluster_name is None

    ## Classes and Methods

    - SwitchActionsClusterEndpointParams.to_query_string()
    """
    instance = SwitchActionsClusterEndpointParams()
    assert instance.to_query_string() == ""


def test_endpoints_api_v1_manage_fabrics_switches_00320():
    """
    # Summary

    Verify SwitchActionsClusterEndpointParams to_query_string with cluster_name

    ## Test

    - to_query_string() returns "clusterName=cluster1" when cluster_name is set

    ## Classes and Methods

    - SwitchActionsClusterEndpointParams.to_query_string()
    """
    instance = SwitchActionsClusterEndpointParams(cluster_name="cluster1")
    assert instance.to_query_string() == "clusterName=cluster1"


# =============================================================================
# Test: EpManageFabricsSwitchProvisionRMAPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switches_00500():
    """
    # Summary

    Verify EpManageFabricsSwitchProvisionRMAPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchProvisionRMAPost.__init__()
    - EpManageFabricsSwitchProvisionRMAPost.class_name
    - EpManageFabricsSwitchProvisionRMAPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchProvisionRMAPost()
    assert instance.class_name == "EpManageFabricsSwitchProvisionRMAPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switches_00510():
    """
    # Summary

    Verify EpManageFabricsSwitchProvisionRMAPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchProvisionRMAPost.path
    """
    instance = EpManageFabricsSwitchProvisionRMAPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switches_00520():
    """
    # Summary

    Verify EpManageFabricsSwitchProvisionRMAPost raises ValueError when switch_sn is not set

    ## Test

    - Accessing path raises ValueError when switch_sn is None

    ## Classes and Methods

    - EpManageFabricsSwitchProvisionRMAPost.path
    """
    instance = EpManageFabricsSwitchProvisionRMAPost()
    instance.fabric_name = "MyFabric"
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switches_00530():
    """
    # Summary

    Verify EpManageFabricsSwitchProvisionRMAPost path without query params

    ## Test

    - Path is correctly built with fabric_name and switch_sn
    - No query string appended when ticket_id is not set

    ## Classes and Methods

    - EpManageFabricsSwitchProvisionRMAPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchProvisionRMAPost()
        instance.fabric_name = "MyFabric"
        instance.switch_sn = "SAL1948TRTT"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/provisionRMA"


def test_endpoints_api_v1_manage_fabrics_switches_00540():
    """
    # Summary

    Verify EpManageFabricsSwitchProvisionRMAPost path with ticket_id

    ## Test

    - Path includes ticketId query parameter when set

    ## Classes and Methods

    - EpManageFabricsSwitchProvisionRMAPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchProvisionRMAPost()
        instance.fabric_name = "MyFabric"
        instance.switch_sn = "SAL1948TRTT"
        instance.endpoint_params.ticket_id = "CHG12345"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/provisionRMA?ticketId=CHG12345"


# =============================================================================
# Test: EpManageFabricsSwitchChangeSerialNumberPost
# =============================================================================


def test_endpoints_api_v1_manage_fabrics_switches_00600():
    """
    # Summary

    Verify EpManageFabricsSwitchChangeSerialNumberPost basic instantiation

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is POST

    ## Classes and Methods

    - EpManageFabricsSwitchChangeSerialNumberPost.__init__()
    - EpManageFabricsSwitchChangeSerialNumberPost.class_name
    - EpManageFabricsSwitchChangeSerialNumberPost.verb
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchChangeSerialNumberPost()
    assert instance.class_name == "EpManageFabricsSwitchChangeSerialNumberPost"
    assert instance.verb == HttpVerbEnum.POST


def test_endpoints_api_v1_manage_fabrics_switches_00610():
    """
    # Summary

    Verify EpManageFabricsSwitchChangeSerialNumberPost raises ValueError when fabric_name is not set

    ## Test

    - Accessing path raises ValueError when fabric_name is None

    ## Classes and Methods

    - EpManageFabricsSwitchChangeSerialNumberPost.path
    """
    instance = EpManageFabricsSwitchChangeSerialNumberPost()
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switches_00620():
    """
    # Summary

    Verify EpManageFabricsSwitchChangeSerialNumberPost raises ValueError when switch_sn is not set

    ## Test

    - Accessing path raises ValueError when switch_sn is None

    ## Classes and Methods

    - EpManageFabricsSwitchChangeSerialNumberPost.path
    """
    instance = EpManageFabricsSwitchChangeSerialNumberPost()
    instance.fabric_name = "MyFabric"
    with pytest.raises(ValueError):
        instance.path


def test_endpoints_api_v1_manage_fabrics_switches_00630():
    """
    # Summary

    Verify EpManageFabricsSwitchChangeSerialNumberPost path without query params

    ## Test

    - Path is correctly built with fabric_name and switch_sn
    - No query string appended when cluster_name is not set

    ## Classes and Methods

    - EpManageFabricsSwitchChangeSerialNumberPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchChangeSerialNumberPost()
        instance.fabric_name = "MyFabric"
        instance.switch_sn = "SAL1948TRTT"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/changeSwitchSerialNumber"


def test_endpoints_api_v1_manage_fabrics_switches_00640():
    """
    # Summary

    Verify EpManageFabricsSwitchChangeSerialNumberPost path with cluster_name

    ## Test

    - Path includes clusterName query parameter when set

    ## Classes and Methods

    - EpManageFabricsSwitchChangeSerialNumberPost.path
    """
    with does_not_raise():
        instance = EpManageFabricsSwitchChangeSerialNumberPost()
        instance.fabric_name = "MyFabric"
        instance.switch_sn = "SAL1948TRTT"
        instance.endpoint_params.cluster_name = "cluster1"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/MyFabric/switches/SAL1948TRTT/actions/changeSwitchSerialNumber?clusterName=cluster1"
