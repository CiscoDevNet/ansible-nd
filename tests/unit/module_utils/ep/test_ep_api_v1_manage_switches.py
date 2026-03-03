# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ep_api_v1_manage_switches.py

Tests the ND Manage Inventory Switches endpoint classes
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.ep.v1.ep_manage_switches import (
    EpManageSwitchesGet,
    SwitchesEndpointParams,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: SwitchesEndpointParams
# =============================================================================


def test_ep_switches_00010():
    """
    # Summary

    Verify SwitchesEndpointParams default values

    ## Test

    - All parameters default to None

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = SwitchesEndpointParams()
    assert params.fabric_name is None
    assert params.switch_id is None
    assert params.hostname is None


def test_ep_switches_00020():
    """
    # Summary

    Verify SwitchesEndpointParams fabric_name can be set

    ## Test

    - fabric_name can be set to a string value

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(fabric_name="MyFabric")
    assert params.fabric_name == "MyFabric"


def test_ep_switches_00030():
    """
    # Summary

    Verify SwitchesEndpointParams switch_id can be set

    ## Test

    - switch_id can be set to a string value

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(switch_id="FDO12345678")
    assert params.switch_id == "FDO12345678"


def test_ep_switches_00040():
    """
    # Summary

    Verify SwitchesEndpointParams hostname can be set

    ## Test

    - hostname can be set to a string value

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(hostname="leaf-01")
    assert params.hostname == "leaf-01"


def test_ep_switches_00050():
    """
    # Summary

    Verify SwitchesEndpointParams all params can be set

    ## Test

    - All three parameters can be set together

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(fabric_name="Fabric1", switch_id="101", hostname="switch1")
    assert params.fabric_name == "Fabric1"
    assert params.switch_id == "101"
    assert params.hostname == "switch1"


def test_ep_switches_00060():
    """
    # Summary

    Verify SwitchesEndpointParams generates correct query string

    ## Test

    - to_query_string() returns correct format with all parameters

    ## Classes and Methods

    - SwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(fabric_name="MyFabric", switch_id="101", hostname="leaf-01")
        result = params.to_query_string()
    assert result == "fabricName=MyFabric&switchId=101&hostname=leaf-01"


def test_ep_switches_00070():
    """
    # Summary

    Verify SwitchesEndpointParams snake_case to camelCase conversion

    ## Test

    - fabric_name converts to fabricName
    - switch_id converts to switchId
    - hostname remains hostname (no underscore)

    ## Classes and Methods

    - SwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(fabric_name="test", switch_id="123", hostname="host1")
        result = params.to_query_string()
    # Verify camelCase conversion
    assert "fabricName=" in result
    assert "switchId=" in result
    assert "hostname=" in result
    # Verify no snake_case
    assert "fabric_name" not in result
    assert "switch_id" not in result


def test_ep_switches_00080():
    """
    # Summary

    Verify SwitchesEndpointParams query string with partial params

    ## Test

    - to_query_string() only includes set parameters

    ## Classes and Methods

    - SwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchesEndpointParams(fabric_name="Fabric1")
        result = params.to_query_string()
    assert result == "fabricName=Fabric1"


def test_ep_switches_00090():
    """
    # Summary

    Verify SwitchesEndpointParams empty query string

    ## Test

    - to_query_string() returns empty string when no params set

    ## Classes and Methods

    - SwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        params = SwitchesEndpointParams()
        result = params.to_query_string()
    assert result == ""


# =============================================================================
# Test: EpManageSwitchesGet
# =============================================================================


def test_ep_switches_00100():
    """
    # Summary

    Verify EpManageSwitchesGet basic instantiation

    ## Test

    - Instance can be created
    - verb is GET

    ## Classes and Methods

    - EpManageSwitchesGet.__init__()
    - EpManageSwitchesGet.verb
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
    assert instance.verb == HttpVerbEnum.GET


def test_ep_switches_00110():
    """
    # Summary

    Verify EpManageSwitchesGet path without params

    ## Test

    - path returns base path when no query params are set

    ## Classes and Methods

    - EpManageSwitchesGet.path
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        result = instance.path
    assert result == "/api/v1/manage/inventory/switches"


def test_ep_switches_00120():
    """
    # Summary

    Verify EpManageSwitchesGet path with fabric_name

    ## Test

    - path includes query string when fabric_name is set

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.fabric_name = "Fabric1"
        result = instance.path
    assert result == "/api/v1/manage/inventory/switches?fabricName=Fabric1"


def test_ep_switches_00130():
    """
    # Summary

    Verify EpManageSwitchesGet path with switch_id

    ## Test

    - path includes query string when switch_id is set

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.switch_id = "101"
        result = instance.path
    assert result == "/api/v1/manage/inventory/switches?switchId=101"


def test_ep_switches_00140():
    """
    # Summary

    Verify EpManageSwitchesGet path with hostname

    ## Test

    - path includes query string when hostname is set

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.hostname = "leaf-01"
        result = instance.path
    assert result == "/api/v1/manage/inventory/switches?hostname=leaf-01"


def test_ep_switches_00150():
    """
    # Summary

    Verify EpManageSwitchesGet path with all endpoint params

    ## Test

    - path includes query string with all endpoint parameters

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.fabric_name = "Fabric1"
        instance.endpoint_params.switch_id = "101"
        instance.endpoint_params.hostname = "switch1"
        result = instance.path
    assert result == "/api/v1/manage/inventory/switches?fabricName=Fabric1&switchId=101&hostname=switch1"


def test_ep_switches_00160():
    """
    # Summary

    Verify EpManageSwitchesGet path with Lucene filter

    ## Test

    - path includes Lucene filter parameter

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.lucene_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.lucene_params.filter = "role:leaf AND status:active"
        result = instance.path
    # URL encoding should be applied
    assert result.startswith("/api/v1/manage/inventory/switches?filter=")
    assert "role" in result
    assert "leaf" in result


def test_ep_switches_00170():
    """
    # Summary

    Verify EpManageSwitchesGet path with Lucene pagination

    ## Test

    - path includes max and offset parameters

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.lucene_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.lucene_params.max = 10
        instance.lucene_params.offset = 20
        result = instance.path
    assert result == "/api/v1/manage/inventory/switches?max=10&offset=20"


def test_ep_switches_00180():
    """
    # Summary

    Verify EpManageSwitchesGet path with Lucene sort

    ## Test

    - path includes sort parameter

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.lucene_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.lucene_params.sort = "hostname:asc"
        result = instance.path
    # URL encoding should be applied
    assert result.startswith("/api/v1/manage/inventory/switches?sort=")
    assert "hostname" in result


def test_ep_switches_00190():
    """
    # Summary

    Verify EpManageSwitchesGet path with combined params

    ## Test

    - path includes both endpoint params and Lucene params

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.endpoint_params
    - EpManageSwitchesGet.lucene_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.fabric_name = "Fabric1"
        instance.lucene_params.max = 50
        instance.lucene_params.sort = "hostname:asc"
        result = instance.path
    assert result.startswith("/api/v1/manage/inventory/switches?fabricName=Fabric1")
    assert "max=50" in result
    assert "sort=" in result
    assert "hostname" in result


def test_ep_switches_00200():
    """
    # Summary

    Verify EpManageSwitchesGet path with all params

    ## Test

    - path includes all endpoint and Lucene parameters

    ## Classes and Methods

    - EpManageSwitchesGet.path
    - EpManageSwitchesGet.endpoint_params
    - EpManageSwitchesGet.lucene_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.fabric_name = "Fabric1"
        instance.endpoint_params.hostname = "switch1"
        instance.lucene_params.filter = "role:leaf"
        instance.lucene_params.max = 50
        instance.lucene_params.sort = "hostname:asc"
        result = instance.path
    # Check all parameters are present
    assert "fabricName=Fabric1" in result
    assert "hostname=switch1" in result
    assert "filter=" in result
    assert "max=50" in result
    assert "sort=" in result


# =============================================================================
# Test: Pydantic validation
# =============================================================================


def test_ep_switches_00300():
    """
    # Summary

    Verify Pydantic validation for empty string

    ## Test

    - Empty string is rejected for fabric_name (min_length=1)

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    with pytest.raises(ValueError):
        SwitchesEndpointParams(fabric_name="")


def test_ep_switches_00310():
    """
    # Summary

    Verify Pydantic validation for fabric_name max length

    ## Test

    - Strings longer than 64 characters are rejected

    ## Classes and Methods

    - SwitchesEndpointParams.__init__()
    """
    long_name = "a" * 65  # 65 characters
    with pytest.raises(ValueError):
        SwitchesEndpointParams(fabric_name=long_name)


def test_ep_switches_00320():
    """
    # Summary

    Verify parameters can be modified after instantiation

    ## Test

    - endpoint_params can be changed after object creation

    ## Classes and Methods

    - EpManageSwitchesGet.endpoint_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        assert instance.path == "/api/v1/manage/inventory/switches"

        instance.endpoint_params.fabric_name = "NewFabric"
        assert instance.path == "/api/v1/manage/inventory/switches?fabricName=NewFabric"


def test_ep_switches_00330():
    """
    # Summary

    Verify Lucene params can be modified after instantiation

    ## Test

    - lucene_params can be changed after object creation

    ## Classes and Methods

    - EpManageSwitchesGet.lucene_params
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        assert instance.path == "/api/v1/manage/inventory/switches"

        instance.lucene_params.max = 100
        assert "max=100" in instance.path


# =============================================================================
# Test: Composite query parameter ordering
# =============================================================================


def test_ep_switches_00400():
    """
    # Summary

    Verify endpoint params come before Lucene params in query string

    ## Test

    - CompositeQueryParams maintains order: endpoint params first, Lucene params second

    ## Classes and Methods

    - EpManageSwitchesGet.path
    """
    with does_not_raise():
        instance = EpManageSwitchesGet()
        instance.endpoint_params.fabric_name = "Fabric1"
        instance.lucene_params.max = 10
        result = instance.path

    # fabricName should appear before max in the query string
    fabric_pos = result.index("fabricName")
    max_pos = result.index("max")
    assert fabric_pos < max_pos
