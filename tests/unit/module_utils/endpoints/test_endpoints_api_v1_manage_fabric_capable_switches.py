# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for manage_fabric_capable_switches.py

Tests the ND Manage Fabrics capableSwitches endpoint classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabric_capable_switches import (
    CapableSwitchesEndpointParams,
    EpManageFabricsCapableSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: CapableSwitchesEndpointParams
# =============================================================================


def test_endpoints_api_v1_manage_fabric_capable_switches_00010():
    """
    # Summary

    Verify `CapableSwitchesEndpointParams` defaults all fields to None and produces an empty query string.

    ## Test

    - Instance can be created with no arguments
    - interface_type and mode default to None
    - to_query_string() returns ""
    - is_empty() returns True

    ## Classes and Methods

    - CapableSwitchesEndpointParams.__init__()
    - CapableSwitchesEndpointParams.to_query_string()
    - CapableSwitchesEndpointParams.is_empty()
    """
    with does_not_raise():
        instance = CapableSwitchesEndpointParams()
    assert instance.interface_type is None
    assert instance.mode is None
    assert instance.to_query_string() == ""
    assert instance.is_empty() is True


def test_endpoints_api_v1_manage_fabric_capable_switches_00020():
    """
    # Summary

    Verify `CapableSwitchesEndpointParams` snake_case fields convert to camelCase in the query string.

    ## Test

    - interface_type="loopback" and mode="managed" -> "interfaceType=loopback&mode=managed"

    ## Classes and Methods

    - CapableSwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        instance = CapableSwitchesEndpointParams(interface_type="loopback", mode="managed")
        result = instance.to_query_string()
    assert result == "interfaceType=loopback&mode=managed"


def test_endpoints_api_v1_manage_fabric_capable_switches_00030():
    """
    # Summary

    Verify `CapableSwitchesEndpointParams` preserves camelCase values verbatim (e.g. `dot1qTunnel`) in the query string.

    ## Test

    - interface_type="portChannel" and mode="dot1qTunnel" -> "interfaceType=portChannel&mode=dot1qTunnel"

    ## Classes and Methods

    - CapableSwitchesEndpointParams.to_query_string()
    """
    with does_not_raise():
        instance = CapableSwitchesEndpointParams(interface_type="portChannel", mode="dot1qTunnel")
        result = instance.to_query_string()
    assert result == "interfaceType=portChannel&mode=dot1qTunnel"


# =============================================================================
# Test: EpManageFabricsCapableSwitchesGet
# =============================================================================


def test_endpoints_api_v1_manage_fabric_capable_switches_00100():
    """
    # Summary

    Verify `EpManageFabricsCapableSwitchesGet` basic instantiation.

    ## Test

    - Instance can be created
    - class_name is set correctly
    - verb is GET
    - fabric_name, interface_type, and mode default to None

    ## Classes and Methods

    - EpManageFabricsCapableSwitchesGet.__init__()
    - EpManageFabricsCapableSwitchesGet.verb
    - EpManageFabricsCapableSwitchesGet.class_name
    """
    with does_not_raise():
        instance = EpManageFabricsCapableSwitchesGet()
    assert instance.class_name == "EpManageFabricsCapableSwitchesGet"
    assert instance.verb == HttpVerbEnum.GET
    assert instance.fabric_name is None
    assert instance.endpoint_params.interface_type is None
    assert instance.endpoint_params.mode is None


def test_endpoints_api_v1_manage_fabric_capable_switches_00110():
    """
    # Summary

    Verify `EpManageFabricsCapableSwitchesGet.path` builds the correct URL when all required values are set.

    ## Test

    - fabric_name, interface_type, and mode all set -> path is "/api/v1/manage/fabrics/{fabric}/capableSwitches?interfaceType={t}&mode={m}"

    ## Classes and Methods

    - EpManageFabricsCapableSwitchesGet.path
    """
    with does_not_raise():
        instance = EpManageFabricsCapableSwitchesGet()
        instance.fabric_name = "fabric_1"
        instance.endpoint_params.interface_type = "loopback"
        instance.endpoint_params.mode = "managed"
        result = instance.path
    assert result == "/api/v1/manage/fabrics/fabric_1/capableSwitches?interfaceType=loopback&mode=managed"


def test_endpoints_api_v1_manage_fabric_capable_switches_00120():
    """
    # Summary

    Verify `EpManageFabricsCapableSwitchesGet.path` raises ValueError when fabric_name is not set.

    ## Test

    - interface_type and mode set, fabric_name not set -> ValueError mentioning fabric_name

    ## Classes and Methods

    - EpManageFabricsCapableSwitchesGet.path
    """
    instance = EpManageFabricsCapableSwitchesGet()
    instance.endpoint_params.interface_type = "loopback"
    instance.endpoint_params.mode = "managed"
    match = r"fabric_name must be set"
    with pytest.raises(ValueError, match=match):
        result = instance.path  # pylint: disable=pointless-statement  # noqa: F841


def test_endpoints_api_v1_manage_fabric_capable_switches_00130():
    """
    # Summary

    Verify `EpManageFabricsCapableSwitchesGet.path` raises ValueError when interface_type is not set.

    ## Test

    - fabric_name and mode set, interface_type not set -> ValueError mentioning interface_type

    ## Classes and Methods

    - EpManageFabricsCapableSwitchesGet.path
    """
    instance = EpManageFabricsCapableSwitchesGet()
    instance.fabric_name = "fabric_1"
    instance.endpoint_params.mode = "managed"
    match = r"interface_type must be set"
    with pytest.raises(ValueError, match=match):
        result = instance.path  # pylint: disable=pointless-statement  # noqa: F841


def test_endpoints_api_v1_manage_fabric_capable_switches_00140():
    """
    # Summary

    Verify `EpManageFabricsCapableSwitchesGet.path` raises ValueError when mode is not set.

    ## Test

    - fabric_name and interface_type set, mode not set -> ValueError mentioning mode

    ## Classes and Methods

    - EpManageFabricsCapableSwitchesGet.path
    """
    instance = EpManageFabricsCapableSwitchesGet()
    instance.fabric_name = "fabric_1"
    instance.endpoint_params.interface_type = "loopback"
    match = r"mode must be set"
    with pytest.raises(ValueError, match=match):
        result = instance.path  # pylint: disable=pointless-statement  # noqa: F841


def test_endpoints_api_v1_manage_fabric_capable_switches_00150():
    """
    # Summary

    Verify `set_identifiers` populates the fabric_name on the endpoint.

    ## Test

    - set_identifiers("fabric_1") sets fabric_name to "fabric_1"

    ## Classes and Methods

    - EpManageFabricsCapableSwitchesGet.set_identifiers
    """
    with does_not_raise():
        instance = EpManageFabricsCapableSwitchesGet()
        instance.set_identifiers("fabric_1")
    assert instance.fabric_name == "fabric_1"
