# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for loopback_interface.py

Tests the Loopback Interface Pydantic model classes.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import copy
from contextlib import contextmanager

import pytest  # pylint: disable=unused-import
from pydantic import ValidationError  # pylint: disable=unused-import
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LOOPBACK_POLICY_TYPE_MAPPING,
    LoopbackConfigDataModel,
    LoopbackInterfaceModel,
    LoopbackNetworkOSModel,
    LoopbackPolicyModel,
)


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_API_RESPONSE = {
    "interfaceName": "loopback0",
    "interfaceType": "loopback",
    "configData": {
        "mode": "managed",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "adminState": True,
                "ip": "10.1.1.1/32",
                "vrfInterface": "management",
                "policyType": "loopback",
                "routeMapTag": 12345,
                "description": "mgmt loopback",
            },
        },
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "interface_name": "loopback0",
    "interface_type": "loopback",
    "config_data": {
        "mode": "managed",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "admin_state": True,
                "ip": "10.1.1.1/32",
                "vrf": "management",
                "policy_type": "loopback",
                "route_map_tag": 12345,
                "description": "mgmt loopback",
            },
        },
    },
}


# =============================================================================
# Test: LOOPBACK_POLICY_TYPE_MAPPING
# =============================================================================


def test_loopback_interface_00000():
    """
    # Summary

    Verify get_original_data() returns the expected list.

    ## Test

    - get_original_data() returns ["loopback", "ipfm_loopback", "user_defined"]

    ## Classes and Methods

    - NDConstantMapping.get_original_data()
    """
    result = LOOPBACK_POLICY_TYPE_MAPPING.get_original_data()
    assert result == ["loopback", "ipfm_loopback", "user_defined"]


def test_loopback_interface_00001():
    """
    # Summary

    Verify get_dict() maps correctly.

    ## Test

    - ipfm_loopback -> ipfmLoopback
    - user_defined -> userDefined
    - Reverse mapping also present

    ## Classes and Methods

    - NDConstantMapping.get_dict()
    """
    mapping = LOOPBACK_POLICY_TYPE_MAPPING.get_dict()
    assert mapping["ipfm_loopback"] == "ipfmLoopback"
    assert mapping["user_defined"] == "userDefined"
    assert mapping["loopback"] == "loopback"
    assert mapping["ipfmLoopback"] == "ipfm_loopback"
    assert mapping["userDefined"] == "user_defined"


# =============================================================================
# Test: LoopbackPolicyModel
# =============================================================================


def test_loopback_interface_00010():
    """
    # Summary

    Verify all fields default to None.

    ## Test

    - Instantiate with no arguments
    - All fields are None

    ## Classes and Methods

    - LoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackPolicyModel()
    assert instance.admin_state is None
    assert instance.ip is None
    assert instance.ipv6 is None
    assert instance.vrf is None
    assert instance.route_map_tag is None
    assert instance.link_state_routing_tag is None
    assert instance.description is None
    assert instance.extra_config is None
    assert instance.policy_type is None


def test_loopback_interface_00020():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - All values accessible

    ## Classes and Methods

    - LoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackPolicyModel(
            admin_state=True,
            ip="10.1.1.1/32",
            vrf="management",
            policy_type="loopback",
            route_map_tag=100,
            description="test",
        )
    assert instance.admin_state is True
    assert instance.ip == "10.1.1.1/32"
    assert instance.vrf == "management"
    assert instance.policy_type == "loopback"
    assert instance.route_map_tag == 100
    assert instance.description == "test"


def test_loopback_interface_00030():
    """
    # Summary

    Verify construction with camelCase aliases (populate_by_name=True).

    ## Test

    - Construct with API alias names
    - All values accessible by Python names

    ## Classes and Methods

    - LoopbackPolicyModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackPolicyModel(
            adminState=False,
            ip="10.2.2.2/32",
            vrfInterface="default",
            policyType="loopback",
            routeMapTag=200,
        )
    assert instance.admin_state is False
    assert instance.ip == "10.2.2.2/32"
    assert instance.vrf == "default"
    assert instance.policy_type == "loopback"
    assert instance.route_map_tag == 200


def test_loopback_interface_00040():
    """
    # Summary

    Verify normalize_policy_type converts API "ipfmLoopback" to "ipfm_loopback".

    ## Test

    - Construct with policyType="ipfmLoopback"
    - policy_type is normalized to "ipfm_loopback"

    ## Classes and Methods

    - LoopbackPolicyModel.normalize_policy_type()
    """
    instance = LoopbackPolicyModel(policyType="ipfmLoopback")
    assert instance.policy_type == "ipfm_loopback"


def test_loopback_interface_00041():
    """
    # Summary

    Verify normalize_policy_type passes through "ipfm_loopback" unchanged.

    ## Test

    - Construct with policy_type="ipfm_loopback"
    - Value passes through unchanged (already in Ansible format)

    ## Classes and Methods

    - LoopbackPolicyModel.normalize_policy_type()
    """
    instance = LoopbackPolicyModel(policy_type="ipfm_loopback")
    assert instance.policy_type == "ipfm_loopback"


def test_loopback_interface_00042():
    """
    # Summary

    Verify normalize_policy_type converts "userDefined" to "user_defined".

    ## Test

    - Construct with policyType="userDefined"
    - policy_type is normalized to "user_defined"

    ## Classes and Methods

    - LoopbackPolicyModel.normalize_policy_type()
    """
    instance = LoopbackPolicyModel(policyType="userDefined")
    assert instance.policy_type == "user_defined"


def test_loopback_interface_00043():
    """
    # Summary

    Verify normalize_policy_type passes through None.

    ## Test

    - Construct with policy_type=None (default)
    - Value is None

    ## Classes and Methods

    - LoopbackPolicyModel.normalize_policy_type()
    """
    instance = LoopbackPolicyModel()
    assert instance.policy_type is None


def test_loopback_interface_00044():
    """
    # Summary

    Verify normalize_policy_type passes through unknown values unchanged.

    ## Test

    - Construct with policy_type="custom_unknown"
    - Value passes through unchanged

    ## Classes and Methods

    - LoopbackPolicyModel.normalize_policy_type()
    """
    instance = LoopbackPolicyModel(policy_type="custom_unknown")
    assert instance.policy_type == "custom_unknown"


def test_loopback_interface_00050():
    """
    # Summary

    Verify serialize_policy_type in payload mode produces camelCase.

    ## Test

    - model_dump with payload context
    - policy_type serialized to camelCase

    ## Classes and Methods

    - LoopbackPolicyModel.serialize_policy_type()
    """
    instance = LoopbackPolicyModel(policy_type="ipfm_loopback")
    result = instance.model_dump(by_alias=True, exclude_none=True, context={"mode": "payload"})
    assert result["policyType"] == "ipfmLoopback"


def test_loopback_interface_00051():
    """
    # Summary

    Verify serialize_policy_type in config mode keeps ansible name.

    ## Test

    - model_dump with config context
    - policy_type stays as ansible name

    ## Classes and Methods

    - LoopbackPolicyModel.serialize_policy_type()
    """
    instance = LoopbackPolicyModel(policy_type="ipfm_loopback")
    result = instance.model_dump(by_alias=False, exclude_none=True, context={"mode": "config"})
    assert result["policy_type"] == "ipfm_loopback"


def test_loopback_interface_00052():
    """
    # Summary

    Verify serialize_policy_type with None returns None in both modes.

    ## Test

    - policy_type is None
    - Serialization in both modes returns None (excluded by exclude_none)

    ## Classes and Methods

    - LoopbackPolicyModel.serialize_policy_type()
    """
    instance = LoopbackPolicyModel()
    payload_result = instance.model_dump(by_alias=True, context={"mode": "payload"})
    config_result = instance.model_dump(by_alias=False, context={"mode": "config"})
    assert payload_result["policyType"] is None
    assert config_result["policy_type"] is None


def test_loopback_interface_00053():
    """
    # Summary

    Verify default serialization (no context) uses payload mode (camelCase).

    ## Test

    - model_dump with no context
    - policy_type serialized to camelCase (default is payload)

    ## Classes and Methods

    - LoopbackPolicyModel.serialize_policy_type()
    """
    instance = LoopbackPolicyModel(policy_type="user_defined")
    result = instance.model_dump(by_alias=True, exclude_none=True)
    assert result["policyType"] == "userDefined"


def test_loopback_interface_00060():
    """
    # Summary

    Verify model_dump(exclude_none=True) excludes None fields.

    ## Test

    - Only ip is set
    - exclude_none=True omits all None fields

    ## Classes and Methods

    - LoopbackPolicyModel.model_dump()
    """
    instance = LoopbackPolicyModel(ip="10.1.1.1/32")
    result = instance.model_dump(exclude_none=True)
    assert "ip" in result
    assert "admin_state" not in result
    assert "vrf" not in result
    assert "policy_type" not in result


# =============================================================================
# Test: LoopbackNetworkOSModel
# =============================================================================


def test_loopback_interface_00100():
    """
    # Summary

    Verify network_os_type defaults to "nx-os".

    ## Test

    - Construct with only required policy field
    - network_os_type defaults to "nx-os"

    ## Classes and Methods

    - LoopbackNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackNetworkOSModel(policy=LoopbackPolicyModel())
    assert instance.network_os_type == "nx-os"


def test_loopback_interface_00110():
    """
    # Summary

    Verify policy field defaults to None when not provided.

    ## Test

    - Construct without policy field
    - policy is None
    - network_os_type has default value

    ## Classes and Methods

    - LoopbackNetworkOSModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackNetworkOSModel()
    assert instance.policy is None
    assert instance.network_os_type == "nx-os"


def test_loopback_interface_00120():
    """
    # Summary

    Verify construction from camelCase dict with nested policy normalization.

    ## Test

    - Construct from API-style camelCase dict
    - Nested policy_type is normalized

    ## Classes and Methods

    - LoopbackNetworkOSModel.__init__()
    - LoopbackPolicyModel.normalize_policy_type()
    """
    data = {
        "networkOSType": "nx-os",
        "policy": {
            "adminState": True,
            "policyType": "ipfmLoopback",
        },
    }
    with does_not_raise():
        instance = LoopbackNetworkOSModel(**data)
    assert instance.network_os_type == "nx-os"
    assert instance.policy.admin_state is True
    assert instance.policy.policy_type == "ipfm_loopback"


# =============================================================================
# Test: LoopbackConfigDataModel
# =============================================================================


def test_loopback_interface_00150():
    """
    # Summary

    Verify mode defaults to "managed".

    ## Test

    - Construct with only required network_os field
    - mode defaults to "managed"

    ## Classes and Methods

    - LoopbackConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackConfigDataModel(network_os=LoopbackNetworkOSModel(policy=LoopbackPolicyModel()))
    assert instance.mode == "managed"


def test_loopback_interface_00160():
    """
    # Summary

    Verify deeply nested construction and field access.

    ## Test

    - Construct with full nesting
    - All nested fields accessible

    ## Classes and Methods

    - LoopbackConfigDataModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackConfigDataModel(
            mode="managed",
            network_os=LoopbackNetworkOSModel(
                policy=LoopbackPolicyModel(ip="10.1.1.1/32", admin_state=True),
            ),
        )
    assert instance.mode == "managed"
    assert instance.network_os.policy.ip == "10.1.1.1/32"
    assert instance.network_os.policy.admin_state is True


# =============================================================================
# Test: LoopbackInterfaceModel — Initialization
# =============================================================================


def test_loopback_interface_00200():
    """
    # Summary

    Verify ClassVars: identifiers and identifier_strategy.

    ## Test

    - identifiers == ["interface_name"]
    - identifier_strategy == "single"

    ## Classes and Methods

    - LoopbackInterfaceModel class attributes
    """
    assert LoopbackInterfaceModel.identifiers == ["interface_name"]
    assert LoopbackInterfaceModel.identifier_strategy == "single"


def test_loopback_interface_00210():
    """
    # Summary

    Verify interface_type defaults to "loopback".

    ## Test

    - Construct with only interface_name
    - interface_type defaults to "loopback"

    ## Classes and Methods

    - LoopbackInterfaceModel.__init__()
    """
    with does_not_raise():
        instance = LoopbackInterfaceModel(interface_name="loopback0")
    assert instance.interface_type == "loopback"


def test_loopback_interface_00220():
    """
    # Summary

    Verify config_data defaults to None.

    ## Test

    - Construct with only interface_name
    - config_data defaults to None

    ## Classes and Methods

    - LoopbackInterfaceModel.__init__()
    """
    instance = LoopbackInterfaceModel(interface_name="loopback0")
    assert instance.config_data is None


def test_loopback_interface_00230():
    """
    # Summary

    Verify interface_name is required — ValidationError without it.

    ## Test

    - Construct without interface_name
    - Raises ValidationError

    ## Classes and Methods

    - LoopbackInterfaceModel.__init__()
    """
    with pytest.raises(ValidationError):
        LoopbackInterfaceModel()


# =============================================================================
# Test: LoopbackInterfaceModel — Validators
# =============================================================================


def test_loopback_interface_00250():
    """
    # Summary

    Verify normalize_interface_name lowercases "Loopback0" to "loopback0".

    ## Test

    - Construct with interface_name="Loopback0"
    - Value normalized to "loopback0"

    ## Classes and Methods

    - LoopbackInterfaceModel.normalize_interface_name()
    """
    instance = LoopbackInterfaceModel(interface_name="Loopback0")
    assert instance.interface_name == "loopback0"


def test_loopback_interface_00251():
    """
    # Summary

    Verify normalize_interface_name lowercases "LOOPBACK1" to "loopback1".

    ## Test

    - Construct with interface_name="LOOPBACK1"
    - Value normalized to "loopback1"

    ## Classes and Methods

    - LoopbackInterfaceModel.normalize_interface_name()
    """
    instance = LoopbackInterfaceModel(interface_name="LOOPBACK1")
    assert instance.interface_name == "loopback1"


def test_loopback_interface_00252():
    """
    # Summary

    Verify already-lowercase passes through unchanged.

    ## Test

    - Construct with interface_name="loopback0"
    - Value unchanged

    ## Classes and Methods

    - LoopbackInterfaceModel.normalize_interface_name()
    """
    instance = LoopbackInterfaceModel(interface_name="loopback0")
    assert instance.interface_name == "loopback0"


# =============================================================================
# Test: LoopbackInterfaceModel — to_payload
# =============================================================================


def test_loopback_interface_00300():
    """
    # Summary

    Verify top-level keys are camelCase in payload.

    ## Test

    - to_payload() returns camelCase keys

    ## Classes and Methods

    - LoopbackInterfaceModel.to_payload()
    """
    instance = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    assert "interfaceName" in result
    assert "interfaceType" in result
    assert "configData" in result


def test_loopback_interface_00310():
    """
    # Summary

    Verify config_data=None excluded from payload output.

    ## Test

    - Construct with only interface_name
    - to_payload() does not include configData

    ## Classes and Methods

    - LoopbackInterfaceModel.to_payload()
    """
    instance = LoopbackInterfaceModel(interface_name="loopback0")
    result = instance.to_payload()
    assert "configData" not in result
    assert "interfaceName" in result


def test_loopback_interface_00320():
    """
    # Summary

    Verify nested aliases in payload: configData.networkOS.policy keys.

    ## Test

    - Nested keys use camelCase aliases

    ## Classes and Methods

    - LoopbackInterfaceModel.to_payload()
    """
    instance = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_payload()
    policy = result["configData"]["networkOS"]["policy"]
    assert "adminState" in policy
    assert "vrfInterface" in policy
    assert "policyType" in policy
    assert "routeMapTag" in policy


def test_loopback_interface_00330():
    """
    # Summary

    Verify policy_type serialized to camelCase in payload: ipfm_loopback -> ipfmLoopback.

    ## Test

    - policy_type="ipfm_loopback" becomes "ipfmLoopback" in payload

    ## Classes and Methods

    - LoopbackInterfaceModel.to_payload()
    - LoopbackPolicyModel.serialize_policy_type()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["config_data"]["network_os"]["policy"]["policy_type"] = "ipfm_loopback"
    instance = LoopbackInterfaceModel.from_config(config)
    result = instance.to_payload()
    assert result["configData"]["networkOS"]["policy"]["policyType"] == "ipfmLoopback"


# =============================================================================
# Test: LoopbackInterfaceModel — to_config
# =============================================================================


def test_loopback_interface_00350():
    """
    # Summary

    Verify top-level keys are snake_case in config.

    ## Test

    - to_config() returns snake_case keys

    ## Classes and Methods

    - LoopbackInterfaceModel.to_config()
    """
    instance = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    assert "interface_name" in result
    assert "interface_type" in result
    assert "config_data" in result


def test_loopback_interface_00360():
    """
    # Summary

    Verify nested keys in config: config_data.network_os.policy keys.

    ## Test

    - Nested keys use snake_case Python names

    ## Classes and Methods

    - LoopbackInterfaceModel.to_config()
    """
    instance = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    result = instance.to_config()
    policy = result["config_data"]["network_os"]["policy"]
    assert "admin_state" in policy
    assert "vrf" in policy
    assert "route_map_tag" in policy


def test_loopback_interface_00370():
    """
    # Summary

    Verify policy_type stays as ansible name in config mode.

    ## Test

    - policy_type="ipfm_loopback" stays as "ipfm_loopback" in config output

    ## Classes and Methods

    - LoopbackInterfaceModel.to_config()
    - LoopbackPolicyModel.serialize_policy_type()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["config_data"]["network_os"]["policy"]["policy_type"] = "ipfm_loopback"
    instance = LoopbackInterfaceModel.from_config(config)
    result = instance.to_config()
    assert result["config_data"]["network_os"]["policy"]["policy_type"] == "ipfm_loopback"


# =============================================================================
# Test: LoopbackInterfaceModel — from_response
# =============================================================================


def test_loopback_interface_00400():
    """
    # Summary

    Verify from_response constructs from SAMPLE_API_RESPONSE.

    ## Test

    - All fields accessible by Python names

    ## Classes and Methods

    - LoopbackInterfaceModel.from_response()
    """
    with does_not_raise():
        instance = LoopbackInterfaceModel.from_response(copy.deepcopy(SAMPLE_API_RESPONSE))
    assert instance.interface_name == "loopback0"
    assert instance.interface_type == "loopback"
    assert instance.config_data.mode == "managed"
    assert instance.config_data.network_os.policy.ip == "10.1.1.1/32"
    assert instance.config_data.network_os.policy.vrf == "management"
    assert instance.config_data.network_os.policy.admin_state is True


def test_loopback_interface_00410():
    """
    # Summary

    Verify from_response normalizes "Loopback0" to "loopback0".

    ## Test

    - API response with "Loopback0" is lowercased

    ## Classes and Methods

    - LoopbackInterfaceModel.from_response()
    - LoopbackInterfaceModel.normalize_interface_name()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["interfaceName"] = "Loopback0"
    instance = LoopbackInterfaceModel.from_response(response)
    assert instance.interface_name == "loopback0"


def test_loopback_interface_00420():
    """
    # Summary

    Verify from_response normalizes "ipfmLoopback" to "ipfm_loopback".

    ## Test

    - API response with policyType="ipfmLoopback" is normalized

    ## Classes and Methods

    - LoopbackInterfaceModel.from_response()
    - LoopbackPolicyModel.normalize_policy_type()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["policyType"] = "ipfmLoopback"
    instance = LoopbackInterfaceModel.from_response(response)
    assert instance.config_data.network_os.policy.policy_type == "ipfm_loopback"


def test_loopback_interface_00430():
    """
    # Summary

    Verify from_response ignores unknown keys (extra="ignore" in model config).

    ## Test

    - API response with extra keys does not raise

    ## Classes and Methods

    - LoopbackInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["unknownField"] = "should be ignored"
    response["configData"]["unknownNested"] = "also ignored"
    with does_not_raise():
        instance = LoopbackInterfaceModel.from_response(response)
    assert instance.interface_name == "loopback0"


# =============================================================================
# Test: LoopbackInterfaceModel — from_config
# =============================================================================


def test_loopback_interface_00450():
    """
    # Summary

    Verify from_config constructs from SAMPLE_ANSIBLE_CONFIG.

    ## Test

    - All fields correct

    ## Classes and Methods

    - LoopbackInterfaceModel.from_config()
    """
    with does_not_raise():
        instance = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance.interface_name == "loopback0"
    assert instance.interface_type == "loopback"
    assert instance.config_data.mode == "managed"
    assert instance.config_data.network_os.policy.ip == "10.1.1.1/32"
    assert instance.config_data.network_os.policy.vrf == "management"


def test_loopback_interface_00460():
    """
    # Summary

    Verify minimal config: only interface_name produces config_data=None.

    ## Test

    - Minimal config with just interface_name
    - config_data is None

    ## Classes and Methods

    - LoopbackInterfaceModel.from_config()
    """
    instance = LoopbackInterfaceModel.from_config({"interface_name": "loopback0"})
    assert instance.interface_name == "loopback0"
    assert instance.config_data is None


# =============================================================================
# Test: LoopbackInterfaceModel — Round-trip
# =============================================================================


def test_loopback_interface_00500():
    """
    # Summary

    Verify config -> from_config -> to_payload -> from_response -> to_config == original.

    ## Test

    - Round-trip through all serialization methods preserves data

    ## Classes and Methods

    - LoopbackInterfaceModel.from_config()
    - LoopbackInterfaceModel.to_payload()
    - LoopbackInterfaceModel.from_response()
    - LoopbackInterfaceModel.to_config()
    """
    original = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    instance = LoopbackInterfaceModel.from_config(original)
    payload = instance.to_payload()
    instance2 = LoopbackInterfaceModel.from_response(payload)
    result = instance2.to_config()
    assert result == original


def test_loopback_interface_00510():
    """
    # Summary

    Verify response -> from_response -> to_config -> from_config -> to_payload == original.

    ## Test

    - Round-trip starting from API response preserves data

    ## Classes and Methods

    - LoopbackInterfaceModel.from_response()
    - LoopbackInterfaceModel.to_config()
    - LoopbackInterfaceModel.from_config()
    - LoopbackInterfaceModel.to_payload()
    """
    original = copy.deepcopy(SAMPLE_API_RESPONSE)
    instance = LoopbackInterfaceModel.from_response(original)
    config = instance.to_config()
    instance2 = LoopbackInterfaceModel.from_config(config)
    result = instance2.to_payload()
    assert result == original


def test_loopback_interface_00520():
    """
    # Summary

    Verify policy_type round-trip: ipfm_loopback (config) -> ipfmLoopback (payload) -> ipfm_loopback (config).

    ## Test

    - policy_type correctly converts between formats in round-trip

    ## Classes and Methods

    - LoopbackPolicyModel.normalize_policy_type()
    - LoopbackPolicyModel.serialize_policy_type()
    """
    config = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config["config_data"]["network_os"]["policy"]["policy_type"] = "ipfm_loopback"

    instance = LoopbackInterfaceModel.from_config(config)
    payload = instance.to_payload()
    assert payload["configData"]["networkOS"]["policy"]["policyType"] == "ipfmLoopback"

    instance2 = LoopbackInterfaceModel.from_response(payload)
    result_config = instance2.to_config()
    assert result_config["config_data"]["network_os"]["policy"]["policy_type"] == "ipfm_loopback"


# =============================================================================
# Test: LoopbackInterfaceModel — Identifier
# =============================================================================


def test_loopback_interface_00550():
    """
    # Summary

    Verify get_identifier_value() returns "loopback0".

    ## Test

    - get_identifier_value() returns the interface_name

    ## Classes and Methods

    - LoopbackInterfaceModel.get_identifier_value()
    """
    instance = LoopbackInterfaceModel(interface_name="loopback0")
    assert instance.get_identifier_value() == "loopback0"


def test_loopback_interface_00560():
    """
    # Summary

    Verify get_identifier_value returns lowercased value when constructed with "Loopback1".

    ## Test

    - Constructed with "Loopback1"
    - get_identifier_value() returns "loopback1"

    ## Classes and Methods

    - LoopbackInterfaceModel.get_identifier_value()
    - LoopbackInterfaceModel.normalize_interface_name()
    """
    instance = LoopbackInterfaceModel(interface_name="Loopback1")
    assert instance.get_identifier_value() == "loopback1"


# =============================================================================
# Test: LoopbackInterfaceModel — get_diff
# =============================================================================


def test_loopback_interface_00600():
    """
    # Summary

    Verify identical models -> True (other is subset of self).

    ## Test

    - Two identical models
    - get_diff returns True

    ## Classes and Methods

    - LoopbackInterfaceModel.get_diff()
    """
    instance1 = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    instance2 = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    assert instance1.get_diff(instance2) is True


def test_loopback_interface_00610():
    """
    # Summary

    Verify different ip -> False.

    ## Test

    - Two models with different ip
    - get_diff returns False

    ## Classes and Methods

    - LoopbackInterfaceModel.get_diff()
    """
    config1 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2 = copy.deepcopy(SAMPLE_ANSIBLE_CONFIG)
    config2["config_data"]["network_os"]["policy"]["ip"] = "10.2.2.2/32"
    instance1 = LoopbackInterfaceModel.from_config(config1)
    instance2 = LoopbackInterfaceModel.from_config(config2)
    assert instance1.get_diff(instance2) is False


def test_loopback_interface_00620():
    """
    # Summary

    Verify other with fewer fields (None excluded) -> True (subset).

    ## Test

    - other has fewer fields than self
    - get_diff returns True (other is subset of self)

    ## Classes and Methods

    - LoopbackInterfaceModel.get_diff()
    """
    instance_full = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    instance_minimal = LoopbackInterfaceModel(interface_name="loopback0")
    assert instance_full.get_diff(instance_minimal) is True


# =============================================================================
# Test: LoopbackInterfaceModel — merge
# =============================================================================


def test_loopback_interface_00650():
    """
    # Summary

    Verify non-None fields from other update self.

    ## Test

    - Merge other with ip set into self without ip
    - Self now has ip from other

    ## Classes and Methods

    - LoopbackInterfaceModel.merge()
    """
    config_base = {
        "interface_name": "loopback0",
        "config_data": {
            "network_os": {
                "policy": {
                    "admin_state": True,
                },
            },
        },
    }
    config_other = {
        "interface_name": "loopback0",
        "config_data": {
            "network_os": {
                "policy": {
                    "ip": "10.1.1.1/32",
                },
            },
        },
    }
    instance = LoopbackInterfaceModel.from_config(config_base)
    other = LoopbackInterfaceModel.from_config(config_other)
    instance.merge(other)
    assert instance.config_data.network_os.policy.ip == "10.1.1.1/32"


def test_loopback_interface_00660():
    """
    # Summary

    Verify None fields in other do not overwrite existing values.

    ## Test

    - Self has ip set, other has ip=None (config_data=None)
    - After merge, self still has ip

    ## Classes and Methods

    - LoopbackInterfaceModel.merge()
    """
    instance = LoopbackInterfaceModel.from_config(copy.deepcopy(SAMPLE_ANSIBLE_CONFIG))
    other = LoopbackInterfaceModel(interface_name="loopback0")
    instance.merge(other)
    assert instance.config_data.network_os.policy.ip == "10.1.1.1/32"


def test_loopback_interface_00670():
    """
    # Summary

    Verify mismatched types -> TypeError.

    ## Test

    - Merge with wrong type raises TypeError

    ## Classes and Methods

    - LoopbackInterfaceModel.merge()
    """
    instance = LoopbackInterfaceModel(interface_name="loopback0")
    with pytest.raises(TypeError, match="Cannot merge"):
        instance.merge(LoopbackPolicyModel())


def test_loopback_interface_00680():
    """
    # Summary

    Verify merge returns self for chaining.

    ## Test

    - merge() returns self

    ## Classes and Methods

    - LoopbackInterfaceModel.merge()
    """
    instance = LoopbackInterfaceModel(interface_name="loopback0")
    other = LoopbackInterfaceModel(interface_name="loopback0")
    result = instance.merge(other)
    assert result is instance


# =============================================================================
# Test: LoopbackInterfaceModel — get_argument_spec
# =============================================================================


def test_loopback_interface_00700():
    """
    # Summary

    Verify top-level keys in argument spec.

    ## Test

    - get_argument_spec() returns fabric_name, switch_ip, config, state

    ## Classes and Methods

    - LoopbackInterfaceModel.get_argument_spec()
    """
    spec = LoopbackInterfaceModel.get_argument_spec()
    assert "fabric_name" in spec
    assert "switch_ip" in spec
    assert "config" in spec
    assert "state" in spec


def test_loopback_interface_00710():
    """
    # Summary

    Verify config is type="list", elements="dict", has nested options.

    ## Test

    - config spec has correct type, elements, and options

    ## Classes and Methods

    - LoopbackInterfaceModel.get_argument_spec()
    """
    spec = LoopbackInterfaceModel.get_argument_spec()
    config_spec = spec["config"]
    assert config_spec["type"] == "list"
    assert config_spec["elements"] == "dict"
    assert "options" in config_spec
    assert "interface_name" in config_spec["options"]


def test_loopback_interface_00720():
    """
    # Summary

    Verify state choices and default.

    ## Test

    - state choices: ["merged", "replaced", "overridden", "deleted"]
    - state default: "merged"

    ## Classes and Methods

    - LoopbackInterfaceModel.get_argument_spec()
    """
    spec = LoopbackInterfaceModel.get_argument_spec()
    state_spec = spec["state"]
    assert state_spec["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert state_spec["default"] == "merged"


def test_loopback_interface_00730():
    """
    # Summary

    Verify policy_type choices from mapping and default.

    ## Test

    - policy_type choices: ["loopback", "ipfm_loopback", "user_defined"]
    - policy_type default: "loopback"

    ## Classes and Methods

    - LoopbackInterfaceModel.get_argument_spec()
    """
    spec = LoopbackInterfaceModel.get_argument_spec()
    policy_spec = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]["policy"]["options"]["policy_type"]
    assert policy_spec["choices"] == ["loopback", "ipfm_loopback", "user_defined"]
    assert policy_spec["default"] == "loopback"
