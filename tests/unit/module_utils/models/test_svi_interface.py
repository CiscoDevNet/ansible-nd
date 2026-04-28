# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for svi_interface.py

Tests the SVI (switched virtual interface) Pydantic model classes.
"""

# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-many-lines

from __future__ import annotations

import copy
from contextlib import contextmanager

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import (
    SviConfigDataModel,
    SviInterfaceModel,
    SviNetworkOSModel,
    SviOperDataModel,
    SviPolicyModel,
)
from pydantic import ValidationError


@contextmanager
def does_not_raise():
    """A context manager that does not raise an exception."""
    yield


# =============================================================================
# Test data constants
# =============================================================================

SAMPLE_API_RESPONSE = {
    "switchIp": "192.168.1.1",
    "interfaceName": "vlan333",
    "interfaceType": "svi",
    "switchId": "9NIE7U0ZXHZ",
    "configData": {
        "mode": "managed",
        "networkOS": {
            "networkOSType": "nx-os",
            "policy": {
                "policyType": "svi",
                "adminState": True,
                "advertiseSubnetInUnderlay": False,
                "description": "Sample SVI",
                "hsrpGroup": 1,
                "ip": "10.99.99.1",
                "ipRedirects": True,
                "netflow": False,
                "pimDrPriority": 1,
                "pimSparse": False,
                "preempt": False,
                "prefix": 24,
            },
        },
    },
    "operData": {
        "adminStatus": "up",
        "operationalDescription": "VLAN/BD is down",
        "operationalStatus": "down",
        "portChannelId": -1,
        "switchName": "LE1",
        "vlanRange": "-1",
    },
}

SAMPLE_ANSIBLE_CONFIG = {
    "switch_ip": "192.168.1.1",
    "interface_name": "vlan333",
    "interface_type": "svi",
    "config_data": {
        "mode": "managed",
        "network_os": {
            "network_os_type": "nx-os",
            "policy": {
                "policy_type": "svi",
                "admin_state": True,
                "advertise_subnet_in_underlay": False,
                "description": "Sample SVI",
                "hsrp_group": 1,
                "ip": "10.99.99.1",
                "ip_redirects": True,
                "netflow": False,
                "pim_dr_priority": 1,
                "pim_sparse": False,
                "preempt": False,
                "prefix": 24,
            },
        },
    },
}


# =============================================================================
# Test: SviPolicyModel — initialization and defaults
# =============================================================================


def test_svi_interface_00100():
    """
    # Summary

    Verify every policy field defaults to None except `policy_type` which defaults to `SviPolicyTypeEnum.SVI`.

    ## Test

    - Instantiate with no arguments
    - All optional fields are None
    - policy_type defaults to "svi"

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SviPolicyModel()
    assert instance.policy_type == "svi"
    assert instance.admin_state is None
    assert instance.description is None
    assert instance.extra_config is None
    assert instance.mtu is None
    assert instance.ip is None
    assert instance.prefix is None
    assert instance.ipv6 is None
    assert instance.v6prefix is None
    assert instance.ip_redirects is None
    assert instance.pim_sparse is None
    assert instance.pim_dr_priority is None
    assert instance.hsrp_group is None
    assert instance.hsrp_version is None
    assert instance.preempt is None
    assert instance.advertise_subnet_in_underlay is None
    assert instance.netflow is None


def test_svi_interface_00110():
    """
    # Summary

    Verify construction with snake_case field names.

    ## Test

    - Construct with Python field names
    - Values accessible

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SviPolicyModel(
            admin_state=True,
            description="test",
            ip="10.0.0.1",
            prefix=24,
            mtu=9216,
            policy_type="svi",
        )
    assert instance.admin_state is True
    assert instance.description == "test"
    assert instance.ip == "10.0.0.1"
    assert instance.prefix == 24
    assert instance.mtu == 9216
    assert instance.policy_type == "svi"


def test_svi_interface_00120():
    """
    # Summary

    Verify construction with camelCase aliases.

    ## Test

    - Construct with API alias names
    - Values accessible by Python names

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        instance = SviPolicyModel(
            adminState=True,
            ipRedirects=True,
            pimDrPriority=5,
            advertiseSubnetInUnderlay=True,
            policyType="svi",
        )
    assert instance.admin_state is True
    assert instance.ip_redirects is True
    assert instance.pim_dr_priority == 5
    assert instance.advertise_subnet_in_underlay is True
    assert instance.policy_type == "svi"


# =============================================================================
# Test: SviPolicyModel — description ASCII validator
# =============================================================================


@pytest.mark.parametrize(
    "value,should_raise",
    [
        ("plain ASCII", False),
        ("with-hyphen and 123", False),
        ("", False),  # max_length lower bound 0 acceptable here, validator only checks ASCII
        (None, False),
        ("em — dash", True),
        ("smart “quotes”", True),
        ("emoji \U0001f600", True),
        ("latin-1 \xe9", True),
    ],
    ids=[
        "ascii_ok",
        "ascii_punct_digits",
        "empty_string",
        "none_passthrough",
        "em_dash_rejected",
        "smart_quotes_rejected",
        "emoji_rejected",
        "latin1_rejected",
    ],
)
def test_svi_interface_00130(value, should_raise):
    """
    # Summary

    Verify `description` (typed `AsciiDescription`) rejects any non-ASCII character.

    Cisco backend pipes interface descriptions through CLI generators that 500 on UTF-8. Catching this client-side
    gives users a clear error instead of a generic "unexpected error during policy execution" 500.

    ## Test

    - ASCII strings (including empty and None) accepted
    - Any non-ASCII character (em-dash, smart quotes, emoji, latin-1) raises

    ## Classes and Methods

    - SviPolicyModel.__init__()
    - models.types.ascii_only()
    """
    if should_raise:
        with pytest.raises(ValidationError, match="description must contain only ASCII"):
            SviPolicyModel(description=value)
    else:
        with does_not_raise():
            instance = SviPolicyModel(description=value)
        assert instance.description == value


# =============================================================================
# Test: SviPolicyModel — policy_type normalize and serialize
# =============================================================================


@pytest.mark.parametrize(
    "value,expected,raises",
    [
        ("svi", "svi", False),
        ("unknown_value", None, True),
        (None, None, True),
    ],
    ids=[
        "ansible_name_passthrough",
        "unknown_rejected_by_enum",
        "none_rejected_field_required_with_default",
    ],
)
def test_svi_interface_00170(value, expected, raises):
    """
    # Summary

    Verify `normalize_policy_type` accepts the Ansible/API name and rejects unknown values. `None` is also rejected
    because `policy_type` is a non-optional field carrying a default — the API requires it on every PUT/POST.

    ## Test

    - "svi" passes through
    - Unknown values fail enum validation
    - None is rejected (field is required-with-default, not Optional)

    ## Classes and Methods

    - SviPolicyModel.normalize_policy_type()
    """
    if raises:
        with pytest.raises(ValidationError):
            SviPolicyModel(policy_type=value)
    else:
        with does_not_raise():
            instance = SviPolicyModel(policy_type=value)
        assert instance.policy_type == expected


@pytest.mark.parametrize(
    "stored_value,mode,expected",
    [
        ("svi", "payload", "svi"),
        ("svi", "config", "svi"),
        ("svi", None, "svi"),
        (None, "payload", None),
    ],
    ids=[
        "payload_mode",
        "config_mode",
        "default_mode_payload",
        "none_value",
    ],
)
def test_svi_interface_00180(stored_value, mode, expected):
    """
    # Summary

    Verify `serialize_policy_type` returns the API value in payload mode and the Ansible name in config mode. For SVI
    these happen to be identical, but the validator-serializer pair is preserved for symmetry with ethernet models.

    ## Test

    - payload mode returns API value
    - config mode returns Ansible name
    - None passes through

    ## Classes and Methods

    - SviPolicyModel.serialize_policy_type()
    """
    instance = SviPolicyModel(policy_type=stored_value) if stored_value else SviPolicyModel()
    if stored_value is None:
        # field default kicks in; result is "svi" not None — adjust expectation
        if mode == "payload":
            data = instance.model_dump(by_alias=True, context={"mode": "payload"})
        else:
            data = instance.model_dump(by_alias=False, context={"mode": "config"})
        assert data.get("policyType" if mode == "payload" else "policy_type") == "svi"
        return
    if mode == "payload":
        data = instance.model_dump(by_alias=True, context={"mode": "payload"})
        assert data["policyType"] == expected
    elif mode == "config":
        data = instance.model_dump(by_alias=False, context={"mode": "config"})
        assert data["policy_type"] == expected
    else:
        data = instance.model_dump(by_alias=True)
        assert data["policyType"] == expected


# =============================================================================
# Test: SviPolicyModel — range validation
# =============================================================================


@pytest.mark.parametrize(
    "field,value,should_raise",
    [
        ("mtu", 576, False),
        ("mtu", 9216, False),
        ("mtu", 575, True),
        ("mtu", 9217, True),
        ("prefix", 1, False),
        ("prefix", 31, False),
        ("prefix", 0, True),
        ("prefix", 32, True),
        ("v6prefix", 1, False),
        ("v6prefix", 127, False),
        ("v6prefix", 0, True),
        ("v6prefix", 128, True),
        ("pim_dr_priority", 1, False),
        ("pim_dr_priority", 4294967295, False),
        ("pim_dr_priority", 0, True),
        ("pim_dr_priority", 4294967296, True),
    ],
    ids=lambda v: str(v) if not isinstance(v, bool) else ("raise" if v else "ok"),
)
def test_svi_interface_00220(field, value, should_raise):
    """
    # Summary

    Verify ge/le constraints on every numeric policy field.

    ## Test

    - At-min and at-max values accepted
    - Below-min and above-max values rejected with ValidationError

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    if should_raise:
        with pytest.raises(ValidationError):
            SviPolicyModel(**{field: value})
    else:
        with does_not_raise():
            instance = SviPolicyModel(**{field: value})
        assert getattr(instance, field) == value


def test_svi_interface_00230():
    """
    # Summary

    Verify `description` max_length=254.

    ## Test

    - 254 characters accepted
    - 255 characters rejected

    ## Classes and Methods

    - SviPolicyModel.__init__()
    """
    with does_not_raise():
        SviPolicyModel(description="a" * 254)
    with pytest.raises(ValidationError):
        SviPolicyModel(description="a" * 255)


# =============================================================================
# Test: SviPolicyModel — payload / config serialization
# =============================================================================


def test_svi_interface_00300():
    """
    # Summary

    Verify `to_payload`-style serialization (model_dump with aliases, exclude_none) emits camelCase keys.

    ## Test

    - Construct with snake_case
    - Dump with by_alias=True
    - Output uses API camelCase keys

    ## Classes and Methods

    - SviPolicyModel.model_dump()
    """
    instance = SviPolicyModel(
        admin_state=True,
        description="payload",
        ip_redirects=True,
        pim_dr_priority=2,
        advertise_subnet_in_underlay=True,
    )
    data = instance.model_dump(by_alias=True, exclude_none=True)
    assert data["adminState"] is True
    assert data["description"] == "payload"
    assert data["ipRedirects"] is True
    assert data["pimDrPriority"] == 2
    assert data["advertiseSubnetInUnderlay"] is True
    assert "admin_state" not in data
    assert "ip_redirects" not in data


# =============================================================================
# Test: SviNetworkOSModel
# =============================================================================


def test_svi_interface_00400():
    """
    # Summary

    Verify default values for SviNetworkOSModel.

    ## Test

    - network_os_type defaults to "nx-os"
    - policy defaults to None

    ## Classes and Methods

    - SviNetworkOSModel.__init__()
    """
    instance = SviNetworkOSModel()
    assert instance.network_os_type == "nx-os"
    assert instance.policy is None


def test_svi_interface_00410():
    """
    # Summary

    Verify SviNetworkOSModel accepts a SviPolicyModel as the `policy` field.

    ## Test

    - Pass a populated policy
    - Access through the network OS container

    ## Classes and Methods

    - SviNetworkOSModel.__init__()
    """
    policy = SviPolicyModel(admin_state=True, description="net-os")
    instance = SviNetworkOSModel(policy=policy)
    assert instance.policy is not None
    assert instance.policy.admin_state is True
    assert instance.policy.description == "net-os"


# =============================================================================
# Test: SviConfigDataModel
# =============================================================================


def test_svi_interface_00500():
    """
    # Summary

    Verify SviConfigDataModel defaults — `mode` is "managed" and `network_os` is required.

    ## Test

    - Construct with only network_os
    - mode defaults to "managed"

    ## Classes and Methods

    - SviConfigDataModel.__init__()
    """
    nos = SviNetworkOSModel(policy=SviPolicyModel(admin_state=True))
    instance = SviConfigDataModel(network_os=nos)
    assert instance.mode == "managed"
    assert instance.network_os is not None


def test_svi_interface_00510():
    """
    # Summary

    Verify SviConfigDataModel rejects construction without network_os.

    ## Test

    - Construct with no network_os
    - ValidationError raised

    ## Classes and Methods

    - SviConfigDataModel.__init__()
    """
    with pytest.raises(ValidationError):
        SviConfigDataModel()  # network_os is required


# =============================================================================
# Test: SviOperDataModel — read-only operational data
# =============================================================================


def test_svi_interface_00600():
    """
    # Summary

    Verify SviOperDataModel parses GET-side aliases.

    ## Test

    - Construct with camelCase aliases
    - Access by snake_case fields

    ## Classes and Methods

    - SviOperDataModel.__init__()
    """
    instance = SviOperDataModel(
        adminStatus="up",
        operationalDescription="VLAN/BD is down",
        operationalStatus="down",
        portChannelId=-1,
        switchName="LE1",
        vlanRange="-1",
    )
    assert instance.admin_status == "up"
    assert instance.operational_description == "VLAN/BD is down"
    assert instance.operational_status == "down"
    assert instance.port_channel_id == -1
    assert instance.switch_name == "LE1"
    assert instance.vlan_range == "-1"


# =============================================================================
# Test: SviInterfaceModel — interface_name normalization
# =============================================================================


@pytest.mark.parametrize(
    "value,expected",
    [
        ("vlan333", "vlan333"),
        ("Vlan333", "vlan333"),
        ("VLAN333", "vlan333"),
        ("vLaN333", "vlan333"),
        ("333", "vlan333"),
        (333, "vlan333"),
        ("  333  ", "vlan333"),
    ],
    ids=[
        "lowercase_passthrough",
        "title_case",
        "all_caps",
        "mixed_case",
        "bare_digit_string",
        "bare_int",
        "padded_digit_string",
    ],
)
def test_svi_interface_00700(value, expected):
    """
    # Summary

    Verify `normalize_interface_name` converts all common forms to the lowercase API form `vlan<id>`.

    ## Test

    - Title / mixed / all-caps cased forms normalize to lowercase `vlan<id>`
    - Bare integer (or its string form) is prefixed with `vlan`

    ## Classes and Methods

    - SviInterfaceModel.normalize_interface_name()
    """
    instance = SviInterfaceModel(switch_ip="1.2.3.4", interface_name=value)
    assert instance.interface_name == expected


# =============================================================================
# Test: SviInterfaceModel — composite identifier
# =============================================================================


def test_svi_interface_00800():
    """
    # Summary

    Verify identifier configuration: composite `(switch_ip, interface_name)`.

    ## Test

    - identifier_strategy is "composite"
    - identifiers is ["switch_ip", "interface_name"]
    - get_identifier_value returns the tuple

    ## Classes and Methods

    - SviInterfaceModel — class attributes
    - SviInterfaceModel.get_identifier_value()
    """
    assert SviInterfaceModel.identifier_strategy == "composite"
    assert SviInterfaceModel.identifiers == ["switch_ip", "interface_name"]
    instance = SviInterfaceModel(switch_ip="1.2.3.4", interface_name="vlan333")
    assert instance.get_identifier_value() == ("1.2.3.4", "vlan333")


def test_svi_interface_00810():
    """
    # Summary

    Verify `payload_exclude_fields` excludes `switch_ip` and `oper_data` from `to_payload`.

    ## Test

    - Construct with all top-level fields
    - to_payload omits switch_ip and operData

    ## Classes and Methods

    - SviInterfaceModel.to_payload()
    """
    instance = SviInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()
    assert "switchIp" not in payload
    assert "operData" not in payload
    # Verify the remaining top-level shape
    assert payload["interfaceName"] == "vlan333"
    assert payload["interfaceType"] == "svi"


# =============================================================================
# Test: SviInterfaceModel — from_response strips hsrpVersion
# =============================================================================


def test_svi_interface_00900():
    """
    # Summary

    Verify `from_response` strips `hsrpVersion` (poison field) and preserves `hsrpGroup` (round-trips fine).

    ND's GET returns `hsrpVersion: 1` (integer) as a server-side default even when HSRP is unconfigured. Re-emitting
    that on PUT triggers a generic 500. `hsrpGroup: 1` is benign on round-trip.

    ## Test

    - Response with hsrpGroup=1 and hsrpVersion=1
    - Model has hsrp_group=1 and hsrp_version=None
    - to_payload() includes hsrpGroup but not hsrpVersion

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["hsrpVersion"] = 1
    response["configData"]["networkOS"]["policy"]["hsrpGroup"] = 1

    instance = SviInterfaceModel.from_response(response)
    policy = instance.config_data.network_os.policy
    assert policy.hsrp_group == 1
    assert policy.hsrp_version is None

    payload = instance.to_payload()
    policy_payload = payload["configData"]["networkOS"]["policy"]
    assert policy_payload["hsrpGroup"] == 1
    assert "hsrpVersion" not in policy_payload


def test_svi_interface_00910():
    """
    # Summary

    Verify `from_response` does not mutate the caller's input dict.

    ## Test

    - Response includes hsrpVersion
    - After from_response, response still includes hsrpVersion

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    """
    response = copy.deepcopy(SAMPLE_API_RESPONSE)
    response["configData"]["networkOS"]["policy"]["hsrpVersion"] = 1

    SviInterfaceModel.from_response(response)
    # Caller's dict must be untouched
    assert response["configData"]["networkOS"]["policy"]["hsrpVersion"] == 1


def test_svi_interface_00920():
    """
    # Summary

    Verify `from_response` is robust to missing nested structures.

    ## Test

    - Response with no configData
    - Response with configData but no networkOS
    - Response with networkOS but no policy
    - All return a valid model without raising

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    """
    minimal = {
        "switchIp": "1.2.3.4",
        "interfaceName": "vlan333",
        "switchId": "X",
    }
    with does_not_raise():
        SviInterfaceModel.from_response(minimal)

    no_policy = copy.deepcopy(minimal)
    no_policy["configData"] = {"mode": "managed", "networkOS": {"networkOSType": "nx-os"}}
    with does_not_raise():
        SviInterfaceModel.from_response(no_policy)


# =============================================================================
# Test: SviInterfaceModel — round-trip from_response -> to_payload
# =============================================================================


def test_svi_interface_01000():
    """
    # Summary

    Verify a full GET response round-trips through from_response and to_payload, producing the same shape minus
    excluded fields and stripped hsrpVersion.

    ## Test

    - Build model from SAMPLE_API_RESPONSE
    - to_payload result matches expected

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.to_payload()
    """
    instance = SviInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    payload = instance.to_payload()

    expected_policy_keys = {
        "policyType",
        "adminState",
        "advertiseSubnetInUnderlay",
        "description",
        "hsrpGroup",
        "ip",
        "ipRedirects",
        "netflow",
        "pimDrPriority",
        "pimSparse",
        "preempt",
        "prefix",
    }
    assert set(payload["configData"]["networkOS"]["policy"].keys()) == expected_policy_keys
    assert payload["interfaceName"] == "vlan333"
    assert payload["interfaceType"] == "svi"
    assert payload["configData"]["mode"] == "managed"
    assert payload["configData"]["networkOS"]["networkOSType"] == "nx-os"


def test_svi_interface_01010():
    """
    # Summary

    Verify from_config (Ansible-side snake_case) produces an equivalent model to from_response (API-side camelCase).

    ## Test

    - Build model A from SAMPLE_API_RESPONSE
    - Build model B from SAMPLE_ANSIBLE_CONFIG
    - to_payload outputs match

    ## Classes and Methods

    - SviInterfaceModel.from_response()
    - SviInterfaceModel.from_config()
    """
    a = SviInterfaceModel.from_response(SAMPLE_API_RESPONSE)
    b = SviInterfaceModel.from_config(SAMPLE_ANSIBLE_CONFIG)
    # b has no oper_data so payloads should match (oper_data excluded from payload anyway)
    assert a.to_payload() == b.to_payload()


# =============================================================================
# Test: SviInterfaceModel — get_argument_spec
# =============================================================================


def test_svi_interface_01100():
    """
    # Summary

    Verify the argument spec exposes the expected top-level keys and required structure.

    ## Test

    - fabric_name is required str
    - config is required list-of-dict
    - state is enum with merged/replaced/overridden/deleted
    - policy options include the phase 1 writable fields

    ## Classes and Methods

    - SviInterfaceModel.get_argument_spec()
    """
    spec = SviInterfaceModel.get_argument_spec()
    assert spec["fabric_name"]["type"] == "str"
    assert spec["fabric_name"]["required"] is True
    assert spec["config"]["type"] == "list"
    assert spec["config"]["required"] is True
    assert spec["state"]["choices"] == ["merged", "replaced", "overridden", "deleted"]
    assert spec["state"]["default"] == "merged"

    config_options = spec["config"]["options"]
    assert config_options["switch_ip"]["required"] is True
    assert config_options["vlan_ids"]["type"] == "list"
    assert config_options["vlan_ids"]["elements"] == "int"
    assert config_options["vlan_ids"]["required"] is True
    assert config_options["interface_type"]["default"] == "svi"

    policy_options = config_options["config_data"]["options"]["network_os"]["options"]["policy"]["options"]
    expected_policy_fields = {
        "policy_type",
        "admin_state",
        "description",
        "extra_config",
        "mtu",
        "ip",
        "prefix",
        "ipv6",
        "v6prefix",
        "ip_redirects",
        "pim_sparse",
        "pim_dr_priority",
        "hsrp_group",
        "hsrp_version",
        "preempt",
        "advertise_subnet_in_underlay",
        "netflow",
    }
    assert set(policy_options.keys()) == expected_policy_fields
    assert policy_options["policy_type"]["choices"] == ["svi"]
    assert policy_options["policy_type"]["default"] == "svi"


# =============================================================================
# Test: SviInterfaceModel — interface_type default
# =============================================================================


def test_svi_interface_01200():
    """
    # Summary

    Verify `interface_type` defaults to "svi".

    ## Test

    - Construct without interface_type
    - Field equals "svi"

    ## Classes and Methods

    - SviInterfaceModel.__init__()
    """
    instance = SviInterfaceModel(switch_ip="1.2.3.4", interface_name="vlan333")
    assert instance.interface_type == "svi"
