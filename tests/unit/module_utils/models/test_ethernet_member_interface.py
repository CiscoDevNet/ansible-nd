# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Focused tests for the internal ethernet port-channel member model layer."""

from __future__ import annotations

import copy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_member_interface import (
    MEMBER_POLICY_DESCRIPTORS,
    EthernetMemberInterfaceModel,
    MemberPolicyDisposition,
    UnmodeledMemberConfigurationError,
    UnsafeMemberUpdateError,
    UnsupportedMemberPolicyError,
    build_member_update_payload,
    classify_member_policy,
    get_member_policy_descriptor,
    is_member_policy,
    is_supported_member_policy,
    normalize_port_channel_id,
    normalize_safe_member_updates,
    parse_member_interface_response,
)
from pydantic import ValidationError


def member_record(policy_type="poMember", *, mode="trunk", network_os="nx-os"):
    """Return an authentic-shaped member inventory record with response-only noise."""

    policy = {
        "policyType": policy_type,
        "portChannelId": "port-channel20",
        "portChannelMode": "active",
        "description": "existing member",
        "extraConfig": "logging event link-status",
        "adminState": True,
    }
    if network_os == "nx-os":
        policy["ptp"] = False
    if policy_type in {"poMember", "vpcMember"}:
        policy.update(
            {
                "allowedVlans": "1-100",
                "cdp": True,
                "lacpPortPriority": 32768,
                "lacpRate": "fast",
                "debounceTimer": 100,
                "debounceLinkupTimer": 1000,
                "fec": "auto",
            }
        )
    if policy_type in {"accessPoMember", "accessVpcPoMember"}:
        policy.update(
            {
                "cdp": False,
                "lacpPortPriority": 100,
                "lacpRate": "normal",
                "debounceTimer": 200,
                "debounceLinkupTimer": 2000,
                "fec": "off",
            }
        )
    if policy_type in {"vpcMember", "accessVpcPoMember"}:
        policy["primaryInterface"] = "vPC20"
    return {
        "switchId": "SERIAL1",
        "switchIp": "192.0.2.10",
        "interfaceName": "Ethernet1/24",
        "interfaceType": "ethernet",
        "configData": {
            "mode": mode,
            "networkOS": {"networkOSType": network_os, "policy": policy},
        },
        "operData": {"portChannelId": 20, "adminStatus": "up"},
        "fabricName": "fabric1",
    }


@pytest.mark.parametrize(
    "policy_type,family,network_os,wire_mode,parent_type,parent_policy,parent_mode,parent_os,pair_aware",
    [
        ("poMember", "trunk", "nx-os", "trunk", "portChannel", "trunkPoHost", "trunk", "nx-os", False),
        (
            "accessPoMember",
            "access",
            "nx-os",
            "access",
            "portChannel",
            "accessPoHost",
            "access",
            "nx-os",
            False,
        ),
        ("l3PoMember", "routed", "nx-os", "routed", "portChannel", "l3Po", "routed", "nx-os", False),
        (
            "iosXeL3PoMember",
            "routed",
            "ios-xe",
            "routed",
            "portChannel",
            "iosXeL3PortChannel",
            "routed",
            "ios-xe",
            False,
        ),
        ("vpcMember", "trunk", "nx-os", "trunk", "vpc", "trunkVpcHost", "trunk", "nx-os", True),
        (
            "accessVpcPoMember",
            "access",
            "nx-os",
            "access",
            "vpc",
            "accessVpcHost",
            "access",
            "nx-os",
            True,
        ),
    ],
)
def test_member_policy_descriptor_metadata(
    policy_type,
    family,
    network_os,
    wire_mode,
    parent_type,
    parent_policy,
    parent_mode,
    parent_os,
    pair_aware,
):
    descriptor = get_member_policy_descriptor(policy_type)
    assert descriptor is not None
    assert descriptor.family == family
    assert descriptor.network_os == network_os
    assert descriptor.wire_mode == wire_mode
    assert descriptor.parent_interface_type == parent_type
    assert descriptor.parent_policy_types == (parent_policy,)
    assert descriptor.parent_wire_mode == parent_mode
    assert descriptor.parent_network_os == parent_os
    assert descriptor.pair_aware is pair_aware


def test_member_policy_classification_fails_closed():
    assert classify_member_policy("poMember") == MemberPolicyDisposition.SUPPORTED
    assert classify_member_policy("vpcMember") == MemberPolicyDisposition.PAIR_AWARE
    assert classify_member_policy("l3PoMemberInternal") == MemberPolicyDisposition.PROTECTED
    assert classify_member_policy("futureControllerMember") == MemberPolicyDisposition.PROTECTED
    assert classify_member_policy("trunkHost") == MemberPolicyDisposition.NOT_MEMBER
    assert is_member_policy("futureControllerMember") is True
    assert is_supported_member_policy("vpcMember") is False
    assert is_supported_member_policy("vpcMember", include_pair_aware=True) is True


@pytest.mark.parametrize(
    "value,expected",
    [
        (20, 20),
        ("20", 20),
        ("Port-channel20", 20),
        ("portchannel20", 20),
        (" PORT-CHANNEL 20 ", 20),
        (-1, None),
        ("-1", None),
        (None, None),
    ],
)
def test_normalize_port_channel_id(value, expected):
    assert normalize_port_channel_id(value) == expected


@pytest.mark.parametrize("value", [True, "Ethernet1/1", "Port-channel4097", 4097, 0, "0", -2, "-2", object()])
def test_normalize_port_channel_id_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        normalize_port_channel_id(value)


@pytest.mark.parametrize(
    "policy_type,mode,network_os",
    [
        ("poMember", "trunk", "nx-os"),
        ("accessPoMember", "access", "nx-os"),
        ("l3PoMember", "routed", "nx-os"),
        ("iosXeL3PoMember", "routed", "ios-xe"),
        ("vpcMember", "trunk", "nx-os"),
        ("accessVpcPoMember", "access", "nx-os"),
    ],
)
def test_parse_all_modeled_member_policies(policy_type, mode, network_os):
    model = parse_member_interface_response(member_record(policy_type, mode=mode, network_os=network_os))
    assert isinstance(model, EthernetMemberInterfaceModel)
    assert model.policy_type == policy_type
    assert model.descriptor == MEMBER_POLICY_DESCRIPTORS[policy_type]
    assert model.normalized_port_channel_id == 20


def test_parse_access_po_member_captured_nd_wire_shape():
    """Intent mode is access even when operational mode reports trunk."""

    captured_record = {
        "interfaceName": "Ethernet1/46",
        "interfaceType": "ethernet",
        "switchId": "SERIAL1",
        "configData": {
            "mode": "access",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "accessPoMember",
                    "portChannelId": "port-channel901",
                    "portMode": "normal",
                    "adminState": True,
                    "cdp": True,
                    "debounceTimer": 100,
                    "fec": "auto",
                    "lacpPortPriority": 32768,
                    "lacpRate": "normal",
                    "portChannelMode": "active",
                    "ptp": False,
                },
            },
        },
        "operData": {"adminStatus": "up", "mode": "trunk", "portChannelId": 901},
    }

    model = parse_member_interface_response(captured_record)

    assert model.config_data.mode == "access"
    assert model.policy_type == "accessPoMember"
    assert model.normalized_port_channel_id == 901

    payload = build_member_update_payload(captured_record, {"description": "updated"})
    assert "portMode" not in payload["configData"]["networkOS"]["policy"]


@pytest.mark.parametrize(
    "path",
    ["configData", "configData.networkOS", "configData.networkOS.policy"],
)
def test_parse_rejects_unclassified_nested_configuration(path):
    response = member_record()
    target = response
    for component in path.split("."):
        target = target[component]
    target["futureControllerField"] = "must-not-be-dropped"

    with pytest.raises(UnmodeledMemberConfigurationError, match="futureControllerField"):
        parse_member_interface_response(response)


@pytest.mark.parametrize(
    "field,value",
    [("ptp", 1), ("portMode", False)],
)
def test_parse_rejects_malformed_response_only_field(field, value):
    response = member_record(policy_type="accessPoMember", mode="access")
    response["configData"]["networkOS"]["policy"][field] = value

    with pytest.raises(UnmodeledMemberConfigurationError, match=field):
        parse_member_interface_response(response)


def test_safe_overlay_preserves_declared_fields_and_strips_response_only_data():
    response = member_record()
    original = copy.deepcopy(response)
    payload = build_member_update_payload(
        response,
        {
            "admin_state": False,
            "description": "updated",
            "extra_config": "logging event trunk-status",
        },
        switch_id="SERIAL2",
    )

    assert response == original
    assert payload["switchId"] == "SERIAL2"
    assert "switchIp" not in payload
    assert "operData" not in payload
    assert "fabricName" not in payload
    policy = payload["configData"]["networkOS"]["policy"]
    assert policy["policyType"] == "poMember"
    assert policy["portChannelId"] == "port-channel20"
    assert policy["portChannelMode"] == "active"
    assert policy["allowedVlans"] == "1-100"
    assert policy["lacpPortPriority"] == 32768
    assert policy["adminState"] is False
    assert policy["description"] == "updated"
    assert policy["extraConfig"] == "logging event trunk-status"
    assert "ptp" not in policy


def test_safe_overlay_accepts_wire_aliases():
    assert normalize_safe_member_updates({"adminState": False, "extraConfig": "description helper"}) == {
        "admin_state": False,
        "extra_config": "description helper",
    }


@pytest.mark.parametrize("field", ["allowed_vlans", "portChannelMode", "policy_type", "speed"])
def test_safe_overlay_rejects_non_safe_fields(field):
    with pytest.raises(UnsafeMemberUpdateError, match="may update only"):
        normalize_safe_member_updates({field: "unsafe"})


@pytest.mark.parametrize(
    "extra_config",
    [
        "channel-group 30 mode active",
        "no channel-group 20",
        "default channel-group",
        "default interface Ethernet1/24",
        "description safe ; no channel-group 20",
        "description safe\rdefault interface Ethernet1/24",
        "exit ; interface port-channel20 ; shutdown",
        "end\ninterface Ethernet1/24\nno channel-group 20",
        "do configure terminal ; interface Port-channel20",
    ],
)
def test_safe_overlay_rejects_membership_changing_extra_config(extra_config):
    with pytest.raises(UnsafeMemberUpdateError, match="must not change channel-group"):
        normalize_safe_member_updates({"extra_config": extra_config})


@pytest.mark.parametrize(
    "extra_config",
    [
        "ch 30 mode active",
        "chan 30 mode active",
        "no ch 20",
        "default channel-g",
        "def chan",
        "int Ethernet1/24",
        "default int Ethernet1/24",
        "def inte Ethernet1/24",
        "default-int Ethernet1/24",
        "ex",
        "exi",
        "en",
        "conf t",
        "configure term",
        "do conf t",
        "description safe ; NO CH 20",
    ],
)
def test_safe_overlay_rejects_abbreviated_membership_and_context_commands(extra_config):
    with pytest.raises(UnsafeMemberUpdateError, match="must not change channel-group"):
        normalize_safe_member_updates({"extra_config": extra_config})


@pytest.mark.parametrize(
    "extra_config",
    [
        "description channel-group is documentation",
        "description conf t is documentation",
        "no cdp enable",
        "default cdp",
        "channel-protocol lacp",
        "no channel-protocol lacp",
        "default channel-protocol",
        "ip address 192.0.2.1/31",
        "inherit port-profile EDGE",
        "configuration checkpoint member-safe",
        "endpoint tracker",
        "exit-rate 10",
    ],
)
def test_safe_overlay_accepts_benign_abbreviation_near_misses(extra_config):
    assert normalize_safe_member_updates({"extra_config": extra_config}) == {"extra_config": extra_config}


def test_pair_aware_payload_requires_validation_attestation():
    response = member_record("vpcMember")
    with pytest.raises(UnsafeMemberUpdateError, match="pair-aware"):
        build_member_update_payload(response, {"description": "updated"})
    payload = build_member_update_payload(response, {"description": "updated"}, pair_validated=True)
    assert payload["configData"]["networkOS"]["policy"]["policyType"] == "vpcMember"


@pytest.mark.parametrize(
    "policy_type,mode,network_os",
    [
        ("poMember", "access", "nx-os"),
        ("poMember", "trunk", "ios-xe"),
        ("iosXeL3PoMember", "trunk", "ios-xe"),
    ],
)
def test_policy_envelope_rejects_mode_or_os_mismatch(policy_type, mode, network_os):
    with pytest.raises(ValidationError):
        parse_member_interface_response(member_record(policy_type, mode=mode, network_os=network_os))


@pytest.mark.parametrize("policy_type", ["l3PoMemberInternal", "futureControllerMember", "trunkHost"])
def test_parse_rejects_unmodeled_policy(policy_type):
    with pytest.raises(UnsupportedMemberPolicyError):
        parse_member_interface_response(member_record(policy_type))
