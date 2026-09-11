# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Focused tests for cached ethernet membership ownership validation."""

from __future__ import annotations

import copy

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import (
    EthernetMembershipIndex,
    MembershipValidationError,
    MissingPeerIdentityError,
    MissingPeerInventoryError,
)


def _inventory(*records):
    return {record["interfaceName"].lower(): record for record in records}


def _member(
    switch_id="SERIAL1",
    interface_name="Ethernet1/24",
    *,
    policy_type="poMember",
    configured_id=20,
    operational_id=20,
    primary_interface=None,
):
    metadata = {
        "poMember": ("trunk", "nx-os"),
        "accessPoMember": ("access", "nx-os"),
        "l3PoMember": ("routed", "nx-os"),
        "iosXeL3PoMember": ("routed", "ios-xe"),
        "vpcMember": ("trunk", "nx-os"),
        "accessVpcPoMember": ("access", "nx-os"),
    }
    mode, network_os = metadata.get(policy_type, ("trunk", "nx-os"))
    policy = {
        "policyType": policy_type,
        "portChannelId": f"port-channel{configured_id}",
        "portChannelMode": "active",
        "adminState": True,
        "description": "existing member",
        "extraConfig": "logging event link-status",
    }
    if primary_interface is not None:
        policy["primaryInterface"] = primary_interface
    return {
        "switchId": switch_id,
        "interfaceName": interface_name,
        "interfaceType": "ethernet",
        "configData": {
            "mode": mode,
            "networkOS": {
                "networkOSType": network_os,
                "policy": policy,
            },
        },
        "operData": {"portChannelId": operational_id},
    }


def _parent(
    switch_id="SERIAL1",
    interface_name="port-channel20",
    *,
    policy_type="trunkPoHost",
    member_names=("Ethernet1/24",),
    interface_type="portChannel",
    policy_extra=None,
):
    mode, network_os = {
        "trunkPoHost": ("trunk", "nx-os"),
        "accessPoHost": ("access", "nx-os"),
        "l3Po": ("routed", "nx-os"),
        "iosXeL3PortChannel": ("routed", "ios-xe"),
    }.get(policy_type, ("trunk", "nx-os"))
    policy = {"policyType": policy_type, "ports": list(member_names)}
    policy.update(policy_extra or {})
    return {
        "switchId": switch_id,
        "interfaceName": interface_name,
        "interfaceType": interface_type,
        "configData": {
            "mode": mode,
            "networkOS": {"networkOSType": network_os, "policy": policy},
        },
    }


def _vpc_parent(
    switch_id,
    peer_switch_id,
    *,
    interface_name="vpc100",
    policy_type="trunkVpcHost",
    peer1_id,
    peer2_id,
    peer1_members,
    peer2_members,
    policy_extra=None,
):
    mode = {"trunkVpcHost": "trunk", "accessVpcHost": "access"}.get(policy_type, "trunk")
    policy = {
        "policyType": policy_type,
        "peerSwitchId": peer_switch_id,
        "peer1PortChannelId": peer1_id,
        "peer2PortChannelId": peer2_id,
        "peer1MemberPorts": list(peer1_members),
        "peer2MemberPorts": list(peer2_members),
    }
    policy.update(policy_extra or {})
    return {
        "switchId": switch_id,
        "interfaceName": interface_name,
        "interfaceType": "vpc",
        "configData": {
            "mode": mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": policy,
            },
        },
    }


def _vpc_parent_side_port_channel(switch_id, port_channel_id, policy_type):
    mode = "access" if policy_type == "accessVpcMember" else "trunk"
    return {
        "switchId": switch_id,
        "interfaceName": f"port-channel{port_channel_id}",
        "interfaceType": "portChannel",
        "configData": {
            "mode": mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": policy_type,
                    "portChannelId": f"port-channel{port_channel_id}",
                    "primaryInterface": "vpc100",
                },
            },
        },
        "operData": {"portChannelId": -1},
    }


def _valid_vpc_inventories(*, policy_type="vpcMember"):
    parent_policy = {
        "vpcMember": "trunkVpcHost",
        "accessVpcPoMember": "accessVpcHost",
    }[policy_type]
    parent_side_policy = {
        "vpcMember": "trunkVpcMember",
        "accessVpcPoMember": "accessVpcMember",
    }[policy_type]
    s1_member = _member(
        "SERIAL1",
        "Ethernet1/24",
        policy_type=policy_type,
        configured_id=20,
        operational_id=20,
        primary_interface="vPC100",
    )
    s2_member = _member(
        "SERIAL2",
        "Ethernet1/25",
        policy_type=policy_type,
        configured_id=30,
        operational_id=30,
        primary_interface="vpc100",
    )
    s1_parent = _vpc_parent(
        "SERIAL1",
        "SERIAL2",
        policy_type=parent_policy,
        peer1_id=20,
        peer2_id=30,
        peer1_members=("Ethernet1/24",),
        peer2_members=("Ethernet1/25",),
    )
    s2_parent = _vpc_parent(
        "SERIAL2",
        "SERIAL1",
        policy_type=parent_policy,
        peer1_id=20,
        peer2_id=30,
        peer1_members=("Ethernet1/24",),
        peer2_members=("Ethernet1/25",),
    )
    return {
        "SERIAL1": _inventory(s1_member, s1_parent, _vpc_parent_side_port_channel("SERIAL1", 20, parent_side_policy)),
        "SERIAL2": _inventory(s2_member, s2_parent, _vpc_parent_side_port_channel("SERIAL2", 30, parent_side_policy)),
    }


@pytest.mark.parametrize(
    "policy_type,parent_policy",
    [
        ("poMember", "trunkPoHost"),
        ("accessPoMember", "accessPoHost"),
        ("l3PoMember", "l3Po"),
        ("iosXeL3PoMember", "iosXeL3PortChannel"),
    ],
)
def test_validate_standalone_member_uses_one_cached_inventory(policy_type, parent_policy):
    member = _member(policy_type=policy_type)
    parent = _parent(policy_type=parent_policy)
    inventories = {"SERIAL1": _inventory(member, parent)}

    result = EthernetMembershipIndex(inventories).validate("SERIAL1", "ethernet1/24")

    assert result.member.policy_type == policy_type
    assert result.owner.interface_name == "port-channel20"
    assert result.owner.policy_type == parent_policy
    assert result.owner.port_channel_id == 20
    assert result.configured_port_channel_id == 20
    assert result.operational_port_channel_id == 20
    assert result.peer_owner is None
    assert result.peer_members == ()
    assert result.pair_validated is False


def test_index_keys_members_by_serial_and_lower_case_name():
    supported = _member(interface_name="Ethernet1/24")
    protected = _member(interface_name="Ethernet1/25", policy_type="futureControllerMember")
    host = copy.deepcopy(supported)
    host["interfaceName"] = "Ethernet1/26"
    host["configData"]["networkOS"]["policy"]["policyType"] = "trunkHost"
    index = EthernetMembershipIndex({"SERIAL1": _inventory(supported, protected, host)})

    assert index.member_keys == (
        ("SERIAL1", "ethernet1/24"),
        ("SERIAL1", "ethernet1/25"),
    )
    assert index.get_member("SERIAL1", "ETHERNET1/24") is not None
    assert index.get_member("SERIAL1", "Ethernet1/26") is None
    with pytest.raises(MembershipValidationError, match="protected or unsupported"):
        index.validate("SERIAL1", "Ethernet1/25")


@pytest.mark.parametrize("operational_id", [None, -1, "-1"])
def test_unset_operational_id_does_not_override_valid_configured_id(
    operational_id,
):
    member = _member(operational_id=operational_id)
    parent = _parent()

    result = EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")

    assert result.configured_port_channel_id == 20
    assert result.operational_port_channel_id is None


@pytest.mark.parametrize("operational_id", [0, "0", -2, "-2"])
def test_malformed_operational_id_fails_closed(operational_id):
    member = _member(configured_id=20, operational_id=operational_id)
    parent = _parent()

    with pytest.raises(MembershipValidationError, match="Cannot validate member"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


def test_configured_and_operational_port_channel_ids_must_agree():
    member = _member(configured_id=20, operational_id=21)
    parent = _parent()

    with pytest.raises(
        MembershipValidationError,
        match="configured port-channel ID 20 but operational ID 21",
    ):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


def test_member_requires_a_parent_claim():
    member = _member()

    with pytest.raises(MembershipValidationError, match="orphaned"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member)}).validate("SERIAL1", "Ethernet1/24")


def test_member_rejects_multiple_parent_claims():
    member = _member()
    parent1 = _parent(interface_name="port-channel20")
    parent2 = _parent(interface_name="port-channel21")

    with pytest.raises(MembershipValidationError, match="multiple parent owners"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent1, parent2)}).validate("SERIAL1", "Ethernet1/24")


def test_standalone_member_rejects_a_second_wrong_type_parent_claim():
    member = _member()
    parent = _parent()
    vpc_parent = _vpc_parent(
        "SERIAL1",
        "SERIAL2",
        peer1_id=40,
        peer2_id=50,
        peer1_members=("Ethernet1/30",),
        peer2_members=("Ethernet1/24",),
    )

    with pytest.raises(MembershipValidationError, match="multiple parent owners"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent, vpc_parent)}).validate("SERIAL1", "Ethernet1/24")


def test_member_rejects_incompatible_parent_policy():
    member = _member(policy_type="poMember")
    parent = _parent(policy_type="accessPoHost")

    with pytest.raises(MembershipValidationError, match="incompatible parent policy"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


def test_member_and_parent_port_channel_ids_must_agree():
    member = _member(configured_id=20, operational_id=20)
    parent = _parent(interface_name="port-channel21")

    with pytest.raises(
        MembershipValidationError,
        match="declares port-channel ID 20, but parent 'port-channel21' resolves to ID 21",
    ):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


def test_parent_policy_id_cannot_disagree_with_parent_name():
    member = _member()
    parent = _parent(policy_extra={"portChannelId": "port-channel21"})

    with pytest.raises(MembershipValidationError, match="name ID 20.*policy"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


def test_parent_must_claim_standalone_member_through_ports():
    member = _member()
    parent = _parent(member_names=())
    policy = parent["configData"]["networkOS"]["policy"]
    policy["peer1MemberPorts"] = ["Ethernet1/24"]

    with pytest.raises(MembershipValidationError, match="required field 'ports'"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


@pytest.mark.parametrize(
    "policy_type,parent_policy",
    [
        ("poMember", "trunkPoHost"),
        ("accessPoMember", "accessPoHost"),
        ("l3PoMember", "l3Po"),
        ("iosXeL3PoMember", "iosXeL3PortChannel"),
    ],
)
@pytest.mark.parametrize("field", ("mode", "network_os"))
def test_standalone_parent_requires_matching_mode_and_network_os(policy_type, parent_policy, field):
    member = _member(policy_type=policy_type)
    parent = _parent(policy_type=parent_policy)
    if field == "mode":
        parent["configData"]["mode"] = "invalid-mode"
        error = "has mode"
    else:
        parent["configData"]["networkOS"]["networkOSType"] = "invalid-os"
        error = "has networkOSType"

    with pytest.raises(MembershipValidationError, match=error):
        EthernetMembershipIndex({"SERIAL1": _inventory(member, parent)}).validate("SERIAL1", "Ethernet1/24")


@pytest.mark.parametrize("policy_type", ["vpcMember", "accessVpcPoMember"])
def test_validate_vpc_member_requires_reciprocal_pair_evidence(policy_type):
    inventories = _valid_vpc_inventories(policy_type=policy_type)

    result = EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")

    assert result.member.policy_type == policy_type
    assert result.owner.interface_name == "vpc100"
    assert result.owner.port_channel_id == 20
    assert result.peer_owner is not None
    assert result.peer_owner.switch_id == "SERIAL2"
    assert result.peer_owner.port_channel_id == 30
    assert [item.key for item in result.peer_members] == [("SERIAL2", "ethernet1/25")]
    assert result.pair_validated is True


@pytest.mark.parametrize("policy_type", ["vpcMember", "accessVpcPoMember"])
def test_vpc_literal_peer2_slot_maps_to_second_switch(policy_type):
    inventories = _valid_vpc_inventories(policy_type=policy_type)

    result = EthernetMembershipIndex(inventories).validate("SERIAL2", "Ethernet1/25")

    assert result.owner.switch_id == "SERIAL2"
    assert result.owner.port_channel_id == 30
    assert result.owner.claim_fields == ("peer2MemberPorts",)
    assert result.peer_owner is not None
    assert result.peer_owner.switch_id == "SERIAL1"
    assert result.peer_owner.port_channel_id == 20


def test_vpc_validation_reports_exact_missing_peer_inventory():
    inventories = _valid_vpc_inventories()
    inventories.pop("SERIAL2")

    with pytest.raises(MissingPeerInventoryError) as exc_info:
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")

    assert exc_info.value.peer_switch_id == "SERIAL2"


def test_vpc_requires_parent_copy_on_peer():
    inventories = _valid_vpc_inventories()
    inventories["SERIAL2"].pop("vpc100")

    with pytest.raises(MembershipValidationError, match="does not contain vPC parent"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_peer_switch_ids_must_be_reciprocal():
    inventories = _valid_vpc_inventories()
    peer_parent = inventories["SERIAL2"]["vpc100"]
    peer_parent["configData"]["networkOS"]["policy"]["peerSwitchId"] = "SERIAL3"

    with pytest.raises(MembershipValidationError, match="not reciprocal"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_copies_require_compatible_policies():
    inventories = _valid_vpc_inventories()
    peer_parent = inventories["SERIAL2"]["vpc100"]
    peer_parent["configData"]["networkOS"]["policy"]["policyType"] = "accessVpcHost"

    with pytest.raises(MembershipValidationError, match="incompatible policy"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_copies_require_identical_literal_port_channel_ids():
    inventories = _valid_vpc_inventories()
    peer_parent = inventories["SERIAL2"]["vpc100"]
    peer_parent["configData"]["networkOS"]["policy"]["peer2PortChannelId"] = 21

    with pytest.raises(MembershipValidationError, match="inconsistent literal configured data"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_copies_require_identical_literal_member_lists():
    inventories = _valid_vpc_inventories()
    peer_parent = inventories["SERIAL2"]["vpc100"]
    peer_parent["configData"]["networkOS"]["policy"]["peer2MemberPorts"] = ["Ethernet1/99"]

    with pytest.raises(MembershipValidationError, match="inconsistent literal configured data"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_copies_require_consistent_full_config_data():
    inventories = _valid_vpc_inventories()
    peer_policy = inventories["SERIAL2"]["vpc100"]["configData"]["networkOS"]["policy"]
    peer_policy["nativeVlan"] = 200

    with pytest.raises(MembershipValidationError, match="inconsistent literal configured data"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_fingerprint_ignores_echo_metadata_and_member_presentation():
    inventories = _valid_vpc_inventories()
    local_parent = inventories["SERIAL1"]["vpc100"]
    peer_parent = inventories["SERIAL2"]["vpc100"]
    local_parent["configData"]["networkOS"]["policy"]["policyId"] = "LOCAL-POLICY-ID"
    peer_policy = peer_parent["configData"]["networkOS"]["policy"]
    peer_policy["policyId"] = "PEER-POLICY-ID"
    peer_policy["peer1MemberPorts"] = [" ethernet1/24 "]
    peer_policy["peer2MemberPorts"] = ["ETHERNET1/25"]

    result = EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")

    assert result.pair_validated is True


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("policyType", "accessVpcPoMember", "uses policy"),
        ("portChannelId", "port-channel31", "declares port-channel ID"),
        ("primaryInterface", "vpc999", "member-set mismatch"),
    ],
)
def test_vpc_peer_member_records_must_match_pair(field, value, error):
    inventories = _valid_vpc_inventories()
    peer_member_policy = inventories["SERIAL2"]["ethernet1/25"]["configData"]["networkOS"]["policy"]
    peer_member_policy[field] = value
    if field == "portChannelId":
        inventories["SERIAL2"]["ethernet1/25"]["operData"]["portChannelId"] = 31

    with pytest.raises(MembershipValidationError, match=error):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_member_must_be_claimed_by_its_evidenced_slot():
    inventories = _valid_vpc_inventories()
    for inventory in inventories.values():
        policy = inventory["vpc100"]["configData"]["networkOS"]["policy"]
        policy["peer1MemberPorts"] = ["Ethernet1/99"]

    with pytest.raises(MembershipValidationError, match="orphaned"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_target_member_rejects_a_second_stale_parent_claim():
    inventories = _valid_vpc_inventories()
    inventories["SERIAL1"]["vpc200"] = _vpc_parent(
        "SERIAL1",
        "SERIAL2",
        interface_name="vpc200",
        peer1_id=40,
        peer2_id=50,
        peer1_members=("Ethernet1/30",),
        peer2_members=("Ethernet1/24",),
    )

    with pytest.raises(MembershipValidationError, match="multiple parent owners"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_non_target_peer_member_rejects_a_second_stale_parent_claim():
    inventories = _valid_vpc_inventories()
    inventories["SERIAL2"]["vpc200"] = _vpc_parent(
        "SERIAL2",
        "SERIAL1",
        interface_name="vpc200",
        peer1_id=40,
        peer2_id=50,
        peer1_members=("Ethernet1/30",),
        peer2_members=("Ethernet1/25",),
    )

    with pytest.raises(MembershipValidationError, match="multiple parent owners"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


@pytest.mark.parametrize("policy_type", ["vpcMember", "accessVpcPoMember"])
@pytest.mark.parametrize("side", ["SERIAL1", "SERIAL2"])
@pytest.mark.parametrize("field", ["mode", "network_os"])
def test_vpc_parent_requires_matching_mode_and_network_os(policy_type, side, field):
    inventories = _valid_vpc_inventories(policy_type=policy_type)
    parent = inventories[side]["vpc100"]
    if field == "mode":
        parent["configData"]["mode"] = "invalid-mode"
        error = "has mode"
    else:
        parent["configData"]["networkOS"]["networkOSType"] = "invalid-os"
        error = "has networkOSType"

    with pytest.raises(MembershipValidationError, match=error):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_rejects_ambiguous_non_equivalent_slot_assignment():
    inventories = _valid_vpc_inventories()
    inventories["SERIAL2"].pop("ethernet1/25")
    inventories["SERIAL2"]["ethernet1/24"] = _member(
        "SERIAL2",
        "Ethernet1/24",
        policy_type="vpcMember",
        configured_id=20,
        operational_id=20,
        primary_interface="vpc100",
    )
    for inventory in inventories.values():
        policy = inventory["vpc100"]["configData"]["networkOS"]["policy"]
        policy["peer1PortChannelId"] = 20
        policy["peer2PortChannelId"] = 20
        policy["peer1MemberPorts"] = ["Ethernet1/24"]
        policy["peer2MemberPorts"] = ["Ethernet1/24"]
        policy["peer1PortChannelDescription"] = "non-equivalent peer one"
        policy["peer2PortChannelDescription"] = "non-equivalent peer two"

    with pytest.raises(MembershipValidationError, match="unambiguously map non-equivalent"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_allows_indistinguishable_identical_slot_assignment():
    inventories = _valid_vpc_inventories()
    inventories["SERIAL2"].pop("ethernet1/25")
    inventories["SERIAL2"]["ethernet1/24"] = _member(
        "SERIAL2",
        "Ethernet1/24",
        policy_type="vpcMember",
        configured_id=20,
        operational_id=20,
        primary_interface="vpc100",
    )
    for inventory in inventories.values():
        policy = inventory["vpc100"]["configData"]["networkOS"]["policy"]
        policy["peer1PortChannelId"] = 20
        policy["peer2PortChannelId"] = 20
        policy["peer1MemberPorts"] = ["Ethernet1/24"]
        policy["peer2MemberPorts"] = ["ethernet1/24"]

    result = EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")

    assert result.pair_validated is True
    assert result.owner.port_channel_id == 20
    assert result.peer_owner is not None
    assert result.peer_owner.port_channel_id == 20


def test_vpc_pair_validation_caches_all_members_with_linear_work(monkeypatch):
    inventories = _valid_vpc_inventories()
    inventories["SERIAL1"]["ethernet1/26"] = _member(
        "SERIAL1", "Ethernet1/26", policy_type="vpcMember", configured_id=20, operational_id=20, primary_interface="vpc100"
    )
    inventories["SERIAL2"]["ethernet1/27"] = _member(
        "SERIAL2", "Ethernet1/27", policy_type="vpcMember", configured_id=30, operational_id=30, primary_interface="vpc100"
    )
    for inventory in inventories.values():
        policy = inventory["vpc100"]["configData"]["networkOS"]["policy"]
        policy["peer1MemberPorts"] = ["Ethernet1/26", "Ethernet1/24"]
        policy["peer2MemberPorts"] = ["Ethernet1/27", "Ethernet1/25"]

    index = EthernetMembershipIndex(inventories)
    original = index._member_port_channel_ids
    validation_count = 0

    def count_member_validation(member):
        nonlocal validation_count
        validation_count += 1
        return original(member)

    monkeypatch.setattr(index, "_member_port_channel_ids", count_member_validation)
    first = index.validate("SERIAL1", "Ethernet1/24")
    count_after_pair = validation_count
    second = index.validate("SERIAL1", "Ethernet1/26")
    peer = index.validate("SERIAL2", "Ethernet1/27")

    assert first.pair_validated is True
    assert second.pair_validated is True
    assert peer.pair_validated is True
    assert count_after_pair == 4
    assert validation_count == count_after_pair


def test_inventory_record_switch_id_must_match_outer_cache_key():
    member = _member(switch_id="SERIAL2")

    with pytest.raises(MembershipValidationError, match="stored under switch"):
        EthernetMembershipIndex({"SERIAL1": _inventory(member)})


def test_vpc_parent_echoes_without_peer_ids_use_cached_reciprocal_evidence():
    inventories = _valid_vpc_inventories()
    for inventory in inventories.values():
        inventory["vpc100"]["configData"]["networkOS"]["policy"].pop("peerSwitchId")

    result = EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")

    assert result.peer_owner is not None
    assert result.peer_owner.switch_id == "SERIAL2"
    assert result.pair_validated is True


def test_vpc_missing_peer_ids_use_authoritative_pair_evidence():
    inventories = _valid_vpc_inventories()
    for inventory in inventories.values():
        inventory["vpc100"]["configData"]["networkOS"]["policy"].pop("peerSwitchId")
    pair_evidence = {"SERIAL1": "SERIAL2", "SERIAL2": "SERIAL1"}

    result = EthernetMembershipIndex(inventories, peer_switch_ids=pair_evidence).validate("SERIAL1", "Ethernet1/24")

    assert result.peer_owner is not None
    assert result.peer_owner.switch_id == "SERIAL2"


def test_vpc_authoritative_pair_evidence_identifies_uncached_peer():
    inventories = _valid_vpc_inventories()
    inventories.pop("SERIAL2")
    inventories["SERIAL1"]["vpc100"]["configData"]["networkOS"]["policy"].pop("peerSwitchId")

    with pytest.raises(MissingPeerInventoryError) as exc_info:
        EthernetMembershipIndex(
            inventories,
            peer_switch_ids={"SERIAL1": "SERIAL2", "SERIAL2": "SERIAL1"},
        ).validate("SERIAL1", "Ethernet1/24")

    assert exc_info.value.peer_switch_id == "SERIAL2"


def test_vpc_missing_peer_identity_fails_closed_without_evidence():
    inventories = _valid_vpc_inventories()
    inventories.pop("SERIAL2")
    inventories["SERIAL1"]["vpc100"]["configData"]["networkOS"]["policy"].pop("peerSwitchId")

    with pytest.raises(MissingPeerIdentityError) as exc_info:
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")

    assert exc_info.value.switch_id == "SERIAL1"
    assert exc_info.value.parent_name == "vpc100"


def test_vpc_cached_peer_inference_rejects_ambiguous_reciprocal_copies():
    inventories = _valid_vpc_inventories()
    for inventory in inventories.values():
        inventory["vpc100"]["configData"]["networkOS"]["policy"].pop("peerSwitchId")
    third_inventory = copy.deepcopy(inventories["SERIAL2"])
    for record in third_inventory.values():
        record["switchId"] = "SERIAL3"
    inventories["SERIAL3"] = third_inventory

    with pytest.raises(MembershipValidationError, match="ambiguous"):
        EthernetMembershipIndex(inventories).validate("SERIAL1", "Ethernet1/24")


def test_vpc_parent_echo_must_agree_with_authoritative_pair_evidence():
    inventories = _valid_vpc_inventories()

    with pytest.raises(MembershipValidationError, match="authoritative pair evidence"):
        EthernetMembershipIndex(
            inventories,
            peer_switch_ids={"SERIAL1": "SERIAL3", "SERIAL3": "SERIAL1"},
        ).validate("SERIAL1", "Ethernet1/24")
