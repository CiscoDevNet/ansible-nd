# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Real public-workflow ownership checks across asymmetric vPC peers."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.interface_membership import EthernetMembershipIndex
from ansible_collections.cisco.nd.plugins.module_utils import interface_missing_member_preparation
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_missing_member_preparation as preparation_fakes
from ansible_collections.cisco.nd.tests.unit.module_utils.member_review_fakes import Controller, explicit_request, run_module, wire


def _asymmetric_controller(*, remote_name="Ethernet1/10", local_name="Ethernet1/20", reverse_peer_copy=False, local_parent=True):
    controller = Controller(paired=True)
    for switch_id in ("S1", "S2"):
        parent = wire(
            "vpc90",
            "trunkVpcHost",
            switch_id=switch_id,
            interface_type="vpc",
            peer1MemberPorts=[local_name],
            peer2MemberPorts=[remote_name],
            peer1PortChannelId=90,
            peer2PortChannelId=90,
            peerSwitchId="S2" if switch_id == "S1" else "S1",
        )
        if reverse_peer_copy and switch_id == "S2":
            policy = parent["configData"]["networkOS"]["policy"]
            policy["peer1MemberPorts"], policy["peer2MemberPorts"] = policy["peer2MemberPorts"], policy["peer1MemberPorts"]
        member = wire(
            local_name if switch_id == "S1" else remote_name,
            "vpcMember",
            switch_id=switch_id,
            primaryInterface="vpc90",
            portChannelId="90",
        )
        controller.rows[switch_id] = {row["interfaceName"].casefold(): row for row in (parent, member)}
    if not local_parent:
        del controller.rows["S1"]["vpc90"]
    return controller


@pytest.mark.parametrize("remote_name", ["Ethernet1/10", "Ethernet1/30"])
@pytest.mark.parametrize("reverse_peer_copy", [False, True])
@pytest.mark.parametrize("convert_host", [False, True])
def test_public_workflow_ignores_only_proven_remote_member_names(monkeypatch, remote_name, reverse_peer_copy, convert_host):
    controller = _asymmetric_controller(remote_name=remote_name, reverse_peer_copy=reverse_peer_copy)
    if convert_host:
        controller.rows["S1"]["ethernet1/10"] = wire("Ethernet1/10", "accessHost", mode="access", accessVlan=100)
    before_remote = deepcopy(controller.rows["S2"])
    index = EthernetMembershipIndex(controller.rows, peer_switch_ids={"S1": "S2", "S2": "S1"})
    assert index.get_member("S1", "Ethernet1/10") is None
    assert index.claiming_parents("S1", "Ethernet1/10") == ()

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is False, outcome.result.get("msg")
    assert outcome.result["changed"] is True
    assert len(controller.writes) == 2
    proof = outcome.result["member_verifications"]
    assert proof["complete"] is True
    assert [(row["switch_id"], row["interface_name"], row["owner_switch_id"], row["parent_interface_name"]) for row in proof["members"]] == [
        ("S1", "Ethernet1/10", "S1", "port-channel10")
    ]
    assert controller.rows["S2"] == before_remote
    assert controller.rows["S1"]["vpc90"]["configData"]["networkOS"]["policy"]["peer1MemberPorts"] == ["Ethernet1/20"]

    controller.calls.clear()
    replay = run_module(monkeypatch, explicit_request(), controller)
    assert replay.failed is False, replay.result.get("msg")
    assert replay.result["changed"] is False
    assert controller.writes == []
    assert replay.result["member_verifications"]["complete"] is True


def test_public_workflow_rejects_actual_local_member_ownership_before_writes(monkeypatch):
    controller = _asymmetric_controller(local_name="Ethernet1/10", remote_name="Ethernet1/30")
    before = deepcopy(controller.rows)

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is True
    assert controller.writes == []
    assert controller.rows == before


def test_public_workflow_rejects_reciprocal_local_claim_without_local_parent_copy(monkeypatch):
    controller = _asymmetric_controller(local_name="Ethernet1/10", remote_name="Ethernet1/30", local_parent=False)
    del controller.rows["S1"]["ethernet1/10"]
    before = deepcopy(controller.rows)

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is True
    assert controller.writes == []
    assert controller.rows == before


def test_public_workflow_refuses_ambiguous_remote_slot_orientation(monkeypatch):
    controller = _asymmetric_controller()
    policy = controller.rows["S2"]["vpc90"]["configData"]["networkOS"]["policy"]
    policy["peer1MemberPorts"] = ["Ethernet1/10"]
    before = deepcopy(controller.rows)

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is True
    assert controller.writes == []
    assert controller.rows == before


def test_public_workflow_refuses_missing_local_orientation_evidence(monkeypatch):
    controller = _asymmetric_controller()
    del controller.rows["S1"]["ethernet1/20"]
    before = deepcopy(controller.rows)

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is True
    assert controller.writes == []
    assert controller.rows == before


@pytest.mark.parametrize("switch_id", ["S1", "S2"])
@pytest.mark.parametrize("declared_peer", ["S3", 123, False])
def test_public_workflow_refuses_mismatched_parent_peer_identity(monkeypatch, switch_id, declared_peer):
    controller = _asymmetric_controller()
    controller.rows[switch_id]["vpc90"]["configData"]["networkOS"]["policy"]["peerSwitchId"] = declared_peer
    before = deepcopy(controller.rows)

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is True
    assert controller.writes == []
    assert controller.rows == before


@pytest.mark.parametrize("switch_id", ["S1", "S2"])
def test_fresh_preparation_guard_rejects_parent_peer_change(switch_id):
    controller = _asymmetric_controller()
    controller.rows[switch_id]["vpc90"]["configData"]["networkOS"]["policy"]["peerSwitchId"] = "S3"
    snapshot = preparation_fakes.Snapshot()
    snapshot.clean_interfaces_by_switch = controller.rows
    snapshot.context.switch_map_by_id["S2"] = "192.0.2.2"
    snapshot.context.switches.append({"switchId": "S2", "fabricName": "fab", "additionalData": {"platformType": "nx-os", "systemMode": "normal"}})
    receipt = preparation_fakes._receipt()
    receipt.orchestrator._member_peer_serial_cache = {"S1": "S2", "S2": "S1"}
    receipt.orchestrator._load_staged_detachment_peer = lambda *_args, **_kwargs: "S2"

    with pytest.raises(RuntimeError, match="parent peer"):
        interface_missing_member_preparation.refresh_missing_preparations([receipt], snapshot)


@pytest.mark.parametrize("field", ["peer1MemberPorts", "peer2MemberPorts"])
def test_public_workflow_refuses_malformed_reciprocal_membership(monkeypatch, field):
    controller = _asymmetric_controller()
    controller.rows["S2"]["vpc90"]["configData"]["networkOS"]["policy"][field] = {"invalid": "Ethernet1/10"}

    outcome = run_module(monkeypatch, explicit_request(), controller)

    assert outcome.failed is True
    assert controller.writes == []
