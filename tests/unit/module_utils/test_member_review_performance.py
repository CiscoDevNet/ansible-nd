# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Bound inventory/index work by fresh phases, not explicit member count."""

from collections import Counter
from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils import interface_missing_member_preparation as helper
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_missing_member_preparation as preparation_fakes
from ansible_collections.cisco.nd.tests.unit.module_utils.member_review_fakes import Controller, explicit_request, run_module, wire


def _measure_phase_work(monkeypatch):
    metrics, phases = Counter(), []
    original_index = helper.EthernetMembershipIndex
    original_clean = InterfaceStateSnapshot.clean_interfaces_by_switch.fget
    original_refresh = helper.refresh_missing_preparations

    class CountingIndex(original_index):
        """Count real index constructions without replacing their validation."""

        def __init__(self, inventories, *, peer_switch_ids=None):
            metrics["indexes"] += 1
            super().__init__(inventories, peer_switch_ids=peer_switch_ids)

    def clean(snapshot):
        metrics["copies"] += 1
        return original_clean(snapshot)

    def refresh(preparations, snapshot, phase="absent"):
        preparations = tuple(preparations)
        before = metrics.copy()
        result = original_refresh(preparations, snapshot, phase=phase)
        if preparations:
            phases.append({"phase": phase, "members": len(preparations), **dict(metrics - before)})
        return result

    monkeypatch.setattr(helper, "EthernetMembershipIndex", CountingIndex)
    monkeypatch.setattr(InterfaceStateSnapshot, "clean_interfaces_by_switch", property(clean))
    monkeypatch.setattr(helper, "refresh_missing_preparations", refresh)
    return metrics, phases


@pytest.mark.parametrize("member_count", [1, 10, 100])
def test_public_create_and_replay_build_one_inventory_index_per_fresh_phase(monkeypatch, member_count):
    metrics, phases = _measure_phase_work(monkeypatch)
    controller = Controller()
    controller.rows["S1"] = {f"ethernet2/{number}": wire(f"Ethernet2/{number}", "trunkHost", allowedVlans="none") for number in range(1, 301)}
    params = explicit_request(names=tuple(f"Ethernet1/{number}" for number in range(10, 10 + member_count)))

    created = run_module(monkeypatch, params, controller)

    assert created.failed is False, created.result.get("msg")
    assert created.result["changed"] is True
    assert len(controller.writes) == 2
    assert created.result["member_verifications"]["complete"] is True
    assert len(created.result["member_verifications"]["members"]) == member_count
    assert phases and {item["phase"] for item in phases} == {"absent", "prepared", "member"}
    assert all(item["members"] == member_count and item["indexes"] == 1 and item["copies"] == 1 for item in phases), phases
    assert metrics["indexes"] == len(phases)
    assert metrics["copies"] <= len(phases) + 2
    expected = deepcopy(controller.rows)

    metrics.clear()
    phases.clear()
    controller.calls.clear()
    replay = run_module(monkeypatch, params, controller)

    assert replay.failed is False, replay.result.get("msg")
    assert replay.result["changed"] is False
    assert controller.writes == []
    assert controller.rows == expected
    assert replay.result["member_verifications"]["complete"] is True
    assert phases == [{"phase": "member", "members": member_count, "copies": 1, "indexes": 1}]
    assert metrics == {"copies": 1, "indexes": 1}


def test_fresh_guard_discards_previous_absence_after_inventory_changes():
    snapshot = preparation_fakes.Snapshot()
    receipt = preparation_fakes._receipt()
    helper.refresh_missing_preparations([receipt], snapshot)
    snapshot.next_records = [preparation_fakes._wire("Ethernet1/10", "trunkHost")]

    with pytest.raises(RuntimeError, match="appeared after planning"):
        helper.refresh_missing_preparations([receipt], snapshot)

    assert snapshot.invalidations == 2
    assert snapshot.refreshes == [["S1"], ["S1"]]


def test_precomputation_keeps_unrelated_inventory_outside_unowned_guard_scope():
    snapshot = preparation_fakes.Snapshot()
    snapshot.clean_interfaces_by_switch["S3"] = {
        "port-channel99": wire("port-channel99", "trunkPoHost", switch_id="S3", interface_type="portChannel", ports={"malformed": True})
    }

    helper.refresh_missing_preparations([preparation_fakes._receipt()], snapshot)

    assert snapshot.refreshes == [["S1"]]


def test_many_members_share_validation_only_until_next_fresh_call(monkeypatch):
    snapshot = preparation_fakes.Snapshot()
    first = preparation_fakes._receipt()
    counts, links = Counter(), {}
    original_metadata = helper._check_metadata

    def metadata(context, switch_id):
        counts["metadata"] += 1
        return original_metadata(context, switch_id)

    def peer(*_args, **_kwargs):
        counts["peer"] += 1
        return None

    def endpoints():
        counts["links"] += 1
        return links

    monkeypatch.setattr(helper, "_check_metadata", metadata)
    first.orchestrator._load_staged_detachment_peer = peer
    first.orchestrator._fabric_link_endpoints = endpoints
    receipts = [preparation_fakes._receipt(orchestrator=first.orchestrator, interface_name=f"Ethernet1/{number}") for number in range(10, 110)]

    helper.refresh_missing_preparations(receipts, snapshot)
    assert counts == {"metadata": 1, "peer": 1, "links": 1}

    links[("S1", "ethernet1/109")] = {"policyType": "numbered"}
    with pytest.raises(RuntimeError, match="fabric-link endpoint"):
        helper.refresh_missing_preparations(receipts, snapshot)

    assert counts == {"metadata": 2, "peer": 2, "links": 2}
    assert snapshot.invalidations == 2
    assert snapshot.refreshes == [["S1"], ["S1"]]


def test_incompatible_fresh_pair_providers_cannot_share_an_index():
    snapshot = preparation_fakes.Snapshot()
    receipts = [preparation_fakes._receipt(interface_name=f"Ethernet1/{number}") for number in (10, 11)]
    for receipt, peer in zip(receipts, ("S2", "S3")):
        snapshot.clean_interfaces_by_switch[peer] = {}
        snapshot.context.switch_map_by_id[peer] = f"192.0.2.{peer[1:]}"
        snapshot.context.switches.append({"switchId": peer, "fabricName": "fab", "additionalData": {"platformType": "nx-os"}})
        receipt.orchestrator._member_peer_serial_cache = {"S1": peer, peer: "S1"}
        receipt.orchestrator._load_staged_detachment_peer = lambda *_args, peer=peer, **_kwargs: peer

    with pytest.raises(RuntimeError, match="conflicting reciprocal pair identities"):
        helper.refresh_missing_preparations(receipts, snapshot)

    assert snapshot.invalidations == 1
    assert snapshot.refreshes == []
