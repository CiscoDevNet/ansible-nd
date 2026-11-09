# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Controller-intent guards and target-only inverse readiness with scripted REST.

These tests distinguish policy-backed child identities from discovered physical
targets. No controller is contacted and no wall-clock discovery wait is performed.
"""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators import manage_breakout_interfaces as implementation
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import (
    P21,
    P22,
    P23,
    P24,
    P49,
    combined,
    summary_calls,
    topology,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import (
    BREAKOUT,
    OTHER_SERIAL,
    REMOVE,
    SERIAL,
    action,
    group,
    item,
    response,
    run,
    writes,
)

VERIFY = {"enabled": True}
FAST = {"enabled": False}


def intent_topology(*parents, native=(), ready_children=(), policy_id="POLICY-test", mark_deleted=False, switch=SERIAL):
    """Model the real summary window: active child policies ahead of discovery."""
    rows = []
    for name in [*native, *(parent + "/" + str(lane) for parent in parents for lane in (1, 2, 3, 4))]:
        ready = name in ready_children
        rows.append(
            {
                "switchId": switch,
                "interfaceName": name,
                "interfaceType": "ethernet",
                "physicalInterface": ready,
                "discovered": ready,
                "fex": False,
                "speed": "25Gb" if ready else None,
                "policyId": policy_id,
                "markDeleted": mark_deleted,
            }
        )
    return response({"interfaces": rows, "meta": {"counts": {"total": len(rows), "remaining": 0}}})


@pytest.fixture
def clock(monkeypatch):
    """Advance the internal readiness budget only when the workflow sleeps."""

    class Clock:
        now = 0.0

        def __init__(self):
            self.sleeps = []

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.sleeps.append(seconds)
            self.now += seconds

    fake = Clock()
    monkeypatch.setattr(implementation.time, "monotonic", fake.monotonic)
    monkeypatch.setattr(implementation.time, "sleep", fake.sleep)
    return fake


def assert_targeted_read(call, parent=P21):
    query = parse_qs(urlsplit(call["path"]).query)
    assert call["verb"] == HttpVerbEnum.GET
    assert query["switchId"] == [SERIAL]
    assert query["includeAll"] == ["true"]
    assert query["filter"] == ["interfaceName:*" + parent + "* AND switchId:" + SERIAL]


def test_coupled_intent_is_detected_before_discovery_and_inverse_waits_only_for_its_child(clock):
    report, calls = run(
        [
            topology(native=(P21, P22, P23, P24)),
            action(item(P21)),
            intent_topology(P21, P23),
            intent_topology(P21),
            intent_topology(P21, ready_children=(P21 + "/1",)),
            action(item(P21 + "/1")),
        ],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert "Unexpected breakout family 'Ethernet1/23'" in report["msg"]
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert report["recovery"][0]["topology_verified"] is False
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
    assert {row["interface_name"] for row in report["observed_before_recovery"]} == {P21, P23}
    assert all(row["evidence"] == "controller_intent" for row in report["observed_before_recovery"])
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    reads = summary_calls(calls)
    assert len(reads) == 4
    for call in reads[2:]:
        assert_targeted_read(call)
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert clock.sleeps and all(delay == 2 for delay in clock.sleeps)


def test_all_requested_intent_families_succeed_without_waiting_for_physical_discovery(clock):
    report, calls = run(
        [topology(native=(P21, P22, P23, P24)), action(item(P23), item(P21)), intent_topology(P21, P23)],
        config=[group(P21, P23)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "observed"
    assert {row["interface_name"] for row in report["after"]} == {P21, P23}
    assert all(row["broken_out"] and row["evidence"] == "controller_intent" and len(row["children"]) == 4 for row in report["after"])
    assert all(not ({"parent_available", "child_readiness", "physical_children", "snapshot_phase"} & row.keys()) for row in report["after"])
    assert report["recovery"] == []
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 2
    assert clock.sleeps == []


def test_existing_policy_backed_intent_families_are_baseline_not_new_collateral(clock):
    report, calls = run([intent_topology(P21, P23)], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is False and report["changed"] is False
    assert report["after_status"] == "unchanged"
    assert {row["interface_name"] for row in report["before"]} == {P21, P23}
    assert all(row["evidence"] == "controller_intent" for row in report["before"])
    assert len(summary_calls(calls)) == 1 and writes(calls) == []
    assert clock.sleeps == []


@pytest.mark.parametrize("policy_id,mark_deleted", [(None, False), ("", False), ("  ", False), ("POLICY-old", True), ("POLICY-old", None)])
def test_unowned_or_marked_deleted_ghosts_do_not_create_false_collateral(clock, policy_id, mark_deleted):
    after = combined(topology(P21), intent_topology(P23, policy_id=policy_id, mark_deleted=mark_deleted))
    report, calls = run([topology(native=(P21, P23)), action(item(P21)), after], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is False and report["changed"] is True
    assert report["recovery"] == []
    assert {row["interface_name"] for row in report["after"]} == {P21}
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 2
    assert clock.sleeps == []


def test_an_already_ready_nonfirst_child_is_reused_without_a_readiness_get(clock):
    report, calls = run(
        [topology(native=(P21, P23)), action(item(P21)), intent_topology(P21, P23, ready_children=(P21 + "/2",)), action(item(P21 + "/2"))],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/2"}]}
    assert len(summary_calls(calls)) == 2
    assert clock.sleeps == []


def test_inverse_breakout_reuses_an_available_intent_only_parent_without_waiting(clock):
    report, calls = run(
        [topology(P21, P23), action(item(P21 + "/1")), intent_topology(native=(P21, P23)), action(item(P21))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert [call["path"] for call in writes(calls)] == [REMOVE, BREAKOUT]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21, "breakoutMap": "25g-4x"}]}
    assert len(summary_calls(calls)) == 2
    assert clock.sleeps == []


def test_missing_parent_is_queried_narrowly_before_inverse_breakout(clock):
    report, calls = run(
        [topology(P21, P23), action(item(P21 + "/1")), topology(), topology(), intent_topology(native=(P21,)), action(item(P21))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert len(summary_calls(calls)) == 4
    for call in summary_calls(calls)[2:]:
        assert_targeted_read(call)
    assert [call["path"] for call in writes(calls)] == [REMOVE, BREAKOUT]
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert clock.sleeps


@pytest.mark.parametrize("failure", ["timeout", "malformed", "transport"])
def test_unready_or_unreadable_inverse_target_never_causes_a_mutation_replay(clock, failure):
    pending = intent_topology(P21)
    failed_reads = (
        [deepcopy(pending) for _ in range(60)]
        if failure == "timeout"
        else [response({"interfaces": None})] if failure == "malformed" else [ValueError("Readiness GET connection interrupted")]
    )
    report, calls = run(
        [topology(native=(P21, P23)), action(item(P21)), intent_topology(P21, P23), *failed_reads],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["may_have_changed"] is True
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
    assert report["recovery"][0]["status"] == "not_attempted"
    assert report["recovery"][0]["api_outcomes"] == []
    assert {row["interface_name"] for row in report["observed_before_recovery"]} == {P21, P23}
    assert len(writes(calls)) == 1 and writes(calls)[0]["path"] == BREAKOUT
    for call in summary_calls(calls)[2:]:
        assert_targeted_read(call)
    if failure == "timeout":
        assert "90" in report["recovery"][0]["msg"]
        assert 90 <= clock.now <= 92
    else:
        assert len(summary_calls(calls)) == 3


@pytest.mark.parametrize("scenario", ["noop", "check_mode", "verify_disabled"])
def test_readiness_handling_adds_no_calls_to_ordinary_or_nonexecuting_paths(clock, scenario):
    check_mode = scenario == "check_mode"
    scripted = [topology(P21) if scenario == "noop" else topology(native=(P21,))]
    if scenario == "verify_disabled":
        scripted.append(action(item(P21)))
    report, calls = run(scripted, config=[group(P21)], verify=FAST if scenario == "verify_disabled" else VERIFY, check_mode=check_mode)
    assert report["failed"] is False
    assert len(summary_calls(calls)) == 1
    assert len(writes(calls)) == (1 if scenario == "verify_disabled" else 0)
    assert report.get("recovery", []) == []
    assert clock.sleeps == []


def test_untouched_intent_only_switch_retains_partial_observation_provenance(clock):
    report, calls = run(
        [intent_topology(P21), topology(native=(P21,), switch=OTHER_SERIAL), action(item(P21, switch=OTHER_SERIAL)), topology(P21, switch=OTHER_SERIAL)],
        config=[group(P21), group(P21, switch=OTHER_SERIAL)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "partially_observed"
    after = {(row["switch_id"], row["interface_name"]): row for row in report["after"]}
    assert after[(SERIAL, P21)]["evidence"] == "controller_intent"
    assert after[(OTHER_SERIAL, P21)]["evidence"] == "post_action_discovery"
    assert [parse_qs(urlsplit(call["path"]).query)["switchId"][0] for call in summary_calls(calls)] == [SERIAL, OTHER_SERIAL, OTHER_SERIAL]
    assert len(writes(calls)) == 1 and clock.sleeps == []


def test_stale_physical_parents_do_not_hide_new_policy_backed_child_identities(clock):
    after = combined(topology(native=(P21, P23)), intent_topology(P21, P23))
    report, calls = run([topology(native=(P21, P23)), action(item(P21), item(P23)), after], config=[group(P21, P23)], verify=VERIFY)
    assert report["failed"] is False and report["changed"] is True
    assert {row["interface_name"] for row in report["after"]} == {P21, P23}
    assert all(row["broken_out"] and row["evidence"] == "controller_intent" and len(row["children"]) == 4 for row in report["after"])
    assert report["recovery"] == []
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert clock.sleeps == []


def test_cold_intent_only_delete_waits_before_submitting_a_real_unbreakout(clock):
    baseline = combined(intent_topology(P21), topology(P23))
    report, calls = run(
        [baseline, intent_topology(P21), topology(P21), action(item(P21 + "/1")), topology(P23, native=(P21,))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    original = next(row for row in report["before"] if row["interface_name"] == P21)
    assert original["evidence"] == "controller_intent"
    assert report["after_status"] == "observed"
    assert report["recovery"] == []
    reads = summary_calls(calls)
    assert len(reads) == 4
    for call in reads[1:3]:
        assert_targeted_read(call)
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert clock.sleeps


def test_already_discovered_unknown_speed_fails_map_readiness_without_polling(clock):
    report, calls = run([topology(P21, speed="auto")], state="deleted", config=[group(P21, breakout_map=None)], verify=VERIFY)
    assert report["failed"] is True and report["changed"] is False
    assert "Cannot infer recovery map" in report["msg"]
    assert len(summary_calls(calls)) == 1 and writes(calls) == []
    assert clock.sleeps == []


def test_check_mode_cold_intent_delete_does_not_wait_for_discovery_or_speed(clock):
    report, calls = run([intent_topology(P21)], state="deleted", config=[group(P21, breakout_map=None)], verify=VERIFY, check_mode=True)
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "predicted"
    assert report["api_outcomes"][0]["outcome"] == "planned"
    assert len(summary_calls(calls)) == 1 and writes(calls) == []
    assert clock.sleeps == []


@pytest.mark.parametrize("failure", ["timeout", "server_error"])
def test_incomplete_forward_request_does_not_start_inverse_readiness_wait(clock, monkeypatch, failure):
    if failure == "server_error":
        original_timeout = implementation.RestSend.timeout
        monkeypatch.setattr(implementation.RestSend, "timeout", property(original_timeout.fget, lambda self, value: original_timeout.fset(self, 1)))
    failed_reply = (
        TimeoutError("Forward POST response lost") if failure == "timeout" else response({"message": "Controller unavailable"}, code=500, method="POST")
    )
    report, calls = run([topology(native=(P21, P23)), failed_reply, intent_topology(P21, P23)], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["may_have_changed"] is True
    assert report["recovery"][0]["status"] == "not_attempted"
    assert "did not report synchronous completion" in report["recovery"][0]["msg"]
    assert report["recovery"][0]["api_outcomes"] == []
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 2
    assert clock.sleeps == []


def test_mixed_completed_response_keeps_readiness_gets_body_free_and_recovers_only_changed_parent(clock):
    post_action = combined(intent_topology(P21, P23), topology(native=(P49,)))
    report, calls = run(
        [
            topology(native=(P21, P23, P49)),
            action(item(P21), item(P49, status="Failed", message="Unsupported map on Ethernet1/49")),
            post_action,
            intent_topology(P21),
            intent_topology(P21, ready_children=(P21 + "/1",)),
            action(item(P21 + "/1")),
        ],
        config=[group(P21, P49)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["may_have_changed"] is True
    assert "Unsupported map on Ethernet1/49" in report["msg"]
    assert "Unexpected breakout family 'Ethernet1/23'" in report["msg"]
    outcomes = {entry["interface_name"]: entry for entry in report["api_outcomes"]}
    assert outcomes[P21]["outcome"] == "success"
    assert outcomes[P49]["outcome"] == "failed"
    assert outcomes[P49]["message"] == "Unsupported map on Ethernet1/49"
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert [entry["interface_name"] for entry in report["recovery"][0]["api_outcomes"]] == [P21]
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
    actions = writes(calls)
    assert [call["path"] for call in actions] == [BREAKOUT, REMOVE]
    assert actions[0]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": P21, "breakoutMap": "25g-4x"},
            {"switchId": SERIAL, "interfaceName": P49, "breakoutMap": "25g-4x"},
        ]
    }
    assert actions[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert all(call["payload"] is None for call in calls if call["verb"] == HttpVerbEnum.GET)
    reads = summary_calls(calls)
    assert len(reads) == 4
    for call in reads[2:]:
        assert_targeted_read(call)
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert clock.sleeps


def test_cold_delete_waits_for_complete_recovery_speeds_after_one_child_becomes_ready(clock):
    report, calls = run(
        [
            intent_topology(P21),
            intent_topology(P21, ready_children=(P21 + "/1",)),
            topology(P21),
            action(item(P21 + "/1")),
            topology(native=(P21,)),
        ],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["api_outcomes"][0]["api_interface_name"] == P21 + "/1"
    assert report["api_outcomes"][0]["outcome"] == "success"
    assert report["before"][0]["evidence"] == "controller_intent"
    assert report["after_status"] == "observed"
    assert report["recovery"] == []
    reads = summary_calls(calls)
    assert len(reads) == 4
    for call in reads[1:3]:
        assert_targeted_read(call)
    assert [call["path"] for call in calls[1:]] == [reads[0]["path"], reads[1]["path"], reads[2]["path"], REMOVE, reads[3]["path"]]
    assert len(writes(calls)) == 1
    assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert clock.sleeps


def test_ready_nonfirst_child_with_complete_cached_speeds_is_used_for_forward_delete_without_wait(clock):
    baseline = intent_topology(P21, ready_children=(P21 + "/2",))
    for row in baseline["DATA"]["interfaces"]:
        row["speed"] = "25Gb"
    report, calls = run(
        [baseline, action(item(P21 + "/2")), topology(native=(P21,))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["api_outcomes"][0]["api_interface_name"] == P21 + "/2"
    assert report["api_outcomes"][0]["outcome"] == "success"
    assert report["recovery"] == []
    assert report["after_status"] == "observed" and report["after"][0]["broken_out"] is False
    assert len(summary_calls(calls)) == 2
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/2"}]}
    assert clock.sleeps == []
