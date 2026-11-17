# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Exercise configurable wait budgets through the real workflow and a virtual clock.

Scripted controller responses distinguish discovery prerequisites from forward
verification. These tests do not contact a switch or retry mutation requests.
"""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guard_settling import assert_guard_queries
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import combined
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import RecordingSender
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_readiness import (
    BREAKOUT,
    P21,
    P23,
    P49,
    REMOVE,
    SERIAL,
    action,
    assert_targeted_read,
    clock as shared_clock_fixture,
    group,
    intent_topology,
    item,
    response,
    run,
    summary_calls,
    topology,
    writes,
)

clock = shared_clock_fixture


@pytest.mark.parametrize("state", ["deleted", "overridden"])
def test_longer_verification_budget_accepts_native_restoration_after_thirty_seconds(clock, state):
    retained = (P23,) if state == "overridden" else ()
    pending = topology(P21, *retained)
    responses = [topology(P21, native=retained)]
    if state == "overridden":
        responses.extend([action(item(P23)), deepcopy(pending)])
    responses.extend([action(item(P21 + "/1")), *[deepcopy(pending) for _ in range(7)], topology(*retained, native=(P21,))])
    report, calls = run(
        responses,
        state=state,
        config=[group(P23)] if state == "overridden" else [group(P21, breakout_map=None)],
        verify={"enabled": True, "wait_timeout": 40},
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "observed"
    assert report["recovery"] == []
    assert all(phase["topology_matches"] for phase in report["verification"]["phases"])
    assert clock.now == 35 and clock.sleeps == [5] * 7
    assert [call["path"] for call in writes(calls)] == ([BREAKOUT, REMOVE] if state == "overridden" else [REMOVE])
    assert_guard_queries(calls)


def test_shorter_override_verification_budget_preserves_two_successful_creations(clock):
    # Match the reported create-two/remove-one failure without inventing recovery.
    pending = topology(P21, P23, P49)
    report, calls = run(
        [
            topology(P49, native=(P21, P23)),
            action(item(P21), item(P23)),
            deepcopy(pending),
            action(item(P49 + "/1")),
            deepcopy(pending),
            deepcopy(pending),
        ],
        state="overridden",
        config=[group(P21, P23)],
        verify={"enabled": True, "wait_timeout": 7},
    )
    assert report["failed"] is True and report["changed"] is True
    assert "within the 7-second verification budget" in report["msg"]
    assert report["after_status"] == "observed" and report["recovery"] == []
    assert all(row["broken_out"] for row in report["after"])
    assert {row["interface_name"] for row in report["after"]} == {P21, P23, P49}
    assert all(outcome["outcome"] == "success" for outcome in report["api_outcomes"])
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert clock.now == 7 and clock.sleeps == [5, 2]
    assert len(summary_calls(calls)) == 4
    assert_guard_queries(calls)


def test_override_gives_each_action_phase_its_own_verification_budget(clock):
    baseline = topology(P23, native=(P21,))
    both = topology(P21, P23)
    report, calls = run(
        [baseline, action(item(P21)), deepcopy(baseline), deepcopy(both), action(item(P23 + "/1")), both, topology(P21, native=(P23,))],
        state="overridden",
        config=[group(P21)],
        verify={"enabled": True, "wait_timeout": 6},
    )
    assert report["failed"] is False and report["changed"] is True
    assert clock.now == 10 and clock.sleeps == [5, 5]
    assert all(phase["topology_matches"] for phase in report["verification"]["phases"])
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert report["recovery"] == []


def test_custom_verification_deadline_stops_a_paginated_guard_before_the_next_get(clock, monkeypatch):
    original = RecordingSender.commit
    action_started = False

    def slow_commit(self):
        nonlocal action_started
        original(self)
        if self.verb == HttpVerbEnum.POST:
            action_started = True
        elif action_started and "/interfacesSummary?" in self.path:
            clock.now += 8

    monkeypatch.setattr(RecordingSender, "commit", slow_commit)
    first_page = response({"interfaces": topology(P21)["DATA"]["interfaces"][:1], "meta": {"counts": {"total": 2, "remaining": 1}}})
    report, calls = run(
        [topology(native=(P21,)), action(item(P21)), first_page],
        config=[group(P21)],
        verify={"enabled": True, "wait_timeout": 7},
    )
    assert report["failed"] is True and report["changed"] is True
    assert "7-second verification budget expired" in report["msg"]
    assert report["verification"]["complete"] is False
    assert report["after_status"] == "unknown" and report.get("after", []) == []
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert clock.sleeps == []


@pytest.mark.parametrize("state", ["deleted", "overridden"])
def test_shorter_discovery_budget_stops_before_any_forward_mutation(clock, state):
    baseline = intent_topology(P21)
    if state == "overridden":
        baseline = combined(baseline, topology(native=(P23,)))
    report, calls = run(
        [baseline, intent_topology(P21)],
        state=state,
        config=[group(P23)] if state == "overridden" else [group(P21, breakout_map=None)],
        verify={"enabled": True, "discovery_timeout": 6},
    )
    assert report["failed"] is True and report["changed"] is False
    assert "within 6 seconds" in report["msg"]
    assert "no inverse or unbreakout request was sent" in report["msg"]
    assert report["after_status"] == "unknown" and report["recovery"] == []
    assert writes(calls) == []
    assert clock.now == 6 and clock.sleeps == [5, 1]
    assert len(summary_calls(calls)) == 2
    assert_targeted_read(summary_calls(calls)[1])


@pytest.mark.parametrize("state", ["deleted", "overridden"])
@pytest.mark.parametrize("discovery_timeout", [1, 3])
def test_discovery_budget_shorter_than_poll_interval_stops_without_a_readiness_get(clock, state, discovery_timeout):
    baseline = intent_topology(P21)
    if state == "overridden":
        baseline = combined(baseline, topology(native=(P23,)))
    report, calls = run(
        [baseline],
        state=state,
        config=[group(P23)] if state == "overridden" else [group(P21, breakout_map=None)],
        verify={"enabled": True, "discovery_timeout": discovery_timeout},
    )
    assert report["failed"] is True and report["changed"] is False
    assert f"within {discovery_timeout} seconds" in report["msg"]
    assert "no inverse or unbreakout request was sent" in report["msg"]
    assert report["after_status"] == "unknown" and report["recovery"] == []
    assert writes(calls) == []
    assert clock.now == discovery_timeout and clock.sleeps == [discovery_timeout]
    assert len(summary_calls(calls)) == 1


def test_longer_discovery_budget_can_obtain_a_recovery_map_after_ninety_seconds(clock):
    pending = intent_topology(P21)
    report, calls = run(
        [pending, *[deepcopy(pending) for _ in range(18)], topology(P21), action(item(P21 + "/1")), topology(native=(P21,))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify={"enabled": True, "discovery_timeout": 98},
    )
    assert report["failed"] is False and report["changed"] is True
    assert clock.now == 95 and clock.sleeps == [5] * 19
    assert report["after_status"] == "observed" and report["recovery"] == []
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    for call in summary_calls(calls)[1:-1]:
        assert_targeted_read(call)


@pytest.mark.parametrize("scenario", ["inverse_unbreakout", "inverse_breakout", "unbreakout_transition"])
def test_custom_discovery_budget_bounds_recovery_readiness_without_an_inverse_write(clock, scenario):
    if scenario == "inverse_unbreakout":
        responses = [topology(native=(P21, P23)), action(item(P21)), intent_topology(P21, P23), intent_topology(P21)]
        state, config, forward = "merged", [group(P21)], BREAKOUT
    else:
        pending = intent_topology(P21) if scenario == "unbreakout_transition" else topology()
        responses = [topology(P21, P23), action(item(P21 + "/1")), pending, deepcopy(pending)]
        state, config, forward = "deleted", [group(P21, breakout_map=None)], REMOVE
    report, calls = run(responses, state=state, config=config, verify={"enabled": True, "discovery_timeout": 6})
    assert report["failed"] is True and report["changed"] is True
    assert report["after_status"] == "unknown" and report.get("after", []) == []
    assert report["recovery"][0]["status"] == "not_attempted"
    assert "within 6 seconds" in report["recovery"][0]["msg"]
    assert report["recovery"][0]["api_outcomes"] == []
    assert [call["path"] for call in writes(calls)] == [forward]
    assert clock.now == 6 and clock.sleeps == [5, 1]
    assert_targeted_read(summary_calls(calls)[-1])


@pytest.mark.parametrize("scenario", ["noop", "check_mode", "verify_disabled"])
def test_custom_budgets_add_no_waits_or_reads_when_checks_do_not_run(clock, scenario):
    verify = {"enabled": scenario != "verify_disabled", "wait_timeout": 1, "discovery_timeout": 1}
    responses = [topology(P21) if scenario == "noop" else topology(native=(P21,))]
    if scenario == "verify_disabled":
        responses.append(action(item(P21)))
    report, calls = run(responses, config=[group(P21)], verify=verify, check_mode=scenario == "check_mode")
    assert report["failed"] is False
    assert report["after_status"] == {"noop": "unchanged", "check_mode": "predicted", "verify_disabled": "response_confirmed"}[scenario]
    assert len(summary_calls(calls)) == 1
    assert len(writes(calls)) == (1 if scenario == "verify_disabled" else 0)
    assert clock.sleeps == []
