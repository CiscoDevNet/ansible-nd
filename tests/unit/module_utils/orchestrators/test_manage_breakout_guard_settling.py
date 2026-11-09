# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Original-action guard settling with scripted REST and a virtual clock.

These tests never contact a controller. A later GET may resolve a successful
action's topology transition; it cannot repair its API receipt or verify an
inverse. Every transport call remains visible through the real workflow.
"""

from __future__ import annotations

from copy import deepcopy
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import (
    P21,
    P23,
    P49,
    assert_no_map_or_deploy_queries,
    summary_calls,
    topology,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import (
    BREAKOUT,
    OTHER_SERIAL,
    REMOVE,
    RecordingSender,
    SERIAL,
    action,
    group,
    item,
    outcomes,
    response,
    run,
    writes,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_readiness import (
    FAST,
    VERIFY,
    clock,
    implementation,
    intent_topology,
)


def assert_guard_queries(calls):
    """Settling must retain complete switch scope and never carry a POST body."""
    for call in summary_calls(calls):
        query = parse_qs(urlsplit(call["path"]).query)
        assert query["filter"] == ["interfaceType:ethernet AND switchId:" + query["switchId"][0]]
        assert query["includeAll"] == ["true"]
        assert query["switchId"] in ([SERIAL], [OTHER_SERIAL])
        assert call["verb"] == HttpVerbEnum.GET
        assert call["payload"] is None
    assert_no_map_or_deploy_queries(calls)


@pytest.mark.parametrize("intent_only", [False, True])
def test_delayed_creation_uses_later_complete_snapshot_without_replaying_post(clock, intent_only):
    final = intent_topology(P21) if intent_only else topology(P21)
    report, calls = run(
        [topology(native=(P21,)), action(item(P21)), topology(native=(P21,)), final],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["may_have_changed"] is False
    assert report["api_outcomes"][0]["outcome"] == "success"
    assert report["after_status"] == "observed"
    assert report["after"][0]["interface_name"] == P21
    assert report["after"][0]["broken_out"] is True
    assert len(report["after"][0]["children"]) == 4
    if intent_only:
        assert report["after"][0]["evidence"] == "controller_intent"
    assert report["recovery"] == []
    assert len(writes(calls)) == 1 and writes(calls)[0]["path"] == BREAKOUT
    assert len(summary_calls(calls)) == 3
    assert clock.sleeps == [5]
    assert len(report["verification"]["phases"]) == 1
    assert report["verification"]["phases"][0]["topology_matches"] is True
    assert_guard_queries(calls)


@pytest.mark.parametrize("intent_only", [False, True])
def test_delayed_unbreakout_accepts_native_evidence_without_replaying_remove(clock, intent_only):
    # A parent can be present before its active native policy is available.
    pending = intent_topology(native=(P21,), policy_id=None)
    final = intent_topology(native=(P21,)) if intent_only else topology(native=(P21,))
    report, calls = run(
        [topology(P21), action(item(P21 + "/1")), pending, final],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["may_have_changed"] is False
    assert report["after_status"] == "observed"
    assert report["after"][0]["broken_out"] is False
    assert report["after"][0]["children"] == []
    if intent_only:
        assert report["after"][0]["evidence"] == "controller_intent"
    assert report["recovery"] == []
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert len(summary_calls(calls)) == 3
    assert clock.sleeps == [5]
    assert_guard_queries(calls)


@pytest.mark.parametrize("parent", [P21, "Ethernet1/29"])
def test_native_intent_with_old_discovered_50g_children_settles_to_intent_only_parent(clock, parent):
    # Live C50x4-delete shape: a new active native policy coexists with old
    # discovered physical children that no longer have child policy IDs.
    native = intent_topology(native=(parent,))
    old_children = topology(parent, speed="50Gb")["DATA"]["interfaces"]
    assert all(row["physicalInterface"] is True and row["discovered"] is True and "policyId" not in row for row in old_children)
    rows = deepcopy(native["DATA"]["interfaces"]) + deepcopy(old_children)
    pending = response({"interfaces": rows, "meta": {"counts": {"total": len(rows), "remaining": 0}}})
    report, calls = run(
        [topology(parent, speed="50Gb"), action(item(parent + "/1")), pending, deepcopy(pending), native],
        state="deleted",
        config=[group(parent, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "observed"
    assert report["after"] == [{"switch_id": SERIAL, "interface_name": parent, "broken_out": False, "children": [], "evidence": "controller_intent"}]
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": parent + "/1"}]}
    assert report["recovery"] == []
    assert len(summary_calls(calls)) == 4
    assert clock.sleeps == [5, 5]
    assert_guard_queries(calls)


def test_only_unresolved_mutated_switch_is_requeried(clock):
    report, calls = run(
        [
            topology(native=(P21,)),
            topology(native=(P49,), switch=OTHER_SERIAL),
            action(item(P49, switch=OTHER_SERIAL), item(P21)),
            topology(P21),
            topology(native=(P49,), switch=OTHER_SERIAL),
            topology(P49, switch=OTHER_SERIAL),
        ],
        config=[group(P21), group(P49, switch=OTHER_SERIAL)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "observed"
    assert {(row["switch_id"], row["interface_name"]) for row in report["after"]} == {(SERIAL, P21), (OTHER_SERIAL, P49)}
    assert [parse_qs(urlsplit(call["path"]).query)["switchId"][0] for call in summary_calls(calls)] == [
        SERIAL,
        OTHER_SERIAL,
        SERIAL,
        OTHER_SERIAL,
        OTHER_SERIAL,
    ]
    assert len(writes(calls)) == 1
    assert clock.sleeps == [5]
    assert_guard_queries(calls)


def test_recheck_consumes_complete_pagination_before_comparing(clock):
    final = topology(P21, native=(P49,))["DATA"]["interfaces"]
    first_page = response({"interfaces": final[:2], "meta": {"counts": {"total": len(final), "remaining": len(final) - 2}}})
    last_page = response({"interfaces": final[2:], "meta": {"counts": {"total": len(final), "remaining": 0}}})
    report, calls = run(
        [topology(native=(P21, P49)), action(item(P21)), topology(native=(P21, P49)), first_page, last_page],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after"][0]["children"] == [P21 + "/" + str(lane) for lane in (1, 2, 3, 4)]
    assert [parse_qs(urlsplit(call["path"]).query)["offset"][0] for call in summary_calls(calls)] == ["0", "0", "0", "2"]
    assert len(writes(calls)) == 1
    assert clock.sleeps == [5]
    assert_guard_queries(calls)


def test_collateral_appearing_during_settling_stops_wait_and_uses_existing_inverse(clock):
    report, calls = run(
        [topology(native=(P21, P23)), action(item(P21)), topology(native=(P21, P23)), topology(P21, P23), action(item(P21 + "/1"))],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert "Unexpected breakout family 'Ethernet1/23'" in report["msg"]
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert report["recovery"][0]["topology_verified"] is False
    assert report["after_status"] == "unknown" and report.get("after", []) == []
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert len(summary_calls(calls)) == 3
    assert clock.sleeps == [5]
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert_guard_queries(calls)


@pytest.mark.parametrize("state", ["merged", "overridden"])
def test_exhaustion_preserves_confirmed_changes_last_snapshot_and_stops_cleanup(clock, state):
    pending = topology(P23, native=(P21,)) if state == "overridden" else topology(native=(P21,))
    report, calls = run(
        [deepcopy(pending), action(item(P21)), *[deepcopy(pending) for _ in range(12)]],
        state=state,
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["may_have_changed"] is False
    assert report["api_outcomes"][-1]["outcome"] == "success"
    assert report["after_status"] == "observed"
    after = {(row["switch_id"], row["interface_name"]): row for row in report["after"]}
    assert after[(SERIAL, P21)]["broken_out"] is False
    assert report["verification"]["complete"] is True
    assert report["verification"]["phases"][0]["topology_matches"] is False
    assert report["recovery"] == []
    assert [call["path"] for call in writes(calls)] == [BREAKOUT]
    assert 25 <= clock.now <= 30
    assert clock.sleeps and all(0 < delay <= 5 for delay in clock.sleeps)
    assert len(summary_calls(calls)) <= 7
    assert_guard_queries(calls)


def test_get_latency_consumes_the_same_guard_budget(clock, monkeypatch):
    original = implementation.ManageBreakoutInterfacesOrchestrator._topology_snapshot

    def slow_snapshot(self, switch_ids=None, evidence="post_action_discovery"):
        snapshot = original(self, switch_ids, evidence=evidence)
        if evidence != "initial_discovery":
            clock.now += 20
        return snapshot

    monkeypatch.setattr(implementation.ManageBreakoutInterfacesOrchestrator, "_topology_snapshot", slow_snapshot)
    pending = topology(native=(P21,))
    report, calls = run([deepcopy(pending), action(item(P21)), *[deepcopy(pending) for _ in range(8)]], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["changed"] is True
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 3
    assert clock.sleeps == [5]
    assert clock.now == 45
    assert_guard_queries(calls)


def test_initial_guard_read_that_exhausts_budget_is_not_followed_by_another_get(clock, monkeypatch):
    original = implementation.ManageBreakoutInterfacesOrchestrator._topology_snapshot

    def slow_snapshot(self, switch_ids=None, evidence="post_action_discovery"):
        snapshot = original(self, switch_ids, evidence=evidence)
        if evidence != "initial_discovery":
            clock.now += 31
        return snapshot

    monkeypatch.setattr(implementation.ManageBreakoutInterfacesOrchestrator, "_topology_snapshot", slow_snapshot)
    report, calls = run([topology(native=(P21,)), action(item(P21)), topology(native=(P21,))], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["changed"] is True
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert clock.sleeps == []


def test_budget_expiring_during_pagination_does_not_start_the_next_page(clock, monkeypatch):
    original = RecordingSender.commit
    action_started = False

    def slow_commit(self):
        nonlocal action_started
        original(self)
        if self.verb == HttpVerbEnum.POST:
            action_started = True
        elif action_started and "/interfacesSummary?" in self.path:
            clock.now += 31

    monkeypatch.setattr(RecordingSender, "commit", slow_commit)
    parent = topology(native=(P21,))["DATA"]["interfaces"]
    first_page = response({"interfaces": parent, "meta": {"counts": {"total": 2, "remaining": 1}}})
    unused_next_page = response({"interfaces": topology(native=(P49,))["DATA"]["interfaces"], "meta": {"counts": {"total": 2, "remaining": 0}}})
    report, calls = run([topology(native=(P21,)), action(item(P21)), first_page, unused_next_page], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["changed"] is True
    assert report["verification"]["complete"] is False
    assert report["after_status"] == "unknown" and report.get("after", []) == []
    assert "verification budget expired" in report["msg"]
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert clock.sleeps == []


@pytest.mark.parametrize(
    "failure",
    [response({"interfaces": None}), ValueError("Settling GET interrupted"), response({"message": "Controller unavailable"}, code=500)],
    ids=["malformed", "transport", "http_500"],
)
def test_recheck_error_preserves_accepted_change_without_stale_after_or_inverse(clock, failure):
    report, calls = run(
        [topology(native=(P21,)), action(item(P21)), topology(native=(P21,)), failure],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["may_have_changed"] is True
    assert report["api_outcomes"][0]["outcome"] == "success"
    assert report["verification"]["complete"] is False
    assert report["after_status"] == "unknown" and report.get("after", []) == []
    assert report["recovery"] == []
    assert len(summary_calls(calls)) == 3 and len(writes(calls)) == 1
    assert clock.sleeps == [5]
    assert_guard_queries(calls)


@pytest.mark.parametrize("receipt", ["explicit_error", "missing_result", "wrong_identity"])
def test_api_failures_never_gain_a_settling_wait_or_success_from_matching_topology(clock, receipt):
    reply = (
        action(item(P21, status="Failed", message="Unsupported map"))
        if receipt == "explicit_error"
        else action() if receipt == "missing_result" else action(item(P23))
    )
    report, calls = run([topology(native=(P21,)), reply, topology(P21)], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["changed"] is True
    assert report["api_outcomes"][0]["outcome"] == ("failed" if receipt == "explicit_error" else "unknown")
    assert report["after_status"] == "observed"
    assert report["verification"]["phases"][0]["topology_matches"] is True
    assert report["recovery"] == []
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert clock.sleeps == []


@pytest.mark.parametrize("receipt", ["explicit_error", "missing_result"])
def test_definite_api_failure_does_not_poll_an_unresolved_topology(clock, receipt):
    reply = action(item(P21, status="Failed", message="Unsupported map")) if receipt == "explicit_error" else action()
    report, calls = run([topology(native=(P21,)), reply, topology(native=(P21,))], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True
    assert outcomes(report)[(SERIAL, P21)]["outcome"] == ("failed" if receipt == "explicit_error" else "unknown")
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert report["recovery"] == []
    assert clock.sleeps == []


@pytest.mark.parametrize("failure", ["timeout", "server_error"])
def test_incomplete_forward_transport_has_no_guard_settling_or_inverse(clock, monkeypatch, failure):
    if failure == "server_error":
        timeout = implementation.RestSend.timeout
        monkeypatch.setattr(implementation.RestSend, "timeout", property(timeout.fget, lambda self, value: timeout.fset(self, 1)))
    reply = TimeoutError("Forward action response lost") if failure == "timeout" else response({"message": "Controller unavailable"}, code=500, method="POST")
    report, calls = run([topology(native=(P21,)), reply, topology(native=(P21,))], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["may_have_changed"] is True
    assert report["api_outcomes"][0]["outcome"] in {"failed", "unknown"}
    assert report["recovery"] == []
    assert len(summary_calls(calls)) == 2 and len(writes(calls)) == 1
    assert clock.sleeps == []


@pytest.mark.parametrize("scenario", ["first_match", "noop", "check_mode", "verify_disabled"])
def test_first_match_and_nonexecuting_paths_keep_their_existing_get_budget(clock, scenario):
    scripted = [topology(P21) if scenario == "noop" else topology(native=(P21,))]
    if scenario in {"first_match", "verify_disabled"}:
        scripted.append(action(item(P21)))
    if scenario == "first_match":
        scripted.append(topology(P21))
    report, calls = run(scripted, config=[group(P21)], verify=FAST if scenario == "verify_disabled" else VERIFY, check_mode=scenario == "check_mode")
    assert report["failed"] is False
    assert len(summary_calls(calls)) == (2 if scenario == "first_match" else 1)
    assert len(writes(calls)) == (1 if scenario in {"first_match", "verify_disabled"} else 0)
    assert report.get("recovery", []) == []
    assert clock.sleeps == []


def test_override_waits_for_validated_creation_before_starting_removal(clock):
    report, calls = run(
        [
            topology(P23, native=(P21,)),
            action(item(P21)),
            topology(P23, native=(P21,)),
            topology(P21, P23),
            action(item(P23 + "/1")),
            topology(P21, native=(P23,)),
        ],
        state="overridden",
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False and report["changed"] is True
    assert report["after_status"] == "observed"
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert [entry["phase"] for entry in report["verification"]["phases"]] == ["breakout", "unbreakout"]
    assert all(entry["topology_matches"] for entry in report["verification"]["phases"])
    assert len(summary_calls(calls)) == 4
    assert clock.sleeps == [5]
    assert_guard_queries(calls)


@pytest.mark.parametrize("scenario", ["read_failure", "exhaustion", "late_collateral"])
def test_guard_restores_original_attempt_limit_and_deadline_before_return_or_inverse(clock, monkeypatch, scenario):
    orchestrator = implementation.ManageBreakoutInterfacesOrchestrator
    original_action = orchestrator._execute_action
    original_guard = orchestrator._observe_action_guard
    attempts_property = implementation.RestSend.max_attempts
    attempt_assignments, action_limits, guard_limits = [], [], []

    def assign_attempts(self, value):
        attempt_assignments.append(value)
        attempts_property.fset(self, value)

    monkeypatch.setattr(implementation.RestSend, "max_attempts", property(attempts_property.fget, assign_attempts))

    def record_action(self, *args, **kwargs):
        if not action_limits:
            # A nondefault existing limit exposes accidental restoration to a
            # hardcoded None, and must not be overwritten before the inverse.
            self.rest_send.max_attempts = 7
        action_limits.append(self.rest_send.max_attempts)
        return original_action(self, *args, **kwargs)

    def record_guard(self, *args, **kwargs):
        prior_limit = self.rest_send.max_attempts
        prior_deadline = self._verification_deadline
        try:
            return original_guard(self, *args, **kwargs)
        finally:
            guard_limits.append((prior_limit, self.rest_send.max_attempts, prior_deadline, self._verification_deadline))

    monkeypatch.setattr(orchestrator, "_execute_action", record_action)
    monkeypatch.setattr(orchestrator, "_observe_action_guard", record_guard)
    pending = topology(native=(P21, P23))
    if scenario == "read_failure":
        scripted = [deepcopy(pending), action(item(P21)), deepcopy(pending), response({"interfaces": None})]
    elif scenario == "exhaustion":
        scripted = [deepcopy(pending), action(item(P21)), *[deepcopy(pending) for _ in range(12)]]
    else:
        scripted = [deepcopy(pending), action(item(P21)), deepcopy(pending), topology(P21, P23), action(item(P21 + "/1"))]
    report, calls = run(scripted, config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True and report["changed"] is True
    assert guard_limits == [(7, 7, None, None)]
    assert 1 in attempt_assignments and attempt_assignments[-1] == 7
    assert action_limits == ([7, 7] if scenario == "late_collateral" else [7])
    assert [call["path"] for call in writes(calls)] == ([BREAKOUT, REMOVE] if scenario == "late_collateral" else [BREAKOUT])
    if scenario == "late_collateral":
        assert report["recovery"][0]["status"] == "response_confirmed"
        assert report["recovery"][0]["topology_verified"] is False
