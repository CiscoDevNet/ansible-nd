# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Bounded forward unbreakout retries through scripted, real REST handling.

Fresh summary responses authorize another attempt, not exactly-once execution.
These synthetic cases make every wire call observable and never contact a lab.
"""

from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_breakout_interfaces import ManageBreakoutInterfacesOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest import rest_send as rest_implementation
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules.nd_manage_breakout_interfaces import _format_output
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import summary_calls, topology
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import (
    BREAKOUT,
    OTHER_SERIAL,
    REMOVE,
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
    clock as shared_clock_fixture,
    intent_topology,
)

clock = shared_clock_fixture
P50, P51, P52 = ("Ethernet1/" + str(port) for port in (50, 51, 52))


@pytest.fixture(autouse=True)
def production_backoff_with_a_virtual_clock(monkeypatch, clock):
    """Exercise production delays without giving synthetic fixtures real sleeps."""
    unit_test = RestSend.unit_test
    monkeypatch.setattr(RestSend, "unit_test", property(lambda _self: False, unit_test.fset))
    monkeypatch.setattr(rest_implementation, "sleep", clock.sleep)


def delete(scripted, *, verify=False, names=(P50,), results=None):
    return run(scripted, state="deleted", config=[group(*names, breakout_map=None)], verify={"enabled": verify}, results=results)


def failed_remove(parent=P50, *, empty=False, code=207):
    return action(code=code) if empty else action(item(parent + "/1", status="Failed", message="Temporary unbreakout failure"), code=code)


def assert_gets_are_body_free(calls):
    assert all(call["payload"] is None for call in calls if call["verb"] == HttpVerbEnum.GET)
    assert all(not any(part in call["path"] for part in ("/policies", "configSave", "/deploy")) for call in calls)


@pytest.mark.parametrize("verify", [False, True])
def test_first_attempt_success_keeps_the_existing_get_budget(clock, verify):
    script = [topology(P50), action(item(P50 + "/1"))]
    if verify:
        script.append(topology(native=(P50,)))
    report, calls = delete(script, verify=verify)
    assert report["failed"] is False and report["changed"] is True
    assert report["api_outcomes"][0]["attempts"] == 1
    assert report["after_status"] == ("observed" if verify else "response_confirmed")
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 1 + verify
    assert clock.sleeps == []
    assert_gets_are_body_free(calls)


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("attempts", [2, 3])
@pytest.mark.parametrize("empty", [False, True], ids=["identified-failure", "empty-results"])
def test_later_explicit_success_replaces_transient_errors_without_losing_attempts(clock, verify, attempts, empty):
    script = [topology(P50)]
    for _unused_attempt in range(attempts - 1):
        script.extend([failed_remove(empty=empty), topology(P50)])
    script.append(action(item(P50 + "/1")))
    if verify:
        script.append(topology(native=(P50,)))
    report, calls = delete(script, verify=verify)
    assert report["failed"] is False and report["changed"] is True
    assert report["may_have_changed"] is False
    assert "Temporary unbreakout failure" not in report.get("msg", "")
    assert len(report["api_outcomes"]) == 1
    assert report["api_outcomes"][0]["outcome"] == "success"
    assert report["api_outcomes"][0]["attempts"] == attempts
    assert len(writes(calls)) == attempts
    assert len(summary_calls(calls)) == attempts + verify
    assert clock.sleeps == [5, 10][: attempts - 1]
    assert all(call["path"] == REMOVE for call in writes(calls))
    assert_gets_are_body_free(calls)


@pytest.mark.parametrize("code", [200, 201, 207])
def test_only_completed_success_class_envelopes_can_authorize_empty_result_retries(clock, code):
    report, calls = delete([topology(P50), failed_remove(empty=True, code=code), topology(P50), action(item(P50 + "/1"))])
    assert report["failed"] is False
    assert report["api_outcomes"][0]["attempts"] == 2
    assert len(writes(calls)) == 2 and clock.sleeps == [5]


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("empty", [False, True])
def test_failed_unbreakout_is_exhausted_at_exactly_three_wire_requests(clock, verify, empty):
    script = [topology(P50), failed_remove(empty=empty), topology(P50), failed_remove(empty=empty), topology(P50), failed_remove(empty=empty)]
    if verify:
        script.append(topology(P50))
    report, calls = delete(script, verify=verify)
    assert report["failed"] is True and report["changed"] is False
    assert report["api_outcomes"][0]["outcome"] == ("unknown" if empty else "failed")
    assert report["api_outcomes"][0]["attempts"] == 3
    assert report.get("recovery", []) == []
    assert len(writes(calls)) == 3
    assert len(summary_calls(calls)) == 3 + verify
    assert clock.sleeps == [5, 10]
    assert_gets_are_body_free(calls)


@pytest.mark.parametrize("verify", [False, True])
def test_bulk_retries_pin_success_and_use_a_fresh_child_for_only_the_failed_parent(clock, verify):
    script = [
        topology(P50, P51),
        action(item(P51 + "/1", status="Failed"), item(P50 + "/1")),
        topology(P51, native=(P50,), lanes=(2, 3, 4, 5)),
        action(item(P51 + "/2")),
    ]
    if verify:
        script.append(topology(native=(P50, P51)))
    report, calls = delete(script, verify=verify, names=(P50, P51))
    assert report["failed"] is False and report["changed"] is True
    assert len(report["api_outcomes"]) == 2
    by_parent = outcomes(report)
    assert by_parent[(SERIAL, P50)]["attempts"] == 1
    assert by_parent[(SERIAL, P51)]["attempts"] == 2
    assert [record["interface_name"] for record in report["api_outcomes"]] == [P50, P51]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P51 + "/2"}]}
    assert len(writes(calls)) == 2 and clock.sleeps == [5]
    probe = summary_calls(calls)[1]
    query = parse_qs(urlsplit(probe["path"]).query)
    assert query["filter"] == [("interfaceType:ethernet" if verify else "interfaceName:*" + P51 + "*") + " AND switchId:" + SERIAL]
    assert_gets_are_body_free(calls)


def test_retry_retains_the_users_child_selector_when_the_wire_child_changes(clock):
    report, calls = delete(
        [topology(P50), failed_remove(empty=True), topology(P50, lanes=(2, 3, 4, 5)), action(item(P50 + "/2"))],
        names=(P50 + "/4",),
    )
    assert report["failed"] is False
    outcome = report["api_outcomes"][0]
    assert outcome["interface_name"] == P50
    assert outcome["requested_interface_name"] == P50 + "/4"
    assert outcome["api_interface_name"] == P50 + "/2"
    assert outcome["attempts"] == 2
    assert [entry["payload"]["interfaces"][0]["interfaceName"] for entry in writes(calls)] == [P50 + "/1", P50 + "/2"]


@pytest.mark.parametrize("verify", [False, True])
def test_partial_bulk_exhaustion_keeps_confirmed_success_and_honest_after_evidence(clock, verify):
    script = [
        topology(P50, P51),
        action(item(P50 + "/1"), item(P51 + "/1", status="Failed")),
        topology(P51, native=(P50,)),
        failed_remove(P51),
        topology(P51, native=(P50,)),
        failed_remove(P51),
    ]
    if verify:
        script.append(topology(P51, native=(P50,)))
    report, calls = delete(script, verify=verify, names=(P50, P51))
    assert report["failed"] is True and report["changed"] is True
    assert len(report["api_outcomes"]) == 2
    by_parent = outcomes(report)
    assert by_parent[(SERIAL, P50)]["outcome"] == "success"
    assert by_parent[(SERIAL, P50)]["attempts"] == 1
    assert by_parent[(SERIAL, P51)]["outcome"] == "failed"
    assert by_parent[(SERIAL, P51)]["attempts"] == 3
    assert all(call["payload"]["interfaces"] == [{"switchId": SERIAL, "interfaceName": P51 + "/1"}] for call in writes(calls)[1:])
    if verify:
        assert {row["interface_name"]: row["broken_out"] for row in report["after"]} == {P50: False, P51: True}
        assert report["after_status"] == "observed"
    else:
        assert report["after_status"] == "unknown" and not report.get("after")
    assert report.get("recovery", []) == [] and clock.sleeps == [5, 10]


@pytest.mark.parametrize("verify", [False, True])
def test_nonempty_partial_receipt_with_an_unreported_item_is_not_replayed(clock, verify):
    script = [topology(P50, P51), action(item(P50 + "/1"))]
    if verify:
        script.append(topology(P51, native=(P50,)))
    report, calls = delete(script, verify=verify, names=(P50, P51))
    assert report["failed"] is True and report["changed"] is True
    assert outcomes(report)[(SERIAL, P50)]["outcome"] == "success"
    assert outcomes(report)[(SERIAL, P51)]["outcome"] == "unknown"
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 1 + verify
    assert clock.sleeps == []


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("terminal", ["timeout", "http500", "foreign"])
def test_retry_sequence_stops_immediately_if_a_later_attempt_becomes_uncertain(clock, verify, terminal):
    last = {
        "timeout": TimeoutError("Retry response lost"),
        "http500": response({"message": "Controller unavailable"}, code=500, method="POST"),
        "foreign": action(item(P52 + "/1")),
    }[terminal]
    script = [topology(P50), failed_remove(empty=True), topology(P50), last]
    if verify:
        script.append(topology(P50))
    report, calls = delete(script, verify=verify)
    assert report["failed"] is True
    assert report["api_outcomes"][0]["outcome"] == "unknown"
    assert report["api_outcomes"][0]["attempts"] == 2
    assert len(writes(calls)) == 2 and clock.sleeps == [5]
    assert report.get("recovery", []) == []


@pytest.mark.parametrize(
    "receipt",
    [
        response({}, code=207, method="POST"),
        response({"results": None}, code=207, method="POST"),
        response({"results": "not an array"}, code=207, method="POST"),
        response({"results": [None]}, code=207, method="POST"),
        action(item(P52 + "/1")),
        action(item(P50 + "/1"), item(P50 + "/1", status="Failed")),
        action({"status": "Failed"}),
        action(item(P50 + "/1", status="inProgress")),
        action(item(P50 + "/1", status="Failed"), code=202),
        response({"message": "Invalid request"}, code=400, method="POST"),
        response({"message": "Controller unavailable"}, code=500, method="POST"),
        action(item(P50 + "/1"), code=500),
        TimeoutError("Unbreakout response lost"),
    ],
    ids=[
        "missing-array",
        "null-array",
        "malformed-array",
        "malformed-row",
        "foreign",
        "duplicate",
        "missing-id",
        "in-progress",
        "accepted",
        "http400",
        "http500",
        "http500-success-body",
        "timeout",
    ],
)
def test_ambiguous_or_incomplete_transport_results_do_not_authorize_another_remove(clock, receipt):
    report, calls = delete([topology(P50), receipt])
    assert report["failed"] is True
    assert report["api_outcomes"][0]["attempts"] == 1
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 1
    assert clock.sleeps == []
    assert report.get("recovery", []) == []


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("state", ["native", "missing", "undiscovered", "ambiguous", "get-failed", "get-timeout"])
def test_retry_stops_when_fresh_observation_cannot_authorize_another_remove(clock, verify, state):
    observed = {
        "native": topology(native=(P50,)),
        "missing": topology(),
        "undiscovered": intent_topology(P50),
        "ambiguous": topology(P50, native=(P50,)),
        "get-failed": response({"message": "Read unavailable"}, code=500),
        "get-timeout": TimeoutError("Retry read response lost"),
    }[state]
    report, calls = delete([topology(P50), failed_remove(empty=True), observed], verify=verify)
    assert report["failed"] is True
    assert report["api_outcomes"][0]["outcome"] == "unknown"
    assert report["api_outcomes"][0]["attempts"] == 1
    assert report.get("recovery", []) == []
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 2
    assert clock.sleeps == [5]
    if state in {"native", "missing"}:
        assert report["changed"] is True
        if verify and state == "native":
            assert report["after"][0]["broken_out"] is False
    assert_gets_are_body_free(calls)


def test_collateral_read_stops_forward_retries_and_uses_the_original_recovery_map(clock):
    report, calls = delete(
        [topology(P50, P51), failed_remove(empty=True), topology(native=(P50, P51)), action(item(P50))],
        verify=True,
    )
    assert report["failed"] is True and report["changed"] is True
    assert [entry["path"] for entry in writes(calls)] == [REMOVE, BREAKOUT]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P50, "breakoutMap": "25g-4x"}]}
    assert report["api_outcomes"][0]["attempts"] == 1
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert "include 'Ethernet1/51' in the deleted config too" in report["msg"]
    assert clock.sleeps == [5]


def test_collateral_on_a_successful_switch_stops_retrying_the_other_switch(clock):
    report, calls = run(
        [
            topology(P50, P52),
            topology(P51, switch=OTHER_SERIAL),
            action(item(P50 + "/1"), item(P51 + "/1", switch=OTHER_SERIAL, status="Failed")),
            topology(native=(P50, P52)),
            topology(P51, switch=OTHER_SERIAL),
            action(item(P50)),
        ],
        state="deleted",
        config=[group(P50, breakout_map=None), group(P51, switch=OTHER_SERIAL, breakout_map=None)],
        verify={"enabled": True},
    )
    assert report["failed"] is True
    assert [entry["path"] for entry in writes(calls)] == [REMOVE, BREAKOUT]
    assert writes(calls)[1]["payload"]["interfaces"][0]["switchId"] == SERIAL
    assert outcomes(report)[(OTHER_SERIAL, P51)]["attempts"] == 1
    assert report["recovery"][0]["switch_id"] == SERIAL
    assert clock.sleeps == [5]


def test_overridden_exhaustion_preserves_earlier_validated_creations(clock):
    report, calls = run(
        [
            topology(P51, native=(P50,)),
            action(item(P50)),
            topology(P50, P51),
            failed_remove(P51),
            topology(P50, P51),
            failed_remove(P51),
            topology(P50, P51),
            failed_remove(P51),
            topology(P50, P51),
        ],
        state="overridden",
        config=[group(P50)],
        verify={"enabled": True},
    )
    assert report["failed"] is True and report["changed"] is True
    assert [entry["path"] for entry in writes(calls)] == [BREAKOUT, REMOVE, REMOVE, REMOVE]
    by_parent = outcomes(report)
    assert by_parent[(SERIAL, P50)]["outcome"] == "success"
    assert by_parent[(SERIAL, P51)]["attempts"] == 3
    assert report.get("recovery", []) == []
    assert {entry["interface_name"] for entry in report["after"] if entry["broken_out"]} == {P50, P51}
    assert clock.sleeps == [5, 10]


@pytest.mark.parametrize("finish", ["success", "exhausted"])
@pytest.mark.parametrize("shared_prefix", [False, True], ids=["exact-pending-family", "prefix-includes-created-family"])
def test_response_only_override_retries_do_not_invent_children_for_earlier_api_creations(clock, finish, shared_prefix):
    """An accepted creation has no discovered children in response-only state.

    A later removal retry must compare only its observed pending families. Its
    filtered response may also contain the newly created desired family when
    several removal targets share that family's leading port-number prefix.
    """
    pending = (P51, P52) if shared_prefix else (P51,)
    rejected = action(*(item(parent + "/1", status="Failed") for parent in pending))
    observed = topology(*((P50, *pending) if shared_prefix else pending))
    script = [topology(*pending, native=(P50,)), action(item(P50)), rejected, observed]
    if finish == "success":
        script.append(action(*(item(parent + "/1") for parent in pending)))
    else:
        script.extend([rejected, observed, rejected])
    report, calls = run(script, state="overridden", config=[group(P50)], verify={"enabled": False})
    attempts = 2 if finish == "success" else 3
    assert report["failed"] is (finish == "exhausted")
    assert report["changed"] is True
    assert len(report["api_outcomes"]) == 1 + len(pending)
    by_parent = outcomes(report)
    assert by_parent[(SERIAL, P50)]["outcome"] == "success"
    assert "attempts" not in by_parent[(SERIAL, P50)]
    assert all(by_parent[(SERIAL, parent)]["attempts"] == attempts for parent in pending)
    assert all(by_parent[(SERIAL, parent)]["outcome"] == ("success" if finish == "success" else "failed") for parent in pending)
    assert [entry["path"] for entry in writes(calls)] == [BREAKOUT] + [REMOVE] * attempts
    expected_removals = [{"switchId": SERIAL, "interfaceName": parent + "/1"} for parent in pending]
    assert all(call["payload"]["interfaces"] == expected_removals for call in writes(calls)[1:])
    assert len(summary_calls(calls)) == attempts
    for probe in summary_calls(calls)[1:]:
        query = parse_qs(urlsplit(probe["path"]).query)
        prefix = "Ethernet1/5" if shared_prefix else P51
        assert query["filter"] == ["interfaceName:*" + prefix + "* AND switchId:" + SERIAL]
    if finish == "success":
        created = next(row for row in report["after"] if row["interface_name"] == P50)
        assert created["broken_out"] is True and created["evidence"] == "api_response"
        assert "children" not in created
        assert report["after_status"] == "response_confirmed"
    else:
        assert report["after_status"] == "unknown" and not report.get("after")
    assert report.get("recovery", []) == []
    assert clock.sleeps == [5, 10][: attempts - 1]
    assert_gets_are_body_free(calls)


@pytest.mark.parametrize("finish", ["success", "timeout", "http500", "get-failed"])
def test_shared_attempt_limit_is_restored_after_every_forward_exit(monkeypatch, clock, finish):
    recorded = []
    original = ManageBreakoutInterfacesOrchestrator._execute_action

    def observe(self, submitted, state, *, recovery=False):
        if state == "deleted" and not recovery:
            recorded.append(self.rest_send)
            assert self.rest_send.max_attempts == 1
        return original(self, submitted, state, recovery=recovery)

    monkeypatch.setattr(ManageBreakoutInterfacesOrchestrator, "_execute_action", observe)
    script = [topology(P50)]
    if finish == "success":
        script.append(action(item(P50 + "/1")))
    elif finish == "timeout":
        script.append(TimeoutError("Remove timed out"))
    elif finish == "http500":
        script.append(response({"message": "Controller unavailable"}, code=500, method="POST"))
    else:
        script.extend([failed_remove(empty=True), response({"message": "Read unavailable"}, code=500)])
    report, calls = delete(script)
    assert report["failed"] is (finish != "success")
    assert recorded and all(writer.max_attempts is None for writer in recorded)
    assert len(writes(calls)) == 1


def test_successful_remove_uses_verification_get_polling_without_replaying_it(clock):
    report, calls = delete([topology(P50), action(item(P50 + "/1")), topology(P50), topology(native=(P50,))], verify=True)
    assert report["failed"] is False
    assert report["api_outcomes"][0]["attempts"] == 1
    assert len(writes(calls)) == 1 and len(summary_calls(calls)) == 3
    assert clock.sleeps == [5]


@pytest.mark.parametrize("verify", [False, True])
@pytest.mark.parametrize("already_native", [False, True])
def test_nonexecuting_paths_do_not_gain_retry_waits_or_attempt_counts(clock, verify, already_native):
    report, calls = run(
        [topology(native=(P50,)) if already_native else topology(P50)],
        state="deleted",
        config=[group(P50, breakout_map=None)],
        check_mode=not already_native,
        verify={"enabled": verify},
    )
    assert report["failed"] is False
    assert report["api_outcomes"][0]["outcome"] == ("noop" if already_native else "planned")
    assert "attempts" not in report["api_outcomes"][0]
    assert not writes(calls) and clock.sleeps == []


def test_breakout_failures_and_recovery_unbreakout_are_not_replayed(clock):
    report, calls = run([topology(native=(P50,)), action()], config=[group(P50)])
    assert report["failed"] is True and len(writes(calls)) == 1 and clock.sleeps == []
    report, calls = run(
        [topology(native=(P50, P51)), action(item(P50)), topology(P50, P51), failed_remove()],
        config=[group(P50)],
        verify={"enabled": True},
    )
    assert report["failed"] is True
    assert [entry["path"] for entry in writes(calls)] == [BREAKOUT, REMOVE]
    assert report["recovery"][0]["status"] == "failed"
    assert clock.sleeps == []


@pytest.mark.parametrize("verbosity,output_level", [(0, "normal"), (2, "info"), (3, "debug")])
def test_retry_history_and_final_business_results_follow_ndoutput_gating(clock, verbosity, output_level):
    trace = Results()
    report, calls = delete([topology(P50), failed_remove(empty=True), topology(P50), action(item(P50 + "/1"))], results=trace)
    module = SimpleNamespace(params={"output_level": output_level, "state": "deleted"}, _verbosity=verbosity)
    output = _format_output(module, report, trace)
    assert output["failed"] is False and output["changed"] is True
    assert len(output["api_outcomes"]) == 1 and output["api_outcomes"][0]["attempts"] == 2
    assert output["after_status"] == "response_confirmed" and output["after"][0]["broken_out"] is False
    assert len(trace.responses) == len(calls)
    assert ("api_calls" in output) is (verbosity >= 3)
    if verbosity >= 2:
        assert output["api_verbs"].count("POST") == 2
    if verbosity >= 3:
        assert output["api_response"] == trace.responses
        assert output["api_payload"] == trace.payload
        assert len([entry for entry in output["api_calls"] if entry["method"] == "POST"]) == 2
