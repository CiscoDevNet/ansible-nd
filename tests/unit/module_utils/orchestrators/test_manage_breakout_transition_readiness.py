# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Resolve contradictory unbreakout intent before deciding recovery eligibility.

Scripted requests distinguish delayed child-policy removal from a family that
remains physically broken out. No controller or wall-clock delay is involved.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_readiness import (
    BREAKOUT,
    P21,
    P23,
    REMOVE,
    SERIAL,
    VERIFY,
    action,
    assert_targeted_read,
    clock as shared_clock_fixture,
    group,
    implementation,
    intent_topology,
    item,
    response,
    run,
    summary_calls,
    topology,
    writes,
)

clock = shared_clock_fixture


def test_stale_removed_family_is_settled_before_inverse_breakout(clock):
    report, calls = run(
        [
            topology(P21, P23),
            action(item(P21 + "/1")),
            intent_topology(P21),
            intent_topology(P21),
            intent_topology(native=(P21,)),
            action(item(P21)),
        ],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["may_have_changed"] is True
    assert "Retained breakout family 'Ethernet1/23' disappeared" in report["msg"]
    assert "include 'Ethernet1/23' in the deleted config too" in report["msg"]
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert report["recovery"][0]["topology_verified"] is False
    assert [call["path"] for call in writes(calls)] == [REMOVE, BREAKOUT]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21, "breakoutMap": "25g-4x"}]}
    reads = summary_calls(calls)
    assert len(reads) == 4
    for call in reads[2:]:
        assert_targeted_read(call)
    assert clock.sleeps == [2, 2]
    assert all(call["payload"] is None for call in calls if call["verb"] == HttpVerbEnum.GET)
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert report.get("after", []) == [] and report["after_status"] == "unknown"


def test_rediscovered_original_family_is_not_recreated_when_it_remains_broken(clock):
    report, calls = run(
        [topology(P21, P23), action(item(P21 + "/1")), intent_topology(P21), topology(P21)],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert "Retained breakout family 'Ethernet1/23' disappeared" in report["msg"]
    assert report["recovery"][0]["status"] == "not_attempted"
    assert report["recovery"][0]["api_outcomes"] == []
    assert "No changed original parent" in report["recovery"][0]["msg"]
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    assert len(summary_calls(calls)) == 3
    assert_targeted_read(summary_calls(calls)[2])
    assert clock.sleeps == [2]
    assert report.get("after", []) == [] and report["after_status"] == "unknown"


@pytest.mark.parametrize("failure", ["timeout", "malformed", "transport"])
def test_unresolved_removed_family_preserves_changes_without_guessing_inverse(clock, failure):
    pending = intent_topology(P21)
    failed_reads = (
        [deepcopy(pending) for _unused_attempt in range(60)]
        if failure == "timeout"
        else [response({"interfaces": None})] if failure == "malformed" else [ValueError("Transition GET connection interrupted")]
    )
    report, calls = run(
        [topology(P21, P23), action(item(P21 + "/1")), pending, *failed_reads],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["changed"] is True
    assert report["may_have_changed"] is True
    assert report["recovery"][0]["status"] == "not_attempted"
    assert report["recovery"][0]["api_outcomes"] == []
    assert {row["interface_name"] for row in report["observed_before_recovery"]} == {P21}
    assert [call["path"] for call in writes(calls)] == [REMOVE]
    for call in summary_calls(calls)[2:]:
        assert_targeted_read(call)
        assert call["payload"] is None
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
    if failure == "timeout":
        assert "90" in report["recovery"][0]["msg"]
        assert 90 <= clock.now <= 92
    else:
        assert len(summary_calls(calls)) == 3
        assert "Transition GET" in report["recovery"][0]["msg"] or "interfaces array" in report["recovery"][0]["msg"]


@pytest.mark.parametrize("failure", ["timeout", "server_error"])
def test_incomplete_remove_never_polls_transition_or_submits_inverse(clock, monkeypatch, failure):
    if failure == "server_error":
        original_timeout = implementation.RestSend.timeout
        monkeypatch.setattr(implementation.RestSend, "timeout", property(original_timeout.fget, lambda self, value: original_timeout.fset(self, 1)))
    failed_reply = (
        TimeoutError("Unbreakout POST response lost") if failure == "timeout" else response({"message": "Controller unavailable"}, code=500, method="POST")
    )
    report, calls = run(
        [topology(P21, P23), failed_reply, intent_topology(P21)],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True and report["may_have_changed"] is True
    assert report["recovery"][0]["status"] == "not_attempted"
    assert report["recovery"][0]["api_outcomes"] == []
    assert "did not report synchronous completion" in report["recovery"][0]["msg"]
    assert len(writes(calls)) == 1 and writes(calls)[0]["path"] == REMOVE
    assert len(summary_calls(calls)) == 2
    assert clock.sleeps == []
    assert report.get("after", []) == [] and report["after_status"] == "unknown"
