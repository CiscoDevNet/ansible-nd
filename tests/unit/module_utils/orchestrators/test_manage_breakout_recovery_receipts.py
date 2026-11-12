# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""A single inverse may acknowledge a different coupled parent on the same switch.

These scripted receipts establish API acknowledgement only. They intentionally
perform no post-inverse read and do not establish controller/device restoration.
Forward actions and multi-target inverse requests retain exact identity matching.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_breakout_interfaces import ManageBreakoutInterfacesOrchestrator
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_guarded_workflows import (
    P21,
    P22,
    P23,
    P24,
    P49,
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


def _submitted(*names):
    return [{"switch_id": SERIAL, "interface_name": name, "api_interface_name": name, "breakout_map": "25g-4x"} for name in names]


@pytest.mark.parametrize("code", [200, 201, 207])
def test_single_s07_inverse_retains_different_reported_parent_as_acknowledgement_only(code):
    receipt = action(item(P21, message="Breakout completed for coupled parent"), code=code)
    original = deepcopy(receipt)
    report, calls = run(
        [topology(P21, P23), action(item(P23 + "/1")), topology(native=(P21, P22, P23, P24)), receipt],
        state="deleted",
        config=[group(P23, breakout_map=None)],
        verify={"enabled": True},
    )

    assert report["failed"] is True and report["changed"] is True
    assert report["api_outcomes"][0]["outcome"] == "success"
    assert report["api_outcomes"][0]["api_interface_name"] == P23 + "/1"
    recovery = report["recovery"][0]
    assert recovery["action"] == "breakout"
    assert recovery["status"] == "response_confirmed"
    assert recovery["topology_verified"] is False
    recovered = recovery["api_outcomes"][0]
    assert recovered["interface_name"] == recovered["api_interface_name"] == P23
    assert recovered["outcome"] == "success"
    assert recovered["reported_interface_name"] == P21
    assert recovered["identity_matched"] is False
    assert "not independently verified" in recovery["msg"]
    assert receipt == original
    assert report["after_status"] == "unknown" and report.get("after", []) == []
    assert [call["path"] for call in writes(calls)] == [REMOVE, BREAKOUT]
    assert writes(calls)[0]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P23 + "/1"}]}
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P23, "breakoutMap": "25g-4x"}]}
    assert len(summary_calls(calls)) == 2
    assert calls[-1]["verb"] == HttpVerbEnum.POST


@pytest.mark.parametrize("verify", [False, True])
def test_forward_result_with_a_different_parent_still_has_unknown_outcome(verify):
    scripted = [topology(native=(P21, P23)), action(item(P21))]
    if verify:
        scripted.append(topology(P23, native=(P21,)))
    report, calls = run(scripted, config=[group(P23)], verify={"enabled": verify})
    assert report["failed"] is True
    assert report["api_outcomes"][0]["interface_name"] == P23
    assert report["api_outcomes"][0]["outcome"] == "unknown"
    assert "unrequested identity" in report["msg"]
    assert not report.get("recovery")
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == (2 if verify else 1)


@pytest.mark.parametrize(
    "receipt",
    [
        action(item(P21, switch=OTHER_SERIAL)),
        action(item(P21, status="failed")),
        action(item(P21, status="error")),
        action(item(P21, status="warning")),
        action(item(P21, status="notexecuted")),
        action(item(P21, status=None)),
        action(item(P21, status="")),
        action(item(P21), code=202),
        action(item(P21), code=204),
        action(item(P21), code=400),
        action(item(P21), code=500),
        action(item("")),
        action(item("   ")),
        action(item(None)),
        action(),
        action(item(P21), item(P21)),
        action(item(P23), item(P23)),
        action(None),
        response({}, method="POST", code=207),
        response({"results": None}, method="POST", code=207),
        response({"results": {}}, method="POST", code=207),
        response({"results": "not an array"}, method="POST", code=207),
        response(None, method="POST", code=207),
    ],
)
def test_single_inverse_does_not_relax_incomplete_failed_ambiguous_or_foreign_switch_receipts(receipt):
    original = deepcopy(receipt)
    outcomes, errors = ManageBreakoutInterfacesOrchestrator._match_recovery_results(receipt, _submitted(P23), "breakout")
    assert len(outcomes) == 1
    assert outcomes[0]["outcome"] != "success"
    assert outcomes[0].get("identity_matched") is not False
    assert errors
    assert receipt == original


def test_extra_foreign_row_does_not_erase_strict_match_or_suppress_its_identity_error():
    outcomes, errors = ManageBreakoutInterfacesOrchestrator._match_recovery_results(action(item(P21), item(P23)), _submitted(P23), "breakout")
    assert outcomes[0]["outcome"] == "success"
    assert outcomes[0].get("identity_matched") is not False
    assert errors and any("unrequested identity" in error for error in errors)


@pytest.mark.parametrize("status", ["failed", "error", "failure"])
def test_matching_failed_single_inverse_remains_a_failure(status):
    outcomes, errors = ManageBreakoutInterfacesOrchestrator._match_recovery_results(action(item(P23, status=status)), _submitted(P23), "breakout")
    assert outcomes[0]["outcome"] == "failed"
    assert outcomes[0].get("reported_interface_name", P23) == P23
    assert outcomes[0].get("identity_matched") is not False


@pytest.mark.parametrize(
    "receipt,expected",
    [
        (action(item(P21)), ["success", "unknown"]),
        (action(item(P49)), ["unknown", "unknown"]),
        (action(item(P21), item(P49)), ["success", "unknown"]),
        (action(item(P21), item(P21)), ["unknown", "unknown"]),
        (action(item(P21, switch=OTHER_SERIAL), item(P23, switch=OTHER_SERIAL)), ["unknown", "unknown"]),
    ],
)
def test_multi_target_inverse_keeps_strict_identity_and_coverage_requirements(receipt, expected):
    original = deepcopy(receipt)
    outcomes, errors = ManageBreakoutInterfacesOrchestrator._match_recovery_results(receipt, _submitted(P21, P23), "breakout")
    assert [entry["outcome"] for entry in outcomes] == expected
    assert all(entry.get("identity_matched") is not False for entry in outcomes)
    assert errors
    assert receipt == original


def test_complete_multi_target_inverse_is_matched_by_identity_despite_reordered_rows():
    outcomes, errors = ManageBreakoutInterfacesOrchestrator._match_recovery_results(action(item(P23), item(P21)), _submitted(P21, P23), "breakout")
    assert [entry["interface_name"] for entry in outcomes] == [P21, P23]
    assert [entry["outcome"] for entry in outcomes] == ["success", "success"]
    assert all(entry.get("identity_matched") is not False for entry in outcomes)
    assert errors == []
