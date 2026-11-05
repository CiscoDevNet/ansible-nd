# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Guarded breakout workflows using only scripted, observable REST responses.

These tests exercise the public workflow and real shared response handling.
Synthetic responses do not establish controller or device convergence.
"""

from __future__ import annotations

import copy
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_breakout_interfaces import ManageBreakoutInterfacesOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.modules.nd_manage_breakout_interfaces import _format_output
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_manage_breakout_interfaces import (
    BASE,
    BREAKOUT,
    OTHER_SERIAL,
    REMOVE,
    SERIAL,
    action,
    group,
    inventory,
    item,
    outcomes,
    response,
    run,
    writes,
)

P21 = "Ethernet1/21"
P22 = "Ethernet1/22"
P23 = "Ethernet1/23"
P24 = "Ethernet1/24"
P49 = "Ethernet1/49"
VERIFY = {"enabled": True}
FAST = {"enabled": False}


def topology(*broken, native=(), switch=SERIAL, speed="25Gb", lanes=(1, 2, 3, 4)):
    """Give a complete switch snapshot with explicit physical classification."""
    rows = []
    for parent in native:
        rows.append(
            {
                "switchId": switch,
                "interfaceName": parent,
                "interfaceType": "ethernet",
                "physicalInterface": True,
                "discovered": True,
                "fex": False,
                "speed": "100Gb",
            }
        )
    for parent in broken:
        for lane in lanes:
            row = {
                "switchId": switch,
                "interfaceName": parent + "/" + str(lane),
                "interfaceType": "ethernet",
                "physicalInterface": True,
                "discovered": True,
                "fex": False,
            }
            if speed is not None:
                row["speed"] = speed
            rows.append(row)
    return response({"interfaces": rows, "meta": {"counts": {"total": len(rows), "remaining": 0}}})


def combined(*snapshots):
    """Compose a fabric-wide page while retaining each row's switch identity."""
    rows = [row for snapshot in snapshots for row in snapshot["DATA"]["interfaces"]]
    return response({"interfaces": rows, "meta": {"counts": {"total": len(rows), "remaining": 0}}})


def summary_calls(calls):
    return [call for call in calls if urlsplit(call["path"]).path == BASE + "/interfacesSummary"]


def assert_whole_ethernet(call, switch=SERIAL):
    query = parse_qs(urlsplit(call["path"]).query)
    assert call["verb"] == HttpVerbEnum.GET
    assert query["filter"] == ["interfaceType:ethernet"]
    assert query["includeAll"] == ["true"]
    if switch is None:
        assert "switchId" not in query
    else:
        assert query["switchId"] == [switch]


def assert_no_map_or_deploy_queries(calls):
    assert all(not any(part in call["path"] for part in ("/policies", "/diff", "configSave", "/deploy")) for call in calls)


def test_verified_merge_queries_whole_switch_once_before_and_once_after():
    report, calls = run(
        [topology(native=(P21, P49)), action(item(P21)), topology(P21, native=(P49,))],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert report["changed"] is True
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 2
    for call in summary_calls(calls):
        assert_whole_ethernet(call)
    assert_no_map_or_deploy_queries(calls)


def test_merge_collateral_recovers_only_submitted_parent_without_inverse_get():
    report, calls = run(
        [
            topology(native=(P21, P22, P23, P24)),
            action(item(P21)),
            topology(P21, P23),
            action(item(P21 + "/1")),
        ],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]}
    assert len(summary_calls(calls)) == 2
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert report["recovery"][0]["status"] == "response_confirmed"
    assert report["recovery"][0]["topology_verified"] is False
    assert "include all affected parents (Ethernet1/21, Ethernet1/23) in config" in report["msg"]
    assert "Inverse unbreakout" in report["msg"]
    assert "response_confirmed" in report["msg"]
    assert "not independently verified" in report["recovery"][0]["msg"]
    assert_no_map_or_deploy_queries(calls)


def test_missing_recovery_identity_is_unknown_without_replay_or_final_readback():
    report, calls = run(
        [topology(native=(P21, P23)), action(item(P21)), topology(P21, P23), action()],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert len(writes(calls)) == 2
    assert len(summary_calls(calls)) == 2
    assert report["recovery"][0]["status"] == "unknown"
    assert report["recovery"][0]["topology_verified"] is False


def test_requested_creation_absence_fails_without_collateral_compensation():
    report, calls = run(
        [topology(native=(P21,)), action(item(P21)), topology(native=(P21,))],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


def test_empty_action_results_stay_failed_but_observed_creation_is_changed():
    report, calls = run(
        [topology(native=(P21,)), action(), topology(P21)],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert outcomes(report)[(SERIAL, P21)]["outcome"] == "unknown"
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


def test_partial_api_failure_with_no_collateral_does_not_trigger_compensation():
    report, calls = run(
        [
            topology(native=(P21, P49)),
            action(item(P21), item(P49, status="error")),
            topology(P21, native=(P49,)),
        ],
        config=[group(P21, P49)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert outcomes(report)[(SERIAL, P21)]["outcome"] == "success"
    assert outcomes(report)[(SERIAL, P49)]["outcome"] == "failed"
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


@pytest.mark.parametrize("status", ["Failed", "error"])
def test_inverse_item_failure_is_not_reported_as_recovered(status):
    report, calls = run(
        [
            topology(native=(P21, P23)),
            action(item(P21)),
            topology(P21, P23),
            action(item(P21 + "/1", status=status)),
        ],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert len(writes(calls)) == 2
    assert len(summary_calls(calls)) == 2
    assert report["recovery"][0]["status"] == "failed"
    assert report["recovery"][0]["topology_verified"] is False


def test_same_child_count_with_changed_identity_is_collateral():
    after = topology(P49, lanes=(1, 2, 3, 5))
    after = combined(after, topology(P21))
    report, calls = run(
        [
            topology(P49, native=(P21,)),
            action(item(P21)),
            after,
            action(item(P21 + "/1")),
        ],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert len(summary_calls(calls)) == 2


def test_disappearing_native_siblings_do_not_trigger_family_guard():
    report, calls = run(
        [
            topology(native=(P21, P22, P23, P24)),
            action(item(P21), item(P23)),
            topology(P21, P23),
        ],
        config=[group(P21, P23)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


def test_incomplete_post_action_snapshot_does_not_guess_an_inverse():
    report, calls = run(
        [topology(native=(P21,)), action(item(P21)), response({"interfaces": None})],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


def test_unanswered_mutation_never_uses_stale_response_for_compensation():
    report, calls = run(
        [topology(native=(P21,)), ValueError("POST connection interrupted")],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["may_have_changed"] is True
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


def test_deleted_guard_retained_sibling_loss_recreates_only_submitted_parent():
    report, calls = run(
        [
            topology(P21, P23),
            action(item(P21 + "/1")),
            topology(native=(P21, P22, P23, P24)),
            action(item(P21)),
        ],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert [call["path"] for call in writes(calls)] == [REMOVE, BREAKOUT]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P21, "breakoutMap": "25g-4x"}]}
    assert len(summary_calls(calls)) == 2
    assert calls[-1]["verb"] == HttpVerbEnum.POST
    assert_no_map_or_deploy_queries(calls)


@pytest.mark.parametrize("speed", [None, "unknown", "auto"])
def test_unbreakout_recovery_map_requires_known_child_speed_before_writing(speed):
    report, calls = run(
        [topology(P21, speed=speed)],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert not writes(calls)
    assert_no_map_or_deploy_queries(calls)


def test_unbreakout_mixed_child_speed_fails_before_writing():
    baseline = topology(P21)
    baseline["DATA"]["interfaces"][0]["speed"] = "10Gb"
    report, calls = run(
        [baseline],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert not writes(calls)


def test_unrelated_missing_speed_does_not_block_verified_creation():
    baseline = combined(topology(P49, speed=None), topology(native=(P21,)))
    observed = combined(topology(P49, speed=None), topology(P21))
    report, calls = run([baseline, action(item(P21)), observed], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is False
    assert len(writes(calls)) == 1
    assert_no_map_or_deploy_queries(calls)


def test_only_actual_remove_target_needs_a_recovery_map():
    baseline = combined(topology(P49, speed=None), topology(P21))
    observed = combined(topology(P49, speed=None), topology(native=(P21,)))
    report, calls = run(
        [baseline, action(item(P21 + "/1")), observed],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert len(writes(calls)) == 1


def test_override_creates_then_removes_using_three_total_snapshots():
    report, calls = run(
        [
            topology(P49, native=(P21,)),
            action(item(P21)),
            topology(P49, P21),
            action(item(P49 + "/1")),
            topology(P21, native=(P49,)),
        ],
        state="overridden",
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert report["changed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P49 + "/1"}]}
    assert len(summary_calls(calls)) == 3
    assert_no_map_or_deploy_queries(calls)


def test_override_invalid_remove_map_is_rejected_before_creation_phase():
    report, calls = run(
        [topology(P49, native=(P21,), speed=None)],
        state="overridden",
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert not writes(calls)
    assert_no_map_or_deploy_queries(calls)


def test_override_creation_collateral_stops_before_cleanup_of_original_family():
    report, calls = run(
        [
            topology(P49, native=(P21, P23)),
            action(item(P21)),
            topology(P49, P21, P23),
            action(item(P21 + "/1")),
        ],
        state="overridden",
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"]["interfaces"] == [{"switchId": SERIAL, "interfaceName": P21 + "/1"}]
    assert len(summary_calls(calls)) == 2


def test_override_unresolved_creation_does_not_start_destructive_cleanup():
    report, calls = run(
        [topology(P49, native=(P21,)), action(), topology(P49, P21)],
        state="overridden",
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


def test_override_unbreakout_violation_preserves_earlier_successful_creation():
    report, calls = run(
        [
            topology(P21, P23, native=(P49,)),
            action(item(P49)),
            topology(P21, P23, P49),
            action(item(P23 + "/1")),
            topology(P49, native=(P21, P23)),
            action(item(P23)),
        ],
        state="overridden",
        config=[group(P21, P49)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE, BREAKOUT]
    assert writes(calls)[-1]["payload"] == {"interfaces": [{"switchId": SERIAL, "interfaceName": P23, "breakoutMap": "25g-4x"}]}
    assert len(summary_calls(calls)) == 3
    assert calls[-1]["verb"] == HttpVerbEnum.POST


def test_override_fast_mode_keeps_scope_baseline_but_skips_post_action_queries():
    report, calls = run(
        [topology(P49, native=(P21,)), action(item(P21)), action(item(P49 + "/1"))],
        state="overridden",
        config=[group(P21)],
        verify=FAST,
    )
    assert report["failed"] is False
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert len(summary_calls(calls)) == 1
    assert_whole_ethernet(summary_calls(calls)[0])


@pytest.mark.parametrize("verify", [VERIFY, FAST])
def test_override_empty_selected_switch_group_clears_that_switch(verify):
    scripted = [topology(P21, P23), action(item(P23 + "/1"), item(P21 + "/1"))]
    if verify["enabled"]:
        scripted.append(topology(native=(P21, P23)))
    report, calls = run(scripted, state="overridden", config=[group(breakout_map=None)], verify=verify)
    assert report["failed"] is False
    assert len(writes(calls)) == 1
    assert writes(calls)[0]["path"] == REMOVE
    assert {entry["interfaceName"] for entry in writes(calls)[0]["payload"]["interfaces"]} == {P21 + "/1", P23 + "/1"}
    assert len(summary_calls(calls)) == (2 if verify["enabled"] else 1)


def test_override_empty_fabric_scope_discovers_then_validates_only_broken_switches():
    fabric = combined(topology(P21), topology(native=(P49,), switch=OTHER_SERIAL))
    report, calls = run(
        [fabric, inventory(), action(item(P21 + "/1")), topology(native=(P21,))],
        state="overridden",
        config=[],
        platform_inventory=None,
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert len(writes(calls)) == 1
    assert_whole_ethernet(summary_calls(calls)[0], switch=None)
    assert_whole_ethernet(summary_calls(calls)[1])
    metadata = [call for call in calls if urlsplit(call["path"]).path.endswith("/switches/" + SERIAL)]
    assert len(metadata) == 1
    assert all(not urlsplit(call["path"]).path.endswith("/switches/" + OTHER_SERIAL) for call in calls)
    assert_no_map_or_deploy_queries(calls)


def test_override_empty_fabric_without_breakouts_is_one_read_noop():
    report, calls = run(
        [topology(native=(P21,))],
        state="overridden",
        config=[],
        platform_inventory=None,
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert report["changed"] is False
    assert len(calls) == 1
    assert_whole_ethernet(calls[0], switch=None)


def test_override_fabric_scope_validates_all_broken_platforms_before_any_write():
    fabric = combined(topology(P21), topology(P49, switch=OTHER_SERIAL))
    report, calls = run(
        [fabric, inventory(), inventory(OTHER_SERIAL, platform="ios-xe")],
        state="overridden",
        config=[],
        platform_inventory=None,
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert not writes(calls)
    assert_whole_ethernet(calls[0], switch=None)


def test_guard_compensates_only_offending_switch_not_successful_peer_switch():
    report, calls = run(
        [
            topology(native=(P21, P23)),
            topology(native=(P21, P23), switch=OTHER_SERIAL),
            action(item(P21, switch=OTHER_SERIAL), item(P21)),
            topology(P21, native=(P23,)),
            topology(P21, P23, switch=OTHER_SERIAL),
            action(item(P21 + "/1", switch=OTHER_SERIAL)),
        ],
        config=[group(P21), group(P21, switch=OTHER_SERIAL)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT, REMOVE]
    assert writes(calls)[1]["payload"] == {"interfaces": [{"switchId": OTHER_SERIAL, "interfaceName": P21 + "/1"}]}
    assert len(summary_calls(calls)) == 4
    assert len(report["recovery"]) == 1
    assert report["recovery"][0]["switch_id"] == OTHER_SERIAL


def test_multiple_offenders_keep_inverse_input_order_and_preserve_successful_switch():
    safe_switch = "FDO28481BZZ"
    report, calls = run(
        [
            topology(native=(P21, P23, P49)),
            topology(native=(P21, P23), switch=OTHER_SERIAL),
            topology(native=(P21,), switch=safe_switch),
            action(item(P21, switch=safe_switch), item(P21), item(P21, switch=OTHER_SERIAL), item(P49)),
            topology(P21, P23, P49),
            topology(P21, P23, switch=OTHER_SERIAL),
            topology(P21, switch=safe_switch),
            action(item(P21 + "/1"), item(P49 + "/1")),
            action(item(P21 + "/1", switch=OTHER_SERIAL)),
        ],
        config=[group(P49), group(P21, switch=OTHER_SERIAL), group(P21), group(P21, switch=safe_switch)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    actions = writes(calls)
    assert [call["path"] for call in actions] == [BREAKOUT, REMOVE, REMOVE]
    assert actions[1]["payload"] == {
        "interfaces": [
            {"switchId": SERIAL, "interfaceName": P49 + "/1"},
            {"switchId": SERIAL, "interfaceName": P21 + "/1"},
        ]
    }
    assert actions[2]["payload"] == {"interfaces": [{"switchId": OTHER_SERIAL, "interfaceName": P21 + "/1"}]}
    assert [entry["switch_id"] for entry in report["recovery"]] == [SERIAL, OTHER_SERIAL]
    assert all(entry["status"] == "response_confirmed" for entry in report["recovery"])
    assert any(row["switch_id"] == safe_switch and row["interface_name"] == P21 and row["broken_out"] for row in report["observed_before_recovery"])
    assert len(summary_calls(calls)) == 6
    assert calls[-1]["verb"] == HttpVerbEnum.POST


def test_post_action_refresh_preserves_noop_switch_and_requested_get_order():
    third_switch = "FDO28481BZZ"
    report, calls = run(
        [
            topology(native=(P21,), switch=third_switch),
            topology(P21, switch=OTHER_SERIAL),
            topology(native=(P21,)),
            action(item(P21), item(P21, switch=third_switch)),
            topology(P21, switch=third_switch),
            topology(P21),
        ],
        config=[group(P21, switch=third_switch), group(P21, switch=OTHER_SERIAL), group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert report["changed"] is True
    reads = summary_calls(calls)
    assert [parse_qs(urlsplit(call["path"]).query)["switchId"][0] for call in reads] == [third_switch, OTHER_SERIAL, SERIAL, third_switch, SERIAL]
    assert len(writes(calls)) == 1
    noop = next(row for row in report["after"] if row["switch_id"] == OTHER_SERIAL)
    assert noop["broken_out"] is True
    assert noop["evidence"] == "initial_discovery"
    assert report["after_status"] == "partially_observed"


def test_merge_noop_does_not_require_recovery_map_or_post_action_read():
    report, calls = run([topology(P21, speed=None)], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is False
    assert report["changed"] is False
    assert not writes(calls)
    assert len(summary_calls(calls)) == 1
    assert_no_map_or_deploy_queries(calls)


def test_fast_deleted_does_not_require_map_derivation_or_guard_read():
    report, calls = run(
        [topology(P21, speed=None), action(item(P21 + "/1"))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=FAST,
    )
    assert report["failed"] is False
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 1


@pytest.mark.parametrize("reply", ["complete", "error", "missing"])
def test_all_listed_coupled_create_keeps_strict_action_results_when_topology_matches(reply):
    """Synthetic coupled topology does not claim actual hardware accepted the bulk."""
    rows = [item(P21)]
    if reply != "missing":
        rows.append(item(P23, status="error" if reply == "error" else "Success"))
    report, calls = run(
        [topology(native=(P21, P22, P23, P24)), action(*rows), topology(P21, P23)],
        state="overridden",
        config=[group(P21, P23)],
        verify=VERIFY,
    )
    assert report["failed"] is (reply != "complete")
    assert report["changed"] is True
    assert outcomes(report)[(SERIAL, P23)]["outcome"] == {"complete": "success", "error": "failed", "missing": "unknown"}[reply]
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 2
    assert not report.get("recovery")


@pytest.mark.parametrize("reply", ["complete", "error", "missing"])
def test_all_listed_coupled_removal_keeps_strict_results_even_when_both_native(reply):
    rows = [item(P21 + "/1")]
    if reply != "missing":
        rows.append(item(P23 + "/1", status="Failed" if reply == "error" else "Success"))
    report, calls = run(
        [topology(P21, P23), action(*rows), topology(native=(P21, P22, P23, P24))],
        state="deleted",
        config=[group(P21, P23, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is (reply != "complete")
    assert report["changed"] is True
    assert len(writes(calls)) == 1
    assert not report.get("recovery")


@pytest.mark.parametrize("failure", ["timeout", "server_error"])
def test_unsettled_forward_request_never_compensates_even_if_guard_finds_collateral(monkeypatch, failure):
    if failure == "server_error":
        # Bound only this test's real shared retry budget, not production policy.
        original_timeout = RestSend.timeout
        monkeypatch.setattr(RestSend, "timeout", property(original_timeout.fget, lambda self, value: original_timeout.fset(self, 1)))
    failed_response = TimeoutError("Lost POST response") if failure == "timeout" else response({"message": "Controller unavailable"}, code=500, method="POST")
    report, calls = run(
        [topology(native=(P21, P23)), failed_response, topology(P21, P23)],
        config=[group(P21)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert report["may_have_changed"] is True
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 2
    assert all(call["payload"] is None for call in calls if call["verb"] == HttpVerbEnum.GET)
    assert report["recovery"][0]["status"] == "not_attempted"
    assert report["recovery"][0]["api_outcomes"] == []


def test_unbreakout_missing_children_and_missing_native_parent_is_not_success_or_collateral():
    report, calls = run(
        [topology(P21, native=(P49,)), action(item(P21 + "/1")), topology(native=(P49,))],
        state="deleted",
        config=[group(P21, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert len(writes(calls)) == 1
    assert report["verification"]["phases"][0]["topology_matches"] is False
    assert report["verification"]["phases"][0]["collateral"] == []
    assert not report.get("recovery")


def test_override_partial_create_on_one_switch_stops_cleanup_on_every_switch():
    report, calls = run(
        [
            topology(P49, native=(P21,)),
            topology(P49, native=(P21,), switch=OTHER_SERIAL),
            action(item(P21), item(P21, switch=OTHER_SERIAL, status="error")),
            topology(P49, P21),
            topology(P49, native=(P21,), switch=OTHER_SERIAL),
        ],
        state="overridden",
        config=[group(P21), group(P21, switch=OTHER_SERIAL)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert [call["path"] for call in writes(calls)] == [BREAKOUT]
    assert len(summary_calls(calls)) == 4
    assert not report.get("recovery")


def test_partial_inverse_on_offending_switch_preserves_peer_switch_success():
    report, calls = run(
        [
            topology(native=(P21,)),
            topology(native=(P21, P23, P49), switch=OTHER_SERIAL),
            action(item(P21), item(P21, switch=OTHER_SERIAL), item(P49, switch=OTHER_SERIAL)),
            topology(P21),
            topology(P21, P23, P49, switch=OTHER_SERIAL),
            action(item(P21 + "/1", switch=OTHER_SERIAL)),
        ],
        config=[group(P21), group(P21, P49, switch=OTHER_SERIAL)],
        verify=VERIFY,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert outcomes(report)[(SERIAL, P21)]["outcome"] == "success"
    assert len(writes(calls)) == 2
    inverse = writes(calls)[1]["payload"]["interfaces"]
    assert {entry["switchId"] for entry in inverse} == {OTHER_SERIAL}
    assert {entry["interfaceName"] for entry in inverse} == {P21 + "/1", P49 + "/1"}
    assert len(report["recovery"]) == 1
    assert report["recovery"][0]["status"] == "unknown"
    assert len(summary_calls(calls)) == 4


def test_noop_switch_snapshot_is_initial_evidence_not_post_action_observation():
    report, calls = run(
        [topology(P21), topology(native=(P21,), switch=OTHER_SERIAL), action(item(P21, switch=OTHER_SERIAL)), topology(P21, switch=OTHER_SERIAL)],
        config=[group(P21), group(P21, switch=OTHER_SERIAL)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert report["after_status"] == "partially_observed"
    after = {(entry["switch_id"], entry["interface_name"]): entry for entry in report["after"]}
    assert after[(SERIAL, P21)]["evidence"] == "initial_discovery"
    assert after[(OTHER_SERIAL, P21)]["evidence"] == "post_action_discovery"
    assert len(summary_calls(calls)) == 3


def test_selected_clear_proposed_input_retains_empty_group_with_canonical_serial():
    ip = "192.0.2.21"
    lookup = response(
        {"switches": [{"switchId": SERIAL, "fabricManagementIp": ip, "additionalData": {"platformType": "nx-os"}}], "meta": {"counts": {"remaining": 0}}}
    )
    report, calls = run(
        [lookup, topology(P21), action(item(P21 + "/1")), topology(native=(P21,))],
        state="overridden",
        config=[group(switch=ip, breakout_map=None)],
        verify=VERIFY,
    )
    assert report["failed"] is False
    assert report["proposed"] == [{"switch_id": SERIAL, "interface_names": []}]
    assert len(writes(calls)) == 1


@pytest.mark.parametrize(
    "bad_counts",
    [
        {"total": 5, "remaining": 1},
        {"total": 4, "remaining": 1},
        {"total": 1, "remaining": 0},
        {"total": 4, "remaining": "0"},
    ],
)
def test_corrupted_later_guard_page_is_inconclusive_without_guessed_inverse(bad_counts):
    page_one = topology(P21, lanes=(1, 2))
    page_one["DATA"]["meta"]["counts"] = {"total": 4, "remaining": 2}
    page_two = topology(P21, lanes=(3, 4))
    page_two["DATA"]["meta"]["counts"] = bad_counts
    report, calls = run([topology(native=(P21,)), action(item(P21)), page_one, page_two], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is True
    assert report["verification"]["complete"] is False
    assert len(writes(calls)) == 1
    assert len(summary_calls(calls)) == 3
    assert not report.get("recovery")


def test_complete_paginated_guard_combines_children_before_comparing():
    page_one = topology(P21, lanes=(1, 2))
    page_one["DATA"]["meta"]["counts"] = {"total": 4, "remaining": 2}
    page_two = topology(P21, lanes=(3, 4))
    page_two["DATA"]["meta"]["counts"] = {"total": 4, "remaining": 0}
    report, calls = run([topology(native=(P21,)), action(item(P21)), page_one, page_two], config=[group(P21)], verify=VERIFY)
    assert report["failed"] is False
    assert report["after"][0]["children"] == [P21 + "/" + str(lane) for lane in (1, 2, 3, 4)]
    assert len(summary_calls(calls)) == 3
    assert parse_qs(urlsplit(summary_calls(calls)[-1]["path"]).query)["offset"] == ["2"]


@pytest.mark.parametrize("state", ["merged", "deleted"])
def test_default_verify_omission_selects_guarded_workflow(monkeypatch, state):
    original_run = ManageBreakoutInterfacesOrchestrator.run

    def without_verify(self):
        self.rest_send.params.pop("verify", None)
        return original_run(self)

    monkeypatch.setattr(ManageBreakoutInterfacesOrchestrator, "run", without_verify)
    before = topology(P21) if state == "deleted" else topology(native=(P21,))
    after = topology(native=(P21,)) if state == "deleted" else topology(P21)
    report, calls = run(
        [before, action(item(P21 + "/1" if state == "deleted" else P21)), after],
        state=state,
        config=[group(P21, breakout_map=None if state == "deleted" else "25g-4x")],
    )
    assert report["failed"] is False
    assert report["verification"]["enabled"] is True
    assert len(summary_calls(calls)) == 2
    assert_whole_ethernet(summary_calls(calls)[0])


def test_override_check_mode_predicts_both_phases_without_inventing_children():
    report, calls = run([topology(P49, native=(P21,))], state="overridden", config=[group(P21)], verify=VERIFY, check_mode=True)
    assert report["failed"] is False
    assert report["changed"] is True
    assert report["after_status"] == "predicted"
    assert not writes(calls)
    assert len(summary_calls(calls)) == 1
    after = {entry["interface_name"]: entry for entry in report["after"]}
    assert after[P21]["broken_out"] is True
    assert "children" not in after[P21]
    assert after[P21]["requested_breakout_map"] == "25g-4x"
    assert after[P49]["broken_out"] is False
    assert after[P49]["children"] == []


@pytest.mark.parametrize("output_level", ["normal", "info", "debug"])
@pytest.mark.parametrize("verbosity", [0, 2, 3])
def test_real_guard_recovery_ndoutput_keeps_primary_failure_and_verbosity_contract(output_level, verbosity):
    trace = Results()
    report, calls = run(
        [topology(native=(P21, P23)), action(item(P21)), topology(P21, P23), action(item(P21 + "/1"))],
        config=[group(P21)],
        verify=VERIFY,
        results=trace,
    )
    untouched = copy.deepcopy(report)
    module = SimpleNamespace(params={"state": "merged", "output_level": output_level}, _verbosity=verbosity)
    output = _format_output(module, report, trace)
    assert report == untouched
    assert output["failed"] is True
    assert output["changed"] is True
    assert output["after_status"] == "unknown"
    assert output["after"] == []
    assert output["recovery"] == report["recovery"]
    assert output["observed_before_recovery"] == report["observed_before_recovery"]
    assert ("proposed" in output) is (output_level in {"info", "debug"})
    assert ("logs" in output) is (output_level == "debug")
    assert ("api_calls" in output) is (verbosity == 3)
    indices = [index for index, call in enumerate(calls) if verbosity >= 3 or verbosity == 2 and call["verb"] == HttpVerbEnum.POST]
    assert ("api_paths" in output) is bool(indices)
    if indices:
        assert output["api_paths"] == [calls[index]["path"] for index in indices]
        assert output["api_verbs"] == [calls[index]["verb"].value for index in indices]
    if verbosity == 3:
        assert output["api_response"] == trace.responses
        assert output["api_payload"] == trace.payload


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_fast_noop_snapshots_keep_initial_discovery_provenance(state, check_mode):
    baseline = topology(P21) if state == "merged" else topology(native=(P21,))
    report, calls = run(
        [baseline],
        state=state,
        config=[group(P21, breakout_map=None if state == "deleted" else "25g-4x")],
        verify=FAST,
        check_mode=check_mode,
    )
    assert report["failed"] is False
    assert report["changed"] is False
    assert report["may_have_changed"] is False
    assert report["after_status"] == ("predicted" if check_mode else "unchanged")
    assert report["before"] == report["after"]
    assert report["before"][0]["evidence"] == "initial_discovery"
    assert report["before"][0]["broken_out"] is (state == "merged")
    assert report["api_outcomes"][0]["outcome"] == "noop"
    assert report["api_outcomes"][0]["api_interface_name"] is None
    assert not writes(calls)
    assert len(summary_calls(calls)) == 1
    assert len(calls) == 2
    assert not report.get("verification")
    assert not report.get("recovery")


@pytest.mark.parametrize("state", ["merged", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_fast_action_before_snapshot_is_initial_discovery_not_response_evidence(state, check_mode):
    baseline = topology(native=(P21,)) if state == "merged" else topology(P21)
    scripted = [baseline]
    if not check_mode:
        scripted.append(action(item(P21 if state == "merged" else P21 + "/1")))
    report, calls = run(
        scripted,
        state=state,
        config=[group(P21, breakout_map=None if state == "deleted" else "25g-4x")],
        verify=FAST,
        check_mode=check_mode,
    )
    assert report["failed"] is False
    assert report["changed"] is True
    assert report["before"][0]["evidence"] == "initial_discovery"
    assert report["before"][0]["broken_out"] is (state == "deleted")
    assert report["after"][0]["evidence"] == ("prediction" if check_mode else "api_response")
    assert report["after"][0]["broken_out"] is (state == "merged")
    assert len(writes(calls)) == (0 if check_mode else 1)
    assert len(summary_calls(calls)) == 1
    assert len(calls) == (2 if check_mode else 3)
    assert not report.get("verification")
    assert not report.get("recovery")


@pytest.mark.parametrize("verify", [VERIFY, FAST], ids=["verified", "response_only"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_former_child_delete_noop_keeps_selector_identity_in_every_mode(verify, check_mode):
    child = P21 + "/3"
    report, calls = run(
        [topology(native=(P21,))],
        state="deleted",
        config=[group(child, breakout_map=None)],
        verify=verify,
        check_mode=check_mode,
    )
    assert report["failed"] is False
    assert report["changed"] is False
    assert report["may_have_changed"] is False
    assert report["after_status"] == ("predicted" if check_mode else "unchanged")
    assert report["before"] == report["after"]
    assert report["before"] == [
        {
            "switch_id": SERIAL,
            "interface_name": P21,
            "broken_out": False,
            "children": [],
            "evidence": "initial_discovery",
        }
    ]
    assert len(report["api_outcomes"]) == 1
    outcome = report["api_outcomes"][0]
    assert outcome["switch_id"] == SERIAL
    assert outcome["interface_name"] == P21
    assert outcome["requested_interface_name"] == child
    assert outcome["api_interface_name"] is None
    assert outcome["action"] == "unbreakout"
    assert outcome["outcome"] == "noop"
    assert not report["diff"]
    assert not writes(calls)
    assert len(summary_calls(calls)) == 1
    assert len(calls) == 2
    assert not report.get("verification")
    assert not report.get("recovery")


@pytest.mark.parametrize("message", [{"message": "Unsupported map"}, ["Unsupported map"], 17], ids=["object", "array", "integer"])
@pytest.mark.parametrize("state", ["merged", "deleted", "overridden"])
@pytest.mark.parametrize("verify", [VERIFY, FAST], ids=["verified", "response_only"])
def test_non_string_item_failure_message_preserves_known_partial_change(message, state, verify):
    deleting = state == "deleted"
    baseline = topology(P21, P23) if deleting else topology(native=(P21, P23))
    accepted_api_name = P21 + "/1" if deleting else P21
    rejected_api_name = P23 + "/1" if deleting else P23
    scripted = [baseline, action(item(accepted_api_name), item(rejected_api_name, status="error", message=message))]
    if verify["enabled"]:
        scripted.append(topology(P23, native=(P21,)) if deleting else topology(P21, native=(P23,)))
    report, calls = run(
        scripted,
        state=state,
        config=[group(P21, P23, breakout_map=None if deleting else "25g-4x")],
        verify=verify,
    )
    assert report["failed"] is True
    assert report["changed"] is True
    assert isinstance(report["msg"], str) and report["msg"]
    assert report["before"]
    assert len(report["api_outcomes"]) == 2
    accepted = outcomes(report)[(SERIAL, P21)]
    rejected = outcomes(report)[(SERIAL, P23)]
    assert accepted["outcome"] == "success"
    assert accepted["api_interface_name"] == accepted_api_name
    assert rejected["outcome"] == "failed"
    assert rejected["api_interface_name"] == rejected_api_name
    assert isinstance(rejected["message"], str) and rejected["message"]
    expected_message = "Unsupported map" if isinstance(message, (dict, list)) else "17"
    assert expected_message in rejected["message"]
    assert len(writes(calls)) == 1
    assert writes(calls)[0]["path"] == (REMOVE if deleting else BREAKOUT)
    assert len(summary_calls(calls)) == (2 if verify["enabled"] else 1)
    assert len(calls) == (4 if verify["enabled"] else 3)
    assert not report.get("recovery")
    assert_no_map_or_deploy_queries(calls)
    if verify["enabled"]:
        assert report["after_status"] == "observed"
        after = {row["interface_name"]: row for row in report["after"]}
        assert after[P21]["broken_out"] is (not deleting)
        assert after[P23]["broken_out"] is deleting
        assert {row["evidence"] for row in after.values()} == {"post_action_discovery"}
    else:
        assert report["after_status"] == "unknown"
        assert not report.get("after")
