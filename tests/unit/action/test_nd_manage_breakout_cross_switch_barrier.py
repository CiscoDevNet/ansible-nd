# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Exercise the actual S22 task ordering and assertions without controller calls.

Only the production invocation and independent observers return scripted data.
The real YAML's facts, receipt assertions, rescue and final cleanup gate execute
with Ansible templating. These tests do not certify hardware restoration.
"""

from copy import deepcopy

import pytest
import yaml

from ansible_collections.cisco.nd.tests.unit.action.test_nd_manage_breakout_guard_budget_contract import (
    TARGET,
    condition,
    execute_tasks,
    render,
)

COUPLED = "FDO27020W5V"
SAFE = "FLM27170JC2"
CONTROL = "Ethernet1/21"
SIBLING = "Ethernet1/23"
SAFE_PARENT = "Ethernet1/53"


def native_snapshot(*parents):
    return {
        "families": {parent: {"native": True, "children": [], "child_speeds": {}} for parent in parents},
        "outside_families": {},
    }


def confirmed_result():
    children = [CONTROL + "/" + str(lane) for lane in range(1, 5)]
    return {
        "failed": True,
        "changed": True,
        "after_status": "unknown",
        "api_outcomes": [
            {"switch_id": SAFE, "interface_name": SAFE_PARENT, "outcome": "success"},
            {"switch_id": COUPLED, "interface_name": CONTROL, "outcome": "success"},
        ],
        "recovery": [
            {
                "switch_id": COUPLED,
                "status": "response_confirmed",
                "topology_verified": False,
                "action": "unbreakout",
                "api_outcomes": [{"interface_name": CONTROL, "api_interface_name": children[0], "outcome": "success"}],
            }
        ],
        "observed_before_recovery": [{"switch_id": COUPLED, "interface_name": CONTROL, "children": children}],
        "api_calls": [
            {"method": "POST", "path": "/api/v1/manage/fabrics/fab1/interfaceActions/breakout"},
            {"method": "POST", "path": "/api/v1/manage/fabrics/fab1/interfaceActions/remove"},
        ],
        "msg": f"Unexpected {SIBLING} after {CONTROL}; include all affected parents in config.",
    }


def run_cross_switch(result=None, *, observer_failure=None, stale_immediate=True, stop_writes=False):
    """Run S22's real local tasks; substitute only external invocation results."""
    case = yaml.safe_load((TARGET / "tasks" / "coupled_cross_switch.yaml").read_text())[0]
    coupled_observer = yaml.safe_load((TARGET / "tasks" / "coupled_observe.yaml").read_text())
    baseline = native_snapshot(*(f"Ethernet1/{port}" for port in range(21, 25)))
    immediate = deepcopy(baseline)
    if stale_immediate:
        for parent in ("Ethernet1/22", "Ethernet1/24"):
            immediate["families"][parent]["native"] = False
    safe_native = native_snapshot(SAFE_PARENT)
    safe_created = deepcopy(safe_native)
    safe_created["families"][SAFE_PARENT] = {
        "native": False,
        "children": [SAFE_PARENT + "/" + str(lane) for lane in range(1, 5)],
        "child_speeds": {SAFE_PARENT + "/" + str(lane): 25 for lane in range(1, 5)},
    }
    values = {
        "ansible_verbosity": 3,
        "test_breakout_coupled_fabric_name": "fab1",
        "test_breakout_coupled_switch_id": COUPLED,
        "test_breakout_coupled_safe_fixture": {
            "switch_id": SAFE,
            "control_parent": SAFE_PARENT,
            "profiles": {"map_a": {"breakout_map": "25g-4x"}},
        },
        "test_breakout_coupled_observe_retries": 7,
        "test_breakout_coupled_observe_interval": 10,
        "coupled_native_baseline": baseline,
        "coupled_control": CONTROL,
        "coupled_sibling": SIBLING,
        "coupled_map": "25g-4x",
        "coupled_case_failures": [],
        "coupled_case_records": [],
        "coupled_stop_writes": stop_writes,
    }
    invocation = deepcopy(confirmed_result() if result is None else result)
    events = []
    written = False

    def execute(task):
        nonlocal written
        local = {**values, **render(task.get("vars", {}), values)}
        checks = task.get("when", [])
        checks = checks if isinstance(checks, list) else [checks]
        if not all(condition(check, local) for check in checks):
            return
        if "cisco.nd.nd_manage_breakout_interfaces" in task:
            assert values["coupled_cross_pending"] is True
            written = True
            events.append("write")
            values[task["register"]] = deepcopy(invocation)
        elif "ansible.builtin.include_tasks" in task:
            safe = task["ansible.builtin.include_tasks"] == "coupled_safe_observe.yaml"
            assert safe or task["ansible.builtin.include_tasks"] == "coupled_observe.yaml"
            only = local.get("coupled_safe_observe_only" if safe else "coupled_observe_only", False)
            label = ("safe" if safe else "coupled") + ("_immediate" if only else "_strict")
            events.append(("post_" if written else "pre_") + label)
            if written and observer_failure == label:
                raise AssertionError("Scripted independent observer failure: " + label)
            if safe:
                snapshot = safe_created if written else safe_native
                expected = "map_a" if written else "native"
                assert local["coupled_safe_profile"] == expected
            else:
                snapshot = immediate if written and only else baseline
                assert local["coupled_observe_profile"] == "native"
            observation = {"changed": False, "failed": False, "snapshot": deepcopy(snapshot)}
            values["coupled_safe_observation" if safe else "coupled_observation"] = observation
            if not safe:
                # Execute the observer include's actual argument-validation and
                # evidence assertions, omitting only its external action call.
                execute_tasks(
                    [included for included in coupled_observer if "ansible.builtin.assert" in included], {**local, "coupled_observation": observation}
                )
        else:
            execute_tasks([task], values)
            if task.get("ansible.builtin.set_fact", {}).get("coupled_cross_pending") is False and written:
                events.append("release")

    try:
        for task in case["block"]:
            execute(task)
    except AssertionError as error:
        values["ansible_failed_result"] = {"failed": True, "msg": str(error)}
        execute_tasks(case["rescue"], values)
    # The real always fact freezes the barrier before its cleanup when is read.
    execute_tasks([case["always"][0]], values)
    cleanup_allowed = condition(case["always"][1]["when"], values)
    return values, events, cleanup_allowed


def test_stale_immediate_quad_snapshot_releases_only_after_both_strict_observers_succeed():
    values, events, cleanup_allowed = run_cross_switch()
    assert values["coupled_case_failures"] == []
    assert values["coupled_cross_pending"] is False
    assert values["coupled_stop_writes"] is False and cleanup_allowed
    assert events[-3:] == ["post_coupled_strict", "post_safe_strict", "release"]
    assert events.count("write") == 1
    frozen = values["coupled_case_records"][0]["coupled_observation_before_cleanup"]["snapshot"]["families"]
    assert frozen["Ethernet1/22"]["native"] is False and frozen["Ethernet1/24"]["native"] is False
    assert values["coupled_observation"]["snapshot"] == values["coupled_native_baseline"]


@pytest.mark.parametrize("unknown", ["forward", "inverse", "inverse_item", "missing_receipt"])
def test_unknown_or_incomplete_receipts_cannot_release_even_if_immediate_topology_is_native(unknown):
    result = confirmed_result()
    if unknown == "forward":
        result["api_outcomes"][0]["outcome"] = "unknown"
    elif unknown == "inverse":
        result["recovery"][0]["status"] = "unknown"
    elif unknown == "inverse_item":
        result["recovery"][0]["api_outcomes"][0]["outcome"] = "unknown"
    else:
        result["recovery"] = []
    values, events, cleanup_allowed = run_cross_switch(result, stale_immediate=False)
    assert values["coupled_cross_pending"] is True
    assert values["coupled_stop_writes"] is True and not cleanup_allowed
    assert len(values["coupled_case_failures"]) == 1
    assert "release" not in events and "post_coupled_strict" not in events


@pytest.mark.parametrize("observer", ["coupled_strict", "safe_strict", "coupled_immediate", "safe_immediate"])
def test_failed_independent_observer_keeps_pending_and_prevents_cleanup(observer):
    values, events, cleanup_allowed = run_cross_switch(observer_failure=observer, stale_immediate=False)
    assert values["coupled_cross_pending"] is True
    assert values["coupled_stop_writes"] is True and not cleanup_allowed
    assert len(values["coupled_case_failures"]) == 1 and "release" not in events
    if observer == "safe_strict":
        assert events[-2:] == ["post_coupled_strict", "post_safe_strict"]


def test_existing_trace_assertion_failure_cannot_release_before_strict_observation():
    result = confirmed_result()
    result["api_calls"].append({"method": "GET", "path": "/interfacesSummary"})
    values, events, cleanup_allowed = run_cross_switch(result, stale_immediate=False)
    assert values["coupled_cross_pending"] is True
    assert values["coupled_stop_writes"] is True and not cleanup_allowed
    assert "release" not in events and "post_coupled_strict" not in events


def test_successful_s22_does_not_clear_an_earlier_suite_write_barrier():
    values, events, cleanup_allowed = run_cross_switch(stop_writes=True)
    assert values["coupled_cross_pending"] is False and events[-1] == "release"
    assert values["coupled_stop_writes"] is True and not cleanup_allowed
