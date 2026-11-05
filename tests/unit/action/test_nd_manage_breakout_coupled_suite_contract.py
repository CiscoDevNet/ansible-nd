# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Offline execution of coupled-playbook preflight and no-replay expressions.

These tests read the real integration YAML; they do not send controller requests
or replace the real-request-only integration cases with simulated recovery.
"""

from copy import deepcopy
from pathlib import Path
import re

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

TARGET = Path(__file__).resolve().parents[2] / "integration" / "targets" / "nd_manage_breakout_interfaces"
PREFLIGHT = yaml.safe_load((TARGET / "tasks" / "coupled_preflight.yaml").read_text())
NAMES = yaml.safe_load((TARGET / "tasks" / "coupled_validate_names.yaml").read_text())
CASES = yaml.safe_load((TARGET / "tasks" / "coupled_case.yaml").read_text())
ASSERTIONS = yaml.safe_load((TARGET / "tasks" / "coupled_assert.yaml").read_text())
CROSS_SWITCH = yaml.safe_load((TARGET / "tasks" / "coupled_cross_switch.yaml").read_text())
SAFE_VALIDATION = yaml.safe_load((TARGET / "tasks" / "coupled_safe_validate.yaml").read_text())
OBSERVE = yaml.safe_load((TARGET / "tasks" / "coupled_observe.yaml").read_text())
OBSERVER = next(task for task in OBSERVE if "cisco.nd.nd_manage_breakout_interfaces_validate" in task)
PREPARE = yaml.safe_load((TARGET / "tasks" / "coupled_prepare.yaml").read_text())
CLEANUP = yaml.safe_load((TARGET / "tasks" / "coupled_cleanup.yaml").read_text())
DEFAULTS = yaml.safe_load((TARGET / "defaults" / "main.yaml").read_text())
SUITE = yaml.safe_load((TARGET / "tests" / "coupled.yaml").read_text())


def _fixture():
    return {
        "control_parent": "Ethernet1/21",
        "native_interfaces": ["Ethernet1/21", "Ethernet1/22", "Ethernet1/23", "Ethernet1/24"],
        "guard_interfaces": ["Ethernet1/60"],
        "profiles": {
            "map_a": {
                "breakout_map": "25g-4x",
                "child_lanes": {"Ethernet1/21": [1, 2, 3, 4], "Ethernet1/23": [1, 2, 3, 4]},
                "native_interfaces": [],
                "policy_maps": {"Ethernet1/21": "25g-4x"},
                "child_speeds": {"Ethernet1/23": 25},
            }
        },
    }


def _environment():
    environment = NativeEnvironment(undefined=StrictUndefined)
    environment.tests["match"] = lambda value, pattern: isinstance(value, str) and re.match(pattern, value) is not None
    environment.filters["bool"] = bool
    environment.filters["intersect"] = lambda left, right: list(set(left) & set(right))
    environment.filters["difference"] = lambda left, right: list(set(left) - set(right))
    environment.filters["dict2items"] = lambda value: [{"key": key, "value": item} for key, item in value.items()]
    environment.filters["items2dict"] = lambda rows: {row["key"]: row["value"] for row in rows}
    return environment


def _expression(expression, variables):
    return _environment().from_string("{{ " + expression + " }}").render(**variables)


def _valid_names(fixture):
    variables = {"coupled_names_fixture": fixture}
    first = all(_expression(expression, variables) for expression in NAMES[0]["ansible.builtin.assert"]["that"])
    profiles = all(
        _expression(expression, {**variables, "item": {"key": label, "value": profile}})
        for label, profile in fixture["profiles"].items()
        for expression in NAMES[1]["ansible.builtin.assert"]["that"]
    )
    return first and profiles


def _pending_expression():
    return next(
        task["ansible.builtin.set_fact"]["coupled_case_write_pending"]
        for task in CASES[1]["block"]
        if isinstance(task.get("ansible.builtin.set_fact", {}).get("coupled_case_write_pending"), str)
    )


def _response_pending_expression():
    return next(
        task["ansible.builtin.set_fact"]["coupled_case_response_pending"]
        for task in CASES[1]["block"]
        if isinstance(task.get("ansible.builtin.set_fact", {}).get("coupled_case_response_pending"), str)
    )


def _pending(variables):
    variables = {"coupled_case": {"expect": "recovery"}, **variables}
    variables["coupled_case_response_pending"] = _environment().from_string(_response_pending_expression()).render(**variables)
    return _environment().from_string(_pending_expression()).render(**variables)


def test_canonical_guarded_fixture_passes_the_actual_local_name_assertions():
    assert _valid_names(_fixture()) is True


@pytest.mark.parametrize(
    "field",
    ["control_parent", "native_interfaces", "guard_interfaces", "child_lanes", "retained_native", "policy_maps", "child_speeds"],
)
@pytest.mark.parametrize("transform", [str.lower, lambda value: " " + value + " "])
def test_every_parent_field_rejects_spelling_variants_before_scope_comparisons(field, transform):
    fixture = _fixture()
    if field == "control_parent":
        fixture[field] = transform(fixture[field])
    elif field in {"native_interfaces", "guard_interfaces"}:
        fixture[field][0] = transform(fixture[field][0])
    elif field == "retained_native":
        fixture["profiles"]["map_a"]["native_interfaces"] = [transform("Ethernet1/22")]
    else:
        mapping = fixture["profiles"]["map_a"][field]
        key = next(iter(mapping))
        mapping[transform(key)] = mapping.pop(key)
    assert _valid_names(fixture) is False


def test_names_are_checked_in_additional_profiles_not_just_map_a():
    fixture = _fixture()
    fixture["profiles"]["map_b"] = deepcopy(fixture["profiles"]["map_a"])
    fixture["profiles"]["map_b"]["child_lanes"] = {"ethernet1/21": [1, 2]}
    assert _valid_names(fixture) is False


def test_case_variant_guard_cannot_evade_raw_intersection_or_authoritative_override_safety():
    fixture = _fixture()
    fixture["guard_interfaces"] = ["ethernet1/30"]
    assert _valid_names(fixture) is False
    check_names = next(index for index, task in enumerate(PREFLIGHT) if task.get("ansible.builtin.include_tasks") == "coupled_validate_names.yaml")
    first_read = next(index for index, task in enumerate(PREFLIGHT) if task.get("ansible.builtin.include_tasks") == "coupled_observe.yaml")
    assert check_names < first_read


def test_independent_fixture_names_are_checked_before_merge_and_controller_reads():
    check = next(
        index
        for index, task in enumerate(PREFLIGHT)
        if task.get("ansible.builtin.include_tasks") == "coupled_validate_names.yaml" and "independent_fixture" in task["vars"]["coupled_names_fixture"]
    )
    merge = next(index for index, task in enumerate(PREFLIGHT) if task["name"].startswith("Merge independent native footprint"))
    first_read = next(index for index, task in enumerate(PREFLIGHT) if task.get("ansible.builtin.include_tasks") == "coupled_observe.yaml")
    assert check < merge < first_read


@pytest.mark.parametrize("guards,expected", [([], True), (["Ethernet1/60"], False)])
def test_independent_guard_declarations_are_explicitly_rejected_rather_than_dropped(guards, expected):
    task = next(task for task in PREFLIGHT if task["name"].startswith("Require disjoint independent footprint"))
    expression = next(expression for expression in task["ansible.builtin.assert"]["that"] if "guard_interfaces | default([]) | length == 0" in expression)
    assert _expression(expression, {"test_breakout_coupled_independent_fixture": {"guard_interfaces": guards}}) is expected
    assert "must never be silently dropped" in task["ansible.builtin.assert"]["fail_msg"]


def test_guard_baseline_is_captured_observe_only_then_used_by_strict_native_validation():
    read_indices = [index for index, task in enumerate(PREFLIGHT) if task.get("ansible.builtin.include_tasks") == "coupled_observe.yaml"]
    first, second = [PREFLIGHT[index] for index in read_indices]
    baseline = next(index for index, task in enumerate(PREFLIGHT) if "coupled_native_baseline" in task.get("ansible.builtin.set_fact", {}))
    assert first["vars"]["coupled_observe_only"] is True
    assert read_indices[0] < baseline < read_indices[1]
    assert second["vars"]["coupled_observe_only"] is False
    assert second["vars"]["coupled_observe_baseline"] == "{{ coupled_native_baseline }}"
    assert all("cisco.nd.nd_manage_breakout_interfaces" not in task and "cisco.nd.nd_rest" not in task for task in PREFLIGHT)


@pytest.mark.parametrize("status", ["failed", "unknown", "not_attempted"])
def test_failed_or_uncertain_inverse_prevents_cleanup_replay(status):
    variables = {
        "coupled_original_result": {"recovery": [{"status": status}], "api_outcomes": []},
        "coupled_observation": {"snapshot": {"families": {}}},
        "coupled_case_baseline": {"families": {}},
        "test_breakout_coupled_fixture": {"native_interfaces": []},
    }
    assert _pending(variables) is True


@pytest.mark.parametrize("restored,expected_blocked", [(True, False), (False, True)])
def test_response_confirmed_inverse_cannot_hide_failed_topology_restoration(restored, expected_blocked):
    family = {"native": True, "children": [], "child_speeds": {}}
    observed = deepcopy(family) if restored else {"native": False, "children": ["Ethernet1/21/1"], "child_speeds": {"Ethernet1/21/1": 25}}
    variables = {
        "coupled_original_result": {"recovery": [{"status": "response_confirmed"}], "api_outcomes": [{"outcome": "success"}]},
        "coupled_observation": {"snapshot": {"families": {"Ethernet1/21": observed}}},
        "coupled_case_baseline": {"families": {"Ethernet1/21": family}},
        "test_breakout_coupled_fixture": {"native_interfaces": ["Ethernet1/21"]},
    }
    assert _pending(variables) is expected_blocked


def test_creation_recovery_requires_actionable_requested_and_unexpected_parent_guidance():
    task = next(task for task in ASSERTIONS if task["name"].startswith("Creation collateral errors"))
    variables = {
        "coupled_control": "Ethernet1/21",
        "coupled_sibling": "Ethernet1/23",
        "coupled_original_result": {"msg": "Unexpected Ethernet1/23 after Ethernet1/21; include all affected parents (Ethernet1/21, Ethernet1/23) in config."},
    }
    assert all(_expression(expression, variables) for expression in task["ansible.builtin.assert"]["that"])
    variables["coupled_original_result"]["msg"] = "Unexpected breakout family Ethernet1/23."
    assert not all(_expression(expression, variables) for expression in task["ansible.builtin.assert"]["that"])


def test_optional_safe_switch_is_locally_validated_before_the_first_coupled_get():
    validation = next(index for index, task in enumerate(PREFLIGHT) if task.get("ansible.builtin.include_tasks") == "coupled_safe_validate.yaml")
    first_read = next(index for index, task in enumerate(PREFLIGHT) if task.get("ansible.builtin.include_tasks") == "coupled_observe.yaml")
    assert validation < first_read
    assert SAFE_VALIDATION[1]["ansible.builtin.include_tasks"] == "coupled_validate_names.yaml"
    args = SAFE_VALIDATION[2]["cisco.nd.nd_manage_breakout_interfaces_validate"]
    assert args["validate_only"] is True and args["whole_switch"] is True
    assert "switch_id != test_breakout_coupled_switch_id" in " ".join(SAFE_VALIDATION[0]["ansible.builtin.assert"]["that"])


def test_cross_switch_case_captures_both_independent_snapshots_before_assertion_or_cleanup():
    tasks = CROSS_SWITCH[0]["block"]
    mutation = next(index for index, task in enumerate(tasks) if "cisco.nd.nd_manage_breakout_interfaces" in task)
    coupled = next(
        index for index, task in enumerate(tasks) if "coupled_cross_coupled_observation" in task.get("ansible.builtin.set_fact", {}) and index > mutation
    )
    safe = next(index for index, task in enumerate(tasks) if "coupled_cross_safe_observation" in task.get("ansible.builtin.set_fact", {}) and index > mutation)
    first_assertion = next(index for index, task in enumerate(tasks) if "ansible.builtin.assert" in task)
    assert mutation < coupled < safe < first_assertion
    assert tasks[mutation]["ignore_errors"] is True
    assert "failed_when" not in tasks[mutation]
    always = CROSS_SWITCH[0]["always"]
    assert "coupled_case_records" in always[0]["ansible.builtin.set_fact"]
    assert "block" in always[1] and always[1]["when"] == "not coupled_stop_writes"


def test_cross_switch_guard_baseline_is_observed_before_native_validation_or_mutation():
    tasks = CROSS_SWITCH[0]["block"]
    observe = next(index for index, task in enumerate(tasks) if task.get("ansible.builtin.include_tasks") == "coupled_safe_observe.yaml")
    baseline = next(index for index, task in enumerate(tasks) if "coupled_safe_baseline" in task.get("ansible.builtin.set_fact", {}))
    strict = next(index for index, task in enumerate(tasks) if task["name"].startswith("Require the reserved safe-switch"))
    mutation = next(index for index, task in enumerate(tasks) if "cisco.nd.nd_manage_breakout_interfaces" in task)
    assert tasks[observe]["vars"]["coupled_safe_observe_only"] is True
    assert observe < baseline < strict < mutation
    assert tasks[strict]["vars"]["coupled_safe_observe_only"] is False


@pytest.mark.parametrize(
    "confirmed,restored,unknown_forward,expected",
    [(True, True, False, False), (False, True, False, True), (True, False, False, True), (True, True, True, True)],
)
def test_cross_switch_barrier_requires_confirmed_inverse_and_restoration(confirmed, restored, unknown_forward, expected):
    expression = next(
        task["ansible.builtin.set_fact"]["coupled_cross_pending"]
        for task in CROSS_SWITCH[0]["block"]
        if isinstance(task.get("ansible.builtin.set_fact", {}).get("coupled_cross_pending"), str)
    )
    native = {"Ethernet1/21": {"native": True, "children": [], "child_speeds": {}}}
    actual = native if restored else {"Ethernet1/21": {"native": False, "children": ["Ethernet1/21/1"], "child_speeds": {"Ethernet1/21/1": 25}}}
    variables = {
        "coupled_cross_result": {
            "recovery": [{"status": "response_confirmed" if confirmed else "unknown"}],
            "api_outcomes": [{"outcome": "unknown" if unknown_forward else "success"}],
        },
        "coupled_cross_coupled_observation": {"snapshot": {"families": actual}},
        "coupled_native_baseline": {"families": native},
    }
    assert _environment().from_string(expression).render(**variables) is expected


def test_cross_switch_recovery_targets_only_violating_switch_and_keeps_safe_creation():
    assertion = next(task for task in CROSS_SWITCH[0]["block"] if task["name"].startswith("Require collateral failure"))
    checks = assertion["ansible.builtin.assert"]["that"]
    assert "coupled_cross_result.recovery | length == 1" in checks
    assert "coupled_cross_result.recovery[0].switch_id == test_breakout_coupled_switch_id" in checks
    safe = next(task for task in CROSS_SWITCH[0]["block"] if task["name"].startswith("Prove safe-switch creation remains"))
    assert safe["vars"]["coupled_safe_profile"] == "map_a"
    assert safe["vars"]["coupled_safe_observe_only"] is False
    gated = next(task for task in SUITE[1]["block"] if task.get("ansible.builtin.include_tasks") == "../tasks/coupled_cross_switch.yaml")
    assert gated["when"] == ["coupled_has_safe_switch", "not coupled_stop_writes"]


@pytest.mark.parametrize("settle,observe_only,attempts,interval", [(False, False, 1, 0), (True, True, 1, 0), (True, False, 7, 10)])
def test_only_explicit_strict_observation_can_get_settle_within_existing_hard_limits(settle, observe_only, attempts, interval):
    arguments = OBSERVER["cisco.nd.nd_manage_breakout_interfaces_validate"]
    variables = {**DEFAULTS, "coupled_observe_settle": settle, "coupled_observe_only": observe_only}
    actual_attempts = _environment().from_string(arguments["retries"]).render(**variables)
    actual_interval = _environment().from_string(arguments["interval"]).render(**variables)
    assert actual_attempts == attempts
    assert actual_interval == interval
    assert 1 <= actual_attempts <= 10 and (actual_attempts - 1) * actual_interval <= 60
    assert OBSERVER["check_mode"] is False
    assert arguments["whole_switch"] is True
    assert arguments["include_speeds"] is True
    assert arguments["topology_only"] is True
    assert arguments["baseline"] == "{{ coupled_observe_baseline | default(omit) }}"
    assert all("cisco.nd.nd_manage_breakout_interfaces" not in task and "cisco.nd.nd_rest" not in task for task in OBSERVE)


@pytest.mark.parametrize(
    "attempts,interval,valid",
    [
        (7, 10, True),
        (10, 6, True),
        (1, 60, True),
        (0, 1, False),
        (11, 1, False),
        (True, 1, False),
        (7, True, False),
        (7, -1, False),
        (7, 11, False),
        ("7", 10, False),
        (7, "10", False),
    ],
)
def test_settling_knobs_are_locally_checked_before_first_get_and_every_mutation(attempts, interval, valid):
    variables = {"test_breakout_coupled_observe_retries": attempts, "test_breakout_coupled_observe_interval": interval}
    assert OBSERVE[0]["name"].startswith("Validate test-only GET settling limits")
    checks = OBSERVE[0]["ansible.builtin.assert"]["that"]
    assert all(_expression(expression, variables) for expression in checks) is valid
    first_observer = next(index for index, task in enumerate(OBSERVE) if "cisco.nd.nd_manage_breakout_interfaces_validate" in task)
    assert first_observer > 0
    assert any(task.get("ansible.builtin.include_tasks") == "coupled_observe.yaml" for task in PREFLIGHT)
    assert all("cisco.nd.nd_manage_breakout_interfaces" not in task and "cisco.nd.nd_rest" not in task for task in PREFLIGHT)


def test_immediate_snapshot_is_frozen_before_response_gate_and_strict_get_settling():
    tasks = CASES[1]["block"]
    mutation = next(index for index, task in enumerate(tasks) if "cisco.nd.nd_manage_breakout_interfaces" in task)
    immediate = next(index for index, task in enumerate(tasks) if task["name"].startswith("Capture real state immediately"))
    frozen = next(
        index for index, task in enumerate(tasks) if "coupled_immediate_observation" in task.get("ansible.builtin.set_fact", {}) and index > mutation
    )
    gate = next(index for index, task in enumerate(tasks) if task["name"].startswith("Freeze uncertain invocations"))
    barrier = next(index for index, task in enumerate(tasks) if task["name"].startswith("Keep the write barrier raised"))
    settling = next(index for index, task in enumerate(tasks) if task["name"].startswith("Settle only completed actions"))
    settled = next(index for index, task in enumerate(tasks) if task["name"].startswith("Save settled recovery evidence"))
    assertions = next(index for index, task in enumerate(tasks) if task.get("ansible.builtin.include_tasks") == "coupled_assert.yaml")
    assert mutation < immediate < frozen < gate < barrier < settling < settled < assertions
    assert tasks[mutation]["ignore_errors"] is True
    assert "until" not in tasks[mutation] and "retries" not in tasks[mutation]
    assert tasks[immediate]["vars"]["coupled_observe_only"] is True
    assert tasks[immediate]["vars"]["coupled_observe_settle"] is False
    assert tasks[gate]["ansible.builtin.assert"]["that"] == ["not coupled_case_response_pending"]
    assert tasks[barrier]["ansible.builtin.set_fact"]["coupled_case_write_pending"] is True
    assert tasks[settling]["ansible.builtin.include_tasks"] == "coupled_observe.yaml"
    assert tasks[settling]["vars"]["coupled_observe_only"] is False
    assert tasks[settling]["vars"]["coupled_observe_profile"] == "{{ coupled_case.after }}"
    assert tasks[settling]["vars"]["coupled_observe_baseline"] == "{{ coupled_native_baseline }}"


@pytest.mark.parametrize("status", ["unknown", "warning", "planned", None])
@pytest.mark.parametrize("inverse_confirmed", [False, True])
def test_unknown_forward_status_freezes_before_get_settling_even_when_inverse_acknowledged(status, inverse_confirmed):
    variables = {
        "coupled_case": {"expect": "recovery"},
        "coupled_original_result": {
            "api_outcomes": [{"outcome": status}],
            "recovery": [{"status": "response_confirmed" if inverse_confirmed else "unknown"}],
        },
    }
    assert _environment().from_string(_response_pending_expression()).render(**variables) is True


@pytest.mark.parametrize("original", [{}, {"api_outcomes": []}, {"api_outcomes": [{"outcome": "success"}], "recovery": []}])
def test_missing_forward_or_required_inverse_evidence_prevents_settling(original):
    variables = {"coupled_case": {"expect": "recovery"}, "coupled_original_result": original}
    assert _environment().from_string(_response_pending_expression()).render(**variables) is True


@pytest.mark.parametrize(
    "expect,outcome,recovery", [("success", "success", []), ("noop", "noop", []), ("recovery", "success", [{"status": "response_confirmed"}])]
)
def test_only_known_completed_response_evidence_releases_the_read_only_settling_gate(expect, outcome, recovery):
    variables = {"coupled_case": {"expect": expect}, "coupled_original_result": {"api_outcomes": [{"outcome": outcome}], "recovery": recovery}}
    assert _environment().from_string(_response_pending_expression()).render(**variables) is False


def test_prewrite_error_with_no_actions_only_permits_immediate_strict_validation_not_settling():
    variables = {"coupled_case": {"expect": "preflight_error"}, "coupled_original_result": {"api_outcomes": [], "recovery": []}}
    assert _environment().from_string(_response_pending_expression()).render(**variables) is False
    task = next(task for task in CASES[1]["block"] if task["name"].startswith("Settle only completed actions"))
    assert _environment().from_string(task["vars"]["coupled_observe_settle"]).render(**variables) is False


def test_original_result_immediate_and_settled_evidence_are_preserved_before_any_cleanup():
    facts = CASES[1]["always"][0]["ansible.builtin.set_fact"]
    record = facts["coupled_case_records"]
    assert "'result': coupled_original_result" in record
    assert "'immediate_observation_after_invocation': coupled_immediate_observation" in record
    assert "'settled_observation_before_cleanup': coupled_settled_observation" in record
    assert "'observation_before_cleanup': coupled_recovery_observation" in record
    after_mutation = False
    for task in CASES[1]["block"]:
        after_mutation = after_mutation or "cisco.nd.nd_manage_breakout_interfaces" in task
        if after_mutation:
            assert "coupled_original_result" not in task.get("ansible.builtin.set_fact", {})
    assert "coupled_case_write_pending" in facts["coupled_stop_writes"]
    cleanup = CASES[1]["always"][1]["block"][0]
    assert cleanup["when"] == "not coupled_stop_writes"


def test_failed_settling_preserves_last_get_and_does_not_release_the_write_barrier():
    rescue = next(task for task in CASES[1]["rescue"] if task["name"].startswith("Preserve the final GET attempt"))
    assert rescue["when"] == ["coupled_case_settle_started", "coupled_observation.snapshot is defined"]
    assert rescue["ansible.builtin.set_fact"]["coupled_settled_observation"] == "{{ coupled_observation }}"
    assert rescue["ansible.builtin.set_fact"]["coupled_recovery_observation"] == "{{ coupled_observation }}"
    assert "coupled_case_write_pending" not in rescue["ansible.builtin.set_fact"]
    assert "coupled_immediate_observation" not in rescue["ansible.builtin.set_fact"]


def test_setup_ack_and_declared_profile_must_both_complete_before_next_mutation():
    mutation = next(index for index, task in enumerate(PREPARE) if "cisco.nd.nd_rest" in task)
    acknowledgment = next(index for index, task in enumerate(PREPARE) if "ansible.builtin.assert" in task)
    strict = next(index for index, task in enumerate(PREPARE) if task.get("ansible.builtin.include_tasks") == "coupled_observe.yaml")
    release = next(index for index, task in enumerate(PREPARE) if task.get("ansible.builtin.set_fact", {}).get("coupled_case_write_pending") is False)
    assert mutation < acknowledgment < strict < release
    assert PREPARE[strict]["vars"]["coupled_observe_settle"] is True
    assert PREPARE[strict]["vars"]["coupled_observe_only"] is False
    assert PREPARE[strict]["vars"]["coupled_observe_profile"] == "map_a"
    assert "until" not in PREPARE[mutation] and "retries" not in PREPARE[mutation]
    assert PREPARE[mutation]["cisco.nd.nd_rest"] == {
        "method": "POST",
        "path": "/api/v1/manage/fabrics/{{ test_breakout_coupled_fabric_name | urlencode }}/interfaceActions/breakout",
        "content": {
            "interfaces": [
                {
                    "switchId": "{{ test_breakout_coupled_switch_id }}",
                    "interfaceName": "{{ coupled_control }}",
                    "breakoutMap": "{{ coupled_map }}",
                }
            ]
        },
    }
    assert PREPARE[mutation]["register"] == "coupled_preparation_result"
    assert PREPARE[mutation]["check_mode"] is False
    assert all("nd_breakout_prepare" not in task for task in PREPARE)


def _setup_acknowledged(result):
    checks = next(task["ansible.builtin.assert"]["that"] for task in PREPARE if "ansible.builtin.assert" in task)
    variables = {
        "coupled_preparation_result": result,
        "test_breakout_coupled_switch_id": "FDO27020W5V",
        "coupled_control": "Ethernet1/21",
    }
    return all(_expression(check, variables) for check in checks)


@pytest.mark.parametrize("status", [200, 201, 207])
def test_setup_ack_accepts_only_a_complete_identified_success_in_nd_rest_jsondata(status):
    body = {"results": [{"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/21", "status": "Success"}]}
    assert _setup_acknowledged({"status": status, "jsondata": body, "current": {"results": []}})


@pytest.mark.parametrize(
    "result",
    [
        {"status": status, "jsondata": {"results": [{"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/21", "status": "Success"}]}}
        for status in (202, 204, 400, 500)
    ]
    + [
        {"status": 207, "jsondata": None},
        {"status": 207, "jsondata": {}},
        {"status": 207, "jsondata": {"results": []}},
        {"status": 207, "jsondata": {"results": [{"switchId": "OTHER12345", "interfaceName": "Ethernet1/21", "status": "Success"}]}},
        {"status": 207, "jsondata": {"results": [{"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/23", "status": "Success"}]}},
        {"status": 207, "jsondata": {"results": [{"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/21", "status": "Failed"}]}},
        {
            "status": 207,
            "jsondata": {
                "results": [
                    {"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/21", "status": "Success"},
                    {"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/23", "status": "Success"},
                ]
            },
        },
        {
            "status": 207,
            "jsondata": {"results": []},
            "current": {"results": [{"switchId": "FDO27020W5V", "interfaceName": "Ethernet1/21", "status": "Success"}]},
        },
    ],
)
def test_setup_ack_rejects_incomplete_foreign_failed_or_non_jsondata_receipts(result):
    assert not _setup_acknowledged(result)


def test_cleanup_requires_full_native_get_settling_without_replaying_a_write():
    first = CLEANUP[0]
    last = CLEANUP[-1]
    assert first["vars"]["coupled_observe_only"] is True
    assert last["ansible.builtin.include_tasks"] == "coupled_observe.yaml"
    assert last["vars"]["coupled_observe_profile"] == "native"
    assert last["vars"]["coupled_observe_only"] is False
    assert last["vars"]["coupled_observe_settle"] is True
    assert last["vars"]["coupled_observe_baseline"] == "{{ coupled_native_baseline }}"
    assert all("until" not in task and "retries" not in task for task in CLEANUP)
