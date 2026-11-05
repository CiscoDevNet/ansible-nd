# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Render real matrix YAML using Ansible's templar, without controller execution.

This checks fixture scope, map selection and completion safety. It does not
simulate a successful controller run or replace live integration coverage.
"""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

from ansible_collections.cisco.nd.plugins.action import nd_manage_breakout_interfaces_validate as observer

TARGET = Path(__file__).resolve().parents[2] / "integration" / "targets" / "nd_manage_breakout_interfaces"
SERIAL = "FDO28481BXX"
OWNED = ["Ethernet1/53", "Ethernet1/54"]
OUTSIDE = ["Ethernet1/50", "Ethernet1/51", "Ethernet1/52"]


def tasks(path):
    return yaml.safe_load((TARGET / path).read_text())


def task(path, prefix):
    return next(item for item in tasks(path) if item["name"].startswith(prefix))


def render(value, variables):
    if isinstance(value, dict):
        return {key: render(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, variables) for item in value]
    return Templar(loader=DataLoader(), variables=variables).template(trust_as_template(value)) if isinstance(value, str) else value


def condition(expression, variables):
    return Templar(loader=DataLoader(), variables=variables)._engine.evaluate_conditional(trust_as_template(expression))


def assertions(item, variables):
    expressions = item["ansible.builtin.assert"]["that"]
    if not isinstance(expressions, list):
        expressions = [expressions]
    return all(condition(expression, variables) for expression in expressions)


def family(parent, native=True, speed=25, lanes=4):
    children = [] if native else [parent + "/" + str(lane) for lane in range(1, lanes + 1)]
    return {"native": native, "children": children, "child_speeds": {child: speed for child in children}}


def fixture(parent, breakout_map):
    speed, lanes = breakout_map.split("g-")
    return {
        "switch_id": SERIAL,
        "control_parent": parent,
        "native_interfaces": [parent],
        "profiles": {"map_a": {"breakout_map": breakout_map, "child_lanes": {parent: list(range(1, int(lanes[:-1]) + 1))}}},
    }


def variables():
    fixtures = [fixture(OWNED[0], "25g-4x"), fixture(OWNED[1], "50g-2x")]
    snapshots = {
        str(index): {
            "switch_id": SERIAL,
            "families": {item["control_parent"]: family(item["control_parent"])},
            "policy_maps": {},
            "owned_interfaces": OWNED,
            "outside_families": {parent: family(parent, native=False) for parent in OUTSIDE},
            "outside_policy_maps": {parent: "25g-4x" for parent in OUTSIDE},
        }
        for index, item in enumerate(fixtures)
    }
    return {
        "test_fabric_name": "fab1",
        "test_switch_serial": SERIAL,
        "test_breakout_bulk_fixtures": fixtures,
        "test_breakout_preserved_config": [{"switch_id": SERIAL, "interface_names": OUTSIDE, "breakout_map": "25g-4x"}],
        "test_breakout_invalid_map": "integration-invalid-breakout-map",
        "breakout_bulk_fixtures": fixtures,
        "breakout_matrix_fixtures": fixtures,
        "breakout_matrix_owned": OWNED,
        "breakout_matrix_profiles": ["native", "native"],
        "breakout_matrix_snapshots": snapshots,
        "breakout_matrix_baselines": deepcopy(snapshots),
        "breakout_matrix_outside": OUTSIDE,
        "breakout_matrix_ready": True,
        "ansible_verbosity": 3,
        "omit": "__omit__",
    }


def test_matrix_preparation_preserves_owned_scope_and_all_three_existing_outside_breakouts():
    values = variables()
    select = task("tasks/matrix_prepare.yaml", "Select two independently")
    assert render(select["ansible.builtin.set_fact"], values)["breakout_matrix_fixtures"] == values["test_breakout_bulk_fixtures"]
    owned = task("tasks/matrix_prepare.yaml", "Initialize the two-parent")
    assert render(owned["ansible.builtin.set_fact"], values)["breakout_matrix_owned"] == OWNED
    protect = task("tasks/matrix_prepare.yaml", "Save immutable matrix")
    assert render(protect["ansible.builtin.set_fact"], values)["breakout_matrix_outside"] == OUTSIDE


def test_authoritative_protection_also_includes_guard_breakouts_excluded_from_outside_projection():
    values = variables()
    for snapshot in values["breakout_matrix_snapshots"].values():
        snapshot["families"]["Ethernet1/60"] = family("Ethernet1/60", native=False)
    protect = task("tasks/matrix_prepare.yaml", "Save immutable matrix")
    assert render(protect["ansible.builtin.set_fact"], values)["breakout_matrix_outside"] == OUTSIDE + ["Ethernet1/60"]


@pytest.mark.parametrize("profiles", [["native", "native"], ["map_a", "native"], ["native", "map_a"], ["map_a", "map_a"]])
def test_each_observer_receives_its_own_profile_with_identical_owned_baseline_scope(profiles):
    values = variables()
    values["breakout_matrix_profiles"] = profiles
    observe = tasks("tasks/matrix_observe_one.yaml")[0]
    for index in range(2):
        args = render(observe["cisco.nd.nd_manage_breakout_interfaces_validate"], {**values, "breakout_matrix_index": index})
        assert args["expected_profile"] == profiles[index]
        assert args["owned_interfaces"] == OWNED
        assert args["baseline"] == values["breakout_matrix_baselines"][str(index)]
        prepared = observer._prepare_fixture(args["fixture"])
        assert observer._baseline(args["baseline"], SERIAL, prepared["native"] + prepared["guards"], True, True, OWNED) == args["baseline"]


def test_capture_has_no_baseline_before_writes_but_post_action_observation_keeps_same_owned_scope():
    values = variables()
    values["breakout_matrix_baselines"] = {}
    observe = tasks("tasks/matrix_observe_one.yaml")[0]
    for index in range(2):
        args = render(
            observe["cisco.nd.nd_manage_breakout_interfaces_validate"], {**values, "breakout_matrix_index": index, "breakout_matrix_observe_only": True}
        )
        assert args["baseline"] == "__omit__"
        assert args["observe_only"] is True
        assert args["owned_interfaces"] == OWNED


def override_cases():
    block = task("tests/overridden.yaml", "Exercise selected-switch")["block"]
    return next(item for item in block if item["name"].startswith("Run independent overridden"))["loop"]


@pytest.mark.parametrize("case", override_cases(), ids=lambda value: value["id"])
def test_every_override_case_builds_correct_interface_level_maps_and_retains_existing_outside_config(case):
    values = variables()
    values["breakout_override_case"] = case
    case_tasks = tasks("tasks/override_case.yaml")
    values.update(render(case_tasks[0]["ansible.builtin.set_fact"], values))
    if condition(case_tasks[1]["when"], values):
        values.update(render(case_tasks[1]["ansible.builtin.set_fact"], values))
    for index in case["desired"]:
        values.update(render(case_tasks[2]["ansible.builtin.set_fact"], {**values, "item": index}))
    args = render(case_tasks[3]["cisco.nd.nd_manage_breakout_interfaces"], values)
    assert args["config"][0] == values["test_breakout_preserved_config"][0]
    own_groups = [item for item in args["config"] if item["interface_names"] and item["interface_names"][0] in OWNED]
    assert [item["interface_names"][0] for item in own_groups] == [OWNED[index] for index in case["desired"]]
    for group, index in zip(own_groups, case["desired"]):
        assert group["breakout_map"] == case.get("map_override", values["breakout_matrix_fixtures"][index]["profiles"]["map_a"]["breakout_map"])
    assert render(case_tasks[-1]["vars"], values)["breakout_matrix_profiles"] == case["profiles"]
    assert render(case_tasks[3]["check_mode"], values) is case.get("check_mode", False)


def test_protection_groups_cannot_authorize_an_extra_switch_or_unobserved_parent():
    guard = task("tests/overridden.yaml", "Validate explicitly preserved")
    values = variables()
    allowed = values["test_breakout_preserved_config"][0]
    assert assertions(guard, {**values, "item": allowed})
    assert not assertions(guard, {**values, "item": {**allowed, "switch_id": "OTHER"}})
    assert not assertions(guard, {**values, "item": {**allowed, "interface_names": ["Ethernet1/49"]}})


@pytest.mark.parametrize(
    "result,allowed",
    [
        ({"failed": True, "msg": "runner lost module reply"}, False),
        ({"api_outcomes": [{"outcome": "unknown"}], "api_calls": [{"method": "POST", "http_status": None}]}, False),
        ({"api_outcomes": [{"outcome": "unknown"}], "api_calls": [{"method": "POST", "http_status": 500}]}, False),
        ({"api_outcomes": [{"outcome": "unknown"}], "api_calls": [{"method": "POST", "http_status": 207}]}, True),
        ({"api_outcomes": [{"outcome": "unknown"}], "api_calls": [{"method": "POST", "http_status": 400}]}, True),
        ({"api_outcomes": [{"outcome": "success"}]}, True),
        ({"api_outcomes": [{"outcome": "noop"}]}, True),
        ({"api_outcomes": [{"outcome": "planned"}]}, True),
        ({"api_outcomes": [{"outcome": "arbitrary"}]}, False),
        ({"api_outcomes": [{"outcome": "success"}], "recovery": [{"status": "unknown"}]}, False),
        ({"api_outcomes": [{"outcome": "success"}], "recovery": [{"status": "failed"}]}, False),
    ],
)
def test_cleanup_requires_completed_known_evidence_and_never_replays_missing_or_500_replies(result, allowed):
    values = {**variables(), "breakout_matrix_last_result": result}
    check = task("tasks/matrix_cleanup.yaml", "Do not replay uncertain")
    assert assertions(check, values) is allowed


def test_low_verbosity_cannot_authorize_unknown_completed_207_teardown_without_trace_evidence():
    values = {
        **variables(),
        "ansible_verbosity": 0,
        "breakout_matrix_last_result": {"api_outcomes": [{"outcome": "unknown"}], "api_calls": [{"method": "POST", "http_status": 207}]},
    }
    assert not assertions(task("tasks/matrix_cleanup.yaml", "Do not replay uncertain"), values)


def test_cleanup_targets_only_fresh_broken_owned_parents_and_never_outside_resources():
    values = variables()
    values["breakout_matrix_snapshots"]["1"]["families"][OWNED[1]] = family(OWNED[1], native=False, speed=50, lanes=2)
    values["breakout_matrix_cleanup_config"] = []
    build = task("tasks/matrix_cleanup.yaml", "Build fresh scoped teardown")
    for parent in OWNED:
        if condition(build["when"], {**values, "item": parent}):
            values.update(render(build["ansible.builtin.set_fact"], {**values, "item": parent}))
    assert values["breakout_matrix_cleanup_config"] == [{"switch_id": SERIAL, "interface_names": [OWNED[1]]}]


@pytest.mark.parametrize("state", ["merged", "overridden"])
def test_failure_and_correction_payloads_use_each_independent_fixture_map(state):
    values = variables()
    values["breakout_failure_case"] = {"state": state, "entries": [{"index": 0, "valid": True}, {"index": 1, "valid": False}]}
    wrapper = tasks("tasks/api_failure_case.yaml")
    values.update(render(wrapper[0]["ansible.builtin.set_fact"], values))
    block = wrapper[1]["block"]
    build = next(item for item in block if item["name"].startswith("Build the ordered"))
    for entry in values["breakout_failure_case"]["entries"]:
        values.update(render(build["ansible.builtin.set_fact"], {**values, "item": entry}))
    assert values["breakout_failure_config"][-2:] == [
        {"switch_id": SERIAL, "interface_names": [OWNED[0]], "breakout_map": "25g-4x"},
        {"switch_id": SERIAL, "interface_names": [OWNED[1]], "breakout_map": "integration-invalid-breakout-map"},
    ]
    reset = next(item for item in block if item["name"].startswith("Build corrected user"))
    values.update(render(reset["ansible.builtin.set_fact"], values))
    correct = next(item for item in block if item["name"].startswith("Add correctly mapped"))
    for index in render(correct["loop"], values):
        values.update(render(correct["ansible.builtin.set_fact"], {**values, "item": index}))
    expected_owned = [{"switch_id": SERIAL, "interface_names": [OWNED[0]], "breakout_map": "25g-4x"}]
    if state == "merged":
        expected_owned.append({"switch_id": SERIAL, "interface_names": [OWNED[1]], "breakout_map": "50g-2x"})
    assert values["breakout_correction_config"] == (values["test_breakout_preserved_config"] if state == "overridden" else []) + expected_owned


@pytest.mark.parametrize(
    "valid,broken,outcome,accepted",
    [
        (True, True, "success", True),
        (True, True, "unknown", True),
        (True, False, "unknown", True),
        (True, False, "success", False),
        (False, False, "failed", True),
        (False, False, "success", False),
    ],
)
def test_partial_207_reporting_does_not_promote_unreported_items_or_unapplied_success(valid, broken, outcome, accepted):
    values = variables()
    values["item"] = {"index": 0, "valid": valid}
    values["breakout_failure_original_result"] = {"api_outcomes": [{"switch_id": SERIAL, "interface_name": OWNED[0], "outcome": outcome}]}
    values["breakout_matrix_snapshots"]["0"]["families"][OWNED[0]] = family(OWNED[0], native=not broken)
    block = tasks("tasks/api_failure_case.yaml")[1]["block"]
    check = next(item for item in block if item["name"].startswith("Correlate reported"))
    assert assertions(check, values) is accepted


def test_case_baseline_is_captured_after_preparation_and_immediately_before_failed_action():
    block = tasks("tasks/api_failure_case.yaml")[1]["block"]
    position = next(index for index, item in enumerate(block) if item["name"].startswith("Freeze exact per-case"))
    assert block[position + 1]["register"] == "breakout_matrix_last_result"
    values = variables()
    values["breakout_matrix_snapshots"]["1"]["families"][OWNED[1]] = family(OWNED[1], native=False, speed=50, lanes=2)
    captured = render(block[position]["ansible.builtin.set_fact"], values)["breakout_failure_before_snapshots"]
    assert captured["1"]["families"][OWNED[1]]["children"] == [OWNED[1] + "/1", OWNED[1] + "/2"]
    assert values["breakout_matrix_baselines"]["1"]["families"][OWNED[1]]["children"] == []


@pytest.mark.parametrize("changed,created,accepted", [(True, True, True), (False, True, False), (False, False, True), (True, False, True)])
def test_observed_partial_creation_cannot_be_hidden_by_changed_false(changed, created, accepted):
    values = variables()
    values["item"] = {"index": 0, "valid": True}
    values["breakout_failure_before_snapshots"] = deepcopy(values["breakout_matrix_snapshots"])
    values["breakout_failure_original_snapshots"] = deepcopy(values["breakout_matrix_snapshots"])
    if created:
        values["breakout_failure_original_snapshots"]["0"]["families"][OWNED[0]] = family(OWNED[0], native=False)
    values["breakout_failure_original_result"] = {"changed": changed}
    check = next(item for item in tasks("tasks/api_failure_case.yaml")[1]["block"] if item["name"].startswith("Require independently observed partial"))
    assert assertions(check, values) is accepted


@pytest.mark.parametrize("broken", [False, True])
@pytest.mark.parametrize("regression", [None, "stale_state", "stale_children", "predicted_evidence", "missing", "duplicate", "foreign_switch"])
def test_guarded_partial_after_state_must_match_fresh_independent_family_evidence(broken, regression):
    values = variables()
    values["item"] = {"index": 0, "valid": True}
    values["breakout_failure_case"] = {"entries": [values["item"]]}
    observed = family(OWNED[0], native=not broken)
    values["breakout_failure_original_snapshots"] = deepcopy(values["breakout_matrix_snapshots"])
    values["breakout_failure_original_snapshots"]["0"]["families"][OWNED[0]] = observed
    reported = {"switch_id": SERIAL, "interface_name": OWNED[0], "evidence": "post_action_discovery", "broken_out": broken, "children": observed["children"]}
    if regression == "stale_state":
        reported["broken_out"] = not broken
    elif regression == "stale_children":
        reported["children"] = [OWNED[0] + "/100"]
    elif regression == "predicted_evidence":
        reported["evidence"] = "api_response"
    elif regression == "foreign_switch":
        reported["switch_id"] = "OTHER"
    values["breakout_failure_original_result"] = {
        "after": [] if regression == "missing" else [reported, deepcopy(reported)] if regression == "duplicate" else [reported]
    }
    check = next(item for item in tasks("tasks/api_failure_case.yaml")[1]["block"] if item["name"].startswith("Validate reported observed family"))
    values.update(render(check["vars"], values))
    assert assertions(check, values) is (regression is None)


def test_omitted_baseline_family_is_included_in_post_failure_report_validation_without_inventing_a_request():
    values = variables()
    values["breakout_failure_case"] = {"entries": [{"index": 0, "valid": False}], "prepare_omitted": True}
    check = next(item for item in tasks("tasks/api_failure_case.yaml")[1]["block"] if item["name"].startswith("Validate reported observed family"))
    assert render(check["loop"], values) == [{"index": 0, "valid": False}, {"index": 1, "valid": True}]


@pytest.mark.parametrize("unknown", [False, True])
@pytest.mark.parametrize("wrong", [None, "after_status", "guard_incomplete", "wrong_switch", "false_uncertainty", "collateral"])
def test_guarded_failure_preserves_truthful_observation_and_api_uncertainty(unknown, wrong):
    values = variables()
    result = {
        "failed": True,
        "recovery": [],
        "after_status": "observed",
        "may_have_changed": unknown,
        "verification": {"enabled": True, "complete": True, "phases": [{"switch_id": SERIAL, "collateral": []}]},
        "api_outcomes": [{"outcome": "unknown" if unknown else "failed"}],
        "api_calls": [{"method": "POST", "path": "/api/v1/manage/fabrics/fab1/interfaceActions/breakout", "http_status": 207}],
    }
    if wrong == "after_status":
        result["after_status"] = "response_confirmed"
    elif wrong == "guard_incomplete":
        result["verification"]["complete"] = False
    elif wrong == "wrong_switch":
        result["verification"]["phases"][0]["switch_id"] = "OTHER"
    elif wrong == "false_uncertainty":
        result["may_have_changed"] = not unknown
    elif wrong == "collateral":
        result["verification"]["phases"][0]["collateral"] = ["unexpected other family"]
    values["breakout_matrix_last_result"] = result
    check = next(item for item in tasks("tasks/api_failure_case.yaml")[1]["block"] if item["name"].startswith("Require honest failure"))
    assert assertions(check, values) is (wrong is None)


def nested_tasks(items):
    for item in items:
        yield item
        for section in ("block", "rescue", "always"):
            yield from nested_tasks(item.get(section, []))


@pytest.mark.parametrize("failure", [{}, {"task": "controller mutation", "result": {"failed": True, "msg": "original error"}}])
@pytest.mark.parametrize(
    "path,prefix,key",
    [
        ("tests/overridden.yaml", "Do not hide an overridden regression", "breakout_matrix_failure"),
        ("tasks/api_failure_case.yaml", "Retain API failure scenario regressions", "breakout_matrix_failure"),
        ("tests/fabric_clear.yaml", "Re-raise any original regression", "breakout_fabric_failure"),
    ],
)
def test_terminal_assertion_failure_messages_always_render_to_strings(path, prefix, key, failure):
    check = next(item for item in nested_tasks(tasks(path)) if item["name"].startswith(prefix))
    arguments = render(check["ansible.builtin.assert"], {key: failure})
    assert isinstance(arguments["fail_msg"], str)
    assert "scenario" in arguments["fail_msg"]
    assert str(failure) in arguments["fail_msg"]


def api_case_task(prefix):
    return next(item for item in tasks("tasks/api_failure_case.yaml")[1]["block"] if item["name"].startswith(prefix))


def test_partial_validation_flags_reset_for_every_case_and_default_to_strict_matrix_reads():
    values = variables()
    values["breakout_failure_case"] = {"entries": []}
    values["breakout_matrix_topology_only_indices"] = [0, 1]
    values["breakout_failure_partial_indices"] = [0, 1]
    reset = render(tasks("tasks/api_failure_case.yaml")[0]["ansible.builtin.set_fact"], values)
    assert reset["breakout_matrix_topology_only_indices"] == []
    assert reset["breakout_failure_partial_indices"] == []
    values.update(reset)
    read = tasks("tasks/matrix_observe_one.yaml")[0]["cisco.nd.nd_manage_breakout_interfaces_validate"]
    for index in (0, 1):
        assert render(read, {**values, "breakout_matrix_index": index})["topology_only"] is False
    del values["breakout_matrix_topology_only_indices"]
    assert render(read, {**values, "breakout_matrix_index": 0})["topology_only"] is False


@pytest.mark.parametrize("outcome", ["success", "failed", "unknown", "noop"])
@pytest.mark.parametrize("valid,broken", [(True, True), (True, False), (False, True)])
def test_only_physically_applied_valid_failed_or_unknown_items_get_selective_policy_diagnostics(outcome, valid, broken):
    values = variables()
    values.update(
        item={"index": 0, "valid": valid},
        breakout_failure_partial_indices=[],
        breakout_failure_partial_policy_diagnostics={},
        breakout_failure_original_snapshots=deepcopy(values["breakout_matrix_snapshots"]),
        breakout_failure_original_result={"api_outcomes": [{"switch_id": SERIAL, "interface_name": OWNED[0], "outcome": outcome}]},
    )
    values["breakout_failure_original_snapshots"]["0"]["families"][OWNED[0]] = family(OWNED[0], native=not broken)
    identify = api_case_task("Identify physically applied")
    eligible = all(condition(expression, values) for expression in identify["when"])
    assert eligible is (valid and broken and outcome in ["failed", "unknown"])
    if eligible:
        captured = render(identify["ansible.builtin.set_fact"], values)
        assert captured["breakout_failure_partial_indices"] == [0]
        diagnostic = captured["breakout_failure_partial_policy_diagnostics"]["0"]
        assert diagnostic["expected_policy_maps"] == {OWNED[0]: "25g-4x"}
        assert diagnostic["observed_policy_maps"] == {}


@pytest.mark.parametrize("change", ["foreign_switch", "wrong_parent", "duplicate_identity"])
def test_partial_policy_exception_requires_one_exact_composite_outcome_identity(change):
    values = variables()
    outcomes = [{"switch_id": SERIAL, "interface_name": OWNED[0], "outcome": "unknown"}]
    if change == "foreign_switch":
        outcomes[0]["switch_id"] = "OTHER"
    elif change == "wrong_parent":
        outcomes[0]["interface_name"] = OWNED[1]
    else:
        outcomes.append(deepcopy(outcomes[0]))
    values.update(
        item={"index": 0, "valid": True},
        breakout_failure_original_snapshots=deepcopy(values["breakout_matrix_snapshots"]),
        breakout_failure_original_result={"api_outcomes": outcomes},
    )
    values["breakout_failure_original_snapshots"]["0"]["families"][OWNED[0]] = family(OWNED[0], native=False)
    assert not all(condition(expression, values) for expression in api_case_task("Identify physically applied")["when"])


def test_correction_policy_exception_is_scoped_to_existing_partial_index_not_fresh_create_or_global_facts():
    values = variables()
    values.update(breakout_failure_case={"state": "merged"}, breakout_failure_partial_indices=[0], breakout_matrix_topology_only_indices=[])
    read = tasks("tasks/matrix_observe_one.yaml")[0]["cisco.nd.nd_manage_breakout_interfaces_validate"]
    for prefix in ["Independently prove the corrected", "Independently validate topology and fresh"]:
        scoped = render(api_case_task(prefix)["vars"], values)
        assert scoped["breakout_matrix_topology_only_indices"] == [0]
        assert render(read, {**values, **scoped, "breakout_matrix_index": 0})["topology_only"] is True
        assert render(read, {**values, **scoped, "breakout_matrix_index": 1})["topology_only"] is False
        assert values["breakout_matrix_topology_only_indices"] == []


@pytest.mark.parametrize("known_success", [False, True])
def test_valid_partial_observation_keeps_strict_policy_validation_for_explicit_success(known_success):
    values = variables()
    values.update(item={"index": 0, "valid": True}, breakout_failure_partial_indices=[] if known_success else [0])
    values["breakout_matrix_snapshots"]["0"]["families"][OWNED[0]] = family(OWNED[0], native=False)
    args = render(api_case_task("Validate an applied valid")["cisco.nd.nd_manage_breakout_interfaces_validate"], values)
    assert args["topology_only"] is (not known_success)
    prepared = observer._prepare_fixture(args["fixture"])
    differences = observer._compare(values["breakout_matrix_snapshots"]["0"], prepared, "map_a", include_speeds=True, topology_only=args["topology_only"])
    assert (not differences) is (not known_success)
    if known_success:
        assert differences[0]["check"] == "policy_maps"


@pytest.mark.parametrize("regression", [None, "policy_created", "policy_changed", "speed_changed", "foreign_switch", "success_instead_of_noop"])
def test_corrected_partial_noop_preserves_exact_family_and_actual_missing_policy(regression):
    values = variables()
    values.update(
        item=0,
        breakout_failure_original_snapshots=deepcopy(values["breakout_matrix_snapshots"]),
        breakout_matrix_last_result={"api_outcomes": [{"switch_id": SERIAL, "interface_name": OWNED[0], "outcome": "noop"}]},
    )
    for snapshots in (values["breakout_failure_original_snapshots"], values["breakout_matrix_snapshots"]):
        snapshots["0"]["families"][OWNED[0]] = family(OWNED[0], native=False)
    if regression in ["policy_created", "policy_changed"]:
        values["breakout_matrix_snapshots"]["0"]["policy_maps"] = {OWNED[0]: "25g-4x" if regression == "policy_created" else "50g-2x"}
    elif regression == "speed_changed":
        values["breakout_matrix_snapshots"]["0"]["families"][OWNED[0]]["child_speeds"][OWNED[0] + "/1"] = 10
    elif regression == "foreign_switch":
        values["breakout_matrix_last_result"]["api_outcomes"][0]["switch_id"] = "OTHER"
    elif regression == "success_instead_of_noop":
        values["breakout_matrix_last_result"]["api_outcomes"][0]["outcome"] = "success"
    original = api_case_task("Preserve partial existing-family")
    repeated = api_case_task("Recheck exact partial no-op")
    assert assertions(original, values) is (regression is None)
    assert assertions(repeated, values) is (regression is None)


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize("wrong", [False, True])
def test_corrected_each_family_outcome_distinguishes_existing_noop_from_fresh_success(existing, wrong):
    values = variables()
    values.update(item=0, breakout_failure_original_snapshots=deepcopy(values["breakout_matrix_snapshots"]))
    values["breakout_failure_original_snapshots"]["0"]["families"][OWNED[0]] = family(OWNED[0], native=not existing)
    expected = "noop" if existing else "success"
    values["breakout_matrix_last_result"] = {"api_outcomes": [{"switch_id": SERIAL, "interface_name": OWNED[0], "outcome": "unknown" if wrong else expected}]}
    assert assertions(api_case_task("Validate corrected creation"), values) is (not wrong)
