# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Evaluate real fabric-clear YAML safety contracts without controller execution.

These tests render the integration assertions and arguments using Ansible's
templar. They neither mock a successful controller run nor establish live
global-clear coverage.
"""

from pathlib import Path

import pytest
import yaml
from ansible.errors import AnsibleError
from ansible.parsing.dataloader import DataLoader
from ansible import template as ansible_template

TARGET = Path(__file__).resolve().parents[2] / "integration" / "targets" / "nd_manage_breakout_interfaces"
PAGE = "tasks/fabric_clear_page.yaml"
READ = "tasks/fabric_clear_read.yaml"
CASE = "tasks/fabric_clear_case.yaml"
CLEANUP = "tasks/fabric_clear_cleanup.yaml"
CHECK_MODE = "tests/check_mode.yaml"


def tasks(path):
    return yaml.safe_load((TARGET / path).read_text())


def task(path, prefix):
    return next(item for item in tasks(path) if item["name"].startswith(prefix))


def evaluate(expression, variables):
    return render("{{ " + expression + " }}", variables)


def render(value, variables):
    if isinstance(value, dict):
        return {key: render(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, variables) for item in value]
    trust = getattr(ansible_template, "trust_as_template", lambda item: item)
    return ansible_template.Templar(loader=DataLoader(), variables=variables).template(trust(value)) if isinstance(value, str) else value


def assertions(item, variables):
    expressions = item["ansible.builtin.assert"]["that"]
    if isinstance(expressions, str):
        expressions = [expressions]
    try:
        return all(evaluate(expression, variables) for expression in expressions)
    except AnsibleError:
        return False  # Missing required evidence must reject, never default open.


def row(name="Ethernet1/53", switch="S1", **changes):
    return {"switchId": switch, "interfaceName": name, "physicalInterface": True, "fex": False, **changes}


def variables(rows=None, remaining=0):
    rows = [row()] if rows is None else rows
    return {
        "breakout_fabric_pages": 0,
        "breakout_fabric_offset": 0,
        "breakout_fabric_total": -1,
        "breakout_fabric_page_fingerprints": [],
        "breakout_fabric_identities": [],
        "breakout_fabric_page": {"status": 200, "current": {"interfaces": rows, "meta": {"counts": {"total": len(rows) + remaining, "remaining": remaining}}}},
        "breakout_fabric_page_rows": rows,
        "item": rows[0] if rows else row(),
    }


def test_valid_native_and_intermediate_pages_have_explicit_complete_metadata():
    for values in (variables(), variables(remaining=1), variables([])):
        assert assertions(task(PAGE, "Require explicit successful"), values)
        assert assertions(task(PAGE, "Validate page structure"), values)


@pytest.mark.parametrize("field,value", [("status", 207), ("status", "200"), ("status", True), ("failed", True), ("skipped", True)])
def test_non_200_or_unexecuted_page_cannot_authorize_global_clear(field, value):
    values = variables()
    values["breakout_fabric_page"][field] = value
    assert not assertions(task(PAGE, "Require explicit successful"), values)


@pytest.mark.parametrize("name", ["total", "remaining"])
@pytest.mark.parametrize("invalid", [-1, True, "1", None])
def test_invalid_pagination_count_is_rejected(name, invalid):
    values = variables()
    values["breakout_fabric_page"]["current"]["meta"]["counts"][name] = invalid
    assert not assertions(task(PAGE, "Require explicit successful"), values)


@pytest.mark.parametrize("missing", ["meta", "counts", "total", "remaining"])
def test_missing_pagination_evidence_is_not_inferred_from_a_short_page(missing):
    values = variables()
    current = values["breakout_fabric_page"]["current"]
    if missing == "meta":
        current.pop("meta")
    elif missing == "counts":
        current["meta"].pop("counts")
    else:
        current["meta"]["counts"].pop(missing)
    assert not assertions(task(PAGE, "Require explicit successful"), values)


def test_omitted_empty_array_requires_initial_explicit_zero_counts_and_null_is_rejected():
    extract = task(PAGE, "Extract a page")["ansible.builtin.set_fact"]
    values = variables([])
    values["breakout_fabric_page"]["current"].pop("interfaces")
    assert render(extract, values)["breakout_fabric_page_rows"] == []
    values["breakout_fabric_page"]["current"]["interfaces"] = None
    # Older Ansible defaults stringify a null template result as an empty
    # string. Neither form may pass the production page-structure guard.
    values.update(render(extract, values))
    assert values["breakout_fabric_page_rows"] in (None, "")
    assert not assertions(task(PAGE, "Validate page structure"), values)
    values["breakout_fabric_page"]["current"].pop("interfaces")
    values["breakout_fabric_offset"] = 1000
    values.update(render(extract, values))
    assert values["breakout_fabric_page_rows"] in (None, "")
    assert not assertions(task(PAGE, "Validate page structure"), values)


@pytest.mark.parametrize(
    "changes",
    [
        {"breakout_fabric_total": 99},
        {"breakout_fabric_offset": 2},
        {"breakout_fabric_page_rows": []},
        {"breakout_fabric_page_rows": None},
        {"breakout_fabric_page_rows": {}},
        {"breakout_fabric_page_rows": ["not-an-object"]},
    ],
)
def test_changed_total_missing_rows_and_inconsistent_arithmetic_are_rejected(changes):
    values = variables(remaining=1)
    values.update(changes)
    assert not assertions(task(PAGE, "Validate page structure"), values)


def test_repeated_page_is_rejected_before_another_page_can_be_requested():
    values = variables(remaining=1)
    fingerprint = evaluate("breakout_fabric_page_rows | to_json", values)
    values["breakout_fabric_page_fingerprints"] = [fingerprint]
    assert not assertions(task(PAGE, "Validate page structure"), values)


@pytest.mark.parametrize("pages,allowed", [(0, True), (99, True), (100, False)])
def test_pagination_limit_is_checked_before_the_next_get(pages, allowed):
    assert assertions(task(PAGE, "Bound fabric-wide pagination"), {"breakout_fabric_pages": pages}) is allowed


@pytest.mark.parametrize(
    "candidate,allowed",
    [
        (row(), True),
        (row("Ethernet1/53/4"), True),
        (row("ethernet1/53/4"), True),
        (row("Ethernet1/53.100"), True),
        (row("Ethernet1/53/4.100"), True),
        (row(physicalInterface=False, fex=None), True),
        (row("Ethernet101/1/1/1", fex=True), True),
        (row("Ethernet1/53/0"), False),
        (row("Ethernet1/53/1/1"), False),
        (row("eth1/53"), False),
        (row("unknown-physical-name"), False),
        (row("Ethernet0/53"), False),
        (row(physicalInterface="true"), False),
        (row(fex=None), False),
        ({"interfaceName": "Ethernet1/53", "physicalInterface": True, "fex": False}, False),
    ],
)
def test_unknown_physical_names_and_classification_cannot_be_silently_ignored(candidate, allowed):
    assert assertions(task(PAGE, "Require complete switch"), {**variables(), "item": candidate}) is allowed


def test_same_page_case_insensitive_duplicate_identity_is_rejected_before_acceptance():
    values = variables([row(), row("ethernet1/53")])
    collect = task(PAGE, "Accumulate canonical composite")["ansible.builtin.set_fact"]
    for item in values["breakout_fabric_page_rows"]:
        values.update(render(collect, {**values, "item": item}))
    assert not assertions(task(PAGE, "Reject duplicate identities within"), values)
    names = [item["name"] for item in tasks(PAGE)]
    assert names.index("Reject duplicate identities within the current page before accepting or continuing it") < names.index(
        "Accept the validated page and retain exact complete-row evidence"
    )


def test_previous_page_duplicate_rejected_but_same_port_on_another_switch_remains_distinct():
    values = variables()
    values["breakout_fabric_identities"] = ["S1/ethernet1/53"]
    assert not assertions(task(PAGE, "Require complete switch"), values)
    assert assertions(task(PAGE, "Require complete switch"), {**values, "item": row(switch="S2")})


def test_global_classification_uses_physical_child_identity_not_native_ghost_fex_or_subinterface():
    values = variables()
    values["breakout_fabric_broken_keys"] = []
    classify = task(READ, "Independently classify")
    inputs = [
        row(),
        row("ethernet1/53/1"),
        row("Ethernet1/53/2"),
        row("Ethernet1/53/4", switch="S2"),
        row("Ethernet1/54/1", physicalInterface=False),
        row("Ethernet101/1/1", fex=True),
        row("Ethernet1/53/1.10"),
    ]
    for item in inputs:
        scoped = {**values, "item": item}
        if all(evaluate(expr, scoped) for expr in classify["when"]):
            values.update(render(classify["ansible.builtin.set_fact"], scoped))
    assert values["breakout_fabric_broken_keys"] == ["S1/Ethernet1/53", "S2/Ethernet1/53"]


@pytest.mark.parametrize("changed,rounds,metadata", [(True, 3, 2), (False, 1, 0)])
def test_clear_and_empty_noop_have_distinct_pagination_safe_query_budgets(changed, rounds, metadata):
    values = {"breakout_fabric_case": {"changed": changed}, "breakout_fabric_switches": ["S1", "S2"], "breakout_fabric_fixtures": [{}, {}]}
    args = render(task(CASE, "Require complete identity-based")["vars"], values)
    # The actual result assertions cast these counts with |int; older Ansible
    # defaults retain numeric expression results as strings until that cast.
    context = {**args, "expected_rounds": rounds, "expected_metadata": metadata, "expected_outcomes": 2 if changed else 0}
    assert evaluate("breakout_expected_discovery_rounds | int == expected_rounds", context) is True
    assert evaluate("breakout_expected_metadata_count | int == expected_metadata", context) is True
    assert evaluate("breakout_expected_outcome_count | int == expected_outcomes", context) is True


@pytest.mark.parametrize("explicit", [True, False])
def test_explicit_empty_and_omitted_configs_are_distinct_real_module_arguments(explicit):
    values = {"test_fabric_name": "isolated", "breakout_fabric_case": {"explicit": explicit}, "omit": "__omit__"}
    for prefix in ("Predict the complete clear", "Execute explicit-empty"):
        args = render(task(CASE, prefix)["cisco.nd.nd_manage_breakout_interfaces"], values)
        assert args == {"fabric_name": "isolated", "state": "overridden", "config": [] if explicit else "__omit__"}


@pytest.mark.parametrize(
    "action,result,allowed",
    [
        ("breakout", {"failed": False, "may_have_changed": False, "api_outcomes": [{"outcome": "success"}]}, True),
        ("breakout", {"failed": True, "may_have_changed": False, "api_outcomes": [{"outcome": "success"}]}, False),
        ("breakout", {"failed": False, "may_have_changed": True, "api_outcomes": [{"outcome": "success"}]}, False),
        ("breakout", {"failed": False, "may_have_changed": False, "api_outcomes": [{"outcome": "unknown"}]}, False),
        ("breakout", {"failed": False, "may_have_changed": False, "api_outcomes": [{"outcome": "failed"}]}, False),
        ("breakout", {"failed": False, "may_have_changed": False, "recovery": [{"status": "response_confirmed"}]}, False),
        ("breakout", {"failed": False, "may_have_changed": False}, False),
        ("breakout", {"failed": False, "may_have_changed": False, "api_outcomes": []}, False),
        ("remove", {"failed": False, "may_have_changed": False, "api_outcomes": [{"outcome": "success"}]}, False),
        ("none", {}, False),
    ],
)
def test_teardown_cannot_replay_failed_uncertain_or_previously_attempted_removal(action, result, allowed):
    values = {"breakout_fabric_last_action": action, "breakout_fabric_last_result": result, "breakout_fabric_fixtures": [{"switch_id": "S1"}]}
    assert assertions(task(CLEANUP, "Refuse inverse replay"), values) is allowed


def test_immediate_clear_precondition_rejects_unowned_or_missing_expected_families():
    check = task(CASE, "Require exactly the intentionally")
    values = {"breakout_fabric_owned_keys": ["S1/Ethernet1/53"], "breakout_fabric_case": {"changed": True}, "breakout_fabric_broken_keys": ["S1/Ethernet1/53"]}
    assert assertions(check, values)
    assert not assertions(check, {**values, "breakout_fabric_broken_keys": []})
    assert not assertions(check, {**values, "breakout_fabric_broken_keys": ["S1/Ethernet1/53", "S2/Ethernet1/53"]})
    assert assertions(check, {**values, "breakout_fabric_case": {"changed": False}, "breakout_fabric_broken_keys": []})


def test_observer_scope_excludes_only_explicit_same_switch_owned_parents():
    fixtures = [
        {"switch_id": switch, "native_interfaces": [parent]} for switch, parent in [("S1", "Ethernet1/53"), ("S1", "Ethernet1/54"), ("S2", "Ethernet1/53")]
    ]
    values = {
        "test_fabric_name": "isolated",
        "breakout_fabric_fixtures": fixtures,
        "breakout_fabric_index": 0,
        "breakout_fabric_profiles": ["native"] * 3,
        "breakout_fabric_baselines": {},
        "omit": "__omit__",
        "test_breakout_observe_retries": 1,
        "test_breakout_observe_interval": 0,
    }
    args = render(tasks("tasks/fabric_clear_observe_one.yaml")[0]["cisco.nd.nd_manage_breakout_interfaces_validate"], values)
    assert args["whole_switch"] is True
    assert args["include_speeds"] is True
    assert args["owned_interfaces"] == ["Ethernet1/53", "Ethernet1/54"]
    assert args["baseline"] == "__omit__"


def test_teardown_uses_scoped_deleted_with_verification_disabled_never_global_overridden():
    remove = task(CLEANUP, "Remove only freshly observed")["cisco.nd.nd_manage_breakout_interfaces"]
    assert remove["state"] == "deleted"
    assert remove["verify"] == {"enabled": False}
    assert all(item.get("cisco.nd.nd_manage_breakout_interfaces", {}).get("state") != "overridden" for item in tasks(CLEANUP))


def clear_predictions():
    values = {
        "test_switch_serial": "S1",
        "breakout_fabric_broken_keys": ["S2/Ethernet1/53", "S1/Ethernet1/54", "S1/Ethernet1/53"],
    }
    return render(task(CHECK_MODE, "CHECK MODE - Define selected-switch")["ansible.builtin.set_fact"], values)["breakout_clear_predictions"]


def test_readonly_clear_definitions_distinguish_selected_switch_explicit_empty_and_omitted_config():
    cases = clear_predictions()
    assert len(cases) == 3
    assert cases[0]["config"] == [{"switch_id": "S1", "interface_names": []}]
    assert cases[1]["config"] == []
    assert "config" not in cases[2]
    assert cases[0]["expected_keys"] == ["S1/Ethernet1/53", "S1/Ethernet1/54"]
    assert cases[1]["expected_keys"] == cases[2]["expected_keys"] == ["S1/Ethernet1/53", "S1/Ethernet1/54", "S2/Ethernet1/53"]


@pytest.mark.parametrize("index", [0, 1, 2])
def test_each_clear_prediction_is_forced_check_mode_without_destructive_optin(index):
    predict = task(CHECK_MODE, "CHECK MODE - Predict authoritative")
    values = {"test_fabric_name": "shared", "clear_prediction": clear_predictions()[index], "omit": "__omit__"}
    args = render(predict["cisco.nd.nd_manage_breakout_interfaces"], values)
    assert predict["check_mode"] is True
    assert args["state"] == "overridden"
    assert args["config"] == ([{"switch_id": "S1", "interface_names": []}] if index == 0 else [] if index == 1 else "__omit__")
    assert "test_breakout_allow_fabric_clear" not in str(predict)


def prediction_result(keys):
    return {
        "clear_prediction": {"name": "test clear prediction", "expected_keys": keys},
        "failed": False,
        "changed": bool(keys),
        "after_status": "predicted",
        "api_outcomes": [
            {"switch_id": key.split("/", 1)[0], "interface_name": key.split("/", 1)[1], "outcome": "planned", "action": "unbreakout"} for key in reversed(keys)
        ],
        "after": [{"broken_out": False, "children": []} for _unused_index in keys],
        "recovery": [],
        "api_calls": [{"method": "GET", "path": "/interfacesSummary"}],
    }


@pytest.mark.parametrize("keys", [[], ["S1/Ethernet1/53"], ["S1/Ethernet1/53", "S2/Ethernet1/53"]])
def test_clear_predictions_match_complete_composite_identities_without_order_assumptions(keys):
    check = task(CHECK_MODE, "CHECK MODE - Match exact planned")
    assert assertions(check, {"clear_result": prediction_result(keys)})


@pytest.mark.parametrize(
    "changes",
    [
        {"failed": True},
        {"changed": False},
        {"after_status": "response_confirmed"},
        {"after": [{"broken_out": True}]},
        {"verification": {}},
        {"recovery": [{"status": "response_confirmed"}]},
        {"api_calls": [{"method": "POST", "path": "/interfaceActions/remove"}]},
        {"api_outcomes": [{"switch_id": "S2", "interface_name": "Ethernet1/53", "outcome": "planned", "action": "unbreakout"}]},
        {"api_outcomes": [{"switch_id": "S1", "interface_name": "Ethernet1/53", "outcome": "unknown", "action": "unbreakout"}]},
        {"api_outcomes": [{"switch_id": "S1", "interface_name": "Ethernet1/53", "outcome": "planned", "action": "breakout"}]},
        {"api_outcomes": []},
    ],
)
def test_clear_prediction_assertions_reject_mutation_success_claims_wrong_scope_or_recovery(changes):
    result = prediction_result(["S1/Ethernet1/53"])
    result.update(changes)
    assert not assertions(task(CHECK_MODE, "CHECK MODE - Match exact planned"), {"clear_result": result})


def project_physical_rows(rows, before=True):
    prefix = "CHECK MODE - Capture every physical" if before else "CHECK MODE - Project every current physical"
    key = "breakout_check_mode_fabric_baseline" if before else "breakout_check_mode_fabric_after"
    project = task(CHECK_MODE, prefix)
    values = {key: {}}
    for item in rows:
        scoped = {**values, "item": item}
        if all(evaluate(expr, scoped) for expr in project["when"]):
            values.update(render(project["ansible.builtin.set_fact"], scoped))
    return values[key]


def test_global_before_after_projection_preserves_stable_identity_speed_without_requiring_missing_speed():
    rows = [
        row("Ethernet1/53/1", speed="25Gb", status="up"),
        row("Ethernet1/53/1", switch="S2", speed="50Gb", status="down"),
        row("Ethernet1/54"),  # Native rows can legitimately omit speed metadata.
        row("Ethernet1/55", physicalInterface=False, fex=None),
        row("Ethernet101/1/1", fex=True),
    ]
    baseline = project_physical_rows(rows)
    changed_status = [dict(item, status="not-a-stable-comparison-field") for item in reversed(rows)]
    assert project_physical_rows(changed_status, before=False) == baseline
    assert baseline == {"S1/ethernet1/53/1": {"speed": "25Gb"}, "S2/ethernet1/53/1": {"speed": "50Gb"}, "S1/ethernet1/54": {"speed": None}}


@pytest.mark.parametrize("change", ["lane", "speed", "switch", "new", "missing"])
def test_checkmode_whole_fabric_comparison_detects_changes_hidden_by_identical_parent_family_sets(change):
    rows = [row("Ethernet1/53/1", speed="25Gb"), row("Ethernet1/53/1", switch="S2", speed="25Gb")]
    baseline = project_physical_rows(rows)
    if change == "lane":
        rows[1]["interfaceName"] = "Ethernet1/53/2"
    elif change == "speed":
        rows[1]["speed"] = "50Gb"
    elif change == "switch":
        rows[1]["switchId"] = "S3"
    elif change == "new":
        rows.append(row("Ethernet1/53/3", switch="S2", speed="25Gb"))
    else:
        rows.pop()
    values = {
        "breakout_fabric_broken_keys": ["S1/Ethernet1/53", "S2/Ethernet1/53"],
        "breakout_clear_predictions": clear_predictions(),
        "breakout_check_mode_fabric_baseline": baseline,
        "breakout_check_mode_fabric_after": project_physical_rows(rows, before=False),
    }
    values["breakout_clear_predictions"][1]["expected_keys"] = values["breakout_fabric_broken_keys"]
    assert not assertions(task(CHECK_MODE, "CHECK MODE - Prove no fabric-wide family"), values)


def test_every_module_call_in_standalone_checkmode_suite_is_forced_readonly():
    calls = [item for item in tasks(CHECK_MODE) if "cisco.nd.nd_manage_breakout_interfaces" in item]
    assert calls
    assert all(item["check_mode"] is True for item in calls)
