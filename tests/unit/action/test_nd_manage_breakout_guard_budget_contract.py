# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Execute the real integration-result assertions against adversarial traces.

Only Ansible templating, local facts, loops and assertions are evaluated here.
No module or controller is invoked, and these checks do not simulate a passing
live breakout. In particular, they protect the exact default GET budget while
allowing explicitly opted-in, scoped original-action guard observations.
"""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from urllib.parse import urlencode

import pytest
import yaml
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

TARGET = Path(__file__).resolve().parents[2] / "integration" / "targets" / "nd_manage_breakout_interfaces"
BASE = "/api/v1/manage/fabrics/fab1"
SERIAL = "FDO28481BXX"
OTHER = "FDO28481BYY"


def render(value, variables):
    if isinstance(value, dict):
        return {key: render(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, variables) for item in value]
    if isinstance(value, str):
        return Templar(loader=DataLoader(), variables=variables).template(trust_as_template(value))
    return value


def condition(expression, variables):
    return Templar(loader=DataLoader(), variables=variables)._engine.evaluate_conditional(trust_as_template(expression))


def trusted_source_variables(value):
    """Preserve Ansible YAML trust for task vars referencing sibling task vars."""
    if isinstance(value, dict):
        return {key: trusted_source_variables(item) for key, item in value.items()}
    if isinstance(value, list):
        return [trusted_source_variables(item) for item in value]
    return trust_as_template(value) if isinstance(value, str) else value


def execute_tasks(tasks, variables):
    """Run assertion-only YAML using Ansible's actual conditional semantics."""
    for task in tasks:
        loop = task.get("loop")
        items = render(loop, variables) if loop is not None else [None]
        for index, item in enumerate(items):
            local = dict(variables)
            if loop is not None:
                controls = task.get("loop_control", {})
                local[controls.get("loop_var", "item")] = item
                if controls.get("index_var"):
                    local[controls["index_var"]] = index
            declared = trusted_source_variables(task.get("vars", {}))
            local.update(declared)
            local.update(render(declared, local))
            checks = task.get("when", [])
            checks = checks if isinstance(checks, list) else [checks]
            if not all(condition(check, local) if isinstance(check, str) else bool(check) for check in checks):
                continue
            if "block" in task:
                execute_tasks(task["block"], local)
                # Facts from a nested block remain available to later tasks.
                variables.update({key: value for key, value in local.items() if key not in declared})
            elif "ansible.builtin.set_fact" in task:
                variables.update(render(task["ansible.builtin.set_fact"], local))
            elif "ansible.builtin.assert" in task:
                expressions = task["ansible.builtin.assert"]["that"]
                expressions = expressions if isinstance(expressions, list) else [expressions]
                for expression in expressions:
                    assert condition(expression, local), task["name"] + ": " + expression
            else:
                raise AssertionError("Unexpected nonlocal operation in result assertions: " + task["name"])


def accepted(variables):
    try:
        tasks = yaml.safe_load((TARGET / "tasks" / "assert_result.yaml").read_text())
        execute_tasks(tasks, deepcopy(variables))
    except Exception as error:
        return False, str(error)
    return True, ""


def require_accepted(variables):
    allowed, reason = accepted(variables)
    assert allowed, reason


def summary(switch=SERIAL, **overrides):
    scoped_switch = overrides.get("switchId", switch)
    query = {
        "offset": 0,
        "max": 1000,
        "filter": "interfaceType:ethernet" if scoped_switch is None else "interfaceType:ethernet AND switchId:" + scoped_switch,
        "includeAll": "true",
    }
    if scoped_switch is not None:
        query["switchId"] = scoped_switch
    for key, value in overrides.items():
        if value is None:
            query.pop(key, None)
        else:
            query[key] = value
    return {"method": "GET", "path": BASE + "/interfacesSummary?" + urlencode(query), "http_status": 200}


def variables(extra=0, *, opt_in=False):
    calls = [
        {"method": "GET", "path": BASE + "/switches/" + SERIAL, "purpose": "switch_metadata", "http_status": 200},
        summary(),
        {"method": "POST", "path": BASE + "/interfaceActions/breakout", "http_status": 207},
        summary(),
        *[summary() for _ in range(extra)],
    ]
    result = {
        "failed": False,
        "changed": True,
        "output_level": "normal",
        "before": [],
        "after": [],
        "diff": [{"switch_id": SERIAL, "interface_names": ["Ethernet1/53"]}],
        "proposed": [{"switch_id": SERIAL, "interface_names": ["Ethernet1/53"], "breakout_map": "25g-4x"}],
        "after_status": "observed",
        "may_have_changed": False,
        "api_outcomes": [{"switch_id": SERIAL, "interface_name": "Ethernet1/53", "action": "breakout", "outcome": "success"}],
        "recovery": [],
        "verification": {
            "enabled": True,
            "complete": True,
            "phases": [{"switch_id": SERIAL, "phase": "breakout", "topology_matches": True, "collateral": []}],
        },
        "api_calls": calls,
        "api_payload": [
            None,
            None,
            {"interfaces": [{"switchId": SERIAL, "interfaceName": "Ethernet1/53", "breakoutMap": "25g-4x"}]},
            *[None for _ in range(extra + 1)],
        ],
    }
    values = {
        "ansible_verbosity": 3,
        "test_fabric_name": "fab1",
        "test_switch_serial": SERIAL,
        "breakout_result": result,
        "breakout_expected_changed": True,
        "breakout_expected_outcome": "success",
        "breakout_expected_write_actions": ["breakout"],
        "breakout_expected_discovery_rounds": 2,
        "breakout_expected_metadata_count": 1,
    }
    if opt_in:
        values["breakout_allow_guard_settling"] = True
    return values


def test_default_budget_still_accepts_exact_existing_trace():
    require_accepted(variables())


def test_default_budget_rejects_an_extra_complete_summary_round():
    assert not accepted(variables(extra=1))[0]


@pytest.mark.parametrize("extra", range(6))
def test_explicit_guard_opt_in_allows_only_bounded_additional_original_action_rounds(extra):
    require_accepted(variables(extra=extra, opt_in=True))


def test_guard_opt_in_rejects_six_additional_rounds_on_one_switch():
    assert not accepted(variables(extra=6, opt_in=True))[0]


@pytest.mark.parametrize(
    "query",
    [
        {"filter": "interfaceName:*Ethernet1/53*"},
        {"filter": None},
        {"includeAll": "false"},
        {"includeAll": None},
        {"switchId": OTHER},
        {"switchId": None},
        {"offset": "-1"},
        {"offset": "invalid"},
        {"offset": None},
    ],
    ids=[
        "targeted_filter",
        "missing_filter",
        "not_include_all",
        "missing_include_all",
        "other_switch",
        "missing_switch",
        "negative_offset",
        "bad_offset",
        "missing_offset",
    ],
)
def test_opt_in_rejects_malformed_or_out_of_scope_extra_round(query):
    values = variables(extra=1, opt_in=True)
    values["breakout_result"]["api_calls"][-1] = summary(**query)
    assert not accepted(values)[0]


@pytest.mark.parametrize("suffix", ["&switchId=" + SERIAL, "&filter=interfaceType%3Aethernet", "&includeAll=true", "&offset=0"])
def test_opt_in_rejects_duplicate_scope_or_pagination_parameters(suffix):
    values = variables(extra=1, opt_in=True)
    values["breakout_result"]["api_calls"][-1]["path"] += suffix
    assert not accepted(values)[0]


def test_valid_same_switch_pagination_does_not_consume_an_additional_observation_round():
    values = variables(extra=5, opt_in=True)
    values["breakout_result"]["api_calls"].append(summary(offset=1000))
    require_accepted(values)


def test_scope_validation_does_not_depend_on_query_parameter_order():
    values = variables(extra=1, opt_in=True)
    query = {"includeAll": "true", "switchId": SERIAL, "filter": "interfaceType:ethernet AND switchId:" + SERIAL, "max": 1000, "offset": 0}
    values["breakout_result"]["api_calls"][-1]["path"] = BASE + "/interfacesSummary?" + urlencode(query)
    require_accepted(values)


@pytest.mark.parametrize(
    "wire_filter",
    [
        "interfaceType:ethernet AND switchId:" + OTHER,
        "interfaceType:ethernet OR switchId:" + SERIAL,
        "interfaceType:ethernet AND switchId:" + SERIAL + " OR switchId:" + OTHER,
        'interfaceType:ethernet AND switchId:"' + SERIAL + '"',
    ],
    ids=["mismatched_serial", "broadened_or", "extra_or_peer", "unsupported_quoted_serial"],
)
def test_new_explicit_filter_cannot_broaden_or_disagree_with_the_query_switch(wire_filter):
    values = variables(extra=1, opt_in=True)
    values["breakout_result"]["api_calls"][-1] = summary(filter=wire_filter)
    assert not accepted(values)[0]


def test_opt_in_never_allows_an_extra_pre_mutation_snapshot():
    values = variables(opt_in=True)
    values["breakout_result"]["api_calls"].insert(2, summary())
    assert not accepted(values)[0]


def test_opt_in_does_not_expand_the_switch_metadata_budget():
    values = variables(opt_in=True)
    values["breakout_result"]["api_calls"].append({"method": "GET", "path": BASE + "/switches/" + SERIAL, "purpose": "switch_metadata", "http_status": 200})
    assert not accepted(values)[0]


@pytest.mark.parametrize("scenario", ["noop", "check_mode", "verify_disabled"])
def test_opt_in_cannot_authorize_extra_guard_rounds_without_a_successful_verified_mutation(scenario):
    values = variables(extra=1, opt_in=True)
    result = values["breakout_result"]
    result.pop("verification")
    values["breakout_expected_discovery_rounds"] = 1
    if scenario == "verify_disabled":
        result["after_status"] = "response_confirmed"
        result["api_calls"].pop(3)
    else:
        result["api_calls"] = [result["api_calls"][0], summary(), summary()]
        values["breakout_expected_write_actions"] = []
        result["api_outcomes"][0]["outcome"] = "noop" if scenario == "noop" else "planned"
        values["breakout_expected_outcome"] = result["api_outcomes"][0]["outcome"]
        result["changed"] = scenario != "noop"
        values["breakout_expected_changed"] = result["changed"]
        result["after_status"] = "unchanged" if scenario == "noop" else "predicted"
        if scenario == "noop":
            result["diff"] = []
    assert not accepted(values)[0]


def test_a_configured_noop_switch_cannot_be_used_for_additional_guard_rounds():
    values = variables(opt_in=True)
    result = values["breakout_result"]
    values.update(
        breakout_expected_outcome_count=2,
        breakout_expected_outcomes=["noop", "success"],
        breakout_expected_discovery_rounds=3,
        breakout_expected_metadata_count=2,
    )
    result["api_outcomes"].append({"switch_id": OTHER, "interface_name": "Ethernet1/53", "action": "breakout", "outcome": "noop"})
    result["proposed"].append({"switch_id": OTHER, "interface_names": ["Ethernet1/53"], "breakout_map": "25g-4x"})
    result["api_calls"].insert(1, {"method": "GET", "path": BASE + "/switches/" + OTHER, "purpose": "switch_metadata", "http_status": 200})
    result["api_calls"].insert(3, summary(switch=OTHER))
    result["api_calls"].append(summary(switch=OTHER))
    assert not accepted(values)[0]


def test_two_mutated_switches_can_each_have_their_own_bounded_guard_rounds():
    values = variables(extra=5, opt_in=True)
    result = values["breakout_result"]
    values.update(breakout_expected_outcome_count=2, breakout_expected_discovery_rounds=4, breakout_expected_metadata_count=2)
    result["api_outcomes"].append({"switch_id": OTHER, "interface_name": "Ethernet1/53", "action": "breakout", "outcome": "success"})
    result["verification"]["phases"].append({"switch_id": OTHER, "phase": "breakout", "topology_matches": True, "collateral": []})
    result["proposed"].append({"switch_id": OTHER, "interface_names": ["Ethernet1/53"], "breakout_map": "25g-4x"})
    result["api_calls"].insert(1, {"method": "GET", "path": BASE + "/switches/" + OTHER, "purpose": "switch_metadata", "http_status": 200})
    result["api_calls"].insert(3, summary(switch=OTHER))
    result["api_calls"].extend(summary(switch=OTHER) for _ in range(6))
    result["api_payload"] = [
        (
            None
            if call["method"] == "GET"
            else {"interfaces": [{"switchId": serial, "interfaceName": "Ethernet1/53", "breakoutMap": "25g-4x"} for serial in (SERIAL, OTHER)]}
        )
        for call in result["api_calls"]
    ]
    require_accepted(values)
    result["api_calls"].append(summary(switch=OTHER))
    assert not accepted(values)[0]


def fabric_clear_variables():
    values = variables(opt_in=True)
    result = values["breakout_result"]
    values.update(
        breakout_expected_outcome_count=3,
        breakout_expected_discovery_rounds=3,
        breakout_expected_metadata_count=2,
        breakout_expected_write_actions=["remove"],
    )
    targets = [(SERIAL, "Ethernet1/53"), (SERIAL, "Ethernet1/54"), (OTHER, "Ethernet1/30")]
    result["api_outcomes"] = [{"switch_id": serial, "interface_name": parent, "action": "unbreakout", "outcome": "success"} for serial, parent in targets]
    result["verification"]["phases"] = [{"switch_id": serial, "phase": "unbreakout", "topology_matches": True, "collateral": []} for serial in (SERIAL, OTHER)]
    result["api_calls"] = [
        summary(switchId=None),
        {"method": "GET", "path": BASE + "/switches/" + SERIAL, "purpose": "switch_metadata", "http_status": 200},
        {"method": "GET", "path": BASE + "/switches/" + OTHER, "purpose": "switch_metadata", "http_status": 200},
        {"method": "POST", "path": BASE + "/interfaceActions/remove", "http_status": 207},
        summary(),
        summary(switch=OTHER),
        summary(switch=OTHER),
    ]
    result["api_payload"] = [
        None if call["method"] == "GET" else {"interfaces": [{"switchId": serial, "interfaceName": parent + "/1"} for serial, parent in targets]}
        for call in result["api_calls"]
    ]
    return values


def test_global_fabric_baseline_and_two_switch_guard_reports_allow_retry_only_on_second_switch():
    require_accepted(fabric_clear_variables())


def test_one_switch_cannot_exceed_its_round_cap_even_with_unused_other_switch_allowance():
    values = fabric_clear_variables()
    # Nine total summary starts are below 3 + 5*2, but the second switch has
    # seven post-action starts. The aggregate cap alone must not authorize it.
    values["breakout_result"]["api_calls"].extend(summary(switch=OTHER) for _ in range(5))
    assert not accepted(values)[0]


@pytest.mark.parametrize("malformation", ["duplicate_switch", "missing_switch", "wrong_switch", "mixed_action_phase"])
def test_successful_bulk_guard_requires_exactly_one_report_per_mutated_switch(malformation):
    values = fabric_clear_variables()
    phases = values["breakout_result"]["verification"]["phases"]
    if malformation == "duplicate_switch":
        phases.append(deepcopy(phases[0]))
    elif malformation == "missing_switch":
        phases.pop()
    elif malformation == "wrong_switch":
        phases[-1]["switch_id"] = "ANOTHER-SWITCH"
    else:
        phases[-1]["phase"] = "breakout"
    assert not accepted(values)[0]


@pytest.mark.parametrize("status", [500, None, "200"])
def test_a_failed_or_malformed_extra_guard_receipt_is_not_a_budget_exception(status):
    values = variables(extra=1, opt_in=True)
    values["breakout_result"]["api_calls"][-1]["http_status"] = status
    assert not accepted(values)[0]


@pytest.mark.parametrize("path", [BASE + "/switches", BASE + "/switches/" + SERIAL + "/interfaces", BASE + "/interfacesSummary"])
def test_opt_in_does_not_authorize_unrelated_or_malformed_extra_gets(path):
    values = variables(extra=1, opt_in=True)
    values["breakout_result"]["api_calls"][-1]["path"] = path
    assert not accepted(values)[0]


def task_nodes(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from task_nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from task_nodes(child)


def test_lifecycle_opt_ins_are_limited_to_two_successful_guarded_creation_assertions():
    tasks = yaml.safe_load((TARGET / "tests" / "lifecycle.yaml").read_text())
    opted = [task for task in task_nodes(tasks) if "breakout_allow_guard_settling" in task.get("vars", {})]
    assert len(opted) == 2
    for task in opted:
        values = task["vars"]
        assert values["breakout_allow_guard_settling"] is True
        assert values["breakout_expected_changed"] is True
        assert values["breakout_expected_outcome"] == "success"
        assert values["breakout_expected_write_actions"] == ["breakout"]
        assert values["breakout_expected_after_status"] == "observed"
        assert values["breakout_expected_discovery_rounds"] == 2


@pytest.mark.parametrize("changed", [False, True])
def test_fabric_clear_does_not_opt_in_its_unchanged_idempotent_repeat(changed):
    tasks = yaml.safe_load((TARGET / "tasks" / "fabric_clear_case.yaml").read_text())
    opted = [task for task in tasks if "breakout_allow_guard_settling" in task.get("vars", {})]
    assert len(opted) == 1
    assert render(opted[0]["vars"]["breakout_allow_guard_settling"], {"breakout_fabric_case": {"changed": changed}}) is changed


def test_the_opt_in_is_not_enabled_globally_in_role_defaults():
    defaults = yaml.safe_load((TARGET / "defaults" / "main.yaml").read_text())
    assert not defaults.get("breakout_allow_guard_settling", False)
