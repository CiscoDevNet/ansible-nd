# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Offline contracts for the target's independent inventory expressions.

These tests render YAML expressions only; they execute no integration tasks.
"""

from pathlib import Path
from copy import deepcopy

import pytest
import yaml
from ansible.errors import AnsibleError
from ansible.parsing.dataloader import DataLoader
from ansible import template as ansible_template


TARGET = Path(__file__).resolve().parents[2] / "integration" / "targets" / "nd_manage_smart_switches_onboarding"


def task_named(file_name, name):
    tasks = yaml.safe_load((TARGET / "tasks" / "helpers" / file_name).read_text())
    return next(task for task in tasks if task["name"] == name)


def render(expression, variables):
    # Newer ansible-core requires an explicit trust marker for test-loaded text.
    trust = getattr(ansible_template, "trust_as_template", lambda value: value)
    return ansible_template.Templar(loader=DataLoader(), variables=variables).template(trust(expression))


def assert_conditions(task, variables):
    context = {**variables, **task.get("vars", {})}
    for expression in task["ansible.builtin.assert"]["that"]:
        assert render("{{ " + expression + " }}", context) is True, expression


def inventory_row(identifier="a", *, integration="", alias="additionalData"):
    return {
        "switchId": identifier,
        "hostname": f"leaf-{identifier}",
        "fabricName": "fabric",
        alias: {"smartSwitch": True, "hypershieldIntegrationName": integration},
    }


def test_inventory_does_not_include_a_fact_rebuilding_task_for_each_row():
    path = TARGET / "tasks" / "helpers" / "inventory_page.yaml"
    tasks = yaml.safe_load(path.read_text())
    assert not any("loop" in task and "ansible.builtin.include_tasks" in task for task in tasks)
    assert all("loop" not in task for task in tasks if "ansible.builtin.set_fact" in task)


@pytest.mark.parametrize(
    "rows", [[], [inventory_row()], [inventory_row("A", integration="h"), inventory_row("a", alias="additionalSwitchData"), {"switchId": "other"}]]
)
def test_actual_inventory_projection_preserves_exact_identity_and_aliases(rows):
    original = deepcopy(rows)
    validate = task_named("inventory_page.yaml", "Validate every row before retaining this page")
    for row in rows:
        assert_conditions(validate, {"ss_row": row, "ss_seen_ids": {}, "nd_test_smart_switches_fabric_name": "fabric"})
    project = task_named("inventory.yaml", "Build the exact inventory index once per complete snapshot")
    index = render(project["ansible.builtin.set_fact"]["ss_inventory"], {"ss_inventory_rows": rows})
    assert isinstance(index, dict)
    assert list(index) == [row["switchId"] for row in rows]
    assert rows == original
    associations = task_named("inventory.yaml", "Project all onboarded associations from the completed independent index")
    onboarded = render(associations["ansible.builtin.set_fact"]["ss_associations"], {"ss_inventory": index})
    assert [row["switch_id"] for row in onboarded] == (["A"] if "A" in index else [])
    if "A" in index:
        assert index["a"]["integration_name"] == ""
        assert index["A"] == {"switch_id": "A", "switch_name": "leaf-A", "smart": True, "integration_name": "h"}
        assert index["other"]["smart"] is False


@pytest.mark.parametrize(
    "row",
    [
        None,
        {},
        {"switchId": 12},
        {"switchId": ""},
        {**inventory_row(), "fabricName": "other"},
        {**inventory_row(), "additionalData": None},
        {**inventory_row(), "additionalSwitchData": {"smartSwitch": False}},
        {"switchId": "a", "additionalData": {"smartSwitch": "true", "hypershieldIntegrationName": ""}},
        {"switchId": "a", "additionalData": {"smartSwitch": True}},
        {"switchId": "a", "additionalData": {"smartSwitch": True, "hypershieldIntegrationName": None}},
        {"switchId": "a", "additionalData": {"smartSwitch": False, "hypershieldIntegrationName": "h"}},
    ],
)
def test_actual_row_guards_reject_ambiguous_evidence(row):
    task = task_named("inventory_page.yaml", "Validate every row before retaining this page")
    with pytest.raises((AssertionError, AnsibleError)):
        assert_conditions(task, {"ss_row": row, "ss_seen_ids": {}, "nd_test_smart_switches_fabric_name": "fabric"})


def test_duplicate_guards_cover_same_page_and_previous_pages_without_case_folding():
    task = task_named("inventory_page.yaml", "Reject duplicate identifiers within this page")
    assert_conditions(task, {"ss_page": {"jsondata": {"switches": [inventory_row("A"), inventory_row("a")]}}})
    with pytest.raises(AssertionError):
        assert_conditions(task, {"ss_page": {"jsondata": {"switches": [inventory_row(), inventory_row()]}}})
    task = task_named("inventory_page.yaml", "Validate every row before retaining this page")
    with pytest.raises(AssertionError):
        assert_conditions(task, {"ss_row": inventory_row(), "ss_seen_ids": {"a": "a"}, "nd_test_smart_switches_fabric_name": "fabric"})


@pytest.mark.parametrize("total,remaining,offset,previous,row_count", [(2, 1, 1, -1, 1), (2, 0, 2, 2, 1), (0, 0, 0, -1, 0)])
def test_actual_page_counts_accept_complete_and_continuing_pages(total, remaining, offset, previous, row_count):
    task = task_named("inventory_page.yaml", "Validate supplied inventory counts")
    assert_conditions(
        task,
        {
            "ss_page": {"jsondata": {"meta": {"counts": {"total": total, "remaining": remaining}}, "switches": [{}] * row_count}},
            "ss_offset": offset,
            "ss_total": previous,
        },
    )


@pytest.mark.parametrize(
    "counts,offset,previous,rows",
    [
        ({"total": True, "remaining": 0}, 1, -1, 1),
        ({"total": 2, "remaining": -1}, 1, -1, 1),
        ({"total": 2, "remaining": 0}, 1, -1, 1),
        ({"total": 3, "remaining": 2}, 1, 2, 1),
        ({"total": 2, "remaining": 1}, 1, -1, 0),
        (None, 0, -1, 0),
    ],
)
def test_actual_page_count_guards_reject_incomplete_or_unstable_reads(counts, offset, previous, rows):
    task = task_named("inventory_page.yaml", "Validate supplied inventory counts")
    with pytest.raises((AssertionError, AnsibleError)):
        assert_conditions(task, {"ss_page": {"jsondata": {"meta": {"counts": counts}, "switches": [{}] * rows}}, "ss_offset": offset, "ss_total": previous})


def test_count_free_termination_and_bound_do_not_claim_an_incomplete_snapshot():
    terminal = task_named("inventory_page.yaml", "Terminate count-free pagination only on an empty page")
    for rows, expected in [([], True), ([inventory_row()], False)]:
        variables = {"ss_page": {"jsondata": {"switches": rows}}}
        assert all(render("{{ " + condition + " }}", variables) for condition in terminal["when"]) is expected
    guard = task_named("inventory_page.yaml", "Reject premature count-free termination after a counted page")
    with pytest.raises(AssertionError):
        assert_conditions(guard, {"ss_total": 2, "ss_offset": 1})
    with pytest.raises(AssertionError):
        assert_conditions(task_named("inventory.yaml", "Require safe pagination termination"), {"ss_inventory_done": False})
    recurse = task_named("inventory_page.yaml", "Read another page only while incomplete and within bounds")
    context = {"ss_inventory_done": False, "ss_inventory_page_number": 100, "nd_test_smart_switches_max_pages": 100}
    assert not all(render("{{ " + condition + " }}", context) for condition in recurse["when"])


def test_page_accumulation_retains_all_rows_and_exact_seen_keys():
    retain = task_named("inventory_page.yaml", "Retain validated rows and identifier membership once per page")
    row_guard = task_named("inventory_page.yaml", "Validate every row before retaining this page")
    state = {"ss_inventory_rows": [], "ss_seen_ids": {}, "nd_test_smart_switches_fabric_name": "fabric"}
    pages = [[inventory_row("A", integration="h")], [inventory_row("a", alias="additionalSwitchData")], []]
    for rows in pages:
        for row in rows:
            assert_conditions(row_guard, {**state, "ss_row": row})
        variables = {**state, **retain["vars"], "ss_page": {"jsondata": {"switches": rows}}}
        state.update({name: render(expression, variables) for name, expression in retain["ansible.builtin.set_fact"].items()})
    assert state["ss_inventory_rows"] == pages[0] + pages[1]
    assert state["ss_seen_ids"] == {"A": "A", "a": "a"}


@pytest.mark.parametrize("status,switches,meta", [(500, [], {}), (200, {}, {}), (200, "invalid", {}), (200, [], None)])
def test_inventory_wrapper_requires_a_successful_unambiguous_collection(status, switches, meta):
    task = task_named("inventory_page.yaml", "Validate inventory response wrapper and metadata")
    with pytest.raises((AssertionError, AnsibleError)):
        assert_conditions(task, {"ss_page": {"status": status, "jsondata": {"switches": switches, "meta": meta}}})
