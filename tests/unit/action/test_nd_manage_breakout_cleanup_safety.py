# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Offline checks of the playbook's no-replay recovery barrier.

These execute the actual YAML fact expressions with synthetic module evidence;
they never invoke a module or controller. The separate real-Ansible smoke test
also checks that a blocked recovery fails before the remove task is reached.
"""

from pathlib import Path

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment

TARGET = Path(__file__).resolve().parents[2] / "integration" / "targets" / "nd_manage_breakout_interfaces"
CLEANUP = yaml.safe_load((TARGET / "tasks" / "cleanup.yaml").read_text())
LIFECYCLE = yaml.safe_load((TARGET / "tests" / "lifecycle.yaml").read_text())


def _fact_environment():
    environment = NativeEnvironment(undefined=StrictUndefined)
    environment.filters["bool"] = bool
    return environment


def _blocked(result, pending="", already_blocked=False):
    """Evaluate the actual cleanup decision, not a reimplementation of its rule."""
    variables = {
        "breakout_result": result,
        "breakout_pending_removal": pending,
        "breakout_cleanup_removal_blocked": already_blocked,
    }
    environment = _fact_environment()
    for task in CLEANUP[:2]:
        for key, expression in task["ansible.builtin.set_fact"].items():
            variables[key] = environment.from_string(expression).render(**variables)
    return variables["breakout_cleanup_removal_blocked"], variables["breakout_cleanup_original_removals"]


@pytest.mark.parametrize("status", ["failed", "unknown"])
def test_original_failed_or_uncertain_deleted_request_blocks_cleanup_remove(status):
    blocked, rows = _blocked({"failed": True, "api_outcomes": [{"action": "unbreakout", "outcome": status}]}, pending="deleted")
    assert blocked is True and rows[0]["outcome"] == status


@pytest.mark.parametrize("result", [{}, {"failed": True}, {"failed": True, "api_outcomes": []}, {"failed": True, "api_outcomes": None}])
def test_lost_module_result_cannot_release_a_pending_removal_barrier(result):
    blocked, rows = _blocked(result, pending="deleted")
    assert blocked is True and rows == []


def test_uncertain_remove_is_blocked_even_when_a_later_assertion_has_no_pending_marker():
    blocked, _ = _blocked({"api_outcomes": [{"action": "unbreakout", "outcome": "unknown"}]})
    assert blocked is True


@pytest.mark.parametrize("pending", ["", "deleted"])
def test_confirmed_original_remove_prevents_replay_without_relabeling_its_success(pending):
    result = {"api_outcomes": [{"action": "unbreakout", "outcome": "success"}]}
    blocked, rows = _blocked(result, pending=pending)
    assert blocked is True
    assert rows[0]["outcome"] == "success"
    assert result["api_outcomes"][0]["outcome"] == "success"


@pytest.mark.parametrize("status", ["noop", "planned", "not_executed"])
def test_unexecuted_original_remove_does_not_block_normal_owned_cleanup(status):
    blocked, _ = _blocked({"api_outcomes": [{"action": "unbreakout", "outcome": status}]})
    assert blocked is False


def test_actual_delete_noop_releases_pending_marker_without_claiming_a_mutation():
    blocked, _ = _blocked({"api_outcomes": [{"action": "unbreakout", "outcome": "noop"}]}, pending="deleted")
    assert blocked is False


@pytest.mark.parametrize("status", ["failed", "unknown", None])
def test_failed_or_missing_removal_evidence_blocks_replay(status):
    row = {"action": "unbreakout"}
    if status is not None:
        row["outcome"] = status
    blocked, _ = _blocked({"api_outcomes": [row]})
    assert blocked is True


def test_created_owned_breakout_can_be_cleaned_if_no_remove_has_been_attempted():
    blocked, rows = _blocked({"api_outcomes": [{"action": "breakout", "outcome": "success"}]})
    assert blocked is False and rows == []


def test_failed_breakout_does_not_itself_become_a_failed_remove():
    blocked, rows = _blocked({"api_outcomes": [{"action": "breakout", "outcome": "unknown"}]})
    assert blocked is False and rows == []


def test_mixed_remove_results_are_not_released_by_one_successful_family():
    blocked, _ = _blocked(
        {"api_outcomes": [{"action": "unbreakout", "outcome": "success"}, {"action": "unbreakout", "outcome": "unknown"}]}, pending="deleted"
    )
    assert blocked is True


def test_previously_blocked_footprint_cannot_be_reenabled_by_success_evidence():
    blocked, _ = _blocked({"api_outcomes": [{"action": "unbreakout", "outcome": "success"}]}, already_blocked=True)
    assert blocked is True


def test_barrier_is_evaluated_after_observation_and_before_any_cleanup_mutation():
    names = [task["name"] for task in CLEANUP]
    observe = names.index("Inspect only a test-owned footprint before cleanup")
    settle = names.index("Allow only readback settling for a reported successful original direct unbreakout")
    barrier = names.index("Refuse removal replay while retaining the independently observed remaining state")
    mutation = names.index("Remove one verified remaining family, preferring the control parent")
    assert observe < settle < barrier < mutation
    assert CLEANUP[barrier]["ansible.builtin.assert"]["that"] == ["not (breakout_cleanup_removal_blocked | bool)"]
    assert "breakout_cleanup_remaining | length > 0" in CLEANUP[barrier]["when"]


def test_successful_original_remove_settles_with_read_only_native_oracle_and_keeps_failures_separate():
    settle = next(task for task in CLEANUP if task["name"] == "Allow only readback settling for a reported successful original direct unbreakout")
    oracle = settle["block"][0]
    assert oracle["cisco.nd.nd_manage_breakout_interfaces_validate"]["expected_profile"] == "native"
    assert oracle["cisco.nd.nd_manage_breakout_interfaces_validate"]["retries"] == "{{ test_breakout_observe_retries }}"
    assert oracle["check_mode"] is False
    assert settle["rescue"][0]["ansible.builtin.set_fact"]["breakout_cleanup_original_topology_failure"] == "{{ ansible_failed_result }}"
    assert settle["always"][0]["ansible.builtin.set_fact"]["breakout_observation"] == "{{ breakout_cleanup_original_settling }}"
    assert all("cisco.nd.nd_manage_breakout_interfaces" not in task for section in ("block", "rescue", "always") for task in settle[section])


@pytest.mark.parametrize("outcome,expected", [("success", True), ("failed", False), ("unknown", False), ("noop", False), ("planned", False)])
def test_only_explicit_successful_direct_removal_is_eligible_for_native_settling(outcome, expected):
    settle = next(task for task in CLEANUP if task["name"] == "Allow only readback settling for a reported successful original direct unbreakout")
    row = {"action": "unbreakout", "outcome": outcome}
    variables = {"breakout_result": {"api_outcomes": [row]}, "breakout_cleanup_original_removals": [row]}
    predicates = [_fact_environment().from_string("{{ " + expression + " }}").render(**variables) for expression in settle["when"][2:]]
    assert all(predicates) is expected


def test_original_failure_is_preserved_before_cleanup_and_reraised_afterward():
    block = LIFECYCLE[0]
    assert block["rescue"][0]["ansible.builtin.set_fact"]["breakout_lifecycle_failure"]["result"] == "{{ ansible_failed_result }}"
    assert block["always"][0]["ansible.builtin.debug"]["var"] == "breakout_lifecycle_failure"
    assert block["always"][1]["ansible.builtin.include_tasks"] == "../tasks/cleanup.yaml"
    assert "ansible.builtin.fail" in LIFECYCLE[1]


def test_lifecycle_marks_all_disruptive_remove_paths_before_module_invocation():
    tasks = LIFECYCLE[0]["block"]
    paths = [
        (tasks, "DELETED - Unbreak the control parent", "deleted"),
        (tasks, "DELETED - Unbreak using an actual child-family alias", "deleted"),
    ]
    for sequence, name, state in paths:
        index = next(index for index, task in enumerate(sequence) if task["name"] == name)
        assert sequence[index - 1]["ansible.builtin.set_fact"]["breakout_pending_removal"] == state


def test_lifecycle_releases_removal_markers_only_after_independent_post_state_validation():
    tasks = LIFECYCLE[0]["block"]
    paths = [
        (tasks, "Release parent removal barrier only after independent native validation", "native"),
        (tasks, "Release child removal barrier only after independent native validation", "native"),
    ]
    for sequence, name, profile in paths:
        index = next(index for index, task in enumerate(sequence) if task["name"] == name)
        assert sequence[index - 1]["ansible.builtin.include_tasks"] == "../tasks/observe.yaml"
        assert sequence[index - 1]["vars"]["breakout_expected_profile"] == profile
        assert sequence[index]["ansible.builtin.set_fact"]["breakout_pending_removal"] == ""
