# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Opt-in execution never publishes prospective state as confirmed state."""

from typing import ClassVar
from types import SimpleNamespace
import logging

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import MutationOutcome, MutationResourceOutcome, MutationResult
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.test_nd_state_plan import PlanModel


class OutcomeOrchestrator(NDBaseOrchestrator):
    model_class: ClassVar[type] = PlanModel
    supports_mutation_outcomes: ClassVar[bool] = True
    supports_bulk_create: ClassVar[bool] = True
    create_endpoint: type = NDEndpointBaseModel
    create_bulk_endpoint: type = NDEndpointBaseModel
    update_endpoint: type = NDEndpointBaseModel
    delete_endpoint: type = NDEndpointBaseModel
    query_all_endpoint: type = NDEndpointBaseModel
    query_one_endpoint: type = NDEndpointBaseModel
    _rows: list = []
    _responses: list = []
    _calls: list = []
    _guard_error: bool = False

    def query_all(self, **kwargs):
        return self._rows

    def preflight_delete(self, model_instances):
        if self._guard_error:
            raise ValueError("delete preflight rejected")

    def create_bulk(self, model_instances, **kwargs):
        self._calls.append(("create", [item.name for item in model_instances], self.rest_send.max_attempts))
        return self._respond()

    def delete(self, model_instance, **kwargs):
        self._calls.append(("delete", model_instance.name, self.rest_send.max_attempts))
        return self._respond()

    def _respond(self):
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def result(*pairs):
    return MutationResult(tuple(MutationResourceOutcome(key, MutationOutcome(state), messages=(f"{key}: {state}",)) for key, state in pairs))


def machine(*, state="replaced", rows=(), desired=({"name": "a"}, {"name": "b"}), responses=(), check=False):
    orchestrator = OutcomeOrchestrator(rest_send=RestSend({"check_mode": check}))
    orchestrator._rows = list(rows)
    orchestrator._responses = list(responses)
    orchestrator._calls = []
    module = SimpleNamespace(params={"state": state, "config": list(desired), "output_level": "normal"}, check_mode=check)
    return NDStateMachine(module, orchestrator)


@pytest.mark.parametrize(
    "pairs,changed,failed,after",
    [
        ((("a", "succeeded"), ("b", "succeeded")), True, False, ["a", "b"]),
        ((("a", "succeeded"), ("b", "failed")), True, True, ["a"]),
        ((("a", "failed"), ("b", "failed")), False, True, []),
    ],
)
def test_complete_bulk_results(pairs, changed, failed, after):
    sm = machine(responses=(result(*pairs),))
    if failed:
        with pytest.raises(NDStateMachineError):
            sm.manage_state()
    else:
        sm.manage_state()
    output = sm.output.format()
    assert output["changed"] is changed
    assert output["failed"] is failed
    assert [item["name"] for item in output["after"]] == after
    assert sm.before.keys() == []
    assert sm.planned.keys() == ["a", "b"]
    assert sm.sent.keys() == after
    assert sm.model_orchestrator.rest_send.max_attempts is None
    assert len(output["action_results"]) == 2


@pytest.mark.parametrize("response", [result(("a", "succeeded")), RuntimeError("delivery uncertain"), {}])
def test_unknown_omits_after_and_diff(response):
    sm = machine(responses=(response,))
    with pytest.raises(NDStateMachineError):
        sm.manage_state()
    output = sm.output.format()
    assert "after" not in output and "diff" not in output
    assert output["failed"] and output["may_have_changed"]
    assert output["after_status"] == "unknown"
    assert output["changed"] is isinstance(response, MutationResult)
    assert sm.model_orchestrator.rest_send.max_attempts is None


def test_check_mode_is_planned_not_confirmed():
    sm = machine(check=True)
    sm.manage_state()
    output = sm.output.format()
    assert output["changed"]
    assert output["after_status"] == "planned"
    assert sm.confirmed.keys() == []
    assert sm.model_orchestrator._calls == []
    assert output["action_results"] == []


def test_noop_has_no_fabricated_outcomes():
    sm = machine(rows=({"name": "a"}, {"name": "b"}))
    sm.manage_state()
    assert not sm.output.format()["changed"]
    assert sm.output.format()["action_results"] == []
    assert sm.model_orchestrator._calls == []


def test_override_failure_stops_deletion():
    sm = machine(state="overridden", rows=({"name": "old"},), responses=(result(("a", "succeeded"), ("b", "failed")),))
    with pytest.raises(NDStateMachineError):
        sm.manage_state()
    assert sm.confirmed.keys() == ["old", "a"]
    assert [call[0] for call in sm.model_orchestrator._calls] == ["create"]
    assert sm.removed.keys() == []
    assert sm.output.format()["planned_operations"][-1] == {"identifier": "old", "operation": "delete", "outcome": "not_attempted"}


def test_known_delete_failure_retains_safe_snapshot_and_retry_setting():
    sm = machine(state="deleted", rows=({"name": "a"}, {"name": "b"}), responses=(result(("a", "succeeded")), result(("b", "failed"))))
    sm.model_orchestrator.rest_send.max_attempts = 3
    with pytest.raises(NDStateMachineError):
        sm.manage_state()
    output = sm.output.format()
    assert output["changed"] and output["failed"]
    assert [item["name"] for item in output["after"]] == ["b"]
    assert [item["name"] for item in output["diff"]["before"]] == ["a", "b"]
    assert [item["name"] for item in output["diff"]["after"]] == ["b"]
    assert sm.model_orchestrator.rest_send.max_attempts == 3
    assert [call[2] for call in sm.model_orchestrator._calls] == [1, 1]


def test_delete_retains_earlier_confirmed_success_on_later_unknown():
    sm = machine(state="deleted", rows=({"name": "a"}, {"name": "b"}), responses=(result(("a", "succeeded")), RuntimeError("lost")))
    with pytest.raises(NDStateMachineError):
        sm.manage_state()
    assert sm.confirmed.keys() == ["b"]
    assert sm.removed.keys() == ["a"]
    assert sm.sent.keys() == []
    assert sm.output.format()["changed"]


@pytest.mark.parametrize("check", [True, False])
def test_all_override_deletions_preflight_before_any_create(check):
    sm = machine(state="overridden", rows=({"name": "old"},), check=check)
    sm.model_orchestrator._guard_error = True
    with pytest.raises(NDStateMachineError, match="preflight"):
        sm.manage_state()
    assert sm.model_orchestrator._calls == []
    assert not sm.output.format()["changed"]
    assert [item["name"] for item in sm.output.format()["after"]] == ["old"]


def test_fail_json_retains_partial_evidence():
    sm = machine(responses=(result(("a", "succeeded"), ("b", "failed")),))
    captured = {}

    class StopFail(Exception):
        pass

    def fail_json(**kwargs):
        captured.update(kwargs)
        raise StopFail

    sm.module.fail_json = fail_json
    try:
        sm.manage_state()
    except NDStateMachineError as error:
        with pytest.raises(StopFail):
            fail_from_exception(sm.module, logging.getLogger("test"), sm, error)
    assert captured["changed"] and captured["failed"]
    assert [item["name"] for item in captured["after"]] == ["a"]
    assert captured["action_results"][1]["messages"] == ["b: failed"]
