# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Failure-path tests for evidence-backed NDStateMachine after-state."""

from __future__ import annotations

from typing import Any, ClassVar, Literal

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_reconciliation import (
    DeferredMutation,
    MutationJournal,
    MutationOutcome,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


class _Model(NDBaseModel):
    identifiers: ClassVar[list[str] | None] = ["name"]
    identifier_strategy: ClassVar[
        Literal["single", "composite", "hierarchical", "singleton"] | None
    ] = "single"

    name: str
    value: str | None = None


class _Module:
    def __init__(
        self, *, state: str, check_mode: bool, ignore_errors: bool, verify: Any = None
    ) -> None:
        self.check_mode = check_mode
        self.params = {
            "state": state,
            "config": [],
            "output_level": "normal",
            "ignore_errors": ignore_errors,
            "verify": verify,
        }


class _RestSend:
    timeout = 30


class _Orchestrator:
    model_class = _Model
    supports_bulk_create = False
    supports_bulk_delete = False

    def __init__(
        self, results: Results, behaviors: dict[str, str] | None = None
    ) -> None:
        self.results = results
        self.behaviors = behaviors or {}
        self.calls: list[str] = []
        self.final_responses: list[Any] = []
        self.rest_send = _RestSend()

    def preflight_create(self, _items) -> None:
        return

    def preflight(self, _items) -> None:
        return

    def _register(
        self, *, success: bool, changed: bool, certainty: str | None = None
    ) -> None:
        attempt = self.results.begin_api_call("/api/v1/items", HttpVerbEnum.PUT)
        self.results.action = OperationType.UPDATE.value
        self.results.operation_type = OperationType.UPDATE
        self.results.path_current = "/api/v1/items"
        self.results.verb_current = HttpVerbEnum.PUT
        self.results.response_current = {"RETURN_CODE": 200 if success else 207}
        result = {"success": success, "changed": changed}
        if certainty is not None:
            result["outcome_certainty"] = certainty
        self.results.result_current = result
        self.results.diff_current = {}
        self.results.register_api_call()
        self.results.complete_api_call(attempt)

    def _mutate(self, item: _Model):
        self.calls.append(item.name)
        behavior = self.behaviors.get(item.name, "success")
        if behavior == "success":
            self._register(success=True, changed=True)
            return {}
        if behavior == "local_failure":
            raise RuntimeError("local validation failed")
        if behavior == "no_change":
            self._register(success=False, changed=False, certainty="no_change")
            raise RuntimeError("controller rejected request")
        if behavior == "mixed":
            self._register(success=False, changed=True)
            raise RuntimeError("mixed multi-status failure")
        if behavior == "timeout":
            self.results.begin_api_call("/api/v1/items", HttpVerbEnum.PUT)
            raise RuntimeError("response lost")
        if behavior == "partial_multi_call":
            self._register(success=True, changed=True)
            self._register(success=False, changed=False)
            raise RuntimeError("second request failed")
        if behavior == "deferred":
            return DeferredMutation(phase="remove")
        raise AssertionError(f"Unknown behavior: {behavior}")

    create = _mutate
    update = _mutate
    delete = _mutate

    def create_bulk(self, items: list[_Model]):
        self.calls.extend(item.name for item in items)
        behavior = self.behaviors.get("bulk", "success")
        if behavior == "mixed":
            self._register(success=False, changed=True)
            raise RuntimeError("mixed multi-status failure")
        self._register(success=True, changed=True)
        return {}

    def delete_bulk(self, items: list[_Model]):
        return self.create_bulk(items)

    def query_final_state(self, _context):
        response = self.final_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _collection(items: list[_Model]) -> NDConfigCollection:
    return NDConfigCollection(model_class=_Model, items=items)


def _state_machine(
    *,
    state: str = "replaced",
    before: list[_Model] | None = None,
    proposed: list[_Model] | None = None,
    behaviors: dict[str, str] | None = None,
    ignore_errors: bool = False,
    check_mode: bool = False,
    verify: Any = None,
    bulk_create: bool = False,
) -> NDStateMachine:
    sm = object.__new__(NDStateMachine)
    sm.module = _Module(
        state=state, check_mode=check_mode, ignore_errors=ignore_errors, verify=verify
    )
    sm.state = state
    sm.check_mode = check_mode
    sm.ignore_errors = ignore_errors
    sm.model_class = _Model
    sm.results = Results()
    sm.results.state = state
    sm.results.check_mode = check_mode
    sm.model_orchestrator = _Orchestrator(sm.results, behaviors)
    sm.model_orchestrator.supports_bulk_create = bulk_create
    sm.supports_bulk_create = bulk_create
    sm.supports_bulk_delete = False
    sm.before = _collection(before or [])
    sm.planned = sm.before.copy()
    sm.confirmed = sm.before.copy()
    sm.existing = sm.confirmed
    sm.proposed = _collection(proposed or [])
    sm.sent = _collection([])
    sm.output = NDOutput("normal")
    sm.output.assign(before=sm.before, proposed=sm.proposed)
    sm.output.set_after_state(sm.confirmed, status="confirmed")
    sm.journal = MutationJournal()
    sm.plan = None
    sm.observed = None
    sm._finalized = False
    sm._verify_settings = sm._verification_settings()
    return sm


def _values(output: dict) -> dict[str, str | None]:
    return {item["name"]: item.get("value") for item in output["after"]}


def test_earlier_success_is_confirmed_when_later_update_fails() -> None:
    sm = _state_machine(
        before=[
            _Model(name="a", value="old"),
            _Model(name="b", value="old"),
            _Model(name="c", value="old"),
        ],
        proposed=[
            _Model(name="a", value="new"),
            _Model(name="b", value="new"),
            _Model(name="c", value="new"),
        ],
        behaviors={"b": "local_failure"},
    )

    with pytest.raises(NDStateMachineError, match="Failed to update b"):
        sm.manage_state()

    output = sm.output.format()
    assert sm.model_orchestrator.calls == ["a", "b"]
    assert _values(output) == {"a": "new", "b": "old", "c": "old"}
    assert output["after_status"] == "confirmed"
    assert output["changed"] is True
    assert [item.name for item in sm.sent] == ["a"]
    assert [checkpoint.outcome for checkpoint in sm.journal.checkpoints] == [
        MutationOutcome.SUCCEEDED,
        MutationOutcome.FAILED,
        MutationOutcome.NOT_ATTEMPTED,
    ]


def test_unknown_with_internal_continuation_keeps_later_evidence_but_omits_after() -> (
    None
):
    sm = _state_machine(
        before=[_Model(name="a", value="old"), _Model(name="b", value="old")],
        proposed=[_Model(name="a", value="new"), _Model(name="b", value="new")],
        behaviors={"a": "timeout"},
        ignore_errors=True,
    )

    sm.manage_state()

    output = sm.output.format()
    assert sm.model_orchestrator.calls == ["a", "b"]
    assert "after" not in output
    assert "diff" not in output
    assert output["after_status"] == "unknown"
    assert output["may_have_changed"] is True
    assert output["changed"] is True  # later b success is still proven
    assert [item.name for item in sm.sent] == ["b"]


def test_mixed_unkeyed_bulk_response_is_unknown() -> None:
    sm = _state_machine(
        state="merged",
        proposed=[_Model(name="a", value="new"), _Model(name="b", value="new")],
        behaviors={"bulk": "mixed"},
        bulk_create=True,
    )

    with pytest.raises(NDStateMachineError, match="mixed multi-status failure"):
        sm.manage_state()

    output = sm.output.format()
    assert output["changed"] is True
    assert output["after_status"] == "unknown"
    assert set(output["affected_identifiers"]) == {"a", "b"}
    assert "after" not in output


def test_opt_in_finalization_replaces_unknown_with_observed_state() -> None:
    sm = _state_machine(
        before=[_Model(name="a", value="old")],
        proposed=[_Model(name="a", value="new")],
        behaviors={"a": "timeout"},
        verify={"enabled": True, "retries": 1, "timeout": 5, "delay": 0},
    )
    sm.model_orchestrator.final_responses = [[{"name": "a", "value": "controller"}]]

    with pytest.raises(NDStateMachineError) as exc_info:
        sm.manage_state()
    sm.finalize(primary_error=exc_info.value)

    output = sm.output.format()
    assert _values(output) == {"a": "controller"}
    assert output["after_status"] == "observed"
    assert output["verification_performed"] is True


def test_known_success_does_not_requery_even_when_verify_is_enabled() -> None:
    sm = _state_machine(
        before=[_Model(name="a", value="old")],
        proposed=[_Model(name="a", value="new")],
        verify={"enabled": True, "retries": 1, "timeout": 5, "delay": 0},
    )

    sm.manage_state()
    sm.finalize()

    assert sm.model_orchestrator.final_responses == []
    assert sm.output.format()["after_status"] == "confirmed"


def test_multi_request_partial_failure_is_unknown_without_semantic_subcheckpoints() -> (
    None
):
    sm = _state_machine(
        before=[_Model(name="a", value="old")],
        proposed=[_Model(name="a", value="new")],
        behaviors={"a": "partial_multi_call"},
    )

    with pytest.raises(NDStateMachineError):
        sm.manage_state()

    assert sm.journal.checkpoints[0].outcome is MutationOutcome.UNKNOWN
    assert sm.output.format()["after_status"] == "unknown"


def test_deferred_receipt_is_not_promoted_to_confirmed_or_sent() -> None:
    sm = _state_machine(
        before=[_Model(name="a", value="old")],
        proposed=[_Model(name="a", value="new")],
        behaviors={"a": "deferred"},
    )

    sm.manage_state()

    assert sm.journal.checkpoints[0].outcome is MutationOutcome.QUEUED
    assert _values(sm.output.format()) == {"a": "old"}
    assert len(sm.sent) == 0


def test_check_mode_returns_planned_without_controller_calls() -> None:
    sm = _state_machine(
        before=[_Model(name="a", value="old")],
        proposed=[_Model(name="a", value="new")],
        check_mode=True,
    )

    sm.manage_state()

    output = sm.output.format()
    assert sm.model_orchestrator.calls == []
    assert _values(output) == {"a": "new"}
    assert output["after_status"] == "planned"
    assert output["changed"] is True
