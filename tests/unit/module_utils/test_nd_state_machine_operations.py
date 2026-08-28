# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for ``NDStateMachine`` operation wiring.

These cover the state-machine behavior that the pure ``issubset``/``get_diff``
tests in ``test_utils.py`` cannot reach:

- ``_execute_operation`` returns a boolean success signal and skips the API call
  in check mode.
- creates/updates/deletes are added to ``sent`` after a successful operation
  (per-item gating); ``sent`` stays populated in check mode so downstream
  config-save/deploy previews are not skipped (PR #225).
- under ``ignore_errors`` a failed delete leaves the item in ``existing`` and out
  of ``sent``; without it the failure is raised as ``NDStateMachineError``.
- bulk-delete failure keeps every item, while bulk-delete success removes only
  the targeted items.
- ``NDStateMachine`` rejects omitted/null config for mutating write states so
  ``state: overridden`` cannot accidentally delete everything.

A tiny real ``NDBaseModel`` subclass drives the genuine diff/merge logic, while a
duck-typed fake orchestrator records the CRUD calls it receives and can simulate
failures. The heavy ``NDStateMachine.__init__`` (RestSend/Sender/endpoints) is
bypassed with ``object.__new__`` so the tests stay focused on the state logic.
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Any, ClassVar, List, Literal, Optional

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator

# =============================================================================
# Test doubles
# =============================================================================


class _FakeModel(NDBaseModel):
    """Minimal single-identifier model so the real diff/merge logic runs."""

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[Literal["single", "composite", "hierarchical", "singleton"]] = "single"

    name: str
    value: Optional[str] = None


class _FakeOutput:
    """No-op stand-in for ``NDOutput``; the state machine only calls ``assign``."""

    def assign(self, **kwargs: Any) -> None:
        return None


class _FakeOrchestrator:
    """Duck-typed orchestrator that records CRUD calls and can simulate failures.

    ``fail_ops`` is a set of operation names ("create", "update", "delete",
    "create_bulk", "delete_bulk"); a listed operation records the attempt and
    then raises, mirroring an orchestrator whose API call failed.
    """

    def __init__(self, supports_bulk_create: bool = False, supports_bulk_delete: bool = False, fail_ops: Optional[set] = None) -> None:
        self.model_class = _FakeModel
        self.supports_bulk_create = supports_bulk_create
        self.supports_bulk_delete = supports_bulk_delete
        self.results = None
        self.fail_ops = set(fail_ops or set())
        self.calls: dict = {
            "create": [],
            "update": [],
            "delete": [],
            "create_bulk": [],
            "delete_bulk": [],
            "preflight_create": [],
            "preflight": [],
        }

    def preflight_create(self, model_instances) -> None:
        self.calls["preflight_create"].append(list(model_instances))

    def preflight(self, model_instances) -> None:
        self.calls["preflight"].append(list(model_instances))

    def query_all(self, model_instance=None, **kwargs):
        return []

    def create(self, model_instance, **kwargs):
        self.calls["create"].append(model_instance)
        if "create" in self.fail_ops:
            raise Exception("create failed")
        return {}

    def create_bulk(self, model_instances, **kwargs):
        self.calls["create_bulk"].append(list(model_instances))
        if "create_bulk" in self.fail_ops:
            raise Exception("create_bulk failed")
        return {}

    def update(self, model_instance, **kwargs):
        self.calls["update"].append(model_instance)
        if "update" in self.fail_ops:
            raise Exception("update failed")
        return {}

    def delete(self, model_instance, **kwargs):
        self.calls["delete"].append(model_instance)
        if "delete" in self.fail_ops:
            raise Exception("delete failed")
        return None

    def delete_bulk(self, model_instances, **kwargs):
        self.calls["delete_bulk"].append(list(model_instances))
        if "delete_bulk" in self.fail_ops:
            raise Exception("delete_bulk failed")
        return None


_MISSING = object()


class _FakeModule:
    """Minimal module object for exercising ``NDStateMachine.__init__``."""

    def __init__(self, state: str = "merged", config: Any = _MISSING, check_mode: bool = False, ignore_errors: bool = False) -> None:
        self.check_mode = check_mode
        self.params: dict[str, Any] = {
            "state": state,
            "output_level": "normal",
            "ignore_errors": ignore_errors,
        }
        if config is not _MISSING:
            self.params["config"] = config


class _InitFakeOrchestrator(NDBaseOrchestrator):
    """Minimal real orchestrator subclass for ``NDStateMachine.__init__`` tests."""

    model_class: ClassVar[type[NDBaseModel]] = _FakeModel
    create_endpoint: ClassVar[Any] = None
    update_endpoint: ClassVar[Any] = None
    delete_endpoint: ClassVar[Any] = None
    query_one_endpoint: ClassVar[Any] = None
    query_all_endpoint: ClassVar[Any] = None

    def query_all(self, model_instance=None, **kwargs):
        return []

    def create(self, model_instance, **kwargs):
        return {}

    def update(self, model_instance, **kwargs):
        return {}

    def delete(self, model_instance, **kwargs):
        return None


def _model(name: str, value: Optional[str] = None) -> _FakeModel:
    return _FakeModel(name=name, value=value)


def _make_state_machine(
    state: str = "merged",
    check_mode: bool = False,
    ignore_errors: bool = False,
    orchestrator: Optional[_FakeOrchestrator] = None,
    existing: Optional[List[_FakeModel]] = None,
    proposed: Optional[List[_FakeModel]] = None,
) -> NDStateMachine:
    """Build an ``NDStateMachine`` wired to the fakes, bypassing ``__init__``."""
    if orchestrator is None:
        orchestrator = _FakeOrchestrator()

    sm = object.__new__(NDStateMachine)
    sm.state = state
    sm.check_mode = check_mode
    sm.ignore_errors = ignore_errors
    sm.model_class = _FakeModel
    sm.model_orchestrator = orchestrator
    sm.supports_bulk_create = orchestrator.supports_bulk_create
    sm.supports_bulk_delete = orchestrator.supports_bulk_delete
    sm.output = _FakeOutput()
    sm.before = NDConfigCollection(model_class=_FakeModel, items=list(existing or []))
    sm.existing = sm.before.copy()
    sm.proposed = NDConfigCollection(model_class=_FakeModel, items=list(proposed or []))
    sm.sent = NDConfigCollection(model_class=_FakeModel)
    return sm


def _names(items) -> List[str]:
    return sorted(item.name for item in items)


# =============================================================================
# manage_state dispatch
# =============================================================================


def test_manage_state_invalid_state_raises():
    """An unknown state is rejected rather than silently ignored."""
    sm = _make_state_machine(state="bogus")
    with pytest.raises(NDStateMachineError, match="Invalid state"):
        sm.manage_state()


# =============================================================================
# check mode: API is skipped but items are still marked sent (deploy preview)
# =============================================================================


def test_check_mode_create_skips_api_but_marks_sent():
    """Check-mode create previews the new item and marks it sent (no API call)."""
    orch = _FakeOrchestrator()
    sm = _make_state_machine(state="merged", check_mode=True, orchestrator=orch, proposed=[_model("a", "x")])

    sm.manage_state()

    assert orch.calls["create"] == []  # no API call in check mode
    assert _names(sm.sent) == ["a"]  # sent stays populated so deploy preview is not skipped
    assert sm.existing.get("a") is not None  # previewed 'after' still reflects it


def test_check_mode_update_skips_api_but_marks_sent():
    """Check-mode update previews the change and marks it sent (no API call)."""
    orch = _FakeOrchestrator()
    sm = _make_state_machine(state="replaced", check_mode=True, orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a", "y")])

    sm.manage_state()

    assert orch.calls["update"] == []
    assert _names(sm.sent) == ["a"]
    assert sm.existing.get("a").value == "y"  # previewed change


def test_check_mode_delete_skips_api_but_marks_sent():
    """Check-mode delete previews the removal and marks it sent (no API call)."""
    orch = _FakeOrchestrator()
    sm = _make_state_machine(state="deleted", check_mode=True, orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a")])

    sm.manage_state()

    assert orch.calls["delete"] == []
    assert _names(sm.sent) == ["a"]
    assert len(sm.existing) == 0  # previewed removal


# =============================================================================
# normal mode: successful operations are marked sent
# =============================================================================


def test_create_individual_marks_sent():
    """A successful individual create is pushed and recorded in ``sent``."""
    orch = _FakeOrchestrator(supports_bulk_create=False)
    sm = _make_state_machine(state="merged", orchestrator=orch, proposed=[_model("a", "x")])

    sm.manage_state()

    assert _names(orch.calls["create"]) == ["a"]
    assert orch.calls["create_bulk"] == []
    assert _names(sm.sent) == ["a"]
    assert sm.existing.get("a") is not None


def test_create_bulk_marks_sent():
    """When bulk create is supported, creates go through ``create_bulk``."""
    orch = _FakeOrchestrator(supports_bulk_create=True)
    sm = _make_state_machine(state="merged", orchestrator=orch, proposed=[_model("a", "x"), _model("b", "y")])

    sm.manage_state()

    assert orch.calls["create"] == []
    assert len(orch.calls["create_bulk"]) == 1
    assert _names(orch.calls["create_bulk"][0]) == ["a", "b"]
    assert _names(sm.sent) == ["a", "b"]


def test_update_marks_sent():
    """A successful update is pushed, recorded in ``sent``, and reflected in 'after'."""
    orch = _FakeOrchestrator()
    sm = _make_state_machine(state="replaced", orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a", "y")])

    sm.manage_state()

    assert _names(orch.calls["update"]) == ["a"]
    assert _names(sm.sent) == ["a"]
    assert sm.existing.get("a").value == "y"


def test_delete_individual_marks_sent():
    """A successful individual delete removes the item and records it in ``sent``."""
    orch = _FakeOrchestrator(supports_bulk_delete=False)
    sm = _make_state_machine(state="deleted", orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a")])

    sm.manage_state()

    assert _names(orch.calls["delete"]) == ["a"]
    assert len(sm.existing) == 0
    assert _names(sm.sent) == ["a"]


def test_delete_bulk_marks_sent():
    """When bulk delete is supported, deletes go through ``delete_bulk``."""
    orch = _FakeOrchestrator(supports_bulk_delete=True)
    sm = _make_state_machine(state="deleted", orchestrator=orch, existing=[_model("a", "x"), _model("b", "y")], proposed=[_model("a"), _model("b")])

    sm.manage_state()

    assert orch.calls["delete"] == []
    assert len(orch.calls["delete_bulk"]) == 1
    assert _names(orch.calls["delete_bulk"][0]) == ["a", "b"]
    assert _names(sm.sent) == ["a", "b"]
    assert len(sm.existing) == 0


# =============================================================================
# merged diff handling
# =============================================================================


def test_merged_no_diff_is_noop():
    """An item already matching its desired config triggers no operation."""
    orch = _FakeOrchestrator()
    sm = _make_state_machine(state="merged", orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a", "x")])

    sm.manage_state()

    assert orch.calls["create"] == []
    assert orch.calls["update"] == []
    assert len(sm.sent) == 0
    assert sm.existing.get("a").value == "x"


def test_merged_merges_changed_fields():
    """Merged state merges explicitly set fields and updates the item."""
    orch = _FakeOrchestrator()
    sm = _make_state_machine(state="merged", orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a", "y")])

    sm.manage_state()

    assert _names(orch.calls["update"]) == ["a"]
    assert sm.existing.get("a").value == "y"
    assert _names(sm.sent) == ["a"]


# =============================================================================
# ignore_errors handling
# =============================================================================


def test_delete_ignored_error_keeps_item_and_skips_sent():
    """An ignored delete failure leaves the item in 'after' and out of ``sent``."""
    orch = _FakeOrchestrator(supports_bulk_delete=False, fail_ops={"delete"})
    sm = _make_state_machine(state="deleted", ignore_errors=True, orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a")])

    sm.manage_state()

    assert _names(orch.calls["delete"]) == ["a"]  # the delete was attempted
    assert sm.existing.get("a") is not None  # but the item is kept
    assert len(sm.sent) == 0  # and not marked sent


def test_delete_non_ignored_error_raises():
    """Without ignore_errors a failed delete surfaces as NDStateMachineError."""
    orch = _FakeOrchestrator(supports_bulk_delete=False, fail_ops={"delete"})
    sm = _make_state_machine(state="deleted", ignore_errors=False, orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a")])

    with pytest.raises(NDStateMachineError, match="Failed to delete"):
        sm.manage_state()


def test_bulk_delete_ignored_error_keeps_all_items():
    """An ignored bulk-delete failure keeps every targeted item."""
    orch = _FakeOrchestrator(supports_bulk_delete=True, fail_ops={"delete_bulk"})
    sm = _make_state_machine(
        state="deleted",
        ignore_errors=True,
        orchestrator=orch,
        existing=[_model("a", "x"), _model("b", "y")],
        proposed=[_model("a"), _model("b")],
    )

    sm.manage_state()

    assert len(orch.calls["delete_bulk"]) == 1  # bulk delete attempted once
    assert _names(sm.existing) == ["a", "b"]  # nothing removed
    assert len(sm.sent) == 0  # nothing marked sent


def test_bulk_delete_non_ignored_error_raises():
    """Without ignore_errors a failed bulk delete surfaces as NDStateMachineError."""
    orch = _FakeOrchestrator(supports_bulk_delete=True, fail_ops={"delete_bulk"})
    sm = _make_state_machine(state="deleted", ignore_errors=False, orchestrator=orch, existing=[_model("a", "x")], proposed=[_model("a")])

    with pytest.raises(NDStateMachineError, match="Failed to delete in bulk"):
        sm.manage_state()


def test_bulk_delete_success_removes_only_targeted():
    """A successful bulk delete removes only the proposed items."""
    orch = _FakeOrchestrator(supports_bulk_delete=True)
    sm = _make_state_machine(
        state="deleted",
        orchestrator=orch,
        existing=[_model("a", "x"), _model("b", "y"), _model("c", "z")],
        proposed=[_model("a"), _model("b")],
    )

    sm.manage_state()

    assert _names(sm.existing) == ["c"]  # only the untargeted item remains
    assert _names(sm.sent) == ["a", "b"]


# =============================================================================
# overridden deletions
# =============================================================================


def test_overridden_deletes_non_proposed_items():
    """Overridden removes existing items absent from the proposed config."""
    orch = _FakeOrchestrator(supports_bulk_delete=False)
    sm = _make_state_machine(
        state="overridden",
        orchestrator=orch,
        existing=[_model("a", "x"), _model("b", "y"), _model("c", "z")],
        proposed=[_model("a", "x")],
    )

    sm.manage_state()

    assert _names(orch.calls["delete"]) == ["b", "c"]  # only non-proposed deleted
    assert _names(sm.existing) == ["a"]
    assert _names(sm.sent) == ["b", "c"]


@pytest.mark.parametrize("check_mode", [False, True])
def test_overridden_explicit_empty_config_deletes_all_existing(check_mode):
    """An explicit empty overridden config means delete every existing item."""
    orch = _FakeOrchestrator(supports_bulk_delete=False)
    sm = _make_state_machine(
        state="overridden",
        check_mode=check_mode,
        orchestrator=orch,
        existing=[_model("a", "x"), _model("b", "y")],
        proposed=[],
    )

    sm.manage_state()

    assert len(sm.existing) == 0
    if check_mode:
        assert orch.calls["delete"] == []  # no API call in check mode
        assert _names(sm.sent) == ["a", "b"]  # but the deletes are previewed as sent
    else:
        assert _names(orch.calls["delete"]) == ["a", "b"]
        assert _names(sm.sent) == ["a", "b"]


# =============================================================================
# _execute_operation contract
# =============================================================================


def test_execute_operation_check_mode_skips_call():
    """In check mode the API callable is not invoked but success is reported."""
    sm = _make_state_machine(check_mode=True)
    calls: List[tuple] = []

    result = sm._execute_operation(lambda *a, **k: calls.append(a), "payload")

    assert result is True
    assert calls == []  # callable skipped


def test_execute_operation_success_returns_true():
    """Outside check mode a successful callable runs and reports success."""
    sm = _make_state_machine(check_mode=False)
    calls: List[tuple] = []

    result = sm._execute_operation(lambda *a, **k: calls.append(a), "payload")

    assert result is True
    assert calls == [("payload",)]


def test_execute_operation_ignored_error_returns_false():
    """An ignored failure is swallowed and reported as not-sent (False)."""
    sm = _make_state_machine(check_mode=False, ignore_errors=True)

    def _boom(*args, **kwargs):
        raise Exception("boom")

    assert sm._execute_operation(_boom, "payload") is False


def test_execute_operation_non_ignored_error_raises():
    """A non-ignored failure is wrapped in NDStateMachineError."""
    sm = _make_state_machine(check_mode=False, ignore_errors=False)

    def _boom(*args, **kwargs):
        raise Exception("boom")

    with pytest.raises(NDStateMachineError, match="Operation failed"):
        sm._execute_operation(_boom, "payload")


# =============================================================================
# config missing/null/empty handling
# =============================================================================


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize(
    "config",
    [
        pytest.param(_MISSING, id="missing"),
        pytest.param(None, id="null"),
    ],
)
def test_state_machine_rejects_missing_or_null_config_for_write_states(state, config):
    """Write states require explicit config so null cannot become destructive."""
    module = _FakeModule(state=state, config=config)

    with pytest.raises(NDStateMachineError, match=r"config must be provided and cannot be null"):
        NDStateMachine(module=module, model_orchestrator=_InitFakeOrchestrator)


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "deleted"])
def test_state_machine_accepts_explicit_empty_config(state):
    """Explicit ``config: []`` remains distinct from omitted/null config."""
    module = _FakeModule(state=state, config=[])
    sm = NDStateMachine(module=module, model_orchestrator=_InitFakeOrchestrator)

    assert len(sm.proposed) == 0


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(_MISSING, id="missing"),
        pytest.param(None, id="null"),
    ],
)
def test_deleted_state_tolerates_missing_or_null_config_as_empty(config):
    """Missing/null delete config is non-destructive: it targets no proposed items."""
    module = _FakeModule(state="deleted", config=config)
    sm = NDStateMachine(module=module, model_orchestrator=_InitFakeOrchestrator)

    assert len(sm.proposed) == 0


# =============================================================================
# from_ansible_config normalization
# =============================================================================


@pytest.mark.parametrize(
    "data, expected_len",
    [
        (None, 0),  # config omitted / explicitly null must not crash
        ([], 0),
        ([{"name": "a"}], 1),
        ([{"name": "a"}, {"name": "b"}], 2),
    ],
)
def test_from_ansible_config_normalizes_data(data, expected_len):
    """``from_ansible_config`` tolerates None and builds a collection otherwise."""
    collection = NDConfigCollection.from_ansible_config(data=data, model_class=_FakeModel)
    assert len(collection) == expected_len
