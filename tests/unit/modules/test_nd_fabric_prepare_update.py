# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `nd_fabric_prepare_update` module wrapper.

Covers the user-facing Ansible contract that the orchestrator/model tests do not exercise: the
`update_groups` non-empty guard (`_validate_update_groups`), and the `_run_prepare` decision surface
(idempotency short-circuit, check-mode handoff, and the wait / no-wait branches). Every orchestrator
method is monkeypatched so no controller I/O occurs; `RestSend` and `Sender` are only constructed,
never committed.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=invalid-name,line-too-long,unused-variable,unused-argument

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.modules import nd_fabric_prepare_update as mod
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


class _FailJson(Exception):
    """Raised by `_FakeModule.fail_json` to mimic AnsibleModule.fail_json aborting execution."""


class _FakeModule:
    """Minimal AnsibleModule stand-in exposing `params`, `check_mode`, and a raising `fail_json`."""

    def __init__(self, params: dict, check_mode: bool = False) -> None:
        self.params = params
        self.check_mode = check_mode
        self.fail_json_calls: list[dict] = []

    def fail_json(self, **kwargs) -> None:
        """Record the call and raise, mirroring AnsibleModule.fail_json halting the module."""
        self.fail_json_calls.append(kwargs)
        raise _FailJson(kwargs.get("msg", ""))


def _prepare_params(update_groups: list[str], *, wait: bool = True, check_mode: bool = False) -> dict:
    """Build a module params dict with the keys `_run_prepare` and the guard read."""
    return {
        "fabric_name": "SITE1",
        "update_groups": update_groups,
        "wait": wait,
        "wait_timeout": 1800,
        "wait_interval": 10,
        "state": "merged",
        "check_mode": check_mode,
    }


def _patch_orchestrator(monkeypatch, *, fully_prepared: bool, calls: dict) -> None:
    """
    # Summary

    Monkeypatch every `FabricPrepareUpdateOrchestrator` method `_run_prepare` calls so the wrapper
    logic runs without controller I/O. Records `stage` / `wait_for_completion` invocations in `calls`.

    ## Raises

    None
    """
    calls.setdefault("stage", [])
    calls.setdefault("wait", [])

    monkeypatch.setattr(mod.FabricPrepareUpdateOrchestrator, "get_summary", lambda self, update_group_name=None: {"summary": True})
    monkeypatch.setattr(mod.FabricPrepareUpdateOrchestrator, "preflight_role_check", lambda self, groups, summary=None: None)
    monkeypatch.setattr(mod.FabricPrepareUpdateOrchestrator, "status_snapshot", lambda self, groups, summary=None: [{"update_group_name": g} for g in groups])
    monkeypatch.setattr(mod.FabricPrepareUpdateOrchestrator, "snapshot_fully_prepared", staticmethod(lambda snapshot: fully_prepared))
    monkeypatch.setattr(mod.FabricPrepareUpdateOrchestrator, "stage", lambda self, groups: calls["stage"].append(list(groups)))
    monkeypatch.setattr(
        mod.FabricPrepareUpdateOrchestrator,
        "wait_for_completion",
        lambda self, groups, timeout, interval: calls["wait"].append((list(groups), timeout, interval)) or {"summary": "final"},
    )


# =============================================================================
# Test: _validate_update_groups
# =============================================================================


def test_nd_fabric_prepare_update_00100() -> None:
    """
    # Summary

    Verify `_validate_update_groups` fails when `update_groups` is empty. Ansible's `required=True`
    accepts an empty list, which would silently prepare nothing.

    ## Classes and Methods

    - nd_fabric_prepare_update._validate_update_groups()
    """
    module = _FakeModule(params=_prepare_params([]))
    output = NDOutput(output_level="normal")

    with pytest.raises(_FailJson, match=r"update_groups must contain at least one update group name"):
        mod._validate_update_groups(module, output)

    assert module.fail_json_calls


def test_nd_fabric_prepare_update_00110() -> None:
    """
    # Summary

    Verify `_validate_update_groups` passes for a non-empty `update_groups` list.

    ## Classes and Methods

    - nd_fabric_prepare_update._validate_update_groups()
    """
    module = _FakeModule(params=_prepare_params(["SITE1_N9K_leaf"]))
    output = NDOutput(output_level="normal")

    with does_not_raise():
        mod._validate_update_groups(module, output)

    assert not module.fail_json_calls


# =============================================================================
# Test: _run_prepare decision surface
# =============================================================================


def test_nd_fabric_prepare_update_00200(monkeypatch) -> None:
    """
    # Summary

    Verify the idempotency short-circuit: when every switch is already staged and validated,
    `_run_prepare` reports `changed=False` and never calls `stage` or `wait_for_completion`.

    ## Classes and Methods

    - nd_fabric_prepare_update._run_prepare()
    """
    calls: dict = {}
    _patch_orchestrator(monkeypatch, fully_prepared=True, calls=calls)

    module = _FakeModule(params=_prepare_params(["SITE1_N9K_leaf"]))

    with does_not_raise():
        _results, fields = mod._run_prepare(module)

    assert fields["changed"] is False
    assert calls["stage"] == []
    assert calls["wait"] == []


def test_nd_fabric_prepare_update_00210(monkeypatch) -> None:
    """
    # Summary

    Verify check mode reports the pending change without acting: `changed=True`, but the stage
    action (which cannot be previewed) is never sent.

    ## Classes and Methods

    - nd_fabric_prepare_update._run_prepare()
    """
    calls: dict = {}
    _patch_orchestrator(monkeypatch, fully_prepared=False, calls=calls)

    module = _FakeModule(params=_prepare_params(["SITE1_N9K_leaf"], check_mode=True), check_mode=True)

    with does_not_raise():
        _results, fields = mod._run_prepare(module)

    assert fields["changed"] is True
    assert calls["stage"] == []
    assert calls["wait"] == []


def test_nd_fabric_prepare_update_00220(monkeypatch) -> None:
    """
    # Summary

    Verify the no-wait branch: staging is required, `stage` is sent once, and `wait_for_completion`
    is NOT called when `wait=false`.

    ## Classes and Methods

    - nd_fabric_prepare_update._run_prepare()
    """
    calls: dict = {}
    _patch_orchestrator(monkeypatch, fully_prepared=False, calls=calls)

    module = _FakeModule(params=_prepare_params(["SITE1_N9K_leaf"], wait=False))

    with does_not_raise():
        _results, fields = mod._run_prepare(module)

    assert fields["changed"] is True
    assert calls["stage"] == [["SITE1_N9K_leaf"]]
    assert calls["wait"] == []


def test_nd_fabric_prepare_update_00230(monkeypatch) -> None:
    """
    # Summary

    Verify the wait branch: staging is required, `stage` is sent, and `wait_for_completion` is
    called exactly once with the configured timeout and interval.

    ## Classes and Methods

    - nd_fabric_prepare_update._run_prepare()
    """
    calls: dict = {}
    _patch_orchestrator(monkeypatch, fully_prepared=False, calls=calls)

    module = _FakeModule(params=_prepare_params(["SITE1_N9K_leaf"], wait=True))

    with does_not_raise():
        _results, fields = mod._run_prepare(module)

    assert fields["changed"] is True
    assert calls["stage"] == [["SITE1_N9K_leaf"]]
    assert calls["wait"] == [(["SITE1_N9K_leaf"], 1800, 10)]
