# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `nd_fabric_update_group` module helpers.

Covers the auto-assign path (`_run_auto_assign`) check-mode guard and failure-output behavior, and
the `analysis` / report-type mutual-exclusion guard (`_validate_report_analysis_exclusion`). The
auto-assign tests monkeypatch the orchestrator's `query_all` / `propose` so no controller I/O occurs;
`RestSend` and `Sender` are only constructed (never committed).
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name
# pylint: disable=invalid-name,line-too-long,unused-variable

from __future__ import annotations

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.nd_output import NDOutput
from ansible_collections.cisco.nd.plugins.modules import nd_fabric_update_group as mod
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


# =============================================================================
# Test: _run_auto_assign check-mode guard
# =============================================================================


@pytest.mark.parametrize(
    "check_mode,expected_propose_calls",
    [(True, 0), (False, 1)],
    ids=["check_mode_skips_propose", "normal_runs_propose"],
)
def test_nd_fabric_update_group_00100(monkeypatch, check_mode: bool, expected_propose_calls: int) -> None:
    """
    # Summary

    Verify `_run_auto_assign` runs the `propose` action only when NOT in check mode. A regression that
    called `propose` under `--check` would mutate the fabric, so this guards the most important gap.

    ## Test

    - `query_all` is stubbed (before / after snapshots)
    - In check mode `propose` is never called; in normal mode it is called exactly once

    ## Classes and Methods

    - nd_fabric_update_group._run_auto_assign()
    """
    propose_calls: list[str] = []
    monkeypatch.setattr(mod.FabricUpdateGroupOrchestrator, "query_all", lambda self, *a, **k: [{"updateGroupName": "g1"}])
    monkeypatch.setattr(mod.FabricUpdateGroupOrchestrator, "propose", lambda self, algorithm: propose_calls.append(algorithm))

    module = _FakeModule(
        params={"auto_assign": "roleBased", "fabric_name": "SITE1", "state": "merged", "check_mode": check_mode},
        check_mode=check_mode,
    )
    output = NDOutput(output_level="normal")

    with does_not_raise():
        mod._run_auto_assign(module, output)

    assert len(propose_calls) == expected_propose_calls


def test_nd_fabric_update_group_00110(monkeypatch) -> None:
    """
    # Summary

    Verify `_run_auto_assign` surfaces the `before` snapshot in the supplied output even when `propose`
    fails after the snapshot was taken (the output is populated in place, not returned).

    ## Test

    - `query_all` returns one group; `propose` raises
    - `_run_auto_assign` propagates the error, but `output` already carries the `before` context

    ## Classes and Methods

    - nd_fabric_update_group._run_auto_assign()
    """
    monkeypatch.setattr(mod.FabricUpdateGroupOrchestrator, "query_all", lambda self, *a, **k: [{"updateGroupName": "g1"}])

    def _boom(self, algorithm):
        raise RuntimeError("propose blew up")

    monkeypatch.setattr(mod.FabricUpdateGroupOrchestrator, "propose", _boom)

    module = _FakeModule(
        params={"auto_assign": "roleBased", "fabric_name": "SITE1", "state": "merged", "check_mode": False},
        check_mode=False,
    )
    output = NDOutput(output_level="normal")

    with pytest.raises(RuntimeError, match=r"propose blew up"):
        mod._run_auto_assign(module, output)

    formatted = output.format()
    assert len(formatted["before"]) == 1
    assert len(formatted["after"]) == 1


# =============================================================================
# Test: _validate_report_analysis_exclusion
# =============================================================================


def test_nd_fabric_update_group_00200() -> None:
    """
    # Summary

    Verify a config item selecting both `analysis` and a non-`noReport` report type fails with a clear
    message (Nexus Dashboard rejects the combination with a raw 400).

    ## Classes and Methods

    - nd_fabric_update_group._validate_report_analysis_exclusion()
    """
    module = _FakeModule(params={"state": "merged", "config": [{"update_group_name": "g1", "analysis": "snapshot", "reports": "useDefaultPreAndPostReports"}]})

    with pytest.raises(_FailJson, match=r"analysis cannot be combined with a report type"):
        mod._validate_report_analysis_exclusion(module)

    assert module.fail_json_calls


def test_nd_fabric_update_group_00210() -> None:
    """
    # Summary

    Verify `analysis` combined with a non-`noReport` `report_selection` also fails.

    ## Classes and Methods

    - nd_fabric_update_group._validate_report_analysis_exclusion()
    """
    module = _FakeModule(params={"state": "merged", "config": [{"update_group_name": "g1", "analysis": "noAnalysis", "report_selection": "basic"}]})

    with pytest.raises(_FailJson, match=r"analysis cannot be combined with a report type"):
        mod._validate_report_analysis_exclusion(module)


@pytest.mark.parametrize(
    "item",
    [
        {"update_group_name": "g1", "reports": "useDefaultPreAndPostReports"},
        {"update_group_name": "g1", "report_selection": "advanced"},
        {"update_group_name": "g1", "analysis": "snapshot"},
        {"update_group_name": "g1", "analysis": "snapshot", "reports": "noReport"},
        {"update_group_name": "g1", "analysis": "snapshot", "report_selection": "noReport"},
        {"update_group_name": "g1"},
    ],
    ids=["reports_only", "report_selection_only", "analysis_only", "analysis_plus_noReport", "analysis_plus_noReport_selection", "neither"],
)
def test_nd_fabric_update_group_00220(item: dict) -> None:
    """
    # Summary

    Verify non-conflicting config items pass validation: a report type alone, analysis alone, and
    analysis combined with an explicit `noReport` (which does not count as a selected report type).

    ## Classes and Methods

    - nd_fabric_update_group._validate_report_analysis_exclusion()
    """
    module = _FakeModule(params={"state": "merged", "config": [item]})

    with does_not_raise():
        mod._validate_report_analysis_exclusion(module)

    assert not module.fail_json_calls


def test_nd_fabric_update_group_00230() -> None:
    """
    # Summary

    Verify the mutual-exclusion check is skipped for `state: deleted`, where settings fields are ignored.

    ## Classes and Methods

    - nd_fabric_update_group._validate_report_analysis_exclusion()
    """
    module = _FakeModule(
        params={"state": "deleted", "config": [{"update_group_name": "g1", "analysis": "snapshot", "reports": "useDefaultPreAndPostReports"}]}
    )

    with does_not_raise():
        mod._validate_report_analysis_exclusion(module)

    assert not module.fail_json_calls
