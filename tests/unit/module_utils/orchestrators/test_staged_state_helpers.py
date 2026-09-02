# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for staged workflow state mapping helpers."""

from __future__ import annotations

from types import SimpleNamespace

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.staged_state_helpers import (
    crud_module_args,
    prepare_crud_state,
    query_module_args,
)


def test_staged_crud_module_args_maps_to_replaced_without_mutating_original():
    module_args = {"state": "staged", "config": [{"name": "BLUE"}]}

    result = crud_module_args(module_args)

    assert result == {"state": "replaced", "config": [{"name": "BLUE"}]}
    assert module_args["state"] == "staged"


def test_staged_query_module_args_maps_to_overridden_without_mutating_original():
    module_args = {"state": "staged", "config": [{"name": "BLUE"}]}

    result = query_module_args(module_args)

    assert result == {"state": "overridden", "config": [{"name": "BLUE"}]}
    assert module_args["state"] == "staged"


def test_non_staged_module_args_are_returned_unchanged():
    module_args = {"state": "merged", "config": []}

    assert crud_module_args(module_args) is module_args
    assert query_module_args(module_args) is module_args


def test_prepare_crud_state_maps_only_staged_to_replaced():
    state_machine = SimpleNamespace(state="overridden", results=SimpleNamespace(state="overridden"))

    prepare_crud_state(state_machine, "staged")

    assert state_machine.state == "replaced"
    assert state_machine.results.state == "staged"


def test_prepare_crud_state_leaves_non_staged_state_unchanged():
    state_machine = SimpleNamespace(state="overridden", results=SimpleNamespace(state="overridden"))

    prepare_crud_state(state_machine, "overridden")

    assert state_machine.state == "overridden"
    assert state_machine.results.state == "overridden"


def test_prepare_crud_state_handles_state_machine_without_results():
    state_machine = SimpleNamespace(state="overridden")

    prepare_crud_state(state_machine, "staged")

    assert state_machine.state == "replaced"
