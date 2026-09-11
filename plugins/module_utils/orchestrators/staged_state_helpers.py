# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Shared helpers for staged resource workflow state mapping."""

from __future__ import annotations

from typing import Any

STAGED_STATE = "staged"
STAGED_CRUD_STATE = "replaced"
STAGED_QUERY_STATE = "overridden"


def crud_module_args(module_args: dict) -> dict:
    """
    # Summary

    Return module arguments for the CRUD state machine.

    The staged workflow uses replaced CRUD behavior so desired resources are
    created or updated without deleting omitted resources.

    Args:
        module_args: Original module arguments.

    Returns:
        Original module arguments, or a shallow copy with staged mapped to replaced.

    ## Raises

    This function does not raise directly.
    """
    if module_args.get("state") != STAGED_STATE:
        return module_args
    crud_args = dict(module_args)
    crud_args["state"] = STAGED_CRUD_STATE
    return crud_args


def query_module_args(module_args: dict) -> dict:
    """
    # Summary

    Return module arguments for the current-state query phase.

    The staged workflow uses overridden query behavior with an empty config so
    omitted resources can be discovered without validating desired write data
    under the overridden state context.

    Args:
        module_args: Original module arguments.

    Returns:
        Original module arguments, or a shallow copy with staged mapped to overridden
        and config cleared for query-only discovery.

    ## Raises

    This function does not raise directly.
    """
    if module_args.get("state") != STAGED_STATE:
        return module_args
    query_args = dict(module_args)
    query_args["state"] = STAGED_QUERY_STATE
    query_args["config"] = []
    return query_args


def prepare_crud_state(state_machine: Any, requested_state: str) -> None:
    """
    # Summary

    Switch staged workflows to replacement CRUD after the query phase.

    The CRUD state is internal.  Public result metadata remains the
    user-requested staged state so verbose API metadata reflects the task that
    the user ran.

    Args:
        state_machine: Generic CRUD state machine instance.
        requested_state: Original requested module state.

    Returns:
        None.

    ## Raises

    This function does not raise directly.
    """
    if requested_state != STAGED_STATE:
        return
    state_machine.state = STAGED_CRUD_STATE
    results = getattr(state_machine, "results", None)
    if results is not None:
        results.state = STAGED_STATE
