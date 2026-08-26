# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pure configuration planning shared by state machines and aggregate workflows."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Literal, Sequence

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)

SupportedState = Literal["merged", "replaced", "overridden", "deleted"]
SUPPORTED_STATES: frozenset[str] = frozenset(
    {"merged", "replaced", "overridden", "deleted"}
)


@dataclass(frozen=True, init=False)
class NDStatePlan:
    """Immutable public snapshot of one resource family's planned operations.

    ``NDConfigCollection`` and ``NDBaseModel`` are mutable.  The plan therefore
    owns private deep copies and returns defensive copies from every public
    collection or operation property.  A caller can safely pass an operation
    model to an orchestrator that enriches or otherwise mutates it without
    changing the stored plan or its planned ``after`` state.
    """

    state: str
    _before: NDConfigCollection = field(repr=False)
    _proposed: NDConfigCollection = field(repr=False)
    _after: NDConfigCollection = field(repr=False)
    _creates: tuple[NDBaseModel, ...] = field(repr=False)
    _updates: tuple[NDBaseModel, ...] = field(repr=False)
    _deletes: tuple[NDBaseModel, ...] = field(repr=False)
    _errors: tuple[str, ...] = field(repr=False)

    def __init__(
        self,
        *,
        state: str,
        before: NDConfigCollection,
        proposed: NDConfigCollection,
        after: NDConfigCollection,
        creates: Sequence[NDBaseModel] = (),
        updates: Sequence[NDBaseModel] = (),
        deletes: Sequence[NDBaseModel] = (),
        errors: Sequence[str] = (),
    ) -> None:
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "_before", before.copy())
        object.__setattr__(self, "_proposed", proposed.copy())
        object.__setattr__(self, "_after", after.copy())
        object.__setattr__(self, "_creates", tuple(deepcopy(tuple(creates))))
        object.__setattr__(self, "_updates", tuple(deepcopy(tuple(updates))))
        object.__setattr__(self, "_deletes", tuple(deepcopy(tuple(deletes))))
        object.__setattr__(self, "_errors", tuple(errors))

    @property
    def before(self) -> NDConfigCollection:
        """Return an isolated copy of the initial-state snapshot."""
        return self._before.copy()

    @property
    def proposed(self) -> NDConfigCollection:
        """Return an isolated copy of the proposed-state snapshot."""
        return self._proposed.copy()

    @property
    def after(self) -> NDConfigCollection:
        """Return an isolated copy of the planned after-state snapshot."""
        return self._after.copy()

    @property
    def creates(self) -> tuple[NDBaseModel, ...]:
        """Return isolated models planned for creation."""
        return tuple(deepcopy(self._creates))

    @property
    def updates(self) -> tuple[NDBaseModel, ...]:
        """Return isolated models planned for update."""
        return tuple(deepcopy(self._updates))

    @property
    def deletes(self) -> tuple[NDBaseModel, ...]:
        """Return isolated models planned for deletion."""
        return tuple(deepcopy(self._deletes))

    @property
    def errors(self) -> tuple[str, ...]:
        """Return planning errors suppressed by ``ignore_errors``."""
        return self._errors

    @property
    def changed(self) -> bool:
        """Return whether the plan contains any mutation."""
        return bool(self._creates or self._updates or self._deletes)

    @property
    def mutation_count(self) -> int:
        """Return the total number of planned create, update, and delete operations."""
        return len(self._creates) + len(self._updates) + len(self._deletes)


class NDStatePlanner:
    """Calculate state operations without invoking an orchestrator mutation method."""

    @staticmethod
    def _error_message(identifier, exc: Exception) -> str:
        """Return a consistent per-item planning error."""
        if identifier is None:
            return f"Failed to process: {exc}"
        return f"Failed to process {identifier}: {exc}"

    @classmethod
    def plan(
        cls,
        *,
        state: str,
        before: NDConfigCollection,
        proposed: NDConfigCollection,
        ignore_errors: bool = False,
    ) -> NDStatePlan:
        """Return create/update/delete operations and their prospective state."""
        if state not in SUPPORTED_STATES:
            raise ValueError(f"Invalid state: {state}")

        after = before.copy()
        creates: list[NDBaseModel] = []
        updates: list[NDBaseModel] = []
        deletes: list[NDBaseModel] = []
        errors: list[str] = []

        if state in {"merged", "replaced", "overridden"}:
            for proposed_item in proposed:
                identifier = None
                try:
                    # Plan each item against a disposable collection.  If an
                    # item-specific merge raises after partially mutating its
                    # receiver, ``ignore_errors`` cannot leak that partial state
                    # into the final plan.
                    candidate_after = after.copy()
                    working_item = deepcopy(proposed_item)
                    identifier = working_item.get_identifier_value()
                    diff_status = candidate_after.get_diff_config(
                        working_item, exclude_unset=state == "merged"
                    )
                    if diff_status == "no_diff":
                        continue

                    if state == "merged":
                        final_item = candidate_after.merge(working_item)
                    else:
                        if diff_status == "changed":
                            candidate_after.replace(working_item)
                        else:
                            candidate_after.add(working_item)
                        final_item = working_item

                    after = candidate_after
                    if diff_status == "changed":
                        updates.append(final_item)
                    elif diff_status == "new":
                        creates.append(final_item)
                except Exception as exc:
                    message = cls._error_message(identifier, exc)
                    if not ignore_errors:
                        raise ValueError(message) from exc
                    errors.append(message)

            if state == "overridden":
                proposed_identifiers = set(proposed.keys())
                deletes = [
                    item
                    for item in after
                    if item.get_identifier_value() not in proposed_identifiers
                ]
                after.delete_many([item.get_identifier_value() for item in deletes])

        elif state == "deleted":
            for proposed_item in proposed:
                identifier = None
                try:
                    identifier = proposed_item.get_identifier_value()
                    existing_item = after.get(identifier)
                    if existing_item is None:
                        continue
                    deletes.append(existing_item)
                    after.delete(identifier)
                except Exception as exc:
                    message = cls._error_message(identifier, exc)
                    if not ignore_errors:
                        raise ValueError(message) from exc
                    errors.append(message)

        return NDStatePlan(
            state=state,
            before=before,
            proposed=proposed,
            after=after,
            creates=creates,
            updates=updates,
            deletes=deletes,
            errors=errors,
        )
