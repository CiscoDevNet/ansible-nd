# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Pure configuration planning shared by state machines and aggregate workflows."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection

SupportedState = Literal["merged", "replaced", "overridden", "deleted"]
SUPPORTED_STATES: frozenset[str] = frozenset({"merged", "replaced", "overridden", "deleted"})


@dataclass(frozen=True)
class NDStatePlan:
    """Immutable operation lists and planned after-state for one resource family."""

    state: str
    before: NDConfigCollection
    proposed: NDConfigCollection
    after: NDConfigCollection
    creates: tuple[NDBaseModel, ...] = ()
    updates: tuple[NDBaseModel, ...] = ()
    deletes: tuple[NDBaseModel, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def changed(self) -> bool:
        """Return whether the plan contains any mutation."""
        return bool(self.creates or self.updates or self.deletes)

    @property
    def mutation_count(self) -> int:
        """Return the total number of planned create, update, and delete operations."""
        return len(self.creates) + len(self.updates) + len(self.deletes)


class NDStatePlanner:
    """Calculate state operations without invoking an orchestrator mutation method."""

    @classmethod
    def plan(
        cls,
        *,
        state: str,
        before: NDConfigCollection,
        proposed: NDConfigCollection,
        ignore_errors: bool = False,
    ) -> NDStatePlan:
        """Return the create/update/delete plan and resulting in-memory state."""
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
                    identifier = proposed_item.get_identifier_value()
                    diff_status = after.get_diff_config(proposed_item, exclude_unset=state == "merged")
                    if diff_status == "no_diff":
                        continue

                    if state == "merged":
                        final_item = after.merge(proposed_item)
                    else:
                        if diff_status == "changed":
                            after.replace(proposed_item)
                        else:
                            after.add(proposed_item)
                        final_item = proposed_item

                    if diff_status == "changed":
                        updates.append(final_item)
                    elif diff_status == "new":
                        creates.append(final_item)
                except Exception as exc:
                    message = f"Failed to process {identifier}: {exc}" if identifier is not None else f"Failed to process: {exc}"
                    if not ignore_errors:
                        raise ValueError(message) from exc
                    errors.append(message)

            if state == "overridden":
                diff_identifiers = before.get_diff_identifiers(proposed)
                deletes = [existing_item for identifier in diff_identifiers if (existing_item := after.get(identifier)) is not None]
                after.delete_many([item.get_identifier_value() for item in deletes])

        elif state == "deleted":
            deletes = [existing_item for proposed_item in proposed if (existing_item := after.get(proposed_item.get_identifier_value())) is not None]
            after.delete_many([item.get_identifier_value() for item in deletes])

        return NDStatePlan(
            state=state,
            before=before,
            proposed=proposed,
            after=after,
            creates=tuple(creates),
            updates=tuple(updates),
            deletes=tuple(deletes),
            errors=tuple(errors),
        )
