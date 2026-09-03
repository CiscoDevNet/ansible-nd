# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Mutation outcomes used to build evidence-backed ND state-machine output."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class MutationOperation(str, Enum):
    """Controller configuration operations represented by a planned effect."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class MutationOutcome(str, Enum):
    """Reconciliation outcome for one logical mutation checkpoint."""

    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    QUEUED = "queued"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class MutationEffect:
    """One planned resource-state transition owned by a checkpoint."""

    operation: MutationOperation
    identifier: Any
    before: NDBaseModel | None
    after: NDBaseModel | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "identifier", deepcopy(self.identifier))
        object.__setattr__(self, "before", deepcopy(self.before))
        object.__setattr__(self, "after", deepcopy(self.after))


@dataclass(frozen=True)
class DeferredMutation:
    """Return receipt for a mutation queued for a later controller write."""

    phase: str


@dataclass
class MutationCheckpoint:
    """Execution and response evidence for one logical controller mutation."""

    sequence_number: int
    phase: str
    effects: tuple[MutationEffect, ...]
    outcome: MutationOutcome = MutationOutcome.NOT_ATTEMPTED
    changed: bool = False
    may_have_changed: bool = False
    error: str | None = None
    api_call_sequences: tuple[int, ...] = ()

    @property
    def affected_identifiers(self) -> tuple[Any, ...]:
        """Return resource identifiers covered by this checkpoint."""
        return tuple(deepcopy(effect.identifier) for effect in self.effects)

    def resolve(
        self,
        outcome: MutationOutcome,
        *,
        changed: bool = False,
        may_have_changed: bool = False,
        error: str | None = None,
        api_call_sequences: Iterable[int] = (),
    ) -> None:
        """Record the checkpoint's final outcome exactly once."""
        if self.outcome is not MutationOutcome.NOT_ATTEMPTED:
            raise ValueError(
                f"Checkpoint {self.sequence_number} is already resolved as {self.outcome.value}"
            )
        self.outcome = outcome
        self.changed = bool(changed)
        self.may_have_changed = bool(may_have_changed)
        self.error = error
        self.api_call_sequences = tuple(api_call_sequences)


@dataclass
class MutationJournal:
    """Ordered logical checkpoints for one state-machine execution."""

    checkpoints: list[MutationCheckpoint] = field(default_factory=list)

    def open(
        self, *, phase: str, effects: Iterable[MutationEffect]
    ) -> MutationCheckpoint:
        """Append and return a not-yet-attempted checkpoint."""
        checkpoint = MutationCheckpoint(
            sequence_number=len(self.checkpoints) + 1,
            phase=phase,
            effects=tuple(effects),
        )
        if not checkpoint.effects:
            raise ValueError("A mutation checkpoint requires at least one effect")
        self.checkpoints.append(checkpoint)
        return checkpoint

    @property
    def changed(self) -> bool:
        """Return whether any checkpoint proves a controller change."""
        return any(checkpoint.changed for checkpoint in self.checkpoints)

    @property
    def may_have_changed(self) -> bool:
        """Return whether uncertain delivery may have changed controller state."""
        return any(checkpoint.may_have_changed for checkpoint in self.checkpoints)

    @property
    def has_unknown(self) -> bool:
        """Return whether any affected scope cannot be reconciled exactly."""
        return any(
            checkpoint.outcome is MutationOutcome.UNKNOWN
            for checkpoint in self.checkpoints
        )

    @property
    def unknown_identifiers(self) -> tuple[Any, ...]:
        """Return de-duplicated identifiers from unknown checkpoints in order."""
        identifiers: list[Any] = []
        for checkpoint in self.checkpoints:
            if checkpoint.outcome is not MutationOutcome.UNKNOWN:
                continue
            for identifier in checkpoint.affected_identifiers:
                if identifier not in identifiers:
                    identifiers.append(identifier)
        return tuple(identifiers)
