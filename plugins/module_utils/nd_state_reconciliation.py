# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Evidence-backed mutation effects, compatible with homogeneous checkpoints."""

from __future__ import annotations

from collections.abc import Iterable
from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class MutationOperation(str, Enum):
    """A requested state transition, not an HTTP method."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


class MutationOutcome(str, Enum):
    """Whether mutation evidence proves an effect or leaves it uncertain."""

    NOT_ATTEMPTED = "not_attempted"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, init=False)
class MutationEffect:
    """One resource transition with defensively retained model snapshots."""

    operation: MutationOperation
    identifier: Any
    _before: NDBaseModel | None = field(repr=False)
    _after: NDBaseModel | None = field(repr=False)

    def __init__(self, operation: MutationOperation, identifier: Any, before: NDBaseModel | None, after: NDBaseModel | None):
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "identifier", deepcopy(identifier))
        object.__setattr__(self, "_before", deepcopy(before))
        object.__setattr__(self, "_after", deepcopy(after))

    @property
    def before(self) -> NDBaseModel | None:
        """Return an isolated initial resource snapshot."""
        return deepcopy(self._before)

    @property
    def after(self) -> NDBaseModel | None:
        """Return an isolated prospective resource snapshot."""
        return deepcopy(self._after)


@dataclass(frozen=True, init=False)
class MutationResourceOutcome:
    """API-independent result correlated to one requested resource identifier."""

    identifier: Any
    outcome: MutationOutcome
    _statuses: tuple[Any, ...] = field(repr=False)
    _messages: tuple[Any, ...] = field(repr=False)
    _evidence: tuple[Any, ...] = field(repr=False)

    def __init__(self, identifier: Any, outcome: MutationOutcome, *, statuses: Iterable[Any] = (), messages: Iterable[Any] = (), evidence: Iterable[Any] = ()):
        object.__setattr__(self, "identifier", deepcopy(identifier))
        object.__setattr__(self, "outcome", outcome)
        object.__setattr__(self, "_statuses", tuple(deepcopy(tuple(statuses))))
        object.__setattr__(self, "_messages", tuple(deepcopy(tuple(messages))))
        object.__setattr__(self, "_evidence", tuple(deepcopy(tuple(evidence))))

    @property
    def statuses(self) -> tuple[Any, ...]:
        """Return isolated controller statuses."""
        return deepcopy(self._statuses)

    @property
    def messages(self) -> tuple[Any, ...]:
        """Return isolated controller messages."""
        return deepcopy(self._messages)

    @property
    def evidence(self) -> tuple[Any, ...]:
        """Return isolated controller/correlation evidence."""
        return deepcopy(self._evidence)


@dataclass(frozen=True)
class MutationResult:
    """Normalized per-resource outcomes returned without raising semantic failures."""

    outcomes: tuple[MutationResourceOutcome, ...] = ()
    protocol_errors: tuple[str, ...] = ()

    def __post_init__(self):
        object.__setattr__(self, "outcomes", tuple(deepcopy(self.outcomes)))
        object.__setattr__(self, "protocol_errors", tuple(self.protocol_errors))


@dataclass
class MutationCheckpoint:
    """One real request, which may contain differently resolved resource effects."""

    sequence_number: int
    phase: str
    effects: tuple[MutationEffect, ...]
    outcome: MutationOutcome = MutationOutcome.NOT_ATTEMPTED
    changed: bool = False
    may_have_changed: bool = False
    error: str | None = None
    api_call_sequences: tuple[int, ...] = ()
    resource_outcomes: tuple[MutationResourceOutcome, ...] = ()

    def __post_init__(self):
        keys = self.affected_identifiers
        if len(set(keys)) != len(keys):
            raise ValueError("Duplicate expected mutation identifiers")

    @property
    def affected_identifiers(self) -> tuple[Any, ...]:
        """Return this request's exact expected correlation keys."""
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
        """Retain the homogeneous request-level contract from PR #525."""
        if self.outcome is not MutationOutcome.NOT_ATTEMPTED:
            raise ValueError(f"Checkpoint {self.sequence_number} is already resolved as {self.outcome.value}")
        if outcome is MutationOutcome.NOT_ATTEMPTED:
            raise ValueError("Resolution requires an attempted outcome")
        self.outcome = outcome
        self.changed = bool(changed)
        self.may_have_changed = bool(may_have_changed)
        self.error = error
        self.api_call_sequences = tuple(api_call_sequences)

    def resolve_resources(self, result: MutationResult) -> None:
        """Validate exact coverage and retain successes even in a failed request."""
        if self.outcome is not MutationOutcome.NOT_ATTEMPTED:
            raise ValueError(f"Checkpoint {self.sequence_number} is already resolved as {self.outcome.value}")
        expected = self.affected_identifiers
        errors = list(result.protocol_errors)
        grouped: dict[Any, list[MutationResourceOutcome]] = {}
        for item in result.outcomes:
            if item.identifier not in expected:
                errors.append(f"Unexpected outcome identifier {item.identifier!r}")
                continue
            grouped.setdefault(item.identifier, []).append(item)
        normalized = []
        for key in expected:
            items = grouped.get(key, [])
            if len(items) == 1 and items[0].outcome in (MutationOutcome.SUCCEEDED, MutationOutcome.FAILED, MutationOutcome.UNKNOWN):
                normalized.append(items[0])
                continue
            errors.append(f"Missing or duplicate outcome for {key!r}")
            normalized.append(
                MutationResourceOutcome(
                    key,
                    MutationOutcome.UNKNOWN,
                    statuses=tuple(status for item in items for status in item.statuses),
                    messages=tuple(message for item in items for message in item.messages),
                    evidence=tuple(evidence for item in items for evidence in item.evidence),
                )
            )
        states = {item.outcome for item in normalized}
        unknown = bool(errors) or MutationOutcome.UNKNOWN in states
        aggregate = MutationOutcome.UNKNOWN if unknown else (MutationOutcome.FAILED if MutationOutcome.FAILED in states else MutationOutcome.SUCCEEDED)
        self.resource_outcomes = tuple(normalized)
        self.resolve(
            aggregate,
            changed=MutationOutcome.SUCCEEDED in states,
            may_have_changed=unknown,
            error="; ".join(errors) or ("One or more resource effects failed or are unknown" if aggregate is not MutationOutcome.SUCCEEDED else None),
        )

    @property
    def confirmed_effects(self) -> tuple[MutationEffect, ...]:
        """Return proven successes, independently of the aggregate request outcome."""
        if self.resource_outcomes:
            keys = {item.identifier for item in self.resource_outcomes if item.outcome is MutationOutcome.SUCCEEDED}
            return tuple(effect for effect in self.effects if effect.identifier in keys)
        return self.effects if self.outcome is MutationOutcome.SUCCEEDED else ()

    @property
    def unknown_identifiers(self) -> tuple[Any, ...]:
        """Return only uncertain scopes, not known successes from the same request."""
        if self.resource_outcomes:
            return tuple(item.identifier for item in self.resource_outcomes if item.outcome is MutationOutcome.UNKNOWN)
        return self.affected_identifiers if self.outcome is MutationOutcome.UNKNOWN else ()


@dataclass
class MutationJournal:
    """Ordered request checkpoints; failure, change and certainty are independent."""

    checkpoints: list[MutationCheckpoint] = field(default_factory=list)

    def open(self, *, phase: str, effects: Iterable[MutationEffect]) -> MutationCheckpoint:
        """Register one request before entering its mutation method."""
        checkpoint = MutationCheckpoint(len(self.checkpoints) + 1, phase, tuple(effects))
        if not checkpoint.effects:
            raise ValueError("A mutation checkpoint requires at least one effect")
        self.checkpoints.append(checkpoint)
        return checkpoint

    @property
    def changed(self) -> bool:
        return any(checkpoint.changed for checkpoint in self.checkpoints)

    @property
    def may_have_changed(self) -> bool:
        return any(checkpoint.may_have_changed for checkpoint in self.checkpoints)

    @property
    def has_unknown(self) -> bool:
        return any(checkpoint.outcome is MutationOutcome.UNKNOWN for checkpoint in self.checkpoints)

    @property
    def has_failed(self) -> bool:
        return any(checkpoint.outcome in (MutationOutcome.FAILED, MutationOutcome.UNKNOWN) for checkpoint in self.checkpoints)

    @property
    def unknown_identifiers(self) -> tuple[Any, ...]:
        identifiers: list[Any] = []
        for checkpoint in self.checkpoints:
            for identifier in checkpoint.unknown_identifiers:
                if identifier not in identifiers:
                    identifiers.append(identifier)
        return tuple(identifiers)
