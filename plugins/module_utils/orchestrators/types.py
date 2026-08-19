# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypeAlias

ResponseType: TypeAlias = list[dict[str, Any]] | dict[str, Any] | None


@dataclass(frozen=True)
class FinalizationContext:
    """State-machine context available to orchestrator final-state queries."""

    state: str
    affected_identifiers: tuple[Any, ...] = ()
