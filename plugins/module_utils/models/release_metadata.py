# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NDMinimumVersion:
    """Internal Pydantic field metadata declaring the earliest supported ND product version."""

    value: str
