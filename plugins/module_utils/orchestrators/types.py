# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

from dataclasses import dataclass
from typing import Any, Union, List, Dict

ResponseType = Union[List[Dict[str, Any]], Dict[str, Any], None]


@dataclass(frozen=True)
class FinalizationContext:
    """Confirmed and unresolved scope available to a final-state query."""

    state: str
    affected_identifiers: tuple[Any, ...]
    confirmed_identifiers: tuple[Any, ...]
