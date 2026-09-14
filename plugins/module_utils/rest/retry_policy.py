# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Explicit retry policy for a scoped set of REST requests."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RestRetryPolicy:
    """Bound HTTP request attempts independently from legacy timeout behavior."""

    attempts: int
    interval: int
    retry_transport_errors: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise TypeError("attempts must be an integer")
        if self.attempts < 1:
            raise ValueError("attempts must be greater than or equal to 1")
        if isinstance(self.interval, bool) or not isinstance(self.interval, int):
            raise TypeError("interval must be an integer")
        if self.interval < 0:
            raise ValueError("interval must be greater than or equal to 0")
        if not isinstance(self.retry_transport_errors, bool):
            raise TypeError("retry_transport_errors must be a boolean")
