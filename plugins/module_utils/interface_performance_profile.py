# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Opt-in, execution-scoped measurements for interface workflow experiments.

Only aggregate sizes and timings are retained.  Payloads, responses, paths,
credentials, and interface names are never placed in the result.
"""

from __future__ import annotations

import json
from collections import defaultdict
from contextlib import contextmanager
from time import monotonic, process_time
from typing import Any, Iterator


class InterfacePerformanceProfile:
    """Collect inclusive phase time and exact transport-attempt counts."""

    def __init__(self) -> None:
        self._phase_stack: list[str] = []
        self._phases: dict[str, dict[str, float | int]] = defaultdict(lambda: {"calls": 0, "wall_seconds": 0.0, "cpu_seconds": 0.0})
        self._requests: dict[str, dict[str, float | int]] = defaultdict(
            lambda: {
                "count": 0,
                "wall_seconds": 0.0,
                "cpu_seconds": 0.0,
                "request_json_bytes": 0,
                "response_json_bytes": 0,
            }
        )
        self._bulk_update_decisions: dict[str, int] = defaultdict(int)

    def record_bulk_update_decision(self, reason: str) -> None:
        """Count one credential-free fast-path decision."""
        self._bulk_update_decisions[reason] += 1

    @contextmanager
    def phase(self, name: str) -> Iterator[None]:
        """Time one inclusive section, allowing nested inventory/safety reads."""
        start_wall, start_cpu = monotonic(), process_time()
        self._phase_stack.append(name)
        try:
            yield
        finally:
            self._phase_stack.pop()
            record = self._phases[name]
            record["calls"] += 1
            record["wall_seconds"] += monotonic() - start_wall
            record["cpu_seconds"] += process_time() - start_cpu

    @staticmethod
    def _json_bytes(value: Any) -> int:
        if value is None:
            return 0
        try:
            return len(json.dumps(value, separators=(",", ":"), default=str).encode("utf-8"))
        except (TypeError, ValueError):
            return 0

    def record_request(
        self,
        *,
        verb: str,
        path: str,
        payload: Any,
        response: Any,
        start_wall: float,
        start_cpu: float,
    ) -> None:
        """Record one sender attempt, including retries and rejected writes."""
        if "interfacesSummary" in path:
            category = "safety_summary"
        elif verb == "GET" and "/interfaces/" in path:
            category = "exact_interface"
        elif verb == "GET" and "/interfaces" in path:
            category = "interface_inventory"
        elif verb == "GET" or path.endswith("/preview"):
            category = "other_read"
        else:
            category = "write"
        key = f"{self._phase_stack[-1] if self._phase_stack else 'unscoped'}:{category}:{verb}"
        record = self._requests[key]
        record["count"] += 1
        record["wall_seconds"] += monotonic() - start_wall
        record["cpu_seconds"] += process_time() - start_cpu
        record["request_json_bytes"] += self._json_bytes(payload)
        record["response_json_bytes"] += self._json_bytes(response)

    def to_dict(self) -> dict[str, Any]:
        """Return rounded, credential-free measurements for a module result."""

        def normalized(
            records: dict[str, dict[str, float | int]],
        ) -> dict[str, dict[str, float | int]]:
            return {
                name: {key: round(value, 6) if isinstance(value, float) else value for key, value in metrics.items()}
                for name, metrics in sorted(records.items())
            }

        return {
            "phases": normalized(self._phases),
            "requests": normalized(self._requests),
            "bulk_update_decisions": dict(sorted(self._bulk_update_decisions.items())),
            "byte_definition": "UTF-8 JSON payload/response sizes after parsing; excludes HTTP headers, TLS, and transport framing",
        }
