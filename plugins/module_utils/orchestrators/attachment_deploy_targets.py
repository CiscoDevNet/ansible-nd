# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Task-local switch selection for VRF and Network deployment."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class RequestedSwitchTargets:
    """Select deployment targets from the unexpanded attachment request."""

    def __init__(self, attachments: dict[tuple[str, str], dict[str, Any]]):
        self.by_resource: dict[str, set[str]] = {}
        self.switch_ids: set[str] = set()
        for resource_name, switch_id in attachments:
            self.by_resource.setdefault(resource_name, set()).add(switch_id)
            self.switch_ids.add(switch_id)

    def select(
        self,
        changed_targets: dict[str, set[str]],
        pending_targets: Callable[[], dict[str, set[str]]] | None = None,
    ) -> dict[str, set[str]]:
        """Combine selected changes with pending work when it can add a switch."""
        selected: dict[str, set[str]] = {}
        self._add_selected(selected, changed_targets)
        covered = {switch_id for switch_ids in selected.values() for switch_id in switch_ids}
        if pending_targets is not None and not self.switch_ids.issubset(covered):
            self._add_selected(selected, pending_targets())
        return selected

    def _add_selected(self, selected: dict[str, set[str]], target_map: dict[str, set[str]]) -> None:
        for resource_name, switch_ids in (target_map or {}).items():
            allowed = self.by_resource.get(resource_name, self.switch_ids)
            selected.setdefault(resource_name, set()).update(switch_ids.intersection(allowed))
