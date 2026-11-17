# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Delete explicit overlay definitions without detachment or deployment.

The caller owns completing attachment changes and their deployment before this
continuation. Ordinary CRUD discovery and dependency checks still apply, but
finalization adds no attachment-readiness or post-delete absence observations.
The default deleted workflow continues to own detach/deploy/delete.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

NETWORK_DELETE_FINALIZE_VERSION = 1
VRF_DELETE_FINALIZE_VERSION = 1


class OverlayDeletionFinalizer:
    """Delete an explicit standalone Network or VRF set using ordinary CRUD."""

    def __init__(self, coordinator: Any, resource: str):
        if resource not in ("network", "vrf"):
            raise ValueError("Overlay finalization resource must be network or vrf")
        self.coordinator = coordinator
        self.resource = resource
        self.plural = resource + "s"

    def validate_scope(self, module_args: dict, strategy: Any) -> list[str]:
        """Reject implicit or unsupported authority before any workflow writes."""
        if module_args.get("state") != "deleted":
            raise ValueError("deletion_mode=finalize requires state=deleted")
        if strategy.is_parent or strategy.is_child or strategy.is_multicluster or strategy.is_multisite:
            raise ValueError("deletion_mode=finalize supports standalone Manage fabrics only")
        config = module_args.get("config")
        if not isinstance(config, list) or not config:
            raise ValueError("deletion_mode=finalize requires explicit non-empty config")
        names = []
        for index, item in enumerate(config):
            name = item.get(self.resource + "_name") if isinstance(item, dict) else None
            if not isinstance(name, str) or not name or name != name.strip():
                raise ValueError(f"config[{index}] requires an exact {self.resource}_name for finalization")
            if name in names:
                raise ValueError(f"Duplicate finalization target {name!r}")
            if item.get("attach") or item.get("detach") or item.get("child_fabric_config"):
                raise ValueError("deletion_mode=finalize accepts definition selectors without attachment or child operations")
            names.append(name)
        return names

    def run(self, module_args: dict, strategy: Any) -> dict[str, Any]:
        """Delete definitions without invoking attachment processing or deploy."""
        names = self.validate_scope(module_args, strategy)
        # Initialization performs the normal current-state discovery and model
        # validation. Reuse it for deletion planning rather than querying again.
        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            return self._run_initialized(sm, module_args, strategy, names)
        finally:
            self.coordinator._restore_state_machine_params(original_config, original_state)

    def _run_initialized(self, sm: Any, module_args: dict, strategy: Any, names: list[str]) -> dict[str, Any]:
        """Apply existing dependency handling and report definition operations."""
        requested = set(names)
        existing = []
        seen = set()
        for model in sm.existing:
            name = getattr(model, self.resource + "_name", None)
            if not isinstance(name, str):
                value = model.get_identifier_value()
                name = value[0] if isinstance(value, (list, tuple)) else value
            if name in requested:
                if name in seen:
                    raise ValueError("Finalization CRUD snapshot contains duplicate target identities")
                existing.append(name)
                seen.add(name)
        getattr(self.coordinator, "_ensure_" + self.plural + "_have_no_networks")(module_args, strategy, existing)
        request = {"fabric_name": strategy.fabric_name, "resource": self.resource, "names": names}
        sm.manage_state()
        result = self.coordinator._format_state_machine_output(sm)
        result.setdefault("fabric_type", strategy.fabric_type)
        result.setdefault("workflow", f"Standalone Fabric {self.resource.capitalize()} Definition Finalization")
        result["deletion_finalization"] = {
            "version": 1,
            "proof": "definition_only_overlay_deletion_v1",
            **request,
            "request_sha256": hashlib.sha256(json.dumps(request, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "existing_before": existing,
            "detach_attempts": 0,
            "deployment_attempts": 0,
            "deletion_operations_succeeded": None if self.coordinator.module.check_mode else not bool(result.get("failed")),
        }
        return result
