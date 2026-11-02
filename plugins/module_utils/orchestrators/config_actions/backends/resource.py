# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Backend adapter for VRF and Network config-action deploy endpoints."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext


class ResourceConfigActionsBackend:
    """Translate common controller targets into a resource deploy payload."""

    def __init__(self, resource_payload_key: str, deploy: Callable[[dict[str, Any]], Any]) -> None:
        self.resource_payload_key = resource_payload_key
        self.deploy = deploy

    def save(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        raise ValueError("save is not supported for resource config actions.")

    def deploy_global(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        raise ValueError("global deploy is not supported for resource config actions.")

    def deploy_switches(self, context: ConfigActionsContext, _fabric_name: str, switch_ids: tuple[str, ...]) -> Any:
        return self.deploy(
            {
                self.resource_payload_key: list(context.resources),
                "switchIds": list(switch_ids),
            }
        )

    def deploy_resources(self, context: ConfigActionsContext, _fabric_name: str, resources: tuple[str, ...]) -> Any:
        return self.deploy({self.resource_payload_key: list(resources)})
