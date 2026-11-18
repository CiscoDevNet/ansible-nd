# Copyright: (c) 2026, Cisco and contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Backend adapter for resource configuration deploy endpoints."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext


class ResourceConfigActionsBackend:
    """Translate shared controller targets into resource endpoint payloads."""

    def __init__(
        self,
        resource_payload_key: str,
        deploy: Callable[[dict[str, Any]], Any],
        switch_deploy: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        self.resource_payload_key = resource_payload_key
        self.deploy = deploy
        self.switch_deploy = switch_deploy

    def save(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        raise ValueError("save is not supported for resource config actions.")

    def deploy_global(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        raise ValueError("global deploy is not supported for resource config actions.")

    def deploy_switches(self, context: ConfigActionsContext, _fabric_name: str, switch_ids: tuple[str, ...]) -> Any:
        payload = {"switchIds": list(switch_ids)}
        if self.switch_deploy is not None:
            return self.switch_deploy(payload)
        payload[self.resource_payload_key] = list(context.resources)
        return self.deploy(payload)

    def deploy_resources(self, context: ConfigActionsContext, _fabric_name: str, resources: tuple[str, ...]) -> Any:
        payload = {self.resource_payload_key: list(resources)}
        if context.switch_ids:
            payload["switchIds"] = list(context.switch_ids)
        return self.deploy(payload)
