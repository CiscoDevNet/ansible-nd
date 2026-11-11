# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Switch module backend adapter for common config action execution.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext


class SwitchConfigActionsBackend:
    """
    # Summary

    Execute switch module save and deploy operations through existing fabric utilities.

    ## Raises

    None
    """

    def __init__(
        self,
        fabric_utils: Any,
        register_operation: Callable[[Any, dict[str, Any] | None, dict[str, Any], str], None] | None = None,
    ) -> None:
        """
        # Summary

        Initialize the backend with the switch fabric utility implementation.

        ## Raises

        None
        """
        self.fabric_utils = fabric_utils
        self.register_operation = register_operation

    def _register_operation(self, endpoint: Any, payload: dict[str, Any] | None, response: dict[str, Any], action: str) -> None:
        """
        # Summary

        Forward a completed endpoint call to the module result recorder when configured.

        ## Raises

        None
        """
        if self.register_operation is not None:
            self.register_operation(endpoint, payload, response, action)

    def save(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        """
        # Summary

        Save or recalculate configuration for `fabric_name`.

        ## Raises

        ### Exception

        - Raised by the fabric utility when the controller rejects config save.
        """
        response = self.fabric_utils.save_config()
        self._register_operation(self.fabric_utils.ep_config_save, None, response, "config_save")
        return response

    def deploy_global(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        """
        # Summary

        Deploy all pending fabric configuration.

        ## Raises

        ### Exception

        - Raised by the fabric utility when the controller rejects global deploy.
        """
        response = self.fabric_utils.deploy_config()
        self._register_operation(self.fabric_utils.ep_config_deploy, None, response, "deploy_config")
        return response

    def deploy_switches(self, _context: ConfigActionsContext, _fabric_name: str, switch_ids: tuple[str, ...]) -> Any:
        """
        # Summary

        Deploy pending configuration to the selected switches.

        ## Raises

        ### Exception

        - Raised by the fabric utility when the controller rejects switch deploy.
        """
        payload = {"switchIds": list(switch_ids)}
        response = self.fabric_utils.deploy_switches(payload["switchIds"])
        self._register_operation(self.fabric_utils.ep_switch_deploy, payload, response, "deploy_switches")
        return response

    def deploy_resources(self, _context: ConfigActionsContext, _fabric_name: str, _resources: tuple[str, ...]) -> Any:
        """
        # Summary

        Reject resource-scoped deploy for switch workflows.

        ## Raises

        ### NotImplementedError

        - Always raised because switch workflows support switch and global deploy only.
        """
        raise NotImplementedError("Switch config actions do not support resource deploy.")
