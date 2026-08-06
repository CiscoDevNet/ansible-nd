# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Switch module backend adapter for common config action execution.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext


class SwitchConfigActionsBackend:
    """
    # Summary

    Execute switch module save and deploy operations through existing fabric utilities.

    ## Raises

    None
    """

    def __init__(self, fabric_utils: Any) -> None:
        """
        # Summary

        Initialize the backend with the switch fabric utility implementation.

        ## Raises

        None
        """
        self.fabric_utils = fabric_utils

    def save(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        """
        # Summary

        Save or recalculate configuration for `fabric_name`.

        ## Raises

        Exception
        """
        return self.fabric_utils.save_config()

    def deploy_global(self, _context: ConfigActionsContext, _fabric_name: str) -> Any:
        """
        # Summary

        Deploy all pending fabric configuration.

        ## Raises

        Exception
        """
        return self.fabric_utils.deploy_config()

    def deploy_switches(self, _context: ConfigActionsContext, _fabric_name: str, switch_ids: tuple[str, ...]) -> Any:
        """
        # Summary

        Deploy pending configuration to the selected switches.

        ## Raises

        Exception
        """
        return self.fabric_utils.deploy_switches(list(switch_ids))

    def deploy_resources(self, _context: ConfigActionsContext, _fabric_name: str, _resources: tuple[str, ...]) -> Any:
        """
        # Summary

        Reject resource-scoped deploy for switch workflows.

        ## Raises

        ### NotImplementedError

        - Always raised because switch workflows support switch and global deploy only.
        """
        raise NotImplementedError("Switch config actions do not support resource deploy.")
