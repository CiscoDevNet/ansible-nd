# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Backend protocol for config action endpoint execution.
"""

from __future__ import annotations

from typing import Any, Protocol

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext


class ConfigActionsBackend(Protocol):
    """
    # Summary

    Protocol implemented by endpoint-specific config action backends.

    ## Raises

    None
    """

    def save(self, context: ConfigActionsContext, fabric_name: str) -> Any:
        """
        # Summary

        Save or recalculate configuration for `fabric_name`.

        ## Raises

        Exception
        """

    def deploy_global(self, context: ConfigActionsContext, fabric_name: str) -> Any:
        """
        # Summary

        Deploy an entire fabric.

        ## Raises

        Exception
        """

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> Any:
        """
        # Summary

        Deploy selected switches.

        ## Raises

        Exception
        """

    def deploy_resources(self, context: ConfigActionsContext, fabric_name: str, resources: tuple[str, ...]) -> Any:
        """
        # Summary

        Deploy selected resources.

        ## Raises

        Exception
        """
