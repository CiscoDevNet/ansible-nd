# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Owner contract shared by fabric-surface config action backends.

Backends in this package are constructed with an owning orchestrator and reach
back into it to execute requests, so that check-mode simulation, error handling
and Results tracking stay in one place. `FabricConfigActionsOwner` declares that
contract explicitly, so a backend never depends on a concrete orchestrator class
and no import cycle exists between a backend and the mixin that selects it.
"""

from __future__ import annotations

from typing import Any, Protocol


class FabricConfigActionsOwner(Protocol):
    """
    # Summary

    Operations a fabric-surface config actions backend requires from its owner.

    Implemented by `ConfigActionsMixin`. Any orchestrator composing that mixin
    satisfies this contract.

    ## Raises

    None
    """

    def config_save(self, fabric_name: str) -> Any:
        """
        # Summary

        Save (recalculate intent for) `fabric_name`.

        ## Raises

        ### Exception

        - Raised by the implementation when the save request fails.
        """

    def deploy_global(self, fabric_name: str) -> Any:
        """
        # Summary

        Deploy the entire fabric `fabric_name`.

        ## Raises

        ### Exception

        - Raised by the implementation when the deploy request fails.
        """

    def deploy_switch_ids(self, fabric_name: str, switch_ids: list[str]) -> Any:
        """
        # Summary

        Deploy `switch_ids` in `fabric_name`.

        ## Raises

        ### Exception

        - Raised by the implementation when the switch deploy request fails.
        """

    def resolve_switch_deploy_targets(self, fabric_name: str) -> list[str]:
        """
        # Summary

        Return the switches in `fabric_name` that currently need deployment.

        ## Raises

        ### Exception

        - Raised by the implementation when the switches query fails.
        """
