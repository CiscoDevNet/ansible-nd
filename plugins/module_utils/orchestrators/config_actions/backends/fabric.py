# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Config actions backend for the fabric save/deploy surface.

Used by every orchestrator whose config actions run against fabric-scoped
``configSave`` / ``actions/deploy`` / ``switchActions/deploy`` endpoints, which
covers the fabric modules, fabric groups, fabric group members and ToR.
"""

from __future__ import annotations

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.backends.base import FabricConfigActionsOwner
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class FabricConfigActionsBackend:
    """
    # Summary

    Execute save and deploy for a fabric surface through the owning orchestrator.

    Implements the `ConfigActionsBackend` protocol so `ConfigActionsController`
    can drive the lifecycle while every request still goes through the
    orchestrator's `_request()` (check-mode simulation, error handling, Results
    tracking).

    Which endpoints are used is decided by the owner's endpoint hooks, so a
    subclass of the owning mixin can retarget this backend at a different surface
    (for example OneManage for a multi-cluster fabric group) without a separate
    backend class.

    ## Raises

    None
    """

    def __init__(self, owner: FabricConfigActionsOwner) -> None:
        """
        # Summary

        Bind the backend to the orchestrator that executes its requests.

        ## Raises

        None
        """
        self.owner = owner

    def save(self, context: ConfigActionsContext, fabric_name: str) -> ResponseType:
        """
        # Summary

        Save (recalculate intent for) `fabric_name`.

        ## Raises

        ### Exception

        - Via the owner when the save API request fails.
        """
        return self.owner.config_save(fabric_name)

    def deploy_global(self, context: ConfigActionsContext, fabric_name: str) -> ResponseType:
        """
        # Summary

        Deploy the entire fabric `fabric_name`.

        ## Raises

        ### Exception

        - Via the owner when the deploy API request fails.
        """
        return self.owner.deploy_global(fabric_name)

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> ResponseType:
        """
        # Summary

        Deploy the switches in `fabric_name` that still need deployment, limited
        to the candidates the caller put in the context.

        `switch_ids` holds candidates captured before `configSave` (fabric
        membership, optionally narrowed by the caller). It is intersected with a
        freshly resolved target list rather than used directly, because
        `configSave` can push a switch that was `inSync` beforehand out of sync.

        ## Raises

        ### Exception

        - Via the owner when the switch query or deploy API request fails.
        """
        candidates = set(switch_ids)
        targets = [switch_id for switch_id in self.owner.resolve_switch_deploy_targets(fabric_name) if switch_id in candidates]
        return self.owner.deploy_switch_ids(fabric_name, targets)

    def deploy_resources(self, context: ConfigActionsContext, fabric_name: str, resources: tuple[str, ...]) -> ResponseType:
        """
        # Summary

        Reject resource-scoped deploy; the fabric surface supports only `global`
        and `switch` deploy.

        ## Raises

        ### ValueError

        - Always, because resource deploy is not supported for fabric config actions.
        """
        raise ValueError("config_actions.type='resource' is not supported for fabric config actions.")
