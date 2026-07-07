# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ConfigActionsMixin — composable mixin for fabric config save/deploy operations.

Add this mixin to any NDBaseOrchestrator subclass that needs to save and/or deploy
fabric configuration after CRUD operations. The mixin reuses the orchestrator's
existing ``_request()`` method, so check-mode simulation, error handling, and
Results tracking (API call registration) are all handled automatically.

Usage::

    class MyFabricOrchestrator(ConfigActionsMixin, NDBaseOrchestrator):
        ...

Then from the module or state machine::

    orchestrator.config_save(fabric_name="my-fabric")
    orchestrator.config_deploy(fabric_name="my-fabric", deploy_type="global")

Or use the convenience method to process a batch::

    orchestrator.execute_config_actions(
        fabric_names=["fab1", "fab2"],
        save=True, deploy=True, deploy_type="switch",
    )
"""

from __future__ import annotations

from typing import List

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_config_save import (
    EpFabricConfigSavePost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_actions_deploy import (
    EpFabricDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switches import (
    EpManageFabricsSwitchesGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switchactions import (
    EpManageFabricsSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class ConfigActionsMixin:
    """Mixin providing fabric config save and deploy operations.

    Designed to be composed with NDBaseOrchestrator (or subclasses). Relies on
    the host class providing ``_request()`` with the standard signature.

    Deploy types:
        - ``"global"``: Deploys the entire fabric via
          ``/fabrics/{fabricName}/actions/deploy`` (no request body).
        - ``"switch"``: Queries switches needing deployment via
          ``/fabrics/{fabricName}/switches``, filters by ``configSyncStatus``,
          then deploys to those switches via
          ``/fabrics/{fabricName}/switchActions/deploy`` with
          ``{"switchIds": [...]}``.
    """

    def config_save(self, fabric_name: str) -> ResponseType:
        """Save fabric configuration.

        Triggers intent recalculation for the entire fabric via
        ``/fabrics/{fabricName}/actions/configSave``. No request body.

        Args:
            fabric_name: Name of the fabric to save.

        Returns:
            API response data.

        Raises:
            Exception: If the save request fails.
        """
        ep = EpFabricConfigSavePost(fabric_name=fabric_name)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            operation_type=OperationType.UPDATE,
        )

    def config_deploy(self, fabric_name: str, deploy_type: str = "global") -> ResponseType:
        """Deploy fabric configuration.

        Args:
            fabric_name: Name of the fabric to deploy.
            deploy_type: ``"global"`` for fabric-wide deploy, ``"switch"`` for
                switch-level deploy targeting only out-of-sync switches.

        Returns:
            API response data, or None if no switches need deployment
            (switch-level only).

        Raises:
            ValueError: If deploy_type is not "global" or "switch".
            Exception: If the deploy request fails.
        """
        if deploy_type == "global":
            return self._deploy_global(fabric_name)
        elif deploy_type == "switch":
            return self._deploy_switches(fabric_name)
        else:
            raise ValueError(f"Invalid deploy_type '{deploy_type}'. Must be 'global' or 'switch'.")

    def _deploy_global(self, fabric_name: str) -> ResponseType:
        """Deploy entire fabric configuration (no request body)."""
        ep = EpFabricDeployPost(fabric_name=fabric_name)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            operation_type=OperationType.UPDATE,
        )

    def _deploy_switches(self, fabric_name: str) -> ResponseType:
        """Deploy to switches that need configuration deployment.

        Queries the fabric's switches, identifies those with a
        ``configSyncStatus`` that is not ``inSync``, and deploys
        to them via the switchActions/deploy endpoint.

        Returns None if all switches are already in sync.
        """
        switch_ids = self._get_switches_needing_deploy(fabric_name)
        if not switch_ids:
            return None

        ep = EpManageFabricsSwitchActionsDeployPost(fabric_name=fabric_name)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            data={"switchIds": switch_ids},
            operation_type=OperationType.UPDATE,
        )

    def _get_switches_needing_deploy(self, fabric_name: str) -> List[str]:
        """Query fabric switches and return serial numbers needing deployment.

        A switch needs deployment if its ``configSyncStatus`` is not ``inSync``.
        """
        ep = EpManageFabricsSwitchesGet(fabric_name=fabric_name)
        result = self._request(
            path=ep.path,
            verb=ep.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )

        switches = result.get("switches", []) if result else []
        switch_ids = []
        for switch in switches:
            additional_data = switch.get("additionalData", {})
            config_status = additional_data.get("configSyncStatus", "")
            if config_status and config_status != "inSync":
                serial_number = switch.get("serialNumber", "")
                if serial_number:
                    switch_ids.append(serial_number)
        return switch_ids

    def execute_config_actions(
        self,
        fabric_names: List[str],
        save: bool = False,
        deploy: bool = False,
        deploy_type: str = "global",
    ) -> None:
        """Execute config save and/or deploy for a list of fabrics.

        Args:
            fabric_names: List of fabric names to process.
            save: Whether to save configuration.
            deploy: Whether to deploy configuration (requires save=True).
            deploy_type: ``"global"`` or ``"switch"`` (default: "global").

        Raises:
            ValueError: If deploy=True but save=False.
            Exception: If any save or deploy request fails.
        """
        if deploy and not save:
            raise ValueError("config_actions: deploy=True requires save=True")

        if not save and not deploy:
            return

        for fabric_name in fabric_names:
            if save:
                self.config_save(fabric_name)
            if deploy:
                self.config_deploy(fabric_name, deploy_type)
