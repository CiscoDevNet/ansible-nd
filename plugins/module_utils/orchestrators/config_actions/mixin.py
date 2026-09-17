# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Matt Tarkington (@mtarking)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
ConfigActionsMixin — orchestrator-side entry point for fabric config save/deploy.

Compose this mixin into any ``NDBaseOrchestrator`` subclass whose config actions
run against fabric-scoped ``configSave`` / ``actions/deploy`` /
``switchActions/deploy`` endpoints. It plugs the orchestrator into the shared
``config_actions`` framework: it supplies a
:class:`FabricConfigActionsBackend` that reuses the orchestrator's ``_request()``
(so check-mode simulation, error handling and Results tracking are automatic) and
delegates planning and execution to :class:`ConfigActionsController`.

Consumers are the fabric modules, fabric groups, fabric group members and ToR.
Two extension points cover the differences between them:

- **Endpoint hooks** (``config_save_endpoint``, ``deploy_global_endpoint``,
  ``switches_endpoint``, ``switch_deploy_endpoint``) select which endpoint each
  operation uses. Override to add query parameters, or to retarget a different
  surface such as OneManage for a multi-cluster fabric group.
- **``only_switch_ids``** narrows a switch-scoped deploy to specific serials, for
  callers that touch a known subset of a fabric rather than the whole fabric.

Usage::

    class MyFabricOrchestrator(ConfigActionsMixin, NDBaseOrchestrator):
        ...

Then from the module, after parsing ``config_actions`` with the shared parser::

    actions = parse_config_actions(
        params=module.params,
        raw_args=get_raw_module_args(),
        policy=FABRIC_CONFIG_ACTIONS,
        state=state,
    )
    orchestrator.run_config_actions(
        actions=actions,
        fabric_names=["fab1", "fab2"],
        state=state,
        check_mode=module.check_mode,
    )
"""

from __future__ import annotations

from collections.abc import Collection
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.backend import ConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.controller import ConfigActionsController
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActions,
    ConfigActionsContext,
    ConfigActionsPolicy,
    ConfigActionsResult,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.backends.fabric import FabricConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class ConfigActionsMixin:
    """Mixin providing fabric config save and deploy operations.

    Designed to be composed with NDBaseOrchestrator (or subclasses). Relies on
    the host class providing ``_request()`` with the standard signature.

    Deploy types:
        - ``"global"``: Deploys the entire fabric via
          ``/fabrics/{fabricName}/actions/deploy`` (no request body).
        - ``"switch"``: Deploys the fabric's out-of-sync switches via
          ``/fabrics/{fabricName}/switchActions/deploy`` with
          ``{"switchIds": [...]}``. Targets are resolved after ``configSave``.
    """

    config_actions_policy: ClassVar[ConfigActionsPolicy] = FABRIC_CONFIG_ACTIONS
    config_actions_backend_class: ClassVar[type[ConfigActionsBackend] | None] = FabricConfigActionsBackend

    # ---------------------------------------------------------------- endpoints

    def config_save_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        """Return the config-save endpoint for this orchestrator's surface."""
        return EpFabricConfigSavePost(fabric_name=fabric_name)

    def deploy_global_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        """Return the fabric-wide deploy endpoint for this orchestrator's surface."""
        return EpFabricDeployPost(fabric_name=fabric_name)

    def switches_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        """Return the switches query endpoint for this orchestrator's surface."""
        return EpManageFabricsSwitchesGet(fabric_name=fabric_name)

    def switch_deploy_endpoint(self, fabric_name: str) -> NDEndpointBaseModel:
        """Return the switch-level deploy endpoint for this orchestrator's surface."""
        return EpManageFabricsSwitchActionsDeployPost(fabric_name=fabric_name)

    # -------------------------------------------------------------- entry point

    def run_config_actions(
        self,
        actions: ConfigActions,
        fabric_names: list[str],
        state: str | None = None,
        check_mode: bool = False,
        only_switch_ids: Collection[str] | None = None,
    ) -> ConfigActionsResult | None:
        """
        # Summary

        Build a config actions context for `fabric_names` and execute the
        normalized `actions` through the shared controller.

        Fabrics with no switches on the controller are skipped (ND rejects
        save/deploy on a switchless fabric) and surfaced as a warning. Switch
        deploy targets are resolved after `configSave`, not from the pre-save
        snapshot. When `only_switch_ids` is given, a switch-scoped deploy is
        limited to those serials; a global deploy ignores it. Returns ``None``
        without any API calls when neither save nor deploy is requested.

        ## Raises

        ### Exception

        - Via the controller/backend when a save or deploy request fails.
        """
        if not actions.save and not actions.deploy_requested():
            return None
        context = self.build_config_actions_context(
            fabric_names,
            state=state,
            check_mode=check_mode,
            only_switch_ids=only_switch_ids,
        )
        return self.execute_config_actions_plan(actions=actions, context=context)

    def build_config_actions_context(
        self,
        fabric_names: list[str],
        state: str | None = None,
        check_mode: bool = False,
        only_switch_ids: Collection[str] | None = None,
    ) -> ConfigActionsContext:
        """
        # Summary

        Build a `ConfigActionsContext` for `fabric_names`, fetching each fabric's
        switch membership so switchless fabrics can be excluded.

        Switchless fabrics are excluded (with a warning) so the controller never
        attempts save/deploy on a fabric ND would reject. The per-fabric switch
        entries are deploy *candidates*, not final targets: membership, narrowed
        by `only_switch_ids` when supplied. The backend intersects them with a
        post-save resolution, so a switch that `configSave` pushes out of sync is
        still deployed.

        ## Raises

        ### Exception

        - Via `_get_fabric_switches` when the switches query fails with a non-404 status.
        """
        allowlist = set(only_switch_ids) if only_switch_ids is not None else None
        eligible_fabrics: list[str] = []
        switch_ids_by_fabric: dict[str, tuple[str, ...]] = {}
        for fabric_name in fabric_names:
            switches = self._get_fabric_switches(fabric_name)
            if not switches:
                self.rest_send.warn(f"Skipping config save/deploy for '{fabric_name}': fabric has no switches.")
                continue
            eligible_fabrics.append(fabric_name)
            candidates = self._extract_switch_ids(switches)
            if allowlist is not None:
                candidates = [switch_id for switch_id in candidates if switch_id in allowlist]
            switch_ids_by_fabric[fabric_name] = tuple(candidates)
        return ConfigActionsContext(
            fabric_names=tuple(eligible_fabrics),
            state=state,
            check_mode=check_mode,
            switch_ids_by_fabric=switch_ids_by_fabric,
        )

    def execute_config_actions_plan(
        self,
        actions: ConfigActions,
        context: ConfigActionsContext,
        backend: ConfigActionsBackend | None = None,
    ) -> ConfigActionsResult:
        """
        # Summary

        Execute normalized config actions through the shared controller.

        ## Raises

        ### ValueError

        - If no backend is supplied and the mixin has no `config_actions_backend_class`.

        ### Exception

        - If any save or deploy step failed. The shared controller records backend
          failures in the result instead of propagating them, so this facade
          re-raises to fail the Ansible task.
        """
        selected_backend = backend
        if selected_backend is None:
            if self.config_actions_backend_class is None:
                raise ValueError("No config actions backend is configured for this orchestrator.")
            selected_backend = self.config_actions_backend_class(self)

        controller = ConfigActionsController(
            policy=self.config_actions_policy,
            backend=selected_backend,
        )
        result = controller.execute(actions, context)
        self._warn_skipped_config_actions(result)
        if result.status == "failed":
            raise Exception(self._config_actions_failure_message(result))
        return result

    def _warn_skipped_config_actions(self, result: ConfigActionsResult) -> None:
        """
        # Summary

        Surface skipped config-action controller decisions as user-visible warnings.

        The shared controller is transport-agnostic, so this facade translates
        skipped results and skipped action steps into `rest_send.warn()` calls.

        ## Raises

        None
        """
        if result.status == "skipped":
            fabrics = ", ".join(result.targets.get("fabrics", ())) or "<none>"
            self.rest_send.warn(f"Skipping config actions for fabric(s) {fabrics}: {result.reason}.")
            return
        for step in result.actions:
            if step.status != "skipped":
                continue
            target = step.target or "<unknown>"
            details = f": {step.error}" if step.error else ""
            scope = f" ({step.scope})" if step.scope else ""
            self.rest_send.warn(f"Skipping config action '{step.action}'{scope} for '{target}'{details}.")

    @staticmethod
    def _config_actions_failure_message(result: ConfigActionsResult) -> str:
        """
        # Summary

        Build a failure message from the first failed action step.

        ## Raises

        None
        """
        failed_steps = [step for step in result.actions if step.status == "failed"]
        if not failed_steps:
            return f"Config actions failed: {result.reason}."
        step = failed_steps[0]
        scope = f" ({step.scope})" if step.scope else ""
        target = step.target or "<unknown>"
        detail = step.error or step.error_type or "unknown error"
        return f"Config action '{step.action}'{scope} failed for '{target}': {detail}"

    # ------------------------------------------------------- backend operations

    def config_save(self, fabric_name: str) -> ResponseType:
        """Save fabric configuration, triggering intent recalculation. No request body."""
        ep = self.config_save_endpoint(fabric_name)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            operation_type=OperationType.UPDATE,
        )

    def deploy_global(self, fabric_name: str) -> ResponseType:
        """Deploy entire fabric configuration (no request body)."""
        ep = self.deploy_global_endpoint(fabric_name)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            operation_type=OperationType.UPDATE,
        )

    def deploy_switch_ids(self, fabric_name: str, switch_ids: list[str]) -> ResponseType:
        """Deploy the given switch serial numbers.

        Returns None when ``switch_ids`` is empty so the controller records a
        skipped step rather than issuing an empty deploy.
        """
        if not switch_ids:
            return None

        ep = self.switch_deploy_endpoint(fabric_name)
        return self._request(
            path=ep.path,
            verb=ep.verb,
            data={"switchIds": list(switch_ids)},
            operation_type=OperationType.UPDATE,
        )

    def resolve_switch_deploy_targets(self, fabric_name: str) -> list[str]:
        """Return switches needing deployment, queried fresh after config save.

        Must not reuse the pre-save snapshot: `configSave` can push a previously
        ``inSync`` switch out of sync, and that switch still needs deploying.
        """
        return self._filter_switches_needing_deploy(self._get_fabric_switches(fabric_name))

    def _get_fabric_switches(self, fabric_name: str) -> list[dict]:
        """Return the fabric's switches from the controller (empty list if none).

        ND rejects configSave/deploy on a switchless fabric ("Fabric ... cannot be
        deployed without any switches"), so callers skip save/deploy when this is
        empty.
        """
        ep = self.switches_endpoint(fabric_name)
        result = self._request(
            path=ep.path,
            verb=ep.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        return result.get("switches", []) if result else []

    @staticmethod
    def _filter_switches_needing_deploy(switches: list[dict]) -> list[str]:
        """Return serial numbers of switches whose ``configSyncStatus`` is not ``inSync``."""
        switch_ids = []
        for switch in switches:
            additional_data = switch.get("additionalData", {})
            config_status = additional_data.get("configSyncStatus", "")
            # Treat any non-inSync value (including empty/missing) as needing
            # deployment. An unknown status must not silently skip the switch.
            if config_status != "inSync":
                serial_number = switch.get("serialNumber", "")
                if serial_number:
                    switch_ids.append(serial_number)
        return switch_ids

    @staticmethod
    def _extract_switch_ids(switches: list[dict]) -> list[str]:
        """Return every switch serial number in `switches`."""
        switch_ids = []
        for switch in switches:
            serial_number = switch.get("serialNumber", "")
            if serial_number:
                switch_ids.append(serial_number)
        return switch_ids
