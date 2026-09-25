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
from time import monotonic, sleep
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.backend import ConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.controller import ConfigActionsController
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import FABRIC_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    NOT_ISSUED,
    ConfigActions,
    ConfigActionsContext,
    ConfigActionsFailed,
    ConfigActionsPolicy,
    ConfigActionsResult,
    NotIssued,
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

# ND models a switch's `additionalData.configSyncStatus` with the `switchConfigSyncStatus` enum, identical in
# docs/openapi/4.2.1/manage.json and docs/openapi/4.3.1/manage.json:
#   deployed, deploymentInProgress, failed, inProgress, inSync, notApplicable, outOfSync, pending,
#   previewInProgress, success
# Nothing needs pushing in these: the switch either matches intent or has no intent to match.
_SWITCH_SYNC_SETTLED = frozenset({"inSync", "deployed", "success", "notApplicable"})

# An operation is already running on the switch, so a save or deploy should wait rather than be issued
# into it. Measured on ND 4.2.1: a normal save/deploy cycle never reports any of these -- switches go
# pending -> outOfSync -> success -> inSync -- so this gate is defensive, for flows (config preview, a
# UI-driven deploy) that do set them. Contention with another operation surfaces as an HTTP 403 instead;
# see `_CONTENTION_SIGNATURES`.
# `pending` is deliberately NOT here: ND uses it for "configuration pending deployment" (spec: "Individual
# configuration command that is pending deployment on the switch"), which is a deploy target, not an
# operation in flight -- and it is the state a fabric edit puts every switch into, verified live.
_SWITCH_SYNC_IN_FLIGHT = frozenset({"inProgress", "deploymentInProgress", "previewInProgress"})

# Documented statuses that a deploy is meant to resolve. Used to report what a deploy left behind; an
# unknown status is treated as a deploy target separately so a new ND status is never silently skipped.
_SWITCH_SYNC_NEEDS_DEPLOY = frozenset({"outOfSync", "pending", "failed"})

# ND refuses a config action that collides with one already running, and this is the ONLY signal for it:
# measured on ND 4.2.1, neither the per-switch nor the fabric-level `configSyncStatus` reports an
# operation in progress. The refusal is an HTTP 403, which is terminal for every other reason a 403 is
# returned, and the error body carries no code beyond the HTTP status -- so the message is the only
# available discriminator. Matching it follows the existing precedent in `manage_vpc_pair/deploy.py`
# and `manage_fabric_group_members.py`; keep the list tight so a real authorization failure still fails.
# Live text: "This operation cannot be performed while recalculate and deploy is in progress. Please try
# again later."
_CONTENTION_SIGNATURES = ("while recalculate and deploy is in progress",)


class ConfigActionsPreconditionError(Exception):
    """A config-action precondition that re-reading cannot resolve, so it is not retried."""


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

    # RestSend retry budget, in seconds, for config-action mutations. RestSend replays a
    # retryable failure every ``send_interval`` seconds until the budget is spent, and a 5xx
    # on a POST is retryable (only 4xx is terminal — see issue #502). configSave and both
    # deploy endpoints document HTTP 500, and ND uses it for deterministic rejections such as
    # a failed vPC sanity check, so the 300s default replayed one rejected save 60 times: 60
    # real recalculations on the fabric while the task appeared to hang for five minutes.
    # These are mutations, not polls — a replay cannot turn a rejection into an acceptance, and
    # re-running the task is the idiomatic remedy — so the window is collapsed to one attempt.
    config_actions_request_timeout: ClassVar[int] = 1

    # How long to keep retrying a config action ND says is temporarily blocked: a 403 contention, or a
    # switch read that failed transiently. Not a prediction of how long ND takes -- measured on a
    # 14-switch fabric the same no-op configSave ran in 26.9s, 28.4s and 36.5s, and ND sends no
    # Retry-After header -- but a patience limit. Failing too early costs a spurious task failure;
    # waiting too long only costs time, so this is deliberately generous.
    config_actions_retry_timeout: ClassVar[int] = 600
    config_actions_retry_interval: ClassVar[int] = 5

    # Post-deploy convergence. A total-duration budget would have to scale with fabric size, so the
    # limit is instead "no switch has come into sync for this long", which means the same at any
    # scale: switches settle incrementally (measured live: 14 -> 11 -> 0 outstanding over ~5s), so a
    # falling count of unsettled switches is real progress. `max_wait` is the backstop, because the
    # stall timer alone is not bounded -- one switch settling just before each expiry would reset it
    # forever, giving switches x stall in the worst case.
    config_actions_converge_stall: ClassVar[int] = 120
    config_actions_converge_max_wait: ClassVar[int] = 1800
    config_actions_converge_interval: ClassVar[int] = 5

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

        Doubles as the pre-action convergence gate: the membership read waits out
        any switch ND is already mid-operation on, so no config action is issued
        into an in-flight deploy.

        ## Raises

        ### Exception

        - Via `_get_fabric_switches` when the switches query fails with a non-404 status.
        - Via `read_fabric_switches` when the read keeps failing.
        """
        allowlist = set(only_switch_ids) if only_switch_ids is not None else None
        eligible_fabrics: list[str] = []
        switch_ids_by_fabric: dict[str, tuple[str, ...]] = {}
        for fabric_name in fabric_names:
            switches = self.read_fabric_switches(fabric_name)
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

        ### ConfigActionsFailed

        - If any save or deploy step failed. The shared controller records backend failures in
          the result instead of propagating them, so this facade re-raises to fail the Ansible
          task, carrying the result so the steps that did succeed are still reported.
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
            raise ConfigActionsFailed(self._config_actions_failure_message(result), result)
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

    def _config_action_request(
        self,
        endpoint: NDEndpointBaseModel,
        data: dict | None = None,
        operation_type: OperationType = OperationType.UPDATE,
        not_found_ok: bool = False,
    ) -> ResponseType:
        """Issue one config-action request with the RestSend retry window collapsed.

        See ``config_actions_request_timeout`` for why a save or deploy must not be
        replayed, and why the reads retry on the settle loop instead. The window is
        restored afterwards so unrelated requests keep the default retry behaviour.

        The one failure that *is* replayed is ND refusing the action because another is
        already running: that refusal means nothing was applied, so re-issuing is safe, and
        the condition clears on its own -- ND's own wording is "Please try again later".
        It is retried on the settle budget, the same one used to wait for switch convergence.

        ## Raises

        ### Exception

        - Via `_request` when the controller rejects the request for any other reason, or when
          contention outlasts `config_actions_retry_timeout`.
        """
        remaining = self.config_actions_retry_timeout
        while True:
            self.rest_send.save_settings()
            self.rest_send.timeout = self.config_actions_request_timeout
            try:
                return self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    data=data,
                    not_found_ok=not_found_ok,
                    operation_type=operation_type,
                )
            except Exception as error:  # pylint: disable=broad-exception-caught
                if not self._is_contention_error(error) or remaining <= 0:
                    raise
                self.rest_send.warn(f"Another operation is running on the fabric; retrying {endpoint.path} in {self.config_actions_retry_interval}s.")
            finally:
                self.rest_send.restore_settings()

            if not getattr(self.rest_send, "unit_test", False):
                sleep(self.config_actions_retry_interval)
            remaining -= self.config_actions_retry_interval

    @staticmethod
    def _is_contention_error(error: Exception) -> bool:
        """Return True when ND refused the action because another one is already running."""
        message = str(error).lower()
        return any(signature in message for signature in _CONTENTION_SIGNATURES)

    def config_save(self, fabric_name: str) -> ResponseType:
        """Save fabric configuration, triggering intent recalculation. No request body."""
        return self._config_action_request(self.config_save_endpoint(fabric_name))

    def deploy_global(self, fabric_name: str) -> ResponseType:
        """Deploy entire fabric configuration (no request body)."""
        return self._config_action_request(self.deploy_global_endpoint(fabric_name))

    def deploy_switch_ids(self, fabric_name: str, switch_ids: list[str]) -> ResponseType | NotIssued:
        """Deploy the given switch identifiers.

        Returns `NOT_ISSUED` when `switch_ids` is empty so the controller records a
        skipped step rather than issuing an empty deploy.
        """
        if not switch_ids:
            return NOT_ISSUED

        return self._config_action_request(self.switch_deploy_endpoint(fabric_name), data={"switchIds": list(switch_ids)})

    def resolve_switch_deploy_targets(self, fabric_name: str) -> list[str]:
        """Return switches needing deployment, queried fresh after config save.

        Must not reuse the pre-save snapshot: `configSave` can push a previously
        ``inSync`` switch out of sync, and that switch still needs deploying.
        """
        return self._filter_switches_needing_deploy(self.read_fabric_switches(fabric_name))

    def read_fabric_switches(self, fabric_name: str) -> list[dict]:
        """Read `fabric_name`'s switches, retrying a transient read failure.

        This is the only retry the read itself gets: `_get_fabric_switches` runs with the RestSend
        window collapsed, so a failure is retried on this loop's budget and schedule instead of
        stalling for RestSend's much longer one inside a single iteration of it.

        ## Raises

        ### ConfigActionsPreconditionError

        - Via `_get_fabric_switches` when ND truncates the switch list; re-reading cannot fix it.

        ### Exception

        - If the read is still failing when `config_actions_retry_timeout` is spent, or immediately
          when retrying is disabled. A read failure is never downgraded to an empty result, which
          callers would read as a switchless fabric and silently skip.
        """
        remaining = self.config_actions_retry_timeout
        while True:
            try:
                return self._get_fabric_switches(fabric_name)
            except ConfigActionsPreconditionError:
                raise
            except Exception as error:  # pylint: disable=broad-exception-caught
                if self.config_actions_retry_timeout <= 0 or remaining <= 0:
                    raise
                self.rest_send.warn(f"Could not read switch state for '{fabric_name}' ({error}); retrying in {self.config_actions_retry_interval}s.")

            if not getattr(self.rest_send, "unit_test", False):
                sleep(self.config_actions_retry_interval)
            remaining -= self.config_actions_retry_interval

    def verify_deploy(self, fabric_name: str, switch_ids: Collection[str] | None = None) -> None:
        """Poll until every deployed switch has settled, failing if any did not.

        ND answers `switchActions/deploy` with a Multi-Status body whose per-item ``notExecuted``
        is not treated as a failure, and answers the fabric-wide deploy with a bare status, so a
        deploy that changed nothing can still report success. `switch_ids` limits the check to the
        switches the caller deployed; omit it to check the whole fabric.

        Polling is only meaningful here: switch status is frozen for the whole recalculation
        phase, but moves incrementally after a deploy.

        ## Raises

        ### Exception

        - If a switch reports ``failed``; if no switch has come into sync for
          `config_actions_converge_stall`; or if `config_actions_converge_max_wait` is reached.
        """
        scope = set(switch_ids) if switch_ids is not None else None
        deadline = monotonic() + self.config_actions_converge_max_wait
        fewest_unsettled: int | None = None
        stalled_for = 0

        while True:
            statuses = {
                switch_id: self._switch_sync_status(switch)
                for switch in self.read_fabric_switches(fabric_name)
                if (switch_id := self._switch_identifier(switch)) and (scope is None or switch_id in scope)
            }

            failed = sorted(switch_id for switch_id, status in statuses.items() if status == "failed")
            if failed:
                raise Exception(f"Deploy failed on switch(es) {', '.join(failed)} in fabric '{fabric_name}'.")

            # An undocumented status counts as unsettled rather than settled: the bailouts below cap the
            # wait, and their message names the status, which beats passing a switch ND is unhappy about.
            # `pending` is exempt -- a deploy can legitimately stage fresh intent.
            unsettled = sorted(
                f"{switch_id} ({status})" for switch_id, status in statuses.items() if status != "pending" and status not in _SWITCH_SYNC_SETTLED
            )
            if not unsettled:
                pending = sorted(switch_id for switch_id, status in statuses.items() if status == "pending")
                if pending:
                    self.rest_send.warn(f"Deploy left switch(es) in fabric '{fabric_name}' with configuration pending: {', '.join(pending)}.")
                return

            # Switches settle incrementally, so a falling count is progress; it cannot churn the way
            # a set of identifiers can.
            progressed = fewest_unsettled is None or len(unsettled) < fewest_unsettled
            stalled_for = 0 if progressed else stalled_for + self.config_actions_converge_interval
            fewest_unsettled = len(unsettled) if fewest_unsettled is None else min(fewest_unsettled, len(unsettled))

            if stalled_for >= self.config_actions_converge_stall:
                raise Exception(f"No switch in fabric '{fabric_name}' has come into sync for {stalled_for}s; still waiting on {', '.join(unsettled)}.")
            if monotonic() >= deadline:
                raise Exception(
                    f"Switch(es) {', '.join(unsettled)} in fabric '{fabric_name}' did not come into sync " f"within {self.config_actions_converge_max_wait}s."
                )
            if not getattr(self.rest_send, "unit_test", False):
                sleep(self.config_actions_converge_interval)

    def _get_fabric_switches(self, fabric_name: str) -> list[dict]:
        """Return the fabric's switches from the controller (empty list if none).

        ND rejects configSave/deploy on a switchless fabric ("Fabric ... cannot be
        deployed without any switches"), so callers skip save/deploy when this is
        empty. Runs with the RestSend retry window collapsed; see
        `config_actions_request_timeout`.

        ## Raises

        ### ConfigActionsPreconditionError

        - If ND paginated the response. Every caller needs the whole fabric: a truncated list
          silently drops deploy targets and hides a failed switch from `verify_deploy`.
        """
        ep = self.switches_endpoint(fabric_name)
        result = self._config_action_request(ep, operation_type=OperationType.QUERY, not_found_ok=True)
        if not result:
            return []
        switches = result.get("switches", [])
        withheld = self._withheld_count(result)
        if withheld:
            raise ConfigActionsPreconditionError(
                f"ND returned only {len(switches)} of {len(switches) + withheld} switches for fabric '{fabric_name}'. "
                f"Config actions need the full list, so deploy targeting and post-deploy verification would be "
                f"incomplete. Reduce the fabric size or raise the controller's page limit."
            )
        return switches

    @staticmethod
    def _withheld_count(result: dict) -> int:
        """Return how many entries ND paginated away, 0 when the response is complete.

        ND is inconsistent about where it puts the counter: `meta.counts.remaining` on
        `/fabrics/{n}/switches`, `meta.remaining` on `/fabrics`. A response without one at all
        is taken as complete.
        """
        meta = result.get("meta")
        if not isinstance(meta, dict):
            return 0
        counts = meta.get("counts") if isinstance(meta.get("counts"), dict) else meta
        remaining = counts.get("remaining")
        return remaining if isinstance(remaining, int) and remaining > 0 else 0

    @staticmethod
    def _switch_identifier(switch: dict) -> str:
        """Return the identifier to deploy `switch` by, preferring ``switchId``.

        ``switchId`` is the schema-required field and is what ``switchActions/deploy``
        expects; for ACI nodes it is a node ID rather than a serial number. Falls back
        to ``serialNumber`` for responses that omit it.
        """
        return switch.get("switchId") or switch.get("serialNumber") or ""

    @staticmethod
    def _switch_sync_status(switch: dict) -> str:
        """Return `switch`'s ``configSyncStatus``, or an empty string when ND omits it."""
        additional_data = switch.get("additionalData") or {}
        return str(additional_data.get("configSyncStatus") or "")

    @staticmethod
    def _filter_switches_needing_deploy(switches: list[dict]) -> list[str]:
        """Return identifiers of switches a deploy should target.

        Skips switches that already match intent or have none (`_SWITCH_SYNC_SETTLED`) and
        switches mid-operation (`_SWITCH_SYNC_IN_FLIGHT`), which a caller is expected to have
        waited out. Everything else is a target, including a status ND has not documented: an
        unknown status must not silently skip the switch.
        """
        switch_ids = []
        for switch in switches:
            status = ConfigActionsMixin._switch_sync_status(switch)
            if status in _SWITCH_SYNC_SETTLED or status in _SWITCH_SYNC_IN_FLIGHT:
                continue
            switch_id = ConfigActionsMixin._switch_identifier(switch)
            if switch_id:
                switch_ids.append(switch_id)
        return switch_ids

    @staticmethod
    def _extract_switch_ids(switches: list[dict]) -> list[str]:
        """Return every switch identifier in `switches`."""
        switch_ids = []
        for switch in switches:
            switch_id = ConfigActionsMixin._switch_identifier(switch)
            if switch_id:
                switch_ids.append(switch_id)
        return switch_ids
