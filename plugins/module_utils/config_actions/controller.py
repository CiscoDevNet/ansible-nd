# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Common config action execution controller.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.backend import ConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActionStepResult,
    ConfigActions,
    ConfigActionsContext,
    ConfigActionsPolicy,
    ConfigActionsResult,
)


class ConfigActionsController:
    """
    # Summary

    Execute normalized config actions through an endpoint-specific backend.

    ## Raises

    None
    """

    def __init__(self, policy: ConfigActionsPolicy, backend: ConfigActionsBackend) -> None:
        """
        # Summary

        Initialize the controller with a policy and backend.

        ## Raises

        None
        """
        self.policy = policy
        self.backend = backend

    def execute(self, actions: ConfigActions, context: ConfigActionsContext) -> ConfigActionsResult:
        """
        # Summary

        Execute or plan config actions using the supplied backend.

        ## Raises

        ### Exception

        - Raised by backend save or deploy operations before the controller records the failure result.
        """
        normalized_context = self._deduplicated_context(context)
        targets = self._targets(normalized_context)

        if not normalized_context.fabric_names:
            return ConfigActionsResult(
                requested=actions,
                effective=actions,
                status="skipped",
                reason="no_fabrics",
                targets=targets,
            )

        if not normalized_context.eligible:
            return ConfigActionsResult(
                requested=actions,
                effective=actions,
                status="skipped",
                reason=normalized_context.reason,
                targets=targets,
            )

        if not actions.save and not actions.deploy_requested():
            return ConfigActionsResult(
                requested=actions,
                effective=actions,
                status="skipped",
                reason="actions_disabled",
                targets=targets,
            )

        self._validate_scoped_targets(actions, normalized_context)

        if normalized_context.check_mode:
            planned_steps = self._planned_steps(actions, normalized_context)
            return ConfigActionsResult(
                requested=actions,
                effective=actions,
                status="planned",
                reason="check_mode",
                targets=targets,
                actions=planned_steps,
            )

        steps: list[ConfigActionStepResult] = []
        for fabric_name in normalized_context.fabric_names:
            fabric_context = self._context_for_fabric(normalized_context, fabric_name)
            if actions.save:
                try:
                    response = self.backend.save(fabric_context, fabric_name)
                    steps.append(ConfigActionStepResult(action="save", status="completed", target=fabric_name, response=response))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    steps.append(self._failed_step_from_exception(action="save", target=fabric_name, exc=exc))
                    return self._result(actions, targets, steps)

            if actions.deploy_requested():
                try:
                    steps.append(self._deploy(actions, fabric_context, fabric_name))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    steps.append(self._failed_step_from_exception(action="deploy", target=fabric_name, exc=exc, scope=actions.type))
                    return self._result(actions, targets, steps)

        return self._result(actions, targets, steps)

    def _deploy(self, actions: ConfigActions, context: ConfigActionsContext, fabric_name: str) -> ConfigActionStepResult:
        """
        # Summary

        Execute one deploy step for `fabric_name`.

        ## Raises

        ### Exception

        - Raised by backend deploy operations when the controller requests a supported deploy scope.
        """
        if actions.type == "global":
            response = self.backend.deploy_global(context, fabric_name)
            return ConfigActionStepResult(action="deploy", scope="global", status="completed", target=fabric_name, response=response)
        if actions.type == "switch":
            if not context.switch_ids:
                return ConfigActionStepResult(action="deploy", scope="switch", status="skipped", target=fabric_name, error="no_targets")
            response = self.backend.deploy_switches(context, fabric_name, context.switch_ids)
            return ConfigActionStepResult(action="deploy", scope="switch", status="completed", target=fabric_name, response=response)
        if actions.type == "resource":
            if not context.resources:
                return ConfigActionStepResult(action="deploy", scope="resource", status="skipped", target=fabric_name, error="no_targets")
            response = self.backend.deploy_resources(context, fabric_name, context.resources)
            return ConfigActionStepResult(action="deploy", scope="resource", status="completed", target=fabric_name, response=response)

        return ConfigActionStepResult(action="deploy", scope=actions.type, status="skipped", target=fabric_name, error="unsupported_type")

    @staticmethod
    def _failed_step_from_exception(action: str, target: str, exc: Exception, scope: str | None = None) -> ConfigActionStepResult:
        """
        # Summary

        Build a failed action step while preserving structured exception details.

        ## Raises

        None
        """
        return ConfigActionStepResult(
            action=action,
            scope=scope,
            status="failed",
            target=target,
            error=getattr(exc, "msg", str(exc)),
            error_type=exc.__class__.__name__,
            http_status=getattr(exc, "status", None),
            request_payload=getattr(exc, "request_payload", None),
            response_payload=getattr(exc, "response_payload", None),
            raw=getattr(exc, "raw", None),
        )

    def _planned_steps(self, actions: ConfigActions, context: ConfigActionsContext) -> tuple[ConfigActionStepResult, ...]:
        """
        # Summary

        Return planned action steps without calling backend endpoints.

        ## Raises

        None
        """
        steps: list[ConfigActionStepResult] = []
        for fabric_name in context.fabric_names:
            fabric_context = self._context_for_fabric(context, fabric_name)
            if actions.save:
                steps.append(ConfigActionStepResult(action="save", status="planned", target=fabric_name))
            if actions.deploy_requested():
                if actions.type == "switch" and not fabric_context.switch_ids:
                    steps.append(ConfigActionStepResult(action="deploy", status="skipped", scope="switch", target=fabric_name, error="no_targets"))
                elif actions.type == "resource" and not fabric_context.resources:
                    steps.append(ConfigActionStepResult(action="deploy", status="skipped", scope="resource", target=fabric_name, error="no_targets"))
                else:
                    steps.append(ConfigActionStepResult(action="deploy", status="planned", scope=actions.type, target=fabric_name))
        return tuple(steps)

    @staticmethod
    def _deduplicated_context(context: ConfigActionsContext) -> ConfigActionsContext:
        """
        # Summary

        Return a context with fabric, switch and resource targets deduplicated in input order.

        ## Raises

        None
        """
        return replace(
            context,
            fabric_names=ConfigActionsController._dedupe(context.fabric_names),
            switch_ids=ConfigActionsController._dedupe(context.switch_ids),
            resources=ConfigActionsController._dedupe(context.resources),
            switch_ids_by_fabric=ConfigActionsController._dedupe_target_map(context.switch_ids_by_fabric),
            resources_by_fabric=ConfigActionsController._dedupe_target_map(context.resources_by_fabric),
        )

    @staticmethod
    def _validate_scoped_targets(actions: ConfigActions, context: ConfigActionsContext) -> None:
        """
        # Summary

        Reject ambiguous flat scoped targets for multi-fabric deploy requests.

        ## Raises

        ### ValueError

        - If switch or resource deploy targets cannot be associated with one fabric.
        """
        if len(context.fabric_names) <= 1 or not actions.deploy_requested():
            return
        if actions.type == "switch" and context.switch_ids:
            raise ValueError("switch deploy with multiple fabrics requires switch_ids_by_fabric instead of flat switch_ids.")
        if actions.type == "resource" and context.resources:
            raise ValueError("resource deploy with multiple fabrics requires resources_by_fabric instead of flat resources.")

    @staticmethod
    def _context_for_fabric(context: ConfigActionsContext, fabric_name: str) -> ConfigActionsContext:
        """
        # Summary

        Return a single-fabric context with targets scoped to `fabric_name`.

        ## Raises

        None
        """
        return replace(
            context,
            fabric_names=(fabric_name,),
            switch_ids=tuple(context.switch_ids_by_fabric.get(fabric_name, context.switch_ids)),
            resources=tuple(context.resources_by_fabric.get(fabric_name, context.resources)),
        )

    @staticmethod
    def _dedupe(values: tuple[str, ...]) -> tuple[str, ...]:
        """
        # Summary

        Deduplicate string values while preserving order.

        ## Raises

        None
        """
        return tuple(dict.fromkeys(values))

    @staticmethod
    def _dedupe_target_map(targets_by_fabric: object) -> dict[str, tuple[str, ...]]:
        """
        # Summary

        Deduplicate fabric-keyed target values while preserving order.

        ## Raises

        None
        """
        if not isinstance(targets_by_fabric, dict):
            return {}
        return {fabric_name: ConfigActionsController._dedupe(tuple(targets)) for fabric_name, targets in targets_by_fabric.items()}

    @staticmethod
    def _targets(context: ConfigActionsContext) -> dict[str, tuple[str, ...]]:
        """
        # Summary

        Return normalized target groups for result output.

        ## Raises

        None
        """
        return {
            "fabrics": context.fabric_names,
            "switches": ConfigActionsController._combined_targets(context.switch_ids, context.switch_ids_by_fabric),
            "resources": ConfigActionsController._combined_targets(context.resources, context.resources_by_fabric),
        }

    @staticmethod
    def _combined_targets(flat_targets: tuple[str, ...], targets_by_fabric: Mapping[str, Sequence[str]]) -> tuple[str, ...]:
        """
        # Summary

        Return flattened target output from flat and fabric-keyed target inputs.

        ## Raises

        None
        """
        combined = list(flat_targets)
        for targets in targets_by_fabric.values():
            combined.extend(targets)
        return ConfigActionsController._dedupe(tuple(combined))

    @staticmethod
    def _result(actions: ConfigActions, targets: dict[str, tuple[str, ...]], steps: list[ConfigActionStepResult]) -> ConfigActionsResult:
        """
        # Summary

        Build a common result from completed, skipped and failed action steps.

        ## Raises

        None
        """
        statuses = {step.status for step in steps}
        if "failed" in statuses:
            status = "failed"
            reason = "action_failed"
        elif not steps:
            status = "skipped"
            reason = "no_actions"
        elif statuses == {"skipped"}:
            status = "skipped"
            reason = "no_targets"
        elif "skipped" in statuses:
            status = "completed"
            reason = "actions_executed_with_skips"
        else:
            status = "completed"
            reason = "actions_executed"

        return ConfigActionsResult(
            requested=actions,
            effective=actions,
            status=status,
            reason=reason,
            targets=targets,
            actions=tuple(steps),
        )
