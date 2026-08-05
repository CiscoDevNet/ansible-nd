# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Common config action execution controller.
"""

from __future__ import annotations

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

        Exception
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

        if not actions.save and not actions.deploy:
            return ConfigActionsResult(
                requested=actions,
                effective=actions,
                status="skipped",
                reason="actions_disabled",
                targets=targets,
            )

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
            if actions.save:
                try:
                    response = self.backend.save(normalized_context, fabric_name)
                    steps.append(ConfigActionStepResult(action="save", status="completed", target=fabric_name, response=response))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    steps.append(ConfigActionStepResult(action="save", status="failed", target=fabric_name, error=str(exc)))
                    return self._result(actions, targets, steps)

            if actions.deploy:
                try:
                    steps.append(self._deploy(actions, normalized_context, fabric_name))
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    steps.append(ConfigActionStepResult(action="deploy", scope=actions.type, status="failed", target=fabric_name, error=str(exc)))
                    return self._result(actions, targets, steps)

        return self._result(actions, targets, steps)

    def _deploy(self, actions: ConfigActions, context: ConfigActionsContext, fabric_name: str) -> ConfigActionStepResult:
        """
        # Summary

        Execute one deploy step for `fabric_name`.

        ## Raises

        Exception
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

    def _planned_steps(self, actions: ConfigActions, context: ConfigActionsContext) -> tuple[ConfigActionStepResult, ...]:
        """
        # Summary

        Return planned action steps without calling backend endpoints.

        ## Raises

        None
        """
        steps: list[ConfigActionStepResult] = []
        for fabric_name in context.fabric_names:
            if actions.save:
                steps.append(ConfigActionStepResult(action="save", status="planned", target=fabric_name))
            if actions.deploy:
                if actions.type == "switch" and not context.switch_ids:
                    steps.append(ConfigActionStepResult(action="deploy", status="skipped", scope="switch", target=fabric_name, error="no_targets"))
                elif actions.type == "resource" and not context.resources:
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
    def _targets(context: ConfigActionsContext) -> dict[str, tuple[str, ...]]:
        """
        # Summary

        Return normalized target groups for result output.

        ## Raises

        None
        """
        return {
            "fabrics": context.fabric_names,
            "switches": context.switch_ids,
            "resources": context.resources,
        }

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
