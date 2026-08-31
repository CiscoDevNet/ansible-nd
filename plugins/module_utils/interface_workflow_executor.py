# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Mutation execution for a completely validated aggregate interface plan."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import (
    InterfaceStateSnapshot,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceResourcePlan,
    InterfaceWorkflowPlan,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_base import (
    EthernetBaseOrchestrator,
)

Target = tuple[str, str]

_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})
_SUCCESS_STATUSES = frozenset({"success"})
_OUTCOME_KEYS = ("results", "switchIds", "links")


@dataclass
class InterfaceExecutionItem:
    """Execution outcome for one planned model mutation."""

    resource_index: int
    resource_type: str
    action: str
    switch_ip: str
    switch_id: str
    interface_name: str
    from_policy_type: str | None = None
    to_policy_type: str | None = None
    status: str = "not_attempted"
    message: str | None = None

    @property
    def target(self) -> Target:
        """Return the controller action identity."""
        return self.interface_name, self.switch_id

    def to_dict(self) -> dict[str, Any]:
        """Serialize this item for module output."""
        result = {
            "resource_index": self.resource_index,
            "type": self.resource_type,
            "action": self.action,
            "switch_ip": self.switch_ip,
            "switch_id": self.switch_id,
            "interface_name": self.interface_name,
            "status": self.status,
        }
        if self.from_policy_type is not None:
            result["from_policy_type"] = self.from_policy_type
        if self.to_policy_type is not None:
            result["to_policy_type"] = self.to_policy_type
        if self.message:
            result["message"] = self.message
        return result


@dataclass
class InterfaceWorkflowExecution:
    """Complete execution and reconciliation result."""

    status: str
    changed: bool
    failed: bool
    items: tuple[InterfaceExecutionItem, ...]
    mutation_requests: int
    deploy_requests: int
    affected_switch_ids: tuple[str, ...]
    deployment: dict[str, Any]
    errors: tuple[str, ...] = ()
    actual_after_by_resource: dict[int, NDConfigCollection] = field(default_factory=dict, repr=False)

    @property
    def message(self) -> str:
        """Return one useful module failure summary."""
        return "; ".join(self.errors) if self.errors else "Interface workflow execution failed."

    def to_dict(self) -> dict[str, Any]:
        """Serialize execution details while keeping model collections internal."""
        return {
            "status": self.status,
            "mutations_sent": self.mutation_requests,
            "deployments_sent": self.deploy_requests,
            "affected_switch_ids": list(self.affected_switch_ids),
            "items": [item.to_dict() for item in self.items],
            "deployment": self.deployment,
            "errors": list(self.errors),
        }


class InterfaceWorkflowExecutor:
    """Execute one precomputed plan using the current develop orchestrators."""

    def __init__(self, *, snapshot: InterfaceStateSnapshot, deploy: bool = False) -> None:
        self.snapshot = snapshot
        self.deploy = deploy
        self._items: list[InterfaceExecutionItem] = []
        self._item_by_key: dict[tuple[int, str, Any], InterfaceExecutionItem] = {}
        self._errors: list[str] = []
        self._deployment: dict[str, Any] = {
            "requested": deploy,
            "status": "not_attempted",
            "targets": [],
        }

    @staticmethod
    def _model_target(resource: InterfaceResourcePlan, model: NDBaseModel) -> Target:
        switch_id = resource.orchestrator.fabric_context.get_switch_id(getattr(model, "switch_ip"))
        return getattr(model, "interface_name"), switch_id

    def _build_items(self, plan: InterfaceWorkflowPlan) -> None:
        for resource in plan.resources:
            for model in resource.operations.deletes:
                interface_name, switch_id = self._model_target(resource, model)
                item = InterfaceExecutionItem(
                    resource_index=resource.resource_index,
                    resource_type=resource.resource_type,
                    action="delete",
                    switch_ip=getattr(model, "switch_ip"),
                    switch_id=switch_id,
                    interface_name=interface_name,
                )
                self._items.append(item)
                self._item_by_key[(resource.resource_index, "delete", model.get_identifier_value())] = item

            for transition in resource.transitions:
                model = transition.desired
                item = InterfaceExecutionItem(
                    resource_index=resource.resource_index,
                    resource_type=resource.resource_type,
                    action="transition",
                    switch_ip=transition.switch_ip,
                    switch_id=transition.switch_id,
                    interface_name=transition.interface_name,
                    from_policy_type=transition.from_policy_type,
                    to_policy_type=transition.to_policy_type,
                )
                self._items.append(item)
                self._item_by_key[(resource.resource_index, "transition", model.get_identifier_value())] = item

            for action, models in (
                ("update", resource.operations.updates),
                ("create", resource.operations.creates),
            ):
                for model in models:
                    interface_name, switch_id = self._model_target(resource, model)
                    item = InterfaceExecutionItem(
                        resource_index=resource.resource_index,
                        resource_type=resource.resource_type,
                        action=action,
                        switch_ip=getattr(model, "switch_ip"),
                        switch_id=switch_id,
                        interface_name=interface_name,
                    )
                    self._items.append(item)
                    self._item_by_key[(resource.resource_index, action, model.get_identifier_value())] = item

    def _item(self, resource: InterfaceResourcePlan, action: str, model: NDBaseModel) -> InterfaceExecutionItem:
        return self._item_by_key[(resource.resource_index, action, model.get_identifier_value())]

    @staticmethod
    def _write_history(rest_send, response_start: int, result_start: int) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        responses = rest_send.responses[response_start:]
        results = rest_send.results[result_start:]
        return list(zip(responses, results))

    @staticmethod
    def _response_outcomes(response: dict[str, Any]) -> list[dict[str, Any]]:
        data = response.get("DATA")
        if not isinstance(data, dict):
            return []
        outcomes: list[dict[str, Any]] = []
        for key in _OUTCOME_KEYS:
            values = data.get(key)
            if isinstance(values, list):
                outcomes.extend(value for value in values if isinstance(value, dict) and value.get("status") is not None)
        return outcomes

    @staticmethod
    def _outcome_target(outcome: dict[str, Any], targets: Iterable[Target]) -> Target | None:
        name_value = outcome.get("interfaceName") or outcome.get("name")
        switch_value = outcome.get("switchId") or outcome.get("serialNumber")
        candidates = list(targets)
        if name_value is not None:
            candidates = [target for target in candidates if target[0].lower() == str(name_value).lower()]
        if switch_value is not None:
            candidates = [target for target in candidates if target[1] == str(switch_value)]
        return candidates[0] if len(candidates) == 1 else None

    @classmethod
    def _classify_response(
        cls,
        targets: Iterable[Target],
        response: dict[str, Any] | None,
        result: dict[str, Any] | None,
        error: str,
    ) -> dict[Target, tuple[str, str | None]]:
        target_list = list(dict.fromkeys(targets))
        response = response or {}
        result = result or {}
        if result.get("success") is True:
            return {target: ("succeeded", None) for target in target_list}

        outcomes = cls._response_outcomes(response)
        classified: dict[Target, tuple[str, str | None]] = {}
        for outcome in outcomes:
            target = cls._outcome_target(outcome, target_list)
            if target is None:
                continue
            status = str(outcome.get("status") or "").strip().lower()
            message = outcome.get("message") or outcome.get("warningMessage")
            if status in _SUCCESS_STATUSES:
                classified[target] = ("succeeded", str(message) if message else None)
            elif status in _FAILURE_STATUSES:
                classified[target] = ("failed", str(message) if message else error)

        changed_on_failure = result.get("changed") is True
        for target in target_list:
            if target not in classified:
                classified[target] = (
                    "uncertain" if changed_on_failure or outcomes else "failed",
                    error,
                )
        return classified

    @staticmethod
    def _apply_outcomes(
        items: Iterable[InterfaceExecutionItem],
        outcomes: dict[Target, tuple[str, str | None]],
    ) -> None:
        for item in items:
            status, message = outcomes.get(
                item.target,
                ("uncertain", "Controller response did not identify this interface."),
            )
            item.status = status
            item.message = message

    def _call_items(
        self,
        orchestrator: NDBaseInterfaceOrchestrator,
        items: list[InterfaceExecutionItem],
        operation: Callable[[], Any],
        context: str,
    ) -> bool:
        response_start = len(orchestrator.rest_send.responses)
        result_start = len(orchestrator.rest_send.results)
        try:
            operation()
        except Exception as exc:  # pylint: disable=broad-except
            error = f"{context}: {exc}"
            history = self._write_history(orchestrator.rest_send, response_start, result_start)
            response, result = history[-1] if history else ({}, {})
            outcomes = self._classify_response((item.target for item in items), response, result, error)
            self._apply_outcomes(items, outcomes)
            self._errors.append(error)
            return False
        for item in items:
            item.status = "succeeded"
        return True

    def _enable_writes_and_preflight(self, plan: InterfaceWorkflowPlan) -> bool:
        for resource in plan.resources:
            resource.orchestrator.rest_send.check_mode = False
            resource.orchestrator.rest_send.params["check_mode"] = False
            resource.orchestrator.deploy = False
            if resource.orchestrator.results is not None:
                resource.orchestrator.results.check_mode = False
        try:
            if plan.resources:
                plan.resources[0].orchestrator.validate_prerequisites()
            for resource in plan.resources:
                if resource.state == "deleted":
                    continue
                create_candidates = [*resource.operations.creates, *(transition.desired for transition in resource.transitions)]
                resource.orchestrator.preflight_create(create_candidates)
                resource.orchestrator.preflight(list(resource.proposed))
        except Exception as exc:  # pylint: disable=broad-except
            self._errors.append(f"Pre-mutation prerequisite validation failed: {exc}")
            return False
        return True

    def _queue_deletes(self, plan: InterfaceWorkflowPlan) -> bool:
        for resource in plan.resources:
            models = list(resource.operations.deletes)
            if not models:
                continue
            orchestrator = resource.orchestrator
            items = [self._item(resource, "delete", model) for model in models]
            if orchestrator.supports_bulk_delete:
                if not self._call_items(
                    orchestrator,
                    items,
                    lambda orchestrator=orchestrator, models=models: orchestrator.delete_bulk(models),
                    f"resources[{resource.resource_index}] {resource.resource_type} delete preparation failed",
                ):
                    return False
                for item in items:
                    if isinstance(orchestrator, EthernetBaseOrchestrator):
                        queued = item.target in orchestrator.pending_normalizes or item.target in orchestrator.pending_resets
                    else:
                        queued = item.target in orchestrator.pending_removes
                    if queued:
                        item.status = "queued"
                    else:
                        item.status = "skipped"
                        item.message = "The develop orchestrator intentionally skipped this deletion."
                continue

            for model, item in zip(models, items):
                if not self._call_items(
                    orchestrator,
                    [item],
                    lambda orchestrator=orchestrator, model=model: orchestrator.delete(model),
                    f"resources[{resource.resource_index}] {resource.resource_type} delete failed",
                ):
                    return False
        return True

    def _flush_base_removes(self, plan: InterfaceWorkflowPlan) -> bool:
        sources = [
            resource.orchestrator
            for resource in plan.resources
            if not isinstance(resource.orchestrator, EthernetBaseOrchestrator) and resource.orchestrator.pending_removes
        ]
        if not sources:
            return True
        target = sources[0]
        targets = tuple(dict.fromkeys(pair for source in sources for pair in source.pending_removes))
        target.queue_remove_targets(targets)
        items = [item for item in self._items if item.action == "delete" and item.status == "queued" and item.target in targets]
        return self._call_items(
            target,
            items,
            target.remove_pending,
            "Consolidated interface removal failed",
        )

    def _flush_ethernet_removes(self, plan: InterfaceWorkflowPlan) -> bool:
        sources = [resource.orchestrator for resource in plan.resources if isinstance(resource.orchestrator, EthernetBaseOrchestrator)]
        normalizes = tuple(dict.fromkeys(pair for source in sources for pair in source.pending_normalizes))
        resets = tuple(dict.fromkeys(pair for source in sources for pair in source.pending_resets))
        if not normalizes and not resets:
            return True
        target = next(source for source in sources if source.pending_normalizes or source.pending_resets)
        target.queue_normalize_targets(normalizes)
        target.queue_reset_targets(resets)
        normalize_items = [item for item in self._items if item.action == "delete" and item.status == "queued" and item.target in normalizes]
        reset_items = [item for item in self._items if item.action == "delete" and item.status == "queued" and item.target in resets]

        response_start = len(target.rest_send.responses)
        result_start = len(target.rest_send.results)
        try:
            target.remove_pending()
        except Exception as exc:  # pylint: disable=broad-except
            error = f"Consolidated Ethernet normalization/reset failed: {exc}"
            history = self._write_history(target.rest_send, response_start, result_start)
            cursor = 0
            if normalize_items:
                response, result = history[cursor] if cursor < len(history) else ({}, {})
                cursor += 1 if cursor < len(history) else 0
                self._apply_outcomes(
                    normalize_items,
                    self._classify_response(
                        (item.target for item in normalize_items),
                        response,
                        result,
                        error,
                    ),
                )
            for item in reset_items:
                if cursor >= len(history):
                    item.status = "not_attempted"
                    item.message = error
                    continue
                response, result = history[cursor]
                cursor += 1
                self._apply_outcomes(
                    [item],
                    self._classify_response([item.target], response, result, error),
                )
            self._errors.append(error)
            return False
        for item in [*normalize_items, *reset_items]:
            item.status = "succeeded"
        return True

    def _execute_transitions(self, plan: InterfaceWorkflowPlan) -> bool:
        """Replace approved foreign policies through destination-family PUTs."""
        for resource in plan.resources:
            for transition in resource.transitions:
                item = self._item(resource, "transition", transition.desired)
                if not self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda resource=resource, transition=transition: resource.orchestrator.update(
                        transition.desired, existing_data=transition.current
                    ),
                    f"resources[{resource.resource_index}] {resource.resource_type} policy transition failed",
                ):
                    return False
        return True

    def _execute_updates(self, plan: InterfaceWorkflowPlan) -> bool:
        for resource in plan.resources:
            for model in resource.operations.updates:
                item = self._item(resource, "update", model)
                if not self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda resource=resource, model=model: resource.orchestrator.update(model),
                    f"resources[{resource.resource_index}] {resource.resource_type} update failed",
                ):
                    return False
        return True

    def _execute_creates(self, plan: InterfaceWorkflowPlan) -> bool:
        for resource in plan.resources:
            models = list(resource.operations.creates)
            if not models:
                continue
            if resource.orchestrator.supports_bulk_create:
                groups: dict[str, list[NDBaseModel]] = defaultdict(list)
                for model in models:
                    groups[self._model_target(resource, model)[1]].append(model)
                for switch_id, group in groups.items():
                    items = [self._item(resource, "create", model) for model in group]
                    if not self._call_items(
                        resource.orchestrator,
                        items,
                        lambda resource=resource, group=group: resource.orchestrator.create_bulk(group),
                        f"resources[{resource.resource_index}] {resource.resource_type} bulk create failed on {switch_id}",
                    ):
                        return False
                continue
            for model in models:
                item = self._item(resource, "create", model)
                if not self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda resource=resource, model=model: resource.orchestrator.create(model),
                    f"resources[{resource.resource_index}] {resource.resource_type} create failed",
                ):
                    return False
        return True

    def _deploy_pending(self, plan: InterfaceWorkflowPlan) -> bool:
        targets = tuple(dict.fromkeys(pair for resource in plan.resources for pair in resource.orchestrator.pending_deploys))
        self._deployment = {
            "requested": self.deploy,
            "status": ("not_needed" if not targets else ("disabled" if not self.deploy else "pending")),
            "targets": [
                {
                    "interface_name": interface_name,
                    "switch_id": switch_id,
                    "status": "not_attempted",
                }
                for interface_name, switch_id in targets
            ],
        }
        if not targets or not self.deploy:
            return True
        target = plan.resources[0].orchestrator
        target.deploy = True
        target.queue_deploy_targets(targets)
        response_start = len(target.rest_send.responses)
        result_start = len(target.rest_send.results)
        try:
            target.deploy_pending()
        except Exception as exc:  # pylint: disable=broad-except
            error = f"Consolidated interface deployment failed: {exc}"
            history = self._write_history(target.rest_send, response_start, result_start)
            response, result = history[-1] if history else ({}, {})
            outcomes = self._classify_response(targets, response, result, error)
            for entry in self._deployment["targets"]:
                status, message = outcomes[(entry["interface_name"], entry["switch_id"])]
                entry["status"] = status
                if message:
                    entry["message"] = message
            statuses = {entry["status"] for entry in self._deployment["targets"]}
            self._deployment["status"] = "partial_failure" if "succeeded" in statuses or "uncertain" in statuses else "failed"
            self._deployment["message"] = error
            self._errors.append(error)
            return False
        for entry in self._deployment["targets"]:
            entry["status"] = "succeeded"
        self._deployment["status"] = "succeeded"
        return True

    @staticmethod
    def _write_observations(plan: InterfaceWorkflowPlan) -> tuple[int, int, bool]:
        mutation_requests = 0
        deploy_requests = 0
        mutation_changed = False
        seen: set[int] = set()
        for resource in plan.resources:
            rest_send = resource.orchestrator.rest_send
            if id(rest_send) in seen:
                continue
            seen.add(id(rest_send))
            for response, result in zip(rest_send.responses, rest_send.results):
                method = str(response.get("METHOD") or "").upper()
                if method == "GET" or method.endswith(".GET"):
                    continue
                path = str(response.get("REQUEST_PATH") or "")
                if "interfaceActions/deploy" in path:
                    deploy_requests += 1
                else:
                    mutation_requests += 1
                    mutation_changed = mutation_changed or result.get("changed") is True
        return mutation_requests, deploy_requests, mutation_changed

    def _reconcile(self, plan: InterfaceWorkflowPlan, *, wrote: bool) -> dict[int, NDConfigCollection]:
        if wrote:
            try:
                self.snapshot.mark_dirty(plan.target_switch_ids)
                self.snapshot.refresh(plan.target_switch_ids)
            except Exception as exc:  # pylint: disable=broad-except
                self._errors.append(f"Post-mutation interface snapshot refresh failed: {exc}")
                return {}
        actual: dict[int, NDConfigCollection] = {}
        try:
            for resource in plan.resources:
                actual[resource.resource_index] = resource.adapter.existing_collection(resource.orchestrator)
        except Exception as exc:  # pylint: disable=broad-except
            self._errors.append(f"Post-mutation actual-state selection failed: {exc}")
            return {}
        return actual

    def execute(self, plan: InterfaceWorkflowPlan) -> InterfaceWorkflowExecution:
        """Execute delete, transition, update, create, and deploy phases, then refetch actual state."""
        self._build_items(plan)
        phases_ok = self._enable_writes_and_preflight(plan)
        if phases_ok:
            phases_ok = self._queue_deletes(plan)
        if phases_ok:
            phases_ok = self._flush_base_removes(plan)
        if phases_ok:
            phases_ok = self._flush_ethernet_removes(plan)
        if phases_ok:
            phases_ok = self._execute_transitions(plan)
        if phases_ok:
            phases_ok = self._execute_updates(plan)
        if phases_ok:
            phases_ok = self._execute_creates(plan)
        if phases_ok:
            phases_ok = self._deploy_pending(plan)

        mutation_requests, deploy_requests, mutation_changed = self._write_observations(plan)
        actual = self._reconcile(plan, wrote=bool(mutation_requests))
        actual_changed = any(
            resource.before.get_diff_collection(actual[resource.resource_index]) for resource in plan.resources if resource.resource_index in actual
        )
        failed = not phases_ok or bool(self._errors)
        changed = mutation_changed or actual_changed
        if failed:
            item_statuses = {item.status for item in self._items}
            status = "partial_failure" if changed or item_statuses & {"succeeded", "uncertain"} else "failed"
        elif self.deploy:
            status = "completed"
        else:
            status = "staged"
        return InterfaceWorkflowExecution(
            status=status,
            changed=changed,
            failed=failed,
            items=tuple(self._items),
            mutation_requests=mutation_requests,
            deploy_requests=deploy_requests,
            affected_switch_ids=plan.target_switch_ids if mutation_requests else (),
            deployment=self._deployment,
            errors=tuple(self._errors),
            actual_after_by_resource=actual,
        )
