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
    InterfaceWorkflowPlanner,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    DeferredDeleteRequestGroup,
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

    def __init__(
        self,
        *,
        snapshot: InterfaceStateSnapshot,
        deploy: bool = False,
        verify: bool = False,
    ) -> None:
        self.snapshot = snapshot
        self.deploy = deploy
        self.verify = verify
        self._items: list[InterfaceExecutionItem] = []
        self._item_by_key: dict[tuple[int, str, Any], InterfaceExecutionItem] = {}
        self._errors: list[str] = []
        self._deployment: dict[str, Any] = {
            "requested": deploy,
            "status": "not_attempted",
            "targets": [],
        }

    @staticmethod
    def _all_orchestrators(plan: InterfaceWorkflowPlan) -> tuple[NDBaseInterfaceOrchestrator, ...]:
        """Return resource and auxiliary orchestrators once, preserving construction order."""
        values = [resource.orchestrator for resource in plan.resources]
        values.extend(getattr(plan, "auxiliary_orchestrators", ()))
        unique: list[NDBaseInterfaceOrchestrator] = []
        seen: set[int] = set()
        for orchestrator in values:
            if id(orchestrator) in seen:
                continue
            seen.add(id(orchestrator))
            unique.append(orchestrator)
        return tuple(unique)

    @staticmethod
    def _routed_delete_orchestrator(plan: InterfaceWorkflowPlan) -> NDBaseInterfaceOrchestrator | None:
        """Return the planner-selected orchestrator that accepts platform-specific reset work."""
        candidates = [*getattr(plan, "auxiliary_orchestrators", ())]
        candidates.extend(resource.orchestrator for resource in plan.resources)
        return next(
            (orchestrator for orchestrator in candidates if "platform_reset" in orchestrator.deferred_delete_queue_names),
            None,
        )

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
        """Return per-item response outcomes using the HTTP 207 exact-success contract."""
        data = response.get("DATA")
        if not isinstance(data, dict):
            return []
        is_multistatus = response.get("RETURN_CODE") == 207
        outcomes: list[dict[str, Any]] = []
        for key in _OUTCOME_KEYS:
            values = data.get(key)
            if isinstance(values, list):
                outcomes.extend(value for value in values if isinstance(value, dict) and (is_multistatus or value.get("status") is not None))
        return outcomes

    @staticmethod
    def _outcome_targets(outcome: dict[str, Any], targets: Iterable[Target]) -> tuple[Target, ...]:
        """Map one outcome to its exact target or to every target in an identified switch scope."""
        name_value = outcome.get("interfaceName") or outcome.get("name")
        switch_value = outcome.get("switchId") or outcome.get("serialNumber")
        if name_value is None and switch_value is None:
            return ()
        candidates = list(targets)
        if name_value is not None:
            candidates = [target for target in candidates if target[0].lower() == str(name_value).lower()]
        if switch_value is not None:
            candidates = [target for target in candidates if target[1] == str(switch_value)]
        if switch_value is not None and name_value is None:
            return tuple(candidates)
        return tuple(candidates) if len(candidates) == 1 else ()

    @classmethod
    def _classify_response(
        cls,
        targets: Iterable[Target],
        response: dict[str, Any] | None,
        result: dict[str, Any] | None,
        error: str,
    ) -> dict[Target, tuple[str, str | None]]:
        """Classify per-target evidence, allowing only exact success outcomes on HTTP 207."""
        target_list = list(dict.fromkeys(targets))
        response = response or {}
        result = result or {}
        is_multistatus = response.get("RETURN_CODE") == 207
        outcomes = cls._response_outcomes(response)
        if result.get("success") is True and not is_multistatus:
            return {target: ("succeeded", None) for target in target_list}

        classified: dict[Target, tuple[str, str | None]] = {}
        for outcome in outcomes:
            status = str(outcome.get("status") or "").strip().lower()
            is_failure = status in _FAILURE_STATUSES or (is_multistatus and status not in _SUCCESS_STATUSES)
            outcome_targets = cls._outcome_targets(outcome, target_list)
            if not outcome_targets:
                continue
            message = outcome.get("message") or outcome.get("warningMessage")
            for target in outcome_targets:
                if status in _SUCCESS_STATUSES:
                    classified.setdefault(target, ("succeeded", str(message) if message else None))
                elif is_failure:
                    # A failure wins if a malformed 207 repeats one target with conflicting statuses.
                    classified[target] = ("failed", str(message) if message else error)

        changed_on_failure = result.get("changed") is True
        for target in target_list:
            if target not in classified:
                classified[target] = (
                    "failed" if is_multistatus else ("uncertain" if changed_on_failure or outcomes else "failed"),
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

    @classmethod
    def _apply_success_response(
        cls,
        items: list[InterfaceExecutionItem],
        response: dict[str, Any] | None,
        result: dict[str, Any] | None,
        error: str,
    ) -> bool:
        """Apply a normal-return response, enforcing exact per-target evidence for HTTP 207."""
        response = response or {}
        if response.get("RETURN_CODE") != 207:
            for item in items:
                item.status = "succeeded"
            return True
        outcomes = cls._classify_response((item.target for item in items), response, result, error)
        cls._apply_outcomes(items, outcomes)
        return all(item.status == "succeeded" for item in items)

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
        history = self._write_history(orchestrator.rest_send, response_start, result_start)
        response, result = history[-1] if history else ({}, {})
        error = f"{context}: HTTP 207 response did not report exact success for every requested interface."
        if not self._apply_success_response(items, response, result, error):
            self._errors.append(error)
            return False
        return True

    def _enable_writes_and_preflight(self, plan: InterfaceWorkflowPlan) -> bool:
        for orchestrator in self._all_orchestrators(plan):
            orchestrator.rest_send.check_mode = False
            orchestrator.rest_send.params["check_mode"] = False
            orchestrator.deploy = False
            if orchestrator.results is not None:
                orchestrator.results.check_mode = False
        try:
            if plan.resources:
                plan.resources[0].orchestrator.validate_prerequisites()
            for resource in plan.resources:
                has_mutations = bool(resource.transitions or resource.operations.deletes or resource.operations.updates or resource.operations.creates)
                if not has_mutations:
                    continue
                if resource.state == "deleted":
                    resource.orchestrator.preflight_delete(list(resource.operations.deletes))
                    if resource.platform_deletes:
                        routed_orchestrator = self._routed_delete_orchestrator(plan)
                        if routed_orchestrator is None:
                            raise RuntimeError("Platform-specific physical deletes were planned without a routed reset orchestrator.")
                        routed_orchestrator.preflight_delete(list(resource.platform_deletes))
                    continue
                create_candidates = [*resource.operations.creates, *(transition.desired for transition in resource.transitions)]
                resource.orchestrator.preflight_create(create_candidates)
                resource.orchestrator.preflight(list(resource.proposed))
        except Exception as exc:  # pylint: disable=broad-except
            self._errors.append(f"Pre-mutation prerequisite validation failed: {exc}")
            return False
        return True

    def _queue_delete_batch(
        self,
        resource: InterfaceResourcePlan,
        orchestrator: NDBaseInterfaceOrchestrator,
        models: list[NDBaseModel],
    ) -> bool:
        """Queue one model batch and mark only targets accepted into the orchestrator's deferred contract."""
        if not models:
            return True
        items = [self._item(resource, "delete", model) for model in models]
        if orchestrator.supports_bulk_delete:
            if not self._call_items(
                orchestrator,
                items,
                lambda: orchestrator.delete_bulk(models),
                f"resources[{resource.resource_index}] {resource.resource_type} delete preparation failed",
            ):
                return False
            pending = set(orchestrator.pending_deferred_delete_targets)
            for item in items:
                if item.target in pending:
                    item.status = "queued"
                else:
                    item.status = "skipped"
                    item.message = "The develop orchestrator intentionally skipped this deletion."
            return True

        for model, item in zip(models, items):
            if not self._call_items(
                orchestrator,
                [item],
                lambda model=model: orchestrator.delete(model),
                f"resources[{resource.resource_index}] {resource.resource_type} delete failed",
            ):
                return False
        return True

    def _queue_deletes(self, plan: InterfaceWorkflowPlan) -> bool:
        for resource in plan.resources:
            models = list(resource.operations.deletes)
            if not models:
                continue
            platform_by_identifier = {model.get_identifier_value(): model for model in getattr(resource, "platform_deletes", ())}
            ordinary = [model for model in models if model.get_identifier_value() not in platform_by_identifier]
            if not self._queue_delete_batch(resource, resource.orchestrator, ordinary):
                return False
            if not platform_by_identifier:
                continue
            routed_orchestrator = self._routed_delete_orchestrator(plan)
            if routed_orchestrator is None:
                self._errors.append(
                    f"resources[{resource.resource_index}] {resource.resource_type} platform-specific delete has no routed reset orchestrator."
                )
                return False
            if not self._queue_delete_batch(resource, routed_orchestrator, list(platform_by_identifier.values())):
                return False
        return True

    def _apply_deferred_history(
        self,
        groups: tuple[DeferredDeleteRequestGroup, ...],
        history: list[tuple[dict[str, Any], dict[str, Any]]],
        error: str,
        *,
        raised: bool,
    ) -> bool:
        """Apply each response only to the exact deferred request group that produced it."""
        success = not raised
        failure_located = False
        for index, group in enumerate(groups):
            items = [item for item in self._items if item.action == "delete" and item.status == "queued" and item.target in group.targets]
            if not items:
                continue
            if index < len(history):
                response, result = history[index]
                if result.get("success") is True:
                    group_ok = self._apply_success_response(items, response, result, error)
                else:
                    self._apply_outcomes(
                        items,
                        self._classify_response((item.target for item in items), response, result, error),
                    )
                    group_ok = False
                if not group_ok:
                    success = False
                    failure_located = True
                continue
            if raised and not failure_located:
                for item in items:
                    item.status = "failed"
                    item.message = error
                failure_located = True
                success = False
                continue
            for item in items:
                item.status = "not_attempted"
                item.message = error
            success = False
        return success

    def _transfer_and_flush_deletes(
        self,
        sources: list[NDBaseInterfaceOrchestrator],
        context: str,
    ) -> bool:
        """Consolidate compatible deferred queues, flush once, and correlate every request boundary."""
        source_queues: list[tuple[NDBaseInterfaceOrchestrator, dict[str, tuple[Target, ...]]]] = []
        queues: dict[str, tuple[Target, ...]] = {}
        for source in sources:
            local = {queue_name: targets for queue_name, targets in source.deferred_delete_queues.items() if targets}
            source_queues.append((source, local))
            for queue_name, targets in local.items():
                queues[queue_name] = tuple(dict.fromkeys((*queues.get(queue_name, ()), *targets)))
        if not queues:
            return True
        required = frozenset(queues)
        target = next((source for source in sources if required.issubset(source.deferred_delete_queue_names)), None)
        if target is None:
            self._errors.append(f"{context}: no orchestrator accepts deferred queues {sorted(required)}.")
            return False
        for queue_name, targets in queues.items():
            target.queue_deferred_delete_targets(queue_name, targets)
        for source, local in source_queues:
            if source is target:
                continue
            for queue_name, targets in local.items():
                source.dequeue_deferred_delete_targets(queue_name, targets)
        groups = target.deferred_delete_request_groups()
        response_start = len(target.rest_send.responses)
        result_start = len(target.rest_send.results)
        try:
            target.remove_pending()
        except Exception as exc:  # pylint: disable=broad-except
            error = f"{context}: {exc}"
            history = self._write_history(target.rest_send, response_start, result_start)
            self._apply_deferred_history(groups, history, error, raised=True)
            self._errors.append(error)
            return False
        history = self._write_history(target.rest_send, response_start, result_start)
        error = f"{context}: controller responses did not report exact success for every requested interface."
        if not self._apply_deferred_history(groups, history, error, raised=False):
            self._errors.append(error)
            return False
        return True

    def _flush_base_removes(self, plan: InterfaceWorkflowPlan) -> bool:
        sources = [
            orchestrator
            for orchestrator in self._all_orchestrators(plan)
            if not isinstance(orchestrator, EthernetBaseOrchestrator) and orchestrator.pending_deferred_delete_targets
        ]
        return self._transfer_and_flush_deletes(sources, "Consolidated interface removal failed")

    def _flush_ethernet_removes(self, plan: InterfaceWorkflowPlan) -> bool:
        sources = [
            orchestrator
            for orchestrator in self._all_orchestrators(plan)
            if isinstance(orchestrator, EthernetBaseOrchestrator) and orchestrator.pending_deferred_delete_targets
        ]
        return self._transfer_and_flush_deletes(sources, "Consolidated Ethernet normalization/reset failed")

    def _execute_transitions(self, plan: InterfaceWorkflowPlan) -> bool:
        """Replace approved foreign policies through destination-family PUTs."""
        for resource in plan.resources:
            for transition in resource.transitions:
                item = self._item(resource, "transition", transition.desired)
                if not self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda resource=resource, transition=transition: resource.orchestrator.update(transition.desired, existing_data=transition.current),
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
                # Most interface families have one frozen policy type, so this remains one POST per switch. Loopback can
                # carry multiple policy discriminators and its orchestrator sends one POST per (switch, policy type);
                # matching that boundary here keeps each response tied to exactly the items in its controller request.
                groups: dict[tuple[str, Any], list[NDBaseModel]] = defaultdict(list)
                for model in models:
                    switch_id = self._model_target(resource, model)[1]
                    policy_type = getattr(model, "policy_type", None)
                    groups[(switch_id, getattr(policy_type, "value", policy_type))].append(model)
                for (switch_id, _policy_type), group in groups.items():
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

    def _deploy_pending(
        self,
        plan: InterfaceWorkflowPlan,
        supplemental_targets: Iterable[Target] = (),
        mutation_targets: Iterable[Target] | None = None,
    ) -> bool:
        selected_mutations = (
            (pair for orchestrator in self._all_orchestrators(plan) for pair in orchestrator.pending_deploys) if mutation_targets is None else mutation_targets
        )
        targets = tuple(dict.fromkeys((*selected_mutations, *supplemental_targets)))
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
        response_start = len(target.rest_send.responses)
        result_start = len(target.rest_send.results)
        try:
            target.deploy_targets(targets)
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
            self._dequeue_deployed_targets(plan)
            self._errors.append(error)
            return False
        history = self._write_history(target.rest_send, response_start, result_start)
        response, result = history[-1] if history else ({}, {})
        if response.get("RETURN_CODE") == 207:
            error = "Consolidated interface deployment failed: HTTP 207 response did not report exact success for every requested interface."
            outcomes = self._classify_response(targets, response, result, error)
            for entry in self._deployment["targets"]:
                status, message = outcomes[(entry["interface_name"], entry["switch_id"])]
                entry["status"] = status
                if message:
                    entry["message"] = message
            statuses = {entry["status"] for entry in self._deployment["targets"]}
            if statuses != {"succeeded"}:
                self._deployment["status"] = "partial_failure" if "succeeded" in statuses else "failed"
                self._deployment["message"] = error
                self._dequeue_deployed_targets(plan)
                self._errors.append(error)
                return False
        else:
            for entry in self._deployment["targets"]:
                entry["status"] = "succeeded"
        self._deployment["status"] = "succeeded"
        self._dequeue_deployed_targets(plan)
        return True

    def _dequeue_deployed_targets(self, plan: InterfaceWorkflowPlan) -> None:
        """Drain only targets backed by exact successful deployment evidence from every source queue."""
        succeeded = {(entry["interface_name"], entry["switch_id"]) for entry in self._deployment["targets"] if entry["status"] == "succeeded"}
        if not succeeded:
            return
        for orchestrator in self._all_orchestrators(plan):
            orchestrator.dequeue_deploy_targets(succeeded)

    @staticmethod
    def _write_observations(plan: InterfaceWorkflowPlan) -> tuple[int, int, bool]:
        mutation_requests = 0
        deploy_requests = 0
        mutation_changed = False
        seen: set[int] = set()
        for orchestrator in InterfaceWorkflowExecutor._all_orchestrators(plan):
            rest_send = orchestrator.rest_send
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

    def _reconcile(
        self,
        plan: InterfaceWorkflowPlan,
        *,
        mutation_attempted: bool,
        force_after_write: bool,
    ) -> dict[int, NDConfigCollection]:
        """Return observed state, skipping successful post-write refresh when verification is disabled."""
        if mutation_attempted and not (self.verify or force_after_write):
            return {}
        if mutation_attempted:
            try:
                self.snapshot.mark_dirty(plan.target_switch_ids)
                self.snapshot.refresh(plan.target_switch_ids)
            except Exception as exc:  # pylint: disable=broad-except
                self._errors.append(f"Post-mutation interface snapshot refresh failed: {exc}")
                return {}
        actual: dict[int, NDConfigCollection] = {}
        vpc_inventory = None
        try:
            for resource in plan.resources:
                if resource.adapter.ownership_domain != "vpc":
                    actual[resource.resource_index] = resource.adapter.existing_collection(resource.orchestrator)
                    continue
                if vpc_inventory is None:
                    vpc_inventory = self.snapshot.interfaces_by_identity
                actual[resource.resource_index] = InterfaceWorkflowPlanner.pair_scoped_vpc_collection(
                    inventory=vpc_inventory,
                    adapter=resource.adapter,
                    orchestrator=resource.orchestrator,
                    proposed=resource.proposed,
                )
        except Exception as exc:  # pylint: disable=broad-except
            self._errors.append(f"Post-mutation actual-state selection failed: {exc}")
            return {}
        return actual

    def execute(
        self,
        plan: InterfaceWorkflowPlan,
        deployment_targets: Iterable[Target] = (),
    ) -> InterfaceWorkflowExecution:
        """Execute mutation and exact-target deployment phases, then reconcile intended state."""
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
            phases_ok = self._deploy_pending(plan, deployment_targets)
        elif self.deploy:
            accepted_targets = tuple(dict.fromkeys(item.target for item in self._items if item.status == "succeeded"))
            if accepted_targets:
                self._deploy_pending(plan, mutation_targets=accepted_targets)

        mutation_requests, deploy_requests, mutation_changed = self._write_observations(plan)
        execution_failed = not phases_ok or bool(self._errors)
        mutation_attempted = bool(mutation_requests) or any(item.status in {"succeeded", "failed", "uncertain"} for item in self._items)
        actual = self._reconcile(
            plan,
            mutation_attempted=mutation_attempted,
            force_after_write=execution_failed,
        )
        actual_changed = any(
            resource.before.get_diff_collection(actual[resource.resource_index]) for resource in plan.resources if resource.resource_index in actual
        )
        failed = not phases_ok or bool(self._errors)
        deployment_changed = any(target["status"] in {"succeeded", "uncertain"} for target in self._deployment["targets"])
        exact_mutation_success = any(item.status == "succeeded" for item in self._items)
        changed = mutation_changed or exact_mutation_success or actual_changed or deployment_changed
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
            affected_switch_ids=plan.target_switch_ids if mutation_attempted else (),
            deployment=self._deployment,
            errors=tuple(self._errors),
            actual_after_by_resource=actual,
        )
