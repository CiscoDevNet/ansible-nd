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
    InterfaceWorkflowOperation,
    InterfaceWorkflowPlan,
    InterfaceWorkflowPlanner,
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
    def _request_markers(rest_send) -> tuple[int, int]:
        """Return cheap response/result freshness markers without copying accumulated history."""
        response_count = getattr(rest_send, "response_count", None)
        result_count = getattr(rest_send, "result_count", None)
        if not isinstance(response_count, int):
            response_count = len(rest_send.responses)
        if not isinstance(result_count, int):
            result_count = len(rest_send.results)
        return response_count, result_count

    @classmethod
    def _fresh_current(
        cls,
        rest_send,
        markers: tuple[int, int],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return only current records proven newer than the supplied markers."""
        response_start, result_start = markers
        response_count, result_count = cls._request_markers(rest_send)
        response = rest_send.response_current if response_count > response_start else {}
        result = rest_send.result_current if result_count > result_start else {}
        return response, result

    @classmethod
    def _fresh_mutation_result(
        cls,
        rest_send,
        markers: tuple[int, int],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Select a write response, never a later recovery inventory GET."""
        response_start, result_start = markers
        response_count, _result_count = cls._request_markers(rest_send)
        if response_count <= response_start:
            return {}, {}
        responses = rest_send.responses[response_start:response_count]
        results = rest_send.results[result_start:]
        for index in range(len(responses) - 1, -1, -1):
            response = responses[index]
            if not isinstance(response, dict) or response.get("METHOD") == "GET":
                continue
            result = results[index] if index < len(results) and isinstance(results[index], dict) else {}
            return response, result
        return {}, {}

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
        markers = self._request_markers(orchestrator.rest_send)
        create_targets = {item.target for item in items if item.action == "create"}
        pending_before = set(orchestrator.pending_deploys) if create_targets else set()
        try:
            operation()
        except Exception as exc:  # pylint: disable=broad-except
            error = f"{context}: {exc}"
            response, result = self._fresh_mutation_result(orchestrator.rest_send, markers)
            outcomes = self._classify_response((item.target for item in items), response, result, error)
            # The standalone bulk-create path can recover exact accepted names
            # after a flat HTTP 500. Its recovery GET is not a write result;
            # only newly queued exact targets may override failed/uncertain.
            newly_accepted = set(orchestrator.pending_deploys) - pending_before if create_targets else set()
            for target in create_targets & newly_accepted:
                outcomes[target] = ("succeeded", None)
            self._apply_outcomes(items, outcomes)
            self._errors.append(error)
            return False
        response, result = self._fresh_current(orchestrator.rest_send, markers)
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
                        resource.orchestrator.preflight_delete(list(resource.platform_deletes))
                    continue
                create_candidates = [*resource.operations.creates, *(transition.desired for transition in resource.transitions)]
                resource.orchestrator.preflight_create(create_candidates)
                mutation_candidates = [
                    *(transition.desired for transition in resource.transitions),
                    *resource.operations.updates,
                    *resource.operations.creates,
                ]
                preflight_candidates = list(resource.proposed) if resource.state == "overridden" else mutation_candidates
                resource.orchestrator.preflight(preflight_candidates)
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

    def _queue_deletes(
        self,
        plan: InterfaceWorkflowPlan,
        operations: Iterable[InterfaceWorkflowOperation] | None = None,
    ) -> bool:
        selected: dict[int, list[NDBaseModel]] | None = None
        if operations is not None:
            selected = defaultdict(list)
            for operation in operations:
                selected[operation.resource_index].append(operation.model)
        for resource in plan.resources:
            models = list(resource.operations.deletes) if selected is None else selected.get(resource.resource_index, [])
            if not models:
                continue
            platform_by_identifier = {model.get_identifier_value(): model for model in getattr(resource, "platform_deletes", ())}
            ordinary = [model for model in models if model.get_identifier_value() not in platform_by_identifier]
            platform = [platform_by_identifier[model.get_identifier_value()] for model in models if model.get_identifier_value() in platform_by_identifier]
            if not self._queue_delete_batch(resource, resource.orchestrator, ordinary):
                return False
            if not platform:
                continue
            if not self._queue_delete_batch(resource, resource.orchestrator, platform):
                return False
        return True

    @staticmethod
    def _queue_targets(orchestrator: NDBaseInterfaceOrchestrator, queue_name: str) -> tuple[Target, ...]:
        """Return one immutable deferred-queue snapshot."""
        return tuple(orchestrator.deferred_delete_queues.get(queue_name, ()))

    def _transfer_delete_queue(
        self,
        sources: list[NDBaseInterfaceOrchestrator],
        queue_name: str,
        context: str,
    ) -> tuple[NDBaseInterfaceOrchestrator, tuple[Target, ...]] | None:
        """Consolidate one compatible queue without combining family-specific reset profiles."""
        source_queues: list[tuple[NDBaseInterfaceOrchestrator, tuple[Target, ...]]] = []
        targets: tuple[Target, ...] = ()
        for source in sources:
            local = self._queue_targets(source, queue_name)
            if not local:
                continue
            source_queues.append((source, local))
            targets = tuple(dict.fromkeys((*targets, *local)))
        if not targets:
            return None
        target = next((source for source in sources if queue_name in source.deferred_delete_queue_names), None)
        if target is None:
            self._errors.append(f"{context}: no orchestrator accepts deferred queue {queue_name!r}.")
            return None
        target.queue_deferred_delete_targets(queue_name, targets)
        for source, local in source_queues:
            if source is target:
                continue
            source.dequeue_deferred_delete_targets(queue_name, local)
        return target, targets

    def _flush_delete_queue(
        self,
        target: NDBaseInterfaceOrchestrator,
        queue_name: str,
        context: str,
    ) -> bool:
        """Flush one queue and reconcile exact accepted targets from its pre/post snapshots.

        A logical normalize group may emit more than one HTTP response when the no-description retry is used. Queue drainage is
        therefore the authoritative request-to-target evidence; the fresh current response is used only to enrich the first remaining
        failed group, never to align history positions with logical groups.
        """
        before = self._queue_targets(target, queue_name)
        if not before:
            return True
        groups = tuple(group.targets for group in target.deferred_delete_request_groups() if group.queue_name == queue_name)
        markers = self._request_markers(target.rest_send)
        raised = False
        exception: Exception | None = None
        try:
            flush_one = getattr(target, "remove_pending_queue", None)
            if callable(flush_one):
                flush_one(queue_name)
            else:
                target.remove_pending()
        except Exception as exc:  # pylint: disable=broad-except
            raised = True
            exception = exc

        after = self._queue_targets(target, queue_name)
        remaining = set(after)
        accepted = [candidate for candidate in before if candidate not in remaining]
        for item in self._items:
            if item.action == "delete" and item.status == "queued" and item.target in accepted:
                item.status = "succeeded"
                item.message = None

        if not raised and not remaining:
            return True

        error = f"{context}: {exception}" if raised else f"{context}: controller did not accept every queued interface."
        response, result = self._fresh_current(target.rest_send, markers)
        first_remaining_group = next((set(group) for group in groups if set(group) & remaining), set(remaining))
        response_outcomes = self._classify_response(first_remaining_group, response, result, error) if raised and response else {}
        for item in self._items:
            if item.action != "delete" or item.status != "queued" or item.target not in remaining:
                continue
            if raised and item.target not in first_remaining_group:
                item.status = "not_attempted"
            else:
                status, message = response_outcomes.get(item.target, ("failed", error))
                item.status = "failed" if status == "succeeded" else status
                item.message = message or error
            if item.message is None:
                item.message = error
        if error not in self._errors:
            self._errors.append(error)
        return False

    def _flush_base_removes(self, plan: InterfaceWorkflowPlan) -> bool:
        sources = [
            orchestrator
            for orchestrator in self._all_orchestrators(plan)
            if not isinstance(orchestrator, EthernetBaseOrchestrator) and orchestrator.pending_deferred_delete_targets
        ]
        transferred = self._transfer_delete_queue(sources, "remove", "Consolidated interface removal failed")
        if transferred is None:
            return not any(self._queue_targets(source, "remove") for source in sources)
        target, _targets = transferred
        return self._flush_delete_queue(target, "remove", "Consolidated interface removal failed")

    def _flush_ethernet_removes(self, plan: InterfaceWorkflowPlan) -> bool:
        sources = [
            orchestrator
            for orchestrator in self._all_orchestrators(plan)
            if isinstance(orchestrator, EthernetBaseOrchestrator) and orchestrator.pending_deferred_delete_targets
        ]
        # Platform reset payloads are class-specific. Flush each family's queue in place before combining the two NX-OS queues.
        for source in sources:
            if self._queue_targets(source, "platform_reset") and not self._flush_delete_queue(
                source,
                "platform_reset",
                f"{type(source).__name__} IOS-XE reset failed",
            ):
                return False
        for queue_name, label in (
            ("normalize", "Consolidated Ethernet normalization failed"),
            ("reset", "Consolidated Ethernet PUT reset failed"),
        ):
            transferred = self._transfer_delete_queue(sources, queue_name, label)
            if transferred is None:
                if any(self._queue_targets(source, queue_name) for source in sources):
                    return False
                continue
            target, _targets = transferred
            if not self._flush_delete_queue(target, queue_name, label):
                return False
        return True

    def _execute_transitions(
        self,
        plan: InterfaceWorkflowPlan,
        operations: Iterable[InterfaceWorkflowOperation] | None = None,
    ) -> bool:
        """Replace approved foreign policies through destination-family PUTs."""
        selected = None if operations is None else {operation.key for operation in operations}
        for resource in plan.resources:
            for transition in resource.transitions:
                operation_key = self._scheduled_key(resource, "transition", transition.desired)
                if selected is not None and operation_key not in selected:
                    continue
                item = self._item(resource, "transition", transition.desired)
                if not self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda resource=resource, transition=transition: resource.orchestrator.update(transition.desired, existing_data=transition.current),
                    f"resources[{resource.resource_index}] {resource.resource_type} policy transition failed",
                ):
                    return False
        return True

    def _execute_updates(
        self,
        plan: InterfaceWorkflowPlan,
        operations: Iterable[InterfaceWorkflowOperation] | None = None,
    ) -> bool:
        selected = None if operations is None else {operation.key for operation in operations}
        for resource in plan.resources:
            for model in resource.operations.updates:
                if selected is not None and self._scheduled_key(resource, "update", model) not in selected:
                    continue
                item = self._item(resource, "update", model)
                if not self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda resource=resource, model=model: resource.orchestrator.update(model),
                    f"resources[{resource.resource_index}] {resource.resource_type} update failed",
                ):
                    return False
        return True

    def _execute_creates(
        self,
        plan: InterfaceWorkflowPlan,
        operations: Iterable[InterfaceWorkflowOperation] | None = None,
    ) -> bool:
        selected_by_resource: dict[int, set[tuple[int, str, str, str]]] | None = None
        if operations is not None:
            selected_by_resource = defaultdict(set)
            for operation in operations:
                selected_by_resource[operation.resource_index].add(operation.key)
        for resource in plan.resources:
            models = list(resource.operations.creates)
            if selected_by_resource is not None:
                selected = selected_by_resource.get(resource.resource_index, set())
                models = [model for model in models if self._scheduled_key(resource, "create", model) in selected]
            if not models:
                continue
            if resource.orchestrator.supports_bulk_create:
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

    @staticmethod
    def _scheduled_key(
        resource: InterfaceResourcePlan,
        action: str,
        model: NDBaseModel,
    ) -> tuple[int, str, str, str]:
        """Return the planner/executor key for one model mutation."""

        switch_id = resource.orchestrator.fabric_context.get_switch_id(getattr(model, "switch_ip"))
        return resource.resource_index, action, switch_id, getattr(model, "interface_name").casefold()

    def _execute_scheduled_layers(self, plan: InterfaceWorkflowPlan) -> bool:
        """Execute dependency layers, flushing deferred deletes between layers."""

        for layer in plan.execution_layers:
            if not layer:
                continue
            actions = {operation.action for operation in layer}
            if len(actions) != 1:
                self._errors.append("Interface execution schedule contains a mixed-action layer.")
                return False
            action = next(iter(actions))
            if action == "delete":
                if not self._queue_deletes(plan, layer):
                    return False
                if not self._flush_base_removes(plan):
                    return False
                if not self._flush_ethernet_removes(plan):
                    return False
                continue
            if action == "transition":
                if not self._execute_transitions(plan, layer):
                    return False
                continue
            if action == "update":
                refresh_operations = [operation for operation in layer if operation.refresh_before]
                if refresh_operations:
                    selected_by_resource: dict[int, list[NDBaseModel]] = defaultdict(list)
                    for operation in refresh_operations:
                        selected_by_resource[operation.resource_index].append(operation.model)
                    for resource in plan.resources:
                        models = selected_by_resource.get(resource.resource_index, [])
                        if not models:
                            continue
                        if not isinstance(resource.orchestrator, EthernetBaseOrchestrator):
                            self._errors.append(f"resources[{resource.resource_index}] scheduled a member refresh on an unsupported orchestrator.")
                            return False
                        try:
                            resource.orchestrator.refresh_member_update_contexts(models)
                        except Exception as exc:  # pylint: disable=broad-except
                            self._errors.append(f"resources[{resource.resource_index}] member state refresh after parent mutation failed: {exc}")
                            return False
                if not self._execute_updates(plan, layer):
                    return False
                continue
            if action == "create":
                if not self._execute_creates(plan, layer):
                    return False
                continue
            self._errors.append(f"Interface execution schedule contains unsupported action {action!r}.")
            return False
        return True

    def _prepare_vpc_deploy_context(self, plan: InterfaceWorkflowPlan, targets: tuple[Target, ...]) -> None:
        """Let each vPC source prove its pair/child preview before consolidated deployment.

        Mutation execution defers every source orchestrator's deploy flag, so
        its ordinary create/update path does not queue this preview. The
        consolidated target cannot infer an omitted peer's generated children
        from a generic preview; the vPC source has the authoritative pair
        context and must establish that scope itself.
        """

        for resource in plan.resources:
            if resource.adapter.ownership_domain != "vpc":
                continue
            models = (
                *resource.proposed,
                *resource.operations.deletes,
                *resource.operations.updates,
                *resource.operations.creates,
                *(transition.desired for transition in resource.transitions),
            )
            resource_keys = {resource.orchestrator._normalized_interface_pair(*self._model_target(resource, model)) for model in models}
            selected = [pair for pair in targets if resource.orchestrator._normalized_interface_pair(*pair) in resource_keys]
            if not selected:
                continue
            for interface_name, switch_id in selected:
                resource.orchestrator._queue_preview_derived_discovery(interface_name, switch_id)
            resource.orchestrator._discover_pending_preview_derived_identities(selected)

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
        # A vPC orchestrator expands every verification pair to its peer.
        # Use an ordinary orchestrator for a mixed-family request so only the
        # vPC parents proven by their sources receive that expansion.
        target = next((resource.orchestrator for resource in plan.resources if resource.adapter.ownership_domain != "vpc"), plan.resources[0].orchestrator)
        target.deploy = True
        markers = self._request_markers(target.rest_send)
        try:
            self._prepare_vpc_deploy_context(plan, targets)
            if isinstance(target, NDBaseInterfaceOrchestrator):
                for source in self._all_orchestrators(plan):
                    if isinstance(source, NDBaseInterfaceOrchestrator):
                        target.absorb_deploy_context_from(source)
            target.deploy_targets(targets)
        except Exception as exc:  # pylint: disable=broad-except
            error = f"Consolidated interface deployment failed: {exc}"
            response, result = self._fresh_current(target.rest_send, markers)
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
        response, result = self._fresh_current(target.rest_send, markers)
        if response.get("RETURN_CODE") == 207 and set(getattr(target, "verified_deploy_targets", ())) != set(targets):
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
        if not mutation_attempted:
            discard_overlays = getattr(self.snapshot, "discard_overlays", None)
            if callable(discard_overlays):
                discard_overlays()
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
        execution_layers = getattr(plan, "execution_layers", ())
        if phases_ok and execution_layers:
            phases_ok = self._execute_scheduled_layers(plan)
        elif phases_ok:
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

        for item in self._items:
            if item.status == "queued":
                item.status = "not_attempted"
                item.message = "An earlier interface workflow phase failed before this queued request was attempted."

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
