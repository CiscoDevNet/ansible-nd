# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Mutation execution for a completely validated aggregate interface plan."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from time import monotonic, sleep
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
_PARENT_DISCOVERY_TIMEOUT_SECONDS = 90
_PARENT_DISCOVERY_POLL_SECONDS = 2


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
    execution_sequence: int | None = None

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
        if self.execution_sequence is not None:
            result["execution_sequence"] = self.execution_sequence
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
    member_preparations: tuple[dict[str, Any], ...] = ()

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
            "member_preparations": list(self.member_preparations),
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
        self._attempted_deploy_targets: set[Target] = set()
        self._preparation_items: dict[tuple[int, str, str, str], InterfaceExecutionItem] = {}
        self._verified_preparations: set[tuple[int, str, str, str]] = set()
        self._sequence = 0
        self._preparation_verification_sequences: dict[tuple[int, str, str, str], int] = {}
        self._member_refresh_sequences: dict[tuple[int, str, str, str], int] = {}

    @staticmethod
    def _all_orchestrators(
        plan: InterfaceWorkflowPlan,
    ) -> tuple[NDBaseInterfaceOrchestrator, ...]:
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
        for preparation in plan.member_preparations:
            self._preparation_items[preparation.key] = InterfaceExecutionItem(
                resource_index=preparation.resource_index,
                resource_type=preparation.resource_type,
                action="create",
                switch_ip=getattr(preparation.model, "switch_ip"),
                switch_id=preparation.switch_id,
                interface_name=preparation.interface_name,
                from_policy_type=preparation.from_policy_type,
                to_policy_type=preparation.to_policy_type,
            )
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
                self._item_by_key[
                    (
                        resource.resource_index,
                        "transition",
                        model.get_identifier_value(),
                    )
                ] = item

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
        """Select the write response, never a later inventory GET or read-only preview POST."""
        response_start, result_start = markers
        response_count, _result_count = cls._request_markers(rest_send)
        if response_count <= response_start:
            return {}, {}
        if hasattr(rest_send, "history_since"):
            responses, results = rest_send.history_since(response_start, result_start)
        else:
            responses = rest_send.responses[response_start:response_count]
            results = rest_send.results[result_start:]
        for index in range(len(responses) - 1, -1, -1):
            response = responses[index]
            if not isinstance(response, dict):
                continue
            method = getattr(response.get("METHOD"), "value", response.get("METHOD"))
            path = str(response.get("REQUEST_PATH") or "")
            if str(method).upper() == "GET" or "interfaceActions/preview" in path:
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
        """Map one outcome to its exact target or identified switch scope."""
        name_value = outcome.get("interfaceName") or outcome.get("name")
        switch_value = outcome.get("switchId") or outcome.get("serialNumber")
        if name_value is None and switch_value is None:
            return ()
        if isinstance(name_value, str) and "~" in name_value:
            prefix, separator, suffix = name_value.partition("~")
            if not separator or not suffix or "~" in suffix or (switch_value is not None and str(switch_value).casefold() != prefix.casefold()):
                return ()
            switch_value, name_value = prefix, suffix
        candidates = list(targets)
        if name_value is not None:
            candidates = [target for target in candidates if target[0].lower() == str(name_value).lower()]
        if switch_value is not None:
            candidates = [target for target in candidates if target[1] == str(switch_value)]
        if switch_value is not None and name_value is None:
            return tuple(candidates)
        return tuple(candidates) if len(candidates) == 1 else ()

    @staticmethod
    def _target_key(target: Target) -> Target:
        """Match controller-canonical interface spelling without changing the wire target."""
        return target[0].casefold(), target[1]

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
            # A switch-level failure implicates every requested target on that
            # switch, but switch-level success cannot prove that each interface
            # was accepted or deployed by an HTTP 207 multi-status operation.
            if status in _SUCCESS_STATUSES and outcome.get("interfaceName") is None and outcome.get("name") is None:
                continue
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
                    ("failed" if is_multistatus else ("uncertain" if changed_on_failure or outcomes else "failed")),
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
        *,
        exact_207_classifier: Callable[[], tuple[set[Target], bool]] | None = None,
    ) -> bool:
        self._sequence += 1
        for item in items:
            item.execution_sequence = self._sequence
        markers = self._request_markers(orchestrator.rest_send)
        attempts_before = getattr(orchestrator.rest_send, "mutation_attempt_count", 0)
        create_targets = {item.target for item in items if item.action == "create"}
        pending_before = set(orchestrator.pending_deploys) if create_targets else set()
        try:
            operation()
        except Exception as exc:  # pylint: disable=broad-except
            error = f"{context}: {exc}"
            response, result = self._fresh_mutation_result(orchestrator.rest_send, markers)
            if response.get("RETURN_CODE") == 207 and exact_207_classifier is not None:
                accepted, _exact = exact_207_classifier()
                outcomes = {item.target: (("succeeded", None) if item.target in accepted else ("failed", error)) for item in items}
            else:
                outcomes = self._classify_response((item.target for item in items), response, result, error)
            if not response and getattr(orchestrator.rest_send, "mutation_attempt_count", 0) > attempts_before:
                outcomes = {item.target: ("uncertain", f"{error}; write was dispatched but no response was recorded") for item in items}
            # The standalone bulk-create path can recover exact accepted names
            # after a flat HTTP 500. Its recovery GET is not a write result;
            # only newly queued exact targets may override failed/uncertain.
            newly_accepted = set(orchestrator.pending_deploys) - pending_before if create_targets else set()
            for target in create_targets & newly_accepted:
                outcomes[target] = ("succeeded", None)
            self._apply_outcomes(items, outcomes)
            self._errors.append(error)
            return False
        response, result = self._fresh_mutation_result(orchestrator.rest_send, markers)
        error = f"{context}: HTTP 207 response did not report exact success for every requested interface."
        if response.get("RETURN_CODE") == 207 and exact_207_classifier is not None:
            accepted, exact = exact_207_classifier()
            for item in items:
                item.status = "succeeded" if item.target in accepted else "failed"
                item.message = None if item.target in accepted else error
            if not exact or any(item.status != "succeeded" for item in items):
                self._errors.append(error)
                return False
            return True
        if not self._apply_success_response(items, response, result, error):
            self._errors.append(error)
            return False
        return True

    def _enable_writes_and_preflight(self, plan: InterfaceWorkflowPlan) -> bool:
        for orchestrator in self._all_orchestrators(plan):
            orchestrator.rest_send.check_mode = False
            orchestrator.rest_send.params["check_mode"] = False
            orchestrator.deploy = False
            orchestrator.workflow_deploy_requested = self.deploy
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
                create_candidates = [
                    *resource.operations.creates,
                    *(transition.desired for transition in resource.transitions),
                    *(preparation.model for preparation in plan.member_preparations
                      if preparation.resource_index == resource.resource_index),
                ]
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
            pending = {self._target_key(target) for target in orchestrator.pending_deferred_delete_targets}
            for item in items:
                if self._target_key(item.target) in pending:
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
        target = next(
            (source for source in sources if queue_name in source.deferred_delete_queue_names),
            None,
        )
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
        remaining_keys = {self._target_key(candidate) for candidate in remaining}
        accepted_keys = {self._target_key(candidate) for candidate in before if self._target_key(candidate) not in remaining_keys}
        for item in self._items:
            if item.action == "delete" and item.status == "queued" and self._target_key(item.target) in accepted_keys:
                item.status = "succeeded"
                item.message = None

        if not raised and not remaining:
            return True

        error = f"{context}: {exception}" if raised else f"{context}: controller did not accept every queued interface."
        response, result = self._fresh_current(target.rest_send, markers)
        first_remaining_group = next((set(group) for group in groups if set(group) & remaining), set(remaining))
        response_outcomes = self._classify_response(first_remaining_group, response, result, error) if raised and response else {}
        outcome_by_key = {self._target_key(candidate): outcome for candidate, outcome in response_outcomes.items()}
        first_remaining_keys = {self._target_key(candidate) for candidate in first_remaining_group}
        for item in self._items:
            if item.action != "delete" or item.status != "queued" or self._target_key(item.target) not in remaining_keys:
                continue
            if raised and self._target_key(item.target) not in first_remaining_keys:
                item.status = "not_attempted"
            else:
                status, message = outcome_by_key.get(self._target_key(item.target), ("failed", error))
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
        batch_type = tuple[
            InterfaceResourcePlan,
            NDBaseModel,
            InterfaceExecutionItem,
            dict[str, Any],
            NDBaseModel | None,
            str,
        ]
        pending: list[batch_type] = []
        completed_batches: list[list[batch_type]] = []
        singular: list[tuple[InterfaceResourcePlan, NDBaseModel, InterfaceExecutionItem, NDBaseModel | None]] = []

        def execute_batch(batch: list[batch_type]) -> bool:
            if len(batch) == 1:
                resource, model, item, _payload, previous, _mode = batch[0]
                return self._call_items(
                    resource.orchestrator,
                    [item],
                    lambda: resource.orchestrator.update(model, previous_model=previous),
                    f"resources[{resource.resource_index}] {resource.resource_type} update failed",
                )
            source = batch[0][0].orchestrator
            items = [entry[2] for entry in batch]
            try:
                # A preceding batch dirties each touched switch's shared
                # snapshot. Revalidate every touched switch before another
                # request; one 4.3.1 modify request may span many switches.
                snapshot = getattr(source, "state_snapshot", None)
                if snapshot is not None:
                    for switch_id in {item.switch_id for item in items}:
                        if not snapshot.has_switch(switch_id):
                            snapshot.load_switch(switch_id)
                for resource, model, _item, _payload, previous, _mode in batch:
                    resource.orchestrator.prepare_bulk_modify_context(model, previous)
            except Exception as exc:  # pylint: disable=broad-except
                self._errors.append(f"Bulk interface update context preflight failed: {exc}")
                return False
            requested = {(item.switch_id.casefold(), item.interface_name.casefold()): (item.switch_id, item.interface_name) for item in items}
            peer_switch_ids = {
                (item.switch_id.casefold(), item.interface_name.casefold()): payload["configData"]["networkOS"]["policy"]["peerSwitchId"]
                for _resource, _model, item, payload, _previous, _mode in batch
                if str(payload.get("interfaceType") or "").casefold() == "vpc"
            }

            def classify_modify() -> tuple[set[Target], bool]:
                accepted_pairs, exact = source._bulk_modify_classify_result_pairs(requested, peer_switch_ids=peer_switch_ids)
                return {(requested[key][1], requested[key][0]) for key in accepted_pairs}, exact

            success = self._call_items(
                source,
                items,
                lambda: source.modify_bulk_prepared(
                    [entry[3] for entry in batch],
                    payload_orchestrators=[entry[0].orchestrator for entry in batch],
                    payload_models=[entry[1] for entry in batch],
                    payload_modes=[entry[5] for entry in batch],
                ),
                f"Bulk interface update failed across {len({item.switch_id for item in items})} switch(es)",
                exact_207_classifier=classify_modify,
            )
            return success

        for resource in plan.resources:
            for model in resource.operations.updates:
                if selected is not None and self._scheduled_key(resource, "update", model) not in selected:
                    continue
                item = self._item(resource, "update", model)
                previous = resource.before.get(model.get_identifier_value()) if hasattr(resource.before, "get") else None
                try:
                    prepare = getattr(resource.orchestrator, "prepare_bulk_description_update", None)
                    payload = prepare(model, previous) if callable(prepare) else None
                    mode = "description"
                    if payload is None:
                        prepare_full = getattr(resource.orchestrator, "prepare_bulk_full_update", None)
                        payload = prepare_full(model, previous) if callable(prepare_full) else None
                        mode = "full"
                except Exception as exc:  # pylint: disable=broad-except
                    item.status = "failed"
                    item.message = f"Bulk interface update preflight failed: {exc}"
                    self._errors.append(item.message)
                    return False
                if payload is not None:
                    # Preserve dependency layers, split repeated exact
                    # identities, and respect ND's documented 10,000-item
                    # request limit.
                    if len(pending) >= 10000 or any(
                        entry[2].switch_id == item.switch_id and entry[2].interface_name.casefold() == item.interface_name.casefold() for entry in pending
                    ):
                        completed_batches.append(pending)
                        pending = []
                    pending.append((resource, model, item, payload, previous, mode))
                    continue
                singular.append((resource, model, item, previous))

        if pending:
            completed_batches.append(pending)
        for batch in completed_batches:
            if not execute_batch(batch):
                return False
        # Every operation in this invocation is in the same independent
        # dependency layer; singular fallbacks may follow bulk batches without
        # crossing a parent/member or routed-parent discovery barrier.
        for resource, model, item, previous in singular:
            if not self._call_items(
                resource.orchestrator,
                [item],
                lambda resource=resource, model=model, previous=previous: resource.orchestrator.update(model, previous_model=previous),
                f"resources[{resource.resource_index}] {resource.resource_type} update failed",
            ):
                return False
        return True

    def _execute_creates(
        self,
        plan: InterfaceWorkflowPlan,
        operations: Iterable[InterfaceWorkflowOperation] | None = None,
    ) -> bool:
        """Use one guarded mixed create per independent layer when worthwhile."""
        selected_by_resource: dict[int, set[tuple[int, str, str, str]]] | None = None
        if operations is not None:
            selected_by_resource = defaultdict(set)
            for operation in operations:
                selected_by_resource[operation.resource_index].add(operation.key)
        eligible: list[tuple[InterfaceResourcePlan, NDBaseModel, InterfaceExecutionItem, dict[str, Any]]] = []
        fallback: dict[int, list[NDBaseModel]] = defaultdict(list)
        for resource in plan.resources:
            models = list(resource.operations.creates)
            if selected_by_resource is not None:
                selected = selected_by_resource.get(resource.resource_index, set())
                models = [model for model in models if self._scheduled_key(resource, "create", model) in selected]
            if not models:
                continue
            for model in models:
                try:
                    prepare = getattr(resource.orchestrator, "prepare_bulk_create_modify", None)
                    payload = prepare(model) if callable(prepare) else None
                except Exception as exc:  # pylint: disable=broad-except
                    self._errors.append(f"resources[{resource.resource_index}] {resource.resource_type} mixed-create preflight failed: {exc}")
                    return False
                if payload is None:
                    fallback[resource.resource_index].append(model)
                else:
                    eligible.append((resource, model, self._item(resource, "create", model), payload))

        batches: list[list[tuple[InterfaceResourcePlan, NDBaseModel, InterfaceExecutionItem, dict[str, Any]]]] = []
        current: list[tuple[InterfaceResourcePlan, NDBaseModel, InterfaceExecutionItem, dict[str, Any]]] = []
        reserved: set[tuple[str, str]] = set()
        for entry in eligible:
            resource, model, item, payload = entry
            keys = {(item.switch_id.casefold(), item.interface_name.casefold())}
            if str(payload.get("interfaceType") or "").casefold() == "vpc":
                keys.add((payload["configData"]["networkOS"]["policy"]["peerSwitchId"].casefold(), item.interface_name.casefold()))
            if len(current) >= 10000 or reserved & keys:
                batches.append(current)
                current = []
                reserved = set()
            current.append((resource, model, item, payload))
            reserved.update(keys)
        if current:
            batches.append(current)
        for batch in batches:
            if len(batch) == 1:
                resource, model, _item, _payload = batch[0]
                fallback[resource.resource_index].append(model)

        # Retain the established per-family path for physical assignments,
        # member-bearing parents, unqualified names, and singletons.
        for resource in plan.resources:
            models = fallback.get(resource.resource_index, [])
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
        for batch in batches:
            if len(batch) < 2:
                continue
            source = batch[0][0].orchestrator
            items = [entry[2] for entry in batch]
            touched = {item.switch_id for item in items}
            touched.update(
                entry[3]["configData"]["networkOS"]["policy"]["peerSwitchId"]
                for entry in batch
                if str(entry[3].get("interfaceType") or "").casefold() == "vpc"
            )
            try:
                for switch_id in touched:
                    if not self.snapshot.has_switch(switch_id):
                        self.snapshot.load_switch(switch_id)
            except Exception as exc:  # pylint: disable=broad-except
                self._errors.append(f"Mixed bulk create inventory refresh failed: {exc}")
                return False
            requested = {(item.switch_id.casefold(), item.interface_name.casefold()): (item.switch_id, item.interface_name) for item in items}
            peer_switch_ids = {
                (item.switch_id.casefold(), item.interface_name.casefold()): payload["configData"]["networkOS"]["policy"]["peerSwitchId"]
                for _resource, _model, item, payload in batch
                if str(payload.get("interfaceType") or "").casefold() == "vpc"
            }

            def classify_create() -> tuple[set[Target], bool]:
                accepted, exact = source._bulk_modify_classify_result_pairs(requested, peer_switch_ids=peer_switch_ids)
                return {(requested[key][1], requested[key][0]) for key in accepted}, exact

            if not self._call_items(
                source,
                items,
                lambda: source.create_bulk_modify_prepared(
                    [entry[3] for entry in batch],
                    payload_orchestrators=[entry[0].orchestrator for entry in batch],
                    payload_models=[entry[1] for entry in batch],
                ),
                f"Mixed bulk create failed across {len(touched)} switch(es)",
                exact_207_classifier=classify_create,
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
        return (
            resource.resource_index,
            action,
            switch_id,
            getattr(model, "interface_name").casefold(),
        )

    def _execute_scheduled_layers(self, plan: InterfaceWorkflowPlan) -> bool:
        """Execute dependency layers and deploy parents before dependent children."""

        barrier_keys = {operation.key for operation in getattr(plan, "parent_deployment_barriers", ())}
        if barrier_keys and not self.deploy:
            self._errors.append("A subinterface requires a same-workflow routed-parent deployment, but deploy is disabled.")
            return False
        for layer in plan.execution_layers:
            if not layer:
                continue
            actions = {operation.action for operation in layer}
            if len(actions) != 1:
                self._errors.append("Interface execution schedule contains a mixed-action layer.")
                return False
            action = next(iter(actions))
            if not self._verify_member_preparations_for_parents(plan, layer):
                return False
            if action == "delete":
                if not self._queue_deletes(plan, layer):
                    return False
                if not self._flush_base_removes(plan):
                    return False
                if not self._flush_ethernet_removes(plan):
                    return False
            elif action == "transition":
                if not self._execute_transitions(plan, layer):
                    return False
            elif action == "prepare_member":
                if not self._execute_member_preparations(plan, layer):
                    return False
            elif action == "update":
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
                            self._sequence += 1
                            for model in models:
                                self._member_refresh_sequences[self._scheduled_key(resource, "update", model)] = self._sequence
                        except Exception as exc:  # pylint: disable=broad-except
                            self._errors.append(f"resources[{resource.resource_index}] member state refresh after parent mutation failed: {exc}")
                            return False
                if not self._execute_updates(plan, layer):
                    return False
            elif action == "create":
                if not self._execute_creates(plan, layer):
                    return False
            else:
                self._errors.append(f"Interface execution schedule contains unsupported action {action!r}.")
                return False
            parents = tuple(operation for operation in layer if operation.key in barrier_keys)
            if parents and not self._deploy_and_discover_parents(plan, parents):
                return False
        return True

    def _execute_member_preparations(self, plan: InterfaceWorkflowPlan, operations: Iterable[InterfaceWorkflowOperation]) -> bool:
        """Stage guarded standalone host policies without normalization or deployment."""
        selected = {operation.key for operation in operations}
        by_resource = {resource.resource_index: resource for resource in plan.resources}
        groups = defaultdict(list)
        for preparation in plan.member_preparations:
            if preparation.key in selected:
                groups[(preparation.resource_index, preparation.switch_id, preparation.to_policy_type)].append(preparation)
        for preparations in groups.values():
            resource = by_resource[preparations[0].resource_index]
            orchestrator = resource.orchestrator
            items = [self._preparation_items[preparation.key] for preparation in preparations]
            try:
                orchestrator.refresh_new_member_preparation_contexts(
                    [preparation.model for preparation in preparations],
                    expected_records={(preparation.switch_id, preparation.interface_name.casefold()): preparation.current
                                      for preparation in preparations},
                )
            except Exception as exc:  # pylint: disable=broad-except
                message = f"resources[{resource.resource_index}] standalone member preparation preflight failed: {exc}"
                for item in items:
                    item.status, item.message = "failed", message
                self._errors.append(message)
                return False
            if not self._call_items(
                orchestrator,
                items,
                lambda orchestrator=orchestrator, preparations=preparations: orchestrator.create_bulk([preparation.model for preparation in preparations]),
                f"resources[{resource.resource_index}] standalone member preparation failed",
            ):
                return False
        return True

    def _verify_member_preparations_for_parents(self, plan: InterfaceWorkflowPlan, operations: Iterable[InterfaceWorkflowOperation]) -> bool:
        """Require fresh controller host intent before any exact parent dependency."""
        parent_keys = {operation.key for operation in operations}
        by_resource = {resource.resource_index: resource for resource in plan.resources}
        groups = defaultdict(list)
        for preparation in plan.member_preparations:
            if preparation.parent_key in parent_keys:
                groups[preparation.resource_index].append(preparation)
        for resource_index, preparations in groups.items():
            try:
                if any(self._preparation_items[preparation.key].status != "succeeded" for preparation in preparations):
                    raise RuntimeError("The required standalone preparation has no exact accepted write receipt.")
                by_resource[resource_index].orchestrator.refresh_new_member_preparation_contexts(
                    [preparation.model for preparation in preparations], require_prepared=True,
                )
            except Exception as exc:  # pylint: disable=broad-except
                self._errors.append(f"resources[{resource_index}] prepared host intent verification before parent staging failed: {exc}")
                return False
            self._verified_preparations.update(preparation.key for preparation in preparations)
            self._sequence += 1
            self._preparation_verification_sequences.update((preparation.key, self._sequence) for preparation in preparations)
        return True

    def _member_preparation_results(self, plan: InterfaceWorkflowPlan) -> tuple[dict[str, Any], ...]:
        result = []
        for preparation in plan.member_preparations:
            item = self._preparation_items[preparation.key]
            value = {**preparation.to_dict(), "status": item.status,
                     "verified_before_membership": preparation.key in self._verified_preparations,
                     "execution_sequence": item.execution_sequence,
                     "verification_sequence": self._preparation_verification_sequences.get(preparation.key)}
            parent = next((candidate for candidate in self._items
                           if (candidate.resource_index, candidate.action, candidate.switch_id, candidate.interface_name.casefold()) == preparation.parent_key), None)
            update_key = preparation.resource_index, "update", preparation.switch_id, preparation.interface_name.casefold()
            update = next((candidate for candidate in self._items
                           if (candidate.resource_index, candidate.action, candidate.switch_id, candidate.interface_name.casefold()) == update_key), None)
            value["parent_operation"] = ({"status": parent.status, "execution_sequence": parent.execution_sequence}
                                         if parent is not None else {"status": "not_attempted", "execution_sequence": None})
            value["member_refresh_sequence"] = self._member_refresh_sequences.get(update_key)
            value["member_update"] = ({"status": update.status, "execution_sequence": update.execution_sequence}
                                      if update is not None else {"status": "not_attempted", "execution_sequence": None})
            if item.message:
                value["message"] = item.message
            result.append(value)
        return tuple(result)

    def _deploy_and_discover_parents(
        self,
        plan: InterfaceWorkflowPlan,
        parents: tuple[InterfaceWorkflowOperation, ...],
    ) -> bool:
        """Deploy only accepted routed parents and wait for operational mode."""

        resources = {resource.resource_index: resource for resource in plan.resources}
        targets: list[Target] = []
        for operation in parents:
            source = resources[operation.resource_index].orchestrator
            matching = [
                target for target in source.pending_deploys if target[1] == operation.switch_id and target[0].casefold() == operation.interface_name.casefold()
            ]
            if len(matching) != 1:
                self._errors.append(f"Routed parent {operation.switch_id}/{operation.interface_name} was not queued exactly once after its accepted mutation.")
                return False
            targets.append(matching[0])
        selected = tuple(dict.fromkeys(targets))
        if not self._deploy_pending(plan, mutation_targets=selected):
            return False

        deadline = monotonic() + _PARENT_DISCOVERY_TIMEOUT_SECONDS
        pending = selected
        last_observed: dict[Target, tuple[object, object, object]] = {}

        def observed_mode(target: Target, row: dict[str, Any] | None) -> bool:
            if isinstance(row, dict):
                last_observed[target] = (
                    row.get("interfaceType"),
                    (row.get("configData") or {}).get("mode"),
                    (row.get("operData") or {}).get("mode"),
                )
            else:
                last_observed[target] = (None, None, None)
            return self._routed_parent_discovered(row)

        # A few parents are cheaper to poll by exact GET. A larger parent set
        # stays on the switch-inventory path to avoid one GET per identity.
        poll_exact = len(selected) <= 2
        while pending:
            try:
                if poll_exact:
                    pending = tuple(
                        (name, switch_id) for name, switch_id in pending if not observed_mode((name, switch_id), self.snapshot.read_exact(switch_id, name))
                    )
                    if not pending:
                        # Exact GET is only a readiness probe. Invalidate and
                        # rebuild complete state before the child safety path.
                        refreshed = self.snapshot.refresh(tuple(dict.fromkeys(switch_id for _name, switch_id in selected)))
                        pending = tuple(
                            (name, switch_id)
                            for name, switch_id in selected
                            if not observed_mode((name, switch_id), refreshed.get(switch_id, {}).get(name.casefold()))
                        )
                else:
                    refreshed = self.snapshot.refresh(tuple(dict.fromkeys(switch_id for _name, switch_id in pending)))
                    pending = tuple(
                        (name, switch_id)
                        for name, switch_id in pending
                        if not observed_mode((name, switch_id), refreshed.get(switch_id, {}).get(name.casefold()))
                    )
            except Exception as exc:  # pylint: disable=broad-except
                self._errors.append(f"Routed-parent discovery refresh failed after deployment: {exc}")
                return False
            if not pending:
                return True
            if monotonic() >= deadline:
                names = ", ".join(f"{switch_id}/{name}" for name, switch_id in pending)
                mode_summaries = []
                for name, switch_id in pending:
                    interface_type, config_mode, operational_mode = last_observed.get((name, switch_id), (None, None, None))
                    mode_summaries.append(f"{switch_id}/{name}=type:{interface_type!r},config:{config_mode!r},oper:{operational_mode!r}")
                modes = ", ".join(mode_summaries)
                self._errors.append(f"Routed-parent deployment did not reach discovered routed mode before child mutation: {names}. Last observed: {modes}.")
                return False
            sleep(min(_PARENT_DISCOVERY_POLL_SECONDS, max(0.0, deadline - monotonic())))
        return True

    @staticmethod
    def _routed_parent_discovered(row: dict[str, Any] | None) -> bool:
        """Require operational, not merely intended, routed mode."""

        if not isinstance(row, dict) or str(row.get("interfaceType") or "").casefold() not in {"ethernet", "portchannel"}:
            return False
        config_data = row.get("configData") or {}
        oper_data = row.get("operData") or {}
        return config_data.get("mode") == "routed" and oper_data.get("mode") == "routed"

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

    def _prepare_port_channel_deploy_context(self, plan: InterfaceWorkflowPlan, targets: tuple[Target, ...]) -> None:
        """Retain exact members of unchanged parents selected for deploy-only replay.

        Mutation paths register their members with the source orchestrator.
        An unchanged parent has no mutation path, so the consolidated deploy
        must do the equivalent registration before absorbing source context.
        Use the already validated current model: submitted ``ports`` may be
        omitted even though the parent owns members in controller intent.
        """

        selected = {(name.casefold(), switch_id) for name, switch_id in targets}
        staged_deletes = {(name.casefold(), switch_id) for name, switch_id in getattr(plan, "staged_delete_targets", ())}
        for resource in plan.resources:
            if resource.adapter.ownership_domain != "port_channel":
                continue
            orchestrator = resource.orchestrator
            mutated = {
                self._model_target(resource, model)
                for model in (
                    *resource.operations.deletes,
                    *resource.operations.updates,
                    *resource.operations.creates,
                    *(transition.desired for transition in resource.transitions),
                )
            }
            mutated_keys = {(name.casefold(), switch_id) for name, switch_id in mutated}
            for model in resource.before:
                name, switch_id = self._model_target(resource, model)
                key = name.casefold(), switch_id
                if key not in selected or key in mutated_keys:
                    continue
                orchestrator._prepare_deploy_context(model, switch_id)
                # A staged removal can leave a former switch-side member
                # absent from current intent even when other members remain.
                # Require parent-scoped pending CLI to prove that derived 207
                # result rather than trusting an unregistered identity.
                orchestrator._queue_preview_derived_discovery(name, switch_id)
                removed = orchestrator._removed_xe_members(model, switch_id)
                orchestrator._preview_and_queue_removed_xe_members(model, switch_id, removed)
            # A staged logical delete is already represented by an ND
            # tombstone, so the managed ``before`` collection is empty. The
            # planner has proved the exact pending parent deletion; require a
            # second parent-scoped preview to register any child reported by
            # the deployment response.
            if staged_deletes:
                for model in resource.proposed:
                    name, switch_id = self._model_target(resource, model)
                    key = name.casefold(), switch_id
                    if key in selected and key in staged_deletes and key not in mutated_keys:
                        orchestrator._queue_preview_derived_discovery(name, switch_id)

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
        if not targets:
            if not self._deployment["targets"]:
                self._deployment["status"] = "not_needed"
            return True
        blocked = {
            (name.casefold(), switch_id)
            for source in self._all_orchestrators(plan)
            for switch_id, name in getattr(source, "reset_auto_negotiation_deploy_blocks", ())
        }
        unsafe = [pair for pair in targets if (pair[0].casefold(), pair[1]) in blocked]
        if self.deploy and unsafe:
            error = f"Reset negotiation staging remains unverified for {unsafe}; consolidated deployment is blocked."
            self._deployment["status"] = "failed"
            self._deployment["message"] = error
            self._errors.append(error)
            return False
        batch = [
            {
                "interface_name": interface_name,
                "switch_id": switch_id,
                "status": "not_attempted",
            }
            for interface_name, switch_id in targets
        ]
        self._deployment["targets"].extend(batch)
        self._deployment["status"] = "disabled" if not self.deploy else "pending"
        if not self.deploy:
            return True
        # A vPC orchestrator expands every verification pair to its peer.
        # Use an ordinary orchestrator for a mixed-family request so only the
        # vPC parents proven by their sources receive that expansion.
        target = next(
            (resource.orchestrator for resource in plan.resources if resource.adapter.ownership_domain != "vpc"),
            plan.resources[0].orchestrator,
        )
        target.deploy = True
        markers: tuple[int, int] | None = None
        deploy_started = False
        queued_before = {pair for source in self._all_orchestrators(plan) for pair in source.pending_deploys}
        try:
            self._prepare_vpc_deploy_context(plan, targets)
            self._prepare_port_channel_deploy_context(plan, targets)
            # A no-diff IOS-XE parent replay may discover an exact pending
            # member detach only after its own read-only preview. Consolidate
            # that proven member into this same deployment request.
            newly_proven = (pair for source in self._all_orchestrators(plan) for pair in source.pending_deploys if pair not in queued_before)
            expanded = tuple(dict.fromkeys((*targets, *newly_proven)))
            for interface_name, switch_id in expanded[len(targets) :]:
                entry = {"interface_name": interface_name, "switch_id": switch_id, "status": "not_attempted"}
                batch.append(entry)
                self._deployment["targets"].append(entry)
            targets = expanded
            if isinstance(target, NDBaseInterfaceOrchestrator):
                for source in self._all_orchestrators(plan):
                    if isinstance(source, NDBaseInterfaceOrchestrator):
                        target.absorb_deploy_context_from(source)
            markers = self._request_markers(target.rest_send)
            deploy_started = True
            self._attempted_deploy_targets.update((name.casefold(), switch_id) for name, switch_id in targets)
            target.deploy_targets(targets)
        except Exception as exc:  # pylint: disable=broad-except
            error = f"Consolidated interface deployment failed: {exc}"
            if not deploy_started or markers is None:
                self._deployment["status"] = "failed"
                self._deployment["message"] = error
                self._errors.append(error)
                return False
            response, result = self._fresh_mutation_result(target.rest_send, markers)
            outcomes = self._classify_response(targets, response, result, error)
            for entry in batch:
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
        response, result = self._fresh_mutation_result(target.rest_send, markers)
        if not response or result.get("success") is not True:
            error = "Consolidated interface deployment returned no successful deployment response."
            outcomes = self._classify_response(targets, response, result, error)
            for entry in batch:
                status, message = outcomes[(entry["interface_name"], entry["switch_id"])]
                entry["status"] = "failed" if status == "succeeded" else status
                entry["message"] = message or error
            self._deployment["status"] = "failed"
            self._deployment["message"] = error
            self._errors.append(error)
            return False
        if response.get("RETURN_CODE") == 207 and set(getattr(target, "verified_deploy_targets", ())) != set(targets):
            error = "Consolidated interface deployment failed: HTTP 207 response did not report exact success for every requested interface."
            outcomes = self._classify_response(targets, response, result, error)
            for entry in batch:
                status, message = outcomes[(entry["interface_name"], entry["switch_id"])]
                entry["status"] = status
                if message:
                    entry["message"] = message
            batch_statuses = {entry["status"] for entry in batch}
            if batch_statuses != {"succeeded"}:
                statuses = {entry["status"] for entry in self._deployment["targets"]}
                self._deployment["status"] = "partial_failure" if "succeeded" in statuses else "failed"
                self._deployment["message"] = error
                self._dequeue_deployed_targets(plan)
                self._errors.append(error)
                return False
        else:
            for entry in batch:
                entry["status"] = "succeeded"
        statuses = {entry["status"] for entry in self._deployment["targets"]}
        self._deployment["status"] = "succeeded" if statuses == {"succeeded"} else "partial_failure"
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
            recorded_mutations = 0
            recorded_deployments = 0
            for response, result in zip(rest_send.responses, rest_send.results):
                method = str(response.get("METHOD") or "").upper()
                if method == "GET" or method.endswith(".GET"):
                    continue
                path = str(response.get("REQUEST_PATH") or "")
                if "interfaceActions/deploy" in path:
                    recorded_deployments += 1
                elif "interfaceActions/preview" in path:
                    # The preview endpoint is a read-only POST, not an intent mutation.
                    continue
                else:
                    recorded_mutations += 1
                    mutation_changed = mutation_changed or result.get("changed") is True
            mutation_requests += max(recorded_mutations, getattr(rest_send, "mutation_attempt_count", 0))
            deploy_requests += max(recorded_deployments, getattr(rest_send, "deployment_attempt_count", 0))
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
            queued_deploys = {self._target_key(pair): pair for orchestrator in self._all_orchestrators(plan) for pair in orchestrator.pending_deploys}
            accepted_targets = tuple(
                dict.fromkeys(
                    queued_deploys.get(self._target_key(item.target), item.target)
                    for item in self._items
                    if item.status == "succeeded" and (item.interface_name.casefold(), item.switch_id) not in self._attempted_deploy_targets
                )
            )
            if accepted_targets:
                self._deploy_pending(plan, mutation_targets=accepted_targets)

        for item in self._items:
            if item.status == "queued":
                item.status = "not_attempted"
                item.message = "An earlier interface workflow phase failed before this queued request was attempted."

        mutation_requests, deploy_requests, mutation_changed = self._write_observations(plan)
        execution_failed = not phases_ok or bool(self._errors)
        mutation_attempted = bool(mutation_requests) or any(item.status in {"succeeded", "failed", "uncertain"}
                                                         for item in [*self._items, *self._preparation_items.values()])
        # A deployment-only replay still needs a fresh observation when the
        # caller requested verification, even when its preview POST is no
        # longer (incorrectly) counted as an intent mutation.
        mutation_attempted = mutation_attempted or (self.verify and bool(deploy_requests))
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
        all_items = [*self._items, *self._preparation_items.values()]
        exact_mutation_success = any(item.status == "succeeded" for item in all_items)
        changed = mutation_changed or exact_mutation_success or actual_changed or deployment_changed or any(item.status == "uncertain" for item in all_items)
        if failed:
            item_statuses = {item.status for item in all_items}
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
            member_preparations=self._member_preparation_results(plan),
        )
