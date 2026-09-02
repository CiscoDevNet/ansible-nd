# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Public-module coordination for the aggregate interface workflow."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vpc_pairs import (
    EpVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import (
    INTERFACE_FAMILY_ADAPTERS,
    InterfaceDeleteStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import (
    InterfaceStateSnapshot,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import (
    InterfaceWorkflowExecution,
    InterfaceWorkflowExecutor,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowPlan,
    InterfaceWorkflowPlanner,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import (
    InterfaceDefaultConfig,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender

PlannerFactory = Callable[..., InterfaceWorkflowPlanner]
ExecutorFactory = Callable[..., InterfaceWorkflowExecutor]
Target = tuple[str, str]
VPC_PAIR_PAGE_SIZE = 500
_CAMEL_WORD_BOUNDARY = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL_LETTER_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
_MISSING = object()
_ADAPTER_BY_WIRE_IDENTITY = {
    (interface_type, policy_type): adapter
    for adapter in INTERFACE_FAMILY_ADAPTERS.values()
    for interface_type in adapter.interface_types
    for policy_type in adapter.policy_types
}


class InterfaceWorkflowExecutionFailed(RuntimeError):
    """Raised with complete output when normal-mode execution is not fully successful."""

    def __init__(self, result: dict[str, Any], message: str) -> None:
        self.result = result
        super().__init__(message)


class InterfaceWorkflowCoordinator:
    """Build one shared snapshot, plan all groups, and coordinate execution."""

    def __init__(
        self,
        module: AnsibleModule,
        planner_factory: PlannerFactory = InterfaceWorkflowPlanner,
        executor_factory: ExecutorFactory = InterfaceWorkflowExecutor,
    ) -> None:
        self.module = module
        self.planner_factory = planner_factory
        self.executor_factory = executor_factory
        self._vpc_pair_gets = 0
        self._snapshot: InterfaceStateSnapshot | None = None

    def _new_rest_send(self, params: dict[str, Any] | None = None, *, check_mode: bool | None = None) -> RestSend:
        """Build an authenticated collection REST runtime for this module invocation."""
        sender = Sender()
        sender.ansible_module = self.module
        rest_send_params = dict(params if params is not None else self.module.params)
        rest_send_params["check_mode"] = self.module.check_mode if check_mode is None else check_mode
        rest_send = RestSend(rest_send_params)
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()
        return rest_send

    @staticmethod
    def _request(
        rest_send: RestSend,
        *,
        path: str,
        verb: HttpVerbEnum,
        not_found_ok: bool = False,
    ) -> dict[str, Any]:
        """Send one read request and return its normalized DATA object."""
        rest_send.path = path
        rest_send.verb = verb
        rest_send.commit()
        if not_found_ok and rest_send.return_code == 404:
            return {}
        if not rest_send.success:
            raise RuntimeError(f"Request failed {rest_send.error_summary}")
        data = rest_send.response_current.get("DATA", {})
        return data if isinstance(data, dict) else {}

    @staticmethod
    def _uses_vpc(resources: list[dict[str, Any]]) -> bool:
        return any(isinstance(resource, dict) and resource.get("type") in {"vpc_access", "vpc_trunk_host"} for resource in resources)

    @staticmethod
    def _coerce_nonnegative_int(value: Any) -> int | None:
        """Return a non-negative integer response count, or None when unusable."""
        if isinstance(value, bool):
            return None
        try:
            converted = int(value)
        except (TypeError, ValueError):
            return None
        return converted if converted >= 0 else None

    def _vpc_pair_map(
        self,
        *,
        resources: list[dict[str, Any]],
        fabric_context: FabricContext,
        rest_send: RestSend,
    ) -> dict[str, str]:
        """Return authoritative primary-IP to peer-ID mappings for requested vPC resources."""
        if not self._uses_vpc(resources):
            return {}

        records: list[Any] = []
        offset = 0
        seen_page_signatures: set[tuple[tuple[str | None, str | None], ...]] = set()
        while True:
            endpoint = EpVpcPairsListGet()
            endpoint.fabric_name = fabric_context.fabric_name
            endpoint.endpoint_params.view = "intendedPairs"
            endpoint.lucene_params.max = VPC_PAIR_PAGE_SIZE
            endpoint.lucene_params.offset = offset
            endpoint.lucene_params.sort = "switchId:asc"
            self._vpc_pair_gets += 1
            data = self._request(rest_send, path=endpoint.path, verb=endpoint.verb, not_found_ok=True)
            page = data.get("vpcPairs") or data.get("items") or []
            if not isinstance(page, list):
                raise InterfaceWorkflowValidationError("The Nexus Dashboard vPC-pair response must contain a list in 'vpcPairs'.")

            signature = tuple(
                (
                    (
                        (record.get("switchId") or record.get("peer1SwitchId")),
                        (record.get("peerSwitchId") or record.get("peer2SwitchId")),
                    )
                    if isinstance(record, dict)
                    else (None, None)
                )
                for record in page
            )
            if page and signature in seen_page_signatures:
                raise InterfaceWorkflowValidationError(f"The Nexus Dashboard vPC-pair pagination repeated a page at offset {offset}.")
            if page:
                seen_page_signatures.add(signature)
            records.extend(page)

            metadata = data.get("meta") or data.get("metadata") or {}
            counts = metadata.get("counts") if isinstance(metadata, dict) else {}
            counts = counts if isinstance(counts, dict) else {}
            total = self._coerce_nonnegative_int(counts.get("total"))
            remaining = self._coerce_nonnegative_int(counts.get("remaining"))
            if total is not None:
                has_next = offset + len(page) < total
            elif remaining is not None:
                has_next = remaining > 0
            else:
                has_next = len(page) >= VPC_PAIR_PAGE_SIZE
            if not has_next:
                break
            if not page:
                raise InterfaceWorkflowValidationError(f"The Nexus Dashboard vPC-pair response reports more records after empty offset {offset}.")
            offset += len(page)

        declared_peer_by_switch_id: dict[str, str] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            first = record.get("switchId") or record.get("peer1SwitchId")
            second = record.get("peerSwitchId") or record.get("peer2SwitchId")
            if not isinstance(first, str) or not first or not isinstance(second, str) or not second:
                continue
            if first.casefold() == second.casefold():
                raise InterfaceWorkflowValidationError(f"The authoritative vPC-pair inventory contains a self-pair for switch '{first}'.")
            existing_peer = declared_peer_by_switch_id.get(first)
            if existing_peer is not None and existing_peer != second:
                raise InterfaceWorkflowValidationError(
                    f"The authoritative vPC-pair inventory contains conflicting mappings for switch '{first}': " f"'{existing_peer}' and '{second}'."
                )
            declared_peer_by_switch_id[first] = second

        for first, second in declared_peer_by_switch_id.items():
            inverse_peer = declared_peer_by_switch_id.get(second)
            if inverse_peer is not None and inverse_peer != first:
                raise InterfaceWorkflowValidationError(
                    "The authoritative vPC-pair inventory contains inverse-inconsistent records: "
                    f"switch '{second}' maps to '{inverse_peer}' instead of '{first}'."
                )

        peer_by_switch_id: dict[str, str] = {}
        for first, second in declared_peer_by_switch_id.items():
            for switch_id, peer_id in ((first, second), (second, first)):
                existing_peer = peer_by_switch_id.get(switch_id)
                if existing_peer is not None and existing_peer != peer_id:
                    raise InterfaceWorkflowValidationError(
                        f"The authoritative vPC-pair inventory contains conflicting mappings for switch '{switch_id}': " f"'{existing_peer}' and '{peer_id}'."
                    )
                peer_by_switch_id[switch_id] = peer_id

        pair_by_switch_ip: dict[str, str] = {}
        for switch_id, peer_id in peer_by_switch_id.items():
            try:
                switch_ip = fabric_context.get_switch_ip(switch_id)
            except RuntimeError:
                continue
            existing_peer = pair_by_switch_ip.get(switch_ip)
            if existing_peer is not None and existing_peer != peer_id:
                raise InterfaceWorkflowValidationError(
                    f"The authoritative vPC-pair inventory contains conflicting mappings for management IP '{switch_ip}': "
                    f"'{existing_peer}' and '{peer_id}'."
                )
            pair_by_switch_ip[switch_ip] = peer_id

        for resource_index, resource in enumerate(resources):
            if not isinstance(resource, dict) or resource.get("type") not in {
                "vpc_access",
                "vpc_trunk_host",
            }:
                continue
            for config_index, item in enumerate(resource.get("config") or []):
                switch_ip = item.get("switch_ip") if isinstance(item, dict) else None
                if switch_ip not in pair_by_switch_ip:
                    raise InterfaceWorkflowValidationError(
                        f"resources[{resource_index}].config[{config_index}] switch_ip '{switch_ip}' is not present in the "
                        f"authoritative vPC-pair inventory for fabric '{fabric_context.fabric_name}'."
                    )
        return pair_by_switch_ip

    def _build_plan(self) -> InterfaceWorkflowPlan:
        """Construct the live shared provider and run every adapter before execution."""
        resources = self.module.params.get("resources") or []
        rest_send = self._new_rest_send()
        fabric_name = self.module.params["fabric_name"]
        fabric_context = FabricContext(rest_send=rest_send, fabric_name=fabric_name)
        snapshot = InterfaceStateSnapshot(
            fabric_name=fabric_name,
            fabric_context=fabric_context,
            request=lambda **kwargs: self._request(rest_send, **kwargs),
        )
        self._snapshot = snapshot
        vpc_pair_by_switch_ip = self._vpc_pair_map(
            resources=resources,
            fabric_context=fabric_context,
            rest_send=rest_send,
        )
        planner = self.planner_factory(
            snapshot=snapshot,
            rest_send_factory=lambda params: self._new_rest_send(params=params, check_mode=True),
            vpc_pair_by_switch_ip=vpc_pair_by_switch_ip,
            run_capability_preflight=True,
        )
        return planner.plan(resources)

    @classmethod
    def _leaf_changes(cls, before: Any, after: Any, path: str = "") -> list[dict[str, Any]]:
        """Return deterministic changed leaf paths without embedding complete state snapshots."""
        if before is not _MISSING and after is not _MISSING and before == after:
            return []

        before_is_mapping = isinstance(before, Mapping)
        after_is_mapping = isinstance(after, Mapping)
        if before_is_mapping or after_is_mapping:
            if (before is not _MISSING and not before_is_mapping) or (after is not _MISSING and not after_is_mapping):
                return [
                    {
                        "path": path,
                        "before": None if before is _MISSING else before,
                        "after": None if after is _MISSING else after,
                    }
                ]
            before_mapping = before if before_is_mapping else {}
            after_mapping = after if after_is_mapping else {}
            keys = sorted(set(before_mapping) | set(after_mapping), key=str)
            if not keys:
                return [
                    {
                        "path": path,
                        "before": None if before is _MISSING else before,
                        "after": None if after is _MISSING else after,
                    }
                ]
            changes = []
            for key in keys:
                child_path = f"{path}.{key}" if path else str(key)
                changes.extend(
                    cls._leaf_changes(
                        before_mapping.get(key, _MISSING),
                        after_mapping.get(key, _MISSING),
                        child_path,
                    )
                )
            return changes

        return [
            {
                "path": path,
                "before": None if before is _MISSING else before,
                "after": None if after is _MISSING else after,
            }
        ]

    @staticmethod
    def _serialized_target_key(config: Mapping[str, Any]) -> tuple[str, str] | None:
        """Return a case-insensitive switch-IP/interface-name key for serialized target state."""
        switch_ip = config.get("switch_ip")
        interface_name = config.get("interface_name")
        if not isinstance(switch_ip, str) or not switch_ip or not isinstance(interface_name, str) or not interface_name:
            return None
        return switch_ip.casefold(), interface_name.casefold()

    @classmethod
    def _target_index(cls, config: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        """Index serialized target state without copying full model dictionaries."""
        return {key: item for item in config if (key := cls._serialized_target_key(item)) is not None}

    @staticmethod
    def _execution_item_key(item: Mapping[str, Any]) -> tuple[int, str, str, str] | None:
        """Return the stable key shared by planned operations and executor outcomes."""
        resource_index = item.get("resource_index")
        action = item.get("action")
        switch_ip = item.get("switch_ip")
        interface_name = item.get("interface_name")
        if not isinstance(resource_index, int) or not isinstance(action, str) or not isinstance(switch_ip, str) or not isinstance(interface_name, str):
            return None
        return resource_index, action, switch_ip.casefold(), interface_name.casefold()

    def _operation_result(
        self,
        resource,
        *,
        action: str,
        switch_ip: str,
        switch_id: str,
        interface_name: str,
        before_by_target: Mapping[tuple[str, str], dict[str, Any]],
        after_by_target: Mapping[tuple[str, str], dict[str, Any]],
        execution_items: Mapping[tuple[int, str, str, str], Mapping[str, Any]],
        from_policy_type: str | None = None,
        to_policy_type: str | None = None,
    ) -> dict[str, Any]:
        """Merge one planned action with its execution status and compact changed paths."""
        execution_key = (resource.resource_index, action, switch_ip.casefold(), interface_name.casefold())
        execution_item = execution_items.get(execution_key, {})
        public_action = action
        if action == "delete" and getattr(resource.adapter, "delete_strategy", None) == InterfaceDeleteStrategy.NORMALIZE:
            public_action = "reset"
        result = {
            "action": public_action,
            "switch_ip": switch_ip,
            "switch_id": switch_id,
            "interface_name": interface_name,
            "status": execution_item.get("status", "planned" if self.module.check_mode else "not_attempted"),
        }
        if from_policy_type is not None:
            result["from_policy_type"] = from_policy_type
        if to_policy_type is not None:
            result["to_policy_type"] = to_policy_type
        if message := execution_item.get("message"):
            result["message"] = message

        if public_action in {"reset", "transition", "update"}:
            target_key = (switch_ip.casefold(), interface_name.casefold())
            before = before_by_target.get(target_key, _MISSING)
            after = after_by_target.get(target_key, _MISSING)
            changes = self._leaf_changes(before, after)
            if changes:
                result["changes"] = changes
        return result

    def _resource_operations(
        self,
        resource,
        *,
        before_config: list[dict[str, Any]],
        after_config: list[dict[str, Any]],
        execution_items: Mapping[tuple[int, str, str, str], Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Return one compact, action-tagged operation list for a resource group."""
        before_by_target = self._target_index(before_config)
        after_by_target = self._target_index(after_config)
        context = resource.orchestrator.fabric_context
        operations = []

        for model in resource.operations.deletes:
            switch_ip = getattr(model, "switch_ip")
            interface_name = getattr(model, "interface_name")
            operations.append(
                self._operation_result(
                    resource,
                    action="delete",
                    switch_ip=switch_ip,
                    switch_id=context.get_switch_id(switch_ip),
                    interface_name=interface_name,
                    before_by_target=before_by_target,
                    after_by_target=after_by_target,
                    execution_items=execution_items,
                )
            )

        for transition in resource.transitions:
            operations.append(
                self._operation_result(
                    resource,
                    action="transition",
                    switch_ip=transition.switch_ip,
                    switch_id=transition.switch_id,
                    interface_name=transition.interface_name,
                    before_by_target=before_by_target,
                    after_by_target=after_by_target,
                    execution_items=execution_items,
                    from_policy_type=transition.from_policy_type,
                    to_policy_type=transition.to_policy_type,
                )
            )

        for action, models in (("update", resource.operations.updates), ("create", resource.operations.creates)):
            for model in models:
                switch_ip = getattr(model, "switch_ip")
                interface_name = getattr(model, "interface_name")
                operations.append(
                    self._operation_result(
                        resource,
                        action=action,
                        switch_ip=switch_ip,
                        switch_id=context.get_switch_id(switch_ip),
                        interface_name=interface_name,
                        before_by_target=before_by_target,
                        after_by_target=after_by_target,
                        execution_items=execution_items,
                    )
                )
        return operations

    @staticmethod
    def _snake_case_key(value: str) -> str:
        """Convert one controller camelCase key to Ansible snake_case."""
        first_pass = _CAMEL_WORD_BOUNDARY.sub(r"\1_\2", value)
        converted = _CAMEL_LETTER_BOUNDARY.sub(r"\1_\2", first_pass).replace("-", "_").lower()
        return re.sub(r"^i_pv([46])", r"ipv\1", converted)

    @classmethod
    def _snake_case_data(cls, value: Any) -> Any:
        """Recursively normalize controller keys for unknown-policy observations."""
        if isinstance(value, Mapping):
            return {cls._snake_case_key(str(key)): cls._snake_case_data(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._snake_case_data(item) for item in value]
        return value

    @staticmethod
    def _canonical_interface_type(value: Any) -> Any:
        """Normalize raw interface-type aliases used by different ND releases."""
        return {"switchVirtualInterface": "svi"}.get(value, value)

    @staticmethod
    def _model_policy_type(model) -> str | None:
        """Return one model's wire policy discriminator without exposing its full payload."""
        try:
            return InterfaceStateSnapshot.policy_type(model.to_payload())
        except Exception:  # pylint: disable=broad-except
            return None

    @classmethod
    def _serialize_model_target(cls, model) -> dict[str, Any]:
        """Serialize a known-family model with an explicit reporting policy discriminator."""
        result = model.to_config()
        policy_type = cls._model_policy_type(model)
        config_data = result.get("config_data")
        network_os = config_data.get("network_os") if isinstance(config_data, Mapping) else None
        policy = network_os.get("policy") if isinstance(network_os, Mapping) else None
        if isinstance(policy, dict):
            policy.pop("policy_type", None)
        if policy_type is not None:
            result["policy_type"] = policy_type
        return result

    @classmethod
    def _serialize_raw_target(cls, raw: Mapping[str, Any], switch_ip: str) -> dict[str, Any]:
        """Serialize a raw target through its source-family model when one is known."""
        current = dict(raw)
        interface_type = cls._canonical_interface_type(current.get("interfaceType"))
        current["interfaceType"] = interface_type
        current["switchIp"] = switch_ip
        policy_type = InterfaceStateSnapshot.policy_type(current)
        adapter = _ADAPTER_BY_WIRE_IDENTITY.get((interface_type, policy_type))
        if adapter is not None:
            try:
                return cls._serialize_model_target(adapter.model_class.from_response(current))
            except Exception:  # pylint: disable=broad-except
                # Result formatting must remain forward-compatible with new controller fields.
                pass

        result = {
            "switch_ip": switch_ip,
            "interface_name": current.get("interfaceName"),
            "interface_type": interface_type,
            "policy_type": policy_type,
        }
        config_data = current.get("configData")
        if isinstance(config_data, Mapping):
            result["config_data"] = cls._snake_case_data(config_data)
            network_os = result["config_data"].get("network_os")
            policy = network_os.get("policy") if isinstance(network_os, Mapping) else None
            if isinstance(policy, dict):
                policy.pop("policy_type", None)
        return {key: value for key, value in result.items() if value is not None}

    @staticmethod
    def _target_key(model) -> Any:
        """Return the family model's switch/IP-aware composite identifier."""
        return model.get_identifier_value()

    @staticmethod
    def _collection_sort_key(model) -> tuple[str, ...]:
        """Return a deterministic string key for full-scope collection presentation."""
        identifier = model.get_identifier_value()
        values = identifier if isinstance(identifier, tuple) else (identifier,)
        return tuple(str(value).casefold() for value in values)

    @classmethod
    def _serialize_family_collection(cls, collection) -> list[dict[str, Any]]:
        """Serialize a full family collection in deterministic identity order."""
        return [item.to_config() for item in sorted(collection, key=cls._collection_sort_key)]

    @classmethod
    def _project_collection(cls, resource, collection) -> list[dict[str, Any]]:
        """Select requested identities from a destination-family collection in playbook order."""
        if resource.state == "overridden":
            return [cls._serialize_model_target(item) for item in sorted(collection, key=cls._collection_sort_key)]
        if not hasattr(collection, "get"):
            return collection.to_ansible_config()
        projected = []
        for desired in resource.proposed:
            current = collection.get(cls._target_key(desired))
            if current is not None:
                projected.append(cls._serialize_model_target(current))
        return projected

    @staticmethod
    def _operation_keys(resource) -> set[Any]:
        """Return requested identities with an actual planned mutation."""
        models = (
            *resource.operations.creates,
            *resource.operations.updates,
            *resource.operations.deletes,
            *(transition.desired for transition in resource.transitions),
        )
        return {model.get_identifier_value() for model in models}

    @staticmethod
    def _model_deployment_target(resource, model) -> Target:
        """Return the exact controller deployment identity for one configured model."""
        switch_id = resource.orchestrator.fabric_context.get_switch_id(getattr(model, "switch_ip"))
        return getattr(model, "interface_name"), switch_id

    @classmethod
    def _operation_deployment_targets(cls, plan: InterfaceWorkflowPlan) -> tuple[Target, ...]:
        """Return exact targets that would be queued by the current mutation plan."""
        targets = []
        for resource in plan.resources:
            orchestrator = getattr(resource, "orchestrator", None)
            if getattr(orchestrator, "fabric_context", None) is None:
                continue
            models = (
                *resource.operations.deletes,
                *(transition.desired for transition in resource.transitions),
                *resource.operations.updates,
                *resource.operations.creates,
            )
            for model in models:
                targets.append(cls._model_deployment_target(resource, model))
        return tuple(dict.fromkeys(targets))

    @classmethod
    def _pending_deployment_targets(cls, plan: InterfaceWorkflowPlan) -> tuple[Target, ...]:
        """Select explicit no-mutation targets on switches the cached inventory reports out of sync or pending."""
        targets = []
        for resource in plan.resources:
            orchestrator = getattr(resource, "orchestrator", None)
            context = getattr(orchestrator, "fabric_context", None)
            if context is None or not hasattr(context, "switch_config_in_sync"):
                continue
            operation_keys = cls._operation_keys(resource)
            for desired in resource.proposed:
                if cls._target_key(desired) in operation_keys:
                    continue
                primary_switch_id = context.get_switch_id(getattr(desired, "switch_ip"))
                switch_scope = [primary_switch_id]
                if resource.adapter.ownership_domain == "vpc":
                    peer_switch_id = getattr(orchestrator, "_peer_serial_cache", {}).get(primary_switch_id)
                    if peer_switch_id is not None:
                        switch_scope.append(peer_switch_id)
                if any(context.switch_config_in_sync(switch_id) is False for switch_id in switch_scope):
                    targets.append((getattr(desired, "interface_name"), primary_switch_id))
        return tuple(dict.fromkeys(targets))

    @staticmethod
    def _deployment_preview(targets: tuple[Target, ...]) -> list[dict[str, str]]:
        """Serialize exact deployment targets for check-mode output."""
        return [
            {
                "interface_name": interface_name,
                "switch_id": switch_id,
                "status": "would_deploy",
            }
            for interface_name, switch_id in targets
        ]

    def _raw_target(self, resource, desired, *, original: bool) -> tuple[str, dict | None]:
        """Resolve one requested model to its primary raw snapshot record."""
        switch_ip = getattr(desired, "switch_ip")
        switch_id = resource.orchestrator.fabric_context.get_switch_id(switch_ip)
        snapshot = self._snapshot
        if snapshot is None:
            return switch_ip, None
        raw = snapshot.cached_interface(
            switch_id,
            getattr(desired, "interface_name"),
            original=original,
        )
        return switch_ip, raw

    def _supports_raw_projection(self, resource) -> bool:
        """Return whether real snapshot and fabric context are available for result projection."""
        return (
            self._snapshot is not None
            and hasattr(self._snapshot, "cached_interface")
            and getattr(resource, "orchestrator", None) is not None
            and getattr(resource.orchestrator, "fabric_context", None) is not None
        )

    def _target_before(self, resource) -> list[dict[str, Any]]:
        """Return observed initial state for only the requested logical identities."""
        if resource.state == "overridden" or not self._supports_raw_projection(resource):
            return self._project_collection(resource, resource.before)
        projected = []
        for desired in resource.proposed:
            switch_ip, raw = self._raw_target(resource, desired, original=True)
            if raw is not None:
                projected.append(self._serialize_raw_target(raw, switch_ip))
        return projected

    @classmethod
    def _default_ethernet_target(cls, desired) -> dict[str, Any]:
        """Return the canonical prospective state after a physical-port reset."""
        raw = InterfaceDefaultConfig().to_payload()
        raw["interfaceName"] = getattr(desired, "interface_name")
        raw["interfaceType"] = "ethernet"
        return cls._serialize_raw_target(raw, getattr(desired, "switch_ip"))

    def _planned_target_after(self, resource) -> list[dict[str, Any]]:
        """Return target-scoped prospective state without changing the shared snapshot."""
        if resource.state == "overridden":
            return self._project_collection(resource, resource.operations.after)
        operation_keys = self._operation_keys(resource)
        projected = []
        for desired in resource.proposed:
            key = self._target_key(desired)
            if key not in operation_keys:
                if self._supports_raw_projection(resource):
                    switch_ip, raw = self._raw_target(resource, desired, original=True)
                    if raw is not None:
                        projected.append(self._serialize_raw_target(raw, switch_ip))
                else:
                    current = resource.operations.after.get(key)
                    if current is not None:
                        projected.append(self._serialize_model_target(current))
                continue
            if resource.state == "deleted":
                if resource.adapter.delete_strategy == InterfaceDeleteStrategy.NORMALIZE:
                    projected.append(self._default_ethernet_target(desired))
                continue
            current = resource.operations.after.get(key)
            if current is not None:
                projected.append(self._serialize_model_target(current))
        return projected

    @staticmethod
    def _vpc_peer_reference_matches(raw: Mapping[str, Any], expected_peer_id: str) -> bool:
        """Return whether one vPC record references its authoritative peer, when populated."""
        config_data = raw.get("configData")
        network_os = config_data.get("networkOS") if isinstance(config_data, Mapping) else None
        policy = network_os.get("policy") if isinstance(network_os, Mapping) else None
        configured_peer_id = policy.get("peerSwitchId") if isinstance(policy, Mapping) else None
        return configured_peer_id is None or configured_peer_id == expected_peer_id

    def _vpc_target_is_pair_consistent(self, resource, desired, primary_raw: dict | None) -> bool:
        """Return whether a reconciled vPC target is absent or coherent on both authoritative peers."""
        if not resource.adapter.safety.requires_pair_consistency:
            return True
        snapshot = self._snapshot
        if snapshot is None:
            return False
        context = resource.orchestrator.fabric_context
        primary_id = context.get_switch_id(getattr(desired, "switch_ip"))
        peer_id = getattr(resource.orchestrator, "_peer_serial_cache", {}).get(primary_id)
        if peer_id is None:
            return False
        peer_raw = snapshot.cached_interface(peer_id, getattr(desired, "interface_name"))
        if primary_raw is None or peer_raw is None:
            return primary_raw is None and peer_raw is None
        scope = tuple(sorted((primary_id, peer_id)))
        if not self._vpc_peer_reference_matches(primary_raw, peer_id):
            return False
        if not self._vpc_peer_reference_matches(peer_raw, primary_id):
            return False
        if self._canonical_interface_type(primary_raw.get("interfaceType")) != self._canonical_interface_type(peer_raw.get("interfaceType")):
            return False
        if InterfaceStateSnapshot.policy_type(primary_raw) != InterfaceStateSnapshot.policy_type(peer_raw):
            return False
        return InterfaceWorkflowPlanner._vpc_record_fingerprint(
            primary_raw,
            primary_id,
            scope,
        ) == InterfaceWorkflowPlanner._vpc_record_fingerprint(peer_raw, peer_id, scope)

    def _observed_target_after(self, resource, fallback) -> tuple[list[dict[str, Any]], bool]:
        """Return target state and vPC pair-verification from the cached reconciled snapshot."""
        if not self._supports_raw_projection(resource):
            return self._project_collection(resource, fallback), True
        projected = []
        pair_verified = True
        for desired in resource.proposed:
            switch_ip, raw = self._raw_target(resource, desired, original=False)
            pair_verified = pair_verified and self._vpc_target_is_pair_consistent(resource, desired, raw)
            if raw is not None:
                projected.append(self._serialize_raw_target(raw, switch_ip))
        return projected, pair_verified

    def _observed_overridden_vpc_after(self, resource, fallback) -> tuple[list[dict[str, Any]], bool]:
        """Return complete pair-keyed vPC family state from the refreshed raw snapshot."""
        if resource.adapter.ownership_domain != "vpc" or not self._supports_raw_projection(resource) or not hasattr(self._snapshot, "interfaces_by_identity"):
            return self._project_collection(resource, fallback), True

        context = resource.orchestrator.fabric_context
        peer_by_switch = getattr(resource.orchestrator, "_peer_serial_cache", {})
        grouped: dict[tuple[tuple[str, ...], str], dict[str, dict[str, Any]]] = {}
        for (switch_id, interface_name), raw in self._snapshot.interfaces_by_identity.items():
            interface_type = self._canonical_interface_type(raw.get("interfaceType"))
            policy_type = InterfaceStateSnapshot.policy_type(raw)
            if interface_type not in resource.adapter.interface_types or policy_type not in resource.adapter.policy_types:
                continue
            peer_id = peer_by_switch.get(switch_id)
            scope = tuple(sorted((switch_id, peer_id))) if peer_id is not None else (switch_id,)
            grouped.setdefault((scope, interface_name), {})[switch_id] = raw

        preferred_by_key = {}
        for desired in resource.proposed:
            primary_id = context.get_switch_id(getattr(desired, "switch_ip"))
            peer_id = peer_by_switch.get(primary_id)
            scope = tuple(sorted((primary_id, peer_id))) if peer_id is not None else (primary_id,)
            preferred_by_key[(scope, getattr(desired, "interface_name").lower())] = primary_id

        projected = []
        pair_verified = True
        for key in sorted(grouped):
            scope, _interface_name = key
            records = grouped[key]
            coherent = len(scope) == 2 and set(records) == set(scope)
            if coherent:
                for switch_id, raw in records.items():
                    expected_peer_id = next(candidate for candidate in scope if candidate != switch_id)
                    if not self._vpc_peer_reference_matches(raw, expected_peer_id):
                        coherent = False
                        break
            if coherent:
                fingerprints = [InterfaceWorkflowPlanner._vpc_record_fingerprint(raw, switch_id, scope) for switch_id, raw in records.items()]
                coherent = all(fingerprint == fingerprints[0] for fingerprint in fingerprints[1:])
            pair_verified = pair_verified and coherent
            selected_id = preferred_by_key.get(key)
            if selected_id not in records:
                selected_id = min(records)
            projected.append(self._serialize_raw_target(records[selected_id], context.get_switch_ip(selected_id)))
        projected.sort(
            key=lambda item: (
                str(item.get("switch_ip", "")).casefold(),
                str(item.get("interface_name", "")).casefold(),
            )
        )
        return projected, pair_verified

    def _resource_result(
        self,
        resource,
        *,
        after,
        execution_items: Mapping[tuple[int, str, str, str], Mapping[str, Any]],
        include_proposed: bool,
        include_family: bool,
        after_verified: bool,
        use_observed_after: bool,
    ) -> dict[str, Any]:
        """Serialize one indexed group without losing repeated resource types."""
        before_config = self._target_before(resource)
        observed_pair_verified = True
        if resource.state == "overridden" and use_observed_after:
            after_config, observed_pair_verified = self._observed_overridden_vpc_after(resource, after)
        elif resource.state == "overridden":
            after_config = self._project_collection(resource, after)
        elif use_observed_after:
            after_config, observed_pair_verified = self._observed_target_after(resource, after)
        else:
            after_config = self._planned_target_after(resource)
        after_verified = after_verified and observed_pair_verified
        result = {
            "resource_index": resource.resource_index,
            "type": resource.resource_type,
            "module": resource.adapter.module_name,
            "state": resource.state,
            "changed": before_config != after_config,
            "planned_changed": resource.changed,
            "before": before_config,
            "after": after_config,
            "after_verified": after_verified,
            "operations": self._resource_operations(
                resource,
                before_config=before_config,
                after_config=after_config,
                execution_items=execution_items,
            ),
        }
        if include_proposed:
            result["proposed"] = resource.proposed.to_ansible_config()
        if include_family:
            family_before = self._serialize_family_collection(resource.before)
            if resource.state == "overridden" and resource.adapter.ownership_domain == "vpc" and use_observed_after:
                family_after = [{key: value for key, value in item.items() if key != "policy_type"} for item in after_config]
            else:
                family_after = self._serialize_family_collection(after)
            result["family_before"] = family_before
            result["family_after"] = family_after
        return result

    def _format_result(
        self,
        plan: InterfaceWorkflowPlan,
        execution: InterfaceWorkflowExecution | None = None,
        deployment_targets: tuple[Target, ...] = (),
    ) -> dict[str, Any]:
        """Return compact indexed resources plus aggregate read and execution metadata."""
        output_level = self.module.params.get("output_level", "normal")

        if execution is not None:
            execution_result = execution.to_dict()
        else:
            deploy = bool((self.module.params.get("config_actions") or {}).get("deploy", False))
            would_deploy = self.module.check_mode and deploy and bool(deployment_targets)
            execution_result = {
                "status": "check_mode" if self.module.check_mode else "no_change",
                "mutations_sent": 0,
                "deployments_sent": 0,
                "affected_switch_ids": [],
                "items": [],
                "deployment": {
                    "requested": deploy,
                    "status": "would_deploy" if would_deploy else "not_needed",
                    "targets": self._deployment_preview(deployment_targets) if would_deploy else [],
                },
                "errors": [],
            }

        raw_execution_items = execution_result.pop("items", [])
        execution_items = {}
        for item in raw_execution_items:
            if not isinstance(item, Mapping):
                continue
            key = self._execution_item_key(item)
            if key is not None:
                execution_items[key] = item

        resource_results = []
        for resource in plan.resources:
            actual = execution.actual_after_by_resource.get(resource.resource_index) if execution is not None else None
            after = actual if actual is not None else resource.operations.after
            after_verified = actual is not None or (execution is None and not self.module.check_mode)
            resource_results.append(
                self._resource_result(
                    resource,
                    after=after,
                    execution_items=execution_items,
                    include_proposed=output_level in {"info", "debug"},
                    include_family=output_level == "debug",
                    after_verified=after_verified,
                    use_observed_after=after_verified,
                )
            )

        request_stats = dict(self._snapshot.request_stats if self._snapshot is not None else plan.request_stats)
        request_stats.pop("mutation_requests", None)
        request_stats.pop("deploy_requests", None)
        request_stats["vpc_pair_gets"] = self._vpc_pair_gets

        if execution is not None:
            observed_projection_changed = any(resource["changed"] and resource["after_verified"] for resource in resource_results)
            changed = execution.changed or observed_projection_changed
        else:
            changed = (plan.changed or bool(deployment_targets)) if self.module.check_mode else False

        return {
            "changed": changed,
            "planned_changed": plan.changed,
            "mutation_count": plan.mutation_count,
            "target_switch_ids": list(plan.target_switch_ids),
            "resources": resource_results,
            "request_stats": request_stats,
            "execution": execution_result,
        }

    def run(self) -> dict[str, Any]:
        """Plan the complete workflow, then execute only after all validation succeeds."""
        plan = self._build_plan()
        deploy = bool((self.module.params.get("config_actions") or {}).get("deploy", False))
        pending_deployment_targets = self._pending_deployment_targets(plan) if deploy else ()
        if self.module.check_mode:
            preview_targets = tuple(dict.fromkeys((*self._operation_deployment_targets(plan), *pending_deployment_targets))) if deploy else ()
            return self._format_result(plan, deployment_targets=preview_targets)
        if not plan.changed and not pending_deployment_targets:
            return self._format_result(plan)
        if self._snapshot is None:
            raise RuntimeError("Interface workflow snapshot was not initialized.")
        execution = self.executor_factory(snapshot=self._snapshot, deploy=deploy).execute(
            plan,
            deployment_targets=pending_deployment_targets,
        )
        result = self._format_result(plan, execution)
        if execution.failed:
            result["failed"] = True
            raise InterfaceWorkflowExecutionFailed(result, execution.message)
        return result
