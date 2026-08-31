# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Public-module coordination for the aggregate interface workflow."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vpc_pairs import (
    EpVpcPairsListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
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
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender

PlannerFactory = Callable[..., InterfaceWorkflowPlanner]
ExecutorFactory = Callable[..., InterfaceWorkflowExecutor]
VPC_PAIR_PAGE_SIZE = 500


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
                    (record.get("switchId") or record.get("peer1SwitchId")),
                    (record.get("peerSwitchId") or record.get("peer2SwitchId")),
                )
                if isinstance(record, dict)
                else (None, None)
                for record in page
            )
            if page and signature in seen_page_signatures:
                raise InterfaceWorkflowValidationError(
                    f"The Nexus Dashboard vPC-pair pagination repeated a page at offset {offset}."
                )
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
                raise InterfaceWorkflowValidationError(
                    f"The Nexus Dashboard vPC-pair response reports more records after empty offset {offset}."
                )
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
                raise InterfaceWorkflowValidationError(
                    f"The authoritative vPC-pair inventory contains a self-pair for switch '{first}'."
                )
            existing_peer = declared_peer_by_switch_id.get(first)
            if existing_peer is not None and existing_peer != second:
                raise InterfaceWorkflowValidationError(
                    f"The authoritative vPC-pair inventory contains conflicting mappings for switch '{first}': "
                    f"'{existing_peer}' and '{second}'."
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
                        f"The authoritative vPC-pair inventory contains conflicting mappings for switch '{switch_id}': "
                        f"'{existing_peer}' and '{peer_id}'."
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

    @staticmethod
    def _config_diff(before, after) -> dict[str, Any]:
        """Return an Ansible-style before/after diff when collections differ."""
        if not before.get_diff_collection(after):
            return {}
        return {
            "before": before.to_ansible_config(),
            "after": after.to_ansible_config(),
        }

    @classmethod
    def _resource_result(cls, resource, *, after, include_proposed: bool, after_verified: bool) -> dict[str, Any]:
        """Serialize one indexed group without losing repeated resource types."""
        changed = bool(resource.before.get_diff_collection(after))
        result = {
            "resource_index": resource.resource_index,
            "type": resource.resource_type,
            "module": resource.adapter.module_name,
            "state": resource.state,
            "transitions": [transition.to_dict() for transition in resource.transitions],
            "changed": changed,
            "planned_changed": resource.changed,
            "before": resource.before.to_ansible_config(),
            "after": after.to_ansible_config(),
            "diff": cls._config_diff(resource.before, after),
            "after_verified": after_verified,
            "created": [item.to_config() for item in resource.operations.creates],
            "updated": [item.to_config() for item in resource.operations.updates],
            "deleted": [item.to_config() for item in resource.operations.deletes],
        }
        if include_proposed:
            result["proposed"] = resource.proposed.to_ansible_config()
        return result

    def _format_result(
        self,
        plan: InterfaceWorkflowPlan,
        execution: InterfaceWorkflowExecution | None = None,
    ) -> dict[str, Any]:
        """Return stable aggregate and indexed per-resource output."""
        output_level = self.module.params.get("output_level", "normal")
        resource_results = []
        for resource in plan.resources:
            actual = execution.actual_after_by_resource.get(resource.resource_index) if execution is not None else None
            after = actual if actual is not None else resource.operations.after
            after_verified = actual is not None or (execution is None and not self.module.check_mode)
            resource_results.append(
                self._resource_result(
                    resource,
                    after=after,
                    include_proposed=output_level in {"info", "debug"},
                    after_verified=after_verified,
                )
            )

        request_stats = dict(self._snapshot.request_stats if self._snapshot is not None else plan.request_stats)
        request_stats.update(
            {
                "vpc_pair_gets": self._vpc_pair_gets,
                "mutation_requests": (execution.mutation_requests if execution is not None else 0),
                "deploy_requests": (execution.deploy_requests if execution is not None else 0),
            }
        )

        def aggregate(field: str) -> list[dict[str, Any]]:
            return [
                {
                    "resource_index": resource["resource_index"],
                    "type": resource["type"],
                    "config": resource[field],
                }
                for resource in resource_results
            ]

        if execution is not None:
            execution_result = execution.to_dict()
            changed = execution.changed
        else:
            deploy = bool((self.module.params.get("config_actions") or {}).get("deploy", False))
            execution_result = {
                "status": "check_mode" if self.module.check_mode else "no_change",
                "mutations_sent": 0,
                "deployments_sent": 0,
                "affected_switch_ids": [],
                "items": [],
                "deployment": {
                    "requested": deploy,
                    "status": "not_needed",
                    "targets": [],
                },
                "errors": [],
            }
            changed = plan.changed if self.module.check_mode else False

        return {
            "changed": changed,
            "planned_changed": plan.changed,
            "check_mode": self.module.check_mode,
            "output_level": output_level,
            "fabric_name": plan.fabric_name,
            "config_actions": dict(self.module.params.get("config_actions") or {}),
            "mutation_count": plan.mutation_count,
            "target_switch_ids": list(plan.target_switch_ids),
            "resources": resource_results,
            "before": aggregate("before"),
            "after": aggregate("after"),
            "diff": aggregate("diff"),
            "request_stats": request_stats,
            "execution": execution_result,
        }

    def run(self) -> dict[str, Any]:
        """Plan the complete workflow, then execute only after all validation succeeds."""
        plan = self._build_plan()
        if self.module.check_mode or not plan.changed:
            return self._format_result(plan)
        if self._snapshot is None:
            raise RuntimeError("Interface workflow snapshot was not initialized.")
        deploy = bool((self.module.params.get("config_actions") or {}).get("deploy", False))
        execution = self.executor_factory(snapshot=self._snapshot, deploy=deploy).execute(plan)
        result = self._format_result(plan, execution)
        if execution.failed:
            result["failed"] = True
            raise InterfaceWorkflowExecutionFailed(result, execution.message)
        return result
