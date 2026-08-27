# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
NetworkWorkflowCoordinator — Parent / child Network workflow orchestration.

The coordinator is constructed inside nd_manage_networks.py and resolves the
target fabric strategy through the Gen-3 REST runtime. For standalone and child
fabrics it runs the state machine directly. For parent fabrics it:
  1. Resolves fabric topology and selects the strategy.
  2. Parses and validates the requested Network config.
  3. Splits child_fabric_config into per-child in-process tasks.
  4. Runs the parent task via the Network state machine.
  5. Runs each child task with the child's resolved strategy.
  6. Deploys deferred parent attachment changes, then aggregates results.
"""

from __future__ import annotations

import copy
import time

from typing import Any

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.config_models import NetworkConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import (
    NetworkAttachmentManager,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_config_utils import (
    configured_network_names,
    deploy_enabled_by_network,
    deploy_type_by_network,
    network_name_filter,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_dependency_checker import (
    NetworkDependencyChecker,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_fabric_resolver import (
    NetworkFabricResolver,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_state_machine import (
    NetworkStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)


class NetworkWorkflowCoordinator:
    """
    Coordinates Network operations across parent and child fabrics.

    Args:
        module:   The AnsibleModule instance (params, fail_json, check_mode).
        strategy: The resolved BaseNetworkStrategy for the target fabric.
    """

    def __init__(
        self,
        module: AnsibleModule,
        strategy: BaseNetworkStrategy | None = None,
        initial_workflow_trace: list[dict[str, Any]] | None = None,
    ):
        self.module = module
        self.strategy = strategy
        self._trace_started_at = time.monotonic()
        self._workflow_trace: list[dict[str, Any]] = []
        if initial_workflow_trace:
            self._workflow_trace.extend(dict(entry) for entry in initial_workflow_trace)

    @property
    def workflow_trace(self) -> list[dict[str, Any]]:
        """Return workflow trace entries collected by the coordinator."""
        return list(self._workflow_trace)

    @property
    def attachments(self) -> NetworkAttachmentManager:
        """Return the Network attachment/deploy manager."""
        if not hasattr(self, "_attachments"):
            self._attachments = NetworkAttachmentManager(self)
        return self._attachments

    @property
    def dependencies(self) -> NetworkDependencyChecker:
        """Return the Network dependency checker."""
        if not hasattr(self, "_dependencies"):
            self._dependencies = NetworkDependencyChecker(self)
        return self._dependencies

    # ── Entry point ────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """
        Execute the workflow appropriate for the resolved fabric type.

        Returns a result dict suitable for module.exit_json(**result).
        """
        module_args: dict = dict(self.module.params)
        if self.strategy is None:
            self.strategy = self._resolve_strategy(module_args)
        self._trace(
            "workflow_start",
            fabric_name=module_args.get("fabric_name"),
            state=module_args.get("state"),
            config_count=len(module_args.get("config") or []),
            strategy=self.strategy.__class__.__name__,
            fabric_type=self.strategy.fabric_type,
            check_mode=self.module.check_mode,
        )
        try:
            fabric_type: str = self.strategy.fabric_type
            self._validate_topology_argument_scope(module_args, fabric_type)

            if self.strategy.is_child:
                result = self._handle_child_workflow(module_args, fabric_type)
            elif self.strategy.is_parent:
                result = self._handle_parent_workflow(module_args, fabric_type)
            else:
                result = self._handle_standalone_workflow(module_args, fabric_type)
        except Exception as exc:
            self._trace("workflow_error", error=repr(exc), exception=type(exc).__name__)
            raise

        self._trace("workflow_end", changed=result.get("changed"), failed=result.get("failed"))
        return self._attach_workflow_trace(result)

    def _new_rest_send(
        self,
        params: dict[str, Any] | None = None,
        check_mode: bool | None = None,
        timeout: int | None = None,
        send_interval: int | None = None,
    ) -> RestSend:
        """Build a Gen-3 REST runtime for resolver or state-machine calls."""
        sender = Sender()
        sender.ansible_module = self.module

        rest_send_params = dict(params if params is not None else self.module.params)
        rest_send_params["check_mode"] = self.module.check_mode if check_mode is None else check_mode
        rest_send = RestSend(rest_send_params)
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()
        if timeout is not None:
            rest_send.timeout = timeout
        if send_interval is not None:
            rest_send.send_interval = send_interval
        return rest_send

    def _resolve_strategy(self, module_args: dict) -> BaseNetworkStrategy:
        """Resolve fabric topology with a short-timeout Gen-3 REST probe.

        Topology detection intentionally uses a non-check-mode, single-attempt
        RestSend variant so expected probe misses do not enter the workflow
        retry loop. State-machine operations build their own RestSend instances
        with the module's check mode and default timeout settings.
        """
        rest_send = self._new_rest_send(params=module_args, check_mode=False, timeout=1, send_interval=1)
        resolver = NetworkFabricResolver(
            rest_send=rest_send,
            fabric_name=module_args["fabric_name"],
        )
        strategy = resolver.resolve()
        resolver_trace = getattr(resolver, "workflow_trace", None)
        if resolver_trace:
            self._workflow_trace.extend(dict(entry) for entry in resolver_trace)
        return strategy

    def _trace_enabled(self) -> bool:
        verbosity = self.module._verbosity if hasattr(self.module, "_verbosity") else 0
        params = getattr(self.module, "params", {}) or {}
        return params.get("output_level") == "debug" or verbosity >= 3

    def _trace(self, event: str, **details: Any) -> None:
        if not self._trace_enabled():
            return
        entry = {
            "sequence": len(self._workflow_trace) + 1,
            "elapsed_ms": int((time.monotonic() - self._trace_started_at) * 1000),
            "event": event,
        }
        entry.update(details)
        self._workflow_trace.append(entry)

    def _attach_workflow_trace(self, result: dict[str, Any]) -> dict[str, Any]:
        if self._trace_enabled():
            result["workflow_trace"] = list(self._workflow_trace)
        return result

    def _validate_topology_argument_scope(
        self,
        module_args: dict,
        fabric_type: str,
    ) -> None:
        """
        Reject topology-scoped task keys before Network workflow execution.

        Ansible's argument spec is static, but parent/child/standalone scope is
        known only after fabric resolution.  This method provides the second
        layer of argument enforcement before any Network payload is sent to ND.
        """
        config = module_args.get("config") or []

        if not self.strategy.is_parent:
            for idx, network in enumerate(config):
                if network.get("child_fabric_config"):
                    self.module.fail_json(
                        msg=(
                            "config[{idx}].child_fabric_config is only valid "
                            "when the target fabric is a multisite or "
                            "multicluster parent. Target fabric "
                            f"'{module_args.get('fabric_name')}' resolved as "
                            f"'{fabric_type}'."
                        ).format(idx=idx)
                    )

        if self.strategy.is_child:
            for idx, network in enumerate(config):
                if network.get("attach"):
                    self.module.fail_json(
                        msg=(
                            "config[{idx}].attach is not valid when targeting "
                            "a child fabric directly. Run attachment and "
                            "deployment operations against the parent fabric."
                        ).format(idx=idx)
                    )

    # ── Config parsing ─────────────────────────────────────────

    def _parse_config(
        self,
        config: list[dict],
        model_cls: type,
        state: str,
    ) -> list[dict]:
        """
        Validate each entry in ``config`` against ``model_cls`` and return
        the normalised list (Python field names, None values excluded).

        ``state`` is passed for context in error messages only; all states
        are validated the same way since the models enforce required fields.

        Validation errors are reported immediately via ``module.fail_json``.
        """
        parsed = []
        for idx, entry in enumerate(config):
            try:
                operational_only = isinstance(entry, dict) and not NDNetworkOrchestrator.has_network_definition_intent(entry)
                model = model_cls.from_config(entry)
                parsed_config = model.to_config(exclude_unset=True)
                if operational_only:
                    sparse_config = {"network_name": parsed_config["network_name"]}
                    for key in ("attach", "deploy", "deploy_type"):
                        if key in parsed_config:
                            sparse_config[key] = parsed_config[key]
                    parsed.append(sparse_config)
                    continue
                parsed.append(parsed_config)
            except ValidationError as exc:
                self.module.fail_json(msg=(f"config[{idx}] validation failed " f"({model_cls.__name__}, state={state!r}): {exc}"))
        return parsed

    # ── Workflow handlers ─────────────────────────────────────────

    def _handle_standalone_workflow(self, module_args: dict, fabric_type: str) -> dict[str, Any]:
        """
        Direct pass-through to the state machine.

        No child fabric considerations. Applies to standalone fabrics and
        to child fabrics that are targeted directly with state=gathered.
        """
        state = module_args.get("state", "merged")
        self._trace("standalone_workflow_start", state=state, fabric_type=fabric_type)
        module_args["config"] = self._parse_config(module_args.get("config") or [], self.strategy.config_model_cls, state)
        self._trace("standalone_config_parsed", parsed_count=len(module_args["config"]))
        result = self._run_state_machine_with_attachments(module_args)
        result.setdefault("fabric_type", fabric_type)
        result.setdefault("workflow", "Standalone Fabric Network Processing")
        self._trace("standalone_workflow_end", changed=result.get("changed"), failed=result.get("failed"))
        return result

    def _handle_child_workflow(self, module_args: dict, fabric_type: str) -> dict[str, Any]:
        """
        Enforce the Multisite / Multicluster operational model for child fabrics.

        Only state='gathered' is permitted when the module targets a child fabric
        directly. All write operations must be driven by the parent fabric.
        """
        state = module_args.get("state")
        fabric_name = module_args.get("fabric_name")
        self._trace("child_workflow_start", state=state, fabric_name=fabric_name, fabric_type=fabric_type)

        if state == "gathered":
            module_args["config"] = self._parse_config(module_args.get("config") or [], NetworkConfigModel, state)
            self._trace("child_config_parsed", parsed_count=len(module_args["config"]))
            result = self._run_state_machine(module_args)
            result.setdefault("fabric_type", fabric_type)
            result.setdefault(
                "workflow",
                f"{fabric_type.replace('_', ' ').title()} Network Gathered",
            )
            self._trace("child_workflow_end", changed=result.get("changed"), failed=result.get("failed"))
            return result

        self.module.fail_json(
            msg=(
                f"Attempted '{state}' operation directly on child fabric "
                f"'{fabric_name}'. "
                "Only state='gathered' is allowed on child fabrics. "
                "Run the operation against the parent fabric instead."
            )
        )

    def _handle_parent_workflow(self, module_args: dict, fabric_type: str) -> dict[str, Any]:
        """
        Full parent orchestration: parent fabric first, then all child fabrics.

        Workflow steps:
          1. Parse and validate configs with the resolved Network model.
          2. Split each Network's child_fabric_config entries into per-fabric tasks.
          3. Build a clean parent config (child_fabric_config stripped).
          4. Run the parent state machine.
          5. If parent succeeded, execute each child task sequentially in-process.
          6. Deploy deferred parent attachment changes.
          7. Aggregate all results into a structured response.
        """
        log_type = "multicluster" if "multicluster" in fabric_type else "multisite"
        parent_fabric = module_args.get("fabric_name")
        state = module_args.get("state", "merged")
        self._trace("parent_workflow_start", state=state, parent_fabric=parent_fabric, fabric_type=fabric_type)
        config: list[dict] = self._parse_config(module_args.get("config") or [], self.strategy.config_model_cls, state)
        self._validate_parent_network_capabilities(config)
        self._trace("parent_config_parsed", parsed_count=len(config))

        # Collect member fabric names for relationship validation
        child_member_names = self.strategy.child_fabric_members()
        child_member_name_set = set(child_member_names)
        child_fabric_data_map: dict[str, dict] = {m.get("fabricName"): m for m in self.strategy.fabric_data.get("members", []) if m.get("fabricName")}
        self._trace("parent_members_resolved", child_members=child_member_names)

        # Step 2 & 3 — split config into parent config + child task groups
        parent_config: list[dict] = []
        child_tasks_dict: dict[str, dict] = {}

        for network in config:
            child_configs = network.get("child_fabric_config") or []

            if state != "deleted":
                for child_cfg in child_configs:
                    child_fabric_name = child_cfg.get("fabric_name")
                    if child_fabric_name not in child_member_name_set:
                        self.module.fail_json(
                            msg=(
                                f"Fabric '{child_fabric_name}' is not a member of " f"parent fabric '{parent_fabric}'. " f"Known members: {child_member_names}"
                            )
                        )
                    if not self._has_child_network_options(child_cfg):
                        self._trace("child_task_skipped_without_child_options", child_fabric=child_fabric_name, state=state)
                        continue
                    child_tasks_dict = self._accumulate_child_task(
                        network,
                        child_cfg,
                        child_tasks_dict,
                        child_fabric_data_map.get(child_fabric_name, {}),
                        state,
                    )

            # Parent config: same Network but without child_fabric_config
            parent_network = dict(network)
            parent_network.pop("child_fabric_config", None)
            parent_config.append(parent_network)
        self._trace("parent_child_tasks_built", parent_config_count=len(parent_config), child_task_count=len(child_tasks_dict))

        # Step 4 — run parent state machine
        parent_module_args = dict(module_args)
        parent_module_args["config"] = parent_config
        self._trace("parent_state_machine_start", config_count=len(parent_config), defer_deploy=True)
        parent_result = self._run_state_machine_with_attachments(
            parent_module_args,
            defer_deploy=True,
        )
        self._trace("parent_state_machine_end", changed=parent_result.get("changed"), failed=parent_result.get("failed"))

        # Step 5 — execute child tasks (only if parent succeeded)
        child_results: list[dict] = []
        if not parent_result.get("failed", False) and child_tasks_dict:
            for child_task in child_tasks_dict.values():
                self._trace("child_task_start", child_fabric=child_task["fabric"], config_count=len(child_task["module_args"].get("config") or []))
                child_result = self._run_child_task(child_task)
                child_result["child_fabric"] = child_task["fabric"]
                child_results.append(child_result)
                self._trace(
                    "child_task_end",
                    child_fabric=child_task["fabric"],
                    changed=child_result.get("changed"),
                    failed=child_result.get("failed"),
                    msg=child_result.get("msg"),
                )
                if child_result.get("failed", False):
                    # Abort on first child failure
                    break

        if not parent_result.get("failed", False) and not any(result.get("failed", False) for result in child_results):
            deploy_payloads = self._collect_deferred_deploy_payloads(parent_result, child_results)
            self._trace("parent_deferred_deploys_start", deploy_payload_count=len(deploy_payloads))
            for deploy_payload in deploy_payloads:
                if deploy_payload:
                    self._trace("parent_deferred_deploy_start", deploy_payload=deploy_payload)
                    deploy_trace = self._deploy_network_attachments(
                        parent_module_args,
                        self.strategy,
                        deploy_payload,
                    )
                    self._merge_api_trace(parent_result, deploy_trace)
                    self._trace("parent_deferred_deploy_end", deploy_payload=deploy_payload)

        # Step 6 — aggregate and structure results
        result = self._build_structured_result(parent_result, child_results, parent_fabric, fabric_type, log_type)
        self._trace("parent_workflow_end", changed=result.get("changed"), failed=result.get("failed"), child_result_count=len(child_results))
        return result

    # ── Config splitting helpers ──────────────────────────────────

    @staticmethod
    def _has_child_network_options(child_cfg: dict[str, Any]) -> bool:
        """Return True when a child_fabric_config entry contains fabric-data options."""
        return any(key != "fabric_name" and value is not None for key, value in child_cfg.items())

    def _validate_parent_network_capabilities(self, config: list[dict]) -> None:
        """Validate parent-fabric Network options that depend on resolved topology."""
        if not (getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False)):
            return

        for idx, network in enumerate(config):
            if NDNetworkOrchestrator.is_pvlan_network_type(network.get("vlan_network_type")):
                self.module.fail_json(
                    msg="config[{idx}].vlan_network_type primary, community, and isolated are not supported on Multicluster parent fabrics.".format(idx=idx)
                )

    def _accumulate_child_task(
        self,
        parent_network: dict,
        child_cfg: dict,
        child_tasks_dict: dict,
        child_fabric_data: dict,
        state: str,
    ) -> dict:
        """
        Merge one child_fabric_config entry into the running child_tasks_dict,
        grouping configs by child fabric name.

        Multiple Networks that target the same child fabric are batched into a
        single task entry so only one module call is needed per child fabric.
        """
        child_cfg = copy.deepcopy(child_cfg)
        child_fabric_name: str = child_cfg.pop("fabric_name")

        # Inherit the Network identifier plus layer context from the parent
        # definition.  The parent owns create/delete and immutable identity
        # fields; layer context only prevents child PUTs from being interpreted
        # as a network-mode change by ND.
        child_cfg["network_name"] = parent_network.get("network_name")
        if child_cfg.get("layer") is None and parent_network.get("layer") is not None:
            child_cfg["layer"] = parent_network.get("layer")

        if child_fabric_name in child_tasks_dict:
            # Append to existing child task (batch multiple Networks together)
            child_tasks_dict[child_fabric_name]["module_args"]["config"].append(child_cfg)
            child_tasks_dict[child_fabric_name]["network_list"].append(child_cfg["network_name"])
        else:
            # First Network for this child: create a new task entry
            child_module_args = self.strategy.build_child_task_args(
                child_fabric_name=child_fabric_name,
                network_configs=[child_cfg],
                state=state,
            )
            child_tasks_dict[child_fabric_name] = {
                "fabric": child_fabric_name,
                "module_args": child_module_args,
                "network_list": [child_cfg["network_name"]],
                "strategy": NetworkFabricResolver.strategy_from_fabric_details(child_fabric_name, child_fabric_data),
            }
        self._trace("child_task_accumulated", child_fabric=child_fabric_name, state=state)

        return child_tasks_dict

    # ── State machine runner ──────────────────────────────────────

    def _run_state_machine(self, module_args: dict, strategy: BaseNetworkStrategy | None = None) -> dict[str, Any]:
        """
        Run NDStateMachine for the given module_args and return the result dict.

        ``strategy`` defaults to ``self.strategy`` (the resolved fabric strategy).
        Pass an explicit strategy when running child fabric tasks so the
        orchestrator uses the child's endpoint configuration instead of the
        parent's.

        Network-specific payload transformation is kept here so the shared state
        machine does not need to know about Network playbook field aliases.
        """
        self._trace(
            "state_machine_basic_start",
            fabric_name=(strategy or self.strategy).fabric_name,
            strategy=(strategy or self.strategy).__class__.__name__,
            state=module_args.get("state"),
            config_count=len(module_args.get("config") or []),
        )
        try:
            result = self._network_state_machine().run_basic(module_args, strategy=strategy)
        except Exception as exc:
            self._trace("state_machine_basic_error", error=repr(exc), exception=type(exc).__name__)
            raise
        self._trace("state_machine_basic_end", changed=result.get("changed"), failed=result.get("failed"))
        return result

    def _network_state_machine(self) -> NetworkStateMachine:
        """Return the Network-specific state machine wrapper for this coordinator."""
        if not hasattr(self, "_network_state_machine_instance"):
            self._network_state_machine_instance = NetworkStateMachine(self)
        return self._network_state_machine_instance

    def _new_state_machine(self, module_args: dict, strategy: BaseNetworkStrategy | None = None) -> tuple[NDStateMachine, Any, Any]:
        """
        Build a Network state machine after applying Network config transformation.

        NDStateMachine initialization performs the current-state query.  Callers
        that need that current state directly, such as Network delete-all, should
        use this helper rather than issuing a second query.
        """
        active_strategy = strategy or self.strategy
        state = module_args.get("state", "merged")
        original_config = self.module.params.get("config")
        original_state = self.module.params.get("state")
        sm = None
        try:
            self.module.params["config"] = module_args.get("config") or []
            self.module.params["state"] = state

            sender = Sender()
            sender.ansible_module = self.module
            rest_send_params = dict(self.module.params)
            rest_send_params["check_mode"] = self.module.check_mode
            rest_send = RestSend(rest_send_params)
            rest_send.sender = sender
            rest_send.response_handler = ResponseHandler()

            orchestrator = NDNetworkOrchestrator(
                rest_send=rest_send,
                strategy=active_strategy,
                trace_hook=self._trace,
            )
            self.module.params["config"] = orchestrator.prepare_config_data(module_args.get("config") or [])
            self.module.params["state"] = state
            self._trace(
                "state_machine_init_start",
                fabric_name=active_strategy.fabric_name,
                strategy=active_strategy.__class__.__name__,
                state=state,
                prepared_config_count=len(self.module.params["config"] or []),
            )
            sm = NDStateMachine(module=self.module, model_orchestrator=orchestrator)
            self._trace(
                "state_machine_init_end",
                fabric_name=active_strategy.fabric_name,
                strategy=active_strategy.__class__.__name__,
                state=state,
                existing_count=len(sm.existing),
                proposed_count=len(sm.proposed),
            )
            return sm, original_config, original_state
        finally:
            if sm is None:
                self._restore_state_machine_params(original_config, original_state)

    def _restore_state_machine_params(self, original_config: Any, original_state: Any) -> None:
        """Restore module params saved by ``_new_state_machine``."""
        self.module.params["config"] = original_config
        self.module.params["state"] = original_state

    def _format_state_machine_output(self, sm: NDStateMachine) -> dict[str, Any]:
        """Format state-machine output using the module verbosity contract."""
        verbosity = self.module._verbosity if hasattr(self.module, "_verbosity") else 0
        if self.module.params.get("output_level") == "debug":
            verbosity = max(verbosity, 3)
        return sm.output.format_with_verbosity(verbosity, sm.results)

    def _run_state_machine_with_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy | None = None,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run Network CRUD plus attachment/deploy side effects for parent scopes.

        The Manage API treats Network definition, attachment, and deployment as
        separate endpoints.  Keep attach/deploy out of the Network payload and
        apply them around the normal state machine.
        """
        self._trace(
            "state_machine_with_attachments_start",
            fabric_name=(strategy or self.strategy).fabric_name,
            strategy=(strategy or self.strategy).__class__.__name__,
            state=module_args.get("state"),
            config_count=len(module_args.get("config") or []),
            defer_deploy=defer_deploy,
        )
        try:
            result = self._network_state_machine().run(module_args, strategy=strategy, defer_deploy=defer_deploy)
        except Exception as exc:
            self._trace("state_machine_with_attachments_error", error=repr(exc), exception=type(exc).__name__)
            raise
        self._trace("state_machine_with_attachments_end", changed=result.get("changed"), failed=result.get("failed"))
        return result

    def _run_overridden_state_machine_with_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run overridden using the state machine's initial current-state query.

        The pre-delete and pre-attach phases need to know which Networks currently
        exist before ``manage_state`` deletes omitted items.  Use
        ``sm.existing`` from NDStateMachine initialization instead of querying
        current Networks separately and then building a second state machine later.
        """
        return self._network_state_machine().run_overridden(module_args, strategy, defer_deploy=defer_deploy)

    def _run_deleted_state_machine_with_detach_deploy(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> dict[str, Any]:
        """
        Detach and deploy current Network attachments before removing the Network.

        ND rejects Network removal while attached or pending attachment changes are
        present.  For ``state=deleted`` the requested ``attach`` block and
        per-Network ``deploy`` boolean are intentionally ignored; only
        ``deploy_type`` controls whether the pre-delete deployment is scoped to
        switches or to the Network.
        """
        return self._network_state_machine().run_deleted(module_args, strategy)

    def _delete_all_existing_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> dict[str, Any]:
        """
        Delete all Networks currently present on the target fabric.

        ``config=[]`` means "delete what exists".  The current Networks come from
        NDStateMachine initialization, which has already queried the fabric;
        do not issue another current-state query or rewrite proposed config.
        """
        return self._network_state_machine().delete_all_existing_networks(module_args, strategy)

    # ── Attachment / deployment helpers ──────────────────────────

    def _new_network_orchestrator(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> tuple[NDNetworkOrchestrator, Results]:
        """Create a REST-capable orchestrator that records API trace data."""
        original_config = self.module.params.get("config")
        original_state = self.module.params.get("state")
        try:
            self.module.params["config"] = module_args.get("config") or []
            self.module.params["state"] = module_args.get("state", "merged")

            sender = Sender()
            sender.ansible_module = self.module
            rest_send_params = dict(self.module.params)
            rest_send_params["check_mode"] = self.module.check_mode
            rest_send = RestSend(rest_send_params)
            rest_send.sender = sender
            rest_send.response_handler = ResponseHandler()

            results = Results()
            orchestrator = NDNetworkOrchestrator(
                rest_send=rest_send,
                strategy=strategy,
                results=results,
                trace_hook=self._trace,
            )
            return orchestrator, results
        finally:
            self.module.params["config"] = original_config
            self.module.params["state"] = original_state

    def _finalize_api_trace(
        self,
        results: Results,
        deploy_targets: dict[str, set[str]] | None = None,
    ) -> dict[str, Any]:
        """Convert collected API calls into a compact mergeable structure."""
        results.build_final_result()
        final = results.final_result or {}
        return {
            "changed": final.get("changed", False),
            "failed": final.get("failed", False),
            "final": final,
            "deploy_targets": deploy_targets or {},
        }

    def _merge_api_trace(
        self,
        result: dict[str, Any],
        trace: dict[str, Any],
        prepend: bool = False,
    ) -> None:
        """Merge attachment/deploy API trace into a state-machine result."""
        if not trace:
            return
        final = trace.get("final") or {}
        if trace.get("changed") or final.get("changed"):
            result["changed"] = True
        if trace.get("failed") or final.get("failed"):
            result["failed"] = True
        for key in ("check_mode_attachment_payloads", "check_mode_deploy_payloads"):
            payloads = trace.get(key)
            if payloads:
                result.setdefault(key, [])
                if prepend:
                    result[key] = payloads + result[key]
                else:
                    result[key].extend(payloads)

        verbosity = self.module._verbosity if hasattr(self.module, "_verbosity") else 0
        if self.module.params.get("output_level") == "debug":
            verbosity = max(verbosity, 3)
        if verbosity < 2:
            return

        field_map = {
            "path": "api_paths",
            "verb": "api_verbs",
        }
        if verbosity >= 3:
            field_map.update(
                {
                    "response": "api_response",
                    "result": "api_result",
                    "diff": "api_diff",
                    "metadata": "api_metadata",
                    "payload": "api_payload",
                }
            )

        verbosity_levels = final.get("verbosity_level", [])
        indices = [i for i, level in enumerate(verbosity_levels) if level <= verbosity]
        for final_key, result_key in field_map.items():
            values = final.get(final_key, [])
            selected = [values[i] for i in indices if i < len(values)]
            if selected:
                result.setdefault(result_key, [])
                if prepend:
                    result[result_key] = selected + result[result_key]
                else:
                    result[result_key].extend(selected)

    def _apply_attachment_phase(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        phase: str,
        desired: dict[tuple[str, str], dict[str, Any]] | None = None,
        current_network_names: list[str] | None = None,
        current: dict[tuple[str, str], dict[str, Any]] | None = None,
        attachment_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Attach or detach Networks according to state and phase."""
        return self.attachments.apply_phase(module_args, strategy, phase, desired, current_network_names, current, attachment_details)

    def _attachment_map_after_detach(
        self,
        current: dict[tuple[str, str], dict[str, Any]],
        payloads: list[dict[str, Any]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """
        Return the cached attachment map after applying detach payloads.

        Replaced/overridden flows run a pre-detach phase followed by a
        post-attach phase.  The post phase does not need another ND query when
        the only intervening attachment operation was the detach payload we
        just sent.
        """
        return self.attachments.attachment_map_after_detach(current, payloads)

    def _apply_deleted_attachment_phase(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
        attachment_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Detach all current attachments for deleted Networks, independent of config.

        This uses the attachment query endpoint directly instead of the desired
        attach map because a delete task should converge what is currently on
        ND, not what the playbook happens to include under ``attach``.
        """
        return self.attachments.apply_deleted_phase(module_args, strategy, network_names, attachment_details)

    def _filter_attachment_details_by_network(
        self,
        attachments: list[dict[str, Any]],
        network_names: list[str] | set[str],
    ) -> list[dict[str, Any]]:
        """Return attachment rows for the requested Network names."""
        return self.attachments.filter_attachment_details_by_network(attachments, network_names)

    def _attachment_has_pending_delete_work(self, attachment: dict[str, Any]) -> bool:
        """Return True for an already-detached row that still needs deploy."""
        return self.attachments.attachment_has_pending_delete_work(attachment)

    def _configured_network_names(self, config: list[dict]) -> list[str]:
        """Return configured Network names in stable order."""
        return configured_network_names(config)

    def _deploy_enabled_by_network(self, config: list[dict]) -> dict[str, bool]:
        """Return per-Network deploy intent; omitted deploy defaults to True."""
        return deploy_enabled_by_network(config)

    def _deploy_type_by_network(self, config: list[dict]) -> dict[str, str]:
        """Return per-Network deploy scope; omitted deploy_type defaults to switch."""
        return deploy_type_by_network(config)

    def _desired_attachment_map(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Build desired attachment payloads keyed by (networkName, switchId)."""
        return self.attachments.desired_attachment_map(module_args, strategy)

    def _resolve_switch_ids(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        config: list[dict],
    ) -> dict[str, str]:
        """Resolve configured switch IPs to ND switchId values."""
        return self.attachments.resolve_switch_ids(module_args, strategy, config)

    def _switch_ip_candidates(self, switch: dict[str, Any]) -> set[str]:
        """Extract known management/IP fields from a switch inventory item."""
        return self.attachments.switch_ip_candidates(switch)

    def _attachment_instance_values(self, attachment: dict[str, Any]) -> dict[str, Any]:
        """Map playbook attachment fields to ND instanceValues."""
        return self.attachments.attachment_instance_values(attachment)

    def _current_attachment_map(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Gathered ND and key attached Network attachments by (networkName, switchId)."""
        return self.attachments.current_attachment_map(module_args, strategy, network_names)

    def _attachment_map_from_details(
        self,
        attachments: list[dict[str, Any]],
        network_names: list[str] | set[str] | None = None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Key attached Network attachment rows by (networkName, switchId)."""
        return self.attachments.attachment_map_from_details(attachments, network_names)

    def _current_attachment_details(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Gathered all attachment details, including pending detach entries."""
        return self.attachments.current_attachment_details(module_args, strategy, network_names)

    def _current_attachment_details_ignore_missing(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Gathered attachment details while treating absent deleted Networks as empty."""
        return self.attachments.current_attachment_details_ignore_missing(module_args, strategy, network_names)

    @staticmethod
    def _is_network_not_found_error(error: Exception) -> bool:
        """Return True for ND's attachment-query error when a Network is absent."""
        return NetworkAttachmentManager.is_network_not_found_error(error)

    def _ensure_networks_have_no_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
    ) -> None:
        """Fail before Network deletion when networks still reference the Networks."""
        self.dependencies.ensure_no_networks(module_args, strategy, network_names)

    def _current_networks_for_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
    ) -> list[dict[str, Any]]:
        """Gather networks referencing the requested Networks."""
        return self.dependencies.current_networks_for_networks(module_args, strategy, network_names)

    def _query_networks_for_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
        use_filter: bool,
    ) -> list[dict[str, Any]]:
        """Query the networks endpoint, optionally scoped by Network filter."""
        return self.dependencies.query_networks_for_networks(module_args, strategy, network_names, use_filter)

    def _network_name_filter(self, network_names: list[str]) -> str:
        """Build a URL-safe Lucene filter for Network names."""
        return network_name_filter(network_names)

    def _planned_detach_payloads(
        self,
        state: str,
        config: list[dict],
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compute detach payloads for deleted/replaced/overridden states."""
        return self.attachments.planned_detach_payloads(state, config, current, desired)

    def _planned_attach_payloads(
        self,
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compute attach payloads for missing or changed desired attachments."""
        return self.attachments.planned_attach_payloads(current, desired)

    def _expand_desired_attachments_with_vpc_peers(
        self,
        desired: dict[tuple[str, str], dict[str, Any]],
        attachment_details: Any,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Add vPC peer attachments using existing attachment-query rows."""
        return self.attachments.expand_desired_attachments_with_vpc_peers(desired, attachment_details)

    def _attachment_matches(
        self,
        existing: dict[str, Any],
        desired: dict[str, Any],
    ) -> bool:
        """Return True when existing attachment satisfies desired fields."""
        return self.attachments.attachment_matches(existing, desired)

    def _post_network_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        payloads: list[dict[str, Any]],
        deploy_targets: dict[str, set[str]],
        operation_type: OperationType,
    ) -> dict[str, Any]:
        """Send attach/detach payload and return mergeable API trace."""
        if self.module.check_mode:
            return {
                "changed": True,
                "failed": False,
                "deploy_targets": deploy_targets,
                "payloads": payloads,
                "check_mode_attachment_payloads": payloads,
            }
        return self.attachments.post_network_attachments(module_args, strategy, payloads, deploy_targets, operation_type)

    def _record_deploy_target(
        self,
        deploy_targets: dict[str, set[str]],
        network_name: str | None,
        switch_id: str | None,
    ) -> None:
        """Record one Network/switch pair for a later Network deployment request."""
        self.attachments.record_deploy_target(deploy_targets, network_name, switch_id)

    def _build_deploy_payloads(
        self,
        config: list[dict],
        *target_maps: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        """Build deploy requests from one or more Network/switch maps."""
        return self.attachments.build_deploy_payloads(config, *target_maps)

    def _build_delete_deploy_payloads(
        self,
        config: list[dict],
        *target_maps: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        """Build delete cleanup deploy requests from Network/switch maps."""
        return self.attachments.build_delete_deploy_payloads(config, *target_maps)

    def _build_pending_network_deploy_payloads(
        self,
        result: dict[str, Any],
        config: list[dict],
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> list[dict[str, Any]]:
        """Build a deploy request for configured Networks already pending in ND."""
        return self.attachments.build_pending_network_deploy_payloads(result, config, module_args, strategy)

    def _query_current_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> list[dict[str, Any]]:
        """Gathered current Network records for the target fabric."""
        networks, _trace = self._query_current_networks_with_trace(module_args, strategy)
        return networks

    def _query_current_networks_with_trace(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Gather current Network records and return the associated API trace."""
        orchestrator, results = self._new_network_orchestrator(module_args, strategy)
        data = orchestrator.query_all()
        if isinstance(data, list):
            networks = data
        elif isinstance(data, dict):
            networks = data.get("networks") or data.get("items") or []
        else:
            networks = []
        return networks, self._finalize_api_trace(results)

    def _wait_for_networks_delete_ready(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
    ) -> None:
        """Wait until configured Networks are absent or in notApplicable state."""
        if self.module.check_mode:
            return
        self.attachments.wait_for_networks_delete_ready(module_args, strategy, network_names)

    def _wait_for_network_attachments_delete_ready(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
    ) -> None:
        """Wait until configured Network attachments no longer block deletion."""
        if self.module.check_mode:
            return
        self.attachments.wait_for_attachments_delete_ready(module_args, strategy, network_names)

    def _deploy_network_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        deploy_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deploy pending Network attachment changes once."""
        if self.module.check_mode:
            return {
                "changed": True,
                "failed": False,
                "check_mode_deploy_payloads": [deploy_payload],
            }
        return self.attachments.deploy_network_attachments(module_args, strategy, deploy_payload)

    # ── Child task runner ─────────────────────────────────────────

    def _run_child_task(self, child_task: dict) -> dict[str, Any]:
        """
        Execute a child fabric Network task via its own orchestrator instance.

        Builds the child strategy from the ``fabric_details`` injected by the
        parent strategy's ``build_child_task_args()``, then runs
        ``_run_state_machine`` with that strategy.  No module re-invocation
        or subprocess is needed — the same state machine path used for
        standalone and parent fabrics is reused here.
        """
        module_args = child_task["module_args"]
        child_strategy = child_task["strategy"]
        trace_start = len(self._workflow_trace)
        try:
            result = self._run_state_machine(module_args, strategy=child_strategy)
        except Exception as exc:
            self._trace(
                "child_task_error",
                child_fabric=child_task.get("fabric"),
                error=repr(exc),
                exception=type(exc).__name__,
            )
            child_trace = self._workflow_trace[trace_start:]
            return {
                "changed": False,
                "failed": True,
                "msg": str(exc),
                "exception": type(exc).__name__,
                "fabric_type": getattr(child_strategy, "fabric_type", "unknown_child"),
                "proposed": copy.deepcopy(module_args.get("config") or []),
                "workflow_trace": list(child_trace),
            }
        result.setdefault("fabric_type", child_strategy.fabric_type)
        child_trace = self._workflow_trace[trace_start:]
        if child_trace:
            result.setdefault("workflow_trace", list(child_trace))
        return result

    @staticmethod
    def _collect_deferred_deploy_payloads(parent_result: dict[str, Any], child_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Pop and de-duplicate deferred deploy payloads from parent and child results."""
        payloads: list[dict[str, Any]] = []
        for result in [parent_result, *child_results]:
            payloads.extend(result.pop("_deferred_deploy_payloads", []) or [])
            payload = result.pop("_deferred_deploy_payload", None)
            if payload:
                payloads.append(payload)

        unique_payloads: list[dict[str, Any]] = []
        seen: set[str] = set()
        for payload in payloads:
            key = repr(payload)
            if key in seen:
                continue
            seen.add(key)
            unique_payloads.append(payload)
        return unique_payloads

    # ── Result aggregation ────────────────────────────────────────

    def _scoped_fabric_result(
        self,
        result: dict[str, Any],
        fabric: str,
        fabric_type: str,
    ) -> dict[str, Any]:
        """
        Return a parent/child scoped result without dropping state-machine data.

        NDStateMachine already formats standalone results with before/after,
        diff, and API trace fields.  Parent workflows should expose that same
        shape under parent_fabric and each child_fabrics entry.
        """
        scoped = copy.deepcopy(result)
        scoped.pop("child_fabric", None)
        scoped["fabric_name"] = fabric
        scoped["fabric_type"] = fabric_type
        scoped.setdefault("invocation", result.get("invocation"))
        return scoped

    def _build_structured_result(
        self,
        parent_result: dict,
        child_results: list[dict],
        parent_fabric: str,
        fabric_type: str,
        log_type: str,
    ) -> dict[str, Any]:
        """
        Combine parent and child results into a single structured response dict.

        Parent-only (no children processed):
            Augments parent_result with fabric_type and workflow metadata.

        Parent-with-children:
            Returns a comprehensive dict with separate parent_fabric and
            child_fabrics sections, plus aggregated changed / failed status.
        """
        if not child_results:
            parent_result.setdefault("fabric_type", fabric_type)
            parent_result.setdefault(
                "workflow",
                f"{log_type.capitalize()} Parent without Child Fabric Processing",
            )
            return parent_result

        structured: dict[str, Any] = {
            "changed": parent_result.get("changed", False),
            "failed": parent_result.get("failed", False),
            "fabric_type": fabric_type,
            "workflow": f"{log_type.capitalize()} Parent with Child Fabric Processing",
            "parent_fabric": self._scoped_fabric_result(
                parent_result,
                parent_fabric,
                fabric_type,
            ),
            "child_fabrics": [],
        }

        for child_result in child_results:
            child_entry = self._scoped_fabric_result(
                child_result,
                child_result.get("child_fabric"),
                child_result.get("fabric_type", "standalone"),
            )
            structured["child_fabrics"].append(child_entry)

            if child_result.get("changed", False):
                structured["changed"] = True

            if child_result.get("failed", False):
                structured["failed"] = True
                structured["msg"] = f"Child fabric task failed for " f"'{child_result.get('child_fabric')}': " f"{child_result.get('msg', 'Unknown error')}"

        return structured
