# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
VrfWorkflowCoordinator — Parent / child VRF workflow orchestration.

Replaces the following workflow handlers from the dcnm_vrf action plugin:
  - handle_parent_workflow
  - handle_child_workflow
  - handle_standalone_workflow
  - create_child_task / execute_child_task
  - create_structured_results

The coordinator is constructed inside nd_vrf.py after the strategy is
resolved. For standalone and child fabrics it runs the state machine
directly. For parent fabrics it:
  1. Pre-validates the config (vlan_id placement, vrf_lite structure).
  2. Strips child_fabric_config from each VRF → clean parent config.
  3. Runs the parent task via NDStateMachine (once wired).
  4. Builds child module_args per child fabric and re-invokes nd_vrf.
  5. Aggregates and structures the combined results.
"""

import copy
import time

from typing import Any

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfactions import (
    EpManageFabricsVrfActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfattachments import (
    EpManageFabricsVrfAttachmentsPost,
    EpManageFabricsVrfAttachmentsQueryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import (
    EpManageSwitchesListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_actions_models import (
    VrfDeployRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_attachment_models import (
    VrfAttachDetachRequestModel,
    VrfAttachmentModel,
    VrfAttachmentQueryRequestModel,
    VrfAttachmentInstanceValuesModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import (
    VrfFabricResolver,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)


class VrfWorkflowCoordinator:
    """
    Coordinates VRF operations across parent and child fabrics.

    Args:
        module:   The AnsibleModule instance (params, fail_json, check_mode).
        strategy: The resolved BaseVrfStrategy for the target fabric.
    """

    def __init__(
        self,
        module: AnsibleModule,
        strategy: BaseVrfStrategy,
    ):
        self.module = module
        self.strategy = strategy

    # ── Entry point ───────────────────────────────────────────────

    def run(self) -> dict[str, Any]:
        """
        Execute the workflow appropriate for the resolved fabric type.

        Returns a result dict suitable for module.exit_json(**result).
        """
        module_args: dict = dict(self.module.params)
        fabric_type: str = self.strategy.fabric_type
        self._validate_topology_argument_scope(module_args, fabric_type)

        if self.strategy.is_child:
            return self._handle_child_workflow(module_args, fabric_type)
        elif self.strategy.is_parent:
            return self._handle_parent_workflow(module_args, fabric_type)
        else:
            return self._handle_standalone_workflow(module_args, fabric_type)

    def _validate_topology_argument_scope(
        self,
        module_args: dict,
        fabric_type: str,
    ) -> None:
        """
        Reject topology-scoped task keys before VRF workflow execution.

        Ansible's argument spec is static, but parent/child/standalone scope is
        known only after fabric resolution.  This method provides the second
        layer of argument enforcement before any VRF payload is sent to ND.
        """
        config = module_args.get("config") or []

        if not self.strategy.is_parent:
            for idx, vrf in enumerate(config):
                if "child_fabric_config" in vrf:
                    self.module.fail_json(
                        msg=(
                            "config[{idx}].child_fabric_config is only valid "
                            "when the target fabric is a multisite or "
                            "multicluster parent. Target fabric "
                            f"'{module_args.get('fabric')}' resolved as "
                            f"'{fabric_type}'."
                        ).format(idx=idx)
                    )

        if self.strategy.is_child:
            for idx, vrf in enumerate(config):
                if "attach" in vrf:
                    self.module.fail_json(
                        msg=(
                            "config[{idx}].attach is not valid when targeting "
                            "a child fabric directly. Run attachment and "
                            "deployment operations against the parent fabric."
                        ).format(idx=idx)
                    )

    # ── Config parsing ────────────────────────────────────────────

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
                model = model_cls.from_config(entry)
                parsed.append(model.to_config())
            except ValidationError as exc:
                self.module.fail_json(
                    msg=(
                        f"config[{idx}] validation failed "
                        f"({model_cls.__name__}, state={state!r}): {exc}"
                    )
                )
        return parsed

    # ── Workflow handlers ─────────────────────────────────────────

    def _handle_standalone_workflow(
        self, module_args: dict, fabric_type: str
    ) -> dict[str, Any]:
        """
        Direct pass-through to the state machine.

        No child fabric considerations. Applies to standalone fabrics and
        to child fabrics that are targeted directly with state=gathered.
        """
        state = module_args.get("state", "merged")
        module_args["config"] = self._parse_config(
            module_args.get("config") or [], self.strategy.config_model_cls, state
        )
        result = self._run_state_machine_with_attachments(module_args)
        result.setdefault("fabric_type", fabric_type)
        result.setdefault("workflow", "Standalone Fabric VRF Processing")
        return result

    def _handle_child_workflow(
        self, module_args: dict, fabric_type: str
    ) -> dict[str, Any]:
        """
        Enforce the Multisite / Multicluster operational model for child fabrics.

        Only state='gathered' is permitted when the module targets a child fabric
        directly. All write operations must be driven by the parent fabric.
        """
        state = module_args.get("state")
        fabric_name = module_args.get("fabric")

        if state == "gathered":
            module_args["config"] = self._parse_config(
                module_args.get("config") or [], self.strategy.config_model_cls, state
            )
            result = self._run_state_machine(module_args)
            result.setdefault("fabric_type", fabric_type)
            result.setdefault(
                "workflow",
                f"{fabric_type.replace('_', ' ').title()} VRF Gathered",
            )
            return result

        self.module.fail_json(
            msg=(
                f"Attempted '{state}' operation directly on child fabric "
                f"'{fabric_name}'. "
                "Only state='gathered' is allowed on child fabrics. "
                "Run the operation against the parent fabric instead."
            )
        )

    def _handle_parent_workflow(
        self, module_args: dict, fabric_type: str
    ) -> dict[str, Any]:
        """
        Full parent orchestration: parent fabric first, then all child fabrics.

        Workflow steps:
          1. Pre-validate configs (vlan_id placement, vrf_lite structure).
          2. Split each VRF's child_fabric_config entries into per-fabric tasks.
          3. Build a clean parent config (child_fabric_config stripped).
          4. Run the parent state machine.
          5. If parent succeeded, execute each child task sequentially.
          6. Aggregate all results into a structured response.
        """
        log_type = "multicluster" if "multicluster" in fabric_type else "multisite"
        parent_fabric = module_args.get("fabric")
        state = module_args.get("state", "merged")
        config: list[dict] = self._parse_config(
            module_args.get("config") or [], self.strategy.config_model_cls, state
        )

        # Collect member fabric names for relationship validation
        child_member_names = self.strategy.child_fabric_members()
        child_member_name_set = set(child_member_names)
        child_fabric_data_map: dict[str, dict] = {
            m.get("fabricName"): m
            for m in self.strategy.fabric_data.get("members", [])
            if m.get("fabricName")
        }

        # Step 2 & 3 — split config into parent config + child task groups
        parent_config: list[dict] = []
        child_tasks_dict: dict[str, dict] = {}

        for vrf in config:
            child_configs = vrf.get("child_fabric_config") or []

            if state != "deleted":
                for child_cfg in child_configs:
                    child_fabric_name = child_cfg.get("fabric")
                    if child_fabric_name not in child_member_name_set:
                        self.module.fail_json(
                            msg=(
                                f"Fabric '{child_fabric_name}' is not a member of "
                                f"parent fabric '{parent_fabric}'. "
                                f"Known members: {child_member_names}"
                            )
                        )
                    child_tasks_dict = self._accumulate_child_task(
                        vrf,
                        child_cfg,
                        child_tasks_dict,
                        child_fabric_data_map.get(child_fabric_name, {}),
                        state,
                    )

            # Parent config: same VRF but without child_fabric_config
            parent_vrf = copy.deepcopy(vrf)
            parent_vrf.pop("child_fabric_config", None)
            parent_config.append(parent_vrf)

        # Step 4 — run parent state machine
        parent_module_args = copy.deepcopy(module_args)
        parent_module_args["config"] = parent_config
        parent_result = self._run_state_machine_with_attachments(
            parent_module_args,
            defer_deploy=True,
        )

        # Step 5 — execute child tasks (only if parent succeeded)
        child_results: list[dict] = []
        if not parent_result.get("failed", False) and child_tasks_dict:
            for child_task in child_tasks_dict.values():
                child_result = self._run_child_task(child_task)
                child_result["child_fabric"] = child_task["fabric"]
                child_results.append(child_result)
                if child_result.get("failed", False):
                    # Abort on first child failure
                    break

        if not parent_result.get("failed", False) and not any(
            result.get("failed", False) for result in child_results
        ):
            deploy_payloads = parent_result.pop("_deferred_deploy_payloads", [])
            deploy_payload = parent_result.pop("_deferred_deploy_payload", None)
            if deploy_payload:
                deploy_payloads.append(deploy_payload)
            for deploy_payload in deploy_payloads:
                if deploy_payload:
                    deploy_trace = self._deploy_vrf_attachments(
                        parent_module_args,
                        self.strategy,
                        deploy_payload,
                    )
                    self._merge_api_trace(parent_result, deploy_trace)

        # Step 6 — aggregate and structure results
        return self._build_structured_result(
            parent_result, child_results, parent_fabric, fabric_type, log_type
        )

    # ── Config splitting helpers ──────────────────────────────────

    def _accumulate_child_task(
        self,
        parent_vrf: dict,
        child_cfg: dict,
        child_tasks_dict: dict,
        child_fabric_data: dict,
        state: str,
    ) -> dict:
        """
        Merge one child_fabric_config entry into the running child_tasks_dict,
        grouping configs by child fabric name.

        Multiple VRFs that target the same child fabric are batched into a
        single task entry so only one module call is needed per child fabric.
        """
        child_cfg = copy.deepcopy(child_cfg)
        child_fabric_name: str = child_cfg.pop("fabric")

        # Inherit the VRF name from the parent VRF definition
        child_cfg["vrf_name"] = parent_vrf.get("vrf_name")

        if child_fabric_name in child_tasks_dict:
            # Append to existing child task (batch multiple VRFs together)
            child_tasks_dict[child_fabric_name]["module_args"]["config"].append(child_cfg)
            child_tasks_dict[child_fabric_name]["vrf_list"].append(child_cfg["vrf_name"])
        else:
            # First VRF for this child: create a new task entry
            child_module_args = self.strategy.build_child_task_args(
                child_fabric_name=child_fabric_name,
                vrf_configs=[child_cfg],
                state=state,
            )
            child_tasks_dict[child_fabric_name] = {
                "fabric": child_fabric_name,
                "module_args": child_module_args,
                "vrf_list": [child_cfg["vrf_name"]],
                "strategy": VrfFabricResolver.strategy_from_fabric_details(
                    child_fabric_name, child_fabric_data
                ),
            }

        return child_tasks_dict

    # ── State machine runner ──────────────────────────────────────

    def _run_state_machine(
        self, module_args: dict, strategy: BaseVrfStrategy | None = None
    ) -> dict[str, Any]:
        """
        Run NDStateMachine for the given module_args and return the result dict.

        ``strategy`` defaults to ``self.strategy`` (the resolved fabric strategy).
        Pass an explicit strategy when running child fabric tasks so the
        orchestrator uses the child's endpoint configuration instead of the
        parent's.

        VRF-specific payload transformation is kept here so the shared state
        machine does not need to know about VRF playbook field aliases.
        """
        active_strategy = strategy or self.strategy
        state = module_args.get("state", "merged")

        original_config = self.module.params.get("config")
        original_state = self.module.params.get("state")
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

            orchestrator = NDVrfOrchestrator(
                rest_send=rest_send,
                strategy=active_strategy,
            )
            self.module.params["config"] = orchestrator.prepare_config_data(
                module_args.get("config") or []
            )
            self.module.params["state"] = state
            sm = NDStateMachine(module=self.module, model_orchestrator=orchestrator)

            if state != "gathered":
                sm.manage_state()

            verbosity = self.module._verbosity if hasattr(self.module, "_verbosity") else 0
            if self.module.params.get("output_level") == "debug":
                verbosity = max(verbosity, 3)
            return sm.output.format_with_verbosity(verbosity, sm.results)
        finally:
            self.module.params["config"] = original_config
            self.module.params["state"] = original_state

    def _run_state_machine_with_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy | None = None,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run VRF CRUD plus attachment/deploy side effects for parent scopes.

        The Manage API treats VRF definition, attachment, and deployment as
        separate endpoints.  Keep attach/deploy out of the VRF payload and
        apply them around the normal state machine.
        """
        active_strategy = strategy or self.strategy
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []

        if active_strategy.is_child or state == "gathered":
            return self._run_state_machine(module_args, strategy=active_strategy)

        if state == "deleted":
            return self._run_deleted_state_machine_with_detach_deploy(
                module_args,
                active_strategy,
            )

        pre_delete_traces: list[dict[str, Any]] = []
        if state == "overridden":
            pre_delete_traces = self._prepare_overridden_deletions(
                module_args,
                active_strategy,
            )

        desired_attachments = None
        desired_vrf_names = None
        if state in ("replaced", "overridden"):
            desired_attachments = self._desired_attachment_map(
                module_args,
                active_strategy,
            )
        if state == "overridden":
            desired_vrf_names = self._configured_vrf_names(config)

        pre_attach = self._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="pre",
            desired=desired_attachments,
            current_vrf_names=desired_vrf_names,
        )
        current_attachments = pre_attach.get("current")
        if current_attachments is not None:
            current_attachments = self._attachment_map_after_detach(
                current_attachments,
                pre_attach.get("payloads", []),
            )
        result = self._run_state_machine(module_args, strategy=active_strategy)

        pre_traces = list(pre_delete_traces)
        if pre_attach:
            pre_traces.append(pre_attach)
        for trace in reversed(pre_traces):
            self._merge_api_trace(result, trace, prepend=True)

        if result.get("failed", False):
            return result

        post_attach = self._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="post",
            desired=desired_attachments,
            current_vrf_names=desired_vrf_names,
            current=current_attachments,
        )
        self._merge_api_trace(result, post_attach)

        deploy_payloads = self._build_deploy_payloads(
            config,
            pre_attach.get("deploy_targets", {}),
            post_attach.get("deploy_targets", {}),
        )
        if not deploy_payloads:
            deploy_payloads = self._build_pending_vrf_deploy_payloads(
                result,
                config,
                module_args,
                active_strategy,
            )
        if not deploy_payloads:
            return result

        if defer_deploy:
            result["_deferred_deploy_payloads"] = deploy_payloads
            return result

        for deploy_payload in deploy_payloads:
            deploy_trace = self._deploy_vrf_attachments(
                module_args,
                active_strategy,
                deploy_payload,
            )
            self._merge_api_trace(result, deploy_trace)
        return result

    def _run_deleted_state_machine_with_detach_deploy(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[str, Any]:
        """
        Detach and deploy current VRF attachments before removing the VRF.

        ND rejects VRF removal while attached or pending attachment changes are
        present.  For ``state=deleted`` the requested ``attach`` block and
        per-VRF ``deploy`` boolean are intentionally ignored; only
        ``deploy_type`` controls whether the pre-delete deployment is scoped to
        switches or to the VRF.
        """
        traces: list[dict[str, Any]] = []
        config = module_args.get("config") or []

        detach_trace = self._apply_deleted_attachment_phase(module_args, strategy)
        if detach_trace:
            traces.append(detach_trace)

        deploy_payloads = self._build_deploy_payloads(
            config,
            detach_trace.get("deploy_targets", {}) if detach_trace else {},
        )
        for deploy_payload in deploy_payloads:
            deploy_trace = self._deploy_vrf_attachments(
                module_args,
                strategy,
                deploy_payload,
            )
            traces.append(deploy_trace)

        if deploy_payloads:
            self._wait_for_vrfs_delete_ready(module_args, strategy)

        result = self._run_state_machine(module_args, strategy=strategy)

        for trace in reversed(traces):
            self._merge_api_trace(result, trace, prepend=True)
        return result

    def _prepare_overridden_deletions(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[dict[str, Any]]:
        """
        Detach/deploy omitted VRFs before overridden deletes them.

        ``overridden`` removes VRFs that exist on ND but are not present in the
        playbook.  Those omitted VRFs may still be attached, so they need the
        same pre-delete detach/deploy/wait sequence used by ``state=deleted``.
        """
        omitted_vrf_names = self._overridden_vrf_names_to_delete(module_args, strategy)
        if not omitted_vrf_names:
            return []

        traces: list[dict[str, Any]] = []
        detach_trace = self._apply_deleted_attachment_phase(
            module_args,
            strategy,
            omitted_vrf_names,
        )
        if detach_trace:
            traces.append(detach_trace)

        deploy_payloads = self._build_deploy_payloads(
            module_args.get("config") or [],
            detach_trace.get("deploy_targets", {}) if detach_trace else {},
        )
        for deploy_payload in deploy_payloads:
            deploy_trace = self._deploy_vrf_attachments(
                module_args,
                strategy,
                deploy_payload,
            )
            traces.append(deploy_trace)

        if deploy_payloads:
            self._wait_for_vrfs_delete_ready(
                module_args,
                strategy,
                omitted_vrf_names,
            )
        return traces

    # ── Attachment / deployment helpers ──────────────────────────

    def _new_vrf_orchestrator(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> tuple[NDVrfOrchestrator, Results]:
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
            orchestrator = NDVrfOrchestrator(
                rest_send=rest_send,
                strategy=strategy,
                results=results,
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
        indices = [
            i
            for i, level in enumerate(verbosity_levels)
            if level <= verbosity
        ]
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
        strategy: BaseVrfStrategy,
        phase: str,
        desired: dict[tuple[str, str], dict[str, Any]] | None = None,
        current_vrf_names: list[str] | None = None,
        current: dict[tuple[str, str], dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Attach or detach VRFs according to state and phase."""
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []

        if phase == "pre" and state not in ("deleted", "replaced", "overridden"):
            return {}
        if phase == "post" and state not in ("merged", "replaced", "overridden"):
            return {}

        if current_vrf_names == []:
            return {}

        desired = desired if desired is not None else self._desired_attachment_map(
            module_args,
            strategy,
        )
        vrf_names = self._configured_vrf_names(config)
        deploy_enabled = self._deploy_enabled_by_vrf(config)

        query_all = state == "overridden"
        query_vrf_names = current_vrf_names
        if query_vrf_names is None:
            query_vrf_names = None if query_all else vrf_names
        if current is None:
            current = self._current_attachment_map(
                module_args,
                strategy,
                query_vrf_names,
            )

        payloads: list[dict[str, Any]] = []
        deploy_targets: dict[str, set[str]] = {}

        if phase == "pre":
            payloads = self._planned_detach_payloads(state, config, current, desired)
        else:
            payloads = self._planned_attach_payloads(current, desired)

        if not payloads:
            return {"current": current} if phase == "pre" else {}

        for payload in payloads:
            vrf_name = payload.get("vrfName")
            if deploy_enabled.get(vrf_name, True):
                self._record_deploy_target(
                    deploy_targets,
                    vrf_name,
                    payload.get("switchId"),
                )

        trace = self._post_vrf_attachments(
            module_args,
            strategy,
            payloads,
            deploy_targets,
            OperationType.DELETE if phase == "pre" else OperationType.CREATE,
        )
        trace["current"] = current
        trace["payloads"] = payloads
        return trace

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
        if not payloads:
            return current

        remaining = dict(current)
        for payload in payloads:
            if payload.get("attach") is False:
                key = (payload.get("vrfName"), payload.get("switchId"))
                remaining.pop(key, None)
        return remaining

    def _apply_deleted_attachment_phase(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Detach all current attachments for deleted VRFs, independent of config.

        This uses the attachment query endpoint directly instead of the desired
        attach map because a delete task should converge what is currently on
        ND, not what the playbook happens to include under ``attach``.
        """
        vrf_names = (
            vrf_names
            if vrf_names is not None
            else self._configured_vrf_names(module_args.get("config") or [])
        )
        attachments = self._current_attachment_details_ignore_missing(
            module_args,
            strategy,
            vrf_names or None,
        )

        payloads: list[dict[str, Any]] = []
        deploy_targets: dict[str, set[str]] = {}
        seen_payloads: set[tuple[str, str]] = set()

        for attachment in attachments:
            vrf_name = attachment.get("vrfName")
            switch_id = attachment.get("switchId")
            if not vrf_name or not switch_id:
                continue

            key = (vrf_name, switch_id)
            if attachment.get("attach") is True:
                self._record_deploy_target(deploy_targets, vrf_name, switch_id)
            elif self._attachment_has_pending_delete_work(attachment):
                self._record_deploy_target(deploy_targets, vrf_name, switch_id)

            if attachment.get("attach") is True and key not in seen_payloads:
                payloads.append(
                    {
                        "vrfName": vrf_name,
                        "switchId": switch_id,
                        "attach": False,
                    }
                )
                seen_payloads.add(key)

        if not payloads:
            return {"deploy_targets": deploy_targets}

        return self._post_vrf_attachments(
            module_args,
            strategy,
            payloads,
            deploy_targets,
            OperationType.DELETE,
        )

    def _attachment_has_pending_delete_work(self, attachment: dict[str, Any]) -> bool:
        """Return True for an already-detached row that still needs deploy."""
        pending_statuses = {
            "deploymentInProgress",
            "failed",
            "inProgress",
            "outOfSync",
            "pending",
            "previewInProgress",
        }
        for key in (
            "status",
            "configStatus",
            "deploymentStatus",
            "vrfStatus",
            "attachmentStatus",
        ):
            status = attachment.get(key)
            if status is not None and str(status).strip() in pending_statuses:
                return True
        return False

    def _overridden_vrf_names_to_delete(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[str]:
        """Return current VRFs that are omitted from an overridden config."""
        desired_names = set(self._configured_vrf_names(module_args.get("config") or []))
        omitted_names: list[str] = []
        seen: set[str] = set()

        for vrf in self._query_current_vrfs(module_args, strategy):
            name = vrf.get("vrf_name") or vrf.get("vrfName")
            if name and name not in desired_names and name not in seen:
                omitted_names.append(name)
                seen.add(name)
        return omitted_names

    def _configured_vrf_names(self, config: list[dict]) -> list[str]:
        """Return configured VRF names in stable order."""
        seen: set[str] = set()
        names: list[str] = []
        for vrf in config:
            name = vrf.get("vrf_name") or vrf.get("vrfName")
            if name and name not in seen:
                names.append(name)
                seen.add(name)
        return names

    def _deploy_enabled_by_vrf(self, config: list[dict]) -> dict[str, bool]:
        """Return per-VRF deploy intent; omitted deploy defaults to True."""
        deploy_enabled: dict[str, bool] = {}
        for vrf in config:
            name = vrf.get("vrf_name") or vrf.get("vrfName")
            if name:
                deploy_enabled[name] = vrf.get("deploy", True)
        return deploy_enabled

    def _deploy_type_by_vrf(self, config: list[dict]) -> dict[str, str]:
        """Return per-VRF deploy scope; omitted deploy_type defaults to switch."""
        deploy_type: dict[str, str] = {}
        for vrf in config:
            name = vrf.get("vrf_name") or vrf.get("vrfName")
            if name:
                deploy_type[name] = vrf.get("deploy_type") or vrf.get("deployType") or "switch"
        return deploy_type

    def _desired_attachment_map(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Build desired attachment payloads keyed by (vrfName, switchId)."""
        config = module_args.get("config") or []
        ip_to_switch = self._resolve_switch_ids(module_args, strategy, config)
        desired: dict[tuple[str, str], dict[str, Any]] = {}

        for vrf in config:
            vrf_name = vrf.get("vrf_name") or vrf.get("vrfName")
            for attachment in vrf.get("attach") or []:
                ip_address = attachment.get("ip_address") or attachment.get("ipAddress")
                switch_id = ip_to_switch.get(ip_address)
                if not vrf_name or not switch_id:
                    continue

                payload = {
                    "vrfName": vrf_name,
                    "switchId": switch_id,
                    "attach": True,
                }
                instance_values = self._attachment_instance_values(attachment)
                if instance_values:
                    payload["instanceValues"] = instance_values
                desired[(vrf_name, switch_id)] = payload

        return desired

    def _resolve_switch_ids(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        config: list[dict],
    ) -> dict[str, str]:
        """Resolve configured switch IPs to ND switchId values."""
        wanted_ips: set[str] = set()
        for vrf in config:
            for attachment in vrf.get("attach") or []:
                ip_address = attachment.get("ip_address") or attachment.get("ipAddress")
                if ip_address:
                    wanted_ips.add(ip_address)

        if not wanted_ips:
            return {}

        orchestrator, results = self._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageSwitchesListGet)
        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            operation_type=OperationType.QUERY,
        )
        # Do not expose switch inventory lookups unless they are needed for
        # troubleshooting a failed mutation.
        results.build_final_result()

        switches = []
        if isinstance(data, dict):
            switches = data.get("switches") or data.get("items") or data.get("DATA") or []
        elif isinstance(data, list):
            switches = data

        resolved: dict[str, str] = {}
        for switch in switches:
            switch_id = switch.get("switchId") or switch.get("serialNumber")
            if not switch_id:
                continue
            for ip_address in self._switch_ip_candidates(switch):
                if ip_address in wanted_ips:
                    resolved[ip_address] = switch_id

        missing = sorted(wanted_ips.difference(resolved))
        if missing:
            self.module.fail_json(
                msg=(
                    "Unable to resolve attach.ip_address values to switchId "
                    f"on fabric '{strategy.fabric_name}': {missing}"
                )
            )
        return resolved

    def _switch_ip_candidates(self, switch: dict[str, Any]) -> set[str]:
        """Extract known management/IP fields from a switch inventory item."""
        candidates: set[str] = set()
        for key in (
            "fabricManagementIp",
            "switchIp",
            "managementIp",
            "ipAddress",
        ):
            if switch.get(key):
                candidates.add(str(switch[key]))

        telemetry = switch.get("telemetryIpCollection") or {}
        if isinstance(telemetry, dict):
            for key in ("outOfBandIpV4Address", "inbandIpV4Address"):
                if telemetry.get(key):
                    candidates.add(str(telemetry[key]))
        return candidates

    def _attachment_instance_values(self, attachment: dict[str, Any]) -> dict[str, Any]:
        """Map playbook attachment fields to ND instanceValues."""
        raw = {
            "loopback_id": attachment.get("loopback_id"),
            "loopback_ipv4_address": attachment.get("loopback_ipv4_address"),
            "loopback_ipv6_address": attachment.get("loopback_ipv6_address"),
            "route_target_import": attachment.get("import_vpn_rt"),
            "route_target_export": attachment.get("export_vpn_rt"),
            "evpn_route_target_import": attachment.get("import_evpn_rt"),
            "evpn_route_target_export": attachment.get("export_evpn_rt"),
        }
        raw = {key: value for key, value in raw.items() if value is not None}
        if not raw:
            return {}
        return VrfAttachmentInstanceValuesModel(**raw).to_payload()

    def _current_attachment_map(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Gathered ND and key attached VRF attachments by (vrfName, switchId)."""
        orchestrator, _results = self._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsVrfAttachmentsQueryPost)
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.include_all = True

        query = VrfAttachmentQueryRequestModel(vrf_names=vrf_names or None)
        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=query.to_payload(),
            operation_type=OperationType.QUERY,
        )

        attachments = []
        if isinstance(data, dict):
            attachments = data.get("attachments") or data.get("items") or []
        elif isinstance(data, list):
            attachments = data

        current: dict[tuple[str, str], dict[str, Any]] = {}
        for attachment in attachments:
            if attachment.get("attach") is not True:
                continue
            vrf_name = attachment.get("vrfName")
            switch_id = attachment.get("switchId")
            if vrf_name and switch_id:
                current[(vrf_name, switch_id)] = attachment
        return current

    def _current_attachment_details(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Gathered all attachment details, including pending detach entries."""
        orchestrator, results = self._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsVrfAttachmentsQueryPost)
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.include_all = True

        query = VrfAttachmentQueryRequestModel(vrf_names=vrf_names or None)
        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=query.to_payload(),
            operation_type=OperationType.QUERY,
        )
        results.build_final_result()

        if isinstance(data, dict):
            return data.get("attachments") or data.get("items") or []
        if isinstance(data, list):
            return data
        return []

    def _current_attachment_details_ignore_missing(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Gathered attachment details while treating absent deleted VRFs as empty."""
        try:
            return self._current_attachment_details(module_args, strategy, vrf_names)
        except Exception as exc:
            if not self._is_vrf_not_found_error(exc):
                raise

        if not vrf_names or len(vrf_names) <= 1:
            return []

        attachments: list[dict[str, Any]] = []
        for vrf_name in vrf_names:
            try:
                attachments.extend(
                    self._current_attachment_details(
                        module_args,
                        strategy,
                        [vrf_name],
                    )
                )
            except Exception as exc:
                if not self._is_vrf_not_found_error(exc):
                    raise
        return attachments

    @staticmethod
    def _is_vrf_not_found_error(error: Exception) -> bool:
        """Return True for ND's attachment-query error when a VRF is absent."""
        message = str(error)
        return "VRF(s)" in message and "not found in fabric" in message

    def _planned_detach_payloads(
        self,
        state: str,
        config: list[dict],
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compute detach payloads for deleted/replaced/overridden states."""
        detach_keys: set[tuple[str, str]] = set()

        if state == "deleted":
            detach_keys = set(current.keys())
        elif state == "overridden":
            detach_keys = set(current.keys()).difference(desired.keys())
        elif state == "replaced":
            vrf_names = set(self._configured_vrf_names(config))
            detach_keys = {
                key for key in current.keys()
                if key[0] in vrf_names and key not in desired
            }

        return [
            {"vrfName": vrf_name, "switchId": switch_id, "attach": False}
            for vrf_name, switch_id in sorted(detach_keys)
        ]

    def _planned_attach_payloads(
        self,
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compute attach payloads for missing or changed desired attachments."""
        payloads: list[dict[str, Any]] = []
        for key, desired_payload in sorted(desired.items()):
            existing = current.get(key)
            if existing is None or not self._attachment_matches(existing, desired_payload):
                payloads.append(desired_payload)
        return payloads

    def _attachment_matches(
        self,
        existing: dict[str, Any],
        desired: dict[str, Any],
    ) -> bool:
        """Return True when existing attachment satisfies desired fields."""
        if existing.get("attach") is not True:
            return False
        desired_instance = desired.get("instanceValues") or {}
        if not desired_instance:
            return True
        existing_instance = existing.get("instanceValues") or {}
        for key, value in desired_instance.items():
            if existing_instance.get(key) != value:
                return False
        return True

    def _post_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        payloads: list[dict[str, Any]],
        deploy_targets: dict[str, set[str]],
        operation_type: OperationType,
    ) -> dict[str, Any]:
        """Send attach/detach payload and return mergeable API trace."""
        request = VrfAttachDetachRequestModel(
            attachments=[VrfAttachmentModel(**payload) for payload in payloads]
        )
        orchestrator, results = self._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsVrfAttachmentsPost)
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=request.to_payload(),
            operation_type=operation_type,
        )
        return self._finalize_api_trace(results, deploy_targets)

    def _record_deploy_target(
        self,
        deploy_targets: dict[str, set[str]],
        vrf_name: str | None,
        switch_id: str | None,
    ) -> None:
        """Record one VRF/switch pair for a later VRF deployment request."""
        if not vrf_name or not switch_id:
            return
        deploy_targets.setdefault(vrf_name, set()).add(switch_id)

    def _build_deploy_payloads(
        self,
        config: list[dict],
        *target_maps: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        """Build deploy requests from one or more VRF/switch maps."""
        deploy_targets: dict[str, set[str]] = {}
        for target_map in target_maps:
            for vrf_name, switch_ids in (target_map or {}).items():
                deploy_targets.setdefault(vrf_name, set()).update(switch_ids)

        if not deploy_targets:
            return []

        deploy_type = self._deploy_type_by_vrf(config)
        payloads: list[dict[str, Any]] = []
        vrf_level_names: list[str] = []
        switch_groups: dict[tuple[str, ...], list[str]] = {}

        for vrf_name in sorted(deploy_targets.keys()):
            if deploy_type.get(vrf_name, "switch") == "vrf":
                vrf_level_names.append(vrf_name)
                continue
            switch_ids = sorted(deploy_targets.get(vrf_name) or [])
            if switch_ids:
                switch_groups.setdefault(tuple(switch_ids), []).append(vrf_name)
            else:
                vrf_level_names.append(vrf_name)

        for switch_ids, vrf_names in sorted(switch_groups.items()):
            payloads.append(
                VrfDeployRequestModel(
                    vrf_names=sorted(vrf_names),
                    switch_ids=list(switch_ids),
                ).to_payload()
            )

        if vrf_level_names:
            payloads.append(
                VrfDeployRequestModel(vrf_names=sorted(vrf_level_names)).to_payload()
            )

        return payloads

    def _build_pending_vrf_deploy_payloads(
        self,
        result: dict[str, Any],
        config: list[dict],
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[dict[str, Any]]:
        """Build a deploy request for configured VRFs already pending in ND."""
        deploy_enabled = self._deploy_enabled_by_vrf(config)
        deploy_type = self._deploy_type_by_vrf(config)
        configured_vrfs = set(self._configured_vrf_names(config))
        pending_statuses = {"pending", "inProgress"}
        pending_vrfs: set[str] = set()

        for vrf in result.get("after") or []:
            vrf_name = vrf.get("vrf_name") or vrf.get("vrfName")
            vrf_status = vrf.get("vrf_status") or vrf.get("vrfStatus")
            if not vrf_name or vrf_name not in configured_vrfs:
                continue
            if not deploy_enabled.get(vrf_name, True):
                continue
            if str(vrf_status or "").strip() in pending_statuses:
                pending_vrfs.add(vrf_name)

        if not pending_vrfs:
            return []

        vrf_level_names: set[str] = set()
        switch_level_names = {
            vrf_name
            for vrf_name in pending_vrfs
            if deploy_type.get(vrf_name, "switch") == "switch"
        }
        vrf_level_names.update(pending_vrfs.difference(switch_level_names))

        deploy_target_map: dict[str, set[str]] = {}
        if switch_level_names:
            attachment_details = self._current_attachment_details(
                module_args,
                strategy,
                sorted(switch_level_names),
            )
            switch_ids_by_vrf: dict[str, set[str]] = {
                vrf_name: set() for vrf_name in switch_level_names
            }
            for attachment in attachment_details:
                vrf_name = attachment.get("vrfName")
                switch_id = attachment.get("switchId")
                if vrf_name in switch_ids_by_vrf and switch_id:
                    switch_ids_by_vrf[vrf_name].add(switch_id)

            for vrf_name in sorted(switch_level_names):
                switch_ids = sorted(switch_ids_by_vrf.get(vrf_name) or [])
                if switch_ids:
                    deploy_target_map[vrf_name] = set(switch_ids)
                else:
                    vrf_level_names.add(vrf_name)

        for vrf_name in vrf_level_names:
            deploy_target_map.setdefault(vrf_name, set())

        return self._build_deploy_payloads(config, deploy_target_map)

    def _query_current_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[dict[str, Any]]:
        """Gathered current VRF records for the target fabric."""
        orchestrator, results = self._new_vrf_orchestrator(module_args, strategy)
        data = orchestrator.query_all()
        results.build_final_result()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("vrfs") or data.get("items") or []
        return []

    def _wait_for_vrfs_delete_ready(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None = None,
    ) -> None:
        """Wait until configured VRFs are absent or in notApplicable state."""
        vrf_name_set = set(
            vrf_names
            if vrf_names is not None
            else self._configured_vrf_names(module_args.get("config") or [])
        )
        if not vrf_name_set:
            return

        timeout = int(module_args.get("timeout") or self.module.params.get("timeout") or 30)
        deadline = time.time() + timeout
        ready_statuses = {"notApplicable", "NA", "na", ""}
        last_statuses: dict[str, str] = {}

        while True:
            vrfs = self._query_current_vrfs(module_args, strategy)
            last_statuses = {}
            for vrf in vrfs:
                name = vrf.get("vrf_name") or vrf.get("vrfName")
                if name in vrf_name_set:
                    status = vrf.get("vrf_status") or vrf.get("vrfStatus") or ""
                    last_statuses[name] = str(status)

            if all(
                name not in last_statuses or last_statuses[name] in ready_statuses
                for name in vrf_name_set
            ):
                return

            if time.time() >= deadline:
                self.module.fail_json(
                    msg=(
                        "Timed out waiting for VRFs to become deletable after "
                        f"detach deployment on fabric '{strategy.fabric_name}': "
                        f"{last_statuses}"
                    )
                )
            time.sleep(5)

    def _deploy_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        deploy_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deploy pending VRF attachment changes once."""
        orchestrator, results = self._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsVrfActionsDeployPost)
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=deploy_payload,
            operation_type=OperationType.UPDATE,
        )
        return self._finalize_api_trace(results)

    # ── Child task runner ─────────────────────────────────────────

    def _run_child_task(self, child_task: dict) -> dict[str, Any]:
        """
        Execute a child fabric VRF task via its own orchestrator instance.

        Builds the child strategy from the ``fabric_details`` injected by the
        parent strategy's ``build_child_task_args()``, then runs
        ``_run_state_machine`` with that strategy.  No module re-invocation
        or subprocess is needed — the same state machine path used for
        standalone and parent fabrics is reused here.
        """
        module_args = child_task["module_args"]
        child_strategy = child_task["strategy"]
        result = self._run_state_machine(module_args, strategy=child_strategy)
        result.setdefault("fabric_type", child_strategy.fabric_type)
        return result

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
        scoped["fabric"] = fabric
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
                structured["msg"] = (
                    f"Child fabric task failed for "
                    f"'{child_result.get('child_fabric')}': "
                    f"{child_result.get('msg', 'Unknown error')}"
                )

        return structured
