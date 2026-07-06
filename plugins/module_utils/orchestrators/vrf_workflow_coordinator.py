# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
VrfWorkflowCoordinator — Parent / child VRF workflow orchestration.

The coordinator is constructed inside nd_manage_vrfs.py after the strategy is
resolved. For standalone and child fabrics it runs the state machine
directly. For parent fabrics it:
  1. Parses and validates the requested VRF config.
  2. Splits child_fabric_config into per-child in-process tasks.
  3. Runs the parent task via the VRF state machine.
  4. Runs each child task with the child's resolved strategy.
  5. Deploys deferred parent attachment changes, then aggregates results.
"""

from __future__ import annotations

import copy

from typing import Any, Optional, Union

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager import (
    VrfAttachmentManager,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_config_utils import (
    configured_vrf_names,
    deploy_enabled_by_vrf,
    deploy_type_by_vrf,
    vrf_name_filter,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_dependency_checker import (
    VrfDependencyChecker,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import (
    VrfFabricResolver,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import (
    VrfStateMachine,
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

    @property
    def attachments(self) -> VrfAttachmentManager:
        """Return the VRF attachment/deploy manager."""
        if not hasattr(self, "_attachments"):
            self._attachments = VrfAttachmentManager(self)
        return self._attachments

    @property
    def dependencies(self) -> VrfDependencyChecker:
        """Return the VRF dependency checker."""
        if not hasattr(self, "_dependencies"):
            self._dependencies = VrfDependencyChecker(self)
        return self._dependencies

    # ── Entry point ────────────────────────────────────────────

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
                if vrf.get("child_fabric_config"):
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
            for idx, vrf in enumerate(config):
                if vrf.get("attach"):
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
                model = model_cls.from_config(entry)
                parsed.append(model.to_config())
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
        module_args["config"] = self._parse_config(module_args.get("config") or [], self.strategy.config_model_cls, state)
        result = self._run_state_machine_with_attachments(module_args)
        result.setdefault("fabric_type", fabric_type)
        result.setdefault("workflow", "Standalone Fabric VRF Processing")
        return result

    def _handle_child_workflow(self, module_args: dict, fabric_type: str) -> dict[str, Any]:
        """
        Enforce the Multisite / Multicluster operational model for child fabrics.

        Only state='gathered' is permitted when the module targets a child fabric
        directly. All write operations must be driven by the parent fabric.
        """
        state = module_args.get("state")
        fabric_name = module_args.get("fabric_name")

        if state == "gathered":
            module_args["config"] = self._parse_config(module_args.get("config") or [], self.strategy.config_model_cls, state)
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

    def _handle_parent_workflow(self, module_args: dict, fabric_type: str) -> dict[str, Any]:
        """
        Full parent orchestration: parent fabric first, then all child fabrics.

        Workflow steps:
          1. Parse and validate configs with the resolved VRF model.
          2. Split each VRF's child_fabric_config entries into per-fabric tasks.
          3. Build a clean parent config (child_fabric_config stripped).
          4. Run the parent state machine.
          5. If parent succeeded, execute each child task sequentially in-process.
          6. Deploy deferred parent attachment changes.
          7. Aggregate all results into a structured response.
        """
        log_type = "multicluster" if "multicluster" in fabric_type else "multisite"
        parent_fabric = module_args.get("fabric_name")
        state = module_args.get("state", "merged")
        config: list[dict] = self._parse_config(module_args.get("config") or [], self.strategy.config_model_cls, state)

        # Collect member fabric names for relationship validation
        child_member_names = self.strategy.child_fabric_members()
        child_member_name_set = set(child_member_names)
        child_fabric_data_map: dict[str, dict] = {m.get("fabricName"): m for m in self.strategy.fabric_data.get("members", []) if m.get("fabricName")}

        # Step 2 & 3 — split config into parent config + child task groups
        parent_config: list[dict] = []
        child_tasks_dict: dict[str, dict] = {}

        for vrf in config:
            child_configs = vrf.get("child_fabric_config") or []

            if state != "deleted":
                for child_cfg in child_configs:
                    child_fabric_name = child_cfg.get("fabric_name")
                    if child_fabric_name not in child_member_name_set:
                        self.module.fail_json(
                            msg=(
                                f"Fabric '{child_fabric_name}' is not a member of " f"parent fabric '{parent_fabric}'. " f"Known members: {child_member_names}"
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
            parent_vrf = dict(vrf)
            parent_vrf.pop("child_fabric_config", None)
            if getattr(self.strategy, "is_multicluster", False):
                self._remove_defaulted_mcfg_parent_fabric_options(parent_vrf)
                if child_configs:
                    self._remove_child_owned_mcfg_parent_fabric_options(parent_vrf)
            parent_config.append(parent_vrf)

        # Step 4 — run parent state machine
        parent_module_args = dict(module_args)
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

        if not parent_result.get("failed", False) and not any(result.get("failed", False) for result in child_results):
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
        return self._build_structured_result(parent_result, child_results, parent_fabric, fabric_type, log_type)

    # ── Config splitting helpers ──────────────────────────────────

    @staticmethod
    def _remove_defaulted_mcfg_parent_fabric_options(parent_vrf: dict[str, Any]) -> None:
        """
        Remove Ansible-injected fabric option defaults from MCFG parent rows
        that are scoped to child fabrics.

        The parent template-config readback does not consistently include these default
        flags when child fabrics disagree, so sending implicit defaults causes
        repeated parent updates.  Non-default values are left intact.
        """
        defaulted_fabric_values = {
            "l3vni_wo_vlan": False,
            "adv_host_routes": False,
            "adv_default_routes": True,
            "static_default_route": True,
            "trm_enable": False,
            "ipv6_trm": False,
            "no_rp": False,
            "rp_external": False,
            "trm_bgw_msite": False,
            "netflow_enable": False,
        }
        for key, default_value in defaulted_fabric_values.items():
            if parent_vrf.get(key) == default_value:
                parent_vrf.pop(key, None)

    @staticmethod
    def _remove_child_owned_mcfg_parent_fabric_options(parent_vrf: dict[str, Any]) -> None:
        """
        Remove fabric-instance options from MCFG parent rows that also have
        explicit child_fabric_config.

        In MCFG, child-specific VRF fabric options are applied through the
        child manage endpoints.  Keeping those same fields on the parent
        template-config record causes repeated parent PUTs because parent readback and
        child readback do not expose the exact same fabricData shape.
        """
        child_owned_fields = {
            "l3vni_wo_vlan",
            "l3_vni_without_vlan",
            "adv_host_routes",
            "advertise_host_route",
            "adv_default_routes",
            "advertise_default_route",
            "static_default_route",
            "configure_static_default_route",
            "bgp_password",
            "bgpPassword",
            "bgp_passwd_encrypt",
            "bgp_password_key_type",
            "netflow_enable",
            "netflow",
            "nf_monitor",
            "netflow_monitor",
            "trm_enable",
            "ipv4_trm",
            "ipv6_trm",
            "no_rp",
            "v4_rp_absent",
            "rp_external",
            "v4_rp_external",
            "rp_address",
            "v4_rp_address",
            "rp_loopback_id",
            "loopback_number",
            "underlay_mcast_ip",
            "l3_vni_multicast_group",
            "overlay_mcast_group",
            "v4_multicast_group",
            "trm_bgw_msite",
            "trm_on_bgw",
            "import_mvpn_rt",
            "mvpn_route_target_import",
            "export_mvpn_rt",
            "mvpn_route_target_export",
        }
        for key in child_owned_fields:
            parent_vrf.pop(key, None)

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
        child_fabric_name: str = child_cfg.pop("fabric_name")

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
                "strategy": VrfFabricResolver.strategy_from_fabric_details(child_fabric_name, child_fabric_data),
            }

        return child_tasks_dict

    # ── State machine runner ──────────────────────────────────────

    def _run_state_machine(self, module_args: dict, strategy: Optional[BaseVrfStrategy] = None) -> dict[str, Any]:
        """
        Run NDStateMachine for the given module_args and return the result dict.

        ``strategy`` defaults to ``self.strategy`` (the resolved fabric strategy).
        Pass an explicit strategy when running child fabric tasks so the
        orchestrator uses the child's endpoint configuration instead of the
        parent's.

        VRF-specific payload transformation is kept here so the shared state
        machine does not need to know about VRF playbook field aliases.
        """
        return self._vrf_state_machine().run_basic(module_args, strategy=strategy)

    def _vrf_state_machine(self) -> VrfStateMachine:
        """Return the VRF-specific state machine wrapper for this coordinator."""
        if not hasattr(self, "_vrf_state_machine_instance"):
            self._vrf_state_machine_instance = VrfStateMachine(self)
        return self._vrf_state_machine_instance

    def _new_state_machine(self, module_args: dict, strategy: Optional[BaseVrfStrategy] = None) -> tuple[NDStateMachine, Any, Any]:
        """
        Build a VRF state machine after applying VRF config transformation.

        NDStateMachine initialization performs the current-state query.  Callers
        that need that current state directly, such as VRF delete-all, should
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

            orchestrator = NDVrfOrchestrator(
                rest_send=rest_send,
                strategy=active_strategy,
            )
            self.module.params["config"] = orchestrator.prepare_config_data(module_args.get("config") or [])
            self.module.params["state"] = state
            sm = NDStateMachine(module=self.module, model_orchestrator=orchestrator)
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
        strategy: Optional[BaseVrfStrategy] = None,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run VRF CRUD plus attachment/deploy side effects for parent scopes.

        The Manage API treats VRF definition, attachment, and deployment as
        separate endpoints.  Keep attach/deploy out of the VRF payload and
        apply them around the normal state machine.
        """
        return self._vrf_state_machine().run(module_args, strategy=strategy, defer_deploy=defer_deploy)

    def _run_overridden_state_machine_with_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run overridden using the state machine's initial current-state query.

        The pre-delete and pre-attach phases need to know which VRFs currently
        exist before ``manage_state`` deletes omitted items.  Use
        ``sm.existing`` from NDStateMachine initialization instead of querying
        current VRFs separately and then building a second state machine later.
        """
        return self._vrf_state_machine().run_overridden(module_args, strategy, defer_deploy=defer_deploy)

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
        return self._vrf_state_machine().run_deleted(module_args, strategy)

    def _delete_all_existing_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[str, Any]:
        """
        Delete all VRFs currently present on the target fabric.

        ``config=[]`` means "delete what exists".  The current VRFs come from
        NDStateMachine initialization, which has already queried the fabric;
        do not issue another current-state query or rewrite proposed config.
        """
        return self._vrf_state_machine().delete_all_existing_vrfs(module_args, strategy)

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
        deploy_targets: Optional[dict[str, set[str]]] = None,
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
        strategy: BaseVrfStrategy,
        phase: str,
        desired: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
        current_vrf_names: Optional[list[str]] = None,
        current: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Attach or detach VRFs according to state and phase."""
        return self.attachments.apply_phase(module_args, strategy, phase, desired, current_vrf_names, current)

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
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]] = None,
        attachment_details: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """
        Detach all current attachments for deleted VRFs, independent of config.

        This uses the attachment query endpoint directly instead of the desired
        attach map because a delete task should converge what is currently on
        ND, not what the playbook happens to include under ``attach``.
        """
        return self.attachments.apply_deleted_phase(module_args, strategy, vrf_names, attachment_details)

    def _filter_attachment_details_by_vrf(
        self,
        attachments: list[dict[str, Any]],
        vrf_names: Union[list[str], set[str]],
    ) -> list[dict[str, Any]]:
        """Return attachment rows for the requested VRF names."""
        return self.attachments.filter_attachment_details_by_vrf(attachments, vrf_names)

    def _attachment_has_pending_delete_work(self, attachment: dict[str, Any]) -> bool:
        """Return True for an already-detached row that still needs deploy."""
        return self.attachments.attachment_has_pending_delete_work(attachment)

    def _configured_vrf_names(self, config: list[dict]) -> list[str]:
        """Return configured VRF names in stable order."""
        return configured_vrf_names(config)

    def _deploy_enabled_by_vrf(self, config: list[dict]) -> dict[str, bool]:
        """Return per-VRF deploy intent; omitted deploy defaults to True."""
        return deploy_enabled_by_vrf(config)

    def _deploy_type_by_vrf(self, config: list[dict]) -> dict[str, str]:
        """Return per-VRF deploy scope; omitted deploy_type defaults to switch."""
        return deploy_type_by_vrf(config)

    def _desired_attachment_map(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Build desired attachment payloads keyed by (vrfName, switchId)."""
        return self.attachments.desired_attachment_map(module_args, strategy)

    def _resolve_switch_ids(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        config: list[dict],
    ) -> dict[str, str]:
        """Resolve configured switch IPs to ND switchId values."""
        return self.attachments.resolve_switch_ids(module_args, strategy, config)

    def _switch_ip_candidates(self, switch: dict[str, Any]) -> set[str]:
        """Extract known management/IP fields from a switch inventory item."""
        return self.attachments.switch_ip_candidates(switch)

    def _attachment_instance_values(self, attachment: dict[str, Any]) -> dict[str, Any]:
        """Map playbook attach fields to ND instanceValues."""
        return self.attachments.attachment_instance_values(attachment)

    def _current_attachment_map(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Gathered ND and key attached VRF attachments by (vrfName, switchId)."""
        return self.attachments.current_attachment_map(module_args, strategy, vrf_names)

    def _attachment_map_from_details(
        self,
        attachments: list[dict[str, Any]],
        vrf_names: Optional[Union[list[str], set[str]]] = None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Key attached VRF attachment rows by (vrfName, switchId)."""
        return self.attachments.attachment_map_from_details(attachments, vrf_names)

    def _current_attachment_details(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]],
    ) -> list[dict[str, Any]]:
        """Gathered all attachment details, including pending detach entries."""
        return self.attachments.current_attachment_details(module_args, strategy, vrf_names)

    def _current_attachment_details_ignore_missing(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]],
    ) -> list[dict[str, Any]]:
        """Gathered attachment details while treating absent deleted VRFs as empty."""
        return self.attachments.current_attachment_details_ignore_missing(module_args, strategy, vrf_names)

    @staticmethod
    def _is_vrf_not_found_error(error: Exception) -> bool:
        """Return True for ND's attachment-query error when a VRF is absent."""
        return VrfAttachmentManager.is_vrf_not_found_error(error)

    def _ensure_vrfs_have_no_networks(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str],
    ) -> None:
        """Fail before VRF deletion when networks still reference the VRFs."""
        self.dependencies.ensure_no_networks(module_args, strategy, vrf_names)

    def _current_networks_for_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str],
    ) -> list[dict[str, Any]]:
        """Gather networks referencing the requested VRFs."""
        return self.dependencies.current_networks_for_vrfs(module_args, strategy, vrf_names)

    def _query_networks_for_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str],
        use_filter: bool,
    ) -> list[dict[str, Any]]:
        """Query the networks endpoint, optionally scoped by VRF filter."""
        return self.dependencies.query_networks_for_vrfs(module_args, strategy, vrf_names, use_filter)

    def _vrf_name_filter(self, vrf_names: list[str]) -> str:
        """Build a URL-safe Lucene filter for VRF names."""
        return vrf_name_filter(vrf_names)

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

    def _post_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
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
        return self.attachments.post_vrf_attachments(module_args, strategy, payloads, deploy_targets, operation_type)

    def _record_deploy_target(
        self,
        deploy_targets: dict[str, set[str]],
        vrf_name: Optional[str],
        switch_id: Optional[str],
    ) -> None:
        """Record one VRF/switch pair for a later VRF deployment request."""
        self.attachments.record_deploy_target(deploy_targets, vrf_name, switch_id)

    def _build_deploy_payloads(
        self,
        config: list[dict],
        *target_maps: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        """Build deploy requests from one or more VRF/switch maps."""
        return self.attachments.build_deploy_payloads(config, *target_maps)

    def _build_pending_vrf_deploy_payloads(
        self,
        result: dict[str, Any],
        config: list[dict],
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[dict[str, Any]]:
        """Build a deploy request for configured VRFs already pending in ND."""
        return self.attachments.build_pending_vrf_deploy_payloads(result, config, module_args, strategy)

    def _query_current_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[dict[str, Any]]:
        """Gathered current VRF records for the target fabric."""
        vrfs, _trace = self._query_current_vrfs_with_trace(module_args, strategy)
        return vrfs

    def _query_current_vrfs_with_trace(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Gather current VRF records and return the associated API trace."""
        orchestrator, results = self._new_vrf_orchestrator(module_args, strategy)
        data = orchestrator.query_all()
        if isinstance(data, list):
            vrfs = data
        elif isinstance(data, dict):
            vrfs = data.get("vrfs") or data.get("items") or []
        else:
            vrfs = []
        return vrfs, self._finalize_api_trace(results)

    def _wait_for_vrfs_delete_ready(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]] = None,
    ) -> None:
        """Wait until configured VRFs are absent or in notApplicable state."""
        if self.module.check_mode:
            return
        self.attachments.wait_for_vrfs_delete_ready(module_args, strategy, vrf_names)

    def _deploy_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        deploy_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deploy pending VRF attachment changes once."""
        if self.module.check_mode:
            return {
                "changed": True,
                "failed": False,
                "check_mode_deploy_payloads": [deploy_payload],
            }
        return self.attachments.deploy_vrf_attachments(module_args, strategy, deploy_payload)

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
        try:
            result = self._run_state_machine(module_args, strategy=child_strategy)
        except Exception as exc:
            return {
                "changed": False,
                "failed": True,
                "msg": str(exc),
                "exception": type(exc).__name__,
                "fabric_type": getattr(child_strategy, "fabric_type", "unknown_child"),
                "proposed": copy.deepcopy(module_args.get("config") or []),
            }
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
