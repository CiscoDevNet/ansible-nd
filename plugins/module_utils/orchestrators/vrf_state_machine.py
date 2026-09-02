# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
VRF-specific state machine wrapper.

The generic NDStateMachine owns single-resource CRUD diffing for VRF objects.
This wrapper owns the VRF-specific workflow around that CRUD phase:

  - pre-detach for replaced/overridden/deleted
  - generic VRF state machine execution
  - post-attach for merged/replaced/overridden
  - deploy of pending attachment changes

It deliberately composes the generic NDStateMachine through the workflow
coordinator helpers instead of changing the shared state-machine contract.
"""

# pylint: disable=protected-access

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)


class VrfStateMachine:
    """
    Execute VRF definition, attachment, and deploy workflows.

    ``coordinator`` is expected to provide the low-level REST, attachment, and
    output helpers. Keeping those helpers injected lets this refactor avoid
    changing endpoint behavior while moving the workflow sequencing into a
    VRF-specific state machine layer.
    """

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator

    def _trace(self, event: str, **details: Any) -> None:
        trace = getattr(self.coordinator, "_trace", None)
        if trace is not None:
            trace(event, **details)

    def _check_mode(self) -> bool:
        """Return True when the owning Ansible module is running in check mode."""
        return bool(getattr(getattr(self.coordinator, "module", None), "check_mode", False))

    def run_basic(self, module_args: dict, strategy: BaseVrfStrategy | None = None) -> dict[str, Any]:
        """
        Run only the generic NDStateMachine-backed VRF CRUD/gathered flow.
        """
        state = module_args.get("state", "merged")
        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            if state != "gathered":
                self._trace("manage_state_start", state=state)
                sm.manage_state()
                self._trace("manage_state_end", state=state)

            return self.coordinator._format_state_machine_output(sm)
        finally:
            self.coordinator._restore_state_machine_params(original_config, original_state)

    def run(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy | None = None,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run VRF CRUD plus attachment/deploy side effects.
        """
        active_strategy = strategy or self.coordinator.strategy
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []

        if active_strategy.is_child or state == "gathered":
            return self.run_basic(module_args, strategy=active_strategy)

        if state == "deleted":
            return self.run_deleted(module_args, active_strategy)

        if state in ("replaced", "overridden"):
            return self._run_state_machine_aware_with_attachments(module_args, active_strategy, defer_deploy)

        desired_attachments = None
        desired_vrf_names = None

        self._trace("attachment_phase_pre_start", state=state)
        pre_attach = self.coordinator._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="pre",
            desired=desired_attachments,
            current_vrf_names=desired_vrf_names,
        )
        self._trace("attachment_phase_pre_end", changed=pre_attach.get("changed"), payload_count=len(pre_attach.get("payloads", [])))
        desired_attachments = pre_attach.get("desired", desired_attachments)
        current_attachments = self._current_after_pre_detach(pre_attach)

        result = self.coordinator._run_state_machine(module_args, strategy=active_strategy)

        self._prepend_traces(result, [pre_attach])

        if result.get("failed", False):
            return result

        self._trace("attachment_phase_post_start", state=state)
        post_attach = self.coordinator._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="post",
            desired=desired_attachments,
            current_vrf_names=desired_vrf_names,
            current=current_attachments,
        )
        self._trace("attachment_phase_post_end", changed=post_attach.get("changed"), payload_count=len(post_attach.get("payloads", [])))
        self.coordinator._merge_api_trace(result, post_attach)

        return self._deploy_after_attachment_changes(
            result,
            config,
            module_args,
            active_strategy,
            pre_attach,
            post_attach,
            defer_deploy,
        )

    def run_overridden(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run overridden using the state machine's initial current-state query.
        """
        return self._run_state_machine_aware_with_attachments(module_args, strategy, defer_deploy)

    def _run_state_machine_aware_with_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run replaced/overridden after deriving current VRF names from the state machine.

        The pre-detach phase must only query attachments for VRFs that already
        exist. First-create ``state=replaced`` tasks can then create the VRF
        before the post-attach phase runs.
        """
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []
        desired_attachments = self.coordinator._desired_attachment_map(module_args, strategy)
        desired_vrf_names = self.coordinator._configured_vrf_names(config)

        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            current_vrf_names = self._vrf_names_from_models(sm.existing)
            current_vrf_name_set = set(current_vrf_names)
            desired_vrf_name_set = set(desired_vrf_names)
            current_desired_vrf_names = [vrf_name for vrf_name in desired_vrf_names if vrf_name in current_vrf_name_set]
            attachment_query_vrf_names = current_vrf_names if state == "overridden" else current_desired_vrf_names
            current_attachment_details = (
                self.coordinator._current_attachment_details_ignore_missing(
                    module_args,
                    strategy,
                    attachment_query_vrf_names,
                )
                if attachment_query_vrf_names
                else []
            )
            current_desired_attachments = self.coordinator._attachment_map_from_details(
                current_attachment_details,
                current_desired_vrf_names,
            )

            pre_delete_traces: list[dict[str, Any]] = []
            if state == "overridden":
                omitted_vrf_names = [vrf_name for vrf_name in current_vrf_names if vrf_name not in desired_vrf_name_set]
                pre_delete_traces = self._prepare_overridden_deletions(
                    module_args,
                    strategy,
                    omitted_vrf_names,
                    current_attachment_details,
                )

            self._trace("attachment_phase_pre_start", state=state)
            pre_attach = self.coordinator._apply_attachment_phase(
                module_args,
                strategy,
                phase="pre",
                desired=desired_attachments,
                current_vrf_names=current_desired_vrf_names,
                current=current_desired_attachments,
                attachment_details=current_attachment_details,
            )
            self._trace("attachment_phase_pre_end", changed=pre_attach.get("changed"), payload_count=len(pre_attach.get("payloads", [])))
            desired_attachments = pre_attach.get("desired", desired_attachments)
            current_attachments = self._current_after_pre_detach(
                pre_attach,
                empty_when_absent=current_desired_vrf_names == [],
            )

            self._trace("manage_state_start", state=state)
            sm.manage_state()
            self._trace("manage_state_end", state=state)
            result = self.coordinator._format_state_machine_output(sm)

            self._prepend_traces(result, pre_delete_traces + [pre_attach])

            if result.get("failed", False):
                return result

            post_attachment_details = list(current_attachment_details or [])
            post_current_attachments = dict(current_attachments or {})
            new_desired_vrf_names = [vrf_name for vrf_name in desired_vrf_names if vrf_name not in current_vrf_name_set]
            if state in ("replaced", "overridden") and desired_attachments and new_desired_vrf_names and not self._check_mode():
                self._trace("attachment_phase_post_new_current_query_start", vrf_names=new_desired_vrf_names)
                new_attachment_details = self.coordinator._current_attachment_details(
                    module_args,
                    strategy,
                    new_desired_vrf_names,
                )
                post_attachment_details.extend(new_attachment_details)
                post_current_attachments.update(self.coordinator._attachment_map_from_details(new_attachment_details, new_desired_vrf_names))
                self._trace(
                    "attachment_phase_post_new_current_query_end",
                    vrf_names=new_desired_vrf_names,
                    attachment_count=len(new_attachment_details or []),
                    current_count=len(post_current_attachments),
                )

            self._trace("attachment_phase_post_start", state=state)
            post_attach = self.coordinator._apply_attachment_phase(
                module_args,
                strategy,
                phase="post",
                desired=desired_attachments,
                current_vrf_names=desired_vrf_names,
                current=post_current_attachments,
                attachment_details=post_attachment_details,
            )
            self._trace("attachment_phase_post_end", changed=post_attach.get("changed"), payload_count=len(post_attach.get("payloads", [])))
            self.coordinator._merge_api_trace(result, post_attach)

            return self._deploy_after_attachment_changes(
                result,
                config,
                module_args,
                strategy,
                pre_attach,
                post_attach,
                defer_deploy,
            )
        finally:
            self.coordinator._restore_state_machine_params(original_config, original_state)

    def _current_after_pre_detach(
        self,
        pre_attach: dict[str, Any],
        empty_when_absent: bool = False,
    ) -> dict[tuple[str, str], dict[str, Any]] | None:
        """Return cached attachments after applying pre-detach payloads."""
        current = pre_attach.get("current")
        if current is None:
            return {} if empty_when_absent else None
        return self.coordinator._attachment_map_after_detach(
            current,
            pre_attach.get("payloads", []),
        )

    def _deploy_after_attachment_changes(
        self,
        result: dict[str, Any],
        config: list[dict],
        module_args: dict,
        strategy: BaseVrfStrategy,
        pre_attach: dict[str, Any],
        post_attach: dict[str, Any],
        defer_deploy: bool,
    ) -> dict[str, Any]:
        """Deploy or defer pending work produced by attachment phases."""
        deploy_payloads = self.coordinator._build_deploy_payloads(
            config,
            pre_attach.get("deploy_targets", {}),
            post_attach.get("deploy_targets", {}),
        )
        self._trace("deploy_payloads_from_attachments", payload_count=len(deploy_payloads), payloads=deploy_payloads)
        if not deploy_payloads:
            deploy_payloads = self.coordinator._build_pending_vrf_deploy_payloads(
                result,
                config,
                module_args,
                strategy,
            )
            self._trace("deploy_payloads_from_result", payload_count=len(deploy_payloads), payloads=deploy_payloads)
        if not deploy_payloads:
            return result

        if defer_deploy:
            result["_deferred_deploy_payloads"] = deploy_payloads
            return result

        if self._check_mode():
            self.coordinator._merge_api_trace(
                result,
                {
                    "changed": True,
                    "failed": False,
                    "check_mode_deploy_payloads": deploy_payloads,
                },
            )
            return result

        for deploy_payload in deploy_payloads:
            self._trace("deploy_start", deploy_payload=deploy_payload)
            deploy_trace = self.coordinator._deploy_vrf_attachments(
                module_args,
                strategy,
                deploy_payload,
            )
            self.coordinator._merge_api_trace(result, deploy_trace)
            self._trace("deploy_end", deploy_payload=deploy_payload)
        return result

    def _prepare_overridden_deletions(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        omitted_vrf_names: list[str],
        current_attachment_details: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Detach/deploy omitted VRFs before overridden deletes them."""
        if not omitted_vrf_names:
            return []

        self.coordinator._ensure_vrfs_have_no_networks(module_args, strategy, omitted_vrf_names)
        omitted_attachment_details = (
            self.coordinator._filter_attachment_details_by_vrf(
                current_attachment_details,
                omitted_vrf_names,
            )
            if current_attachment_details is not None
            else None
        )
        detach_trace = self.coordinator._apply_deleted_attachment_phase(
            module_args,
            strategy,
            omitted_vrf_names,
            attachment_details=omitted_attachment_details,
        )
        return self._deploy_detach_traces(
            api_args=module_args,
            wait_args=module_args,
            strategy=strategy,
            config=[self._delete_all_generated_config(vrf_name, strategy) for vrf_name in omitted_vrf_names],
            detach_trace=detach_trace,
            wait_vrf_names=omitted_vrf_names,
        )

    def run_deleted(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[str, Any]:
        """
        Detach and deploy current VRF attachments before removing the VRF.
        """
        config = module_args.get("config") or []

        if not config:
            return self.delete_all_existing_vrfs(module_args, strategy)

        configured_vrf_names = self.coordinator._configured_vrf_names(config)
        current_vrfs = self.coordinator._query_current_vrfs(module_args, strategy)
        current_vrf_names = set(self._vrf_names_from_records(current_vrfs))
        existing_vrf_names = [vrf_name for vrf_name in configured_vrf_names if vrf_name in current_vrf_names]
        self._trace(
            "delete_existing_vrfs_resolved",
            configured_count=len(configured_vrf_names),
            existing_count=len(existing_vrf_names),
            existing_vrf_names=existing_vrf_names,
        )

        if not existing_vrf_names:
            self._trace("delete_no_existing_vrfs_skip_detach")
            result = self.coordinator._run_state_machine(module_args, strategy=strategy)
            self._trace("delete_manage_state_end", changed=result.get("changed"), failed=result.get("failed"))
            return result

        self._trace("delete_dependency_check_start", vrf_count=len(existing_vrf_names))
        self.coordinator._ensure_vrfs_have_no_networks(
            module_args,
            strategy,
            existing_vrf_names,
        )
        self._trace("delete_dependency_check_end", vrf_count=len(existing_vrf_names))
        self._trace("delete_detach_phase_start", vrf_count=len(existing_vrf_names))
        detach_trace = self.coordinator._apply_deleted_attachment_phase(module_args, strategy, existing_vrf_names)
        self._trace("delete_detach_phase_end", changed=detach_trace.get("changed"), payload_count=len(detach_trace.get("payloads", [])))
        traces = self._deploy_detach_traces(
            api_args=module_args,
            wait_args=module_args,
            strategy=strategy,
            config=config,
            detach_trace=detach_trace,
        )

        self._trace("delete_manage_state_start", vrf_count=len(config))
        result = self.coordinator._run_state_machine(module_args, strategy=strategy)
        self._trace("delete_manage_state_end", changed=result.get("changed"), failed=result.get("failed"))
        self._prepend_traces(result, traces)
        return result

    @staticmethod
    def _vrf_names_from_records(vrfs: list[dict[str, Any]]) -> list[str]:
        """Return VRF names from current-state records."""
        names: list[str] = []
        for vrf in vrfs:
            name = vrf.get("vrf_name") or vrf.get("vrfName")
            if name:
                names.append(name)
        return names

    def delete_all_existing_vrfs(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[str, Any]:
        """
        Delete all VRFs currently present on the target fabric.
        """
        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            items_to_delete = list(sm.existing)
            target_vrf_names = [self._vrf_name_from_model(item) for item in items_to_delete]
            traces: list[dict[str, Any]] = []

            if items_to_delete:
                target_args = dict(module_args)
                target_args["config"] = [self._delete_all_generated_config(vrf_name, strategy) for vrf_name in target_vrf_names]

                self.coordinator._ensure_vrfs_have_no_networks(target_args, strategy, target_vrf_names)
                detach_trace = self.coordinator._apply_deleted_attachment_phase(target_args, strategy, target_vrf_names)
                traces = self._deploy_detach_traces(
                    api_args=target_args,
                    wait_args=module_args,
                    strategy=strategy,
                    config=target_args.get("config") or [],
                    detach_trace=detach_trace,
                    wait_vrf_names=target_vrf_names,
                )
                traces.extend(
                    self._deploy_pending_vrfs_before_delete(
                        module_args,
                        strategy,
                        items_to_delete,
                        target_vrf_names,
                    )
                )

                sm._delete_items(items_to_delete)  # pylint: disable=protected-access

            result = self.coordinator._format_state_machine_output(sm)
            self._prepend_traces(result, traces)
            return result
        finally:
            self.coordinator._restore_state_machine_params(original_config, original_state)

    def _deploy_detach_traces(
        self,
        api_args: dict,
        wait_args: dict,
        strategy: BaseVrfStrategy,
        config: list[dict],
        detach_trace: dict[str, Any],
        wait_vrf_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return detach trace plus deploy traces, waiting when deploy occurs."""
        traces = [detach_trace] if detach_trace else []
        deploy_payloads = self.coordinator._build_deploy_payloads(
            config,
            detach_trace.get("deploy_targets", {}) if detach_trace else {},
        )
        self._trace("delete_deploy_payloads_built", payload_count=len(deploy_payloads), payloads=deploy_payloads)
        if self._check_mode():
            if deploy_payloads:
                traces.append(
                    {
                        "changed": True,
                        "failed": False,
                        "check_mode_deploy_payloads": deploy_payloads,
                    }
                )
            return traces

        for deploy_payload in deploy_payloads:
            self._trace("delete_deploy_start", deploy_payload=deploy_payload)
            traces.append(
                self.coordinator._deploy_vrf_attachments(
                    api_args,
                    strategy,
                    deploy_payload,
                )
            )
            self._trace("delete_deploy_end", deploy_payload=deploy_payload)

        if deploy_payloads:
            self._trace("delete_wait_ready_start", vrf_names=wait_vrf_names)
            if wait_vrf_names is None:
                self.coordinator._wait_for_vrfs_delete_ready(wait_args, strategy)
            else:
                self.coordinator._wait_for_vrfs_delete_ready(wait_args, strategy, wait_vrf_names)
            self._trace("delete_wait_ready_end", vrf_names=wait_vrf_names)
        return traces

    def _deploy_pending_vrfs_before_delete(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        items_to_delete: list[Any],
        target_vrf_names: list[str],
    ) -> list[dict[str, Any]]:
        """Deploy pending VRF definitions once so the controller allows delete."""
        pending_config = [
            {
                "vrf_name": vrf_name,
                "deploy": True,
                "deploy_type": "vrf",
            }
            for vrf_name in target_vrf_names
        ]
        current_result = {"after": [self._model_to_config(item) for item in items_to_delete]}
        deploy_payloads = self.coordinator._build_pending_vrf_deploy_payloads(
            current_result,
            pending_config,
            module_args,
            strategy,
        )
        if not deploy_payloads:
            return []

        if self._check_mode():
            return [
                {
                    "changed": True,
                    "failed": False,
                    "check_mode_deploy_payloads": deploy_payloads,
                }
            ]

        traces: list[dict[str, Any]] = []
        for deploy_payload in deploy_payloads:
            traces.append(
                self.coordinator._deploy_vrf_attachments(
                    module_args,
                    strategy,
                    deploy_payload,
                )
            )
        self.coordinator._wait_for_vrfs_delete_ready(
            module_args,
            strategy,
            target_vrf_names,
        )
        return traces

    def _prepend_traces(self, result: dict[str, Any], traces: list[dict[str, Any]]) -> None:
        """Merge traces before the state-machine trace in result order."""
        for trace in reversed(traces):
            if trace:
                self.coordinator._merge_api_trace(result, trace, prepend=True)

    @staticmethod
    def _vrf_name_from_model(item: Any) -> str:
        """Extract the VRF name from a state-machine model instance."""
        vrf_name = getattr(item, "vrf_name", None)
        if vrf_name:
            return vrf_name
        identifier = item.get_identifier_value()
        if isinstance(identifier, tuple):
            return identifier[0]
        return identifier

    @staticmethod
    def _model_to_config(item: Any) -> dict[str, Any]:
        """Return a config-shaped dict from a state-machine model instance."""
        if hasattr(item, "to_config"):
            return item.to_config()
        if hasattr(item, "model_dump"):
            return item.model_dump(by_alias=False, exclude_none=True, mode="json")
        return {}

    @staticmethod
    def _delete_all_generated_config(vrf_name: str, strategy: BaseVrfStrategy) -> dict[str, Any]:
        """Build synthetic delete config for config=[] cleanup."""
        config = {"vrf_name": vrf_name}
        if getattr(strategy, "is_parent", False):
            config["deploy_type"] = "vrf"
        return config

    def _vrf_names_from_models(self, items: Any) -> list[str]:
        """Return unique VRF names from state-machine model instances."""
        vrf_names: list[str] = []
        seen: set[str] = set()
        for item in items:
            vrf_name = self._vrf_name_from_model(item)
            if vrf_name and vrf_name not in seen:
                vrf_names.append(vrf_name)
                seen.add(vrf_name)
        return vrf_names
