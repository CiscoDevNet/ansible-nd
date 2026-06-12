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

import copy

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

    def run_basic(self, module_args: dict, strategy: BaseVrfStrategy | None = None) -> dict[str, Any]:
        """
        Run only the generic NDStateMachine-backed VRF CRUD/gathered flow.
        """
        state = module_args.get("state", "merged")
        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            if state != "gathered":
                sm.manage_state()

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

        if state == "overridden":
            return self.run_overridden(module_args, active_strategy, defer_deploy)

        desired_attachments = None
        desired_vrf_names = None
        if state in ("replaced", "overridden"):
            desired_attachments = self.coordinator._desired_attachment_map(
                module_args,
                active_strategy,
            )

        pre_attach = self.coordinator._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="pre",
            desired=desired_attachments,
            current_vrf_names=desired_vrf_names,
        )
        current_attachments = pre_attach.get("current")
        if current_attachments is not None:
            current_attachments = self.coordinator._attachment_map_after_detach(
                current_attachments,
                pre_attach.get("payloads", []),
            )

        result = self.coordinator._run_state_machine(module_args, strategy=active_strategy)

        if pre_attach:
            self.coordinator._merge_api_trace(result, pre_attach, prepend=True)

        if result.get("failed", False):
            return result

        post_attach = self.coordinator._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="post",
            desired=desired_attachments,
            current_vrf_names=desired_vrf_names,
            current=current_attachments,
        )
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
        config = module_args.get("config") or []
        desired_attachments = self.coordinator._desired_attachment_map(module_args, strategy)
        desired_vrf_names = self.coordinator._configured_vrf_names(config)

        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            current_vrf_names = self._vrf_names_from_models(sm.existing)
            current_vrf_name_set = set(current_vrf_names)
            desired_vrf_name_set = set(desired_vrf_names)
            omitted_vrf_names = [vrf_name for vrf_name in current_vrf_names if vrf_name not in desired_vrf_name_set]
            current_desired_vrf_names = [vrf_name for vrf_name in desired_vrf_names if vrf_name in current_vrf_name_set]

            pre_delete_traces = self.coordinator._prepare_overridden_deletions(
                module_args,
                strategy,
                omitted_vrf_names,
            )
            pre_attach = self.coordinator._apply_attachment_phase(
                module_args,
                strategy,
                phase="pre",
                desired=desired_attachments,
                current_vrf_names=current_desired_vrf_names,
            )
            current_attachments = pre_attach.get("current")
            if current_attachments is None and current_desired_vrf_names == []:
                current_attachments = {}
            if current_attachments is not None:
                current_attachments = self.coordinator._attachment_map_after_detach(
                    current_attachments,
                    pre_attach.get("payloads", []),
                )

            sm.manage_state()
            result = self.coordinator._format_state_machine_output(sm)

            pre_traces = list(pre_delete_traces)
            if pre_attach:
                pre_traces.append(pre_attach)
            for trace in reversed(pre_traces):
                self.coordinator._merge_api_trace(result, trace, prepend=True)

            if result.get("failed", False):
                return result

            post_attach = self.coordinator._apply_attachment_phase(
                module_args,
                strategy,
                phase="post",
                desired=desired_attachments,
                current_vrf_names=desired_vrf_names,
                current=current_attachments,
            )
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
        if not deploy_payloads:
            deploy_payloads = self.coordinator._build_pending_vrf_deploy_payloads(
                result,
                config,
                module_args,
                strategy,
            )
        if not deploy_payloads:
            return result

        if defer_deploy:
            result["_deferred_deploy_payloads"] = deploy_payloads
            return result

        for deploy_payload in deploy_payloads:
            deploy_trace = self.coordinator._deploy_vrf_attachments(
                module_args,
                strategy,
                deploy_payload,
            )
            self.coordinator._merge_api_trace(result, deploy_trace)
        return result

    def run_deleted(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[str, Any]:
        """
        Detach and deploy current VRF attachments before removing the VRF.
        """
        traces: list[dict[str, Any]] = []
        config = module_args.get("config") or []

        if not config:
            return self.delete_all_existing_vrfs(module_args, strategy)

        detach_trace = self.coordinator._apply_deleted_attachment_phase(module_args, strategy)
        if detach_trace:
            traces.append(detach_trace)

        deploy_payloads = self.coordinator._build_deploy_payloads(
            config,
            detach_trace.get("deploy_targets", {}) if detach_trace else {},
        )
        for deploy_payload in deploy_payloads:
            deploy_trace = self.coordinator._deploy_vrf_attachments(
                module_args,
                strategy,
                deploy_payload,
            )
            traces.append(deploy_trace)

        if deploy_payloads:
            self.coordinator._wait_for_vrfs_delete_ready(module_args, strategy)

        result = self.coordinator._run_state_machine(module_args, strategy=strategy)

        for trace in reversed(traces):
            self.coordinator._merge_api_trace(result, trace, prepend=True)
        return result

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
                target_args = copy.deepcopy(module_args)
                target_args["config"] = [{"vrf_name": vrf_name} for vrf_name in target_vrf_names]

                detach_trace = self.coordinator._apply_deleted_attachment_phase(target_args, strategy, target_vrf_names)
                if detach_trace:
                    traces.append(detach_trace)

                deploy_payloads = self.coordinator._build_deploy_payloads(
                    target_args.get("config") or [],
                    detach_trace.get("deploy_targets", {}) if detach_trace else {},
                )
                for deploy_payload in deploy_payloads:
                    deploy_trace = self.coordinator._deploy_vrf_attachments(
                        target_args,
                        strategy,
                        deploy_payload,
                    )
                    traces.append(deploy_trace)

                if deploy_payloads:
                    self.coordinator._wait_for_vrfs_delete_ready(module_args, strategy, target_vrf_names)

                sm._delete_items(items_to_delete)  # pylint: disable=protected-access

            result = self.coordinator._format_state_machine_output(sm)
            for trace in reversed(traces):
                self.coordinator._merge_api_trace(result, trace, prepend=True)
            return result
        finally:
            self.coordinator._restore_state_machine_params(original_config, original_state)

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
