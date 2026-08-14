# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Network-specific state machine wrapper.

The generic NDStateMachine owns single-resource CRUD diffing for Network objects.
This wrapper owns the Network-specific workflow around that CRUD phase:

  - pre-detach for replaced/overridden/deleted
  - generic Network state machine execution
  - post-attach for merged/replaced/overridden
  - deploy of pending attachment changes

It deliberately composes the generic NDStateMachine through the workflow
coordinator helpers instead of changing the shared state-machine contract.
"""

# pylint: disable=protected-access

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)


class NetworkStateMachine:
    """
    Execute Network definition, attachment, and deploy workflows.

    ``coordinator`` is expected to provide the low-level REST, attachment, and
    output helpers. Keeping those helpers injected lets this refactor avoid
    changing endpoint behavior while moving the workflow sequencing into a
    Network-specific state machine layer.
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

    def run_basic(self, module_args: dict, strategy: BaseNetworkStrategy | None = None) -> dict[str, Any]:
        """
        Run only the generic NDStateMachine-backed Network CRUD/gathered flow.
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
        strategy: BaseNetworkStrategy | None = None,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run Network CRUD plus attachment/deploy side effects.
        """
        active_strategy = strategy or self.coordinator.strategy
        state = module_args.get("state", "merged")
        config = [dict(network) for network in module_args.get("config") or []]

        if active_strategy.is_child or state == "gathered":
            return self.run_basic(module_args, strategy=active_strategy)

        if state == "deleted":
            return self.run_deleted(module_args, active_strategy)

        if state in ("replaced", "overridden"):
            return self._run_state_machine_aware_with_attachments(module_args, active_strategy, defer_deploy)

        desired_attachments = None
        desired_network_names = None
        if state in ("merged", "replaced", "overridden"):
            desired_attachments = self.coordinator._desired_attachment_map(
                module_args,
                active_strategy,
            )

        self._trace("attachment_phase_pre_start", state=state)
        pre_attach = self.coordinator._apply_attachment_phase(
            module_args,
            active_strategy,
            phase="pre",
            desired=desired_attachments,
            current_network_names=desired_network_names,
        )
        self._trace("attachment_phase_pre_end", changed=pre_attach.get("changed"), payload_count=len(pre_attach.get("payloads", [])))
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
            current_network_names=desired_network_names,
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
        strategy: BaseNetworkStrategy,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run overridden using the state machine's initial current-state query.
        """
        return self._run_state_machine_aware_with_attachments(module_args, strategy, defer_deploy)

    def _run_state_machine_aware_with_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        defer_deploy: bool = False,
    ) -> dict[str, Any]:
        """
        Run replaced/overridden after deriving current Network names from the state machine.

        The pre-detach phase must only query attachments for Networks that
        already exist. First-create ``state=replaced`` tasks can then create
        the Network before the post-attach phase runs.
        """
        state = module_args.get("state", "merged")
        config = [dict(network) for network in module_args.get("config") or []]
        desired_attachments = self.coordinator._desired_attachment_map(module_args, strategy)
        desired_network_names = self.coordinator._configured_network_names(config)

        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            current_network_names = self._network_names_from_models(sm.existing)
            current_network_name_set = set(current_network_names)
            desired_network_name_set = set(desired_network_names)
            current_desired_network_names = [network_name for network_name in desired_network_names if network_name in current_network_name_set]
            attachment_query_network_names = current_network_names if state == "overridden" else current_desired_network_names
            current_attachment_details = (
                self.coordinator._current_attachment_details_ignore_missing(
                    module_args,
                    strategy,
                    attachment_query_network_names,
                )
                if attachment_query_network_names
                else []
            )
            current_desired_attachments = self.coordinator._attachment_map_from_details(
                current_attachment_details,
                current_desired_network_names,
            )

            pre_delete_traces: list[dict[str, Any]] = []
            if state == "overridden":
                omitted_network_names = [network_name for network_name in current_network_names if network_name not in desired_network_name_set]
                pre_delete_traces = self._prepare_overridden_deletions(
                    module_args,
                    strategy,
                    omitted_network_names,
                    current_attachment_details,
                )

            self._trace("attachment_phase_pre_start", state=state)
            pre_attach = self.coordinator._apply_attachment_phase(
                module_args,
                strategy,
                phase="pre",
                desired=desired_attachments,
                current_network_names=current_desired_network_names,
                current=current_desired_attachments,
                attachment_details=current_attachment_details,
            )
            self._trace("attachment_phase_pre_end", changed=pre_attach.get("changed"), payload_count=len(pre_attach.get("payloads", [])))
            desired_attachments = pre_attach.get("desired", desired_attachments)
            current_attachments = self._current_after_pre_detach(
                pre_attach,
                empty_when_absent=current_desired_network_names == [],
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
            new_desired_network_names = [network_name for network_name in desired_network_names if network_name not in current_network_name_set]
            if state in ("replaced", "overridden") and desired_attachments and new_desired_network_names and not self._check_mode():
                self._trace("attachment_phase_post_new_current_query_start", network_names=new_desired_network_names)
                new_attachment_details = self.coordinator._current_attachment_details(
                    module_args,
                    strategy,
                    new_desired_network_names,
                )
                post_attachment_details.extend(new_attachment_details)
                post_current_attachments.update(self.coordinator._attachment_map_from_details(new_attachment_details, new_desired_network_names))
                self._trace(
                    "attachment_phase_post_new_current_query_end",
                    network_names=new_desired_network_names,
                    attachment_count=len(new_attachment_details or []),
                    current_count=len(post_current_attachments),
                )

            self._trace("attachment_phase_post_start", state=state)
            post_attach = self.coordinator._apply_attachment_phase(
                module_args,
                strategy,
                phase="post",
                desired=desired_attachments,
                current_network_names=desired_network_names,
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
        strategy: BaseNetworkStrategy,
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
            deploy_payloads = self.coordinator._build_pending_network_deploy_payloads(
                result,
                config,
                module_args,
                strategy,
            )
            self._trace("deploy_payloads_from_result", payload_count=len(deploy_payloads), payloads=deploy_payloads)
        if not deploy_payloads and self._should_query_pending_networks(result, config):
            self._trace("deploy_pending_query_start")
            current_networks, query_trace = self.coordinator._query_current_networks_with_trace(module_args, strategy)
            self.coordinator._merge_api_trace(result, query_trace)
            deploy_payloads = self.coordinator._build_pending_network_deploy_payloads(
                {"after": current_networks},
                config,
                module_args,
                strategy,
            )
            self._trace("deploy_pending_query_end", current_count=len(current_networks), payload_count=len(deploy_payloads), payloads=deploy_payloads)
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
            deploy_trace = self.coordinator._deploy_network_attachments(
                module_args,
                strategy,
                deploy_payload,
            )
            self.coordinator._merge_api_trace(result, deploy_trace)
            self._trace("deploy_end", deploy_payload=deploy_payload)
        return result

    def _should_query_pending_networks(self, result: dict[str, Any], config: list[dict]) -> bool:
        """
        Return True when the current result is not enough to prove there is no
        pending deploy work for deploy-enabled Networks.
        """
        deploy_enabled = self.coordinator._deploy_enabled_by_network(config)
        network_names = self.coordinator._configured_network_names(config)
        deploy_enabled_names = {network_name for network_name in network_names if deploy_enabled.get(network_name, True)}
        if not deploy_enabled_names:
            return False

        after = result.get("after") or []
        if not after:
            return True

        after_names = {network.get("network_name") or network.get("networkName") for network in after if isinstance(network, dict)}
        return not deploy_enabled_names.issubset(after_names)

    def _prepare_overridden_deletions(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        omitted_network_names: list[str],
        current_attachment_details: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Detach/deploy omitted Networks before overridden deletes them."""
        if not omitted_network_names:
            return []

        self.coordinator._ensure_networks_have_no_networks(module_args, strategy, omitted_network_names)
        omitted_attachment_details = (
            self.coordinator._filter_attachment_details_by_network(
                current_attachment_details,
                omitted_network_names,
            )
            if current_attachment_details is not None
            else None
        )
        detach_trace = self.coordinator._apply_deleted_attachment_phase(
            module_args,
            strategy,
            omitted_network_names,
            attachment_details=omitted_attachment_details,
        )
        return self._deploy_detach_traces(
            api_args=module_args,
            wait_args=module_args,
            strategy=strategy,
            config=module_args.get("config") or [],
            detach_trace=detach_trace,
            wait_network_names=omitted_network_names,
        )

    def run_deleted(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> dict[str, Any]:
        """
        Detach and deploy current Network attachments before removing the Network.
        """
        config = module_args.get("config") or []

        if not config:
            return self.delete_all_existing_networks(module_args, strategy)

        requested_network_names = self.coordinator._configured_network_names(config)
        current_networks = self.coordinator._query_current_networks(module_args, strategy)
        current_network_names = {network.get("networkName") or network.get("network_name") for network in current_networks}
        target_network_names = [network_name for network_name in requested_network_names if network_name in current_network_names]
        self._trace(
            "delete_existing_networks_resolved",
            configured_count=len(requested_network_names),
            existing_count=len(target_network_names),
            existing_network_names=target_network_names,
        )

        if not target_network_names:
            self._trace("delete_no_existing_networks_skip_detach")
            result = self.coordinator._run_state_machine(module_args, strategy=strategy)
            self._trace("delete_manage_state_end", changed=result.get("changed"), failed=result.get("failed"))
            return result

        self._trace("delete_dependency_check_start", network_count=len(target_network_names))
        self.coordinator._ensure_networks_have_no_networks(
            module_args,
            strategy,
            target_network_names,
        )
        self._trace("delete_dependency_check_end", network_count=len(target_network_names))
        self._trace("delete_detach_phase_start", network_count=len(target_network_names))
        detach_trace = self.coordinator._apply_deleted_attachment_phase(module_args, strategy, target_network_names)
        self._trace("delete_detach_phase_end", changed=detach_trace.get("changed"), payload_count=len(detach_trace.get("payloads", [])))
        traces = self._deploy_detach_traces(
            api_args=module_args,
            wait_args=module_args,
            strategy=strategy,
            config=config,
            detach_trace=detach_trace,
            wait_network_names=target_network_names,
        )

        self._trace("delete_manage_state_start", network_count=len(config))
        result = self.coordinator._run_state_machine(module_args, strategy=strategy)
        self._trace("delete_manage_state_end", changed=result.get("changed"), failed=result.get("failed"))
        self._prepend_traces(result, traces)
        return result

    def delete_all_existing_networks(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> dict[str, Any]:
        """
        Delete all Networks currently present on the target fabric.
        """
        sm, original_config, original_state = self.coordinator._new_state_machine(module_args, strategy)
        try:
            items_to_delete = list(sm.existing)
            target_network_names = [self._network_name_from_model(item) for item in items_to_delete]
            traces: list[dict[str, Any]] = []

            if items_to_delete:
                target_args = dict(module_args)
                target_args["config"] = [{"network_name": network_name} for network_name in target_network_names]

                self._trace("delete_dependency_check_start", network_count=len(target_network_names))
                self.coordinator._ensure_networks_have_no_networks(target_args, strategy, target_network_names)
                self._trace("delete_dependency_check_end", network_count=len(target_network_names))
                self._trace("delete_detach_phase_start", network_count=len(target_network_names))
                detach_trace = self.coordinator._apply_deleted_attachment_phase(target_args, strategy, target_network_names)
                self._trace("delete_detach_phase_end", changed=detach_trace.get("changed"), payload_count=len(detach_trace.get("payloads", [])))
                traces = self._deploy_detach_traces(
                    api_args=target_args,
                    wait_args=module_args,
                    strategy=strategy,
                    config=target_args.get("config") or [],
                    detach_trace=detach_trace,
                    wait_network_names=target_network_names,
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
        strategy: BaseNetworkStrategy,
        config: list[dict],
        detach_trace: dict[str, Any],
        wait_network_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return detach trace plus delete undeploy traces, then wait for readiness."""
        traces = [detach_trace] if detach_trace else []
        target_network_names = wait_network_names
        if target_network_names is None:
            target_network_names = self.coordinator._configured_network_names(config)
        is_mcfg_parent = bool(getattr(strategy, "is_parent", False) and getattr(strategy, "is_multicluster", False))
        delete_deploy_targets: dict[str, set[str]] = {}
        if not is_mcfg_parent:
            delete_deploy_targets = {network_name: set() for network_name in target_network_names if network_name}
        for network_name, switch_ids in (detach_trace.get("deploy_targets", {}) if detach_trace else {}).items():
            delete_deploy_targets.setdefault(network_name, set()).update(switch_ids or set())

        deploy_payloads = self.coordinator._build_delete_deploy_payloads(
            config,
            delete_deploy_targets,
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
                self.coordinator._deploy_network_attachments(
                    api_args,
                    strategy,
                    deploy_payload,
                )
            )
            self._trace("delete_deploy_end", deploy_payload=deploy_payload)

        if target_network_names:
            self._trace("delete_wait_ready_start", network_names=target_network_names)
            self.coordinator._wait_for_network_attachments_delete_ready(wait_args, strategy, target_network_names)
            self.coordinator._wait_for_networks_delete_ready(wait_args, strategy, target_network_names)
            self._trace("delete_wait_ready_end", network_names=target_network_names)
        return traces

    def _prepend_traces(self, result: dict[str, Any], traces: list[dict[str, Any]]) -> None:
        """Merge traces before the state-machine trace in result order."""
        for trace in reversed(traces):
            if trace:
                self.coordinator._merge_api_trace(result, trace, prepend=True)

    @staticmethod
    def _network_name_from_model(item: Any) -> str:
        """Extract the Network name from a state-machine model instance."""
        network_name = getattr(item, "network_name", None)
        if network_name:
            return network_name
        identifier = item.get_identifier_value()
        if isinstance(identifier, tuple):
            return identifier[0]
        return identifier

    def _network_names_from_models(self, items: Any) -> list[str]:
        """Return unique Network names from state-machine model instances."""
        network_names: list[str] = []
        seen: set[str] = set()
        for item in items:
            network_name = self._network_name_from_model(item)
            if network_name and network_name not in seen:
                network_names.append(network_name)
                seen.add(network_name)
        return network_names
