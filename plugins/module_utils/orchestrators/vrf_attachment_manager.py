# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
VRF attachment and deployment planning/execution.
"""

from __future__ import annotations

import time

from typing import Any, Optional, Union

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_attachments import (
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
    VrfAttachmentInstanceValuesModel,
    VrfAttachmentModel,
    VrfAttachmentQueryRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_config_utils import (
    configured_vrf_names,
    deploy_enabled_by_vrf,
    deploy_type_by_vrf,
)


class VrfAttachmentManager:
    """
    Plans and executes VRF attach, detach, and deploy operations.

    The coordinator still owns REST object construction and output formatting;
    this manager keeps attachment semantics out of the topology workflow.
    """

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator

    def apply_phase(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        phase: str,
        desired: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
        current_vrf_names: Optional[list[str]] = None,
        current: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Attach or detach VRFs according to state and phase."""
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []

        if not config and state != "overridden":
            return {}
        if phase == "pre" and state not in ("deleted", "replaced", "overridden"):
            return {}
        if phase == "post" and state not in ("merged", "replaced", "overridden"):
            return {}
        if current_vrf_names == []:
            return {}

        desired = desired if desired is not None else self.coordinator._desired_attachment_map(module_args, strategy)
        if phase == "post" and not desired:
            return {}

        vrf_names = configured_vrf_names(config)
        deploy_enabled = deploy_enabled_by_vrf(config)

        query_all = state == "overridden"
        query_vrf_names = current_vrf_names
        if query_vrf_names is None:
            query_vrf_names = None if query_all else vrf_names
        if current is None:
            current = self.coordinator._current_attachment_map(module_args, strategy, query_vrf_names)

        if phase == "pre":
            payloads = self.coordinator._planned_detach_payloads(state, config, current, desired)
        else:
            payloads = self.coordinator._planned_attach_payloads(current, desired)

        if not payloads:
            return {"current": current} if phase == "pre" else {}

        deploy_targets: dict[str, set[str]] = {}
        for payload in payloads:
            vrf_name = payload.get("vrfName")
            if deploy_enabled.get(vrf_name, True):
                self.coordinator._record_deploy_target(deploy_targets, vrf_name, payload.get("switchId"))

        trace = self.coordinator._post_vrf_attachments(
            module_args,
            strategy,
            payloads,
            deploy_targets,
            OperationType.DELETE if phase == "pre" else OperationType.CREATE,
        )
        trace["current"] = current
        trace["payloads"] = payloads
        return trace

    def attachment_map_after_detach(
        self,
        current: dict[tuple[str, str], dict[str, Any]],
        payloads: list[dict[str, Any]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Return the cached attachment map after applying detach payloads."""
        if not payloads:
            return current

        remaining = dict(current)
        for payload in payloads:
            if payload.get("attach") is False:
                remaining.pop((payload.get("vrfName"), payload.get("switchId")), None)
        return remaining

    def apply_deleted_phase(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]] = None,
        attachment_details: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Detach all current attachments for deleted VRFs, independent of config."""
        vrf_names = vrf_names if vrf_names is not None else configured_vrf_names(module_args.get("config") or [])
        attachments = attachment_details
        if attachments is None:
            attachments = self.coordinator._current_attachment_details_ignore_missing(module_args, strategy, vrf_names or None)

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
                self.coordinator._record_deploy_target(deploy_targets, vrf_name, switch_id)
            elif self.coordinator._attachment_has_pending_delete_work(attachment):
                self.coordinator._record_deploy_target(deploy_targets, vrf_name, switch_id)

            if attachment.get("attach") is True and key not in seen_payloads:
                payloads.append({"vrfName": vrf_name, "switchId": switch_id, "attach": False})
                seen_payloads.add(key)

        if not payloads:
            return {"deploy_targets": deploy_targets}

        return self.coordinator._post_vrf_attachments(
            module_args,
            strategy,
            payloads,
            deploy_targets,
            OperationType.DELETE,
        )

    @staticmethod
    def filter_attachment_details_by_vrf(
        attachments: list[dict[str, Any]],
        vrf_names: Union[list[str], set[str]],
    ) -> list[dict[str, Any]]:
        """Return attachment rows for the requested VRF names."""
        vrf_name_set = set(vrf_names)
        if not vrf_name_set:
            return []
        return [attachment for attachment in attachments if attachment.get("vrfName") in vrf_name_set]

    @staticmethod
    def attachment_has_pending_delete_work(attachment: dict[str, Any]) -> bool:
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

    def desired_attachment_map(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Build desired attachment payloads keyed by (vrfName, switchId)."""
        config = module_args.get("config") or []
        ip_to_switch = self.coordinator._resolve_switch_ids(module_args, strategy, config)
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
                instance_values = self.coordinator._attachment_instance_values(attachment)
                if instance_values:
                    payload["instanceValues"] = instance_values
                freeform_config = attachment.get("freeform_config")
                if freeform_config is not None:
                    payload["extraConfig"] = freeform_config
                desired[(vrf_name, switch_id)] = payload

        return desired

    def resolve_switch_ids(
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

        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageSwitchesListGet)
        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            operation_type=OperationType.QUERY,
        )
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
            for ip_address in self.coordinator._switch_ip_candidates(switch):
                if ip_address in wanted_ips:
                    resolved[ip_address] = switch_id

        missing = sorted(wanted_ips.difference(resolved))
        if missing:
            self.coordinator.module.fail_json(msg=("Unable to resolve attach.ip_address values to switchId " f"on fabric '{strategy.fabric_name}': {missing}"))
        return resolved

    @staticmethod
    def switch_ip_candidates(switch: dict[str, Any]) -> set[str]:
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

    @staticmethod
    def attachment_instance_values(attachment: dict[str, Any]) -> dict[str, Any]:
        """Map playbook attach fields to ND instanceValues."""
        attachment_options = attachment.get("attachment_options") or {}
        raw = {
            "dpu_secure": attachment_options.get("dpu_secure"),
            "dpu_affinity": attachment_options.get("dpu_affinity"),
            "loopback_id": attachment_options.get("loopback_id"),
            "loopback_ipv4_address": attachment_options.get("loopback_ipv4_address"),
            "loopback_ipv6_address": attachment_options.get("loopback_ipv6_address"),
            "route_target_import": attachment_options.get("import_vpn_rt"),
            "route_target_export": attachment_options.get("export_vpn_rt"),
            "evpn_route_target_import": attachment_options.get("import_evpn_rt"),
            "evpn_route_target_export": attachment_options.get("export_evpn_rt"),
        }
        raw = {key: value for key, value in raw.items() if value is not None}
        if not raw:
            return {}
        return VrfAttachmentInstanceValuesModel(**raw).to_payload()

    def current_attachment_map(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]],
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Gather ND attachments and key attached rows by (vrfName, switchId)."""
        return self.coordinator._attachment_map_from_details(self.coordinator._current_attachment_details(module_args, strategy, vrf_names))

    @staticmethod
    def attachment_map_from_details(
        attachments: list[dict[str, Any]],
        vrf_names: Optional[Union[list[str], set[str]]] = None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Key attached VRF attachment rows by (vrfName, switchId)."""
        vrf_name_set = set(vrf_names) if vrf_names is not None else None
        current: dict[tuple[str, str], dict[str, Any]] = {}
        for attachment in attachments:
            if attachment.get("attach") is not True:
                continue
            vrf_name = attachment.get("vrfName")
            switch_id = attachment.get("switchId")
            if vrf_name_set is not None and vrf_name not in vrf_name_set:
                continue
            if vrf_name and switch_id:
                current[(vrf_name, switch_id)] = attachment
        return current

    def current_attachment_details(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]],
    ) -> list[dict[str, Any]]:
        """Gather all attachment details, including pending detach entries."""
        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
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

    def current_attachment_details_ignore_missing(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]],
    ) -> list[dict[str, Any]]:
        """Gather attachment details while treating absent deleted VRFs as empty."""
        try:
            return self.coordinator._current_attachment_details(module_args, strategy, vrf_names)
        except Exception as exc:
            if not self.coordinator._is_vrf_not_found_error(exc):
                raise

        if not vrf_names or len(vrf_names) <= 1:
            return []

        attachments: list[dict[str, Any]] = []
        for vrf_name in vrf_names:
            try:
                attachments.extend(self.coordinator._current_attachment_details(module_args, strategy, [vrf_name]))
            except Exception as exc:
                if not self.coordinator._is_vrf_not_found_error(exc):
                    raise
        return attachments

    @staticmethod
    def is_vrf_not_found_error(error: Exception) -> bool:
        """Return True for ND's attachment-query error when a VRF is absent."""
        message = str(error)
        return "VRF(s)" in message and "not found in fabric" in message

    def planned_detach_payloads(
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
            vrf_names = set(configured_vrf_names(config))
            detach_keys = {key for key in current.keys() if key[0] in vrf_names and key not in desired}

        return [{"vrfName": vrf_name, "switchId": switch_id, "attach": False} for vrf_name, switch_id in sorted(detach_keys)]

    def planned_attach_payloads(
        self,
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Compute attach payloads for missing or changed desired attachments."""
        payloads: list[dict[str, Any]] = []
        for key, desired_payload in sorted(desired.items()):
            existing = current.get(key)
            if existing is None or not self.coordinator._attachment_matches(existing, desired_payload):
                payloads.append(desired_payload)
        return payloads

    @staticmethod
    def attachment_matches(
        existing: dict[str, Any],
        desired: dict[str, Any],
    ) -> bool:
        """Return True when existing attachment satisfies desired fields."""
        if existing.get("attach") is not True:
            return False
        if existing.get("extraConfig") != desired.get("extraConfig"):
            return False
        desired_instance = desired.get("instanceValues") or {}
        if not desired_instance:
            return True
        existing_instance = existing.get("instanceValues") or {}
        for key, value in desired_instance.items():
            if existing_instance.get(key) != value:
                return False
        return True

    def post_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        payloads: list[dict[str, Any]],
        deploy_targets: dict[str, set[str]],
        operation_type: OperationType,
    ) -> dict[str, Any]:
        """Send attach/detach payload and return mergeable API trace."""
        if getattr(getattr(self.coordinator, "module", None), "check_mode", False):
            return {
                "changed": True,
                "failed": False,
                "deploy_targets": deploy_targets,
                "payloads": payloads,
                "check_mode_attachment_payloads": payloads,
            }
        request = VrfAttachDetachRequestModel(attachments=[VrfAttachmentModel(**payload) for payload in payloads])
        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsVrfAttachmentsPost)
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=request.to_payload(),
            operation_type=operation_type,
        )
        return self.coordinator._finalize_api_trace(results, deploy_targets)

    @staticmethod
    def record_deploy_target(
        deploy_targets: dict[str, set[str]],
        vrf_name: Optional[str],
        switch_id: Optional[str],
    ) -> None:
        """Record one VRF/switch pair for a later VRF deployment request."""
        if not vrf_name or not switch_id:
            return
        deploy_targets.setdefault(vrf_name, set()).add(switch_id)

    def build_deploy_payloads(
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

        deploy_type = deploy_type_by_vrf(config)
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
            payloads.append(VrfDeployRequestModel(vrf_names=sorted(vrf_names), switch_ids=list(switch_ids)).to_payload())

        if vrf_level_names:
            payloads.append(VrfDeployRequestModel(vrf_names=sorted(vrf_level_names)).to_payload())

        return payloads

    def build_pending_vrf_deploy_payloads(
        self,
        result: dict[str, Any],
        config: list[dict],
        module_args: dict,
        strategy: BaseVrfStrategy,
    ) -> list[dict[str, Any]]:
        """Build a deploy request for configured VRFs already pending in ND."""
        deploy_enabled = deploy_enabled_by_vrf(config)
        deploy_type = deploy_type_by_vrf(config)
        configured_vrfs = set(configured_vrf_names(config))
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
        switch_level_names = {vrf_name for vrf_name in pending_vrfs if deploy_type.get(vrf_name, "switch") == "switch"}
        vrf_level_names.update(pending_vrfs.difference(switch_level_names))

        deploy_target_map: dict[str, set[str]] = {}
        if switch_level_names:
            attachment_details = self.coordinator._current_attachment_details(module_args, strategy, sorted(switch_level_names))
            switch_ids_by_vrf: dict[str, set[str]] = {vrf_name: set() for vrf_name in switch_level_names}
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

        return self.coordinator._build_deploy_payloads(config, deploy_target_map)

    def wait_for_vrfs_delete_ready(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: Optional[list[str]] = None,
    ) -> None:
        """Wait until configured VRFs are absent or in notApplicable state."""
        pending_vrf_names = set(vrf_names if vrf_names is not None else configured_vrf_names(module_args.get("config") or []))
        if not pending_vrf_names:
            return

        timeout = int(module_args.get("timeout") or self.coordinator.module.params.get("timeout") or 30)
        deadline = time.time() + timeout
        ready_statuses = {"notApplicable", "NA", "na", ""}
        last_statuses: dict[str, str] = {}

        while pending_vrf_names:
            vrfs = self.coordinator._query_current_vrfs(module_args, strategy)
            last_statuses = {}
            for vrf in vrfs:
                name = vrf.get("vrf_name") or vrf.get("vrfName")
                if name in pending_vrf_names:
                    status = vrf.get("vrf_status") or vrf.get("vrfStatus") or ""
                    last_statuses[name] = str(status)

            ready_vrf_names = {name for name in pending_vrf_names if name not in last_statuses or last_statuses[name] in ready_statuses}
            pending_vrf_names.difference_update(ready_vrf_names)
            if not pending_vrf_names:
                return

            if time.time() >= deadline:
                self.coordinator.module.fail_json(
                    msg=("Timed out waiting for VRFs to become deletable after " f"detach deployment on fabric '{strategy.fabric_name}': " f"{last_statuses}")
                )
            time.sleep(5)

    def deploy_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        deploy_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deploy pending VRF attachment changes once."""
        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(strategy.vrf_actions_deploy_post_cls())
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=deploy_payload,
            operation_type=OperationType.UPDATE,
        )
        return self.coordinator._finalize_api_trace(results)
