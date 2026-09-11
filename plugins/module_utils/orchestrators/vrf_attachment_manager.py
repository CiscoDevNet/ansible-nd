# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
VRF attachment and deployment planning/execution.
"""

from __future__ import annotations

import time

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_attachments import (
    EpManageFabricsVrfAttachmentsPost,
    EpManageFabricsVrfAttachmentsQueryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_vrfs import (
    EpOneManageFabricsVrfAttachmentsPost,
    EpOneManageFabricsVrfAttachmentsQueryPost,
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.attachment_vpc_peer_expander import (
    expand_desired_attachments_with_vpc_peers,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.delete_readiness import (
    DeleteReadinessPolicy,
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

    clear_vlan_id_intent_key = "_clearVlanId"
    delete_wait_delay = 15
    delete_wait_chunk_size = 30
    delete_wait_base_timeout = 600
    delete_wait_extra_chunk_timeout = 30
    delete_wait_max_timeout = 900
    undeploy_retry_attempts = 3
    attachment_query_page_size = 10000

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator

    def _trace(self, event: str, **details: Any) -> None:
        trace = getattr(self.coordinator, "_trace", None)
        if trace is not None:
            try:
                trace(event, **details)
            except AttributeError:
                pass

    @staticmethod
    def _attachments_query_endpoint_cls(strategy: BaseVrfStrategy) -> type:
        if strategy.is_multicluster and strategy.is_parent:
            return EpOneManageFabricsVrfAttachmentsQueryPost
        return EpManageFabricsVrfAttachmentsQueryPost

    @staticmethod
    def _attachments_post_endpoint_cls(strategy: BaseVrfStrategy) -> type:
        if strategy.is_multicluster and strategy.is_parent:
            return EpOneManageFabricsVrfAttachmentsPost
        return EpManageFabricsVrfAttachmentsPost

    def apply_phase(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        phase: str,
        desired: dict[tuple[str, str], dict[str, Any]] | None = None,
        current_vrf_names: list[str] | None = None,
        current: dict[tuple[str, str], dict[str, Any]] | None = None,
        attachment_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Attach or detach VRFs according to state and phase."""
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []
        self._trace("vrf_attachment_phase_start", phase=phase, state=state, config_count=len(config), current_vrf_names=current_vrf_names)

        if not config and state != "overridden":
            self._trace("vrf_attachment_phase_skip", phase=phase, reason="empty_config")
            return {}
        if phase == "pre" and state not in ("deleted", "replaced", "overridden"):
            self._trace("vrf_attachment_phase_skip", phase=phase, reason="state_not_pre_detach")
            return {}
        if phase == "post" and state not in ("merged", "replaced", "overridden"):
            self._trace("vrf_attachment_phase_skip", phase=phase, reason="state_not_post_attach")
            return {}
        if current_vrf_names == []:
            self._trace("vrf_attachment_phase_skip", phase=phase, reason="no_current_vrfs")
            return {}

        desired = desired if desired is not None else self.coordinator._desired_attachment_map(module_args, strategy)
        if phase == "post" and not desired:
            self._trace("vrf_attachment_phase_skip", phase=phase, reason="no_desired_attachments")
            return {}

        vrf_names = configured_vrf_names(config)
        deploy_enabled = deploy_enabled_by_vrf(config)

        query_all = state == "overridden"
        query_vrf_names = current_vrf_names
        if query_vrf_names is None:
            query_vrf_names = None if query_all else vrf_names
        raw_attachment_details = attachment_details
        if current is None:
            if raw_attachment_details is None:
                raw_attachment_details = self.coordinator._current_attachment_details(module_args, strategy, query_vrf_names)
            current = self.coordinator._attachment_map_from_details(raw_attachment_details)
            self._trace(
                "vrf_attachment_current_loaded",
                phase=phase,
                queried_vrf_names=query_vrf_names,
                attachment_count=len(raw_attachment_details or []),
                current_count=len(current),
            )

        if desired:
            desired = self.coordinator._expand_desired_attachments_with_vpc_peers(
                desired, raw_attachment_details if raw_attachment_details is not None else current.values()
            )
            self._trace("vrf_attachment_desired_expanded", phase=phase, desired_count=len(desired))

        if phase == "pre":
            payloads = self.coordinator._planned_detach_payloads(state, config, current, desired)
        else:
            payloads = self.coordinator._planned_attach_payloads(current, desired)

        if not payloads:
            self._trace("vrf_attachment_phase_noop", phase=phase, desired_count=len(desired or {}), current_count=len(current or {}))
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
        self._trace("vrf_attachment_phase_end", phase=phase, payload_count=len(payloads), deploy_target_count=len(deploy_targets))
        trace["current"] = current
        trace["payloads"] = payloads
        trace["desired"] = desired
        trace["attachment_details"] = raw_attachment_details
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
        vrf_names: list[str] | None = None,
        attachment_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Detach all current attachments for deleted VRFs, independent of config."""
        vrf_names = vrf_names if vrf_names is not None else configured_vrf_names(module_args.get("config") or [])
        self._trace("vrf_deleted_attachment_phase_start", vrf_names=vrf_names)
        attachments = attachment_details
        if attachments is None:
            attachments = self.coordinator._current_attachment_details_ignore_missing(module_args, strategy, vrf_names or None)
        self._trace("vrf_deleted_attachment_current_loaded", vrf_names=vrf_names, attachment_count=len(attachments or []))

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
            self._trace("vrf_deleted_attachment_phase_noop", deploy_target_count=len(deploy_targets))
            return {"deploy_targets": deploy_targets}

        self._trace("vrf_deleted_attachment_phase_post", payload_count=len(payloads), deploy_target_count=len(deploy_targets))
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
        vrf_names: list[str] | set[str],
    ) -> list[dict[str, Any]]:
        """Return attachment rows for the requested VRF names."""
        vrf_name_set = set(vrf_names)
        if not vrf_name_set:
            return []
        return [attachment for attachment in attachments if attachment.get("vrfName") in vrf_name_set]

    @staticmethod
    def attachment_has_pending_delete_work(attachment: dict[str, Any]) -> bool:
        """Return True for an already-detached row that still needs deploy."""
        pending_statuses = {"deploymentinprogress", "failed", "inprogress", "outofsync", "pending", "previewinprogress"}
        for key in (
            "status",
            "configStatus",
            "deploymentStatus",
            "vrfStatus",
            "attachmentStatus",
        ):
            status = attachment.get(key)
            if status is not None and VrfAttachmentManager._status_value(status).lower() in pending_statuses:
                return True
        return False

    @staticmethod
    def attachment_status(attachment: dict[str, Any]) -> str:
        """Return the first attachment status value exposed by the controller."""
        for key in ("status", "configStatus", "deploymentStatus", "vrfStatus", "attachmentStatus"):
            status = attachment.get(key)
            if status is not None:
                return VrfAttachmentManager._status_value(status)
        return ""

    @staticmethod
    def _status_value(status: Any) -> str:
        """Return the plain API status string from raw strings or enum values."""
        return str(getattr(status, "value", status) or "").strip()

    @staticmethod
    def attachment_blocks_delete(attachment: dict[str, Any]) -> bool:
        """Return True when an attachment row still prevents VRF deletion."""
        attach = attachment.get("attach")
        if attach is True or str(attach).strip().lower() == "true":
            return True
        status = VrfAttachmentManager.attachment_status(attachment).lower()
        if not status:
            return False
        terminal_statuses = {"na", "notapplicable", "notdeployed", "deleted", "outofsync", "failed"}
        return status not in terminal_statuses

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
                ip_address = attachment.get("ip_address")
                switch_id = ip_to_switch.get(ip_address)
                if not vrf_name or not switch_id:
                    continue

                payload = {
                    "vrfName": vrf_name,
                    "switchId": switch_id,
                    "attach": True,
                }
                if vrf.get("l3vni_wo_vlan") or vrf.get("l3VniWithoutVlan") or vrf.get("l3_vni_without_vlan"):
                    payload[self.clear_vlan_id_intent_key] = True
                else:
                    vlan_id = vrf.get("vlan_id") or vrf.get("vlanId")
                    if vlan_id is not None:
                        payload["vlanId"] = vlan_id
                instance_values = self.coordinator._attachment_instance_values(attachment)
                if attachment.get("attachment_options") is not None:
                    payload["instanceValues"] = instance_values
                freeform_config = attachment.get("freeform_config")
                if freeform_config is not None:
                    payload["extraConfig"] = freeform_config
                desired[(vrf_name, switch_id)] = payload

        return desired

    @staticmethod
    def expand_desired_attachments_with_vpc_peers(
        desired: dict[tuple[str, str], dict[str, Any]],
        attachment_details: Any,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Add vPC peer attachments from existing attachment-query rows."""
        return expand_desired_attachments_with_vpc_peers(desired, attachment_details, "vrfName")

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
                ip_address = attachment.get("ip_address")
                if ip_address:
                    wanted_ips.add(ip_address)

        if not wanted_ips:
            self._trace("vrf_attachment_switch_resolve_end", requested_count=0, resolved_count=0)
            return {}

        self._trace("vrf_attachment_switch_resolve_start", requested_count=len(wanted_ips), fabric_name=strategy.fabric_name)
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
            self._trace("vrf_attachment_switch_resolve_failed", requested_count=len(wanted_ips), resolved_count=len(resolved), missing=missing)
            self.coordinator.module.fail_json(msg=("Unable to resolve attach.ip_address values to switchId " f"on fabric '{strategy.fabric_name}': {missing}"))
        self._trace("vrf_attachment_switch_resolve_end", requested_count=len(wanted_ips), resolved_count=len(resolved))
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
        vrf_names: list[str] | None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Gather ND attachments and key attached rows by (vrfName, switchId)."""
        return self.coordinator._attachment_map_from_details(self.coordinator._current_attachment_details(module_args, strategy, vrf_names))

    @staticmethod
    def attachment_map_from_details(
        attachments: list[dict[str, Any]],
        vrf_names: list[str] | set[str] | None = None,
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
        vrf_names: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Gather all attachment details, including pending detach entries."""
        attachments: list[dict[str, Any]] = []
        offset = 0

        while True:
            data = self._current_attachment_details_page(module_args, strategy, vrf_names, offset)
            page_items = self._attachment_items_from_query_result(data)
            attachments.extend(page_items)
            if not self._has_more_attachment_pages(data, len(page_items), len(attachments)):
                break
            if not page_items:
                break
            offset += len(page_items)

        return attachments

    def _current_attachment_details_page(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None,
        offset: int,
    ) -> Any:
        """Query one page of attachment details."""
        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(self._attachments_query_endpoint_cls(strategy))
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.include_all = True
            endpoint.endpoint_params.max = self.attachment_query_page_size
            endpoint.endpoint_params.offset = offset

        query = VrfAttachmentQueryRequestModel(vrf_names=vrf_names or None)
        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=query.to_payload(),
            operation_type=OperationType.QUERY,
        )
        results.build_final_result()
        return data

    @staticmethod
    def _attachment_items_from_query_result(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, dict):
            return data.get("attachments") or data.get("items") or []
        if isinstance(data, list):
            return data
        return []

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _has_more_attachment_pages(self, data: Any, page_count: int, total_seen: int) -> bool:
        if not isinstance(data, dict):
            return False

        metadata = data.get("metadata") or data.get("meta") or {}
        counts = metadata.get("counts") or {}
        remaining = self._safe_int(counts.get("remaining"))
        if remaining is not None:
            return remaining > 0

        total = self._safe_int(counts.get("total"))
        if total is not None:
            return total_seen < total

        links = metadata.get("links") or {}
        if links.get("next"):
            return True

        return page_count == self.attachment_query_page_size

    def current_attachment_details_ignore_missing(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Gather attachment details while treating absent deleted VRFs as empty."""
        if vrf_names and len(vrf_names) > self.delete_wait_chunk_size:
            attachments: list[dict[str, Any]] = []
            for index in range(0, len(vrf_names), self.delete_wait_chunk_size):
                chunk = vrf_names[index : index + self.delete_wait_chunk_size]
                attachments.extend(self.current_attachment_details_ignore_missing(module_args, strategy, chunk))
            return attachments
        try:
            return self.coordinator._current_attachment_details(module_args, strategy, vrf_names)
        except Exception as exc:
            if not self.coordinator._is_vrf_not_found_error(exc):
                raise

        if not vrf_names or len(vrf_names) <= 1:
            return []

        all_attachments = self.coordinator._current_attachment_details(module_args, strategy, None)
        return self.filter_attachment_details_by_vrf(all_attachments, vrf_names)

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
        if desired.get(VrfAttachmentManager.clear_vlan_id_intent_key):
            if existing.get("vlanId") is not None:
                return False
        elif "vlanId" in desired and existing.get("vlanId") != desired.get("vlanId"):
            return False
        if "extraConfig" in desired:
            existing_extra_config = existing.get("extraConfig") or ""
            desired_extra_config = desired.get("extraConfig") or ""
            if existing_extra_config != desired_extra_config:
                return False
        if "instanceValues" in desired:
            desired_instance = desired.get("instanceValues") or {}
            existing_instance = existing.get("instanceValues") or {}
            if not desired_instance:
                return not existing_instance
            for key, value in desired_instance.items():
                if existing_instance.get(key) != value:
                    return False
        return True

    def api_attachment_payloads(self, payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Strip internal attachment intent markers before API submission."""
        return [{key: value for key, value in payload.items() if key != self.clear_vlan_id_intent_key} for payload in payloads]

    def post_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        payloads: list[dict[str, Any]],
        deploy_targets: dict[str, set[str]],
        operation_type: OperationType,
    ) -> dict[str, Any]:
        """Send attach/detach payload and return mergeable API trace."""
        self._trace(
            "vrf_attachment_post_start",
            operation_type=operation_type.value,
            payload_count=len(payloads),
            deploy_target_count=len(deploy_targets),
        )
        api_payloads = self.api_attachment_payloads(payloads)
        if getattr(getattr(self.coordinator, "module", None), "check_mode", False):
            self._trace("vrf_attachment_post_check_mode", payload_count=len(payloads), deploy_target_count=len(deploy_targets))
            return {
                "changed": True,
                "failed": False,
                "deploy_targets": deploy_targets,
                "payloads": api_payloads,
                "check_mode_attachment_payloads": api_payloads,
            }
        request = VrfAttachDetachRequestModel(attachments=[VrfAttachmentModel(**payload) for payload in api_payloads])
        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(self._attachments_post_endpoint_cls(strategy))
        response = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=request.to_payload(),
            operation_type=operation_type,
        )
        self._raise_on_attachment_failures(response)
        trace = self.coordinator._finalize_api_trace(results, deploy_targets)
        self._trace("vrf_attachment_post_end", operation_type=operation_type.value, changed=trace.get("changed"), failed=trace.get("failed"))
        return trace

    def _raise_on_attachment_failures(self, response: Any) -> None:
        """Fail immediately when a 207 attachment response contains failed rows."""
        if not isinstance(response, dict):
            return
        results = response.get("results")
        if not isinstance(results, list):
            return

        failures: list[str] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "").lower()
            if status not in {"failed", "failure", "error"}:
                continue
            vrf_name = item.get("vrfName") or "unknown-vrf"
            switch_id = item.get("switchId") or item.get("switchName") or "unknown-switch"
            message = item.get("message") or "attachment operation failed"
            failures.append(f"{vrf_name}/{switch_id}: {message}")

        if failures:
            self.coordinator.module.fail_json(msg="VRF attachment failed: " + "; ".join(failures))

    @staticmethod
    def record_deploy_target(
        deploy_targets: dict[str, set[str]],
        vrf_name: str | None,
        switch_id: str | None,
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
        deploy_target_map: dict[str, set[str]] = {}
        after_vrfs: set[str] = set()

        for vrf in result.get("after") or []:
            vrf_name = vrf.get("vrf_name") or vrf.get("vrfName")
            vrf_status = vrf.get("vrf_status") or vrf.get("vrfStatus")
            if not vrf_name or vrf_name not in configured_vrfs:
                continue
            after_vrfs.add(vrf_name)
            if not deploy_enabled.get(vrf_name, True):
                continue
            if str(vrf_status or "").strip() in pending_statuses:
                pending_vrfs.add(vrf_name)

        vrf_level_names: set[str] = set()
        switch_level_names = {vrf_name for vrf_name in pending_vrfs if deploy_type.get(vrf_name, "switch") == "switch"}
        vrf_level_names.update(pending_vrfs.difference(switch_level_names))

        deploy_enabled_names = {vrf_name for vrf_name in after_vrfs if deploy_enabled.get(vrf_name, True)}
        attachment_query_names = sorted((deploy_enabled_names.difference(vrf_level_names)).union(switch_level_names))
        attachment_details = self.coordinator._current_attachment_details(module_args, strategy, attachment_query_names) if attachment_query_names else []

        if switch_level_names:
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

        for attachment in attachment_details:
            vrf_name = attachment.get("vrfName")
            switch_id = attachment.get("switchId")
            if vrf_name not in configured_vrfs or not deploy_enabled.get(vrf_name, True):
                continue
            if attachment.get("attach") is True and self.attachment_has_pending_delete_work(attachment):
                if deploy_type.get(vrf_name, "switch") == "vrf" or not switch_id:
                    deploy_target_map.setdefault(vrf_name, set())
                else:
                    deploy_target_map.setdefault(vrf_name, set()).add(switch_id)
            elif attachment.get("attach") is False and self.attachment_has_pending_delete_work(attachment):
                if deploy_type.get(vrf_name, "switch") == "vrf" or not switch_id:
                    deploy_target_map.setdefault(vrf_name, set())
                else:
                    deploy_target_map.setdefault(vrf_name, set()).add(switch_id)

        for vrf_name in vrf_level_names:
            deploy_target_map.setdefault(vrf_name, set())

        if not deploy_target_map:
            return []
        return self.coordinator._build_deploy_payloads(config, deploy_target_map)

    def wait_for_vrfs_delete_ready(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        vrf_names: list[str] | None = None,
    ) -> None:
        """Wait until VRF attachments and VRF definitions no longer block deletion."""
        pending_vrf_names = set(vrf_names if vrf_names is not None else configured_vrf_names(module_args.get("config") or []))
        if not pending_vrf_names:
            return

        deadline, timeout = self._delete_wait_deadline(len(pending_vrf_names))
        started_at = DeleteReadinessPolicy.now()
        ready_statuses = {"", "na", "notapplicable", "notdeployed", "deleted", "outofsync", "failed"}
        retry_statuses = {"pending", "inprogress", "deploymentinprogress", "previewinprogress"}
        last_statuses: dict[str, str] = {}
        last_blockers: dict[str, list[dict[str, Any]]] = {}
        retried_targets: dict[tuple[str, str, str], int] = {}
        retried_vrfs: dict[str, int] = {}

        while pending_vrf_names:
            attachments = self.current_attachment_details_ignore_missing(module_args, strategy, sorted(pending_vrf_names))
            blockers: dict[str, list[dict[str, Any]]] = {name: [] for name in pending_vrf_names}
            attachment_retry_targets: dict[str, set[str]] = {}
            for attachment in attachments:
                vrf_name = attachment.get("vrfName")
                if vrf_name not in pending_vrf_names:
                    continue
                if self.attachment_blocks_delete(attachment):
                    switch_id = attachment.get("switchId")
                    status = self.attachment_status(attachment)
                    blockers.setdefault(vrf_name, []).append(
                        {
                            "switchId": switch_id,
                            "attach": attachment.get("attach"),
                            "status": status,
                        }
                    )
                    retry_key = (vrf_name, switch_id or "", status.lower())
                    if retried_targets.get(retry_key, 0) < self.undeploy_retry_attempts:
                        attachment_retry_targets.setdefault(vrf_name, set())
                        if switch_id:
                            attachment_retry_targets[vrf_name].add(switch_id)
                        retried_targets[retry_key] = retried_targets.get(retry_key, 0) + 1

            vrfs = self.coordinator._query_current_vrfs_by_names(module_args, strategy, sorted(pending_vrf_names))
            last_statuses = {}
            for vrf in vrfs:
                name = vrf.get("vrf_name") or vrf.get("vrfName")
                if name in pending_vrf_names:
                    status = vrf.get("vrf_status") or vrf.get("vrfStatus") or ""
                    last_statuses[name] = str(status)

            vrf_retry_targets = {
                name: set()
                for name, status in last_statuses.items()
                if (name in pending_vrf_names and retried_vrfs.get(name, 0) < self.undeploy_retry_attempts and str(status).strip().lower() in retry_statuses)
            }
            retry_targets = self._merge_deploy_target_maps(attachment_retry_targets, vrf_retry_targets)
            if retry_targets:
                for deploy_payload in self.build_deploy_payloads(module_args.get("config") or [], retry_targets):
                    self.deploy_vrf_attachments(module_args, strategy, deploy_payload)
                for vrf_name in vrf_retry_targets:
                    retried_vrfs[vrf_name] = retried_vrfs.get(vrf_name, 0) + 1

            ready_vrf_names = {
                name
                for name in pending_vrf_names
                if not blockers.get(name) and (name not in last_statuses or str(last_statuses[name]).strip().lower() in ready_statuses)
            }
            pending_vrf_names.difference_update(ready_vrf_names)
            if not pending_vrf_names:
                return
            last_blockers = {name: values for name, values in blockers.items() if name in pending_vrf_names and values}

            if DeleteReadinessPolicy.now() >= deadline:
                self.coordinator.module.fail_json(
                    msg=("Timed out waiting for VRFs to become deletable after " f"detach deployment on fabric '{strategy.fabric_name}'."),
                    pending_vrf_names=sorted(pending_vrf_names),
                    last_statuses=last_statuses,
                    last_attachment_blockers=last_blockers,
                    elapsed_seconds=int(DeleteReadinessPolicy.now() - started_at),
                    timeout_seconds=timeout,
                )
            time.sleep(self.delete_wait_delay)

    @staticmethod
    def _merge_deploy_target_maps(*target_maps: dict[str, set[str]]) -> dict[str, set[str]]:
        merged: dict[str, set[str]] = {}
        for target_map in target_maps:
            for vrf_name, switch_ids in target_map.items():
                merged.setdefault(vrf_name, set()).update(switch_ids)
        return merged

    def _delete_wait_timeout(self, item_count: int) -> int:
        return self._delete_wait_policy().timeout_for(item_count)

    def _delete_wait_deadline(self, item_count: int) -> tuple[float, int]:
        return self._delete_wait_policy().deadline_for(item_count)

    def _delete_wait_policy(self) -> DeleteReadinessPolicy:
        return DeleteReadinessPolicy(
            poll_interval=self.delete_wait_delay,
            chunk_size=self.delete_wait_chunk_size,
            base_timeout=self.delete_wait_base_timeout,
            extra_chunk_timeout=self.delete_wait_extra_chunk_timeout,
            max_timeout=self.delete_wait_max_timeout,
        )

    def deploy_vrf_attachments(
        self,
        module_args: dict,
        strategy: BaseVrfStrategy,
        deploy_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deploy pending VRF attachment changes once."""
        self._trace("vrf_attachment_deploy_start", deploy_payload=deploy_payload)
        orchestrator, results = self.coordinator._new_vrf_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(strategy.vrf_actions_deploy_post_cls())
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=deploy_payload,
            operation_type=OperationType.UPDATE,
        )
        trace = self.coordinator._finalize_api_trace(results)
        self._trace("vrf_attachment_deploy_end", changed=trace.get("changed"), failed=trace.get("failed"))
        return trace
