# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network attachment and deployment planning/execution."""

from __future__ import annotations

import time

from typing import Any, Optional, Union

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_actions import (
    EpManageFabricsNetworkActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_attachments import (
    EpManageFabricsNetworkAttachmentsPost,
    EpManageFabricsNetworkAttachmentsQueryPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import (
    EpManageSwitchesListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    MappingType,
    NetworkAttachmentMode,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_actions_models import (
    NetworkSwitchesListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_attachment_models import (
    NetworkAttachmentModel,
    NetworkAttachDetachPayloadModel,
    NetworkAttachmentQueryRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_config_utils import (
    configured_network_names,
    deploy_enabled_by_network,
    deploy_type_by_network,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)


class NetworkAttachmentManager:
    """Plans and executes network attach, detach, and deploy operations."""

    wait_attempts = 20
    wait_delay = 15

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator

    def apply_phase(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        phase: str,
        desired: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
        current_network_names: Optional[list[str]] = None,
        current: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []
        if not config and state != "overridden":
            return {}
        if phase == "pre" and state not in ("deleted", "replaced", "overridden"):
            return {}
        if phase == "post" and state not in ("merged", "replaced", "overridden"):
            return {}
        if current_network_names == []:
            return {}

        desired = desired if desired is not None else self.desired_attachment_map(module_args, strategy)
        if phase == "post" and not desired:
            return {}

        query_names = current_network_names
        if query_names is None:
            query_names = None if state == "overridden" else configured_network_names(config)
        if current is None:
            current = self.current_attachment_map(module_args, strategy, query_names)

        payloads = (
            self.planned_detach_payloads(state, config, current, desired)
            if phase == "pre"
            else self.planned_attach_payloads(current, desired)
        )
        if not payloads:
            return {"current": current} if phase == "pre" else {}

        deploy_enabled = deploy_enabled_by_network(config)
        deploy_targets: dict[str, set[str]] = {}
        for payload in payloads:
            network_name = payload.get("networkName")
            if deploy_enabled.get(network_name, True):
                self.record_deploy_target(deploy_targets, network_name, payload.get("switchId"))

        trace = self.post_network_attachments(module_args, strategy, payloads, deploy_targets, OperationType.DELETE if phase == "pre" else OperationType.CREATE)
        trace["current"] = current
        trace["payloads"] = payloads
        return trace

    def apply_deleted_phase(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: Optional[list[str]] = None,
        attachment_details: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        network_names = network_names if network_names is not None else configured_network_names(module_args.get("config") or [])
        attachments = attachment_details
        if attachments is None:
            attachments = self.current_attachment_details_ignore_missing(module_args, strategy, network_names or None)

        payloads: list[dict[str, Any]] = []
        deploy_targets: dict[str, set[str]] = {}
        seen: set[tuple[str, str]] = set()
        for attachment in attachments:
            network_name = attachment.get("networkName")
            switch_id = attachment.get("switchId")
            if not network_name or not switch_id:
                continue
            if attachment.get("attach") is True or self.attachment_has_pending_delete_work(attachment):
                self.record_deploy_target(deploy_targets, network_name, switch_id)
            key = (network_name, switch_id)
            if attachment.get("attach") is True and key not in seen:
                payloads.append({"networkName": network_name, "switchId": switch_id, "attach": False})
                seen.add(key)

        if not payloads:
            return {"deploy_targets": deploy_targets}
        return self.post_network_attachments(module_args, strategy, payloads, deploy_targets, OperationType.DELETE)

    def desired_attachment_map(self, module_args: dict, strategy: BaseNetworkStrategy) -> dict[tuple[str, str], dict[str, Any]]:
        config = module_args.get("config") or []
        ip_to_switch = self.resolve_switch_ids(module_args, strategy, config)
        desired: dict[tuple[str, str], dict[str, Any]] = {}
        for network in config:
            network_name = network.get("network_name") or network.get("networkName")
            for attachment in network.get("attach") or []:
                ip_address = attachment.get("ip_address") or attachment.get("ipAddress")
                switch_id = ip_to_switch.get(ip_address)
                if not network_name or not switch_id:
                    continue
                payload = {
                    "networkName": network_name,
                    "switchId": switch_id,
                    "vlanId": attachment.get("vlan_id") or attachment.get("vlanId"),
                    "interfaces": self._attachment_interfaces(attachment),
                    "instanceValues": attachment.get("attachment_options"),
                    "extraConfig": attachment.get("extra_config") or attachment.get("extraConfig"),
                    "attach": True,
                }
                desired[(network_name, switch_id)] = {k: v for k, v in payload.items() if v is not None}
        return desired

    def resolve_switch_ids(self, module_args: dict, strategy: BaseNetworkStrategy, config: list[dict]) -> dict[str, str]:
        wanted_ips = {
            attachment.get("ip_address") or attachment.get("ipAddress")
            for network in config
            for attachment in network.get("attach") or []
            if attachment.get("ip_address") or attachment.get("ipAddress")
        }
        if not wanted_ips:
            return {}
        orchestrator, _results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageSwitchesListGet)
        data = orchestrator._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True, operation_type=OperationType.QUERY)
        switches = data.get("switches") or data.get("items") or data if isinstance(data, dict) else data
        resolved: dict[str, str] = {}
        for switch in switches or []:
            ip_address = switch.get("ipAddress") or switch.get("ip_address") or switch.get("managementIpAddress")
            switch_id = switch.get("switchId") or switch.get("switch_id") or switch.get("serialNumber")
            if ip_address in wanted_ips and switch_id:
                resolved[ip_address] = switch_id
        missing = sorted(wanted_ips - set(resolved))
        if missing:
            self.coordinator.module.fail_json(msg=f"Could not resolve switchId for network attachment IP(s): {missing}")
        return resolved

    @staticmethod
    def _attachment_interfaces(attachment: dict[str, Any]) -> list[dict[str, Any]] | None:
        interfaces = attachment.get("interfaces")
        if interfaces:
            payloads = []
            for interface in interfaces:
                mapping_type = interface.get("mapping_type") or interface.get("mappingType")
                payload = {
                    "mode": interface.get("mode") or NetworkAttachmentMode.ACCESS.value,
                    "interfaceRange": interface.get("interface_range") or interface.get("interfaceRange"),
                    "interfaceGroupName": interface.get("interface_group_name") or interface.get("interfaceGroupName"),
                    "nativeVlan": interface.get("native_vlan") if "native_vlan" in interface else interface.get("nativeVlan"),
                }
                if mapping_type:
                    mapping = {"mappingType": mapping_type}
                    customer_vlan = interface.get("customer_vlan") or interface.get("customerVlan")
                    if mapping_type == MappingType.SINGLE.value and customer_vlan is not None:
                        mapping["customerVlan"] = customer_vlan
                    payload["mapping"] = mapping
                payloads.append({k: v for k, v in payload.items() if v is not None})
            return payloads
        ports = attachment.get("ports") or []
        return [{"mode": NetworkAttachmentMode.ACCESS.value, "interfaceRange": port} for port in ports] or None

    def current_attachment_details(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        orchestrator, _results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsNetworkAttachmentsQueryPost)
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.include_all = True
        query = NetworkAttachmentQueryRequestModel(network_names=network_names or None)
        data = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=query.to_payload(),
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        if isinstance(data, dict):
            return data.get("attachments") or data.get("items") or []
        return data or []

    def current_attachment_details_ignore_missing(self, module_args: dict, strategy: BaseNetworkStrategy, network_names: Optional[list[str]] = None) -> list[dict[str, Any]]:
        try:
            return self.current_attachment_details(module_args, strategy, network_names)
        except Exception as exc:
            if network_names and self._attachment_query_missing_network(exc):
                return []
            raise

    @staticmethod
    def _attachment_query_missing_network(error: Exception) -> bool:
        message = str(error)
        return "Network(s)" in message and "not found in fabric" in message

    def current_attachment_map(self, module_args: dict, strategy: BaseNetworkStrategy, network_names: Optional[list[str]] = None) -> dict[tuple[str, str], dict[str, Any]]:
        return self.attachment_map_from_details(self.current_attachment_details(module_args, strategy, network_names), network_names)

    @staticmethod
    def attachment_map_from_details(attachments: list[dict[str, Any]], network_names: Optional[Union[list[str], set[str]]] = None) -> dict[tuple[str, str], dict[str, Any]]:
        filter_set = set(network_names or [])
        result: dict[tuple[str, str], dict[str, Any]] = {}
        for attachment in attachments or []:
            network_name = attachment.get("networkName")
            switch_id = attachment.get("switchId")
            if not network_name or not switch_id:
                continue
            if filter_set and network_name not in filter_set:
                continue
            if attachment.get("attach") is True:
                result[(network_name, switch_id)] = attachment
        return result

    @staticmethod
    def attachment_map_after_detach(current: dict[tuple[str, str], dict[str, Any]], payloads: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
        remaining = dict(current)
        for payload in payloads or []:
            if payload.get("attach") is False:
                remaining.pop((payload.get("networkName"), payload.get("switchId")), None)
        return remaining

    @staticmethod
    def planned_attach_payloads(current: dict[tuple[str, str], dict[str, Any]], desired: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
        payloads = []
        for key, desired_payload in desired.items():
            current_payload = current.get(key)
            if current_payload is None or NetworkAttachmentManager._attachment_changed(current_payload, desired_payload):
                payloads.append(desired_payload)
        return payloads

    @staticmethod
    def planned_detach_payloads(
        state: str,
        config: list[dict],
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> list[dict[str, Any]]:
        detach_keys: set[tuple[str, str]] = set()
        if state == "deleted":
            target_names = set(configured_network_names(config))
            detach_keys = {key for key in current if not target_names or key[0] in target_names}
        elif state in ("replaced", "overridden"):
            target_names = set(configured_network_names(config))
            detach_keys = {key for key in current if key[0] in target_names and key not in desired}
        return [{"networkName": name, "switchId": switch_id, "attach": False} for name, switch_id in sorted(detach_keys)]

    @staticmethod
    def _attachment_changed(current: dict[str, Any], desired: dict[str, Any]) -> bool:
        for key in ("vlanId", "interfaces", "instanceValues", "extraConfig"):
            if desired.get(key) != current.get(key):
                return True
        return False

    @staticmethod
    def attachment_matches(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
        """Return True when existing attachment satisfies desired fields."""
        return not NetworkAttachmentManager._attachment_changed(existing, desired)

    @staticmethod
    def attachment_instance_values(attachment: dict[str, Any]) -> dict[str, Any]:
        """Return playbook attachment options that map to ND instanceValues."""
        return attachment.get("attachment_options") or {}

    @staticmethod
    def switch_ip_candidates(switch: dict[str, Any]) -> set[str]:
        """Extract known management/IP fields from a switch inventory item."""
        return {
            value
            for value in (
                switch.get("ipAddress"),
                switch.get("ip_address"),
                switch.get("managementIpAddress"),
                switch.get("mgmtIpAddress"),
            )
            if value
        }

    @staticmethod
    def is_network_not_found_error(error: Exception) -> bool:
        """Return True for ND's attachment-query error when a network is absent."""
        return NetworkAttachmentManager._attachment_query_missing_network(error)

    def post_network_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        payloads: list[dict[str, Any]],
        deploy_targets: dict[str, set[str]],
        operation_type: OperationType,
    ) -> dict[str, Any]:
        request = NetworkAttachDetachPayloadModel(attachments=[NetworkAttachmentModel(**payload) for payload in payloads])
        orchestrator, results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsNetworkAttachmentsPost)
        response = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=request.to_payload(),
            operation_type=operation_type,
        )
        return {"response": response, "sequence": results.response, "deploy_targets": deploy_targets}

    @staticmethod
    def record_deploy_target(deploy_targets: dict[str, set[str]], network_name: str | None, switch_id: str | None) -> None:
        if not network_name:
            return
        deploy_targets.setdefault(network_name, set())
        if switch_id:
            deploy_targets[network_name].add(switch_id)

    @staticmethod
    def build_deploy_payloads(
        config: list[dict],
        *deploy_target_maps: dict[str, set[str]],
    ) -> list[dict[str, Any]]:
        deploy_enabled = deploy_enabled_by_network(config)
        deploy_types = deploy_type_by_network(config)
        grouped: dict[tuple[str, ...], set[str]] = {}
        network_level: set[str] = set()
        for target_map in deploy_target_maps:
            for network_name, switch_ids in (target_map or {}).items():
                if not deploy_enabled.get(network_name, True):
                    continue
                if deploy_types.get(network_name, "switch") == "network" or not switch_ids:
                    network_level.add(network_name)
                else:
                    grouped.setdefault(tuple(sorted(switch_ids)), set()).add(network_name)
        payloads = [
            NetworkSwitchesListModel(network_names=sorted(names), switch_ids=list(switch_ids)).to_payload()
            for switch_ids, names in sorted(grouped.items())
        ]
        if network_level:
            payloads.append(NetworkSwitchesListModel(network_names=sorted(network_level)).to_payload())
        return payloads

    def build_pending_network_deploy_payloads(
        self,
        result: dict[str, Any],
        config: list[dict],
        module_args: dict,
        strategy: BaseNetworkStrategy,
    ) -> list[dict[str, Any]]:
        configured = set(configured_network_names(config))
        deploy_enabled = deploy_enabled_by_network(config)
        pending_statuses = {"pending", "outOfSync", "failed", "inProgress", "deploymentInProgress"}
        pending = []
        for network in result.get("after") or []:
            name = network.get("network_name") or network.get("networkName")
            status = network.get("network_status") or network.get("networkStatus")
            if name in configured and deploy_enabled.get(name, True) and status in pending_statuses:
                pending.append(name)
        if not pending:
            return []
        return [NetworkSwitchesListModel(network_names=sorted(set(pending))).to_payload()]

    def deploy_network_attachments(self, module_args: dict, strategy: BaseNetworkStrategy, deploy_payload: dict[str, Any]) -> dict[str, Any]:
        orchestrator, results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageFabricsNetworkActionsDeployPost)
        response = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=deploy_payload,
            operation_type=OperationType.UPDATE,
        )
        return {"response": response, "sequence": results.response}

    def wait_for_networks_delete_ready(self, module_args: dict, strategy: BaseNetworkStrategy, network_names: Optional[list[str]] = None) -> None:
        pending = set(network_names if network_names is not None else configured_network_names(module_args.get("config") or []))
        if not pending:
            return
        ready_statuses = {"notApplicable", "notDeployed", "deleted"}
        last_statuses: dict[str, str] = {}
        for _attempt in range(self.wait_attempts):
            orchestrator, _results = self.coordinator._new_network_orchestrator(module_args, strategy)
            networks = orchestrator.query_all() or []
            last_statuses = {}
            for network in networks:
                name = network.get("networkName") or network.get("network_name")
                if name in pending:
                    last_statuses[name] = network.get("networkStatus") or network.get("network_status") or ""
            ready = {name for name in pending if name not in last_statuses or last_statuses[name] in ready_statuses}
            pending.difference_update(ready)
            if not pending:
                return
            time.sleep(self.wait_delay)
        self.coordinator.module.fail_json(
            msg=f"Timed out waiting for networks to become deletable on fabric '{strategy.fabric_name}': {last_statuses}"
        )

    @staticmethod
    def filter_attachment_details_by_network(attachments: list[dict[str, Any]], network_names: Union[list[str], set[str]]) -> list[dict[str, Any]]:
        names = set(network_names)
        return [attachment for attachment in attachments if attachment.get("networkName") in names]

    @staticmethod
    def attachment_has_pending_delete_work(attachment: dict[str, Any]) -> bool:
        pending_statuses = {"deploymentInProgress", "failed", "inProgress", "outOfSync", "pending", "previewInProgress"}
        for key in ("status", "configStatus", "deploymentStatus", "networkStatus", "attachmentStatus"):
            status = attachment.get(key)
            if status is not None and str(status).strip() in pending_statuses:
                return True
        return False
