# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Network attachment and deployment planning/execution."""

from __future__ import annotations

import re
import time

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_attachments import (
    EpManageFabricsNetworkAttachmentsPost,
    EpManageFabricsNetworkAttachmentsQueryPost,
    EpManageFabricsNetworkAttachmentsValidateInterfacesPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsNetworkAttachmentsPost,
    EpOneManageFabricsNetworkAttachmentsQueryPost,
    EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_switches import (
    EpManageSwitchesListGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_switch_actions import (
    EpManageSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.onemanage.onemanage_fabrics_networks import (
    EpOneManageFabricsSwitchActionsDeployPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    MappingType,
    PublicNetworkAttachmentMode,
    api_network_attachment_mode,
    public_network_attachment_mode,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_actions_models import (
    NetworkSwitchesListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_attachment_models import (
    NetworkAttachmentInstanceValuesModel,
    NetworkAttachmentModel,
    NetworkAttachDetachPayloadModel,
    NetworkAttachmentQueryRequestModel,
    NetworkAttachmentValidateInterfaceModel,
    NetworkAttachmentValidateInterfacesPayloadModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_common import normalize_ethernet_interface_name
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.port_channel_common import normalize_port_channel_interface_name
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.attachment_vpc_peer_expander import (
    expand_desired_attachments_with_vpc_peers,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.delete_readiness import (
    DeleteReadinessPolicy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_staging_effects import staging_observer
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_config_utils import (
    configured_network_names,
    deploy_enabled_by_network,
    deploy_scope_by_network,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)


class NetworkAttachmentManager:
    """Plans and executes network attach, detach, and deploy operations."""

    wait_attempts = 20
    wait_delay = 15
    wait_chunk_size = 30
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
    def _attachments_query_endpoint_cls(strategy: BaseNetworkStrategy) -> type:
        if strategy.is_multicluster and strategy.is_parent:
            return EpOneManageFabricsNetworkAttachmentsQueryPost
        return EpManageFabricsNetworkAttachmentsQueryPost

    @staticmethod
    def _attachments_post_endpoint_cls(strategy: BaseNetworkStrategy) -> type:
        if strategy.is_multicluster and strategy.is_parent:
            return EpOneManageFabricsNetworkAttachmentsPost
        return EpManageFabricsNetworkAttachmentsPost

    @staticmethod
    def _attachments_validate_endpoint_cls(strategy: BaseNetworkStrategy) -> type:
        if strategy.is_multicluster and strategy.is_parent:
            return EpOneManageFabricsNetworkAttachmentsValidateInterfacesPost
        return EpManageFabricsNetworkAttachmentsValidateInterfacesPost

    def apply_phase(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        phase: str,
        desired: dict[tuple[str, str], dict[str, Any]] | None = None,
        current_network_names: list[str] | None = None,
        current: dict[tuple[str, str], dict[str, Any]] | None = None,
        attachment_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        state = module_args.get("state", "merged")
        config = module_args.get("config") or []
        self._trace("network_attachment_phase_start", phase=phase, state=state, config_count=len(config), current_network_names=current_network_names)
        if not config and state != "overridden":
            self._trace("network_attachment_phase_skip", phase=phase, reason="empty_config")
            return {}
        if phase == "pre" and state not in ("deleted", "replaced", "overridden", "staged"):
            self._trace("network_attachment_phase_skip", phase=phase, reason="state_not_pre_detach")
            return {}
        if phase == "post" and state not in ("merged", "replaced", "overridden", "staged"):
            self._trace("network_attachment_phase_skip", phase=phase, reason="state_not_post_attach")
            return {}
        if current_network_names == []:
            self._trace("network_attachment_phase_skip", phase=phase, reason="no_current_networks")
            return {}

        desired = desired if desired is not None else self.desired_attachment_map(module_args, strategy)
        if phase == "post" and not desired:
            self._trace("network_attachment_phase_skip", phase=phase, reason="no_desired_attachments")
            return {}

        query_names = current_network_names
        if query_names is None:
            query_names = None if state == "overridden" else configured_network_names(config)
        raw_attachment_details = attachment_details
        if current is None:
            if raw_attachment_details is None:
                raw_attachment_details = self.current_attachment_details(module_args, strategy, query_names)
            current = self.attachment_map_from_details(raw_attachment_details, query_names)
            self._trace(
                "network_attachment_current_loaded",
                phase=phase,
                queried_network_names=query_names,
                attachment_count=len(raw_attachment_details or []),
                current_count=len(current),
            )

        explicit_interface_keys = {key for key, payload in desired.items() if "interfaces" in payload}
        if desired:
            desired = self.expand_desired_attachments_with_vpc_peers(
                desired,
                raw_attachment_details if raw_attachment_details is not None else current.values(),
            )
            self._trace("network_attachment_desired_expanded", phase=phase, desired_count=len(desired))

        payloads = (
            self.planned_detach_payloads(state, config, current, desired, explicit_interface_keys)
            if phase == "pre"
            else self.planned_attach_payloads(current, desired, preserve_omitted_fields=state == "merged")
        )
        if not payloads:
            self._trace("network_attachment_phase_noop", phase=phase, desired_count=len(desired or {}), current_count=len(current or {}))
            return {"current": current} if phase == "pre" else {}

        deploy_enabled = deploy_enabled_by_network(config, getattr(self.coordinator, "config_actions", None))
        deploy_targets: dict[str, set[str]] = {}
        for payload in payloads:
            network_name = payload.get("networkName")
            if deploy_enabled.get(network_name, True):
                self.record_deploy_target(deploy_targets, network_name, payload.get("switchId"))

        trace = self.post_network_attachments(
            module_args, strategy, payloads, deploy_targets, OperationType.DELETE if phase == "pre" else OperationType.CREATE
        )
        self._trace("network_attachment_phase_end", phase=phase, payload_count=len(payloads), deploy_target_count=len(deploy_targets))
        trace["current"] = current
        trace["desired"] = desired
        trace["payloads"] = payloads
        return trace

    def apply_deleted_phase(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
        attachment_details: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        network_names = network_names if network_names is not None else configured_network_names(module_args.get("config") or [])
        self._trace("network_deleted_attachment_phase_start", network_names=network_names)
        if network_names == [] and attachment_details is None:
            self._trace("network_deleted_attachment_phase_skip", reason="empty_targets")
            return {"deploy_targets": {}}
        attachments = attachment_details
        if attachments is None:
            attachments = self.current_attachment_details_ignore_missing(module_args, strategy, network_names or None)
        self._trace("network_deleted_attachment_current_loaded", network_names=network_names, attachment_count=len(attachments or []))

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
                payload = {"networkName": network_name, "switchId": switch_id, "vlanId": attachment.get("vlanId"), "attach": False}
                payloads.append({k: v for k, v in payload.items() if v is not None})
                seen.add(key)

        if not payloads:
            self._trace("network_deleted_attachment_phase_noop", deploy_target_count=len(deploy_targets))
            return {"deploy_targets": deploy_targets}
        self._trace("network_deleted_attachment_phase_post", payload_count=len(payloads), deploy_target_count=len(deploy_targets))
        return self.post_network_attachments(module_args, strategy, payloads, deploy_targets, OperationType.DELETE)

    def desired_attachment_map(self, module_args: dict, strategy: BaseNetworkStrategy) -> dict[tuple[str, str], dict[str, Any]]:
        config = module_args.get("config") or []
        ip_to_switch = self.resolve_switch_ids(module_args, strategy, config)
        desired: dict[tuple[str, str], dict[str, Any]] = {}
        for network in config:
            network_name = network.get("network_name") or network.get("networkName")
            for attachment in network.get("attach") or []:
                ip_address = attachment.get("ip_address")
                switch_id = ip_to_switch.get(ip_address)
                if not network_name or not switch_id:
                    continue
                payload = {
                    "networkName": network_name,
                    "switchId": switch_id,
                    "vlanId": attachment.get("vlan_id"),
                    "interfaces": self._attachment_interfaces(attachment),
                    "instanceValues": self.attachment_instance_values(attachment) if attachment.get("attachment_options") is not None else None,
                    "extraConfig": attachment.get("freeform_config"),
                    "attach": True,
                }
                desired[(network_name, switch_id)] = {k: v for k, v in payload.items() if v is not None}
        return desired

    def resolve_switch_ids(self, module_args: dict, strategy: BaseNetworkStrategy, config: list[dict]) -> dict[str, str]:
        wanted_ips = {attachment.get("ip_address") for network in config for attachment in network.get("attach") or [] if attachment.get("ip_address")}
        if not wanted_ips:
            self._trace("network_attachment_switch_resolve_end", requested_count=0, resolved_count=0)
            return {}
        self._trace("network_attachment_switch_resolve_start", requested_count=len(wanted_ips), fabric_name=strategy.fabric_name)
        orchestrator, _results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(EpManageSwitchesListGet)
        data = orchestrator._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True, operation_type=OperationType.QUERY)
        switches = []
        if isinstance(data, dict):
            switches = data.get("switches") or data.get("items") or []
        elif isinstance(data, list):
            switches = data
        resolved: dict[str, str] = {}
        for switch in switches or []:
            observer = staging_observer(self.coordinator)
            if observer is not None:
                observer.remember_switch(switch)
            ip_address = switch.get("ipAddress") or switch.get("ip_address") or switch.get("managementIpAddress") or switch.get("fabricManagementIp")
            switch_id = switch.get("switchId") or switch.get("switch_id") or switch.get("serialNumber")
            if ip_address in wanted_ips and switch_id:
                resolved[ip_address] = switch_id
        missing = sorted(wanted_ips - set(resolved))
        if missing:
            self._trace("network_attachment_switch_resolve_failed", requested_count=len(wanted_ips), resolved_count=len(resolved), missing=missing)
            self.coordinator.module.fail_json(msg=f"Could not resolve switchId for network attachment IP(s): {missing}")
        self._trace("network_attachment_switch_resolve_end", requested_count=len(wanted_ips), resolved_count=len(resolved))
        return resolved

    @staticmethod
    def _attachment_interfaces(attachment: dict[str, Any]) -> list[dict[str, Any]] | None:
        if "interfaces" not in attachment:
            return None
        interfaces = attachment.get("interfaces")
        if interfaces is None:
            return None
        payloads = []
        for interface in interfaces:
            mapping_type = interface.get("mapping_type")
            mode = interface.get("mode") or PublicNetworkAttachmentMode.ACCESS.value
            payload = {
                "mode": mode,
                "interfaceRange": interface.get("interface_range"),
                "interfaceGroupName": interface.get("interface_group_name"),
            }
            if mode == PublicNetworkAttachmentMode.TRUNK.value:
                payload["nativeVlan"] = interface.get("native_vlan")
            if mapping_type:
                mapping = {"mappingType": mapping_type}
                customer_vlan = interface.get("customer_vlan")
                if mapping_type == MappingType.SINGLE.value and customer_vlan is not None:
                    mapping["customerVlan"] = customer_vlan
                payload["mapping"] = mapping
            payloads.append({k: v for k, v in payload.items() if v is not None})
        return payloads

    def current_attachment_details(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        attachments: list[dict[str, Any]] = []
        offset = 0

        while True:
            data = self._current_attachment_details_page(module_args, strategy, network_names, offset)
            page_items = self._attachment_items_from_query_result(data)
            attachments.extend(page_items)
            more = self._has_more_attachment_pages(data, len(page_items), len(attachments))
            observer = staging_observer(self.coordinator)
            if observer is not None:
                observer.observe_page("attachments", data, page_items, offset, self.attachment_query_page_size, more, network_names)
            if not more:
                break
            if not page_items:
                break
            offset += len(page_items)

        return attachments

    def _current_attachment_details_page(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None,
        offset: int,
    ) -> Any:
        orchestrator, _results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(self._attachments_query_endpoint_cls(strategy))
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.include_all = True
            endpoint.endpoint_params.max = self.attachment_query_page_size
            endpoint.endpoint_params.offset = offset
        query = NetworkAttachmentQueryRequestModel(network_names=network_names or None)
        rest_send = orchestrator.rest_send
        rest_send.save_settings()
        rest_send.check_mode = False
        try:
            return orchestrator._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data=query.to_payload(),
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
        finally:
            rest_send.restore_settings()

    @staticmethod
    def _attachment_items_from_query_result(data: Any) -> list[dict[str, Any]]:
        if isinstance(data, dict):
            return data.get("attachments") or data.get("items") or []
        return data or []

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
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        if network_names and len(network_names) > self.wait_chunk_size:
            attachments: list[dict[str, Any]] = []
            for index in range(0, len(network_names), self.wait_chunk_size):
                chunk = network_names[index : index + self.wait_chunk_size]
                attachments.extend(self.current_attachment_details_ignore_missing(module_args, strategy, chunk))
            return attachments
        try:
            return self.current_attachment_details(module_args, strategy, network_names)
        except Exception as exc:
            if not self._attachment_query_missing_network(exc):
                raise

        if not network_names or len(network_names) <= 1:
            return []

        all_attachments = self.current_attachment_details(module_args, strategy, None)
        return self.filter_attachment_details_by_network(all_attachments, network_names)

    @staticmethod
    def _attachment_query_missing_network(error: Exception) -> bool:
        message = str(error)
        if "Network(s)" in message and "not found in fabric" in message:
            return True
        return bool(re.search(r"\bNetwork '[^']+' doesn't exist in the fabric\b", message))

    def current_attachment_map(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        return self.attachment_map_from_details(self.current_attachment_details(module_args, strategy, network_names), network_names)

    @staticmethod
    def expand_desired_attachments_with_vpc_peers(
        desired: dict[tuple[str, str], dict[str, Any]],
        attachment_details: Any,
    ) -> dict[tuple[str, str], dict[str, Any]]:
        """Add vPC peer attachments from attachment-query rows."""

        def clear_peer_interfaces(peer_payload: dict[str, Any]) -> None:
            if "interfaces" in peer_payload:
                peer_payload["interfaces"] = []

        return expand_desired_attachments_with_vpc_peers(
            desired,
            attachment_details,
            "networkName",
            peer_payload_mutator=clear_peer_interfaces,
        )

    @staticmethod
    def attachment_map_from_details(
        attachments: list[dict[str, Any]],
        network_names: list[str] | set[str] | None = None,
    ) -> dict[tuple[str, str], dict[str, Any]]:
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
    def planned_attach_payloads(
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
        preserve_omitted_fields: bool = False,
    ) -> list[dict[str, Any]]:
        payloads = []
        for key, desired_payload in desired.items():
            current_payload = current.get(key)
            if preserve_omitted_fields and current_payload is not None:
                retained = {
                    field: current_payload[field]
                    for field in ("vlanId", "interfaces")
                    if field not in desired_payload and current_payload.get(field) is not None
                }
                if retained:
                    desired_payload = {**desired_payload, **retained}
            if current_payload is None or NetworkAttachmentManager._attachment_changed(current_payload, desired_payload):
                payloads.append(desired_payload)
        return payloads

    @staticmethod
    def planned_detach_payloads(
        state: str,
        config: list[dict],
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
        explicit_interface_keys: set[tuple[str, str]] | None = None,
    ) -> list[dict[str, Any]]:
        detach_keys: set[tuple[str, str]] = set()
        if state == "deleted":
            target_names = set(configured_network_names(config))
            detach_keys = {key for key in current if not target_names or key[0] in target_names}
        elif state in ("overridden", "staged"):
            detach_keys = set(current.keys()).difference(desired.keys())
        elif state == "replaced":
            target_names = set(configured_network_names(config))
            detach_keys = {key for key in current if key[0] in target_names and key not in desired}
        if state in ("replaced", "overridden", "staged"):
            for key in current.keys() & desired.keys():
                # Peer expansion uses interfaces=[] as passive peer metadata.
                # Only an explicitly configured switch attachment may authorize
                # clearing ports on that switch before the exact reattachment.
                if explicit_interface_keys is not None and key not in explicit_interface_keys:
                    continue
                if NetworkAttachmentManager._has_removed_ports(current[key], desired[key]):
                    detach_keys.add(key)
        payloads = []
        for name, switch_id in sorted(detach_keys):
            attachment = current.get((name, switch_id), {})
            payload = {"networkName": name, "switchId": switch_id, "vlanId": attachment.get("vlanId"), "attach": False}
            payloads.append({k: v for k, v in payload.items() if v is not None})
        return payloads

    @staticmethod
    def _has_removed_ports(current: dict[str, Any], desired: dict[str, Any]) -> bool:
        """Recognize removed explicit ports or replaced opaque group targets."""
        if "interfaces" not in desired or not current.get("interfaces"):
            return False
        before = NetworkAttachmentManager._normalized_interfaces(current.get("interfaces"))
        after = NetworkAttachmentManager._normalized_interfaces(desired.get("interfaces"))
        if before == after:
            return False

        def group_targets(interfaces):
            targets = set()
            for interface in interfaces:
                group = interface.get("interfaceGroupName")
                if not group:
                    continue
                selector = interface.get("interfaceRange")
                if not isinstance(group, str) or not group.strip() or selector is not None and not isinstance(selector, str):
                    raise ValueError("Cannot replace Network attachment ports using a malformed interface group selector")
                targets.add((group, selector))
            return targets

        # Group membership is opaque. Removing an exact group target replaces
        # this known Network/switch attachment, without guessing physical ports.
        # Stable group targets with only option edits need no pre-detachment.
        removed_groups = group_targets(before) - group_targets(after)
        before = [interface for interface in before if not interface.get("interfaceGroupName")]
        after = [interface for interface in after if not interface.get("interfaceGroupName")]

        def members(interfaces):
            result = set()
            for interface in interfaces:
                selector = interface.get("interfaceRange")
                if not isinstance(selector, str):
                    raise ValueError("Cannot replace Network attachment ports without an explicit interface range")
                for token in selector.split(","):
                    match = re.fullmatch(r"(?i)(ethernet|eth|port-channel|portchannel|po)([0-9]+(?:/[0-9]+)*)(?:-([0-9]+))?", token.strip())
                    if match is None:
                        opaque = NetworkAttachmentManager._opaque_ios_xe_selector(token)
                        if opaque is not None:
                            result.add(opaque)
                            continue
                        raise ValueError(f"Cannot prove Network port omission for interface selector {token!r}")
                    family, identity, end = match.groups()
                    family = "Ethernet" if family.lower() in ("ethernet", "eth") else "port-channel"
                    components = identity.split("/")
                    if family == "Ethernet" and len(components) < 2 or family == "port-channel" and len(components) != 1:
                        raise ValueError(f"Cannot prove Network port omission for interface selector {token!r}")
                    start = int(components[-1])
                    stop = int(end) if end is not None else start
                    if start < 1 or stop < start or stop > 4096 or stop - start >= 4096:
                        raise ValueError("Network interface replacement range is invalid or exceeds the bounded port limit")
                    prefix = "/".join(str(int(value)) for value in components[:-1])
                    for number in range(start, stop + 1):
                        result.add(family + (prefix + "/" if prefix else "") + str(number))
            return result

        removed_ports = members(before) - members(after)
        return bool(removed_groups or removed_ports)

    @staticmethod
    def _opaque_ios_xe_selector(value: Any) -> str | None:
        """Recognize existing IOS-XE physical families without expanding ports.

        Reuse the native parent-name contract only for non-NX-OS selectors.
        A changed opaque literal/range replaces the exact Network attachment;
        it grants no interface-workflow family support or hardware discovery.
        """
        if not isinstance(value, str):
            return None
        match = re.fullmatch(r"([A-Za-z]+)([0-9]+(?:/[0-9]+)*)(?:-([0-9]+))?", value.strip())
        if match is None:
            return None
        family, path, end = match.groups()
        if family.lower() in ("ethernet", "eth", "portchannel", "po"):
            return None
        # Lazy reuse keeps ordinary NX-OS attachment planning independent of
        # the IOS-XE model's import cost and avoids another family inventory.
        from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_managed_interface import SubinterfaceManagedInterfaceModel

        try:
            parent = SubinterfaceManagedInterfaceModel._normalize_parent(family + path, strict=True)
        except ValueError:
            return None
        if parent.startswith(("Ethernet", "Port-channel")):
            return None
        if end is not None and int(end) < int(path.rsplit("/", 1)[-1]):
            raise ValueError("Network interface replacement range is invalid")
        return parent + ("-" + end if end is not None else "")

    @staticmethod
    def _attachment_changed(current: dict[str, Any], desired: dict[str, Any]) -> bool:
        def normalized_options(value):
            if not isinstance(value, dict):
                return value
            aliases = {name: field.alias or name for name, field in NetworkAttachmentInstanceValuesModel.model_fields.items()}
            normalized = {aliases.get(key, key): item for key, item in value.items()}
            # Conflicting alias spellings must remain visible rather than having
            # dictionary insertion order decide which intent wins.
            return normalized if len(normalized) == len(value) else value

        for key in ("vlanId", "instanceValues", "extraConfig"):
            if key not in desired:
                continue
            if NetworkAttachmentManager._empty_equivalent(desired.get(key)) and NetworkAttachmentManager._empty_equivalent(current.get(key)):
                continue
            want, have = desired.get(key), current.get(key)
            if key == "instanceValues":
                want, have = normalized_options(want), normalized_options(have)
            if want != have:
                return True
        if "interfaces" in desired and NetworkAttachmentManager._normalized_interfaces(
            desired.get("interfaces")
        ) != NetworkAttachmentManager._normalized_interfaces(current.get("interfaces")):
            return True
        return False

    @staticmethod
    def _empty_equivalent(value: Any) -> bool:
        """Return True for API/playbook empty values that are semantically absent."""
        return value in (None, "", {}, [])

    @staticmethod
    def _normalized_interfaces(interfaces: Any) -> list[dict[str, Any]]:
        """Normalize attachment interfaces to fields that affect Network attachment intent."""

        def normalized_name(value):
            if not isinstance(value, str):
                return value
            if re.fullmatch(r"(?:Ethernet|Eth)\d+(?:/\d+)+(?:\.\d+)?", value, re.IGNORECASE):
                return normalize_ethernet_interface_name(value)
            match = re.fullmatch(r"(?:port-channel|po)(\d+)", value, re.IGNORECASE)
            if match:
                try:
                    return normalize_port_channel_interface_name("port-channel" + match.group(1))
                except ValueError:
                    pass
            opaque = NetworkAttachmentManager._opaque_ios_xe_selector(value)
            if opaque is not None:
                return opaque
            return value

        normalized = []
        for interface in interfaces or []:
            mapping = interface.get("mapping") or {}
            normalized_interface = {
                "mode": public_network_attachment_mode(NetworkAttachmentManager._status_value(interface.get("mode"))).lower(),
                "interfaceRange": normalized_name(interface.get("interfaceRange") or interface.get("interface_range")),
                "interfaceGroupName": interface.get("interfaceGroupName") or interface.get("interface_group_name"),
                "nativeVlan": bool(interface.get("nativeVlan") if "nativeVlan" in interface else interface.get("native_vlan", False)),
            }
            if mapping:
                normalized_mapping = {"mappingType": mapping.get("mappingType") or mapping.get("mapping_type")}
                if mapping.get("customerVlan") is not None or mapping.get("customer_vlan") is not None:
                    normalized_mapping["customerVlan"] = (
                        mapping.get("customerVlan") if mapping.get("customerVlan") is not None else mapping.get("customer_vlan")
                    )
                normalized_interface["mapping"] = {key: value for key, value in normalized_mapping.items() if value is not None}
            normalized.append({key: value for key, value in normalized_interface.items() if value is not None})
        return sorted(normalized, key=lambda item: (item.get("mode", ""), item.get("interfaceRange", ""), item.get("interfaceGroupName", "")))

    @staticmethod
    def attachment_matches(existing: dict[str, Any], desired: dict[str, Any]) -> bool:
        """Return True when existing attachment satisfies desired fields."""
        return not NetworkAttachmentManager._attachment_changed(existing, desired)

    @staticmethod
    def attachment_instance_values(attachment: dict[str, Any]) -> dict[str, Any]:
        """Map playbook attachment options to ND instanceValues."""
        attachment_options = attachment.get("attachment_options") or {}
        raw = {
            "dpu_secure": attachment_options.get("dpu_secure"),
            "dpu_affinity": attachment_options.get("dpu_affinity"),
            "svi_enabled": attachment_options.get("svi_enabled"),
            "switch_route_target_import": attachment_options.get("switch_route_target_import"),
            "switch_route_target_export": attachment_options.get("switch_route_target_export"),
            "is_active": attachment_options.get("is_active"),
        }
        raw = {key: value for key, value in raw.items() if value is not None}
        if not raw:
            return {}
        return NetworkAttachmentInstanceValuesModel(**raw).to_payload()

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
        self._trace(
            "network_attachment_post_start",
            operation_type=operation_type.value,
            payload_count=len(payloads),
            deploy_target_count=len(deploy_targets),
        )
        if getattr(getattr(self.coordinator, "module", None), "check_mode", False):
            self._trace("network_attachment_post_check_mode", payload_count=len(payloads), deploy_target_count=len(deploy_targets))
            return {
                "changed": True,
                "failed": False,
                "deploy_targets": deploy_targets,
                "payloads": payloads,
                "check_mode_attachment_payloads": payloads,
            }
        orchestrator, results = self.coordinator._new_network_orchestrator(module_args, strategy)
        controller_version = getattr(getattr(orchestrator, "rest_send", None), "controller_version", None)
        payloads = self._prepare_attachment_payloads(strategy, payloads)
        payloads = self._payloads_for_controller(payloads, controller_version)
        request = NetworkAttachDetachPayloadModel(attachments=[NetworkAttachmentModel(**payload) for payload in payloads])
        self.validate_attachment_interfaces(orchestrator, strategy, payloads)
        endpoint = orchestrator._make_endpoint(self._attachments_post_endpoint_cls(strategy))
        response = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=request.to_payload(),
            operation_type=operation_type,
        )
        self._raise_on_failed_results(response, "Network attachment failed")
        observer = staging_observer(self.coordinator)
        if observer is not None:
            observer.record_payloads(payloads)
        trace = self.coordinator._finalize_api_trace(results, deploy_targets)
        self._trace("network_attachment_post_end", operation_type=operation_type.value, changed=trace.get("changed"), failed=trace.get("failed"))
        return trace

    def preflight_replacement_interfaces(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        current: dict[tuple[str, str], dict[str, Any]],
        desired: dict[tuple[str, str], dict[str, Any]],
    ) -> None:
        """Validate existing attachment replacements before any workflow write.

        The post phase validates again against the then-current definition.
        New Networks are deliberately excluded: their ports cannot be validated
        until the definition exists. Passive synthesized peers do not grant
        authority to replace their ports.
        """
        if module_args.get("state") not in ("staged", "replaced", "overridden"):
            return
        replacements = [
            payload for key, payload in desired.items() if key in current and payload.get("interfaces") and self._has_removed_ports(current[key], payload)
        ]
        if not replacements:
            return
        orchestrator, _results = self.coordinator._new_network_orchestrator(module_args, strategy)
        controller_version = getattr(getattr(orchestrator, "rest_send", None), "controller_version", None)
        replacements = self._payloads_for_controller(self._prepare_attachment_payloads(strategy, replacements), controller_version)
        # This POST is read-only, so perform the same safety check in check
        # mode without enabling any of the later attachment mutation requests.
        rest_send = orchestrator.rest_send
        rest_send.save_settings()
        rest_send.check_mode = False
        try:
            self.validate_attachment_interfaces(orchestrator, strategy, replacements)
        finally:
            rest_send.restore_settings()

    def validate_attachment_interfaces(self, orchestrator: Any, strategy: BaseNetworkStrategy, payloads: list[dict[str, Any]]) -> None:
        """Ask ND to validate attachment interfaces before mutation."""
        validation_payloads = [self._validation_payload(payload) for payload in payloads if payload.get("interfaces")]
        if not validation_payloads:
            self._trace("network_attachment_validate_skip", reason="no_interfaces")
            return
        self._trace("network_attachment_validate_start", payload_count=len(validation_payloads))
        request = NetworkAttachmentValidateInterfacesPayloadModel(
            attachments=[NetworkAttachmentValidateInterfaceModel(**payload) for payload in validation_payloads]
        )
        endpoint = orchestrator._make_endpoint(self._attachments_validate_endpoint_cls(strategy))
        response = orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=request.to_payload(),
            operation_type=OperationType.QUERY,
        )
        self._raise_on_failed_results(response, "Network attachment interface validation failed")
        self._trace("network_attachment_validate_end", payload_count=len(validation_payloads))

    @staticmethod
    def _prepare_attachment_payloads(strategy: BaseNetworkStrategy, payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Fill OneManage MCFG attachment defaults observed in GUI payloads."""
        if not (strategy.is_multicluster and strategy.is_parent):
            return payloads
        prepared = []
        for payload in payloads:
            item = dict(payload)
            item.setdefault("instanceValues", {})
            item.setdefault("interfaces", [])
            item.setdefault("extraConfig", "")
            prepared.append(item)
        return prepared

    @staticmethod
    def _payloads_for_controller(payloads: list[dict[str, Any]], controller_version: str | None) -> list[dict[str, Any]]:
        """Return attachment payload copies with interface modes converted to controller API spelling."""
        converted = []
        for payload in payloads:
            item = dict(payload)
            if "interfaces" in item:
                item["interfaces"] = NetworkAttachmentManager._interfaces_for_controller(item.get("interfaces"), controller_version)
            converted.append(item)
        return converted

    @staticmethod
    def _interfaces_for_controller(interfaces: Any, controller_version: str | None) -> Any:
        if not isinstance(interfaces, list):
            return interfaces
        converted = []
        for interface in interfaces:
            if not isinstance(interface, dict):
                converted.append(interface)
                continue
            item = dict(interface)
            item["mode"] = api_network_attachment_mode(item.get("mode"), controller_version)
            converted.append(item)
        return converted

    @staticmethod
    def _validation_payload(payload: dict[str, Any]) -> dict[str, Any]:
        validation = {
            "networkName": payload.get("networkName"),
            "switchId": payload.get("switchId"),
            "interfaces": payload.get("interfaces"),
            "attach": payload.get("attach", True),
        }
        # VLAN is optional and can be allocated during attachment. The API's
        # valid range is 2..4094; an invented -1 sentinel fails validation.
        if payload.get("vlanId") is not None:
            validation["vlanId"] = payload["vlanId"]
        return validation

    @staticmethod
    def _raise_on_failed_results(response: Any, prefix: str) -> None:
        if not isinstance(response, dict):
            return
        results = response.get("results")
        if not isinstance(results, list):
            return
        failed = [item for item in results if isinstance(item, dict) and str(item.get("status", "")).lower() != "success"]
        if failed:
            raise Exception(f"{prefix}: {failed}")

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
        strategy: BaseNetworkStrategy | None = None,
        actions: Any | None = None,
    ) -> list[dict[str, Any]]:
        deploy_enabled = deploy_enabled_by_network(config, actions)
        deploy_scopes = deploy_scope_by_network(config, actions)
        grouped: dict[tuple[str, ...], set[str]] = {}
        network_level: set[str] = set()
        no_target: set[str] = set()
        switch_scope_targets: set[str] = set()
        for target_map in deploy_target_maps:
            for network_name, switch_ids in (target_map or {}).items():
                if not deploy_enabled.get(network_name, True):
                    continue
                scope = deploy_scopes.get(network_name, "resource")
                msd_parent = bool(
                    strategy
                    and getattr(strategy, "is_parent", False)
                    and getattr(strategy, "is_multisite", False)
                    and not getattr(strategy, "is_multicluster", False)
                )
                if scope == "switch":
                    if switch_ids:
                        switch_scope_targets.update(switch_ids)
                    else:
                        no_target.add(network_name)
                elif scope == "resource" and msd_parent and switch_ids:
                    grouped.setdefault(tuple(sorted(switch_ids)), set()).add(network_name)
                elif scope == "resource":
                    network_level.add(network_name)
                else:
                    grouped.setdefault(tuple(sorted(switch_ids)), set()).add(network_name)
        payloads = [{"switchIds": sorted(switch_scope_targets)}] if switch_scope_targets else []
        payloads.extend(
            [NetworkSwitchesListModel(network_names=sorted(names), switch_ids=list(switch_ids)).to_payload() for switch_ids, names in sorted(grouped.items())]
        )
        if network_level:
            payloads.append(NetworkSwitchesListModel(network_names=sorted(network_level)).to_payload())
        if no_target:
            payloads.append(NetworkSwitchesListModel(network_names=sorted(no_target)).to_payload())
        return payloads

    @staticmethod
    def build_delete_deploy_payloads(
        config: list[dict],
        *deploy_target_maps: dict[str, set[str]],
        strategy: BaseNetworkStrategy | None = None,
        actions: Any | None = None,
    ) -> list[dict[str, Any]]:
        """
        Build Network deploy requests for detach cleanup at the selected scope.

        Delete must deploy the detach/undeploy work before the Network delete is
        attempted, regardless of per-Network ``deploy``. Standalone and MSD
        honor the selected config action scope without deploying unrelated switch configuration.
        Switch scope includes Network names and affected switch IDs; Network
        scope includes Network names. MCFG parent retains affected switch IDs.
        Never widen a missing switch target to an unscoped Network request.
        """
        deploy_scopes = deploy_scope_by_network(config, actions)
        mcfg_parent = bool(strategy and getattr(strategy, "is_multicluster", False) and getattr(strategy, "is_parent", False))
        msd_parent = bool(
            strategy and getattr(strategy, "is_multisite", False) and getattr(strategy, "is_parent", False) and not getattr(strategy, "is_multicluster", False)
        )
        network_level: set[str] = set()
        network_groups: dict[tuple[str, ...], set[str]] = {}
        for target_map in deploy_target_maps:
            for network_name, target_switch_ids in (target_map or {}).items():
                scope = deploy_scopes.get(network_name, "resource")
                if scope == "resource" and msd_parent and target_switch_ids:
                    network_groups.setdefault(tuple(sorted(target_switch_ids)), set()).add(network_name)
                elif scope == "resource" and not (mcfg_parent or msd_parent):
                    network_level.add(network_name)
                elif scope == "resource" and msd_parent and not target_switch_ids:
                    network_level.add(network_name)
                elif not target_switch_ids:
                    continue
                else:
                    network_groups.setdefault(tuple(sorted(target_switch_ids)), set()).add(network_name)
        payloads = [
            NetworkSwitchesListModel(network_names=sorted(names), switch_ids=list(target_ids)).to_payload()
            for target_ids, names in sorted(network_groups.items())
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
        existing_names: set[str] | None = None,
        actions: Any | None = None,
    ) -> list[dict[str, Any]]:
        configured = set(configured_network_names(config))
        deploy_enabled = deploy_enabled_by_network(config, actions)
        pending_statuses = {"pending", "outofsync", "failed", "inprogress", "deploymentinprogress"}
        deploy_targets: dict[str, set[str]] = {}
        after_names: set[str] = set()
        pending_network_names: set[str] = set()
        for network in result.get("after") or []:
            name = network.get("network_name") or network.get("networkName")
            status = self._status_value(network.get("network_status") or network.get("networkStatus"))
            if name in configured:
                after_names.add(name)
            if name in configured and deploy_enabled.get(name, True) and status.lower() in pending_statuses:
                pending_network_names.add(name)

        # Simulated creations have no controller attachment metadata yet.
        queryable_names = after_names if existing_names is None else after_names.intersection(existing_names)
        deploy_enabled_names = sorted(name for name in queryable_names if deploy_enabled.get(name, True))
        if deploy_enabled_names:
            attachment_details = self.current_attachment_details_ignore_missing(module_args, strategy, deploy_enabled_names)
            for attachment in attachment_details:
                network_name = attachment.get("networkName")
                switch_id = attachment.get("switchId")
                if network_name not in configured or not deploy_enabled.get(network_name, True):
                    continue
                attachment_pending = self.attachment_status(attachment).lower() in pending_statuses
                if attachment.get("attach") is True and attachment_pending:
                    self.record_deploy_target(deploy_targets, network_name, switch_id)
                if attachment.get("attach") is False and self.attachment_has_pending_delete_work(attachment):
                    self.record_deploy_target(deploy_targets, network_name, switch_id)
        for network_name in pending_network_names:
            deploy_targets.setdefault(network_name, set())

        if not deploy_targets:
            return []
        return self.build_deploy_payloads(config, deploy_targets, strategy=strategy, actions=actions)

    def deploy_network_attachments(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        deploy_payload: dict[str, Any],
        undeploy: bool = False,
    ) -> dict[str, Any]:
        """
        Deploy attachment changes at the scope selected for the operation.

        ## Raises

        ### ValueError

        - If deployment has no Network names.
        """
        if not deploy_payload.get("networkNames"):
            raise ValueError("Network deployment requires Network names.")
        observer = staging_observer(self.coordinator)
        if observer is not None:
            observer.deployment_attempts += 1
        self._trace("network_attachment_deploy_start", deploy_payload=deploy_payload, undeploy=undeploy)
        orchestrator, results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint = orchestrator._make_endpoint(strategy.network_actions_deploy_post_cls())
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=deploy_payload,
            operation_type=OperationType.UPDATE,
        )
        trace = self.coordinator._finalize_api_trace(results)
        self._trace("network_attachment_deploy_end", changed=trace.get("changed"), failed=trace.get("failed"))
        return trace

    def deploy_network_switches(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        deploy_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Deploy pending fabric configuration to the selected switches."""
        switch_ids = deploy_payload.get("switchIds") or []
        if not switch_ids:
            raise ValueError("Switch deployment requires affected switch IDs.")
        self._trace("network_switch_deploy_start", deploy_payload=deploy_payload)
        orchestrator, results = self.coordinator._new_network_orchestrator(module_args, strategy)
        endpoint_cls = EpOneManageFabricsSwitchActionsDeployPost if strategy.is_multicluster else EpManageSwitchActionsDeployPost
        endpoint = orchestrator._make_endpoint(endpoint_cls)
        if not strategy.is_multicluster:
            endpoint.endpoint_params.force_show_run = False
        orchestrator._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data={"switchIds": list(switch_ids)},
            operation_type=OperationType.UPDATE,
        )
        trace = self.coordinator._finalize_api_trace(results)
        self._trace("network_switch_deploy_end", changed=trace.get("changed"), failed=trace.get("failed"))
        return trace

    def wait_for_attachments_delete_ready(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
        deadline: float | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        pending = set(network_names if network_names is not None else configured_network_names(module_args.get("config") or []))
        if not pending:
            return
        if deadline is None or timeout_seconds is None:
            deadline, timeout_seconds = self.delete_wait_deadline(len(pending))
        started_at = DeleteReadinessPolicy.now()
        last_blockers: dict[str, list[dict[str, Any]]] = {}
        retried_targets: dict[tuple[str, str], int] = {}
        while True:
            attachments = self._current_attachment_details_for_wait(module_args, strategy, sorted(pending))
            blockers: dict[str, list[dict[str, Any]]] = {name: [] for name in pending}
            retry_targets: dict[str, set[str]] = {}
            for attachment in attachments:
                network_name = attachment.get("networkName")
                if network_name not in pending:
                    continue
                if self.attachment_blocks_delete(attachment):
                    switch_id = attachment.get("switchId")
                    blockers.setdefault(network_name, []).append(
                        {
                            "switchId": switch_id,
                            "attach": attachment.get("attach"),
                            "status": self.attachment_status(attachment),
                        }
                    )
                    retry_key = (network_name, switch_id or "", self.attachment_status(attachment).lower())
                    if retried_targets.get(retry_key, 0) < self.undeploy_retry_attempts:
                        retry_targets.setdefault(network_name, set())
                        if switch_id:
                            retry_targets[network_name].add(switch_id)
                        retried_targets[retry_key] = retried_targets.get(retry_key, 0) + 1
            if retry_targets:
                for deploy_payload in self.build_delete_deploy_payloads(module_args.get("config") or [], retry_targets, strategy=strategy):
                    self.deploy_network_attachments(module_args, strategy, deploy_payload, undeploy=True)
            ready = {name for name, values in blockers.items() if not values}
            pending.difference_update(ready)
            if not pending:
                return
            last_blockers = {name: values for name, values in blockers.items() if name in pending}
            if DeleteReadinessPolicy.now() >= deadline:
                self.coordinator.module.fail_json(
                    msg=f"Timed out waiting for network attachments to become deletable on fabric '{strategy.fabric_name}'.",
                    pending_network_names=sorted(pending),
                    last_blockers=last_blockers,
                    elapsed_seconds=int(DeleteReadinessPolicy.now() - started_at),
                    timeout_seconds=timeout_seconds,
                )
            time.sleep(self.wait_delay)

    def wait_for_networks_delete_ready(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str] | None = None,
        deadline: float | None = None,
        timeout_seconds: int | None = None,
    ) -> None:
        """Wait until Network attachments and Network definitions no longer block deletion."""
        pending = set(network_names if network_names is not None else configured_network_names(module_args.get("config") or []))
        if not pending:
            return
        if deadline is None or timeout_seconds is None:
            deadline, timeout_seconds = self.delete_wait_deadline(len(pending))
        started_at = DeleteReadinessPolicy.now()
        ready_statuses = {"", "na", "notapplicable", "notdeployed", "deleted"}
        retry_statuses = {"pending", "inprogress", "deploymentinprogress", "previewinprogress", "outofsync", "failed"}
        blocking_statuses = {"outofsync", "failed"}
        last_statuses: dict[str, str] = {}
        last_blockers: dict[str, list[dict[str, Any]]] = {}
        retried_targets: dict[tuple[str, str, str], int] = {}
        retried_networks: dict[str, int] = {}
        while True:
            attachments = self._current_attachment_details_for_wait(module_args, strategy, sorted(pending))
            blockers: dict[str, list[dict[str, Any]]] = {name: [] for name in pending}
            attachment_retry_targets: dict[str, set[str]] = {}
            detached_attachment_networks: set[str] = set()
            for attachment in attachments:
                network_name = attachment.get("networkName")
                if network_name not in pending:
                    continue
                if self.attachment_blocks_delete(attachment):
                    switch_id = attachment.get("switchId")
                    status = self.attachment_status(attachment)
                    blockers.setdefault(network_name, []).append(
                        {
                            "switchId": switch_id,
                            "attach": attachment.get("attach"),
                            "status": status,
                        }
                    )
                    retry_key = (network_name, switch_id or "", status.lower())
                    if retried_targets.get(retry_key, 0) < self.undeploy_retry_attempts:
                        attachment_retry_targets.setdefault(network_name, set())
                        if switch_id:
                            attachment_retry_targets[network_name].add(switch_id)
                        retried_targets[retry_key] = retried_targets.get(retry_key, 0) + 1
                else:
                    detached_attachment_networks.add(network_name)

            networks = self.coordinator._query_current_networks_by_names(module_args, strategy, sorted(pending))
            last_statuses = {}
            for network in networks:
                name = network.get("networkName") or network.get("network_name")
                if name in pending:
                    last_statuses[name] = network.get("networkStatus") or network.get("network_status") or ""
            network_retry_targets = {
                name: set()
                for name, status in last_statuses.items()
                if (name in pending and retried_networks.get(name, 0) < self.undeploy_retry_attempts and str(status).strip().lower() in retry_statuses)
            }
            retry_targets = self._merge_deploy_target_maps(attachment_retry_targets, network_retry_targets)
            if retry_targets:
                for deploy_payload in self.build_delete_deploy_payloads(module_args.get("config") or [], retry_targets, strategy=strategy):
                    self.deploy_network_attachments(module_args, strategy, deploy_payload, undeploy=True)
                for network_name in network_retry_targets:
                    retried_networks[network_name] = retried_networks.get(network_name, 0) + 1
            ready = {
                name
                for name in pending
                if not blockers.get(name)
                and str(last_statuses.get(name, "")).strip().lower() not in blocking_statuses
                and (name in detached_attachment_networks or name not in last_statuses or str(last_statuses[name]).strip().lower() in ready_statuses)
            }
            pending.difference_update(ready)
            if not pending:
                return
            last_blockers = {name: values for name, values in blockers.items() if name in pending and values}
            if DeleteReadinessPolicy.now() >= deadline:
                self.coordinator.module.fail_json(
                    msg=f"Timed out waiting for networks to become deletable on fabric '{strategy.fabric_name}'.",
                    pending_network_names=sorted(pending),
                    last_statuses=last_statuses,
                    last_attachment_blockers=last_blockers,
                    elapsed_seconds=int(DeleteReadinessPolicy.now() - started_at),
                    timeout_seconds=timeout_seconds,
                )
            time.sleep(self.wait_delay)

    @staticmethod
    def _merge_deploy_target_maps(*target_maps: dict[str, set[str]]) -> dict[str, set[str]]:
        merged: dict[str, set[str]] = {}
        for target_map in target_maps:
            for network_name, switch_ids in target_map.items():
                merged.setdefault(network_name, set()).update(switch_ids)
        return merged

    def _delete_wait_timeout(self, item_count: int) -> int:
        if self.wait_attempts != type(self).wait_attempts:
            return max(0, int(self.wait_attempts) * int(self.wait_delay))
        return self._delete_wait_policy().timeout_for(item_count)

    def delete_wait_deadline(self, item_count: int) -> tuple[float, int]:
        timeout = self._delete_wait_timeout(item_count)
        return DeleteReadinessPolicy.now() + timeout, timeout

    def _delete_wait_policy(self) -> DeleteReadinessPolicy:
        return DeleteReadinessPolicy(
            poll_interval=self.wait_delay,
            chunk_size=self.wait_chunk_size,
            base_timeout=self.delete_wait_base_timeout,
            extra_chunk_timeout=self.delete_wait_extra_chunk_timeout,
            max_timeout=self.delete_wait_max_timeout,
        )

    def _current_attachment_details_for_wait(
        self,
        module_args: dict,
        strategy: BaseNetworkStrategy,
        network_names: list[str],
    ) -> list[dict[str, Any]]:
        if len(network_names) <= self.wait_chunk_size:
            return self.current_attachment_details_ignore_missing(module_args, strategy, network_names)
        attachments: list[dict[str, Any]] = []
        for index in range(0, len(network_names), self.wait_chunk_size):
            chunk = network_names[index : index + self.wait_chunk_size]
            attachments.extend(self.current_attachment_details_ignore_missing(module_args, strategy, chunk))
        return attachments

    @staticmethod
    def filter_attachment_details_by_network(attachments: list[dict[str, Any]], network_names: list[str] | set[str]) -> list[dict[str, Any]]:
        names = set(network_names)
        return [attachment for attachment in attachments if attachment.get("networkName") in names]

    @staticmethod
    def attachment_has_pending_delete_work(attachment: dict[str, Any]) -> bool:
        pending_statuses = {"deploymentinprogress", "failed", "inprogress", "outofsync", "pending", "previewinprogress"}
        for key in ("status", "configStatus", "deploymentStatus", "networkStatus", "attachmentStatus"):
            status = attachment.get(key)
            if status is not None and NetworkAttachmentManager._status_value(status).lower() in pending_statuses:
                return True
        return False

    @staticmethod
    def attachment_status(attachment: dict[str, Any]) -> str:
        for key in ("status", "configStatus", "deploymentStatus", "networkStatus", "attachmentStatus"):
            status = attachment.get(key)
            if status is not None:
                return NetworkAttachmentManager._status_value(status)
        return ""

    @staticmethod
    def _status_value(status: Any) -> str:
        """Return the plain API status string from raw strings or enum values."""
        return str(getattr(status, "value", status) or "").strip()

    @staticmethod
    def attachment_blocks_delete(attachment: dict[str, Any]) -> bool:
        attach = attachment.get("attach")
        if attach is True or str(attach).strip().lower() == "true":
            return True
        status = NetworkAttachmentManager.attachment_status(attachment).lower()
        if not status:
            return False
        terminal_statuses = {"na", "notapplicable", "notdeployed", "deleted"}
        return status not in terminal_statuses
