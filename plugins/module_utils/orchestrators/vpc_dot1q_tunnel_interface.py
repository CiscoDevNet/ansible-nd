# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Standalone NX-OS dot1qTunnelVpc interface orchestration."""

from __future__ import annotations

from copy import deepcopy
from typing import ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.gathered_filter import filter_gathered_response
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.vpc_dot1q_tunnel_interface import VpcDot1qTunnelInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import VpcInterfaceBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType


class VpcDot1qTunnelInterfaceOrchestrator(VpcInterfaceBaseOrchestrator):
    """Manage dot1qTunnelVpc through the established staged interface lifecycle."""

    model_class: ClassVar[type[NDBaseModel]] = VpcDot1qTunnelInterfaceModel

    def _switches_to_query(self) -> dict[str, str]:
        """Read all switches unless every gathered filter names a specific switch."""
        if self.rest_send.params.get("state") != "gathered":
            return super()._switches_to_query()
        switch_map = self.fabric_context.switch_map
        filters = self.rest_send.params.get("config") or []
        switch_ips = {item["switch_ip"].strip() for item in filters if item.get("switch_ip")}
        for switch_ip in sorted(switch_ips):
            if switch_ip not in switch_map:
                raise ValueError(f"Gathered filter references switch_ip '{switch_ip}' which does not exist in fabric '{self.fabric_name}'.")
        if not filters or any(not item.get("switch_ip") for item in filters):
            return switch_map
        return {ip: switch_id for ip, switch_id in switch_map.items() if ip in switch_ips}

    def _managed_vpc_interfaces(self, switch_ip: str, switch_id: str, managed_types: set[str]) -> list[dict]:
        """Keep matching peer copies before the shared pair deduplication runs.

        Different filter items can name opposite peers with different criteria.
        Filtering only after deduplication could keep the peer that does not
        match and incorrectly discard the whole vPC.
        """
        records = super()._managed_vpc_interfaces(switch_ip, switch_id, managed_types)
        filters = self.rest_send.params.get("config") or []
        if self.rest_send.params.get("state") != "gathered" or not filters:
            return records
        matching = filter_gathered_response(
            response_data=records,
            filters=filters,
            model_class=self.model_class,
            normalize_filter=self.model_class.normalize_gathered_filter,
        )
        names = {model.interface_name for model in matching}
        return [record for record in records if self._canonical_interface_name(record["interfaceName"]) in names]

    def _managed_policy_types(self) -> set[str]:
        """Manage the parent policy, never an Ethernet or generated vPC member."""
        return {"dot1qTunnelVpc"}

    def _dot1q_write_payload(self, data: dict | None) -> dict | None:
        """Select the documented VLAN write shape using the cached ND version.

        ND 4.2.1 requires the same access VLAN in two peer fields. ND 4.3.1
        requires a single accessVlan. Keep the Ansible model and comparisons
        canonical; change only this family's outgoing policy bodies.
        """
        if not isinstance(data, dict):
            return data
        interfaces = data.get("interfaces", [data])
        policies = [((item.get("configData") or {}).get("networkOS") or {}).get("policy") for item in interfaces if isinstance(item, dict)]
        policies = [policy for policy in policies if isinstance(policy, dict) and policy.get("policyType") == "dot1qTunnelVpc" and "accessVlan" in policy]
        if not policies:
            return data
        version = self.rest_send.controller_version or ""
        if version == "4.3.1" or version.startswith("4.3.1."):
            return data
        if version != "4.2.1" and not version.startswith("4.2.1."):
            raise ValueError(f"Cannot select the dot1q vPC VLAN payload for Nexus Dashboard version {version!r}; expected 4.2.1 or 4.3.1.")
        converted = deepcopy(data)
        for item in converted.get("interfaces", [converted]):
            policy = ((item.get("configData") or {}).get("networkOS") or {}).get("policy")
            if isinstance(policy, dict) and policy.get("policyType") == "dot1qTunnelVpc" and "accessVlan" in policy:
                vlan = policy.pop("accessVlan")
                policy.update(peer1AccessVlan=vlan, peer2AccessVlan=vlan)
        return converted

    @staticmethod
    def _without_empty_peer_descriptions(data: dict | None) -> dict | None:
        """Omit only explicit empty descriptions on dot1q vPC policy bodies.

        ND rejects these empty strings. Leaving the keys out of PUT clears the
        descriptions; leaving them out of POST creates an undescribed parent.
        Copy only when a change is needed, preserving the caller's intent.
        """
        if not isinstance(data, dict):
            return data
        rows = data.get("interfaces", [data])
        fields = ("peer1PortChannelDescription", "peer2PortChannelDescription")
        if not any(
            isinstance(row, dict)
            and isinstance(policy := ((row.get("configData") or {}).get("networkOS") or {}).get("policy"), dict)
            and policy.get("policyType") == "dot1qTunnelVpc"
            and any(policy.get(field) == "" for field in fields)
            for row in rows
        ):
            return data
        converted = deepcopy(data)
        for row in converted.get("interfaces", [converted]):
            policy = ((row.get("configData") or {}).get("networkOS") or {}).get("policy")
            if isinstance(policy, dict) and policy.get("policyType") == "dot1qTunnelVpc":
                for field in fields:
                    if policy.get(field) == "":
                        policy.pop(field)
        return converted

    def _bulk_full_modify_guard(self, model_instance: NDBaseModel, current: dict) -> bool:
        """Keep description clearing on the qualified singular PUT path."""
        config = getattr(model_instance, "config_data", None)
        policy = config.network_os.policy if config is not None else None
        if policy is not None and any(getattr(policy, field) == "" for field in ("peer1_port_channel_description", "peer2_port_channel_description")):
            return False
        return super()._bulk_full_modify_guard(model_instance, current)

    def _request(
        self,
        path: str,
        verb: HttpVerbEnum,
        data: dict | None = None,
        not_found_ok: bool = False,
        operation_type: OperationType = OperationType.QUERY,
    ) -> ResponseType:
        """Adapt only write payloads; retain shared request and failure handling."""
        if verb in (HttpVerbEnum.POST, HttpVerbEnum.PUT):
            data = self._dot1q_write_payload(data)
            data = self._without_empty_peer_descriptions(data)
        return super()._request(path, verb, data, not_found_ok, operation_type)
