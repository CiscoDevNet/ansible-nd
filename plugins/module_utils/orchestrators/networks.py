# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Orchestrator for ND Manage network CRUD operations."""

from __future__ import annotations

import json
import time

from typing import Any, Callable, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    NetworkLayer,
    NetworkType,
    VlanNetworkType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_actions_models import (
    NetworkRemoveRequestModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import (
    ClassicOrRoutedL2DataModel,
    ClassicOrRoutedL3DataModel,
    DefaultL2DataModel,
    DefaultL2FabricDataModel,
    DefaultL3DataModel,
    NetworkBaseModel,
    VxlanL3FabricDataModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_network import (
    BaseNetworkStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_networks import (
    EpManageFabricsNetworksPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_network_actions import (
    EpManageFabricsNetworkActionsRemovePost,
)

NDNetworkModel = NetworkBaseModel

_VLAN_NETWORK_TYPE_ALIASES = {
    "normal": "normal",
    "primary": "privatePrimary",
    "privatePrimary": "privatePrimary",
    "community": "privateSecondaryCommunity",
    "privateSecondaryCommunity": "privateSecondaryCommunity",
    "isolated": "privateSecondaryIsolated",
    "privateSecondaryIsolated": "privateSecondaryIsolated",
}
_PRIVATE_SECONDARY_TEMPLATE_BY_TYPE = {
    "privateSecondaryCommunity": "Community",
    "privateSecondaryIsolated": "Isolated",
}


class NDNetworkOrchestrator(NDBaseOrchestrator["NDNetworkModel"]):
    """CRUD orchestrator for networks, with strategy-selected endpoints."""

    model_class: ClassVar[type[NDBaseModel]] = NDNetworkModel
    supports_bulk_create: ClassVar[bool] = True
    supports_bulk_delete: ClassVar[bool] = True
    supports_bulk_update: ClassVar[bool] = False

    create_endpoint: type | None = None
    update_endpoint: type | None = None
    delete_endpoint: type | None = None
    query_one_endpoint: type | None = None
    query_all_endpoint: type | None = None
    create_bulk_endpoint: type | None = EpManageFabricsNetworksPost
    delete_bulk_endpoint: type | None = EpManageFabricsNetworkActionsRemovePost

    strategy: BaseNetworkStrategy | None = None
    trace_hook: Callable[..., None] | None = None
    delete_retry_attempts: ClassVar[int] = 3
    delete_retry_delay: ClassVar[int] = 30
    scoped_query_threshold: ClassVar[int] = 5
    unfiltered_query_page_size: ClassVar[int] = 10000
    definition_intent_fields: ClassVar[set[str]] = {
        "network_template_name",
        "networkTemplateName",
        "network_extension_template_name",
        "networkExtensionTemplateName",
        "service_network_template_name",
        "serviceNetworkTemplateName",
        "network_template_config",
        "networkTemplateConfig",
        "network_id",
        "networkId",
        "network_type",
        "networkType",
        "display_name",
        "displayName",
        "vrf_name",
        "vrfName",
        "vlan_id",
        "vlanId",
        "layer",
        "vlan_name",
        "vlanName",
        "route_target_both",
        "routeTargetBoth",
        "x_connect",
        "xConnect",
        "multicast_group_address",
        "multicastGroup",
        "ds_vni",
        "dsVni",
        "gateway_ipv4_address",
        "gatewayIpv4Address",
        "gateway_ipv6_address",
        "gatewayIpv6Address",
        "secondary_gateway_ipv4_collection",
        "secondaryGatewayIpv4Collection",
        "secondary_gateway_ipv6_collection",
        "secondaryGatewayIpv6Collection",
        "vlan_intf_desc",
        "vlanIntfDesc",
        "routing_tag",
        "routingTag",
        "dhcp_servers",
        "dhcpServers",
        "loopback_id",
        "loopbackId",
        "igmp_version",
        "igmpVersion",
        "trm_enable",
        "trmEnable",
        "ipv6_trm",
        "ipv6Trm",
        "l2_netflow_monitor",
        "l2NetflowMonitor",
        "l3_netflow_monitor",
        "l3NetflowMonitor",
        "netflow_sampler",
        "netflowSampler",
        "gateway_on_border",
        "gatewayOnBorder",
        "child_fabric_config",
        "childFabricConfig",
    }

    def model_post_init(self, __context) -> None:
        if self.strategy is None:
            raise ValueError("NDNetworkOrchestrator requires a strategy instance.")

    @staticmethod
    def _value(config: dict[str, Any], *names: str, default: Any = None) -> Any:
        for name in names:
            if name in config:
                return config[name]
        return default

    def _default_network_type(self) -> str:
        fabric_data = self.strategy.fabric_data if self.strategy else {}
        for key in ("network_type", "networkType", "managementType"):
            if isinstance(fabric_data, dict) and fabric_data.get(key):
                return fabric_data[key]
        details = fabric_data.get("manageFabricDetails") if isinstance(fabric_data, dict) else {}
        management = details.get("management") if isinstance(details, dict) else {}
        if isinstance(management, dict) and management.get("type"):
            return management["type"]
        return NetworkType.VXLAN_IBGP.value

    def _network_layer(self, config: dict[str, Any]) -> str:
        explicit = self._value(config, "layer")
        if explicit:
            return explicit
        return NetworkLayer.LAYER3.value

    @staticmethod
    def _allows_l3_data(vlan_network_type: str | None) -> bool:
        return vlan_network_type in (None, VlanNetworkType.NORMAL.value, VlanNetworkType.PRIVATE_PRIMARY.value)

    def _l2_data(self, config: dict[str, Any], network_type: str) -> dict[str, Any] | None:
        fabric_data_payload = None
        kwargs = {
            "vlan_name": self._value(config, "vlan_name", "vlanName"),
        }
        if network_type in (
            NetworkType.ROUTED.value,
            NetworkType.AIML_ROUTED.value,
            NetworkType.CLASSIC_LAN_ENHANCED.value,
        ):
            model = ClassicOrRoutedL2DataModel(**{k: v for k, v in kwargs.items() if v is not None})
        else:
            fabric_data_value: dict[str, Any] = {}
            for target, names in {
                "multicast_group": ("multicast_group_address", "multicastGroup", "multicast_group"),
                "ds_vni": ("ds_vni", "dsVni"),
            }.items():
                value = self._value(config, *names)
                if value is not None:
                    fabric_data_value[target] = value

            if fabric_data_value:
                fabric_data_payload = DefaultL2FabricDataModel(**fabric_data_value).to_payload(exclude_unset=bool(self.strategy and self.strategy.is_child))

            kwargs.update(
                {
                    "rt_auto": self._rt_auto_from_route_target_both(config),
                    "x_connect": self._value(config, "x_connect", "xConnect"),
                    "fabric_data": fabric_data_payload,
                }
            )
            model = DefaultL2DataModel(**{k: v for k, v in kwargs.items() if v is not None})
        payload = model.to_payload(exclude_unset=bool(self.strategy and self.strategy.is_child))
        if fabric_data_payload and isinstance(payload, dict):
            payload["fabricData"] = fabric_data_payload
        return payload or None

    def _rt_auto_from_route_target_both(self, config: dict[str, Any]) -> bool | None:
        route_target_both = self._value(config, "route_target_both", "routeTargetBoth")
        if route_target_both is None:
            return None
        return bool(route_target_both)

    def _l3_data(self, config: dict[str, Any], network_type: str) -> dict[str, Any] | None:
        common = {
            "gateway_ipv4_address": self._value(config, "gateway_ipv4_address", "gatewayIpv4Address"),
            "gateway_ipv6_address": self._value(config, "gateway_ipv6_address", "gatewayIpv6Address"),
            "vlan_interface_description": self._value(config, "vlan_intf_desc", "vlanIntfDesc", "vlanInterfaceDescription"),
            "mtu": self._value(config, "mtu"),
            "routing_tag": self._value(config, "routing_tag", "routingTag"),
        }
        if network_type in (
            NetworkType.ROUTED.value,
            NetworkType.AIML_ROUTED.value,
            NetworkType.CLASSIC_LAN_ENHANCED.value,
        ):
            model = ClassicOrRoutedL3DataModel(**{k: v for k, v in common.items() if v is not None})
            payload = model.to_payload(exclude_unset=bool(self.strategy and self.strategy.is_child))
            return payload or None

        fabric_data = VxlanL3FabricDataModel(
            dhcp_servers=self._value(config, "dhcp_servers", "dhcpServers"),
            loopback_id=self._value(config, "loopback_id", "loopbackId"),
            igmp_version=self._value(config, "igmp_version", "igmpVersion"),
            netflow=self._value(
                config,
                "netflow_enable",
                "netflowEnable",
                "netflow",
                default=None if self.strategy and self.strategy.is_child else False,
            ),
            l2_netflow_monitor=self._value(config, "l2_netflow_monitor", "l2NetflowMonitor"),
            l3_netflow_monitor=self._value(config, "l3_netflow_monitor", "l3NetflowMonitor"),
            netflow_sampler=self._value(config, "netflow_sampler", "netflowSampler"),
            gateway_on_border=self._value(config, "gateway_on_border", "gatewayOnBorder"),
            ipv4_trm=self._value(config, "trm_enable", "trmEnable", "ipv4Trm"),
            ipv6_trm=self._value(config, "ipv6_trm", "ipv6Trm"),
        )
        model = DefaultL3DataModel(
            **{k: v for k, v in common.items() if v is not None},
            secondary_gateway_ipv4_collection=self._value(
                config,
                "secondary_gateway_ipv4_collection",
                "secondaryGatewayIpv4Collection",
            ),
            secondary_gateway_ipv6_collection=self._value(
                config,
                "secondary_gateway_ipv6_collection",
                "secondaryGatewayIpv6Collection",
            ),
            arp_suppression=self._value(config, "arp_suppression", "arpSuppression", default=False),
            fabric_data=fabric_data,
        )
        payload = model.to_payload(exclude_unset=bool(self.strategy and self.strategy.is_child))
        return payload or None

    def _transform_config_to_payload_model_data(self, config: dict[str, Any], fabric_name: str) -> dict[str, Any]:
        if not self.has_network_definition_intent(config):
            return {
                "fabric_name": self._value(config, "fabric_name", "fabricName", default=fabric_name),
                "network_name": self._value(config, "network_name", "networkName"),
            }

        custom_template_fields = {
            "network_template_name": ("network_template_name", "networkTemplateName"),
            "network_extension_template_name": ("network_extension_template_name", "networkExtensionTemplateName"),
            "service_network_template_name": ("service_network_template_name", "serviceNetworkTemplateName"),
            "network_template_config": ("network_template_config", "networkTemplateConfig"),
        }
        explicit_network_type = self._value(config, "network_type", "networkType")
        has_custom_template_fields = any(self._value(config, *names) is not None for names in custom_template_fields.values())
        network_type = explicit_network_type or (NetworkType.USER_DEFINED.value if has_custom_template_fields else self._default_network_type())
        transformed: dict[str, Any] = {
            "fabric_name": self._value(config, "fabric_name", "fabricName", default=fabric_name),
            "network_name": self._value(config, "network_name", "networkName"),
            "network_type": network_type,
        }
        for target, names in {
            "display_name": ("display_name", "displayName"),
            "vrf_name": ("vrf_name", "vrfName"),
            "vlan_id": ("vlan_id", "vlanId"),
            "network_id": ("network_id", "networkId"),
            "vlan_network_type": ("vlan_network_type", "vlanNetworkType"),
            "primary_network_id": ("primary_network_id", "primaryNetworkId"),
        }.items():
            value = self._value(config, *names)
            if value is not None:
                transformed[target] = value

        for target, names in custom_template_fields.items():
            value = self._value(config, *names)
            if value is not None:
                if network_type != NetworkType.USER_DEFINED.value:
                    raise ValueError(f"{target} requires network_type={NetworkType.USER_DEFINED.value}")
                transformed[target] = value

        if network_type == NetworkType.USER_DEFINED.value:
            return transformed

        vlan_network_type = self._normalize_vlan_network_type(transformed.get("vlan_network_type"))
        if vlan_network_type in _PRIVATE_SECONDARY_TEMPLATE_BY_TYPE:
            return self._private_secondary_payload_model_data(config, fabric_name, vlan_network_type, transformed)
        transformed["vlan_network_type"] = vlan_network_type

        layer = self._network_layer(config)
        transformed["layer"] = layer
        if layer == NetworkLayer.LAYER2.value and transformed.get("vrf_name") in (None, ""):
            transformed["vrf_name"] = "NA"
        l2_data = self._l2_data(config, network_type)
        if l2_data:
            transformed["l2_data"] = l2_data
        if layer == NetworkLayer.LAYER3.value:
            l3_data = self._l3_data(config, network_type)
            if l3_data:
                transformed["l3_data"] = l3_data
        return transformed

    @staticmethod
    def _normalize_vlan_network_type(value: Any) -> str:
        if value in (None, ""):
            return "normal"
        normalized = _VLAN_NETWORK_TYPE_ALIASES.get(str(value))
        if normalized is None:
            raise ValueError("vlan_network_type must be one of: " + ", ".join(sorted(_VLAN_NETWORK_TYPE_ALIASES)))
        return normalized

    def _private_secondary_payload_model_data(
        self,
        config: dict[str, Any],
        fabric_name: str,
        vlan_network_type: str,
        transformed: dict[str, Any],
    ) -> dict[str, Any]:
        template_config = {
            "isLayer2Only": "true",
            "networkMode": NetworkLayer.LAYER2.value,
            "networkName": self._value(config, "network_name", "networkName"),
            "networkType": NetworkType.USER_DEFINED.value,
            "nveId": "1",
            "rtBothAuto": self._template_config_string(self._value(config, "route_target_both", "routeTargetBoth", default=False)),
            "segmentId": self._template_config_string(self._value(config, "network_id", "networkId")),
            "type": _PRIVATE_SECONDARY_TEMPLATE_BY_TYPE[vlan_network_type],
            "vlanId": self._template_config_string(self._value(config, "vlan_id", "vlanId")),
            "vrfName": "NA",
        }
        vlan_name = self._value(config, "vlan_name", "vlanName")
        if vlan_name is not None:
            template_config["vlanName"] = self._template_config_string(vlan_name)
        multicast_group = self._value(config, "multicast_group_address", "multicastGroup")
        if multicast_group is not None:
            template_config["mcastGroup"] = self._template_config_string(multicast_group)

        result: dict[str, Any] = {
            "fabric_name": fabric_name,
            "network_name": transformed["network_name"],
            "network_type": NetworkType.USER_DEFINED.value,
            "vlan_network_type": vlan_network_type,
            "display_name": transformed.get("display_name") or transformed["network_name"],
            "vrf_name": "NA",
            "network_id": transformed.get("network_id"),
            "layer": NetworkLayer.LAYER2.value,
            "network_template_name": "Pvlan_Secondary_Network",
            "network_extension_template_name": "Pvlan_Secondary_Network",
            "network_template_config": template_config,
        }
        primary_network_id = self._value(config, "primary_network_id", "primaryNetworkId")
        if primary_network_id is not None:
            result["primary_network_id"] = primary_network_id
        return result

    @staticmethod
    def _template_config_string(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    @classmethod
    def has_network_definition_intent(cls, config: dict[str, Any]) -> bool:
        if any(key in config and config[key] is not None for key in cls.definition_intent_fields):
            return True
        default_sensitive_fields = {
            "netflow_enable": False,
            "netflowEnable": False,
            "arp_suppression": False,
            "arpSuppression": False,
            "mtu": 9216,
        }
        return any(config.get(key) not in (None, default) for key, default in default_sensitive_fields.items() if key in config)

    def prepare_config_data(self, raw_config):
        if not isinstance(raw_config, list):
            return raw_config
        fabric_name = self.strategy.fabric_name
        result = []
        if self.strategy and self.strategy.is_child:
            self._child_payload_source_by_name = {}
        for entry in raw_config:
            if isinstance(entry, dict):
                transformed = self._transform_config_to_payload_model_data(entry, fabric_name)
                if self.strategy and self.strategy.is_child and transformed.get("network_name"):
                    self._child_payload_source_by_name[transformed["network_name"]] = transformed
                result.append(transformed)
            else:
                result.append(entry)
        return result

    def _make_endpoint(self, endpoint_cls, **extra_fields):
        ep = endpoint_cls()
        ep.fabric_name = self.strategy.fabric_name
        self.strategy.configure_endpoint(ep)
        for attr, val in extra_fields.items():
            setattr(ep, attr, val)
        return ep

    def _trace(self, event: str, **details: Any) -> None:
        if self.trace_hook is not None:
            self.trace_hook(event, **details)

    def _request(
        self,
        path: str,
        verb,
        data: dict[str, Any] | None = None,
        not_found_ok: bool = False,
        operation_type: OperationType = OperationType.QUERY,
    ) -> ResponseType:
        self._trace(
            "api_request_start",
            path=path,
            verb=getattr(verb, "value", str(verb)),
            operation_type=operation_type.value,
            payload=data,
            not_found_ok=not_found_ok,
        )
        try:
            response = super()._request(
                path=path,
                verb=verb,
                data=data,
                not_found_ok=not_found_ok,
                operation_type=operation_type,
            )
        except Exception as exc:
            self._trace(
                "api_request_error",
                path=path,
                verb=getattr(verb, "value", str(verb)),
                operation_type=operation_type.value,
                payload=data,
                error=repr(exc),
            )
            raise
        self._trace(
            "api_request_end",
            path=path,
            verb=getattr(verb, "value", str(verb)),
            operation_type=operation_type.value,
            response_summary=self._response_summary(response),
        )
        return response

    @staticmethod
    def _response_summary(response: Any) -> dict[str, Any]:
        if isinstance(response, dict):
            summary: dict[str, Any] = {"type": "dict", "keys": sorted(response.keys())}
            for key in ("networks", "items", "attachments", "results"):
                value = response.get(key)
                if isinstance(value, list):
                    summary[f"{key}_count"] = len(value)
            metadata = response.get("metadata") or response.get("meta")
            if isinstance(metadata, dict):
                summary["metadata"] = metadata
            return summary
        if isinstance(response, list):
            return {"type": "list", "count": len(response)}
        return {"type": type(response).__name__}

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        scoped_network_names = self._query_scope_network_names()
        try:
            if not scoped_network_names:
                return self._query_all_unfiltered()
            if self._is_mcfg_parent():
                return self._filter_query_items_by_name(self._query_all_unfiltered(), scoped_network_names)
            if len(scoped_network_names) >= self.scoped_query_threshold:
                return self._query_all_unfiltered()
            if len(scoped_network_names) > 1:
                return self._query_all_scoped(scoped_network_names)
            endpoint = self._make_endpoint(self.strategy.networks_get_cls())
            if scoped_network_names and hasattr(endpoint, "endpoint_params"):
                endpoint.endpoint_params.filter = self._network_name_filter(scoped_network_names)
            result = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
            if isinstance(result, dict):
                return self._normalize_query_network_items(result.get("networks") or result.get("items") or [])
            return self._normalize_query_network_items(result)
        except Exception as exc:
            if scoped_network_names:
                return self._query_all_unfiltered()
            raise Exception(f"Query all networks failed: {exc}") from exc

    def _query_all_scoped(self, network_names: list[str]) -> ResponseType:
        networks: list[dict[str, Any]] = []
        seen: set[str] = set()
        ordered_names = list(dict.fromkeys(network_names))
        self._append_scoped_network_items(networks, seen, self._query_all_scoped_batch(ordered_names), ordered_names)
        return networks

    @staticmethod
    def _filter_query_items_by_name(items: list[Any], network_names: list[str]) -> list[Any]:
        requested = set(network_names)
        return [item for item in items or [] if not isinstance(item, dict) or (item.get("networkName") or item.get("network_name")) in requested]

    def _query_all_scoped_batch(self, network_names: list[str]) -> list[dict[str, Any]]:
        endpoint = self._make_endpoint(self.strategy.networks_get_cls())
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.filter = (
                self._network_name_filter(network_names) if len(network_names) == 1 else self._network_names_unfielded_filter(network_names)
            )
            endpoint.endpoint_params.max = self.unfiltered_query_page_size if len(network_names) > 1 else 1
        result = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        if isinstance(result, dict):
            return result.get("networks") or result.get("items") or []
        return result or []

    def _query_all_scoped_one(self, network_name: str) -> list[dict[str, Any]]:
        endpoint = self._make_endpoint(self.strategy.networks_get_cls())
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.filter = self._network_name_filter([network_name])
        result = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        if isinstance(result, dict):
            return result.get("networks") or result.get("items") or []
        return result or []

    def _append_scoped_network_items(
        self,
        networks: list[dict[str, Any]],
        seen: set[str],
        items: list[dict[str, Any]],
        requested_names: list[str],
    ) -> None:
        requested = set(requested_names)
        for item in items or []:
            item_name = item.get("networkName") or item.get("network_name") if isinstance(item, dict) else None
            if item_name and item_name in requested and item_name not in seen:
                networks.append(self._normalize_query_network_item(item))
                seen.add(item_name)

    def _query_all_unfiltered(self) -> ResponseType:
        networks: list[dict[str, Any]] = []
        offset = 0

        while True:
            endpoint = self._make_endpoint(self.strategy.networks_get_cls())
            if hasattr(endpoint, "endpoint_params"):
                endpoint.endpoint_params.max = self.unfiltered_query_page_size
                endpoint.endpoint_params.offset = offset

            result = self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True, operation_type=OperationType.QUERY)
            page_items = self._network_items_from_query_result(result)
            networks.extend(page_items)

            if not self._has_more_unfiltered_pages(result, len(page_items), len(networks)):
                break
            if not page_items:
                break
            offset += len(page_items)

        return self._normalize_query_network_items(networks)

    @staticmethod
    def _network_items_from_query_result(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, dict):
            return result.get("networks") or result.get("items") or []
        return result or []

    @staticmethod
    def _safe_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _has_more_unfiltered_pages(self, result: Any, page_count: int, total_seen: int) -> bool:
        if not isinstance(result, dict):
            return False

        metadata = result.get("metadata") or {}
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

        return page_count == self.unfiltered_query_page_size

    def _query_scope_network_names(self) -> list[str]:
        state = self.rest_send.params.get("state")
        if state not in ("merged", "replaced", "deleted"):
            return []
        config = self.rest_send.params.get("config") or []
        names: list[str] = []
        seen: set[str] = set()
        for item in config:
            if isinstance(item, dict):
                name = item.get("network_name") or item.get("networkName")
                if name and name not in seen:
                    names.append(name)
                    seen.add(name)
        return names

    @staticmethod
    def _network_name_filter(network_names: list[str]) -> str:
        terms = [f"networkName:{name}" for name in sorted(set(network_names))]
        expression = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
        return expression

    @staticmethod
    def _network_names_unfielded_filter(network_names: list[str]) -> str:
        terms = sorted(set(network_names))
        expression = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
        return expression

    def _is_mcfg_parent(self) -> bool:
        return bool(getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False))

    def _normalize_query_network_item(self, item: Any) -> Any:
        if not isinstance(item, dict):
            return item

        normalized = dict(item)
        if self._is_mcfg_parent():
            if not normalized.get("fabricName"):
                normalized["fabricName"] = normalized.get("fabric") or self.strategy.fabric_name
            if not normalized.get("vrfName") and normalized.get("vrf"):
                normalized["vrfName"] = normalized.get("vrf")
            if not normalized.get("networkType"):
                normalized["networkType"] = self._default_network_type()
            if normalized.get("networkStatus") == "NA":
                normalized["networkStatus"] = "notApplicable"
        for optional_id in ("primaryNetworkId", "normalNetworkId"):
            if normalized.get(optional_id) in (0, "0", ""):
                normalized.pop(optional_id, None)

        template_config = normalized.get("networkTemplateConfig")
        if isinstance(template_config, str):
            try:
                template_config = json.loads(template_config)
            except ValueError:
                template_config = {}
        if isinstance(template_config, dict):
            template_config = {str(key): "" if value is None else str(value) for key, value in template_config.items()}
            normalized["networkTemplateConfig"] = template_config
            normalized.update(self._schema_fields_from_top_down_template(template_config))
            template_type = str(template_config.get("type") or "").strip().lower()
            if template_type == "community":
                normalized["vlanNetworkType"] = VlanNetworkType.PRIVATE_SECONDARY_COMMUNITY.value
            elif template_type == "isolated":
                normalized["vlanNetworkType"] = VlanNetworkType.PRIVATE_SECONDARY_ISOLATED.value
        return normalized

    def _normalize_query_network_items(self, items: Any) -> list[Any]:
        return [self._normalize_query_network_item(item) for item in (items or [])]

    @staticmethod
    def _top_down_bool(value: Any) -> bool | None:
        if isinstance(value, bool):
            return value
        if value is None or value == "":
            return None
        return str(value).strip().lower() == "true"

    @staticmethod
    def _top_down_int(value: Any) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _top_down_list(value: Any) -> list[str] | None:
        if value is None or value == "":
            return None
        if isinstance(value, list):
            return [str(item) for item in value if str(item)]
        return [item.strip() for item in str(value).split(",") if item.strip()]

    def _schema_fields_from_top_down_template(self, template_config: dict[str, Any]) -> dict[str, Any]:
        converted: dict[str, Any] = {}

        for target, source in {
            "networkId": "segmentId",
            "vlanId": "vlanId",
        }.items():
            value = self._top_down_int(template_config.get(source))
            if value is not None:
                converted[target] = value

        layer2_only = self._top_down_bool(template_config.get("isLayer2Only"))
        converted["layer"] = NetworkLayer.LAYER2.value if layer2_only else NetworkLayer.LAYER3.value

        l2_fabric_data = {
            "multicastGroup": template_config.get("mcastGroup"),
        }
        l2_fabric_data = {key: value for key, value in l2_fabric_data.items() if value not in (None, "")}
        l2_data = {
            "vlanName": template_config.get("vlanName"),
            "rtAuto": self._top_down_bool(template_config.get("rtBothAuto")),
        }
        l2_data = {key: value for key, value in l2_data.items() if value not in (None, "")}
        if l2_fabric_data:
            l2_data["fabricData"] = l2_fabric_data
        if l2_data:
            converted["l2Data"] = l2_data

        dhcp_servers = self._schema_dhcp_servers_from_top_down(template_config.get("dhcpServers"))
        l3_fabric_data = {
            "dhcpServers": dhcp_servers,
            "loopbackId": self._top_down_int(template_config.get("loopbackId")),
            "netflow": self._top_down_bool(template_config.get("ENABLE_NETFLOW")),
            "l2NetflowMonitor": template_config.get("l2NetflowMonitor") or template_config.get("vlanNfMonitor"),
            "l3NetflowMonitor": template_config.get("l3NetflowMonitor") or template_config.get("intfVlanNfMonitor"),
            "netflowSampler": template_config.get("netflowSampler"),
            "gatewayOnBorder": self._top_down_bool(template_config.get("enableL3OnBorder")),
            "ipv4Trm": self._top_down_bool(template_config.get("trmEnabled")),
        }
        l3_fabric_data = {key: value for key, value in l3_fabric_data.items() if value not in (None, "", [])}

        l3_data = {
            "gatewayIpv4Address": template_config.get("gatewayIpAddress"),
            "gatewayIpv6Address": template_config.get("gatewayIpV6Address"),
            "secondaryGatewayIpv4Collection": self._top_down_list_from_keys(template_config, "secondaryGW1", "secondaryGW2", "secondaryGW3", "secondaryGW4"),
            "vlanInterfaceDescription": template_config.get("intfDescription"),
            "mtu": self._top_down_int(template_config.get("mtu")),
            "arpSuppression": self._top_down_bool(template_config.get("suppressArp")),
            "routingTag": self._top_down_int(template_config.get("tag")),
        }
        l3_data = {key: value for key, value in l3_data.items() if value not in (None, "", [])}
        if l3_fabric_data:
            l3_data["fabricData"] = l3_fabric_data
        if l3_data:
            converted["l3Data"] = l3_data

        return converted

    @staticmethod
    def _top_down_list_from_keys(template_config: dict[str, Any], *keys: str) -> list[str] | None:
        values = [str(template_config[key]) for key in keys if template_config.get(key) not in (None, "")]
        return values or None

    @staticmethod
    def _schema_dhcp_servers_from_top_down(value: Any) -> list[dict[str, Any]] | None:
        if value in (None, "", []):
            return None
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return None
        servers = value.get("dhcpServers") if isinstance(value, dict) else value
        if not isinstance(servers, list):
            return None
        normalized = []
        for server in servers:
            if not isinstance(server, dict):
                continue
            address = server.get("serverAddress") or server.get("srvrAddr")
            if not address:
                continue
            normalized.append({"serverAddress": address, "serverVrf": server.get("serverVrf") or server.get("srvrVrf")})
        return normalized or None

    @staticmethod
    def _nested_payload(value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if hasattr(value, "to_payload"):
            return value.to_payload()
        return {}

    @staticmethod
    def _template_value(value: Any) -> Any:
        if value is None:
            return ""
        if isinstance(value, list):
            return ",".join(str(item) for item in value)
        return value

    def _top_down_dhcp_servers(self, dhcp_servers: Any) -> str:
        servers = []
        for server in dhcp_servers or []:
            if not isinstance(server, dict):
                server = self._nested_payload(server)
            address = server.get("serverAddress") or server.get("server_address") or server.get("srvrAddr")
            if not address:
                continue
            servers.append({"srvrAddr": address, "srvrVrf": server.get("serverVrf") or server.get("server_vrf") or server.get("srvrVrf") or ""})
        return json.dumps({"dhcpServers": servers}, separators=(",", ":")) if servers else ""

    def _top_down_network_payload(self, model_instance: NDNetworkModel) -> dict[str, Any]:
        l2_data = self._nested_payload(model_instance.l2_data)
        l3_data = self._nested_payload(model_instance.l3_data)
        l2_fabric_data = self._nested_payload(l2_data.get("fabricData"))
        l3_fabric_data = self._nested_payload(l3_data.get("fabricData"))
        management = ((self.strategy.fabric_data or {}).get("manageFabricDetails") or {}).get("management") or {}

        if model_instance.network_template_config:
            template_config = {key: self._template_value(value) for key, value in model_instance.network_template_config.items()}
            template_config.setdefault("segmentId", self._template_value(model_instance.network_id))
            template_config.setdefault("networkName", model_instance.network_name)
            template_config.setdefault("vlanId", self._template_value(model_instance.vlan_id))
        else:
            template_config = {
                "segmentId": self._template_value(model_instance.network_id),
                "networkName": model_instance.network_name,
                "vlanId": self._template_value(model_instance.vlan_id),
                "gatewayIpAddress": self._template_value(l3_data.get("gatewayIpv4Address")),
                "isLayer2Only": model_instance.layer == NetworkLayer.LAYER2.value,
                "tag": self._template_value(l3_data.get("routingTag")),
                "vlanName": self._template_value(l2_data.get("vlanName")),
                "rtBothAuto": self._template_value(l2_data.get("rtAuto")),
                "intfDescription": self._template_value(l3_data.get("vlanInterfaceDescription")),
                "mtu": self._template_value(l3_data.get("mtu")),
                "suppressArp": self._template_value(l3_data.get("arpSuppression")),
                "dhcpServers": self._top_down_dhcp_servers(l3_fabric_data.get("dhcpServers")),
                "loopbackId": self._template_value(l3_fabric_data.get("loopbackId")),
                "mcastGroup": self._template_value(l2_fabric_data.get("multicastGroup")),
                "gatewayIpV6Address": self._template_value(l3_data.get("gatewayIpv6Address")),
                "trmEnabled": self._template_value(l3_fabric_data.get("ipv4Trm")),
                "enableL3OnBorder": self._template_value(l3_fabric_data.get("gatewayOnBorder")),
                "ENABLE_NETFLOW": self._template_value(l3_fabric_data.get("netflow")),
            }
            for index, gateway in enumerate(l3_data.get("secondaryGatewayIpv4Collection") or [], start=1):
                if index <= 4:
                    template_config[f"secondaryGW{index}"] = gateway
            for index in range(1, 5):
                template_config.setdefault(f"secondaryGW{index}", "")

        return {
            "fabric": self.strategy.fabric_name,
            "vrf": model_instance.vrf_name or "NA",
            "networkName": model_instance.network_name,
            "displayName": model_instance.display_name or model_instance.network_name,
            "networkId": model_instance.network_id,
            "networkTemplate": model_instance.network_template_name or management.get("networkTemplate") or "Default_Network_Universal",
            "networkExtensionTemplate": model_instance.network_extension_template_name
            or management.get("networkExtensionTemplate")
            or "Default_Network_Extension_Universal",
            "networkTemplateConfig": json.dumps(template_config),
        }

    def _mcfg_parent_network_payload(self, model_instance: NDNetworkModel) -> dict[str, Any]:
        """Build the schema-style OneManage manage payload for MCFG parent Network operations."""
        payload = model_instance.to_payload()
        payload["fabricName"] = self.strategy.fabric_name
        payload.setdefault("networkType", self._default_network_type())
        payload.setdefault("displayName", model_instance.network_name)
        payload.pop("vlanId", None)
        network_mode = payload.pop("layer", None)
        if network_mode:
            payload["networkMode"] = network_mode
        if payload.get("networkType") == NetworkType.VXLAN.value:
            payload.setdefault("vlanNetworkType", "normal")
        if not payload.get("vrfName") and payload.get("networkMode") == NetworkLayer.LAYER2.value:
            payload["vrfName"] = "NA"

        l2_data = payload.get("l2Data")
        if isinstance(l2_data, dict):
            l2_data = dict(l2_data)
            l2_data["vlanName"] = ""
            l2_data["fabricData"] = {}
            payload["l2Data"] = l2_data

        if not self._allows_l3_data(payload.get("vlanNetworkType")):
            payload.pop("l3Data", None)
            return payload

        if payload.get("networkMode") == NetworkLayer.LAYER2.value:
            payload["l3Data"] = self._mcfg_parent_default_l3_data()
            return payload

        return payload

    def _child_network_update_payload(self, model_instance: NDNetworkModel) -> dict[str, Any]:
        """Build a child-fabric update payload using current context plus requested fabric-data deltas."""
        source_model = model_instance
        source_by_name = getattr(self, "_child_payload_source_by_name", {})
        source_config = source_by_name.get(model_instance.network_name)
        if source_config:
            source_model = self.model_class.from_config(source_config)
        source = source_model.to_payload(exclude_unset=True)

        payload = model_instance.to_payload()
        payload["fabricName"] = self.strategy.fabric_name
        payload["networkName"] = source.get("networkName") or payload["networkName"]
        payload.setdefault("displayName", payload["networkName"])
        payload["networkType"] = source.get("networkType") or payload.get("networkType") or self._default_network_type()

        source_layer = source.get("layer")
        payload_layer = payload.pop("layer", None)
        network_mode = source_layer or payload_layer
        if network_mode:
            payload["networkMode"] = network_mode
        if payload.get("networkType") in (
            NetworkType.VXLAN.value,
            NetworkType.VXLAN_IBGP.value,
            NetworkType.VXLAN_EBGP.value,
            NetworkType.AIML_VXLAN_IBGP.value,
            NetworkType.AIML_VXLAN_EBGP.value,
        ):
            payload.setdefault("vlanNetworkType", "normal")
        if not payload.get("vrfName") and payload.get("networkMode") == NetworkLayer.LAYER2.value:
            payload["vrfName"] = "NA"

        l2_fabric_data = self._nested_fabric_data(source.get("l2Data"))
        if l2_fabric_data:
            payload.setdefault("l2Data", {})
            payload["l2Data"].setdefault("fabricData", {})
            payload["l2Data"]["fabricData"].update(l2_fabric_data)

        l3_fabric_data = self._nested_fabric_data(source.get("l3Data"))
        if l3_fabric_data:
            payload.setdefault("l3Data", {})
            payload["l3Data"].setdefault("fabricData", {})
            payload["l3Data"]["fabricData"].update(l3_fabric_data)

        return payload

    @staticmethod
    def _nested_fabric_data(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            return {}
        fabric_data = value.get("fabricData")
        return dict(fabric_data) if isinstance(fabric_data, dict) else {}

    @staticmethod
    def _mcfg_parent_default_l3_data() -> dict[str, Any]:
        """Return the OneManage parent L3 compatibility block expected on L2 Network creates."""
        return {
            "gatewayIpv4Address": "",
            "gatewayIpv6Address": "",
            "secondaryGatewayIpv6Collection": [],
            "vlanInterfaceDescription": "",
            "mtu": None,
            "secondaryGatewayIpv4Collection": None,
            "routingTag": 12345,
        }

    def _create_or_update_payload(self, model_instance: NDNetworkModel) -> dict[str, Any]:
        if self.strategy.is_child:
            return self._child_network_update_payload(model_instance)
        if self._is_mcfg_parent():
            return self._mcfg_parent_network_payload(model_instance)
        return model_instance.to_payload()

    def create(self, model_instance: NDNetworkModel, **kwargs) -> ResponseType:
        return self.create_bulk([model_instance])

    def create_bulk(self, model_instances: list[NDNetworkModel], **kwargs) -> ResponseType:
        if not model_instances:
            return {}
        if self.strategy.is_child:
            return [self.update(model_instance) for model_instance in model_instances]
        endpoint = self._make_endpoint(self.strategy.networks_post_cls())
        if self._is_mcfg_parent():
            payload = {
                "networks": [self._create_or_update_payload(model_instance) for model_instance in model_instances],
            }
            if any((model.vrf_name or "NA") == "NA" for model in model_instances):
                payload["vrfName"] = "NA"
            response = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data=payload,
                operation_type=OperationType.CREATE,
            )
            self._raise_on_failed_results(response, "Network create failed")
            return response
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data={"networks": [self._create_or_update_payload(model) for model in model_instances]},
            operation_type=OperationType.CREATE,
        )
        self._raise_on_failed_results(response, "Network create failed")
        return response

    def update(self, model_instance: NDNetworkModel, **kwargs) -> ResponseType:
        network_name = model_instance.get_identifier_value()
        if isinstance(network_name, (list, tuple)):
            network_name = network_name[0]
        endpoint = self._make_endpoint(self.strategy.network_put_cls(), network_name=network_name)
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data=self._create_or_update_payload(model_instance),
            operation_type=OperationType.UPDATE,
        )
        self._raise_on_failed_results(response, "Network update failed")
        return response

    @staticmethod
    def _raise_on_failed_results(response: ResponseType, prefix: str) -> None:
        if not isinstance(response, dict):
            return
        results = response.get("results")
        if not isinstance(results, list):
            return
        failed = [item for item in results if isinstance(item, dict) and str(item.get("status", "")).lower() != "success"]
        if failed:
            raise Exception(f"{prefix}: {failed}")

    def delete(self, model_instance: NDNetworkModel, **kwargs) -> ResponseType:
        return self.delete_bulk([model_instance])

    def delete_bulk(self, model_instances: list[NDNetworkModel], **kwargs) -> ResponseType:
        if not model_instances:
            return {}
        names = []
        for model in model_instances:
            identifier = model.get_identifier_value()
            names.append(identifier[0] if isinstance(identifier, (list, tuple)) else identifier)
        try:
            return self._delete_bulk_with_retry(names)
        except Exception as exc:
            if self._delete_error_is_absent_network(exc) and self._networks_absent(names):
                return {"results": [{"networkName": name, "status": "success"} for name in names]}
            raise Exception(f"Bulk delete networks failed: {exc}") from exc

    def _delete_bulk_with_retry(self, network_names: list[str]) -> ResponseType:
        pending = list(network_names)
        successes: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for attempt in range(1, self.delete_retry_attempts + 1):
            endpoint = self._make_endpoint(self.strategy.network_actions_remove_post_cls())
            try:
                response = self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    data=NetworkRemoveRequestModel(network_names=pending).to_payload(),
                    operation_type=OperationType.DELETE,
                )
            except Exception as exc:
                last_error = exc
                response = self.rest_send.response_current.get("DATA", {})
                if not self._delete_response_has_sync_retry_failure(response):
                    raise

            successful, retryable, failed = self._parse_delete_results(response, pending)
            successes.extend(successful)
            if failed:
                raise Exception(f"Non-retryable delete failure: {failed}; response: {response}")
            if not retryable:
                return self._combined_delete_response(response, successes)
            pending = [item["networkName"] for item in retryable if item.get("networkName")]
            if attempt == self.delete_retry_attempts:
                raise Exception(f"Bulk delete networks failed after {self.delete_retry_attempts} attempts: {response}") from last_error
            time.sleep(self.delete_retry_delay)
        return {"results": successes}

    @staticmethod
    def _parse_delete_results(
        response: ResponseType,
        requested_network_names: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list):
            return ([{"networkName": name, "status": "success"} for name in requested_network_names], [], [])
        successful: list[dict[str, Any]] = []
        retryable: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            if str(item.get("status", "")).lower() == "success":
                successful.append(item)
            elif NDNetworkOrchestrator._delete_result_is_sync_retry_failure(item):
                retryable.append(item)
            else:
                failed.append(item)
        return successful, retryable, failed

    @staticmethod
    def _combined_delete_response(response: ResponseType, successful_results: list[dict[str, Any]]) -> ResponseType:
        if isinstance(response, dict) and isinstance(response.get("results"), list):
            response["results"] = list(response["results"]) + [item for item in successful_results if item not in response["results"]]
        return response

    @staticmethod
    def _delete_response_has_sync_retry_failure(response: ResponseType) -> bool:
        if not isinstance(response, dict):
            return False
        results = response.get("results")
        if isinstance(results, list):
            return any(NDNetworkOrchestrator._delete_result_is_sync_retry_failure(item) for item in results if isinstance(item, dict))
        message = str(response).lower()
        return "fabric re-sync" in message or "fabric resync" in message

    @staticmethod
    def _delete_result_is_sync_retry_failure(result: dict[str, Any]) -> bool:
        message = str(result.get("message") or result.get("error") or result).lower()
        return "fabric re-sync" in message or "fabric resync" in message

    @staticmethod
    def _delete_error_is_absent_network(error: Exception) -> bool:
        message = str(error)
        return "Invalid Network" in message or "not found" in message

    def _networks_absent(self, network_names: list[str]) -> bool:
        remaining = {network.get("networkName") or network.get("network_name") for network in self.query_all() or [] if isinstance(network, dict)}
        return not set(network_names).intersection(remaining)
