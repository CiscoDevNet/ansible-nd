# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Orchestrator for ND Manage network CRUD operations."""

from __future__ import annotations

import json
import time

from typing import Any, ClassVar
from urllib.parse import quote

from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    NetworkLayer,
    NetworkType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_actions_models import (
    NetworkBulkDeleteRequestModel,
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
    delete_retry_attempts: ClassVar[int] = 3
    delete_retry_delay: ClassVar[int] = 30

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
        is_l2only = self._value(config, "is_l2only", "isL2Only")
        if is_l2only is True:
            return NetworkLayer.LAYER2.value
        return NetworkLayer.LAYER3.value

    def _l2_data(self, config: dict[str, Any], network_type: str) -> dict[str, Any] | None:
        kwargs = {
            "vlan_name": self._value(config, "vlan_name", "vlanName"),
            "fabric_data": self._value(config, "l2_fabric_data", "l2FabricData"),
        }
        if network_type in (
            NetworkType.ROUTED.value,
            NetworkType.AIML_ROUTED.value,
            NetworkType.CLASSIC_LAN_ENHANCED.value,
        ):
            model = ClassicOrRoutedL2DataModel(**{k: v for k, v in kwargs.items() if v is not None})
        else:
            fabric_data_value = self._value(config, "l2_fabric_data", "l2FabricData") or {}
            if not isinstance(fabric_data_value, dict):
                fabric_data_value = {}
            for target, names in {
                "stretch": ("stretch",),
                "enable_ir": ("enable_ir", "enableIr"),
                "multicast_group": ("multicast_group_address", "multicastGroup", "multicast_group"),
                "ds_vni": ("ds_vni", "dsVni"),
            }.items():
                value = self._value(config, *names)
                if value is not None:
                    fabric_data_value[target] = value

            kwargs.update(
                {
                    "rt_auto": self._value(config, "rt_auto", "rtAuto"),
                    "x_connect": self._value(config, "x_connect", "xConnect"),
                    "fabric_data": DefaultL2FabricDataModel(**fabric_data_value) if fabric_data_value else None,
                }
            )
            model = DefaultL2DataModel(**{k: v for k, v in kwargs.items() if v is not None})
        payload = model.to_payload()
        return payload or None

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
            payload = model.to_payload()
            return payload or None

        fabric_data = VxlanL3FabricDataModel(
            dhcp_servers=self._value(config, "dhcp_servers", "dhcpServers"),
            loopback_id=self._value(config, "loopback_id", "loopbackId"),
            igmp_version=self._value(config, "igmp_version", "igmpVersion"),
            netflow=self._value(config, "netflow_enable", "netflowEnable", "netflow", default=False),
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
        payload = model.to_payload()
        return payload or None

    def _transform_config_to_payload_model_data(self, config: dict[str, Any], fabric_name: str) -> dict[str, Any]:
        network_type = self._value(config, "network_type", "networkType", default=self._default_network_type())
        transformed: dict[str, Any] = {
            "fabric_name": self._value(config, "fabric_name", "fabricName", default=fabric_name),
            "network_name": self._value(config, "network_name", "networkName"),
            "network_type": network_type,
        }
        for target, names in {
            "display_name": ("display_name", "displayName"),
            "vrf_name": ("vrf_name", "vrfName"),
            "vlan_id": ("vlan_id", "vlanId"),
            "tenant_name": ("tenant_name", "tenantName"),
            "network_id": ("network_id", "networkId"),
            "vlan_network_type": ("vlan_network_type", "vlanNetworkType"),
            "primary_network_id": ("primary_network_id", "primaryNetworkId"),
            "primary_network_name": ("primary_network_name", "primaryNetworkName"),
            "normal_network_id": ("normal_network_id", "normalNetworkId"),
            "normal_network_name": ("normal_network_name", "normalNetworkName"),
        }.items():
            value = self._value(config, *names)
            if value is not None:
                transformed[target] = value

        for target, names in {
            "network_template_name": ("network_template_name", "networkTemplateName"),
            "network_extension_template_name": ("network_extension_template_name", "networkExtensionTemplateName"),
            "network_template_config": ("network_template_config", "networkTemplateConfig"),
        }.items():
            value = self._value(config, *names)
            if value is not None:
                if network_type != NetworkType.USER_DEFINED.value:
                    raise ValueError(f"{target} requires network_type={NetworkType.USER_DEFINED.value}")
                transformed[target] = value

        if network_type == NetworkType.USER_DEFINED.value:
            return transformed

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

    def prepare_config_data(self, raw_config):
        if not isinstance(raw_config, list):
            return raw_config
        fabric_name = self.strategy.fabric_name
        result = []
        for entry in raw_config:
            if isinstance(entry, dict):
                result.append(self._transform_config_to_payload_model_data(entry, fabric_name))
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

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        scoped_network_names = self._query_scope_network_names()
        try:
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
        try:
            self._append_scoped_network_items(networks, seen, self._query_all_scoped_batch(ordered_names), ordered_names)
        except Exception:
            pass

        for network_name in [name for name in ordered_names if name not in seen]:
            self._append_scoped_network_items(networks, seen, self._query_all_scoped_one(network_name), [network_name])
        return networks

    def _query_all_scoped_batch(self, network_names: list[str]) -> list[dict[str, Any]]:
        endpoint = self._make_endpoint(self.strategy.networks_get_cls())
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.filter = self._network_name_filter(network_names)
            endpoint.endpoint_params.max = max(len(network_names), 1)
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
        endpoint = self._make_endpoint(self.strategy.networks_get_cls())
        result = self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True, operation_type=OperationType.QUERY)
        if isinstance(result, dict):
            return self._normalize_query_network_items(result.get("networks") or result.get("items") or [])
        return self._normalize_query_network_items(result)

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
        return quote(expression, safe="")

    def _is_mcfg_parent(self) -> bool:
        return bool(getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False))

    def _normalize_query_network_item(self, item: Any) -> Any:
        if not isinstance(item, dict):
            return item
        if not self._is_mcfg_parent():
            return item

        normalized = dict(item)
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
            normalized["networkTemplateConfig"] = {str(key): "" if value is None else str(value) for key, value in template_config.items()}
        if isinstance(template_config, dict):
            normalized.update(self._schema_fields_from_top_down_template(template_config))
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

        is_l2only = self._top_down_bool(template_config.get("isLayer2Only"))
        converted["layer"] = NetworkLayer.LAYER2.value if is_l2only else NetworkLayer.LAYER3.value

        enable_ir = self._top_down_bool(template_config.get("enableIR", template_config.get("enableIr")))
        if enable_ir is None:
            enable_ir = False
        l2_fabric_data = {
            "enableIr": enable_ir,
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
                "intfDescription": self._template_value(l3_data.get("vlanInterfaceDescription")),
                "mtu": self._template_value(l3_data.get("mtu")),
                "suppressArp": self._template_value(l3_data.get("arpSuppression")),
                "dhcpServers": self._top_down_dhcp_servers(l3_fabric_data.get("dhcpServers")),
                "loopbackId": self._template_value(l3_fabric_data.get("loopbackId")),
                "mcastGroup": self._template_value(l2_fabric_data.get("multicastGroup")),
                "gatewayIpV6Address": self._template_value(l3_data.get("gatewayIpv6Address")),
                "trmEnabled": self._template_value(l3_fabric_data.get("ipv4Trm")),
                "rtBothAuto": self._template_value(l2_data.get("rtAuto")),
                "enableL3OnBorder": self._template_value(l3_fabric_data.get("gatewayOnBorder")),
                "ENABLE_NETFLOW": self._template_value(l3_fabric_data.get("netflow")),
                "enableIR": self._template_value(l2_fabric_data.get("enableIr")),
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

    def _create_or_update_payload(self, model_instance: NDNetworkModel) -> dict[str, Any]:
        if self._is_mcfg_parent():
            return self._top_down_network_payload(model_instance)
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
            return [
                self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    data=self._create_or_update_payload(model_instance),
                    operation_type=OperationType.CREATE,
                )
                for model_instance in model_instances
            ]
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
        if getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False):
            endpoint = self._make_endpoint(self.strategy.network_actions_remove_post_cls())
            endpoint.query_params.network_names = ",".join(network_names)
            return self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                operation_type=OperationType.DELETE,
            )

        pending = list(network_names)
        successes: list[dict[str, Any]] = []
        last_error: Exception | None = None
        for attempt in range(1, self.delete_retry_attempts + 1):
            endpoint = self._make_endpoint(self.strategy.network_actions_remove_post_cls())
            try:
                response = self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    data=NetworkBulkDeleteRequestModel(network_names=pending).to_payload(),
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
