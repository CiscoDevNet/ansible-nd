# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Orchestrator for ND Manage network CRUD operations."""

from __future__ import annotations

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
                return result.get("networks") or result.get("items") or []
            return result or []
        except Exception as exc:
            if scoped_network_names:
                return self._query_all_unfiltered()
            raise Exception(f"Query all networks failed: {exc}") from exc

    def _query_all_scoped(self, network_names: list[str]) -> ResponseType:
        networks: list[dict[str, Any]] = []
        seen: set[str] = set()
        for network_name in network_names:
            endpoint = self._make_endpoint(self.strategy.networks_get_cls())
            if hasattr(endpoint, "endpoint_params"):
                endpoint.endpoint_params.filter = self._network_name_filter([network_name])
            result = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
            items = result.get("networks") if isinstance(result, dict) else result
            for item in items or []:
                item_name = item.get("networkName") or item.get("network_name") if isinstance(item, dict) else None
                if item_name and item_name not in seen:
                    networks.append(item)
                    seen.add(item_name)
        return networks

    def _query_all_unfiltered(self) -> ResponseType:
        endpoint = self._make_endpoint(self.strategy.networks_get_cls())
        result = self._request(path=endpoint.path, verb=endpoint.verb, not_found_ok=True, operation_type=OperationType.QUERY)
        if isinstance(result, dict):
            return result.get("networks") or result.get("items") or []
        return result or []

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

    def create(self, model_instance: NDNetworkModel, **kwargs) -> ResponseType:
        return self.create_bulk([model_instance])

    def create_bulk(self, model_instances: list[NDNetworkModel], **kwargs) -> ResponseType:
        if not model_instances:
            return {}
        if self.strategy.is_child:
            return [self.update(model_instance) for model_instance in model_instances]
        endpoint = self._make_endpoint(self.strategy.networks_post_cls())
        response = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            data={"networks": [model.to_payload() for model in model_instances]},
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
            data=model_instance.to_payload(),
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
            response["results"] = list(response["results"]) + [
                item for item in successful_results if item not in response["results"]
            ]
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
        remaining = {
            network.get("networkName") or network.get("network_name")
            for network in self.query_all() or []
            if isinstance(network, dict)
        }
        return not set(network_names).intersection(remaining)
