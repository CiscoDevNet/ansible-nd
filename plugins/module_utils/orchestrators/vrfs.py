# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
NDVrfOrchestrator — Orchestrator for ND VRF operations.

Unlike the links orchestrator (which uses a single API surface and picks the
strategy at module-entry time), the VRF orchestrator must:

  1. Dynamically select its strategy via VrfFabricResolver at run time.
  2. Handle the parent → child recursive invocation pattern:
       a. Run the parent fabric task through the state machine.
       b. For each child fabric, split the config, rebuild module_args,
          and re-invoke the module (via VrfWorkflowCoordinator).

The orchestrator is intentionally thin: it delegates endpoint selection to the
strategy and parent/child splitting to VrfWorkflowCoordinator.

Architecture overview
─────────────────────
  nd_manage_vrfs.py (AnsibleModule entry)
      │
      ▼
  VrfFabricResolver.resolve()  ──► BaseVrfStrategy subclass
      │
      ▼
  VrfWorkflowCoordinator.run()
      │
      ├── standalone / child ──► NDVrfOrchestrator ──► NDStateMachine
      │
      └── parent ─────────────► NDVrfOrchestrator (parent task)
                                  └── per child ──► NDVrfOrchestrator with child strategy
"""

from __future__ import annotations

import copy
import json
import time

from typing import Any, Callable, ClassVar

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import (
    TrmData,
    VrfDataModel,
    VxlanCoreData,
    VxlanFabricInstance,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.enums import (
    VrfType,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.base_vrf import (
    BaseVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
    EpManageFabricsVrfsPost,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
    EpManageFabricsVrfActionsRemovePost,
)

NDVrfModel = VrfDataModel


class NDVrfOrchestrator(NDBaseOrchestrator["NDVrfModel"]):
    """
    Orchestrator for ND VRF CRUD operations.

    Delegates endpoint selection to a BaseVrfStrategy instance, enabling the
    same orchestrator to work across standalone, multisite-parent,
    multicluster-parent, and child fabric scopes.
    """

    # ── Class-level configuration ─────────────────────────────────

    model_class: ClassVar[type[NDBaseModel]] = NDVrfModel

    # VRFs are individual resources; bulk-create IS supported by the API
    # (POST /vrfs accepts a {"vrfs": [...]} request body).
    supports_bulk_create: ClassVar[bool] = True
    # vrfActions/remove accepts a list of VRF names.
    supports_bulk_delete: ClassVar[bool] = True
    supports_bulk_update: ClassVar[bool] = False

    # Endpoints are None here — always resolved via the strategy at call time.
    create_endpoint: type | None = None
    update_endpoint: type | None = None
    delete_endpoint: type | None = None
    query_one_endpoint: type | None = None
    query_all_endpoint: type | None = None

    # Bulk endpoints satisfy the base-class validator; the actual endpoint
    # selection is handled in our overridden create_bulk / delete_bulk methods.
    create_bulk_endpoint: type | None = EpManageFabricsVrfsPost
    delete_bulk_endpoint: type | None = EpManageFabricsVrfActionsRemovePost

    # Strategy is injected at construction time by nd_manage_vrfs.py / VrfFabricResolver.
    strategy: BaseVrfStrategy | None = None
    trace_hook: Callable[..., None] | None = None
    delete_retry_attempts: ClassVar[int] = 3
    delete_retry_delay: ClassVar[int] = 30
    scoped_query_threshold: ClassVar[int] = 5
    unfiltered_query_page_size: ClassVar[int] = 10000

    def model_post_init(self, __context) -> None:
        if self.strategy is None:
            raise ValueError("NDVrfOrchestrator requires a strategy instance.")

    # ── Config preprocessing ──────────────────────────────────────

    @staticmethod
    def _value(config: dict[str, Any], *names: str, default: Any = None) -> Any:
        """Return the first present config value."""
        for name in names:
            if name in config:
                return config[name]
        return default

    @staticmethod
    def _has_explicit_fabric_data(config: dict[str, Any]) -> bool:
        """Return True when playbook config explicitly sets fabric-level VRF options."""
        fabric_field_names = {
            "l3vni_wo_vlan",
            "adv_host_routes",
            "adv_default_routes",
            "static_default_route",
            "bgp_password",
            "bgp_passwd_encrypt",
            "netflow_enable",
            "nf_monitor",
            "trm_enable",
            "ipv6_trm",
            "no_rp",
            "rp_external",
            "rp_address",
            "rp_loopback_id",
            "underlay_mcast_ip",
            "overlay_mcast_group",
            "trm_bgw_msite",
            "import_mvpn_rt",
            "export_mvpn_rt",
        }
        return any(name in config for name in fabric_field_names)

    def _default_vrf_type(self) -> str:
        """Return the standard VRF type derived from resolved fabric details."""
        fabric_data = self.strategy.fabric_data if self.strategy else {}
        for key in ("vrf_type", "vrfType", "managementType"):
            if isinstance(fabric_data, dict) and fabric_data.get(key):
                return fabric_data[key]
        management = fabric_data.get("management") if isinstance(fabric_data, dict) else {}
        if isinstance(management, dict) and management.get("type"):
            return management["type"]
        details = fabric_data.get("manageFabricDetails") if isinstance(fabric_data, dict) else {}
        management = details.get("management") if isinstance(details, dict) else {}
        if isinstance(management, dict) and management.get("type"):
            return management["type"]
        return VrfType.VXLAN_IBGP.value

    def _transform_child_config_to_payload_model_data(self, config: dict[str, Any], fabric_name: str) -> dict[str, Any]:
        """Transform child overrides into a fabricData-only VRF payload."""
        transformed: dict[str, Any] = {
            "fabric_name": self._value(config, "fabric_name", default=fabric_name),
            "vrf_name": self._value(config, "vrf_name"),
        }

        trm_kwargs = {
            "ipv4_trm": self._value(config, "trm_enable"),
            "v4_rp_absent": self._value(config, "no_rp"),
            "v4_rp_external": self._value(config, "rp_external"),
            "v4_rp_address": self._value(config, "rp_address"),
            "loopback_number": self._value(config, "rp_loopback_id"),
            "l3_vni_multicast_group": self._value(config, "underlay_mcast_ip"),
            "v4_multicast_group": self._value(config, "overlay_mcast_group"),
            "trm_on_bgw": self._value(config, "trm_bgw_msite"),
            "mvpn_route_target_import": self._value(config, "import_mvpn_rt"),
            "mvpn_route_target_export": self._value(config, "export_mvpn_rt"),
        }
        trm_kwargs = {k: v for k, v in trm_kwargs.items() if v is not None}

        fabric_kwargs = {
            "l3_vni_without_vlan": self._value(config, "l3vni_wo_vlan", default=False),
            "advertise_host_route": self._value(config, "adv_host_routes", default=False),
            "advertise_default_route": self._value(config, "adv_default_routes", default=True),
            "configure_static_default_route": self._value(
                config,
                "static_default_route",
                default=True,
            ),
            "bgp_password": self._value(config, "bgp_password"),
            "bgp_password_key_type": self._value(config, "bgp_passwd_encrypt", default=3),
            "netflow": self._value(config, "netflow_enable", default=False),
            "netflow_monitor": self._value(config, "nf_monitor"),
        }
        fabric_kwargs = {k: v for k, v in fabric_kwargs.items() if v is not None}
        if trm_kwargs:
            fabric_kwargs["trm_data"] = TrmData(**trm_kwargs)

        if fabric_kwargs:
            transformed["fabric_data"] = VxlanFabricInstance(**fabric_kwargs).to_payload()

        return transformed

    def _transform_config_to_payload_model_data(self, config: dict[str, Any], fabric_name: str) -> dict[str, Any]:
        """
        Transform playbook-facing VRF config into VrfDataModel-shaped data.

        The state machine later validates this through VrfDataModel and
        create_bulk() serializes it through to_payload().  Keeping this
        transform here prevents Ansible config fields from being silently
        dropped by VrfDataModel.extra="ignore".
        """
        custom_template_fields = {
            "service_vrf_template_name": ("service_vrf_template_name",),
            "vrf_template_name": ("vrf_template_name",),
            "vrf_extension_template_name": ("vrf_extension_template_name",),
            "vrf_template_config": ("vrf_template_config",),
        }
        explicit_vrf_type = self._value(config, "vrf_type")
        has_custom_template_fields = any(self._value(config, *names) is not None for names in custom_template_fields.values())
        vrf_type = explicit_vrf_type or (VrfType.USER_DEFINED.value if has_custom_template_fields else self._default_vrf_type())
        transformed: dict[str, Any] = {
            "fabric_name": self._value(config, "fabric_name", default=fabric_name),
            "vrf_name": self._value(config, "vrf_name"),
            "vrf_type": vrf_type,
        }

        optional_top_level = {
            "tenant_name": ("tenant_name",),
            "vrf_id": ("vrf_id",),
            "vlan_id": ("vlan_id",),
            "default_security_action": ("default_security_action",),
            "default_security_group_tag": ("default_security_group_tag",),
        }
        for target, names in optional_top_level.items():
            value = self._value(config, *names)
            if value is not None:
                transformed[target] = value

        for target, names in custom_template_fields.items():
            value = self._value(config, *names)
            if value is not None:
                if vrf_type != VrfType.USER_DEFINED.value:
                    raise ValueError(f"{target} requires vrf_type={VrfType.USER_DEFINED.value}")
                transformed[target] = value

        if vrf_type == VrfType.USER_DEFINED.value:
            return transformed

        core_data = VxlanCoreData(
            vrf_vlan_name=self._value(config, "vrf_vlan_name"),
            vrf_interface_description=self._value(
                config,
                "vrf_intf_desc",
            ),
            vrf_description=self._value(config, "vrf_description"),
            mtu=self._value(config, "vrf_int_mtu", default=9216),
            routing_tag=self._value(
                config,
                "loopback_route_tag",
                default=12345,
            ),
            vrf_route_map=self._value(
                config,
                "redist_direct_rmap",
                default="FABRIC-RMAP-REDIST-SUBNET",
            ),
            v6_vrf_route_map=self._value(
                config,
                "v6_redist_direct_rmap",
                default="FABRIC-RMAP-REDIST-SUBNET",
            ),
            max_bgp_paths=self._value(config, "max_bgp_paths", default=1),
            max_ibgp_paths=self._value(config, "max_ibgp_paths", default=2),
            ipv6_link_local=self._value(
                config,
                "ipv6_linklocal_enable",
                default=True,
            ),
            disable_rt_auto=self._value(config, "disable_rt_auto", default=False),
            route_target_import=self._value(config, "import_vpn_rt"),
            route_target_export=self._value(config, "export_vpn_rt"),
            evpn_route_target_import=self._value(
                config,
                "import_evpn_rt",
            ),
            evpn_route_target_export=self._value(
                config,
                "export_evpn_rt",
            ),
        )

        trm_data = TrmData(
            ipv4_trm=self._value(config, "trm_enable", default=False),
            ipv6_trm=self._value(config, "ipv6_trm", default=False),
            v4_rp_absent=self._value(config, "no_rp", default=False),
            v4_rp_external=self._value(config, "rp_external", default=False),
            v4_rp_address=self._value(config, "rp_address"),
            loopback_number=self._value(config, "rp_loopback_id"),
            l3_vni_multicast_group=self._value(config, "underlay_mcast_ip"),
            v4_multicast_group=self._value(config, "overlay_mcast_group"),
            trm_on_bgw=self._value(config, "trm_bgw_msite", default=False),
            mvpn_route_target_import=self._value(
                config,
                "import_mvpn_rt",
            ),
            mvpn_route_target_export=self._value(
                config,
                "export_mvpn_rt",
            ),
        )

        fabric_data = VxlanFabricInstance(
            l3_vni_without_vlan=self._value(config, "l3vni_wo_vlan", default=False),
            advertise_host_route=self._value(config, "adv_host_routes", default=False),
            advertise_default_route=self._value(config, "adv_default_routes", default=True),
            configure_static_default_route=self._value(
                config,
                "static_default_route",
                default=True,
            ),
            bgp_password=self._value(config, "bgp_password"),
            bgp_password_key_type=self._value(config, "bgp_passwd_encrypt", default=3),
            netflow=self._value(config, "netflow_enable", default=False),
            netflow_monitor=self._value(config, "nf_monitor"),
            trm_data=trm_data,
        )

        transformed["core_data"] = core_data.to_payload()
        is_parent = getattr(self.strategy, "is_parent", False)
        is_multicluster = getattr(self.strategy, "is_multicluster", False)
        if not is_parent or (is_multicluster and self._has_explicit_fabric_data(config)):
            transformed["fabric_data"] = fabric_data.to_payload()
        return transformed

    def prepare_config_data(self, raw_config):
        """Inject fabric_name and transform config into ND VRF payload shape."""
        if not isinstance(raw_config, list):
            return raw_config
        fabric_name = self.strategy.fabric_name
        result = []
        for entry in raw_config:
            if isinstance(entry, dict):
                if self.strategy.is_child:
                    result.append(self._transform_child_config_to_payload_model_data(entry, fabric_name))
                else:
                    result.append(self._transform_config_to_payload_model_data(entry, fabric_name))
            else:
                result.append(entry)
        return result

    # ── Endpoint factory ──────────────────────────────────────────

    def _make_endpoint(self, endpoint_cls, **extra_fields):
        """
        Instantiate an endpoint, set ``fabric_name`` from the strategy, call
        the strategy's ``configure_endpoint`` hook (e.g. to inject cluster_name
        for Multicluster fabrics), then apply any per-call identifiers.
        """
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
            self._raise_on_failed_results(response)
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
    def _raise_on_failed_results(response: Any) -> None:
        """Raise for VRF action responses whose per-item result failed."""
        if not isinstance(response, dict):
            return
        results = response.get("results")
        if not isinstance(results, list):
            return
        failed: list[str] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "") or "").strip().lower()
            if status not in ("failed", "failure", "error"):
                continue
            name = item.get("vrfName") or item.get("name") or "item"
            message = item.get("message") or "operation failed"
            failed.append(f"{name}: {message}")
        if failed:
            raise Exception("ND Error: " + "; ".join(failed))

    @staticmethod
    def _response_summary(response: Any) -> dict[str, Any]:
        if isinstance(response, dict):
            summary: dict[str, Any] = {"type": "dict", "keys": sorted(response.keys())}
            for key in ("vrfs", "items", "attachments", "results"):
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

    # ── Query ─────────────────────────────────────────────────────

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """GET all VRFs for the fabric."""
        scoped_vrf_names = self._query_scope_vrf_names()
        try:
            if not scoped_vrf_names:
                return self._query_all_unfiltered()
            if self._is_mcfg_parent():
                return self._filter_query_items_by_name(self._query_all_unfiltered(), scoped_vrf_names)
            if len(scoped_vrf_names) >= self.scoped_query_threshold:
                return self._query_all_unfiltered()
            if len(scoped_vrf_names) > 1:
                return self._filter_query_items_by_name(self._query_all_unfiltered(), scoped_vrf_names)
            endpoint = self._make_endpoint(self.strategy.vrfs_get_cls())
            if scoped_vrf_names and hasattr(endpoint, "endpoint_params"):
                endpoint.endpoint_params.filter = self._vrf_name_filter(scoped_vrf_names)
            result = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
            if isinstance(result, dict):
                return self._enrich_mcfg_parent_vrfs_from_children(self._normalize_query_vrf_items(result.get("vrfs") or result.get("items") or []))
            return self._enrich_mcfg_parent_vrfs_from_children(self._normalize_query_vrf_items(result))
        except Exception as e:
            if scoped_vrf_names:
                return self._query_all_unfiltered()
            raise Exception(f"Query all VRFs failed: {e}") from e

    def _query_all_scoped(self, vrf_names: list[str]) -> ResponseType:
        """GET selected VRFs with a single batched filter."""
        vrfs: list[dict[str, Any]] = []
        seen: set[str] = set()
        ordered_names = list(dict.fromkeys(vrf_names))
        self._append_scoped_vrf_items(vrfs, seen, self._query_all_scoped_batch(ordered_names), ordered_names)
        return self._enrich_mcfg_parent_vrfs_from_children(vrfs)

    @staticmethod
    def _filter_query_items_by_name(items: list[Any], vrf_names: list[str]) -> list[Any]:
        requested = set(vrf_names)
        return [item for item in items or [] if not isinstance(item, dict) or (item.get("vrfName") or item.get("vrf_name")) in requested]

    def _query_all_scoped_batch(self, vrf_names: list[str]) -> list[dict[str, Any]]:
        endpoint = self._make_endpoint(self.strategy.vrfs_get_cls())
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.filter = self._vrf_name_filter(vrf_names)
            endpoint.endpoint_params.max = 1
        result = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        if isinstance(result, dict):
            return result.get("vrfs") or result.get("items") or []
        return result or []

    def _query_all_scoped_one(self, vrf_name: str) -> list[dict[str, Any]]:
        endpoint = self._make_endpoint(self.strategy.vrfs_get_cls())
        if hasattr(endpoint, "endpoint_params"):
            endpoint.endpoint_params.filter = self._vrf_name_filter([vrf_name])
        result = self._request(
            path=endpoint.path,
            verb=endpoint.verb,
            not_found_ok=True,
            operation_type=OperationType.QUERY,
        )
        if isinstance(result, dict):
            return result.get("vrfs") or result.get("items") or []
        return result or []

    def _append_scoped_vrf_items(
        self,
        vrfs: list[dict[str, Any]],
        seen: set[str],
        items: list[dict[str, Any]],
        requested_names: list[str],
    ) -> None:
        requested = set(requested_names)
        for item in items or []:
            item_name = item.get("vrfName") or item.get("vrf_name") if isinstance(item, dict) else None
            if item_name and item_name in requested and item_name not in seen:
                vrfs.append(self._normalize_query_vrf_item(item))
                seen.add(item_name)

    def _query_all_unfiltered(self) -> ResponseType:
        """GET all VRFs without a filter fallback."""
        vrfs: list[dict[str, Any]] = []
        offset = 0

        while True:
            endpoint = self._make_endpoint(self.strategy.vrfs_get_cls())
            if hasattr(endpoint, "endpoint_params"):
                endpoint.endpoint_params.max = self.unfiltered_query_page_size
                endpoint.endpoint_params.offset = offset

            result = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
            page_items = self._vrf_items_from_query_result(result)
            vrfs.extend(page_items)

            if not self._has_more_unfiltered_pages(result, len(page_items), len(vrfs)):
                break
            if not page_items:
                break
            offset += len(page_items)

        return self._enrich_mcfg_parent_vrfs_from_children(self._normalize_query_vrf_items(vrfs))

    @staticmethod
    def _vrf_items_from_query_result(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, dict):
            return result.get("vrfs") or result.get("items") or []
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

    def _query_scope_vrf_names(self) -> list[str]:
        """Return VRF names safe to use for targeted current-state discovery."""
        state = self.rest_send.params.get("state")
        if state not in ("merged", "replaced", "deleted"):
            return []
        config = self.rest_send.params.get("config") or []
        if not config:
            return []
        names: list[str] = []
        seen: set[str] = set()
        for item in config:
            if not isinstance(item, dict):
                continue
            name = item.get("vrf_name") or item.get("vrfName")
            if name and name not in seen:
                names.append(name)
                seen.add(name)
        return names

    def _vrf_name_filter(self, vrf_names: list[str]) -> str:
        """Build a raw Lucene filter for endpoint serialization."""
        terms = [f"vrfName:{vrf_name}" for vrf_name in sorted(set(vrf_names))]
        expression = terms[0] if len(terms) == 1 else "(" + " OR ".join(terms) + ")"
        return expression

    def _normalize_query_vrf_item(self, item: Any) -> Any:
        if not isinstance(item, dict):
            return item
        if not (getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False)):
            return item

        normalized = dict(item)
        if not normalized.get("fabricName"):
            normalized["fabricName"] = normalized.get("fabric") or self.strategy.fabric_name
        if not normalized.get("vrfType"):
            normalized["vrfType"] = self._default_vrf_type()
        if normalized.get("vrfStatus") == "NA":
            normalized["vrfStatus"] = "notApplicable"
        template_config = normalized.get("vrfTemplateConfig")
        if isinstance(template_config, str):
            try:
                template_config = json.loads(template_config)
            except ValueError:
                template_config = {}
            normalized["vrfTemplateConfig"] = {str(key): "" if value is None else str(value) for key, value in template_config.items()}
        if isinstance(template_config, dict):
            normalized.update(self._schema_fields_from_top_down_template(template_config))
        return normalized

    def _normalize_query_vrf_items(self, items: Any) -> list[Any]:
        return [self._normalize_query_vrf_item(item) for item in (items or [])]

    def _is_mcfg_parent(self) -> bool:
        return bool(getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False))

    def _child_vrf_records_for_mcfg_parent(self) -> dict[str, dict[str, Any]]:
        """Read child VRFs so parent output can include fabric-instance fields omitted by top-down."""
        if not self._is_mcfg_parent():
            return {}
        members = (self.strategy.fabric_data or {}).get("members") or []
        if not members:
            return {}

        from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_fabric_resolver import VrfFabricResolver

        fabric_fields = ("advertiseHostRoute", "advertiseDefaultRoute", "configureStaticDefaultRoute")
        records_by_name: dict[str, dict[str, Any]] = {}
        conflicts_by_name: dict[str, set[str]] = {}
        for member in members:
            child_fabric_name = member.get("fabricName")
            if not child_fabric_name:
                continue
            child_strategy = VrfFabricResolver.strategy_from_fabric_details(child_fabric_name, member)
            endpoint = child_strategy.vrfs_get_cls()()
            endpoint.fabric_name = child_strategy.fabric_name
            child_strategy.configure_endpoint(endpoint)
            try:
                result = self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    not_found_ok=True,
                    operation_type=OperationType.QUERY,
                )
            except Exception:
                continue

            if isinstance(result, dict):
                child_items = result.get("vrfs") or result.get("items") or []
            else:
                child_items = result or []
            for item in child_items:
                if not isinstance(item, dict):
                    continue
                name = item.get("vrfName") or item.get("vrf_name")
                if not name:
                    continue
                child_fabric_data = item.get("fabricData") or item.get("fabric_data") or {}
                if not isinstance(child_fabric_data, dict):
                    continue
                aggregate = records_by_name.setdefault(name, {"fabricData": {}})
                aggregate_fabric_data = aggregate["fabricData"]
                conflicts = conflicts_by_name.setdefault(name, set())
                for field in fabric_fields:
                    if field in conflicts or field not in child_fabric_data:
                        continue
                    value = child_fabric_data[field]
                    if field not in aggregate_fabric_data:
                        aggregate_fabric_data[field] = value
                    elif aggregate_fabric_data[field] != value:
                        aggregate_fabric_data.pop(field, None)
                        conflicts.add(field)
        return records_by_name

    def _enrich_mcfg_parent_vrfs_from_children(self, items: list[Any]) -> list[Any]:
        if not self._is_mcfg_parent() or not items:
            return items

        child_records = self._child_vrf_records_for_mcfg_parent()
        if not child_records:
            return items

        fabric_fields = ("advertiseHostRoute", "advertiseDefaultRoute", "configureStaticDefaultRoute")
        enriched: list[Any] = []
        for item in items:
            if not isinstance(item, dict):
                enriched.append(item)
                continue
            child_record = child_records.get(item.get("vrfName") or item.get("vrf_name"))
            child_fabric_data = child_record.get("fabricData") if isinstance(child_record, dict) else None
            if not isinstance(child_fabric_data, dict):
                enriched.append(item)
                continue

            parent_item = dict(item)
            parent_fabric_data = dict(parent_item.get("fabricData") or {})
            for field in fabric_fields:
                if field not in parent_fabric_data and field in child_fabric_data:
                    parent_fabric_data[field] = child_fabric_data[field]
            if parent_fabric_data:
                parent_item["fabricData"] = parent_fabric_data
            enriched.append(parent_item)
        return enriched

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
        """Convert top-down template values into the standard VRF schema shape."""
        converted: dict[str, Any] = {}
        vlan_id = self._top_down_int(template_config.get("vrfVlanId"))
        if vlan_id is not None:
            converted["vlanId"] = vlan_id

        core_data = {
            "vrfVlanName": template_config.get("vrfVlanName"),
            "vrfInterfaceDescription": template_config.get("vrfIntfDescription"),
            "vrfDescription": template_config.get("vrfDescription"),
            "mtu": self._top_down_int(template_config.get("mtu")),
            "routingTag": self._top_down_int(template_config.get("tag")),
            "vrfRouteMap": template_config.get("vrfRouteMap"),
            "v6VrfRouteMap": template_config.get("v6VrfRouteMap"),
            "maxBgpPaths": self._top_down_int(template_config.get("maxBgpPaths")),
            "maxIbgpPaths": self._top_down_int(template_config.get("maxIbgpPaths")),
            "ipv6LinkLocal": self._top_down_bool(template_config.get("ipv6LinkLocalFlag")),
            "disableRtAuto": self._top_down_bool(template_config.get("disableRtAuto")),
            "routeTargetImport": self._top_down_list(template_config.get("routeTargetImport")),
            "routeTargetExport": self._top_down_list(template_config.get("routeTargetExport")),
            "evpnRouteTargetImport": self._top_down_list(template_config.get("routeTargetImportEvpn")),
            "evpnRouteTargetExport": self._top_down_list(template_config.get("routeTargetExportEvpn")),
        }
        core_data = {key: value for key, value in core_data.items() if value not in (None, "")}
        if core_data:
            converted["coreData"] = core_data

        l3vni_without_vlan = self._top_down_bool(template_config.get("enableL3VniNoVlan"))
        if l3vni_without_vlan is None:
            l3vni_without_vlan = template_config.get("vrfVlanId") == ""
        trm_data = {
            "ipv4Trm": self._top_down_bool(template_config.get("trmEnabled")),
            "v4RpAbsent": self._top_down_bool(template_config.get("isRPAbsent")),
            "v4RpExternal": self._top_down_bool(template_config.get("isRPExternal")),
            "v4RpAddress": template_config.get("rpAddress"),
            "loopbackNumber": self._top_down_int(template_config.get("loopbackNumber")),
            "l3VniMulticastGroup": template_config.get("L3VniMcastGroup"),
            "v4MulticastGroup": template_config.get("multicastGroup"),
            "trmOnBgw": self._top_down_bool(template_config.get("trmBGWMSiteEnabled")),
            "mvpnRouteTargetImport": self._top_down_list(template_config.get("routeTargetImportMvpn")),
            "mvpnRouteTargetExport": self._top_down_list(template_config.get("routeTargetExportMvpn")),
        }
        trm_data = {key: value for key, value in trm_data.items() if value not in (None, "")}
        fabric_data = {
            "l3VniWithoutVlan": l3vni_without_vlan,
            "advertiseHostRoute": self._top_down_bool(template_config.get("advertiseHostRouteFlag")),
            "advertiseDefaultRoute": self._top_down_bool(template_config.get("advertiseDefaultRouteFlag")),
            "configureStaticDefaultRoute": self._top_down_bool(template_config.get("configureStaticDefaultRouteFlag")),
            "bgpPassword": template_config.get("bgpPassword"),
            "bgpPasswordKeyType": self._top_down_int(template_config.get("bgpPasswordKeyType")),
            "netflow": self._top_down_bool(template_config.get("ENABLE_NETFLOW")),
            "netflowMonitor": template_config.get("NETFLOW_MONITOR"),
        }
        fabric_data = {key: value for key, value in fabric_data.items() if value not in (None, "")}
        if trm_data:
            fabric_data["trmData"] = trm_data
        if fabric_data:
            converted["fabricData"] = fabric_data

        return converted

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

    def _top_down_vrf_payload(self, model_instance: NDVrfModel) -> dict[str, Any]:
        """Build the template-config payload required by MCFG parent VRF operations."""
        core_data = self._nested_payload(model_instance.core_data)
        fabric_data = self._nested_payload(model_instance.fabric_data)
        trm_data = self._nested_payload(fabric_data.get("trmData"))
        management = ((self.strategy.fabric_data or {}).get("manageFabricDetails") or {}).get("management") or {}

        if model_instance.vrf_template_config:
            template_config = {key: self._template_value(value) for key, value in model_instance.vrf_template_config.items()}
            template_config.setdefault("vrfSegmentId", self._template_value(model_instance.vrf_id))
            template_config.setdefault("vrfName", model_instance.vrf_name)
            template_config.setdefault("vrfVlanId", self._template_value(model_instance.vlan_id))
        else:
            template_config = {
                "vrfSegmentId": self._template_value(model_instance.vrf_id),
                "vrfName": model_instance.vrf_name,
                "vrfVlanId": self._template_value(model_instance.vlan_id),
                "vrfVlanName": self._template_value(core_data.get("vrfVlanName")),
                "vrfIntfDescription": self._template_value(core_data.get("vrfInterfaceDescription")),
                "vrfDescription": self._template_value(core_data.get("vrfDescription")),
                "mtu": self._template_value(core_data.get("mtu")),
                "tag": self._template_value(core_data.get("routingTag")),
                "vrfRouteMap": self._template_value(core_data.get("vrfRouteMap")),
                "v6VrfRouteMap": self._template_value(core_data.get("v6VrfRouteMap")),
                "maxBgpPaths": self._template_value(core_data.get("maxBgpPaths")),
                "maxIbgpPaths": self._template_value(core_data.get("maxIbgpPaths")),
                "ipv6LinkLocalFlag": self._template_value(core_data.get("ipv6LinkLocal")),
                "enableL3VniNoVlan": self._template_value(fabric_data.get("l3VniWithoutVlan")),
                "trmEnabled": self._template_value(trm_data.get("ipv4Trm")),
                "isRPExternal": self._template_value(trm_data.get("v4RpExternal")),
                "rpAddress": self._template_value(trm_data.get("v4RpAddress")),
                "loopbackNumber": self._template_value(trm_data.get("loopbackNumber")),
                "L3VniMcastGroup": self._template_value(trm_data.get("l3VniMulticastGroup")),
                "multicastGroup": self._template_value(trm_data.get("v4MulticastGroup")),
                "trmBGWMSiteEnabled": self._template_value(trm_data.get("trmOnBgw")),
                "advertiseHostRouteFlag": self._template_value(fabric_data.get("advertiseHostRoute")),
                "advertiseDefaultRouteFlag": self._template_value(fabric_data.get("advertiseDefaultRoute")),
                "configureStaticDefaultRouteFlag": self._template_value(fabric_data.get("configureStaticDefaultRoute")),
                "bgpPassword": self._template_value(fabric_data.get("bgpPassword")),
                "bgpPasswordKeyType": self._template_value(fabric_data.get("bgpPasswordKeyType")),
                "isRPAbsent": self._template_value(trm_data.get("v4RpAbsent")),
                "ENABLE_NETFLOW": self._template_value(fabric_data.get("netflow")),
                "NETFLOW_MONITOR": self._template_value(fabric_data.get("netflowMonitor")),
                "disableRtAuto": self._template_value(core_data.get("disableRtAuto")),
                "routeTargetImport": self._template_value(core_data.get("routeTargetImport")),
                "routeTargetExport": self._template_value(core_data.get("routeTargetExport")),
                "routeTargetImportEvpn": self._template_value(core_data.get("evpnRouteTargetImport")),
                "routeTargetExportEvpn": self._template_value(core_data.get("evpnRouteTargetExport")),
                "routeTargetImportMvpn": self._template_value(trm_data.get("mvpnRouteTargetImport")),
                "routeTargetExportMvpn": self._template_value(trm_data.get("mvpnRouteTargetExport")),
            }

        return {
            "fabric": self.strategy.fabric_name,
            "vrfName": model_instance.vrf_name,
            "vrfTemplate": model_instance.vrf_template_name or management.get("vrfTemplate") or "Default_VRF_Universal",
            "vrfExtensionTemplate": model_instance.vrf_extension_template_name or management.get("vrfExtensionTemplate") or "Default_VRF_Extension_Universal",
            "vrfId": model_instance.vrf_id,
            "serviceVrfTemplate": model_instance.service_vrf_template_name,
            "source": None,
            "vrfTemplateConfig": json.dumps(template_config),
        }

    def _mcfg_parent_vrf_payload(self, model_instance: NDVrfModel) -> dict[str, Any]:
        """Build the schema-style OneManage manage payload for MCFG parent VRF operations."""
        payload = model_instance.to_payload()
        payload["fabricName"] = self.strategy.fabric_name
        payload.setdefault("vrfType", self._default_vrf_type())
        payload.pop("vlanId", None)
        payload.pop("tenantName", None)

        core_data = dict(payload.get("coreData") or {})
        for key in ("vrfVlanName", "vrfInterfaceDescription", "vrfDescription"):
            core_data.setdefault(key, "")
        for key in ("routeTargetImport", "routeTargetExport", "evpnRouteTargetImport", "evpnRouteTargetExport"):
            core_data.setdefault(key, [])
        payload["coreData"] = core_data
        payload["fabricData"] = {}
        return payload

    def _create_or_update_payload(self, model_instance: NDVrfModel) -> dict[str, Any]:
        if getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False):
            return self._mcfg_parent_vrf_payload(model_instance)
        return model_instance.to_payload()

    # ── Create ────────────────────────────────────────────────────

    def create(self, model_instance: NDVrfModel, **kwargs) -> ResponseType:
        """POST a single VRF."""
        return self.create_bulk([model_instance])

    def create_bulk(self, model_instances: list[NDVrfModel], **kwargs) -> ResponseType:
        """POST a list of VRFs in a single request."""
        if not model_instances:
            return {}
        if self.strategy.is_child:
            return [self.update(model_instance) for model_instance in model_instances]
        try:
            endpoint = self._make_endpoint(self.strategy.vrfs_post_cls())
            if getattr(self.strategy, "is_parent", False) and getattr(self.strategy, "is_multicluster", False):
                return self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    data={"vrfs": [self._create_or_update_payload(m) for m in model_instances]},
                    operation_type=OperationType.CREATE,
                )
            return self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data={"vrfs": [self._create_or_update_payload(m) for m in model_instances]},
                operation_type=OperationType.CREATE,
            )
        except Exception as e:
            raise Exception(f"Bulk create VRFs failed: {e}") from e

    # ── Update ────────────────────────────────────────────────────

    def update(self, model_instance: NDVrfModel, **kwargs) -> ResponseType:
        """PUT (replace) a single VRF identified by vrfName."""
        endpoint_path = ""
        try:
            # Composite identifier is (vrf_name, fabric_name); vrf_name is index 0.
            vrf_name = model_instance.get_identifier_value()[0]
            endpoint = self._make_endpoint(
                self.strategy.vrf_put_cls(),
                vrf_name=vrf_name,
            )
            endpoint_path = endpoint.path
            payload = self._create_or_update_payload(model_instance)
            if self.strategy.is_child:
                payload = {key: value for key, value in payload.items() if key in ("fabricName", "vrfName", "vrfType", "fabricData")}
            return self._request(
                path=endpoint_path,
                verb=endpoint.verb,
                data=payload,
                operation_type=OperationType.UPDATE,
            )
        except Exception as e:
            if self._is_list_only_mcfg_child_update(e, model_instance):
                vrf_name, fabric_name = model_instance.get_identifier_value()
                self._mark_child_update_rejection_handled(endpoint_path)
                return {
                    "status": "skipped",
                    "message": (
                        "Controller rejected direct multicluster child VRF update "
                        f"for fabric '{fabric_name}', but VRF '{vrf_name}' is "
                        "visible through the child fabric list endpoint."
                    ),
                    "vrfName": vrf_name,
                    "fabricName": fabric_name,
                }
            raise Exception(f"Update VRF failed for {model_instance.get_identifier_value()}: {e}") from e

    def _mark_child_update_rejection_handled(self, endpoint_path: str) -> None:
        """
        Mark the rejected remote-child PUT as handled once list visibility
        proves the VRF exists.

        Results are normally immutable API-call records.  This narrowly
        replaces only the matching failed PUT record so debug output still
        shows the controller response without causing the whole task to fail.
        """
        results = getattr(self, "results", None)
        if not endpoint_path or results is None:
            return
        tasks = getattr(results, "_tasks", None)
        if not tasks:
            return
        for index in range(len(tasks) - 1, -1, -1):
            task = tasks[index]
            if task.path != endpoint_path or task.verb.upper() != "PUT" or not task.failed:
                continue
            result = copy.deepcopy(task.result)
            result["success"] = True
            result["handled"] = True
            response = copy.deepcopy(task.response)
            response["handled"] = True
            response["handled_reason"] = "remote multicluster child VRF update is list-visible only"
            tasks[index] = task.model_copy(update={"result": result, "response": response, "failed": False, "changed": False})
            if getattr(results, "_final_result", None) is not None:
                results._final_result = None
            return

    def _is_list_only_mcfg_child_update(self, error: Exception, model_instance: NDVrfModel) -> bool:
        """
        Return True when a remote MCFG child exposes a VRF in list results but
        rejects direct per-VRF update routes.
        """
        if not (getattr(self.strategy, "is_child", False) and getattr(self.strategy, "is_multicluster", False)):
            return False
        error_text = str(error)
        if "Fabric" not in error_text or ("does not exist" not in error_text and "Invalid fabric name" not in error_text):
            return False
        return self._child_vrf_visible_in_list(model_instance)

    def _child_vrf_visible_in_list(self, model_instance: NDVrfModel) -> bool:
        """Check child VRF presence using the list route, avoiding the broken single-object route."""
        vrf_name, fabric_name = model_instance.get_identifier_value()
        try:
            endpoint = self._make_endpoint(self.strategy.vrfs_get_cls())
            if hasattr(endpoint, "endpoint_params"):
                endpoint.endpoint_params.filter = self._vrf_name_filter([vrf_name])
            result = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
        except Exception:
            return False

        if isinstance(result, dict):
            items = result.get("vrfs") or result.get("items") or []
        else:
            items = result or []
        for item in items:
            if not isinstance(item, dict):
                continue
            if (item.get("vrfName") or item.get("vrf_name")) != vrf_name:
                continue
            item_fabric = item.get("fabricName") or item.get("fabric_name")
            if item_fabric in (None, fabric_name):
                return True
        return False

    # ── Delete ────────────────────────────────────────────────────

    def delete(self, model_instance: NDVrfModel, **kwargs) -> ResponseType:
        """Delete a single VRF (delegates to bulk endpoint)."""
        return self.delete_bulk([model_instance])

    def delete_bulk(self, model_instances: list[NDVrfModel], **kwargs) -> ResponseType:
        """POST to vrfActions/remove to delete multiple VRFs in a single call."""
        if not model_instances:
            return {}
        # Composite identifier is (vrf_name, fabric_name); vrf_name is index 0.
        vrf_names = [m.get_identifier_value()[0] for m in model_instances]
        try:
            return self._delete_bulk_with_retry(vrf_names)
        except Exception as e:
            if self._delete_error_is_absent_vrf(e) and self._vrfs_absent(vrf_names):
                return {
                    "results": [
                        {
                            "vrfName": vrf_name,
                            "status": "success",
                        }
                        for vrf_name in vrf_names
                    ]
                }
            raise Exception(f"Bulk delete VRFs failed: {e}") from e

    def _delete_bulk_with_retry(self, vrf_names: list[str]) -> ResponseType:
        """Delete VRFs, retrying controller sync failures for only failed VRFs."""
        pending_vrf_names = list(vrf_names)
        successful_results: list[dict[str, Any]] = []
        last_error: Exception | None = None

        for attempt in range(1, self.delete_retry_attempts + 1):
            endpoint = self._make_endpoint(self.strategy.vrf_actions_remove_post_cls())
            try:
                response = self._request(
                    path=endpoint.path,
                    verb=endpoint.verb,
                    data={"vrfNames": pending_vrf_names},
                    operation_type=OperationType.DELETE,
                )
            except Exception as exc:
                last_error = exc
                response = self.rest_send.response_current.get("DATA", {})
                if not self._delete_response_has_sync_retry_failure(response):
                    raise

            successful, retryable, terminal_failed = self._parse_delete_results(response, pending_vrf_names)
            successful_results.extend(successful)

            if terminal_failed:
                failed_vrfs = ", ".join(item.get("vrfName", "") for item in terminal_failed)
                raise Exception(f"Bulk delete VRFs failed for non-retryable result(s): {failed_vrfs}; response: {response}")

            if not retryable:
                return self._combined_delete_response(response, successful_results)

            pending_vrf_names = [item["vrfName"] for item in retryable if item.get("vrfName")]
            if attempt == self.delete_retry_attempts:
                raise Exception(f"Bulk delete VRFs failed after {self.delete_retry_attempts} attempts: {response}") from last_error
            time.sleep(self.delete_retry_delay)

        raise Exception(f"Bulk delete VRFs failed after {self.delete_retry_attempts} attempts") from last_error

    def _parse_delete_results(
        self,
        response: ResponseType,
        requested_vrf_names: list[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        """Split delete results into successful, retryable, and terminal failures."""
        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list):
            return (
                [{"vrfName": vrf_name, "status": "success"} for vrf_name in requested_vrf_names],
                [],
                [],
            )

        successful: list[dict[str, Any]] = []
        retryable: list[dict[str, Any]] = []
        terminal_failed: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status", "")).lower()
            if status == "success":
                successful.append(item)
                continue
            if self._delete_result_is_sync_retry_failure(item):
                retryable.append(item)
                continue
            terminal_failed.append(item)
        return successful, retryable, terminal_failed

    def _combined_delete_response(
        self,
        response: ResponseType,
        successful_results: list[dict[str, Any]],
    ) -> ResponseType:
        """Return the final delete response with accumulated successes."""
        if isinstance(response, dict) and isinstance(response.get("results"), list):
            known = {(item.get("vrfName"), item.get("status"), item.get("message")) for item in response.get("results", []) if isinstance(item, dict)}
            combined = list(response.get("results", []))
            for item in successful_results:
                key = (item.get("vrfName"), item.get("status"), item.get("message"))
                if key not in known:
                    combined.append(item)
            response["results"] = combined
        return response

    @staticmethod
    def _delete_response_has_sync_retry_failure(response: ResponseType) -> bool:
        """Return True when a delete response contains a controller sync retry error."""
        if not isinstance(response, dict):
            return False
        results = response.get("results")
        if isinstance(results, list):
            return any(NDVrfOrchestrator._delete_result_is_sync_retry_failure(item) for item in results if isinstance(item, dict))
        return "fabric re-sync" in str(response).lower() or "fabric resync" in str(response).lower()

    @staticmethod
    def _delete_result_is_sync_retry_failure(result: dict[str, Any]) -> bool:
        """Return True for controller sync failures that are worth retrying."""
        message = str(result.get("message") or result.get("error") or result).lower()
        return "fabric re-sync" in message or "fabric resync" in message

    @staticmethod
    def _delete_error_is_absent_vrf(error: Exception) -> bool:
        """Return True for ND's remove response when the requested VRF is gone."""
        message = str(error)
        return "Invalid VRF" in message

    def _vrfs_absent(self, vrf_names: list[str]) -> bool:
        """Re-query the fabric and confirm all requested VRFs are absent."""
        remaining = set()
        for vrf in self.query_all() or []:
            vrf_name = vrf.get("vrf_name") or vrf.get("vrfName")
            if vrf_name:
                remaining.add(vrf_name)
        return not set(vrf_names).intersection(remaining)
