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
  nd_vrf.py (AnsibleModule entry)
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
                                  └── per child ──► nd_vrf (recursive)
"""

from typing import Any, ClassVar

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
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfactions import (
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

    # Strategy is injected at construction time by nd_vrf.py / VrfFabricResolver.
    strategy: BaseVrfStrategy | None = None

    def model_post_init(self, __context) -> None:
        if self.strategy is None:
            raise ValueError("NDVrfOrchestrator requires a strategy instance.")

    # ── Config preprocessing ──────────────────────────────────────

    @staticmethod
    def _value(config: dict[str, Any], *names: str, default: Any = None) -> Any:
        """Return the first present config value across Python and alias names."""
        for name in names:
            if name in config:
                return config[name]
        return default

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
            "fabric_name": self._value(config, "fabric_name", "fabricName", default=fabric_name),
            "vrf_name": self._value(config, "vrf_name", "vrfName"),
        }

        trm_kwargs = {
            "ipv4_trm": self._value(config, "trm_enable", "ipv4_trm"),
            "v4_rp_absent": self._value(config, "no_rp", "v4_rp_absent"),
            "v4_rp_external": self._value(config, "rp_external", "v4_rp_external"),
            "v4_rp_address": self._value(config, "rp_address", "v4_rp_address"),
            "loopback_number": self._value(config, "rp_loopback_id", "loopback_number"),
            "l3_vni_multicast_group": self._value(config, "underlay_mcast_ip", "l3_vni_multicast_group"),
            "v4_multicast_group": self._value(config, "overlay_mcast_group", "v4_multicast_group"),
            "trm_on_bgw": self._value(config, "trm_bgw_msite", "trm_on_bgw"),
            "mvpn_route_target_import": self._value(config, "import_mvpn_rt", "mvpn_route_target_import"),
            "mvpn_route_target_export": self._value(config, "export_mvpn_rt", "mvpn_route_target_export"),
        }
        trm_kwargs = {k: v for k, v in trm_kwargs.items() if v is not None}

        fabric_kwargs = {
            "l3_vni_without_vlan": self._value(config, "l3vni_wo_vlan", "l3_vni_without_vlan", default=False),
            "advertise_host_route": self._value(config, "adv_host_routes", "advertise_host_route", default=False),
            "advertise_default_route": self._value(config, "adv_default_routes", "advertise_default_route", default=True),
            "configure_static_default_route": self._value(
                config,
                "static_default_route",
                "configure_static_default_route",
                default=True,
            ),
            "bgp_password": self._value(config, "bgp_password", "bgpPassword"),
            "bgp_password_key_type": self._value(config, "bgp_passwd_encrypt", "bgp_password_key_type", default=3),
            "netflow": self._value(config, "netflow_enable", "netflow", default=False),
            "netflow_monitor": self._value(config, "nf_monitor", "netflow_monitor"),
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
        vrf_type = self._value(
            config,
            "vrf_type",
            "vrfType",
            default=self._default_vrf_type(),
        )
        transformed: dict[str, Any] = {
            "fabric_name": self._value(config, "fabric_name", "fabricName", default=fabric_name),
            "vrf_name": self._value(config, "vrf_name", "vrfName"),
            "vrf_type": vrf_type,
        }

        optional_top_level = {
            "tenant_name": ("tenant_name", "tenantName"),
            "vrf_id": ("vrf_id", "vrfId"),
            "vlan_id": ("vlan_id", "vlanId"),
            "default_security_action": (
                "default_security_action",
                "defaultSecurityAction",
            ),
            "default_security_group_tag": (
                "default_security_group_tag",
                "defaultSecurityGroupTag",
            ),
        }
        for target, names in optional_top_level.items():
            value = self._value(config, *names)
            if value is not None:
                transformed[target] = value

        custom_template_fields = {
            "service_vrf_template_name": (
                "service_vrf_template_name",
                "serviceVrfTemplateName",
            ),
            "vrf_template_name": ("vrf_template_name", "vrfTemplateName"),
            "vrf_extension_template_name": (
                "vrf_extension_template_name",
                "vrfExtensionTemplateName",
            ),
            "vrf_template_config": ("vrf_template_config", "vrfTemplateConfig"),
        }
        for target, names in custom_template_fields.items():
            value = self._value(config, *names)
            if value is not None:
                if vrf_type != VrfType.USER_DEFINED.value:
                    raise ValueError(f"{target} requires vrf_type={VrfType.USER_DEFINED.value}")
                transformed[target] = value

        if vrf_type == VrfType.USER_DEFINED.value:
            return transformed

        core_data = VxlanCoreData(
            vrf_vlan_name=self._value(config, "vrf_vlan_name", "vrfVlanName"),
            vrf_interface_description=self._value(
                config,
                "vrf_intf_desc",
                "vrf_interface_description",
                "vrfIntfDesc",
                "vrfInterfaceDescription",
            ),
            vrf_description=self._value(config, "vrf_description", "vrfDescription"),
            mtu=self._value(config, "vrf_int_mtu", "mtu", "vrfIntMtu", default=9216),
            routing_tag=self._value(
                config,
                "loopback_route_tag",
                "routing_tag",
                "routingTag",
                default=12345,
            ),
            vrf_route_map=self._value(
                config,
                "redist_direct_rmap",
                "vrf_route_map",
                "vrfRouteMap",
                default="FABRIC-RMAP-REDIST-SUBNET",
            ),
            v6_vrf_route_map=self._value(
                config,
                "v6_redist_direct_rmap",
                "v6_vrf_route_map",
                "v6VrfRouteMap",
                default="FABRIC-RMAP-REDIST-SUBNET",
            ),
            max_bgp_paths=self._value(config, "max_bgp_paths", "maxBgpPaths", default=1),
            max_ibgp_paths=self._value(config, "max_ibgp_paths", "maxIbgpPaths", default=2),
            ipv6_link_local=self._value(
                config,
                "ipv6_linklocal_enable",
                "ipv6_link_local",
                "ipv6LinkLocal",
                default=True,
            ),
            disable_rt_auto=self._value(config, "disable_rt_auto", "disableRtAuto", default=False),
            route_target_import=self._value(config, "import_vpn_rt", "route_target_import"),
            route_target_export=self._value(config, "export_vpn_rt", "route_target_export"),
            evpn_route_target_import=self._value(
                config,
                "import_evpn_rt",
                "evpn_route_target_import",
            ),
            evpn_route_target_export=self._value(
                config,
                "export_evpn_rt",
                "evpn_route_target_export",
            ),
        )

        trm_data = TrmData(
            ipv4_trm=self._value(config, "trm_enable", "ipv4_trm", default=False),
            ipv6_trm=self._value(config, "ipv6_trm", default=False),
            v4_rp_absent=self._value(config, "no_rp", "v4_rp_absent", default=False),
            v4_rp_external=self._value(config, "rp_external", "v4_rp_external", default=False),
            v4_rp_address=self._value(config, "rp_address", "v4_rp_address"),
            loopback_number=self._value(config, "rp_loopback_id", "loopback_number"),
            l3_vni_multicast_group=self._value(config, "underlay_mcast_ip", "l3_vni_multicast_group"),
            v4_multicast_group=self._value(config, "overlay_mcast_group", "v4_multicast_group"),
            trm_on_bgw=self._value(config, "trm_bgw_msite", "trm_on_bgw", default=False),
            mvpn_route_target_import=self._value(
                config,
                "import_mvpn_rt",
                "mvpn_route_target_import",
            ),
            mvpn_route_target_export=self._value(
                config,
                "export_mvpn_rt",
                "mvpn_route_target_export",
            ),
        )

        fabric_data = VxlanFabricInstance(
            l3_vni_without_vlan=self._value(config, "l3vni_wo_vlan", "l3_vni_without_vlan", default=False),
            advertise_host_route=self._value(config, "adv_host_routes", "advertise_host_route", default=False),
            advertise_default_route=self._value(config, "adv_default_routes", "advertise_default_route", default=True),
            configure_static_default_route=self._value(
                config,
                "static_default_route",
                "configure_static_default_route",
                default=True,
            ),
            bgp_password=self._value(config, "bgp_password", "bgpPassword"),
            bgp_password_key_type=self._value(config, "bgp_passwd_encrypt", "bgp_password_key_type", default=3),
            netflow=self._value(config, "netflow_enable", "netflow", default=False),
            netflow_monitor=self._value(config, "nf_monitor", "netflow_monitor"),
            trm_data=trm_data,
        )

        transformed["core_data"] = core_data.to_payload()
        if not getattr(self.strategy, "is_parent", False):
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

    # ── Query ─────────────────────────────────────────────────────

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """GET all VRFs for the fabric."""
        try:
            endpoint = self._make_endpoint(self.strategy.vrfs_get_cls())
            result = self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                not_found_ok=True,
                operation_type=OperationType.QUERY,
            )
            if isinstance(result, dict):
                return result.get("vrfs") or result.get("items") or []
            return result or []
        except Exception as e:
            raise Exception(f"Query all VRFs failed: {e}") from e

    # ── Create ────────────────────────────────────────────────────

    def create(self, model_instance: NDVrfModel, **kwargs) -> ResponseType:
        """POST a single VRF."""
        return self.create_bulk([model_instance])

    def create_bulk(self, model_instances: list[NDVrfModel], **kwargs) -> ResponseType:
        """POST a list of VRFs in a single request."""
        if not model_instances:
            return {}
        try:
            endpoint = self._make_endpoint(self.strategy.vrfs_post_cls())
            return self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data={"vrfs": [m.to_payload() for m in model_instances]},
                operation_type=OperationType.CREATE,
            )
        except Exception as e:
            raise Exception(f"Bulk create VRFs failed: {e}") from e

    # ── Update ────────────────────────────────────────────────────

    def update(self, model_instance: NDVrfModel, **kwargs) -> ResponseType:
        """PUT (replace) a single VRF identified by vrfName."""
        try:
            # Composite identifier is (vrf_name, fabric_name); vrf_name is index 0.
            vrf_name = model_instance.get_identifier_value()[0]
            endpoint = self._make_endpoint(
                self.strategy.vrf_put_cls(),
                vrf_name=vrf_name,
            )
            payload = model_instance.to_payload()
            if self.strategy.is_child:
                payload = {key: value for key, value in payload.items() if key in ("fabricName", "vrfName", "vrfType", "fabricData")}
            return self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data=payload,
                operation_type=OperationType.UPDATE,
            )
        except Exception as e:
            raise Exception(f"Update VRF failed for {model_instance.get_identifier_value()}: {e}") from e

    # ── Delete ────────────────────────────────────────────────────

    def delete(self, model_instance: NDVrfModel, **kwargs) -> ResponseType:
        """Delete a single VRF (delegates to bulk endpoint)."""
        return self.delete_bulk([model_instance])

    def delete_bulk(self, model_instances: list[NDVrfModel], **kwargs) -> ResponseType:
        """POST to vrfActions/remove to delete multiple VRFs in a single call."""
        if not model_instances:
            return {}
        try:
            # Composite identifier is (vrf_name, fabric_name); vrf_name is index 0.
            vrf_names = [m.get_identifier_value()[0] for m in model_instances]
            endpoint = self._make_endpoint(self.strategy.vrf_actions_remove_post_cls())
            return self._request(
                path=endpoint.path,
                verb=endpoint.verb,
                data={"vrfNames": vrf_names},
                operation_type=OperationType.DELETE,
            )
        except Exception as e:
            raise Exception(f"Bulk delete VRFs failed: {e}") from e
