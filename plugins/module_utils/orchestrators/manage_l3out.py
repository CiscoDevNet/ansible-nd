# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import re
from copy import deepcopy
from typing import Any, ClassVar, Dict, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_l3out import (
    EpManageL3OutDelete,
    EpManageL3OutGet,
    EpManageL3OutPost,
    EpManageL3OutPut,
    EpManageL3OutsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.l3out.l3out import (
    L3OutModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import (
    NDBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import (
    ResponseType,
)


# --- Field-name mapping tables (snake_case <-> camelCase) ---

# Top-level L3Out fields
_L3OUT_PARAM_TO_API = {
    "fabric1_name": "fabric1Name",
    "fabric2_name": "fabric2Name",
    "vrf1_name": "vrf1Name",
    "vrf2_name": "vrf2Name",
    "tenant1_name": "tenant1Name",
    "tenant2_name": "tenant2Name",
    "configured_fabrics": "configuredFabrics",
    "ip_version": "ipVersion",
    "connectivity_details": "connectivityDetails",
    "routing_details": "routingDetails",
}
_L3OUT_API_TO_PARAM = {v: k for k, v in _L3OUT_PARAM_TO_API.items()}

# Connectivity details fields
_CONN_PARAM_TO_API = {
    "routing_interface_type": "routingInterfaceType",
    "dot1q_id": "dot1qId",
    "vlan_id": "vlanId",
    "ipv4_pim": "ipv4Pim",
    "ipv6_pim": "ipv6Pim",
    "ipv4_mask_length": "ipv4MaskLength",
    "ipv6_prefix_length": "ipv6PrefixLength",
    "switch1_details": "switch1Details",
    "switch2_details": "switch2Details",
}
_CONN_API_TO_PARAM = {v: k for k, v in _CONN_PARAM_TO_API.items()}

# Switch details fields
_SWITCH_PARAM_TO_API = {
    "switch_id": "switchId",
    "interface_name": "interfaceName",
    "interface_admin_state": "interfaceAdminState",
    "ipv4_address": "ipv4Address",
    "ipv6_address": "ipv6Address",
    "netflow_monitor": "netflowMonitor",
    "interface_description": "interfaceDescription",
}
_SWITCH_API_TO_PARAM = {v: k for k, v in _SWITCH_PARAM_TO_API.items()}

# Routing details fields (BGP)
_ROUTING_PARAM_TO_API = {
    "routing_protocol": "routingProtocol",
    "hold_interval": "holdInterval",
    "keep_alive_interval": "keepAliveInterval",
    "fabric1_details": "fabric1Details",
    "fabric2_details": "fabric2Details",
    "fabric1_static_routes": "fabric1StaticRoutes",
    "fabric2_static_routes": "fabric2StaticRoutes",
}
_ROUTING_API_TO_PARAM = {v: k for k, v in _ROUTING_PARAM_TO_API.items()}

# Fabric peering details fields (BGP)
_FABRIC_PEERING_PARAM_TO_API = {
    "auth_key": "authKey",
    "auth_key_encryption_type": "authKeyEncryptionType",
    "advertise_host_routes": "advertiseHostRoutes",
    "advertise_default_route": "advertiseDefaultRoute",
    "configure_static_default_route": "configureStaticDefaultRoute",
    "soft_reconfiguration_inbound": "softReconfigurationInbound",
    "default_originate": "defaultOriginate",
    "local_asn": "localAsn",
    "no_prepend": "noPrepend",
    "replace_as": "replaceAs",
    "as_override": "asOverride",
    "disable_peer_as_check": "disablePeerAsCheck",
    "log_neighbor_change": "logNeighborChange",
    "allow_as_in_asn_occurence_number": "allowAsInAsnOccurenceNumber",
    "ipv4_peering_details": "ipv4PeeringDetails",
    "ipv6_peering_details": "ipv6PeeringDetails",
    "ipv4_route_map_in": "ipv4RouteMapIn",
    "ipv4_route_map_out": "ipv4RouteMapOut",
    "ipv6_route_map_in": "ipv6RouteMapIn",
    "ipv6_route_map_out": "ipv6RouteMapOut",
}
_FABRIC_PEERING_API_TO_PARAM = {v: k for k, v in _FABRIC_PEERING_PARAM_TO_API.items()}

# Static route fields
_STATIC_ROUTE_PARAM_TO_API = {
    "ip_version": "ipVersion",
    "ip_prefix": "ipPrefix",
    "next_hop": "nextHop",
    "switch_ids": "switchIds",
    "route_preference": "routePreference",
    "next_hop_name": "nextHopName",
    "next_hop_vrf_name": "nextHopVrfName",
    "track_id": "trackId",
}
_STATIC_ROUTE_API_TO_PARAM = {v: k for k, v in _STATIC_ROUTE_PARAM_TO_API.items()}


class ManageL3OutOrchestrator(NDBaseOrchestrator[L3OutModel]):
    """
    Orchestrator for L3Out (Layer-3 Out) resources on Nexus Dashboard.

    This API uses the following pattern:
    - List: GET returns {"l3Outs": [...]} or bare list
    - Create: POST with {"l3Outs": [...]} body, returns 207 Multi-Status
    - Get: GET single L3Out by name
    - Update: PUT single L3Out (replaces fully)
    - Delete: DELETE single L3Out

    Supports states: merged (full object merge), replaced (full replace),
    deleted (whole L3Out), gathered (query only).
    """

    model_class: ClassVar[Type[NDBaseModel]] = L3OutModel

    # Endpoint bindings (required by NDBaseOrchestrator)
    create_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageL3OutsGet

    # Fabric scope injected at orchestrator construction time
    fabric_name: str = ""

    # -------------------------------------------------------------------------
    # Generic conversion helpers
    # -------------------------------------------------------------------------

    def _convert_dict(
        self, data: Dict[str, Any], mapping: Dict[str, str], skip_none: bool = True
    ) -> Dict[str, Any]:
        """Convert dict keys using the provided mapping."""
        result = {}
        for key, value in data.items():
            if skip_none and value is None:
                continue
            new_key = mapping.get(key, key)
            result[new_key] = value
        return result

    # -------------------------------------------------------------------------
    # Switch details conversion
    # -------------------------------------------------------------------------

    def _switch_details_to_api(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Convert switch details from Ansible snake_case to API camelCase."""
        if not details:
            return {}
        return self._convert_dict(details, _SWITCH_PARAM_TO_API)

    def _switch_details_from_api(self, api_details: Dict[str, Any]) -> Dict[str, Any]:
        """Convert switch details from API camelCase to Ansible snake_case."""
        if not api_details:
            return {}
        return self._convert_dict(api_details, _SWITCH_API_TO_PARAM)

    # -------------------------------------------------------------------------
    # Link conversion
    # -------------------------------------------------------------------------

    def _link_to_api(self, link: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a link dict from Ansible format to API format."""
        api_link = {}

        for key, value in link.items():
            if value is None:
                continue

            if key in ("switch1_details", "switch2_details"):
                api_key = _CONN_PARAM_TO_API.get(key, key)
                api_link[api_key] = self._switch_details_to_api(value)
            else:
                api_key = _CONN_PARAM_TO_API.get(key, key)
                api_link[api_key] = value

        return api_link

    def _link_from_api(self, api_link: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a link dict from API format to Ansible format."""
        link = {}

        for key, value in api_link.items():
            if value is None:
                continue

            if key in ("switch1Details", "switch2Details"):
                ansible_key = _CONN_API_TO_PARAM.get(key, key)
                link[ansible_key] = self._switch_details_from_api(value)
            else:
                ansible_key = _CONN_API_TO_PARAM.get(key, key)
                link[ansible_key] = value

        return link

    # -------------------------------------------------------------------------
    # Connectivity details conversion
    # -------------------------------------------------------------------------

    def _connectivity_to_api(self, conn: Dict[str, Any]) -> Dict[str, Any]:
        """Convert connectivity details from Ansible format to API format."""
        if not conn:
            return {}

        api_conn = {
            "routingInterfaceType": conn.get("routing_interface_type"),
        }

        links = conn.get("links", [])
        if links:
            api_conn["links"] = [self._link_to_api(link) for link in links]

        return api_conn

    def _connectivity_from_api(self, api_conn: Dict[str, Any]) -> Dict[str, Any]:
        """Convert connectivity details from API format to Ansible format."""
        if not api_conn:
            return {}

        conn = {
            "routing_interface_type": api_conn.get("routingInterfaceType"),
        }

        links = api_conn.get("links", [])
        if links:
            conn["links"] = [self._link_from_api(link) for link in links]

        return conn

    # -------------------------------------------------------------------------
    # Static route conversion
    # -------------------------------------------------------------------------

    def _static_route_to_api(self, route: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a static route from Ansible format to API format."""
        return self._convert_dict(route, _STATIC_ROUTE_PARAM_TO_API)

    def _static_route_from_api(self, api_route: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a static route from API format to Ansible format."""
        return self._convert_dict(api_route, _STATIC_ROUTE_API_TO_PARAM)

    # -------------------------------------------------------------------------
    # Fabric peering details conversion (BGP)
    # -------------------------------------------------------------------------

    def _route_maps_to_api(self, route_maps: Dict[str, Any]) -> Dict[str, Any]:
        """Convert route maps from Ansible format to API format."""
        if not route_maps:
            return {}
        return self._convert_dict(route_maps, _FABRIC_PEERING_PARAM_TO_API)

    def _route_maps_from_api(self, api_route_maps: Dict[str, Any]) -> Dict[str, Any]:
        """Convert route maps from API format to Ansible format."""
        if not api_route_maps:
            return {}
        return self._convert_dict(api_route_maps, _FABRIC_PEERING_API_TO_PARAM)

    def _fabric_peering_to_api(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Convert fabric peering details from Ansible format to API format."""
        if not details:
            return {}

        api_details = {}

        for key, value in details.items():
            if value is None:
                continue

            if key in ("ipv4_peering_details", "ipv6_peering_details"):
                api_key = _FABRIC_PEERING_PARAM_TO_API.get(key, key)
                api_details[api_key] = self._route_maps_to_api(value)
            else:
                api_key = _FABRIC_PEERING_PARAM_TO_API.get(key, key)
                api_details[api_key] = value

        return api_details

    def _fabric_peering_from_api(self, api_details: Dict[str, Any]) -> Dict[str, Any]:
        """Convert fabric peering details from API format to Ansible format."""
        if not api_details:
            return {}

        details = {}

        for key, value in api_details.items():
            if value is None:
                continue

            if key in ("ipv4PeeringDetails", "ipv6PeeringDetails"):
                ansible_key = _FABRIC_PEERING_API_TO_PARAM.get(key, key)
                details[ansible_key] = self._route_maps_from_api(value)
            else:
                ansible_key = _FABRIC_PEERING_API_TO_PARAM.get(key, key)
                details[ansible_key] = value

        return details

    # -------------------------------------------------------------------------
    # Routing details conversion
    # -------------------------------------------------------------------------

    def _routing_to_api(self, routing: Dict[str, Any]) -> Dict[str, Any]:
        """Convert routing details from Ansible format to API format."""
        if not routing:
            return {}

        api_routing = {}
        protocol = routing.get("routing_protocol")
        api_routing["routingProtocol"] = protocol

        if protocol == "static":
            # Handle static routes
            for key in ("fabric1_static_routes", "fabric2_static_routes"):
                routes = routing.get(key, [])
                if routes:
                    api_key = _ROUTING_PARAM_TO_API.get(key, key)
                    api_routing[api_key] = [
                        self._static_route_to_api(r) for r in routes
                    ]

        elif protocol == "bgp":
            # Handle BGP common fields
            for key in ("auth", "bfd", "hold_interval", "keep_alive_interval"):
                value = routing.get(key)
                if value is not None:
                    api_key = _ROUTING_PARAM_TO_API.get(key, key)
                    api_routing[api_key] = value

            # Handle fabric details
            for key in ("fabric1_details", "fabric2_details"):
                details = routing.get(key)
                if details:
                    api_key = _ROUTING_PARAM_TO_API.get(key, key)
                    api_routing[api_key] = self._fabric_peering_to_api(details)

        return api_routing

    def _routing_from_api(self, api_routing: Dict[str, Any]) -> Dict[str, Any]:
        """Convert routing details from API format to Ansible format."""
        if not api_routing:
            return {}

        routing = {}
        protocol = api_routing.get("routingProtocol")
        routing["routing_protocol"] = protocol

        if protocol == "static":
            # Handle static routes
            for api_key in ("fabric1StaticRoutes", "fabric2StaticRoutes"):
                routes = api_routing.get(api_key, [])
                if routes:
                    ansible_key = _ROUTING_API_TO_PARAM.get(api_key, api_key)
                    routing[ansible_key] = [
                        self._static_route_from_api(r) for r in routes
                    ]

        elif protocol == "bgp":
            # Handle BGP common fields
            for api_key in ("auth", "bfd", "holdInterval", "keepAliveInterval"):
                value = api_routing.get(api_key)
                if value is not None:
                    ansible_key = _ROUTING_API_TO_PARAM.get(api_key, api_key)
                    routing[ansible_key] = value

            # Handle fabric details
            for api_key in ("fabric1Details", "fabric2Details"):
                details = api_routing.get(api_key)
                if details:
                    ansible_key = _ROUTING_API_TO_PARAM.get(api_key, api_key)
                    routing[ansible_key] = self._fabric_peering_from_api(details)

        return routing

    # -------------------------------------------------------------------------
    # L3Out conversion
    # -------------------------------------------------------------------------

    def _l3out_to_api(self, l3out: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an L3Out dict from Ansible format to API format."""
        api_l3out = {"name": l3out["name"]}

        # Simple fields
        for key in (
            "fabric1_name",
            "fabric2_name",
            "vrf1_name",
            "vrf2_name",
            "tenant1_name",
            "tenant2_name",
            "configured_fabrics",
            "ip_version",
            "attach",
        ):
            value = l3out.get(key)
            if value is not None:
                api_key = _L3OUT_PARAM_TO_API.get(key, key)
                api_l3out[api_key] = value

        # Complex nested fields
        conn = l3out.get("connectivity_details")
        if conn:
            api_l3out["connectivityDetails"] = self._connectivity_to_api(conn)

        routing = l3out.get("routing_details")
        if routing:
            api_l3out["routingDetails"] = self._routing_to_api(routing)

        return api_l3out

    def _l3out_from_api(self, api_l3out: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an L3Out dict from API format to Ansible format."""
        l3out = {"name": api_l3out["name"]}

        # Simple fields
        for api_key in (
            "fabric1Name",
            "fabric2Name",
            "vrf1Name",
            "vrf2Name",
            "tenant1Name",
            "tenant2Name",
            "configuredFabrics",
            "ipVersion",
            "attach",
        ):
            value = api_l3out.get(api_key)
            if value is not None:
                ansible_key = _L3OUT_API_TO_PARAM.get(api_key, api_key)
                l3out[ansible_key] = value

        # Complex nested fields
        conn = api_l3out.get("connectivityDetails")
        if conn:
            l3out["connectivity_details"] = self._connectivity_from_api(conn)

        routing = api_l3out.get("routingDetails")
        if routing:
            l3out["routing_details"] = self._routing_from_api(routing)

        return l3out

    # -------------------------------------------------------------------------
    # Input validation
    # -------------------------------------------------------------------------

    def validate_config(self, state: str, config: List[Dict]) -> None:
        """Validate the playbook configuration. Raises ValueError on error."""
        if not config and state in ("merged", "replaced"):
            raise ValueError("config is required when state is '{0}'".format(state))

        for l3out in config:
            name = l3out.get("name", "")
            if not re.match(r"^[a-zA-Z0-9_-]+$", name):
                raise ValueError(
                    "L3Out name '{0}' is invalid. Only alphanumeric characters, "
                    "underscores, and hyphens are allowed.".format(name)
                )
            if len(name) > 64:
                raise ValueError(
                    "L3Out name '{0}' exceeds the maximum length of 64 characters.".format(
                        name
                    )
                )

            if state in ("merged", "replaced"):
                self._validate_l3out_required_fields(l3out)
                self._validate_connectivity(l3out)
                self._validate_routing(l3out)

    def _validate_l3out_required_fields(self, l3out: Dict[str, Any]) -> None:
        """Validate required fields for L3Out creation/update."""
        name = l3out.get("name", "")
        required_fields = [
            "fabric1_name",
            "fabric2_name",
            "vrf1_name",
            "vrf2_name",
            "configured_fabrics",
            "ip_version",
            "connectivity_details",
            "routing_details",
        ]

        for field in required_fields:
            if not l3out.get(field):
                raise ValueError(
                    "L3Out '{0}': '{1}' is required for create/update operations".format(
                        name, field
                    )
                )

    def _validate_connectivity(self, l3out: Dict[str, Any]) -> None:
        """Validate connectivity details."""
        name = l3out.get("name", "")
        conn = l3out.get("connectivity_details", {})

        if not conn:
            return

        interface_type = conn.get("routing_interface_type")
        if not interface_type:
            raise ValueError(
                "L3Out '{0}': connectivity_details.routing_interface_type is required".format(
                    name
                )
            )

        links = conn.get("links", [])
        for i, link in enumerate(links):
            self._validate_link(name, i, link, interface_type, l3out.get("ip_version"))

    def _validate_link(
        self,
        l3out_name: str,
        index: int,
        link: Dict[str, Any],
        interface_type: str,
        ip_version: str,
    ) -> None:
        """Validate a single link."""
        # Type-specific required fields
        if interface_type == "subInterface" and link.get("dot1q_id") is None:
            raise ValueError(
                "L3Out '{0}' link {1}: dot1q_id is required for subInterface type".format(
                    l3out_name, index
                )
            )

        if interface_type == "svi" and link.get("vlan_id") is None:
            raise ValueError(
                "L3Out '{0}' link {1}: vlan_id is required for svi type".format(
                    l3out_name, index
                )
            )

        # Switch details validation
        for switch_key in ("switch1_details", "switch2_details"):
            details = link.get(switch_key)
            if details:
                self._validate_switch_details(
                    l3out_name, index, switch_key, details, ip_version
                )

    def _validate_switch_details(
        self,
        l3out_name: str,
        link_index: int,
        switch_key: str,
        details: Dict[str, Any],
        ip_version: str,
    ) -> None:
        """Validate switch details."""
        required = ["switch_id", "interface_name"]
        for field in required:
            if not details.get(field):
                raise ValueError(
                    "L3Out '{0}' link {1} {2}: '{3}' is required".format(
                        l3out_name, link_index, switch_key, field
                    )
                )

        # IP version validation
        if ip_version in ("ipv4", "both") and not details.get("ipv4_address"):
            raise ValueError(
                "L3Out '{0}' link {1} {2}: ipv4_address is required when ip_version is '{3}'".format(
                    l3out_name, link_index, switch_key, ip_version
                )
            )

        if ip_version in ("ipv6", "both") and not details.get("ipv6_address"):
            raise ValueError(
                "L3Out '{0}' link {1} {2}: ipv6_address is required when ip_version is '{3}'".format(
                    l3out_name, link_index, switch_key, ip_version
                )
            )

        # Netflow validation
        if details.get("netflow") and not details.get("netflow_monitor"):
            raise ValueError(
                "L3Out '{0}' link {1} {2}: netflow_monitor is required when netflow is enabled".format(
                    l3out_name, link_index, switch_key
                )
            )

    def _validate_routing(self, l3out: Dict[str, Any]) -> None:
        """Validate routing details."""
        name = l3out.get("name", "")
        routing = l3out.get("routing_details", {})

        if not routing:
            return

        protocol = routing.get("routing_protocol")
        if not protocol:
            raise ValueError(
                "L3Out '{0}': routing_details.routing_protocol is required".format(name)
            )

        if protocol == "static":
            self._validate_static_routing(name, routing, l3out.get("ip_version"))
        elif protocol == "bgp":
            self._validate_bgp_routing(name, routing)

    def _validate_static_routing(
        self, l3out_name: str, routing: Dict[str, Any], ip_version: str
    ) -> None:
        """Validate static routing configuration."""
        for routes_key in ("fabric1_static_routes", "fabric2_static_routes"):
            routes = routing.get(routes_key, [])
            for i, route in enumerate(routes):
                # Required fields
                for field in ("ip_version", "ip_prefix", "next_hop", "switch_ids"):
                    if not route.get(field):
                        raise ValueError(
                            "L3Out '{0}' {1}[{2}]: '{3}' is required".format(
                                l3out_name, routes_key, i, field
                            )
                        )

    def _validate_bgp_routing(self, l3out_name: str, routing: Dict[str, Any]) -> None:
        """Validate BGP routing configuration."""
        # Validate hold_interval
        hold_interval = routing.get("hold_interval")
        if hold_interval is not None and (hold_interval < 3 or hold_interval > 3600):
            raise ValueError(
                "L3Out '{0}': hold_interval must be between 3 and 3600".format(
                    l3out_name
                )
            )

        # Validate keep_alive_interval
        keep_alive = routing.get("keep_alive_interval")
        if keep_alive is not None and (keep_alive < 1 or keep_alive > 3600):
            raise ValueError(
                "L3Out '{0}': keep_alive_interval must be between 1 and 3600".format(
                    l3out_name
                )
            )

        # If auth is enabled, auth_key should be provided in fabric details
        if routing.get("auth"):
            for details_key in ("fabric1_details", "fabric2_details"):
                details = routing.get(details_key, {})
                if details and not details.get("auth_key"):
                    raise ValueError(
                        "L3Out '{0}' {1}: auth_key is required when auth is enabled".format(
                            l3out_name, details_key
                        )
                    )

    # -------------------------------------------------------------------------
    # Current state retrieval
    # -------------------------------------------------------------------------

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """Fetch all L3Outs for the fabric and return as a list of API dicts."""
        try:
            ep = self.query_all_endpoint()
            ep.fabric_name = self.fabric_name
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            if not result:
                return []
            if isinstance(result, dict):
                return result.get("l3Outs", []) or []
            if isinstance(result, list):
                return result
            return []
        except Exception as e:
            raise Exception("Query all L3Outs failed: {0}".format(e)) from e

    def _get_all_l3outs(self) -> List[Dict[str, Any]]:
        """Return current L3Outs as Ansible-format dicts."""
        return [self._l3out_from_api(item) for item in (self.query_all() or [])]

    # -------------------------------------------------------------------------
    # Diff helpers
    # -------------------------------------------------------------------------

    def _find_have(self, name: str, have: List[Dict]) -> Optional[Dict]:
        """Return the existing L3Out with the given name, or None."""
        for l3out in have:
            if l3out["name"] == name:
                return l3out
        return None

    def _deep_equal(self, obj1: Any, obj2: Any) -> bool:
        """Recursively compare two objects for equality."""
        if type(obj1) != type(obj2):
            return False

        if isinstance(obj1, dict):
            if set(obj1.keys()) != set(obj2.keys()):
                return False
            return all(self._deep_equal(obj1[k], obj2[k]) for k in obj1)

        if isinstance(obj1, list):
            if len(obj1) != len(obj2):
                return False
            return all(self._deep_equal(v1, v2) for v1, v2 in zip(obj1, obj2))

        return obj1 == obj2

    def _l3outs_equal(self, l3out1: Dict, l3out2: Dict) -> bool:
        """Compare two L3Out configurations for equality."""
        # Compare all fields
        fields_to_compare = [
            "name",
            "fabric1_name",
            "fabric2_name",
            "vrf1_name",
            "vrf2_name",
            "tenant1_name",
            "tenant2_name",
            "configured_fabrics",
            "ip_version",
            "connectivity_details",
            "routing_details",
        ]

        for field in fields_to_compare:
            val1 = l3out1.get(field)
            val2 = l3out2.get(field)

            if not self._deep_equal(val1, val2):
                return False

        return True

    def _merge_l3outs(self, have: Dict, want: Dict) -> Dict:
        """
        Merge want into have for the merged state.

        For L3Outs, this is a full replacement of the object since the
        structure is complex with nested discriminated types.
        """
        # Deep merge - want values override have values
        merged = deepcopy(have)

        for key, value in want.items():
            if value is not None:
                merged[key] = deepcopy(value)

        return merged

    def _build_want(self, config: List[Dict]) -> List[Dict]:
        """Build the desired-state list from module params."""
        result = []
        for l3out in config:
            want_l3out = {"name": l3out["name"]}

            # Copy all provided fields
            for key in (
                "fabric1_name",
                "fabric2_name",
                "vrf1_name",
                "vrf2_name",
                "tenant1_name",
                "tenant2_name",
                "configured_fabrics",
                "ip_version",
                "connectivity_details",
                "routing_details",
            ):
                if l3out.get(key) is not None:
                    want_l3out[key] = deepcopy(l3out[key])

            result.append(want_l3out)

        return result

    # -------------------------------------------------------------------------
    # API write helpers
    # -------------------------------------------------------------------------

    def _create_l3out(self, l3out: Dict) -> Dict:
        """Create a new L3Out."""
        ep = self.create_endpoint()
        ep.fabric_name = self.fabric_name
        data = {"l3Outs": [self._l3out_to_api(l3out)]}
        result = self._request(path=ep.path, verb=ep.verb, data=data)
        if result:
            items = result.get("l3Outs", result if isinstance(result, list) else [])
            for item in items:
                if isinstance(item, dict) and item.get("statusCode", 200) >= 400:
                    raise Exception(
                        "Failed to create L3Out '{0}': {1}".format(l3out["name"], item)
                    )
        return result or {}

    def _update_l3out(self, l3out: Dict) -> Dict:
        """Update an existing L3Out."""
        ep = self.update_endpoint()
        ep.fabric_name = self.fabric_name
        ep.l3out_name = l3out["name"]
        return (
            self._request(path=ep.path, verb=ep.verb, data=self._l3out_to_api(l3out))
            or {}
        )

    def _delete_l3out(self, l3out_name: str) -> Dict:
        """Delete an L3Out."""
        ep = self.delete_endpoint()
        ep.fabric_name = self.fabric_name
        ep.l3out_name = l3out_name
        return self._request(path=ep.path, verb=ep.verb, not_found_ok=True) or {}

    # -------------------------------------------------------------------------
    # State execution
    # -------------------------------------------------------------------------

    def run(self, state: str, config: List[Dict], check_mode: bool = False) -> Dict:
        """
        Execute the full module workflow for the given state and return the
        result dict ready to pass to module.exit_json().
        """
        self.validate_config(state, config)

        have = self._get_all_l3outs()
        want = self._build_want(config)

        result = dict(
            changed=False,
            diff=[{"merged": [], "replaced": [], "deleted": [], "gathered": []}],
            response=[],
            l3outs=[],
        )

        if state == "gathered":
            self._run_gathered(have, want, result)
            return result

        # Build diffs
        diff_create: List[Dict] = []
        diff_update: List[Dict] = []
        diff_delete: List[str] = []

        if state == "merged":
            for want_l3out in want:
                have_l3out = self._find_have(want_l3out["name"], have)
                if have_l3out is None:
                    diff_create.append(want_l3out)
                    result["diff"][0]["merged"].append(want_l3out["name"])
                else:
                    merged = self._merge_l3outs(have_l3out, want_l3out)
                    if not self._l3outs_equal(have_l3out, merged):
                        diff_update.append(merged)
                        result["diff"][0]["merged"].append(want_l3out["name"])

        elif state == "replaced":
            for want_l3out in want:
                have_l3out = self._find_have(want_l3out["name"], have)
                if have_l3out is None:
                    diff_create.append(want_l3out)
                    result["diff"][0]["replaced"].append(want_l3out["name"])
                elif not self._l3outs_equal(have_l3out, want_l3out):
                    diff_update.append(want_l3out)
                    result["diff"][0]["replaced"].append(want_l3out["name"])

        elif state == "deleted":
            targets = want if want else have
            for l3out in targets:
                if self._find_have(l3out["name"], have) is not None:
                    diff_delete.append(l3out["name"])
                    result["diff"][0]["deleted"].append(l3out["name"])

        result["changed"] = bool(diff_create or diff_update or diff_delete)

        if check_mode:
            return result

        for l3out in diff_create:
            resp = self._create_l3out(l3out)
            result["response"].append(deepcopy(resp))

        for l3out in diff_update:
            resp = self._update_l3out(l3out)
            result["response"].append(deepcopy(resp))

        for l3out_name in diff_delete:
            resp = self._delete_l3out(l3out_name)
            result["response"].append(deepcopy(resp))

        return result

    def _run_gathered(self, have: List[Dict], want: List[Dict], result: Dict) -> None:
        """Populate result with gathered L3Out data (no changes)."""
        if not want:
            result["l3outs"] = list(have)
            result["diff"][0]["gathered"] = [item["name"] for item in have]
        else:
            for want_l3out in want:
                have_l3out = self._find_have(want_l3out["name"], have)
                if have_l3out is not None:
                    result["l3outs"].append(have_l3out)
                    result["diff"][0]["gathered"].append(want_l3out["name"])
