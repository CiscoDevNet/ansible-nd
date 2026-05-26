# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import ClassVar, Dict, List, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.models.nested import NDNestedModel


# =============================================================================
# Nested Models - Bottom-up hierarchy
# =============================================================================


class Ipv4PeeringModel(NDNestedModel):
    """IPv4 BGP peering route map configuration."""

    ipv4_route_map_in: Optional[str] = Field(default=None, alias="ipv4RouteMapIn")
    ipv4_route_map_out: Optional[str] = Field(default=None, alias="ipv4RouteMapOut")


class Ipv6PeeringModel(NDNestedModel):
    """IPv6 BGP peering route map configuration."""

    ipv6_route_map_in: Optional[str] = Field(default=None, alias="ipv6RouteMapIn")
    ipv6_route_map_out: Optional[str] = Field(default=None, alias="ipv6RouteMapOut")


class FabricBgpDetailsModel(NDNestedModel):
    """BGP peering details for a fabric in L3Out routing configuration."""

    local_asn: Optional[str] = Field(default=None, alias="localAsn")
    ipv4_peering_details: Optional[Ipv4PeeringModel] = Field(
        default=None, alias="ipv4PeeringDetails"
    )
    ipv6_peering_details: Optional[Ipv6PeeringModel] = Field(
        default=None, alias="ipv6PeeringDetails"
    )
    advertise_host_routes: Optional[bool] = Field(
        default=None, alias="advertiseHostRoutes"
    )
    advertise_default_route: Optional[bool] = Field(
        default=None, alias="advertiseDefaultRoute"
    )
    configure_static_default_route: Optional[bool] = Field(
        default=None, alias="configureStaticDefaultRoute"
    )
    soft_reconfiguration_inbound: Optional[str] = Field(
        default=None, alias="softReconfigurationInbound"
    )
    default_originate: Optional[bool] = Field(default=None, alias="defaultOriginate")
    log_neighbor_change: Optional[bool] = Field(
        default=None, alias="logNeighborChange"
    )
    allow_as_in_asn_occurence_number: Optional[int] = Field(
        default=None, alias="allowAsInAsnOccurenceNumber"
    )
    as_override: Optional[bool] = Field(default=None, alias="asOverride")
    no_prepend: Optional[bool] = Field(default=None, alias="noPrepend")
    replace_as: Optional[bool] = Field(default=None, alias="replaceAs")
    disable_peer_as_check: Optional[bool] = Field(
        default=None, alias="disablePeerAsCheck"
    )
    auth_key: Optional[str] = Field(default=None, alias="authKey")
    auth_key_encryption_type: Optional[str] = Field(
        default=None, alias="authKeyEncryptionType"
    )


class StaticRouteModel(NDNestedModel):
    """Static route configuration for L3Out."""

    ip_version: str = Field(alias="ipVersion")
    ip_prefix: str = Field(alias="ipPrefix")
    next_hop: str = Field(alias="nextHop")
    switch_ids: List[str] = Field(alias="switchIds")
    route_preference: Optional[int] = Field(default=None, alias="routePreference")
    next_hop_name: Optional[str] = Field(default=None, alias="nextHopName")
    tag: Optional[int] = Field(default=None, alias="tag")
    track_id: Optional[int] = Field(default=None, alias="trackId")
    next_hop_vrf_name: Optional[str] = Field(default=None, alias="nextHopVrfName")


class RoutingDetailsModel(NDNestedModel):
    """Routing configuration for L3Out (BGP or static)."""

    routing_protocol: str = Field(alias="routingProtocol")
    # BGP fields
    auth: Optional[bool] = Field(default=None, alias="auth")
    bfd: Optional[bool] = Field(default=None, alias="bfd")
    hold_interval: Optional[int] = Field(default=None, alias="holdInterval")
    keep_alive_interval: Optional[int] = Field(default=None, alias="keepAliveInterval")
    fabric1_details: Optional[FabricBgpDetailsModel] = Field(
        default=None, alias="fabric1Details"
    )
    fabric2_details: Optional[FabricBgpDetailsModel] = Field(
        default=None, alias="fabric2Details"
    )
    # Static routing fields
    fabric1_static_routes: Optional[List[StaticRouteModel]] = Field(
        default=None, alias="fabric1StaticRoutes"
    )
    fabric2_static_routes: Optional[List[StaticRouteModel]] = Field(
        default=None, alias="fabric2StaticRoutes"
    )


class SwitchDetailsModel(NDNestedModel):
    """Switch interface details for L3Out link configuration."""

    switch_id: str = Field(alias="switchId")
    interface_name: str = Field(alias="interfaceName")
    ipv4_address: Optional[str] = Field(default=None, alias="ipv4Address")
    ipv6_address: Optional[str] = Field(default=None, alias="ipv6Address")
    interface_description: Optional[str] = Field(
        default=None, alias="interfaceDescription"
    )
    interface_admin_state: Optional[bool] = Field(
        default=None, alias="interfaceAdminState"
    )
    netflow: Optional[bool] = Field(default=None, alias="netflow")
    netflow_monitor: Optional[str] = Field(default=None, alias="netflowMonitor")


class LinkModel(NDNestedModel):
    """Link configuration for L3Out connectivity."""

    mtu: Optional[int] = Field(default=None, alias="mtu")
    ipv4_mask_length: Optional[int] = Field(default=None, alias="ipv4MaskLength")
    ipv6_prefix_length: Optional[int] = Field(default=None, alias="ipv6PrefixLength")
    dot1q_id: Optional[int] = Field(default=None, alias="dot1qId")
    vlan_id: Optional[int] = Field(default=None, alias="vlanId")
    ipv4_pim: Optional[bool] = Field(default=None, alias="ipv4Pim")
    ipv6_pim: Optional[bool] = Field(default=None, alias="ipv6Pim")
    switch1_details: Optional[SwitchDetailsModel] = Field(
        default=None, alias="switch1Details"
    )
    switch2_details: Optional[SwitchDetailsModel] = Field(
        default=None, alias="switch2Details"
    )


class ConnectivityDetailsModel(NDNestedModel):
    """Connectivity configuration for L3Out."""

    routing_interface_type: str = Field(alias="routingInterfaceType")
    links: Optional[List[LinkModel]] = Field(default=None, alias="links")


# =============================================================================
# Main L3Out Model
# =============================================================================


class L3OutModel(NDBaseModel):
    """
    Layer-3 Out (L3Out) configuration for Nexus Dashboard.

    L3Outs provide connectivity between NDFC-managed fabrics and external networks.
    They support multiple connectivity types (routed, subInterface, svi) and
    routing protocols (BGP, static).

    Identifier: name (single)

    Serialization notes:
        - attach is excluded from API payload (module-side operation only)
        - All nested structures use Pydantic aliases for camelCase conversion
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["name"]
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "single"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set] = {"attach"}
    exclude_from_diff: ClassVar[set] = {"attach"}

    # --- Fields ---

    name: str = Field(alias="name")
    fabric1_name: Optional[str] = Field(default=None, alias="fabric1Name")
    fabric2_name: Optional[str] = Field(default=None, alias="fabric2Name")
    vrf1_name: Optional[str] = Field(default=None, alias="vrf1Name")
    vrf2_name: Optional[str] = Field(default=None, alias="vrf2Name")
    tenant1_name: Optional[str] = Field(default=None, alias="tenant1Name")
    tenant2_name: Optional[str] = Field(default=None, alias="tenant2Name")
    configured_fabrics: Optional[str] = Field(default=None, alias="configuredFabrics")
    ip_version: Optional[str] = Field(default=None, alias="ipVersion")
    connectivity_details: Optional[ConnectivityDetailsModel] = Field(
        default=None, alias="connectivityDetails"
    )
    routing_details: Optional[RoutingDetailsModel] = Field(
        default=None, alias="routingDetails"
    )

    # Module-side field (not sent to API)
    attach: Optional[bool] = Field(default=None)

    # --- Argument Spec ---

    @classmethod
    def get_argument_spec(cls) -> Dict:
        """
        Return the Ansible argument spec for the nd_l3out module.

        The L3Out module has a complex nested structure with discriminated types
        for connectivity (routed/subInterface/svi) and routing (bgp/static).
        """

        # Switch details spec - used in all link types
        switch_details_spec = dict(
            switch_id=dict(type="str", required=True),
            interface_name=dict(type="str", required=True),
            interface_admin_state=dict(type="bool"),
            ipv4_address=dict(type="str"),
            ipv6_address=dict(type="str"),
            netflow=dict(type="bool"),
            netflow_monitor=dict(type="str"),
            interface_description=dict(type="str"),
        )

        # Link spec - common fields plus type-specific
        link_spec = dict(
            # Common fields
            mtu=dict(type="int"),
            ipv4_pim=dict(type="bool"),
            ipv6_pim=dict(type="bool"),
            ipv4_mask_length=dict(type="int"),
            ipv6_prefix_length=dict(type="int"),
            # Type-specific fields
            dot1q_id=dict(type="int"),  # subInterface only
            vlan_id=dict(type="int"),  # svi only
            # Switch details
            switch1_details=dict(type="dict", options=switch_details_spec),
            switch2_details=dict(type="dict", options=switch_details_spec),
        )

        # Connectivity details spec
        connectivity_details_spec = dict(
            routing_interface_type=dict(
                type="str",
                required=True,
                choices=["routed", "subInterface", "svi"],
            ),
            links=dict(type="list", elements="dict", options=link_spec),
        )

        # Static route spec
        static_route_spec = dict(
            ip_version=dict(type="str", required=True, choices=["ipv4", "ipv6"]),
            ip_prefix=dict(type="str", required=True),
            next_hop=dict(type="str", required=True),
            switch_ids=dict(type="list", elements="str", required=True),
            route_preference=dict(type="int"),
            next_hop_name=dict(type="str"),
            tag=dict(type="int"),
            track_id=dict(type="int"),
            next_hop_vrf_name=dict(type="str"),
        )

        # IPv4/IPv6 route maps spec
        ipv4_peering_details_spec = dict(
            ipv4_route_map_in=dict(type="str"),
            ipv4_route_map_out=dict(type="str"),
        )

        ipv6_peering_details_spec = dict(
            ipv6_route_map_in=dict(type="str"),
            ipv6_route_map_out=dict(type="str"),
        )

        # Fabric peering details spec (for BGP)
        fabric_peering_details_spec = dict(
            auth_key=dict(type="str", no_log=True),
            auth_key_encryption_type=dict(type="str", choices=["3", "7"]),
            advertise_host_routes=dict(type="bool"),
            advertise_default_route=dict(type="bool"),
            configure_static_default_route=dict(type="bool"),
            soft_reconfiguration_inbound=dict(
                type="str",
                choices=["enabled", "disabled", "enabledAlways"],
            ),
            default_originate=dict(type="bool"),
            local_asn=dict(type="str"),
            no_prepend=dict(type="bool"),
            replace_as=dict(type="bool"),
            as_override=dict(type="bool"),
            disable_peer_as_check=dict(type="bool"),
            log_neighbor_change=dict(type="bool"),
            allow_as_in_asn_occurence_number=dict(type="int"),
            ipv4_peering_details=dict(type="dict", options=ipv4_peering_details_spec),
            ipv6_peering_details=dict(type="dict", options=ipv6_peering_details_spec),
        )

        # Routing details spec - discriminated by routing_protocol
        routing_details_spec = dict(
            routing_protocol=dict(
                type="str",
                required=True,
                choices=["static", "bgp"],
            ),
            # Static routing fields
            fabric1_static_routes=dict(
                type="list", elements="dict", options=static_route_spec
            ),
            fabric2_static_routes=dict(
                type="list", elements="dict", options=static_route_spec
            ),
            # BGP routing fields
            auth=dict(type="bool"),
            bfd=dict(type="bool"),
            hold_interval=dict(type="int"),
            keep_alive_interval=dict(type="int"),
            fabric1_details=dict(type="dict", options=fabric_peering_details_spec),
            fabric2_details=dict(type="dict", options=fabric_peering_details_spec),
        )

        # L3Out spec
        l3out_spec = dict(
            name=dict(type="str", required=True),
            attach=dict(type="bool"),  # Optional: attach/detach L3Out after operation
            fabric1_name=dict(type="str"),
            fabric2_name=dict(type="str"),
            vrf1_name=dict(type="str"),
            vrf2_name=dict(type="str"),
            tenant1_name=dict(type="str"),
            tenant2_name=dict(type="str"),
            configured_fabrics=dict(type="str", choices=["both", "fabric1", "fabric2"]),
            ip_version=dict(type="str", choices=["ipv4", "ipv6", "both"]),
            connectivity_details=dict(type="dict", options=connectivity_details_spec),
            routing_details=dict(type="dict", options=routing_details_spec),
        )

        return dict(
            fabric=dict(type="str", required=True),
            state=dict(
                type="str",
                default="merged",
                choices=["merged", "replaced", "overridden", "deleted"],
            ),
            config=dict(type="list", elements="dict", default=[], options=l3out_spec),
        )
