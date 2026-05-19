# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

from typing import ClassVar, Dict, List, Literal, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    Field,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel


class L3OutModel(NDBaseModel):
    """
    Layer-3 Out (L3Out) configuration for Nexus Dashboard.

    L3Outs provide connectivity between NDFC-managed fabrics and external networks.
    They support multiple connectivity types (routed, subInterface, svi) and
    routing protocols (BGP, static).

    Identifier: composite (fabric_name, name)

    Serialization notes:
        - fabric_name is excluded from API payload (path parameter only).
        - Nested structures (connectivity_details, routing_details) are handled
          as plain dicts in the orchestrator due to their complex discriminated
          type requirements.
    """

    # --- Identifier Configuration ---

    identifiers: ClassVar[Optional[List[str]]] = ["fabric_name", "name"]
    identifier_strategy: ClassVar[
        Optional[Literal["single", "composite", "hierarchical", "singleton"]]
    ] = "composite"

    # --- Serialization Configuration ---

    payload_exclude_fields: ClassVar[set] = {"fabric_name"}

    # --- Fields ---

    fabric_name: str = Field(alias="fabricName")
    name: str = Field(alias="name")

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
            interface_admin_state=dict(type="bool", default=True),
            ipv4_address=dict(type="str"),
            ipv6_address=dict(type="str"),
            netflow=dict(type="bool", default=False),
            netflow_monitor=dict(type="str"),
            interface_description=dict(type="str"),
        )

        # Link spec - common fields plus type-specific
        link_spec = dict(
            # Common fields
            mtu=dict(type="int", default=9216),
            ipv4_pim=dict(type="bool", default=False),
            ipv6_pim=dict(type="bool", default=False),
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
            links=dict(type="list", elements="dict", default=[], options=link_spec),
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
            advertise_host_routes=dict(type="bool", default=False),
            advertise_default_route=dict(type="bool", default=True),
            configure_static_default_route=dict(type="bool", default=True),
            soft_reconfiguration_inbound=dict(
                type="str",
                choices=["enabled", "disabled", "enabledAlways"],
                default="disabled",
            ),
            default_originate=dict(type="bool", default=False),
            local_asn=dict(type="str"),
            no_prepend=dict(type="bool"),
            replace_as=dict(type="bool"),
            as_override=dict(type="bool"),
            disable_peer_as_check=dict(type="bool"),
            log_neighbor_change=dict(type="bool", default=False),
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
            auth=dict(type="bool", default=False),
            bfd=dict(type="bool", default=False),
            hold_interval=dict(type="int", default=180),
            keep_alive_interval=dict(type="int", default=60),
            fabric1_details=dict(type="dict", options=fabric_peering_details_spec),
            fabric2_details=dict(type="dict", options=fabric_peering_details_spec),
        )

        # L3Out spec
        l3out_spec = dict(
            name=dict(type="str", required=True),
            attach=dict(
                type="bool"
            ),  # Optional: attach/detach L3Out after create/update
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
                choices=["merged", "replaced", "deleted", "gathered"],
            ),
            config=dict(type="list", elements="dict", default=[], options=l3out_spec),
        )
