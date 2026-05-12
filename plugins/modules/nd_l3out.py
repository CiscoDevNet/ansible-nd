#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: nd_l3out
version_added: "1.6.0"
short_description: Manage L3Outs (Layer-3 Outs) on Cisco Nexus Dashboard
description:
- Manage L3Out (Layer-3 Out) configurations on Cisco Nexus Dashboard (ND).
- L3Outs provide connectivity between NDFC-managed fabrics and external networks.
- Supports multiple connectivity types (routed, subInterface, svi) and routing protocols (BGP, static).
- Requires ND 4.1 or later.
author:
- Slawomir Kaszlikowski
options:
  fabric:
    description:
    - Name of the target fabric for L3Out operations.
    type: str
    required: true
  state:
    description:
    - The desired state of the L3Out resources on Cisco Nexus Dashboard.
    - Use O(state=merged) to merge L3Out configurations into the fabric.
      If an L3Out exists, it will be updated with the provided configuration.
      If an L3Out does not exist, it will be created.
    - Use O(state=replaced) to completely replace existing L3Out configurations.
      If an L3Out exists, it will be fully replaced. If it does not exist, it will be created.
    - Use O(state=deleted) to delete L3Outs.
      If no O(config) is provided, all L3Outs in the fabric will be deleted.
    - Use O(state=gathered) to retrieve current L3Out state from ND without making changes.
      If no O(config) is provided, all L3Outs in the fabric will be returned.
    type: str
    choices: [ merged, replaced, deleted, gathered ]
    default: merged
  config:
    description:
    - A list of dictionaries containing L3Out configurations.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description:
        - Name of the L3Out.
        - Must be 1-64 characters, containing only alphanumeric characters, underscores, and hyphens.
        type: str
        required: true
      fabric1_name:
        description:
        - Name of the first fabric associated with the L3Out.
        - Required when O(state) is C(merged) or C(replaced).
        type: str
      fabric2_name:
        description:
        - Name of the second fabric associated with the L3Out.
        - Required when O(state) is C(merged) or C(replaced).
        type: str
      vrf1_name:
        description:
        - Name of the VRF from the first fabric.
        - Required when O(state) is C(merged) or C(replaced).
        type: str
      vrf2_name:
        description:
        - Name of the VRF from the second fabric.
        - Required when O(state) is C(merged) or C(replaced).
        type: str
      tenant1_name:
        description:
        - Name of the tenant to which vrf1 belongs.
        - Only required if fabric 1 is being configured.
        type: str
      tenant2_name:
        description:
        - Name of the tenant to which vrf2 belongs.
        - Only required if fabric 2 is being configured.
        type: str
      configured_fabrics:
        description:
        - Specifies which fabrics will have configuration generated.
        - C(both) - Generate configuration for both fabrics.
        - C(fabric1) - Generate configuration only for fabric 1.
        - C(fabric2) - Generate configuration only for fabric 2.
        - Required when O(state) is C(merged) or C(replaced).
        type: str
        choices: [ both, fabric1, fabric2 ]
      ip_version:
        description:
        - The IP version used by the L3Out.
        - C(ipv4) - IPv4 only.
        - C(ipv6) - IPv6 only.
        - C(both) - Both IPv4 and IPv6 (dual-stack).
        - Required when O(state) is C(merged) or C(replaced).
        type: str
        choices: [ ipv4, ipv6, both ]
      connectivity_details:
        description:
        - Connectivity details for the L3Out including interface type and links.
        - Required when O(state) is C(merged) or C(replaced).
        type: dict
        suboptions:
          routing_interface_type:
            description:
            - The type of routing interface used by the L3Out.
            - C(routed) - Routed interfaces (physical ports).
            - C(subInterface) - Sub-interfaces with dot1q encapsulation.
            - C(svi) - Switched Virtual Interfaces (SVIs).
            type: str
            required: true
            choices: [ routed, subInterface, svi ]
          links:
            description:
            - List of links for the L3Out connectivity.
            type: list
            elements: dict
            default: []
            suboptions:
              mtu:
                description:
                - Interface MTU on both ends of the link.
                - Must be between 576 and 9216.
                type: int
                default: 9216
              ipv4_pim:
                description:
                - Enable IPv4 PIM on the link.
                type: bool
                default: false
              ipv6_pim:
                description:
                - Enable IPv6 PIM on the link.
                type: bool
                default: false
              ipv4_mask_length:
                description:
                - IPv4 subnet mask length.
                - Required when O(config.ip_version) is C(ipv4) or C(both).
                - Must be between 1 and 31.
                type: int
              ipv6_prefix_length:
                description:
                - IPv6 subnet prefix length.
                - Required when O(config.ip_version) is C(ipv6) or C(both).
                - Must be between 1 and 127.
                type: int
              dot1q_id:
                description:
                - Dot1q VLAN tag for subInterface type.
                - Required when O(config.connectivity_details.routing_interface_type) is C(subInterface).
                - Must be between 1 and 4094.
                type: int
              vlan_id:
                description:
                - VLAN ID for SVI type.
                - Required when O(config.connectivity_details.routing_interface_type) is C(svi).
                - Must be between 2 and 4094.
                type: int
              switch1_details:
                description:
                - Details for the switch on the first fabric side of the link.
                type: dict
                suboptions:
                  switch_id:
                    description:
                    - Unique identifier of the switch (serial number).
                    type: str
                    required: true
                  interface_name:
                    description:
                    - Name of the interface on the switch.
                    type: str
                    required: true
                  interface_admin_state:
                    description:
                    - Admin state of the interface.
                    - C(true) for up, C(false) for down.
                    type: bool
                    default: true
                  ipv4_address:
                    description:
                    - IPv4 address assigned to the interface.
                    - Required when O(config.ip_version) is C(ipv4) or C(both).
                    type: str
                  ipv6_address:
                    description:
                    - IPv6 address assigned to the interface.
                    - Required when O(config.ip_version) is C(ipv6) or C(both).
                    type: str
                  netflow:
                    description:
                    - Enable netflow on the interface.
                    - Only supported if netflow is enabled on the fabric.
                    type: bool
                    default: false
                  netflow_monitor:
                    description:
                    - Netflow monitor name.
                    - Required when O(config.connectivity_details.links.switch1_details.netflow) is C(true).
                    type: str
                  interface_description:
                    description:
                    - Description of the interface.
                    - Only applicable for subInterface and svi types.
                    type: str
              switch2_details:
                description:
                - Details for the switch on the second fabric side of the link.
                - Same structure as O(config.connectivity_details.links.switch1_details).
                type: dict
                suboptions:
                  switch_id:
                    description:
                    - Unique identifier of the switch (serial number).
                    type: str
                    required: true
                  interface_name:
                    description:
                    - Name of the interface on the switch.
                    type: str
                    required: true
                  interface_admin_state:
                    description:
                    - Admin state of the interface.
                    type: bool
                    default: true
                  ipv4_address:
                    description:
                    - IPv4 address assigned to the interface.
                    type: str
                  ipv6_address:
                    description:
                    - IPv6 address assigned to the interface.
                    type: str
                  netflow:
                    description:
                    - Enable netflow on the interface.
                    type: bool
                    default: false
                  netflow_monitor:
                    description:
                    - Netflow monitor name.
                    type: str
                  interface_description:
                    description:
                    - Description of the interface.
                    type: str
      routing_details:
        description:
        - Routing protocol details for the L3Out.
        - Required when O(state) is C(merged) or C(replaced).
        type: dict
        suboptions:
          routing_protocol:
            description:
            - The routing protocol used for peering.
            - C(static) - Static routing.
            - C(bgp) - BGP peering.
            type: str
            required: true
            choices: [ static, bgp ]
          fabric1_static_routes:
            description:
            - List of static routes for fabric 1.
            - Only applicable when O(config.routing_details.routing_protocol) is C(static).
            type: list
            elements: dict
            suboptions:
              ip_version:
                description:
                - IP version for this static route.
                type: str
                required: true
                choices: [ ipv4, ipv6 ]
              ip_prefix:
                description:
                - IP prefix in CIDR notation (e.g., 192.168.1.0/24 or 2001:db8::/32).
                type: str
                required: true
              next_hop:
                description:
                - Next hop IP address for the route.
                type: str
                required: true
              switch_ids:
                description:
                - List of switch IDs to which this static route applies.
                type: list
                elements: str
                required: true
              route_preference:
                description:
                - Administrative distance of the route.
                - Must be between 1 and 255. Default is 1.
                type: int
              next_hop_name:
                description:
                - Name tagged with the static route.
                type: str
              tag:
                description:
                - Tag associated with the static route.
                type: int
              track_id:
                description:
                - Object ID of object to be tracked.
                type: int
              next_hop_vrf_name:
                description:
                - VRF of the next hop, if different from this VRF.
                type: str
          fabric2_static_routes:
            description:
            - List of static routes for fabric 2.
            - Same structure as O(config.routing_details.fabric1_static_routes).
            type: list
            elements: dict
            suboptions:
              ip_version:
                description:
                - IP version for this static route.
                type: str
                required: true
                choices: [ ipv4, ipv6 ]
              ip_prefix:
                description:
                - IP prefix in CIDR notation.
                type: str
                required: true
              next_hop:
                description:
                - Next hop IP address for the route.
                type: str
                required: true
              switch_ids:
                description:
                - List of switch IDs to which this static route applies.
                type: list
                elements: str
                required: true
              route_preference:
                description:
                - Administrative distance of the route.
                type: int
              next_hop_name:
                description:
                - Name tagged with the static route.
                type: str
              tag:
                description:
                - Tag associated with the static route.
                type: int
              track_id:
                description:
                - Object ID of object to be tracked.
                type: int
              next_hop_vrf_name:
                description:
                - VRF of the next hop, if different from this VRF.
                type: str
          auth:
            description:
            - Enable BGP authentication.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: bool
            default: false
          bfd:
            description:
            - Enable BFD (Bidirectional Forwarding Detection).
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: bool
            default: false
          hold_interval:
            description:
            - BGP hold interval in seconds.
            - Must be between 3 and 3600.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: int
            default: 180
          keep_alive_interval:
            description:
            - BGP keepalive interval in seconds.
            - Must be between 1 and 3600.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: int
            default: 60
          fabric1_details:
            description:
            - BGP peering details for fabric 1.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: dict
            suboptions:
              auth_key:
                description:
                - BGP authentication key.
                - Required when O(config.routing_details.auth) is C(true).
                type: str
              auth_key_encryption_type:
                description:
                - Encryption type for the authentication key.
                - C(3) - Type 3 (3DES).
                - C(7) - Type 7 (Vigenere cipher).
                type: str
                choices: [ "3", "7" ]
              advertise_host_routes:
                description:
                - Advertise /32 and /128 host routes to edge routers.
                type: bool
                default: false
              advertise_default_route:
                description:
                - Advertise default route internally.
                type: bool
                default: true
              configure_static_default_route:
                description:
                - Automatically configure static default route for selected links.
                type: bool
                default: true
              soft_reconfiguration_inbound:
                description:
                - Stores raw BGP updates locally to reprocess policies without Route Refresh.
                - C(enabled) - Enable soft reconfiguration.
                - C(disabled) - Disable soft reconfiguration.
                - C(enabledAlways) - Always enable soft reconfiguration.
                type: str
                choices: [ enabled, disabled, enabledAlways ]
                default: disabled
              default_originate:
                description:
                - Advertise a default route (0.0.0.0/0) even without one in routing table.
                type: bool
                default: false
              local_asn:
                description:
                - Makes the router appear as a different ASN to a specific BGP neighbor.
                type: str
              no_prepend:
                description:
                - Do not prepend the local ASN to updates from the eBGP neighbor.
                type: bool
              replace_as:
                description:
                - Prepend only the local ASN to updates to eBGP neighbor.
                type: bool
              as_override:
                description:
                - Replace the BGP neighbor's ASN in AS-path with local ASN when advertising.
                type: bool
              disable_peer_as_check:
                description:
                - Allow advertising routes to eBGP peer with peer's ASN already in AS_PATH.
                type: bool
              log_neighbor_change:
                description:
                - Enable BGP log neighbor change.
                type: bool
                default: false
              allow_as_in_asn_occurence_number:
                description:
                - Number of times local ASN can occur in AS path (for loop prevention bypass).
                - Must be between 1 and 10.
                type: int
              ipv4_peering_details:
                description:
                - IPv4 route map configuration.
                type: dict
                suboptions:
                  ipv4_route_map_in:
                    description:
                    - Inbound route map for IPv4.
                    type: str
                  ipv4_route_map_out:
                    description:
                    - Outbound route map for IPv4.
                    type: str
              ipv6_peering_details:
                description:
                - IPv6 route map configuration.
                type: dict
                suboptions:
                  ipv6_route_map_in:
                    description:
                    - Inbound route map for IPv6.
                    type: str
                  ipv6_route_map_out:
                    description:
                    - Outbound route map for IPv6.
                    type: str
          fabric2_details:
            description:
            - BGP peering details for fabric 2.
            - Same structure as O(config.routing_details.fabric1_details).
            type: dict
            suboptions:
              auth_key:
                description:
                - BGP authentication key.
                type: str
              auth_key_encryption_type:
                description:
                - Encryption type for the authentication key.
                type: str
                choices: [ "3", "7" ]
              advertise_host_routes:
                description:
                - Advertise /32 and /128 host routes to edge routers.
                type: bool
                default: false
              advertise_default_route:
                description:
                - Advertise default route internally.
                type: bool
                default: true
              configure_static_default_route:
                description:
                - Automatically configure static default route for selected links.
                type: bool
                default: true
              soft_reconfiguration_inbound:
                description:
                - Soft reconfiguration inbound setting.
                type: str
                choices: [ enabled, disabled, enabledAlways ]
                default: disabled
              default_originate:
                description:
                - Advertise a default route.
                type: bool
                default: false
              local_asn:
                description:
                - Local ASN override.
                type: str
              no_prepend:
                description:
                - Do not prepend local ASN.
                type: bool
              replace_as:
                description:
                - Replace AS in path.
                type: bool
              as_override:
                description:
                - Override neighbor's ASN.
                type: bool
              disable_peer_as_check:
                description:
                - Disable peer AS check.
                type: bool
              log_neighbor_change:
                description:
                - Log neighbor changes.
                type: bool
                default: false
              allow_as_in_asn_occurence_number:
                description:
                - Allow AS in path occurrence count.
                type: int
              ipv4_peering_details:
                description:
                - IPv4 route map configuration.
                type: dict
                suboptions:
                  ipv4_route_map_in:
                    description:
                    - Inbound route map for IPv4.
                    type: str
                  ipv4_route_map_out:
                    description:
                    - Outbound route map for IPv4.
                    type: str
              ipv6_peering_details:
                description:
                - IPv6 route map configuration.
                type: dict
                suboptions:
                  ipv6_route_map_in:
                    description:
                    - Inbound route map for IPv6.
                    type: str
                  ipv6_route_map_out:
                    description:
                    - Outbound route map for IPv6.
                    type: str
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1 or higher.
- L3Outs provide inter-fabric connectivity between NDFC-managed fabrics and external networks.
- The fabric parameter refers to the fabric context for the L3Out operations (typically fabric1).
"""

EXAMPLES = r"""
- name: Create L3Out with routed interfaces and BGP (check mode)
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-l3out
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: production
        vrf2_name: external
        tenant1_name: tenant1
        tenant2_name: tenant2
        configured_fabrics: both
        ip_version: ipv4
        connectivity_details:
          routing_interface_type: routed
          links:
            - mtu: 9216
              ipv4_mask_length: 30
              switch1_details:
                switch_id: FDO12345678
                interface_name: Ethernet1/1
                ipv4_address: 10.0.0.1
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/1
                ipv4_address: 10.0.0.2
        routing_details:
          routing_protocol: bgp
          auth: false
          bfd: true
          hold_interval: 180
          keep_alive_interval: 60
          fabric1_details:
            advertise_default_route: true
            ipv4_peering_details:
              ipv4_route_map_in: rm-in
              ipv4_route_map_out: rm-out
  check_mode: true
  register: cm_create_l3out

- name: Create L3Out with routed interfaces and BGP
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-l3out
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: production
        vrf2_name: external
        tenant1_name: tenant1
        tenant2_name: tenant2
        configured_fabrics: both
        ip_version: ipv4
        connectivity_details:
          routing_interface_type: routed
          links:
            - mtu: 9216
              ipv4_mask_length: 30
              switch1_details:
                switch_id: FDO12345678
                interface_name: Ethernet1/1
                ipv4_address: 10.0.0.1
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/1
                ipv4_address: 10.0.0.2
        routing_details:
          routing_protocol: bgp
          auth: false
          bfd: true
          hold_interval: 180
          keep_alive_interval: 60
          fabric1_details:
            advertise_default_route: true
            ipv4_peering_details:
              ipv4_route_map_in: rm-in
              ipv4_route_map_out: rm-out
  register: create_l3out

- name: Create L3Out with subInterface and static routing
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: l3out-static
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: production
        vrf2_name: external
        configured_fabrics: fabric1
        ip_version: ipv4
        connectivity_details:
          routing_interface_type: subInterface
          links:
            - dot1q_id: 100
              mtu: 1500
              ipv4_mask_length: 24
              switch1_details:
                switch_id: FDO12345678
                interface_name: Ethernet1/2
                ipv4_address: 192.168.100.1
                interface_description: "Link to external network"
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/2
                ipv4_address: 192.168.100.2
                interface_description: "Link from DC1"
        routing_details:
          routing_protocol: static
          fabric1_static_routes:
            - ip_version: ipv4
              ip_prefix: 0.0.0.0/0
              next_hop: 192.168.100.254
              switch_ids:
                - FDO12345678
              route_preference: 1

- name: Create L3Out with SVI interface and dual-stack
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: l3out-svi-dualstack
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: production
        vrf2_name: external
        configured_fabrics: both
        ip_version: both
        connectivity_details:
          routing_interface_type: svi
          links:
            - vlan_id: 200
              mtu: 9216
              ipv4_mask_length: 24
              ipv6_prefix_length: 64
              ipv4_pim: true
              switch1_details:
                switch_id: FDO12345678
                interface_name: Vlan200
                ipv4_address: 10.200.0.1
                ipv6_address: "2001:db8:200::1"
              switch2_details:
                switch_id: FDO87654321
                interface_name: Vlan200
                ipv4_address: 10.200.0.2
                ipv6_address: "2001:db8:200::2"
        routing_details:
          routing_protocol: bgp
          bfd: true
          fabric1_details:
            advertise_host_routes: true
            ipv4_peering_details:
              ipv4_route_map_in: rm-v4-in
              ipv4_route_map_out: rm-v4-out
            ipv6_peering_details:
              ipv6_route_map_in: rm-v6-in
              ipv6_route_map_out: rm-v6-out

- name: Gather all L3Outs in fabric
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: gathered
  register: all_l3outs

- name: Gather specific L3Outs
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: gathered
    config:
      - name: my-l3out
      - name: l3out-static
  register: gathered_result

- name: Replace an existing L3Out completely
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: replaced
    config:
      - name: my-l3out
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: new-vrf
        vrf2_name: external
        configured_fabrics: fabric1
        ip_version: ipv4
        connectivity_details:
          routing_interface_type: routed
          links:
            - ipv4_mask_length: 30
              switch1_details:
                switch_id: FDO12345678
                interface_name: Ethernet1/3
                ipv4_address: 10.0.1.1
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/3
                ipv4_address: 10.0.1.2
        routing_details:
          routing_protocol: static
          fabric1_static_routes:
            - ip_version: ipv4
              ip_prefix: 0.0.0.0/0
              next_hop: 10.0.1.2
              switch_ids:
                - FDO12345678

- name: Delete specific L3Outs
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: deleted
    config:
      - name: my-l3out
      - name: l3out-static

- name: Delete all L3Outs in fabric
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether any changes were made.
  type: bool
  returned: always
diff:
  description: Per-state lists of L3Out names that were created, replaced, deleted, or gathered.
  type: list
  elements: dict
  returned: always
  sample:
    - merged: ["my-l3out"]
      replaced: []
      deleted: []
      gathered: []
response:
  description: Raw API responses for mutating operations.
  type: list
  elements: dict
  returned: always
l3outs:
  description: List of L3Outs returned for O(state=gathered).
  type: list
  elements: dict
  returned: when state is gathered
  contains:
    name:
      description: Name of the L3Out.
      type: str
    fabric1_name:
      description: Name of the first fabric.
      type: str
    fabric2_name:
      description: Name of the second fabric.
      type: str
    vrf1_name:
      description: VRF name for fabric 1.
      type: str
    vrf2_name:
      description: VRF name for fabric 2.
      type: str
    ip_version:
      description: IP version (ipv4, ipv6, or both).
      type: str
    connectivity_details:
      description: Connectivity configuration including interface type and links.
      type: dict
    routing_details:
      description: Routing protocol configuration (BGP or static).
      type: dict
"""

import traceback
from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.l3out.l3out import (
    L3OutModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_l3out import (
    ManageL3OutOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(L3OutModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    fabric_name = module.params["fabric"]
    state = module.params["state"]
    config = deepcopy(module.params.get("config") or [])

    try:
        sender = Sender()
        sender.ansible_module = module

        rest_send = RestSend(
            {
                "check_mode": module.check_mode,
                "state": state,
            }
        )
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()

        orchestrator = ManageL3OutOrchestrator(
            rest_send=rest_send,
            fabric_name=fabric_name,
        )

        result = orchestrator.run(
            state=state, config=config, check_mode=module.check_mode
        )
        module.exit_json(**result)

    except Exception as e:
        module.fail_json(
            msg="Module execution failed: {0}".format(str(e)),
            exception=traceback.format_exc(),
        )


if __name__ == "__main__":
    main()
