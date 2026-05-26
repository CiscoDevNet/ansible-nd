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
version_added: "1.0.0"
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
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The L3Outs on ND will be modified to exactly match the configuration.
      Any L3Out existing on ND but not present in the configuration will be deleted. Use with extra caution.
    - Use O(state=deleted) to delete L3Outs.
      If no O(config) is provided, all L3Outs in the fabric will be deleted.
    type: str
    choices: [ merged, replaced, overridden, deleted ]
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
      attach:
        description:
        - Whether to attach or detach the L3Out after create/update.
        - When C(true), the L3Out will be attached (deployed) to the fabrics.
        - When C(false), the L3Out will be detached from the fabrics.
        - When not specified, no attachment action is performed.
        - Only applicable when O(state) is C(merged) or C(replaced).
        type: bool
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
            suboptions:
              mtu:
                description:
                - Interface MTU on both ends of the link.
                - Must be between 576 and 9216.
                type: int
              ipv4_pim:
                description:
                - Enable IPv4 PIM on the link.
                type: bool
              ipv6_pim:
                description:
                - Enable IPv6 PIM on the link.
                type: bool
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
                    type: bool
                  ipv4_address:
                    description:
                    - IPv4 address for the interface.
                    type: str
                  ipv6_address:
                    description:
                    - IPv6 address for the interface.
                    type: str
                  netflow:
                    description:
                    - Enable NetFlow on the interface.
                    type: bool
                  netflow_monitor:
                    description:
                    - NetFlow monitor profile name.
                    type: str
                  interface_description:
                    description:
                    - Description for the interface.
                    type: str
              switch2_details:
                description:
                - Details for the switch on the second fabric side of the link.
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
                  ipv4_address:
                    description:
                    - IPv4 address for the interface.
                    type: str
                  ipv6_address:
                    description:
                    - IPv6 address for the interface.
                    type: str
                  netflow:
                    description:
                    - Enable NetFlow on the interface.
                    type: bool
                  netflow_monitor:
                    description:
                    - NetFlow monitor profile name.
                    type: str
                  interface_description:
                    description:
                    - Description for the interface.
                    type: str
      routing_details:
        description:
        - Routing configuration for the L3Out.
        - Required when O(state) is C(merged) or C(replaced).
        type: dict
        suboptions:
          routing_protocol:
            description:
            - The routing protocol for the L3Out.
            - C(bgp) - Use BGP routing.
            - C(static) - Use static routing.
            type: str
            required: true
            choices: [ bgp, static ]
          auth:
            description:
            - Enable BGP authentication.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: bool
          bfd:
            description:
            - Enable BFD for BGP.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: bool
          hold_interval:
            description:
            - BGP hold interval in seconds.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: int
          keep_alive_interval:
            description:
            - BGP keepalive interval in seconds.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: int
          fabric1_details:
            description:
            - BGP configuration details for fabric 1.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: dict
            suboptions:
              local_asn:
                description:
                - Local ASN for BGP peering.
                type: str
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
                - Advertise host routes.
                type: bool
              advertise_default_route:
                description:
                - Advertise default route.
                type: bool
              configure_static_default_route:
                description:
                - Configure static default route.
                type: bool
              soft_reconfiguration_inbound:
                description:
                - Soft reconfiguration inbound setting.
                type: str
                choices: [ enabled, disabled, enabledAlways ]
              default_originate:
                description:
                - Enable default originate.
                type: bool
              log_neighbor_change:
                description:
                - Log neighbor state changes.
                type: bool
              no_prepend:
                description:
                - Do not prepend local ASN to AS path.
                type: bool
              replace_as:
                description:
                - Replace AS path with local ASN.
                type: bool
              as_override:
                description:
                - Override AS path.
                type: bool
              disable_peer_as_check:
                description:
                - Disable peer AS check.
                type: bool
              allow_as_in_asn_occurence_number:
                description:
                - Number of times to allow local ASN in AS path.
                type: int
              ipv4_peering_details:
                description:
                - IPv4 BGP peering details.
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
                - IPv6 BGP peering details.
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
            - BGP configuration details for fabric 2.
            - Only applicable when O(config.routing_details.routing_protocol) is C(bgp).
            type: dict
            suboptions:
              local_asn:
                description:
                - Local ASN for BGP peering.
                type: str
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
                - Advertise host routes.
                type: bool
              advertise_default_route:
                description:
                - Advertise default route.
                type: bool
              configure_static_default_route:
                description:
                - Configure static default route.
                type: bool
              soft_reconfiguration_inbound:
                description:
                - Soft reconfiguration inbound setting.
                type: str
                choices: [ enabled, disabled, enabledAlways ]
              default_originate:
                description:
                - Enable default originate.
                type: bool
              log_neighbor_change:
                description:
                - Log neighbor state changes.
                type: bool
              no_prepend:
                description:
                - Do not prepend local ASN to AS path.
                type: bool
              replace_as:
                description:
                - Replace AS path with local ASN.
                type: bool
              as_override:
                description:
                - Override AS path.
                type: bool
              disable_peer_as_check:
                description:
                - Disable peer AS check.
                type: bool
              allow_as_in_asn_occurence_number:
                description:
                - Number of times to allow local ASN in AS path.
                type: int
              ipv4_peering_details:
                description:
                - IPv4 BGP peering details.
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
                - IPv6 BGP peering details.
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
          fabric1_static_routes:
            description:
            - Static routes for fabric 1.
            - Only applicable when O(config.routing_details.routing_protocol) is C(static).
            type: list
            elements: dict
            suboptions:
              ip_version:
                description:
                - IP version for the static route.
                type: str
                required: true
                choices: [ ipv4, ipv6 ]
              ip_prefix:
                description:
                - Destination IP prefix for the route.
                type: str
                required: true
              next_hop:
                description:
                - Next hop IP address.
                type: str
                required: true
              switch_ids:
                description:
                - List of switch IDs where the route should be configured.
                type: list
                elements: str
                required: true
              route_preference:
                description:
                - Administrative distance for the route.
                type: int
              next_hop_name:
                description:
                - Name for the next hop.
                type: str
              tag:
                description:
                - Tag value for the route.
                type: int
              track_id:
                description:
                - Track ID for route tracking.
                type: int
              next_hop_vrf_name:
                description:
                - VRF name for the next hop.
                type: str
          fabric2_static_routes:
            description:
            - Static routes for fabric 2.
            - Only applicable when O(config.routing_details.routing_protocol) is C(static).
            type: list
            elements: dict
            suboptions:
              ip_version:
                description:
                - IP version for the static route.
                type: str
                required: true
                choices: [ ipv4, ipv6 ]
              ip_prefix:
                description:
                - Destination IP prefix for the route.
                type: str
                required: true
              next_hop:
                description:
                - Next hop IP address.
                type: str
                required: true
              switch_ids:
                description:
                - List of switch IDs where the route should be configured.
                type: list
                elements: str
                required: true
              route_preference:
                description:
                - Administrative distance for the route.
                type: int
              next_hop_name:
                description:
                - Name for the next hop.
                type: str
              tag:
                description:
                - Tag value for the route.
                type: int
              track_id:
                description:
                - Track ID for route tracking.
                type: int
              next_hop_vrf_name:
                description:
                - VRF name for the next hop.
                type: str
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1 or higher.
- L3Outs provide inter-fabric connectivity between NDFC-managed fabrics and external networks.
- The fabric parameter refers to the fabric context for the L3Out operations (typically fabric1).
- The RV(before) output shows existing L3Outs in the fabric before any changes.
- The RV(after) output shows L3Outs in the fabric after changes are applied.
"""

EXAMPLES = r"""
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
            local_asn: "65001"
            advertise_default_route: true
            ipv4_peering_details:
              ipv4_route_map_in: rm-in
              ipv4_route_map_out: rm-out
          fabric2_details:
            local_asn: "65002"
            advertise_default_route: true
  register: create_l3out

- name: Create L3Out with attach (deploy after creation)
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-l3out-deployed
        attach: true
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: production
        vrf2_name: external
        configured_fabrics: both
        ip_version: ipv4
        connectivity_details:
          routing_interface_type: subInterface
          links:
            - dot1q_id: 100
              mtu: 1500
              ipv4_mask_length: 30
              switch1_details:
                switch_id: FDO12345678
                interface_name: Ethernet1/1.100
                ipv4_address: 10.0.0.1
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/1.100
                ipv4_address: 10.0.0.2
        routing_details:
          routing_protocol: bgp
          fabric1_details:
            local_asn: "65001"
          fabric2_details:
            local_asn: "65002"

- name: Detach (undeploy) an existing L3Out
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-l3out-deployed
        attach: false
        fabric1_name: DC1-Fabric
        fabric2_name: External-Fabric
        vrf1_name: production
        vrf2_name: external
        configured_fabrics: both
        ip_version: ipv4
        connectivity_details:
          routing_interface_type: subInterface
          links:
            - dot1q_id: 100
              mtu: 1500
              ipv4_mask_length: 30
              switch1_details:
                switch_id: FDO12345678
                interface_name: Ethernet1/1.100
                ipv4_address: 10.0.0.1
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/1.100
                ipv4_address: 10.0.0.2
        routing_details:
          routing_protocol: bgp
          fabric1_details:
            local_asn: "65001"
          fabric2_details:
            local_asn: "65002"

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
                interface_name: Ethernet1/2.100
                ipv4_address: 192.168.100.1
                interface_description: "Link to external network"
              switch2_details:
                switch_id: FDO87654321
                interface_name: Ethernet1/2.100
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

- name: Delete all L3Outs in fabric (use with caution)
  cisco.nd.nd_l3out:
    fabric: "{{ fabric_name }}"
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether any changes were made.
  type: bool
  returned: always
before:
  description: The state of L3Outs in the fabric before any changes.
  type: list
  elements: dict
  returned: always
after:
  description: The state of L3Outs in the fabric after changes are applied.
  type: list
  elements: dict
  returned: always
diff:
  description: The differences between before and after states.
  type: dict
  returned: always
  contains:
    before:
      description: State before changes.
      type: list
    after:
      description: State after changes.
      type: list
"""

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.l3out.l3out import (
    L3OutModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_l3out import (
    L3OutOrchestrator,
)


def _handle_attachments(nd_state_machine: NDStateMachine, check_mode: bool) -> None:
    """
    Process attach/detach operations for L3Outs that have the attach field set.

    This is called after manage_state() completes to handle deployment operations.
    """
    if check_mode:
        return

    attachments = []
    for item in nd_state_machine.proposed:
        if item.attach is not None:
            attachments.append({"name": item.name, "attach": item.attach})

    if attachments:
        nd_state_machine.model_orchestrator.attach_l3outs(attachments)


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(L3OutModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    nd_state_machine = None

    try:
        # Initialize StateMachine
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=L3OutOrchestrator,
        )

        # Manage state (merged, replaced, overridden, deleted)
        nd_state_machine.manage_state()

        # Post-state: handle attach/detach operations
        _handle_attachments(nd_state_machine, module.check_mode)

        # Format output
        verbosity = module._verbosity if hasattr(module, "_verbosity") else 0
        module.exit_json(
            **nd_state_machine.output.format_with_verbosity(
                verbosity, nd_state_machine.results
            )
        )

    except NDStateMachineError as e:
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module execution failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)

    except Exception as e:
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
