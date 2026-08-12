#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nd_manage_networks
version_added: "2.0.0"
short_description: Manage Network definitions on Cisco Nexus Dashboard
description:
  - Manage Network definitions across standalone, Multisite, and Multicluster fabric topologies.
  - The module resolves fabric topology, selects the appropriate workflow, and supports parent/child Network coordination.
author:
  - Akshayanat C S (@achengam)
options:
  fabric_name:
    description:
      - Name of the fabric to operate on.
    type: str
    required: true
  state:
    description:
      - Desired state of Network resources.
      - V(query) is accepted as a compatibility alias for V(gathered).
    type: str
    choices: [ merged, replaced, overridden, deleted, gathered, query ]
    default: merged
  config:
    description:
      - List of Network definitions to manage.
    type: list
    elements: dict
    default: []
    suboptions:
      network_name:
        description: Name of the Network.
        type: str
      net_name:
        description: Compatibility alias for C(network_name).
        type: str
      network_type:
        description: Network type.
        type: str
        choices:
          - vxlan
          - vxlanIbgp
          - vxlanEbgp
          - vxlanCampus
          - aimlVxlanIbgp
          - aimlVxlanEbgp
          - aimlRouted
          - routed
          - classicLanEnhanced
          - userDefined
          - vxlanAci
          - aci
          - externalConnectivity
          - vxlanExternal
      display_name:
        description: Display name.
        type: str
      vrf_name:
        description: VRF name associated with the Network.
        type: str
      tenant_name:
        description: Tenant name.
        type: str
      layer:
        description: Network layer.
        type: str
        choices: [ layer2, layer2WithSecurityGroup, layer3 ]
      is_l2only:
        description: Whether the Network is L2-only.
        type: bool
      x_connect:
        description: Enable xConnect.
        type: bool
      network_template_name:
        description: Network template name.
        type: str
      network_extension_template_name:
        description: Network extension template name.
        type: str
      service_network_template_name:
        description: Service network template name.
        type: str
      network_template_config:
        description: Network template configuration values.
        type: dict
      net_template:
        description: Compatibility Network template name.
        type: str
      net_extension_template:
        description: Compatibility Network extension template name.
        type: str
      deploy:
        description: Deploy pending changes for this Network.
        type: bool
        default: true
      deploy_type:
        description: Deployment scope for this Network.
        type: str
        choices: [ switch, network ]
        default: switch
      attach:
        description: Switch attachment entries for this Network.
        type: list
        elements: dict
        suboptions:
          ip_address:
            description: Switch management IP address.
            type: str
            required: true
          vlan_id:
            description: Attachment VLAN ID.
            type: int
          interfaces:
            description: Interface attachment entries.
            type: list
            required: true
            elements: dict
            suboptions:
              mode:
                description: Interface mode.
                type: str
                required: true
                choices: [ access, dot1qTunnel, trunk, promiscuous, trunkPromiscuous, host, trunkSecondary ]
              interface_range:
                description: Interface or interface range.
                type: str
                required: true
              interface_group_name:
                description: Interface group name.
                type: str
              native_vlan:
                description: Whether this is a native VLAN attachment.
                type: bool
                default: false
              mapping_type:
                description: VLAN mapping type.
                type: str
                choices: [ none, single ]
              customer_vlan:
                description: Customer VLAN.
                type: int
          deploy:
            description: Per-attachment deploy flag.
            type: bool
            default: true
          attachment_options:
            description: Switch-specific attachment options.
            type: dict
          extra_config:
            description: Raw attachment extra config.
            type: str

      network_id:
        description: Network segment ID.
        type: int
      net_id:
        description: Compatibility alias for C(network_id).
        type: int
      vlan_id:
        description: VLAN ID.
        type: int
      vlan_name:
        description: VLAN name.
        type: str
      gateway_ipv4_address:
        description: IPv4 gateway address and prefix.
        type: str
      gw_ip_subnet:
        description: Compatibility alias for C(gateway_ipv4_address).
        type: str
      gateway_ipv6_address:
        description: IPv6 gateway address and prefix.
        type: str
      gw_ipv6_subnet:
        description: Compatibility alias for C(gateway_ipv6_address).
        type: str
      secondary_gateway_ipv4_collection:
        description: Secondary IPv4 gateway addresses.
        type: list
        elements: str
      secondary_ip_gw1:
        description: Compatibility secondary IPv4 gateway field.
        type: str
      secondary_ip_gw2:
        description: Compatibility secondary IPv4 gateway field.
        type: str
      secondary_ip_gw3:
        description: Compatibility secondary IPv4 gateway field.
        type: str
      secondary_ip_gw4:
        description: Compatibility secondary IPv4 gateway field.
        type: str
      secondary_gateway_ipv6_collection:
        description: Secondary IPv6 gateway addresses.
        type: list
        elements: str
      vlan_intf_desc:
        description: VLAN interface description.
        type: str
      int_desc:
        description: Compatibility alias for C(vlan_intf_desc).
        type: str
      mtu:
        description: Network interface MTU.
        type: int
        default: 9216
      mtu_l3intf:
        description: Compatibility alias for C(mtu).
        type: int
        default: 9216
      arp_suppression:
        description: Enable ARP suppression.
        type: bool
        default: false
      arp_suppress:
        description: Compatibility alias for C(arp_suppression).
        type: bool
        default: false
      routing_tag:
        description: Routing tag.
        type: int
      dhcp_servers:
        description: DHCP server definitions.
        type: list
        elements: dict
        suboptions:
          server_address:
            description: DHCP server address.
            type: str
            required: true
          server_vrf:
            description: DHCP server VRF.
            type: str
      dhcp_srvr1_ip:
        description: Compatibility DHCP server address field.
        type: str
      dhcp_srvr1_vrf:
        description: Compatibility DHCP server VRF field.
        type: str
      dhcp_srvr2_ip:
        description: Compatibility DHCP server address field.
        type: str
      dhcp_srvr2_vrf:
        description: Compatibility DHCP server VRF field.
        type: str
      dhcp_srvr3_ip:
        description: Compatibility DHCP server address field.
        type: str
      dhcp_srvr3_vrf:
        description: Compatibility DHCP server VRF field.
        type: str
      loopback_id:
        description: Loopback ID.
        type: int
      dhcp_loopback_id:
        description: Compatibility alias for C(loopback_id).
        type: int
      igmp_version:
        description: IGMP version.
        type: int
        choices: [ 1, 2, 3 ]
      trm_enable:
        description: Enable Tenant Routed Multicast.
        type: bool
      ipv6_trm:
        description: Enable IPv6 Tenant Routed Multicast.
        type: bool
      l2_fabric_data:
        description: L2 fabric data overrides.
        type: dict
      stretch:
        description: Network stretch setting.
        type: str
      multicast_group_address:
        description: Multicast group address.
        type: str
      ds_vni:
        description: Downstream VNI.
        type: int
      netflow_enable:
        description: Enable netflow.
        type: bool
        default: false
      l2_netflow_monitor:
        description: Netflow monitor for L2 VLAN.
        type: str
      l3_netflow_monitor:
        description: Netflow monitor for L3 VLAN.
        type: str
      netflow_sampler:
        description: Netflow sampler name.
        type: str
      intfvlan_nf_monitor:
        description: Interface VLAN netflow monitor name.
        type: str
      vlan_nf_monitor:
        description: VLAN netflow monitor name.
        type: str
      gateway_on_border:
        description: Enable gateway on border.
        type: bool
      l3gw_on_border:
        description: Compatibility alias for C(gateway_on_border).
        type: bool
      child_fabric_config:
        description:
          - Per-child-fabric instance options for parent fabrics.
          - Parent fabrics own Network creation, deletion, identity, VLAN, gateway,
            attachment, and deployment fields.
        type: list
        elements: dict
        suboptions:
          fabric_name:
            description: Child fabric name.
            type: str
            required: true
          dhcp_servers:
            description: DHCP server definitions.
            type: list
            elements: dict
            suboptions:
              server_address:
                description: DHCP server address.
                type: str
                required: true
              server_vrf:
                description: DHCP server VRF.
                type: str
          dhcp_srvr1_ip:
            description: Compatibility DHCP server address field.
            type: str
          dhcp_srvr1_vrf:
            description: Compatibility DHCP server VRF field.
            type: str
          dhcp_srvr2_ip:
            description: Compatibility DHCP server address field.
            type: str
          dhcp_srvr2_vrf:
            description: Compatibility DHCP server VRF field.
            type: str
          dhcp_srvr3_ip:
            description: Compatibility DHCP server address field.
            type: str
          dhcp_srvr3_vrf:
            description: Compatibility DHCP server VRF field.
            type: str
          loopback_id:
            description: Loopback ID.
            type: int
          dhcp_loopback_id:
            description: Compatibility alias for C(loopback_id).
            type: int
          igmp_version:
            description: IGMP version.
            type: int
            choices: [ 1, 2, 3 ]
          trm_enable:
            description: Enable Tenant Routed Multicast.
            type: bool
          ipv6_trm:
            description: Enable IPv6 Tenant Routed Multicast.
            type: bool
          l2_fabric_data:
            description: L2 fabric data overrides.
            type: dict
          stretch:
            description: Network stretch setting.
            type: str
          multicast_group_address:
            description: Multicast group address.
            type: str
          ds_vni:
            description: Downstream VNI.
            type: int
          netflow_enable:
            description: Enable netflow.
            type: bool
          l2_netflow_monitor:
            description: Netflow monitor for L2 VLAN.
            type: str
          l3_netflow_monitor:
            description: Netflow monitor for L3 VLAN.
            type: str
          netflow_sampler:
            description: Netflow sampler name.
            type: str
          gateway_on_border:
            description: Enable gateway on border.
            type: bool
          l3gw_on_border:
            description: Compatibility alias for C(gateway_on_border).
            type: bool
extends_documentation_fragment:
  - cisco.nd.modules
  - cisco.nd.check_mode
"""
EXAMPLES = r"""
- name: Create an L2-only Network on a standalone fabric
  cisco.nd.nd_manage_networks:
    fabric_name: fab1
    state: merged
    config:
      - network_name: Network_BLUE
        is_l2only: true
        network_id: 50010
        vlan_id: 2001
        vlan_name: Network_BLUE_VLAN
        deploy: false

- name: Create a Network and attach it to a switch interface
  cisco.nd.nd_manage_networks:
    fabric_name: fab1
    state: merged
    config:
      - network_name: Network_BLUE
        is_l2only: true
        network_id: 50010
        vlan_id: 2001
        vlan_name: Network_BLUE_VLAN
        attach:
          - ip_address: 192.0.2.10
            vlan_id: 2001
            interfaces:
              - mode: access
                interface_range: Ethernet1/10
        deploy: true
        deploy_type: switch

- name: Create an L3 Network associated with a VRF
  cisco.nd.nd_manage_networks:
    fabric_name: fab1
    state: merged
    config:
      - network_name: Network_L3
        is_l2only: false
        vrf_name: Tenant_A
        network_id: 50020
        vlan_id: 2002
        vlan_name: Network_L3_VLAN
        gateway_ipv4_address: 10.10.20.1/24
        arp_suppression: true
        routing_tag: 12345
        deploy: false

- name: Create Network on a parent fabric with child fabric overrides
  cisco.nd.nd_manage_networks:
    fabric_name: msd_parent
    state: merged
    config:
      - network_name: Network_PARENT
        is_l2only: true
        network_id: 50030
        vlan_id: 2030
        vlan_name: Network_PARENT_VLAN
        child_fabric_config:
          - fabric_name: child_fabric_1
            multicast_group_address: 239.1.1.30

- name: Gather Networks on a child fabric
  cisco.nd.nd_manage_networks:
    fabric_name: child_fabric_1
    state: gathered
    config: []

- name: Delete a Network
  cisco.nd.nd_manage_networks:
    fabric_name: fab1
    state: deleted
    config:
      - network_name: Network_BLUE
        is_l2only: true
"""
RETURN = r"""
changed:
  description: Whether the module changed Network, attachment, or deployment state.
  returned: always
  type: bool
before:
  description: Network configuration present on ND before the operation.
  returned: always
  type: list
  elements: dict
after:
  description: Network configuration present on ND after the operation.
  returned: always
  type: list
  elements: dict
diff:
  description: Configuration diff calculated by the module.
  returned: always
  type: list
  elements: dict
fabric_type:
  description:
    - Resolved fabric topology used by the workflow.
    - Values include V(standalone), V(multisite_parent), V(multisite_child),
      V(multicluster_parent), and V(multicluster_child).
  returned: always
  type: str
workflow:
  description: Human-readable workflow path selected for the operation.
  returned: always
  type: str
parent_fabric:
  description:
    - Parent fabric result for MSD or MCFG parent workflows that execute child
      fabric tasks.
    - Contains the same state-machine and API trace fields as a standalone
      result, plus C(fabric_name).
  returned: when a parent workflow processes one or more child fabrics
  type: dict
child_fabrics:
  description:
    - Per-child-fabric results for MSD or MCFG parent workflows.
    - Each entry contains the same state-machine and API trace fields as a
      standalone result, plus C(fabric_name).
  returned: when a parent workflow processes one or more child fabrics
  type: list
  elements: dict
api_paths:
  description: REST API paths called by the module.
  returned: with verbosity C(-vv) or C(output_level=debug)
  type: list
  elements: str
api_verbs:
  description: REST API verbs called by the module.
  returned: with verbosity C(-vv) or C(output_level=debug)
  type: list
  elements: str
api_payload:
  description: REST request payloads sent to ND.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
api_response:
  description: Raw normalized REST responses returned by ND.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
api_result:
  description: Response-handler result for each REST call.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
api_diff:
  description: Per-REST-call diff data recorded by the result infrastructure.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
api_metadata:
  description: Per-REST-call metadata recorded by the result infrastructure.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import (
    NetworkWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
    network_parent_argument_spec,
)

# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        fabric_name=dict(type="str", required=True),
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "overridden", "deleted", "gathered", "query"],
        ),
        config=dict(
            type="list",
            elements="dict",
            required=False,
            default=[],
            options=network_parent_argument_spec(),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    try:
        coordinator = NetworkWorkflowCoordinator(module=module)
        result = coordinator.run()

        module.exit_json(**result)

    except NDStateMachineError as e:
        module.fail_json(msg=str(e))
    except NotImplementedError as e:
        module.fail_json(msg=f"Feature not yet implemented: {str(e)}")
    except Exception as e:
        module.fail_json(msg=f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()
