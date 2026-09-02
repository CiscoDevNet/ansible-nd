#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_manage_links
version_added: "2.0.0"
short_description: Manages links on Cisco Nexus Dashboard.
description:
- Manages network links between switches on Cisco Nexus Dashboard.
- Supports both single-cluster and multi-cluster (One Manage) scopes.
- Supports bulk operations for efficient creation and deletion.
- Auto-detects scope from config, or use O(link_scope) to override.
author:
- Shreyas Srish (@shrsr)
options:
  fabric_name:
    description:
    - Name of the fabric. Required for querying links.
    type: str
    required: true
  link_scope:
    description:
    - Which API scope to use for link operations.
    - V(auto) auto-detects based on the presence of cluster fields in config.
    - V(manage) uses the single-cluster scope (6-field identity).
    - V(one_manage) uses the multi-cluster scope (8-field identity including cluster names).
    type: str
    choices: [ auto, manage, one_manage ]
    default: auto
  cluster_name:
    description:
    - Target cluster name for multi-cluster operations.
    - Only used when O(link_scope=one_manage) or auto-detected.
    type: str
  ticket_id:
    description:
    - Change Control Ticket Id for multi-cluster operations.
    - Only used when O(link_scope=one_manage) or auto-detected.
    type: str
  config:
    description:
    - A list of link configurations to manage.
    - Required for all states except O(state=gathered).
    type: list
    elements: dict
    required: false
    suboptions:
      src_cluster_name:
        description:
        - The name of the source cluster.
        - Only used in the multi-cluster (One Manage) scope.
        type: str
      dst_cluster_name:
        description:
        - The name of the destination cluster.
        - Only used in the multi-cluster (One Manage) scope.
        type: str
      src_fabric_name:
        description:
        - The name of the source fabric.
        - Required within each O(config) item; it is a mandatory part of the link identity.
        type: str
        required: true
      dst_fabric_name:
        description:
        - The name of the destination fabric.
        - Required within each O(config) item; it is a mandatory part of the link identity.
        type: str
        required: true
      src_switch_name:
        description:
        - The hostname of the source switch.
        - At least one of O(config.src_switch_name), O(config.src_switch_ip) or O(config.src_switch_id) is required to identify the source switch.
        - When more than one is set, priority is O(config.src_switch_id), then O(config.src_switch_ip), then O(config.src_switch_name).
        - Multiple supplied selectors must resolve to the same switch or the module fails before making a change.
        type: str
      dst_switch_name:
        description:
        - The hostname of the destination switch.
        - At least one of O(config.dst_switch_name), O(config.dst_switch_ip) or O(config.dst_switch_id) is required to identify the destination switch.
        - When more than one is set, priority is O(config.dst_switch_id), then O(config.dst_switch_ip), then O(config.dst_switch_name).
        - Multiple supplied selectors must resolve to the same switch or the module fails before making a change.
        type: str
      src_switch_ip:
        description:
        - The management IP address of the source switch.
        - Useful when switch hostnames are ambiguous within a fabric.
        type: str
      dst_switch_ip:
        description:
        - The management IP address of the destination switch.
        - Useful when switch hostnames are ambiguous within a fabric.
        type: str
      src_switch_id:
        description:
        - The serial number or identifier of the source switch.
        type: str
      dst_switch_id:
        description:
        - The serial number or identifier of the destination switch.
        type: str
      src_interface_name:
        description:
        - The name of the source interface, for example C(Ethernet1/1).
        - Required within each O(config) item; it is a mandatory part of the link identity.
        type: str
        required: true
      dst_interface_name:
        description:
        - The name of the destination interface, for example C(Ethernet1/1).
        - Required within each O(config) item; it is a mandatory part of the link identity.
        type: str
        required: true
      config_data:
        description:
        - The link policy configuration.
        type: dict
        suboptions:
          policy_type:
            description:
            - The link policy type, which determines the valid keys under O(config.config_data.template_inputs).
            - V(numbered) is an IPv4/IPv6 addressed point-to-point link.
            - V(unnumbered) is an unnumbered link that borrows its address from another interface.
            - V(ipv6LinkLocal) uses automatic C(fe80::/10) link-local addressing.
            - V(ebgpVrfLite) is an eBGP peering over a VRF Lite link.
            - V(iosXeNumbered) is an IOS-XE intra-fabric numbered link (for example a Campus C(vxlanCampus) intra-fabric link).
            - V(layer2Dci) is a Layer 2 trunk between data centers.
            - V(layer3DciVrfLite) is a VRF Lite stitched Layer 3 DCI link.
            - V(multisiteOverlay) is a Border Gateway overlay eBGP session.
            - V(multisiteUnderlay) is a Border Gateway underlay reachability link.
            - V(mplsOverlay) is an MPLS Segment Routing loopback eBGP peering.
            - V(mplsUnderlay) is an MPLS underlay using IS-IS or OSPF with segment routing.
            - V(preprovision) pre-provisions a link before the switches are online.
            - V(userDefined) uses a custom template named by O(config.config_data.template_name).
            - V(vpcPeerKeepalive) is a vPC peer keepalive (heartbeat) link.
            type: str
            choices:
            - numbered
            - unnumbered
            - ipv6LinkLocal
            - ebgpVrfLite
            - iosXeNumbered
            - layer2Dci
            - layer3DciVrfLite
            - multisiteOverlay
            - multisiteUnderlay
            - mplsOverlay
            - mplsUnderlay
            - preprovision
            - userDefined
            - vpcPeerKeepalive
          template_name:
            description:
            - The name of the link template.
            - Required when O(config.config_data.policy_type=userDefined).
            type: str
          template_inputs:
            description:
            - The policy specific input fields for the link.
            - This is a free-form dictionary validated per policy type by the module. It is intentionally not modeled as static suboptions because the
              valid keys differ by O(config.config_data.policy_type); the supported keys for each policy type are enumerated below.
            - The accepted keys depend on O(config.config_data.policy_type). Keys that do not belong to the selected policy type are rejected.
            - Omitted fields are sent with ND's documented default (for example C(mtu) 9216, C(interface_admin_state) C(true), C(fec) C(auto)) or,
              when no documented default exists, a typed empty value (C("") / C(0) / C(false)), including secrets. See the note on secret fields below.
            - This module can create and update the policy types listed below. Other valid ND policy types (for example C(ipfmNumbered) or
              C(routedFabric)) are still read back by O(state=gathered) and preserved as opaque records; the module warns about them and never
              modifies or deletes them.
            - 'In the lists below, a key shown as C(name) (int) or C(name) (bool) takes that type; all other keys are strings.'
            - 'Secret fields - C(ebgp_password), C(default_vrf_ebgp_neighbor_password), C(macsec_primary_key_string) and C(macsec_fallback_key_string)
              are sent to the controller but their values are masked as C(VALUE_SPECIFIED_IN_NO_LOG_PARAMETER) in this module''s output and excluded
              from rendered diffs. Nexus Dashboard does not return secret values on read, so explicitly supplying a secret is treated as update
              intent. Omit it for an idempotent reapplication; re-supply it when updating a link for another reason, otherwise it is written empty.
              The module registers supplied values for no-log masking before it prepares or validates link identities.'
            - 'Common interface fields, available on V(numbered), V(unnumbered) and V(ipv6LinkLocal) - C(interface_admin_state) (bool), C(mtu) (int),
              C(speed), C(fec), C(src_interface_description), C(dst_interface_description), C(src_interface_config), C(dst_interface_config)
              and C(macsec) (bool).'
            - 'V(numbered) - the common interface fields plus C(src_ip), C(dst_ip), C(src_ipv6), C(dst_ipv6), C(dhcp_relay_on_src_interface) (bool),
              C(dhcp_relay_on_dst_interface) (bool), C(bfd_echo_on_src_interface) (bool) and C(bfd_echo_on_dst_interface) (bool).'
            - 'V(unnumbered) - the common interface fields plus C(dhcp_relay_on_src_interface) (bool) and C(dhcp_relay_on_dst_interface) (bool).'
            - 'V(ipv6LinkLocal) - the common interface fields only.'
            - 'V(iosXeNumbered) - C(interface_admin_state) (bool), C(src_ip), C(dst_ip), C(speed), C(mtu) (int, IOS-XE default 9198)
              and the interface description fields.'
            - 'V(ebgpVrfLite) - C(src_ebgp_asn), C(dst_ebgp_asn), C(src_ip_address_mask), C(src_ipv6_address_mask), C(dst_ip_address), C(dst_ipv6_address),
              C(link_mtu) (int), C(routing_tag), C(auto_gen_config_default_vrf) (bool), C(auto_gen_config_nx_peer_default_vrf) (bool),
              C(auto_gen_config_peer) (bool), C(dci_tracking) (bool), C(default_vrf_ebgp_neighbor_password),
              C(default_vrf_ebgp_password_key_encryption_type), C(redistrib_ebgp_route_map_name), C(template_config_gen_peer),
              C(vrf_name_nx_peer_switch), the interface description fields, the full MACsec fields, the QKD fields
              and C(inherit_ttag_fabric_setting) (bool).'
            - 'V(layer2Dci) - C(trunk_allowed_vlans), C(native_vlan) (int), C(bpdu_guard), C(port_type_fast) (bool), C(mtu_type), C(speed),
              the interface description fields, the full MACsec fields and the QKD fields.'
            - 'V(layer3DciVrfLite) - C(src_ip_address_mask), C(dst_ip_address_mask), C(src_ipv6_address_mask), C(dst_ipv6_address_mask), C(src_vrf_name),
              C(dst_vrf_name), C(link_mtu) (int), C(speed), C(ip_redirects) (bool), C(ipv4_pim) (bool), C(ipv6_pim) (bool), the interface description fields,
              the full MACsec fields, the QKD fields, the Netflow fields and C(inherit_ttag_fabric_setting) (bool).'
            - 'V(multisiteOverlay) - C(src_ebgp_asn), C(dst_ebgp_asn), C(src_ip_address), C(dst_ip_address), C(ebgp_multihop) (int), C(ipv4_trm) (bool),
              C(ipv6_trm) (bool), C(redistribute_route_server) (bool), C(route_server_routing_tag), C(skip_config_generation) (bool),
              the interface description fields, the full MACsec fields, the QKD fields and the eBGP password fields.'
            - 'V(multisiteUnderlay) - C(src_ebgp_asn), C(dst_ebgp_asn), C(ebgp_bfd) (bool), C(ebgp_log_neighbor_change) (bool), C(ebgp_maximum_paths) (int),
              C(ebgp_send_comboth) (bool), C(src_ip_address_mask), C(src_ipv6_address_mask), C(dst_ip_address), C(dst_ipv6_address), C(link_mtu) (int),
              C(speed), C(routing_tag), C(dci_tracking_enable_flag) (bool), the interface description fields, the eBGP password fields
              and C(inherit_ttag_fabric_setting) (bool).'
            - 'V(mplsOverlay) - C(src_ebgp_asn), C(dst_ebgp_asn) and C(dst_ip_address).'
            - 'V(mplsUnderlay) - C(mpls_fabric_type), C(dci_routing_protocol), C(dci_routing_tag), C(ospf_area_id), C(sr_global_block_range),
              C(src_sr_index) (int), C(dst_sr_index) (int), C(src_ip_address_mask), C(dst_ip_address), C(link_mtu) (int), the interface description fields
              and C(inherit_ttag_fabric_setting) (bool).'
            - 'V(preprovision) - C(src_interface_description), C(dst_interface_description), C(src_interface_config), C(dst_interface_config),
              C(mtu) (int) and C(speed).'
            - 'V(vpcPeerKeepalive) - C(src_ip), C(dst_ip), C(src_ipv6), C(dst_ipv6), C(interface_vrf), C(interface_admin_state) (bool), C(mtu) (int)
              and the interface description fields.'
            - 'V(userDefined) - an open set of fields validated by ND; C(allowed_vlans) and C(mtu) (int) are recognized,
              and O(config.config_data.template_name) must be set.'
            - 'eBGP password fields - C(enable_ebgp_password) (bool), C(ebgp_password), C(ebgp_auth_key_encryption_type)
              and C(inherit_ebgp_password_msd_settings) (bool).'
            - 'Full MACsec fields - C(macsec) (bool), C(macsec_cipher_suite), C(macsec_primary_cryptographic_algorithm), C(macsec_primary_key_string),
              C(macsec_fallback_cryptographic_algorithm), C(macsec_fallback_key_string) and C(override_fabric_macsec) (bool).'
            - 'QKD (Quantum Key Distribution) fields - C(qkd) (bool), C(ignore_certificate) (bool), C(src_kme_server_ip), C(dst_kme_server_ip),
              C(src_kme_server_port_number) (int), C(dst_kme_server_port_number) (int), C(src_macsec_key_chain_prefix), C(dst_macsec_key_chain_prefix),
              C(src_qkd_profile_name), C(dst_qkd_profile_name), C(src_trustpoint_label) and C(dst_trustpoint_label).'
            - 'Netflow fields - C(netflow_on_src_interface) (bool), C(netflow_on_dst_interface) (bool), C(src_netflow_monitor_name)
              and C(dst_netflow_monitor_name).'
            type: dict
  state:
    description:
    - Use V(merged) to create or update the links in O(config). Links that are not listed are left unchanged.
    - Use V(replaced) to replace the configuration of the listed links with O(config).
    - Use V(overridden) to make the links match O(config) exactly. Links in scope that are not listed are deleted.
    - Use V(deleted) to delete the listed links.
    - Use V(gathered) to read the existing links in scope and return them under the C(gathered) key in O(config) format. No changes are made.
    type: str
    choices: [ merged, replaced, overridden, deleted, gathered ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create a numbered (IPv4 point-to-point) link
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: numbered
          template_inputs:
            src_ip: 10.99.30.1
            dst_ip: 10.99.30.2
            mtu: 9216
            speed: auto
            fec: auto
            interface_admin_state: true
            src_interface_description: ansible numbered source
            dst_interface_description: ansible numbered destination
    state: merged

- name: Create multiple numbered links in one bulk call
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: numbered
          template_inputs:
            src_ip: 10.99.30.1
            dst_ip: 10.99.30.2
            mtu: 9216
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/31
        dst_interface_name: Ethernet1/31
        config_data:
          policy_type: numbered
          template_inputs:
            src_ip: 10.99.31.1
            dst_ip: 10.99.31.2
            mtu: 9216
    state: merged

- name: Identify switches by management IP (avoids hostname collisions)
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_ip: 192.0.2.10
        dst_switch_ip: 192.0.2.11
        src_interface_name: Ethernet1/1
        dst_interface_name: Ethernet1/1
        config_data:
          policy_type: numbered
          template_inputs:
            src_ip: 10.0.0.1
            dst_ip: 10.0.0.2
            mtu: 9216
            interface_admin_state: true
    state: merged

- name: Create an unnumbered link
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: unnumbered
          template_inputs:
            mtu: 9216
            speed: auto
            fec: auto
            interface_admin_state: true
    state: merged

- name: Create an IPv6 link-local link
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/1
        dst_interface_name: Ethernet1/1
        config_data:
          policy_type: ipv6LinkLocal
          template_inputs:
            interface_admin_state: true
            mtu: 9216
    state: merged

- name: Create a vPC peer keepalive link
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: leaf-2
        src_interface_name: mgmt0
        dst_interface_name: mgmt0
        config_data:
          policy_type: vpcPeerKeepalive
          template_inputs:
            src_ip: 10.1.1.1
            dst_ip: 10.1.1.2
            interface_vrf: management
            interface_admin_state: true
            mtu: 1500
    state: merged

- name: Pre-provision a link before the switches are online
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: preprovision
          template_inputs:
            src_interface_description: ansible preprovision source
            dst_interface_description: ansible preprovision destination
    state: merged

- name: Create a Layer 2 DCI trunk link between two fabrics
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab-a
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab-a
        dst_fabric_name: ansible-fab-b
        src_switch_name: bgw-1
        dst_switch_name: bgw-2
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: layer2Dci
          template_inputs:
            trunk_allowed_vlans: "100,200,300"
            native_vlan: 1
            port_type_fast: true
            mtu_type: jumbo
            speed: auto
    state: merged

- name: Create a Layer 3 DCI VRF Lite link
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab-a
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab-a
        dst_fabric_name: ansible-fab-b
        src_switch_name: border-1
        dst_switch_name: border-2
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: layer3DciVrfLite
          template_inputs:
            src_ip_address_mask: "10.99.50.1/30"
            dst_ip_address_mask: "10.99.50.2/30"
            src_vrf_name: tenant-a
            dst_vrf_name: tenant-a
            link_mtu: 9216
            speed: auto
    state: merged

- name: Create an eBGP VRF Lite link
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab-a
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab-a
        dst_fabric_name: ansible-fab-b
        src_switch_name: border-1
        dst_switch_name: border-2
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: ebgpVrfLite
          template_inputs:
            src_ebgp_asn: "65001"
            dst_ebgp_asn: "65002"
            src_ip_address_mask: "10.99.30.1/30"
            dst_ip_address: "10.99.30.2"
            link_mtu: 9216
    state: merged

- name: Create an MPLS underlay link (segment routing)
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab-a
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab-a
        dst_fabric_name: ansible-fab-b
        src_switch_name: pe-1
        dst_switch_name: pe-2
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: mplsUnderlay
          template_inputs:
            mpls_fabric_type: mplsSr
            dci_routing_protocol: is-is
            sr_global_block_range: "16000-23999"
            src_sr_index: 100
            dst_sr_index: 101
            src_ip_address_mask: "10.99.60.1/30"
            dst_ip_address: "10.99.60.2"
            link_mtu: 9216
    state: merged

- name: Create an MPLS overlay eBGP peering
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab-a
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab-a
        dst_fabric_name: ansible-fab-b
        src_switch_name: pe-1
        dst_switch_name: pe-2
        src_interface_name: loopback0
        dst_interface_name: loopback0
        config_data:
          policy_type: mplsOverlay
          template_inputs:
            src_ebgp_asn: "65001"
            dst_ebgp_asn: "65002"
            dst_ip_address: 10.99.61.2
    state: merged

- name: Create a multi-cluster multisite underlay link (One Manage, bulk)
  cisco.nd.nd_manage_links:
    fabric_name: fab1
    config:
      - src_cluster_name: cluster-191
        dst_cluster_name: cluster-187
        src_fabric_name: fab2
        dst_fabric_name: fab1
        src_switch_name: v1-bgw2
        dst_switch_name: v1-bgw1
        src_interface_name: Ethernet1/12
        dst_interface_name: Ethernet1/12
        config_data:
          policy_type: multisiteUnderlay
          template_inputs:
            src_ebgp_asn: "200"
            dst_ebgp_asn: "100"
            src_ip_address_mask: "30.30.30.10/31"
            dst_ip_address: "30.30.30.11"
            link_mtu: 9216
            ebgp_maximum_paths: 2
    state: merged

- name: Create a multisite overlay link with explicit scope and change control
  cisco.nd.nd_manage_links:
    fabric_name: fab1
    link_scope: one_manage
    cluster_name: cluster-191
    ticket_id: CHG-12345
    config:
      - src_cluster_name: cluster-191
        dst_cluster_name: cluster-187
        src_fabric_name: fab2
        dst_fabric_name: fab1
        src_switch_name: v1-bgw2
        dst_switch_name: v1-bgw1
        src_interface_name: Ethernet1/40
        dst_interface_name: Ethernet1/40
        config_data:
          policy_type: multisiteOverlay
          template_inputs:
            src_ebgp_asn: "65001"
            dst_ebgp_asn: "65002"
            src_ip_address: 10.99.40.1
            dst_ip_address: 10.99.40.2
            ebgp_multihop: 5
    state: merged

- name: Create a user-defined link using a custom template
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    config:
      - src_fabric_name: ansible-fab
        dst_fabric_name: ansible-fab
        src_switch_name: leaf-1
        dst_switch_name: spine-1
        src_interface_name: Ethernet1/30
        dst_interface_name: Ethernet1/30
        config_data:
          policy_type: userDefined
          template_name: my_custom_link_template
          template_inputs:
            allowed_vlans: "10,20,30"
            mtu: 9216
    state: merged

- name: Gather all links in a fabric (read-only)
  cisco.nd.nd_manage_links:
    fabric_name: ansible-fab
    link_scope: manage
    state: gathered
  register: all_links

- name: Delete links (bulk)
  cisco.nd.nd_manage_links:
    fabric_name: fab1
    config:
      - src_cluster_name: cluster-191
        dst_cluster_name: cluster-187
        src_fabric_name: fab2
        dst_fabric_name: fab1
        src_switch_name: v1-bgw2
        dst_switch_name: v1-bgw1
        src_interface_name: Ethernet1/12
        dst_interface_name: Ethernet1/12
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, the link configuration.
  returned: always
  type: bool
  sample: true
output_level:
  description: The output verbosity level in effect for the run, echoing the O(output_level) parameter.
  returned: always
  type: str
  sample: normal
before:
  description:
  - The existing links matching O(config) before the module ran, structured the same as the O(config) parameter.
  - An empty list when no matching link existed.
  returned: when O(state) is V(merged), V(replaced), V(overridden) or V(deleted)
  type: list
  elements: dict
  sample:
  - src_fabric_name: fabric1
    dst_fabric_name: fabric1
    src_switch_name: leaf-1
    dst_switch_name: spine-1
    src_interface_name: Ethernet1/1
    dst_interface_name: Ethernet1/1
    config_data:
      policy_type: numbered
      template_inputs:
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
after:
  description:
  - The link configuration after the module ran, structured the same as the O(config) parameter.
  - In check mode, the configuration that would result had the module run outside of check mode.
  returned: when O(state) is V(merged), V(replaced), V(overridden) or V(deleted)
  type: list
  elements: dict
  sample:
  - src_fabric_name: fabric1
    dst_fabric_name: fabric1
    src_switch_name: leaf-1
    dst_switch_name: spine-1
    src_interface_name: Ethernet1/1
    dst_interface_name: Ethernet1/1
    config_data:
      policy_type: numbered
      template_inputs:
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
diff:
  description: The per-link difference between C(before) and C(after).
  returned: when O(state) is V(merged), V(replaced), V(overridden) or V(deleted)
  type: list
  elements: dict
  sample:
  - src_fabric_name: fabric1
    dst_fabric_name: fabric1
    src_switch_name: leaf-1
    dst_switch_name: spine-1
    src_interface_name: Ethernet1/1
    dst_interface_name: Ethernet1/1
    config_data:
      template_inputs:
        dst_ip: 10.0.0.2
proposed:
  description:
  - The link configuration as sent to Nexus Dashboard, derived from O(config).
  - Secret template inputs (for example C(ebgp_password)) are masked as C(VALUE_SPECIFIED_IN_NO_LOG_PARAMETER).
  returned: when O(state) is V(merged), V(replaced), V(overridden) or V(deleted)
  type: list
  elements: dict
  sample:
  - src_fabric_name: fabric1
    dst_fabric_name: fabric1
    src_switch_name: leaf-1
    dst_switch_name: spine-1
    src_interface_name: Ethernet1/1
    dst_interface_name: Ethernet1/1
    config_data:
      policy_type: numbered
      template_inputs:
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
gathered:
  description:
  - The links read from Nexus Dashboard, structured so the list can be copied back into the O(config) parameter.
  - Read-only response keys (for example the link identifier) are pruned and secret template inputs are masked.
  returned: when O(state) is V(gathered)
  type: list
  elements: dict
  sample:
  - src_fabric_name: fabric1
    dst_fabric_name: fabric1
    src_switch_name: leaf-1
    dst_switch_name: spine-1
    src_interface_name: Ethernet1/1
    dst_interface_name: Ethernet1/1
    config_data:
      policy_type: numbered
      template_inputs:
        src_ip: 10.0.0.1
        dst_ip: 10.0.0.2
logs:
  description: Ordered list of the operations the module performed against Nexus Dashboard.
  returned: when O(output_level=debug)
  type: list
  elements: str
  sample:
  - "Created link leaf-1:Ethernet1/1 <-> spine-1:Ethernet1/1"
msg:
  description: The error message describing why the module failed.
  returned: on failure
  type: str
  sample: "Initialization failed: ..."
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.links.links import NDLinkModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.links import NDLinkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.manage_link import ManageLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.one_manage_link import OneManageLinkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def determine_strategy(module: AnsibleModule) -> ManageLinkStrategy | OneManageLinkStrategy | None:
    """Pick the link strategy from O(link_scope) or autodetect from config cluster fields."""
    link_scope = module.params.get("link_scope", "auto")
    fabric_name = module.params.get("fabric_name")
    cluster_name = module.params.get("cluster_name")
    ticket_id = module.params.get("ticket_id")

    if link_scope == "manage":
        return ManageLinkStrategy(fabric_name=fabric_name, cluster_name=cluster_name, ticket_id=ticket_id)

    if link_scope == "one_manage":
        return OneManageLinkStrategy(
            fabric_name=fabric_name,
            cluster_name=cluster_name,
            ticket_id=ticket_id,
        )

    if link_scope == "auto":
        # ``config`` is optional (e.g. ``state: gathered`` with no config); Ansible
        # supplies the key with value None, so ``.get("config", [])`` returns None,
        # not the []-fallback. Coalesce with ``or []`` before iterating.
        config = module.params.get("config") or []
        has_cluster_fields = any(item.get("src_cluster_name") or item.get("dst_cluster_name") for item in config)
        if has_cluster_fields:
            return OneManageLinkStrategy(
                fabric_name=fabric_name,
                cluster_name=cluster_name,
                ticket_id=ticket_id,
            )
        return ManageLinkStrategy(fabric_name=fabric_name, cluster_name=cluster_name, ticket_id=ticket_id)

    module.fail_json(msg="Invalid link_scope: {0}".format(link_scope))


def validate_scope_identity(module: AnsibleModule, strategy: ManageLinkStrategy | OneManageLinkStrategy | None) -> None:
    """Validate scope-dependent link identity once ``link_scope`` is resolved.

    The argspec marks the fabric and interface names required on every item (they
    are identity for both scopes). Cluster names are identity only for OneManage,
    so requiredness cannot be expressed statically in the argspec; enforce it here.
    Fail early with a field-specific message instead of a late controller error.
    ``state: gathered`` supplies no config, so it is naturally exempt.
    """
    if not isinstance(strategy, OneManageLinkStrategy):
        return
    for index, item in enumerate(module.params.get("config") or []):
        if not isinstance(item, dict):
            continue
        missing = [name for name in ("src_cluster_name", "dst_cluster_name") if not item.get(name)]
        if missing:
            module.fail_json(
                msg="config item {0} is missing OneManage identity field(s): {1}. "
                "Source and destination cluster names are required in the one_manage scope.".format(index, ", ".join(missing))
            )


def register_secret_values(module: AnsibleModule) -> None:
    """Register free-form template secrets before any preparation can fail.

    ``NDStateMachine`` also performs generic model-level registration, but link
    identity preparation runs before state-machine construction. Register the raw
    user values here so Ansible can scrub them from invocation data even when switch
    resolution or other preparation fails early.
    """
    if not hasattr(module, "no_log_values"):
        return
    for config_item in module.params.get("config") or []:
        module.no_log_values |= NDLinkModel.collect_secret_values(config_item)


def main() -> None:
    argument_spec = nd_argument_spec()
    argument_spec.update(NDLinkModel.get_argument_spec())
    argument_spec.update(
        fabric_name=dict(type="str", required=True),
        link_scope=dict(
            type="str",
            default="auto",
            choices=["auto", "manage", "one_manage"],
        ),
        cluster_name=dict(type="str"),
        ticket_id=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "replaced", ["config"]),
            ("state", "overridden", ["config"]),
            ("state", "deleted", ["config"]),
        ],
    )
    require_pydantic(module)
    register_secret_values(module)

    try:
        strategy = determine_strategy(module)
        NDLinkModel.identifiers = strategy.identifier_fields
        validate_scope_identity(module, strategy)

        sender = Sender()
        sender.ansible_module = module
        rest_send = RestSend(
            {
                "check_mode": module.check_mode,
                "state": module.params.get("state"),
            }
        )
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()

        orchestrator = NDLinkOrchestrator(rest_send=rest_send, strategy=strategy)

        # Resolve switch identities (name/ip/id backfill) on a copy so the raw
        # user config in module.params -- and thus the invocation echo -- stays
        # untouched, then hand the prepared list to the state machine directly.
        prepared_config = orchestrator.prepare_config_data(module.params.get("config") or [])
        state_machine = NDStateMachine(module=module, model_orchestrator=orchestrator, config=prepared_config)
        state_machine.manage_state()

        result = state_machine.output.format()
        module.exit_json(**result)

    except NDStateMachineError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg="Unexpected error: {0}".format(str(e)))


if __name__ == "__main__":
    main()
