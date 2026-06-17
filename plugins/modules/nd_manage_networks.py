#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nd_manage_networks
version_added: "1.0.0"
short_description: Manages Network definitions on Cisco Nexus Dashboard.
description:
  - Manages Network definitions on Cisco Nexus Dashboard across standalone,
    Multisite (MSD), and Multicluster (MCFG) fabric topologies.
  - This module manages Network definitions, parent or standalone Network switch
    attachments, and optional deployment of pending Network changes.
  - Supported Network definition properties include identity, custom templates,
    VLAN/SVI, security group defaults, TRM, routing, netflow, and route targets.
  - Automatically detects fabric type from the ND API and routes to the
    appropriate workflow without requiring extra user input.
  - For parent fabrics (MSD / MCFG), supports child-fabric coordination
    via the C(child_fabric_config) parameter inside each Network definition.
  - Child fabrics only permit C(state=gathered) when targeted directly;
    all write operations must be driven through the parent fabric.
author:
  - Akshayanat C S (@achengam)
options:
  fabric:
    description:
      - Name of the fabric to operate on.
      - The module auto-detects whether this is a standalone, parent,
        or child fabric and routes accordingly.
    type: str
    required: true
  state:
    description:
      - Desired state of the Network resources.
      - V(merged) creates or updates Networks that do not match the desired config.
      - V(replaced) replaces existing Networks that match the desired config.
      - V(overridden) replaces all Networks; removes any not in config.
      - V(deleted) removes specified Networks (or all if config is empty).
      - V(gathered) returns current Network state (the only state allowed on child
        fabrics when targeted directly).
      - V(query) is accepted as a compatibility alias for V(gathered).
    type: str
    choices: [ merged, replaced, overridden, deleted, gathered, query ]
    default: merged
  deploy_type:
    description:
      - Compatibility top-level deployment scope.
      - C(switch) deploys affected switches.
      - C(network) deploys pending work for the network resource.
      - C(resource) is accepted as a compatibility alias for C(network).
      - Per-network C(config[].deploy_type) takes precedence.
    type: str
    choices: [ switch, network, resource ]
    default: switch
  config:
    description:
      - List of Network definition configurations to manage.
      - Each element defines a Network with identity, template, VLAN/SVI,
        routing, TRM, security, attachment, deployment, and other settings.
      - On standalone fabrics, all Network definition, attachment, and deployment
        options are applied directly to the target fabric.
      - For parent fabrics each item may include a C(child_fabric_config)
        list to provide per-child-fabric overrides. The parent-level
        C(attach), C(deploy), and C(deploy_type) options are applied only on
        the parent fabric and are not sent to child fabrics.
      - For child fabrics targeted directly, only C(state=gathered) is supported.
    type: list
    elements: dict
    required: false
    suboptions:
      network_name:
        description:
          - Name of the Network.
          - Use either C(network_name) or compatibility alias C(net_name).
        type: str
      net_name:
        description:
          - Compatibility alias for C(network_name).
        type: str
      network_id:
        description:
          - L3 VNI or Network segment ID, 1-16777214.
          - Use either C(network_id) or compatibility alias C(net_id).
        type: int
      net_id:
        description:
          - Compatibility alias for C(network_id).
        type: int
      network_type:
        description:
          - Network schema type.
          - Leave unset to derive the value from the fabric C(management.type).
          - Set to V(userDefined) to use custom Network template fields.
        type: str
        choices:
          - userDefined
          - vxlan
          - vxlanIbgp
          - vxlanEbgp
          - vxlanCampus
          - aimlVxlanIbgp
          - aimlVxlanEbgp
          - classicLanEnhanced
          - vxlanAci
          - aci
          - externalConnectivity
          - vxlanExternal
      network_template_name:
        description:
          - Custom Network template name.
          - Supported only when C(network_type=userDefined).
        type: str
      network_extension_template_name:
        description:
          - Custom Network extension template name.
          - Supported only when C(network_type=userDefined).
        type: str
      service_network_template_name:
        description:
          - Custom service Network template name.
          - Supported only when C(network_type=userDefined).
        type: str
      network_template_config:
        description:
          - Custom Network template parameters.
          - Supported only when C(network_type=userDefined).
          - Values must be strings as required by the ND schema.
        type: dict
      default_security_action:
        description:
          - Default security group enforcement action.
          - Requires security group support to be enabled in fabric settings.
          - Supported on standalone and parent Network definitions.
        type: str
        choices:
          - unenforcedOrNone
          - enforcedPermit
          - enforcedDeny
      default_security_group_tag:
        description:
          - Default security group tag ID (16-65535).
          - Requires security group support to be enabled in fabric settings.
          - Supported on standalone and parent Network definitions.
        type: int
      vlan_id:
        description:
          - VLAN ID for the Network SVI (2-4094).
          - Not used when C(l3vni_wo_vlan=true).
          - Supported on standalone and parent Network definitions; child fabrics
            inherit the parent value and cannot override it through
            C(child_fabric_config).
        type: int
      network_vlan_name:
        description:
          - VLAN name for the Network SVI.
          - Supported on standalone and parent Network definitions.
        type: str
      network_intf_desc:
        description:
          - Description for the Network SVI interface.
          - Supported on standalone and parent Network definitions.
        type: str
      network_int_mtu:
        description:
          - MTU for the Network SVI interface (68-9216).
          - Supported on standalone and parent Network definitions.
        type: int
        default: 9216
      l3vni_wo_vlan:
        description:
          - Configure L3VNI without VLAN/SVI.
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: false
      network_description:
        description: Description of the Network (max 255 characters).
        type: str
      loopback_route_tag:
        description: Routing tag for loopback routes (0-4294967295).
        type: int
        default: 12345
      redist_direct_rmap:
        description: Route map for redistribute direct (IPv4).
        type: str
        default: FABRIC-RMAP-REDIST-SUBNET
      v6_redist_direct_rmap:
        description: Route map for redistribute direct (IPv6).
        type: str
        default: FABRIC-RMAP-REDIST-SUBNET
      max_bgp_paths:
        description: Maximum eBGP multipaths (1-64).
        type: int
        default: 1
      max_ibgp_paths:
        description: Maximum iBGP multipaths (1-64).
        type: int
        default: 2
      ipv6_linklocal_enable:
        description: Enable IPv6 link-local on Network SVI.
        type: bool
        default: true
      disable_rt_auto:
        description: Disable automatic route-target assignment.
        type: bool
        default: false
      import_vpn_rt:
        description:
          - VPN import route targets.
          - Supported on standalone and parent Network definitions.
        type: list
        elements: str
      export_vpn_rt:
        description:
          - VPN export route targets.
          - Supported on standalone and parent Network definitions.
        type: list
        elements: str
      import_evpn_rt:
        description:
          - EVPN import route targets.
          - Supported on standalone and parent Network definitions.
        type: list
        elements: str
      export_evpn_rt:
        description:
          - EVPN export route targets.
          - Supported on standalone and parent Network definitions.
        type: list
        elements: str
      trm_enable:
        description:
          - Enable Tenant Routed Multicast.
          - Requires TRM support to be enabled in fabric settings.
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: false
      no_rp:
        description: No RP for TRM (SSM only). Requires C(trm_enable=true).
        type: bool
        default: false
      rp_external:
        description: RP is external to the fabric. Requires C(trm_enable=true).
        type: bool
        default: false
      rp_address:
        description: IPv4 RP address. Requires C(trm_enable=true).
        type: str
      rp_loopback_id:
        description: Loopback interface ID for RP (0-1023). Requires C(trm_enable=true).
        type: int
      underlay_mcast_ip:
        description: Underlay IPv4 multicast address. Requires C(trm_enable=true).
        type: str
      overlay_mcast_group:
        description: Overlay multicast group (224.0.0.0/4 range). Requires C(trm_enable=true).
        type: str
      trm_bgw_msite:
        description: Enable TRM on border gateway multisite. Requires C(trm_enable=true).
        type: bool
        default: false
      import_mvpn_rt:
        description: MVPN import route targets. Requires C(trm_enable=true).
        type: list
        elements: str
      export_mvpn_rt:
        description: MVPN export route targets. Requires C(trm_enable=true).
        type: list
        elements: str
      adv_host_routes:
        description:
          - Advertise /32 and /128 host routes to edge routers.
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: false
      adv_default_routes:
        description:
          - Advertise default route internally.
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: true
      static_default_route:
        description:
          - Configure static default route.
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: true
      bgp_password:
        description:
          - BGP neighbour password (4-32 characters).
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: str
      bgp_passwd_encrypt:
        description:
          - BGP password encryption type, 3 (3DES) or 7 (Cisco Type-7).
          - Required when C(bgp_password) is set.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: int
        choices: [ 3, 7 ]
      netflow_enable:
        description:
          - Enable netflow for the Network fabric data.
          - Requires netflow support to be enabled in fabric settings.
          - Supported on standalone and parent Network definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: false
      nf_monitor:
        description:
          - Netflow monitor name.
          - Required when C(netflow_enable=true).
          - May also be overridden per child fabric under C(child_fabric_config).
        type: str
      deploy:
        description:
          - Deploy pending Network attachment changes for this Network.
          - For parent fabrics, deployment is performed once after all child
            fabric tasks complete.
          - Applies only to parent/standalone Network attachments, not child fabric
            override entries.
          - For C(state=deleted), the C(deploy) value is ignored; the module
            detaches existing attachments, deploys the detach using
            C(deploy_type), and then removes the Network.
        type: bool
        default: true
      deploy_type:
        description:
          - Scope of the deploy operation when C(deploy=true).
          - C(switch) deploys only the switches affected by this Network attachment
            operation when switch identifiers are available.
          - C(network) deploys the pending Network changes for this Network.
        type: str
        default: switch
        choices:
          - switch
          - network
      attach:
        description:
          - Parent/standalone switch attachment entries for this Network.
          - Switches are identified by management IP address and resolved to
            ND C(switchId) values before the attachment payload is sent.
          - Existing C(ports) and C(deploy) attachment fields are accepted by
            the argument spec.
          - C(tor_ports) is recognized for compatibility but rejected during
            validation because the Network attachment API does not expose a TOR
            attachment field.
          - API-shaped C(interfaces) entries are also accepted.
          - If C(attach) entries are present, the module attaches the Network to
            those switches.
          - In C(state=replaced), omitting C(attach) deattaches existing
            attachments for the matching Network.
          - In C(state=overridden), attachments not specified in the desired
            configuration are deattached.
          - Not supported under C(child_fabric_config).
        type: list
        elements: dict
        suboptions:
          ip_address:
            description: Management IP address of the switch to attach or detach.
            type: str
            required: true
          ports:
            description:
              - Compatibility attachment interface list.
              - Each entry is converted to an access-mode interface entry.
            type: list
            elements: str
          deploy:
            description:
              - Per-attachment compatibility deploy flag.
              - Network-level C(deploy) controls deployment behavior.
            type: bool
            default: true
          tor_ports:
            description:
              - Compatibility TOR attachment entries.
              - This is recognized but not supported by the Network attachment
                API and fails validation if provided.
            type: list
            elements: dict
            suboptions:
              ip_address:
                description: Management IP address of the TOR switch.
                type: str
                required: true
              ports:
                description: TOR switch interfaces.
                type: list
                elements: str
          interfaces:
            description:
              - API-shaped interface attachment entries.
            type: list
            elements: dict
            suboptions:
              mode:
                description: Interface mode.
                type: str
                choices:
                  - access
                  - dot1qTunnel
                  - trunk
                  - promiscuous
                  - trunkPromiscuous
                  - host
                  - trunkSecondary
              interface_range:
                description: Interface or interface range.
                type: str
              interface_group_name:
                description: Interface group name.
                type: str
              native_vlan:
                description: Whether this is a native VLAN attachment.
                type: bool
              mapping_type:
                description: VLAN mapping type.
                type: str
                choices:
                  - none
                  - single
              customer_vlan:
                description: Customer VLAN when C(mapping_type=single).
                type: int
          vlan_id:
            description: Attachment VLAN ID.
            type: int
          attachment_options:
            description:
              - Switch-specific attachment options.
              - These values are translated to Manage API C(instanceValues).
            type: dict
          extra_config:
            description: Raw Manage attachment extra config.
            type: str
      child_fabric_config:
        description:
          - Per-child-fabric override entries for MSD and MCFG parent fabrics.
          - Each entry targets a child member fabric and may override
            TRM, advertising, BGP auth, netflow, and MVPN route-target settings.
          - Omitted fields inherit the parent Network setting.
          - C(attach), C(deploy), C(deploy_type), VLAN/SVI fields, Network
            identity, custom template fields, and security group fields are not
            valid inside C(child_fabric_config).
          - Ignored when C(state=deleted); child fabric tasks are not executed
            for delete operations.
        type: list
        elements: dict
        suboptions:
          fabric:
            description: Name of the child fabric.
            type: str
            required: true
          l3vni_wo_vlan:
            description: Enable L3VNI without VLAN on this child fabric.
            type: bool
          trm_enable:
            description: Enable Tenant Routed Multicast on this child fabric.
            type: bool
          no_rp:
            description: No RP, SSM only. Requires C(trm_enable=true).
            type: bool
          rp_external:
            description: RP is external to the child fabric. Requires C(trm_enable=true).
            type: bool
          rp_address:
            description: IPv4 RP address. Requires C(trm_enable=true).
            type: str
          rp_loopback_id:
            description: Loopback ID for RP (0-1023). Requires C(trm_enable=true).
            type: int
          underlay_mcast_ip:
            description: Underlay IPv4 multicast address. Requires C(trm_enable=true).
            type: str
          overlay_mcast_group:
            description: Overlay multicast group (224.0.0.0/4 range). Requires C(trm_enable=true).
            type: str
          trm_bgw_msite:
            description: Enable TRM on border gateway multisite. Requires C(trm_enable=true).
            type: bool
          import_mvpn_rt:
            description: MVPN import route targets. Requires C(trm_enable=true).
            type: list
            elements: str
          export_mvpn_rt:
            description: MVPN export route targets. Requires C(trm_enable=true).
            type: list
            elements: str
          adv_host_routes:
            description: Advertise /32 and /128 host routes.
            type: bool
          adv_default_routes:
            description: Advertise default route internally.
            type: bool
          static_default_route:
            description: Configure static default route.
            type: bool
          bgp_password:
            description: BGP neighbour password (4-32 characters).
            type: str
          bgp_passwd_encrypt:
            description: BGP password encryption type.
            type: int
            choices: [ 3, 7 ]
          netflow_enable:
            description: Enable netflow on this child fabric.
            type: bool
          nf_monitor:
            description: Netflow monitor name.
            type: str
extends_documentation_fragment:
  - cisco.nd.modules
  - cisco.nd.check_mode
"""

EXAMPLES = r"""
# ── Standalone fabric — create a Network and attach it to a switch ───────────────
- name: Create Network on standalone fabric and deploy by switch
  cisco.nd.nd_manage_networks:
    fabric: fab1
    state: merged
    config:
      - network_name: Network_BLUE
        network_id: 50010
        vlan_id: 2001
        network_vlan_name: Network_BLUE_VLAN
        network_intf_desc: Network BLUE SVI
        network_description: Blue application Network
        import_vpn_rt:
          - "65000:50010"
        export_vpn_rt:
          - "65000:50010"
        import_evpn_rt:
          - "65000:50010"
        export_evpn_rt:
          - "65000:50010"
        attach:
          - ip_address: 192.0.2.10
            loopback_id: 101
            loopback_ipv4_address: 10.255.101.1
            import_vpn_rt:
              - "65000:50110"
            export_vpn_rt:
              - "65000:50110"
            import_evpn_rt:
              - "65000:50110"
            export_evpn_rt:
              - "65000:50110"
        deploy: true
        deploy_type: switch

# ── Standalone fabric — create Network with TRM ──────────────────────────────────
- name: Create Network with Tenant Routed Multicast enabled
  cisco.nd.nd_manage_networks:
    fabric: fab1
    state: merged
    config:
      - network_name: Network_MCAST
        network_id: 50020
        vlan_id: 2002
        trm_enable: true
        rp_address: 10.254.254.1
        rp_loopback_id: 100
        underlay_mcast_ip: 239.1.1.1
        overlay_mcast_group: 239.1.1.2

# ── Standalone fabric — create user-defined Network template payload ─────────────
- name: Create user-defined Network
  cisco.nd.nd_manage_networks:
    fabric: fab1
    state: merged
    config:
      - network_name: Network_CUSTOM
        network_type: userDefined
        network_template_name: Custom_Network_Template
        network_extension_template_name: Custom_Network_Extension_Template
        service_network_template_name: Custom_Service_Network_Template
        network_template_config:
          Network_NAME: Network_CUSTOM
          Network_ID: "50030"

# ── MSD parent fabric — create Network with child fabric-instance overrides ──────
- name: Create Network on MSD parent with per-child fabric-instance overrides
  cisco.nd.nd_manage_networks:
    fabric: msd_parent
    state: merged
    config:
      - network_name: Network_BLUE
        network_id: 50010
        vlan_id: 2001
        network_vlan_name: Network_BLUE_VLAN
        adv_host_routes: true
        adv_default_routes: false
        static_default_route: false
        bgp_password: abcdef12
        bgp_passwd_encrypt: 3
        attach:
          - ip_address: 192.0.2.10
            loopback_id: 101
            loopback_ipv4_address: 10.255.101.1
            loopback_ipv6_address: 2001:db8:101::1
        deploy: true
        deploy_type: network
        child_fabric_config:
          - fabric: child_fabric_1
            l3vni_wo_vlan: false
            adv_host_routes: true
          - fabric: child_fabric_2
            adv_default_routes: false
            static_default_route: false
            bgp_password: abcdef12
            bgp_passwd_encrypt: 3

# ── MCFG parent fabric — create Network with child fabric-instance overrides ─────
- name: Create Network on MCFG parent with child fabric overrides
  cisco.nd.nd_manage_networks:
    fabric: mcfg_parent
    state: merged
    config:
      - network_name: Network_GREEN
        network_id: 50040
        vlan_id: 2040
        loopback_route_tag: 12345
        max_bgp_paths: 4
        max_ibgp_paths: 4
        ipv6_linklocal_enable: true
        disable_rt_auto: true
        import_vpn_rt:
          - "65000:50040"
        export_vpn_rt:
          - "65000:50040"
        child_fabric_config:
          - fabric: cluster_child_1
            adv_host_routes: true
            netflow_enable: true
            nf_monitor: MON1

# ── Child fabric — gathered only ────────────────────────────────────────────────
- name: Gathered Networks on a child fabric (write ops must go through parent)
  cisco.nd.nd_manage_networks:
    fabric: child_fabric_1
    state: gathered
    config: []

# ── Delete Networks ──────────────────────────────────────────────────────────────
- name: Delete a Network
  cisco.nd.nd_manage_networks:
    fabric: fab1
    state: deleted
    config:
      - network_name: Network_BLUE

# ── Replace Network configuration ───────────────────────────────────────────────
- name: Replace Network configuration (full replace)
  cisco.nd.nd_manage_networks:
    fabric: fab1
    state: replaced
    config:
      - network_name: Network_BLUE
        network_id: 50010
        vlan_id: 2001
        network_description: "Updated Blue Network"
        max_bgp_paths: 4
        max_ibgp_paths: 4
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec, NDModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_fabric_resolver import (
    NetworkFabricResolver,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import (
    NetworkWorkflowCoordinator,
)

# ---------------------------------------------------------------------------
# Argument-spec helpers
# ---------------------------------------------------------------------------


def network_base_argument_spec():
    """Re-exported for backward compatibility. Defined in network_argument_specs."""
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
        network_base_argument_spec as _impl,
    )

    return _impl()


def _child_fabric_config_element_spec():
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
        _child_fabric_config_element_spec as _impl,
    )

    return _impl()


def network_parent_argument_spec():
    """Re-exported for backward compatibility. Defined in network_argument_specs."""
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_argument_specs import (
        network_parent_argument_spec as _impl,
    )

    return _impl()


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        fabric=dict(type="str", required=True),
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "overridden", "deleted", "gathered", "query"],
        ),
        deploy_type=dict(
            type="str",
            default="switch",
            choices=["switch", "network", "resource"],
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

    try:
        fabric_name: str = module.params["fabric"]

        # Resolve the Network strategy from the ND API
        nd_module = NDModule(module)
        resolver = NetworkFabricResolver(
            nd_module=nd_module,
            fabric_name=fabric_name,
        )
        strategy = resolver.resolve()

        # Run the workflow coordinator for the resolved strategy
        coordinator = NetworkWorkflowCoordinator(
            module=module,
            strategy=strategy,
        )
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
