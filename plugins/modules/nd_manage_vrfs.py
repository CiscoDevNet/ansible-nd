#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nd_manage_vrfs
version_added: "2.0.0"
short_description: Manages VRF definitions on Cisco Nexus Dashboard.
description:
  - Manages VRF definitions on Cisco Nexus Dashboard across standalone,
    Multisite (MSD), and Multicluster (MCFG) fabric topologies.
  - This module manages VRF definitions, parent or standalone VRF switch
    attachments, and optional deployment of pending VRF changes.
  - Supported VRF definition properties include identity, custom templates,
    VLAN/SVI, security group defaults, TRM, routing, netflow, and route targets.
  - Automatically detects fabric type from the ND API and routes to the
    appropriate workflow without requiring extra user input.
  - For parent fabrics (MSD / MCFG), supports child-fabric coordination
    via the C(child_fabric_config) parameter inside each VRF definition.
  - Child fabrics only permit C(state=gathered) when targeted directly;
    all write operations must be driven through the parent fabric.
author:
  - Akshayanat C S (@achengam)
options:
  fabric_name:
    description:
      - Name of the fabric to operate on.
      - The module auto-detects whether this is a standalone, parent,
        or child fabric and routes accordingly.
    type: str
    required: true
  state:
    description:
      - Desired state of the VRF resources.
      - V(merged) creates or updates VRFs that do not match the desired config.
      - V(replaced) replaces existing VRFs that match the desired config.
      - V(overridden) replaces all VRFs; removes any not in config.
      - V(deleted) removes specified VRFs (or all if config is empty).
      - V(gathered) returns current VRF state (the only state allowed on child
        fabrics when targeted directly).
      - V(staged) uses V(replaced) definition semantics for listed VRFs, so
        omitted definition properties can be reset to their defaults.
      - V(staged) uses fabric-wide V(overridden) attachment scope. Attachments
        not present in the desired config are detached, but VRF definitions are
        retained.
      - V(staged) always skips deployment. Item-level C(deploy=true) is ignored;
        deploy staged changes later with a deployment workflow.
      - V(staged) with C(config=[]) stages detachment of every current VRF
        attachment while retaining all VRF definitions.
    type: str
    choices: [ merged, replaced, overridden, deleted, gathered, staged ]
    default: merged
  config:
    description:
      - List of VRF definition configurations to manage.
      - Each element defines a VRF with identity, template, VLAN/SVI,
        routing, TRM, security, attachment, deployment, and other settings.
      - On standalone fabrics, all VRF definition, attachment, and deployment
        options are applied directly to the target fabric.
      - On standalone fabrics, custom-template VRFs accept identity, VLAN ID,
        security defaults, template parameters, and attachment/deployment controls;
        standard VXLAN core and fabric-instance options are not applicable.
      - For parent fabrics each item may include a C(child_fabric_config)
        list to provide per-child-fabric overrides. The parent-level
        C(attach), C(deploy), and C(deploy_type) options are applied only on
        the parent fabric and are not sent to child fabrics.
      - For child fabrics targeted directly, only C(state=gathered) is supported.
      - External Connectivity and VXLAN External fabrics support VRF definitions
        with C(vrf_name) and optional C(vrf_description) only. Attachments and
        VXLAN-specific properties are not supported.
    type: list
    elements: dict
    required: true
    suboptions:
      vrf_name:
        description: Name of the VRF (max 94 characters).
        type: str
        required: true
      vrf_id:
        description: L3 VNI (VRF segment ID), 1-16777214.
        type: int
      vrf_template_name:
        description:
          - Custom VRF template name.
          - Supplying custom template fields makes the module use the user-defined VRF schema.
        type: str
      vrf_extension_template_name:
        description:
          - Custom VRF extension template name.
          - Supplying custom template fields makes the module use the user-defined VRF schema.
        type: str
      service_vrf_template_name:
        description:
          - Custom service VRF template name.
          - Supplying custom template fields makes the module use the user-defined VRF schema.
        type: str
      vrf_template_config:
        description:
          - Custom VRF template parameters.
          - Supplying custom template fields makes the module use the user-defined VRF schema.
          - Values must be strings as required by the ND schema.
        type: dict
      default_security_action:
        description:
          - Default security group enforcement action.
          - On standalone fabrics, enforced actions require fabric security groups; use C(unenforcedOrNone) otherwise.
          - On standalone VXLAN fabrics, ND allocates a tag when an enforced action is selected and C(default_security_group_tag) is omitted.
          - Supported on standalone and parent VRF definitions.
        type: str
        choices:
          - unenforcedOrNone
          - enforcedPermit
          - enforcedDeny
      default_security_group_tag:
        description:
          - Default security group tag ID (16-65535).
          - Optional for enforced actions on standalone VXLAN fabrics; ND allocates a tag when omitted.
          - Requires fabric security groups to be enabled and enforced when supplied.
          - Supported on standalone and parent VRF definitions.
        type: int
      vlan_id:
        description:
          - VLAN ID for the VRF SVI (2-4094).
          - Not used when C(l3vni_wo_vlan=true).
          - Supported on standalone and parent VRF definitions; child fabrics
            inherit the parent value and cannot override it through
            C(child_fabric_config).
        type: int
      vrf_vlan_name:
        description:
          - VLAN name for the VRF SVI.
          - Supported on standalone and parent VRF definitions.
        type: str
      vrf_intf_desc:
        description:
          - Description for the VRF SVI interface.
          - Supported on standalone and parent VRF definitions.
        type: str
      vrf_int_mtu:
        description:
          - MTU for the VRF SVI interface (68-9216).
          - Not applicable when C(l3vni_wo_vlan=true).
          - Supported on standalone and parent VRF definitions.
        type: int
        default: 9216
      l3vni_wo_vlan:
        description:
          - Configure L3VNI without VLAN/SVI.
          - When omitted on creation, uses the fabric's L3VNI without VLAN setting; an explicit value overrides it.
          - On existing VRFs, omission in C(merged) retains the current value; C(replaced), C(overridden), and C(staged) use the fabric default when available.
          - Campus requires N9000 -EX/-FX/-GX and NX-OS 10.3.1 or later.
          - Not applicable on parent fabrics.
        type: bool
      vrf_description:
        description: Description of the VRF (max 255 characters), including External VRF definitions.
        type: str
      loopback_route_tag:
        description: Routing tag for loopback routes (0-4294967295); NX-OS only.
        type: int
        default: 12345
      redist_direct_rmap:
        description: Route map for redistribute direct (IPv4).
        type: str
        default: FABRIC-RMAP-REDIST-SUBNET
      v6_redist_direct_rmap:
        description:
          - Route map for redistribute direct (IPv6).
          - On create or authoritative update, omission uses C(redist_direct_rmap).
          - A sparse C(merged) update retains an existing IPv6 map.
        type: str
      max_bgp_paths:
        description: Maximum eBGP multipaths (NX-OS 1-64; IOS-XE 1-32).
        type: int
        default: 1
      max_ibgp_paths:
        description: Maximum iBGP multipaths (NX-OS 1-64; IOS-XE 1-32).
        type: int
        default: 2
      ipv6_linklocal_enable:
        description: Enable IPv6 link-local on a VRF SVI; NX-OS only, not with C(l3vni_wo_vlan=true).
        type: bool
        default: true
      bgp_best_path_relax:
        description: Enable BGP best-path AS-path multipath-relax on standalone or child VRFs; NX-OS only.
        type: bool
        default: false
      bgp_log_neighbor_change:
        description: Log BGP neighbor up/down events on standalone or child VRFs.
        type: bool
        default: false
      route_distinguisher_id:
        description: VRF route distinguisher ID (0-65535) on IOS XE standalone and parent fabrics. If omitted, ND generates one.
        type: int
      enable_vrf_vpn_route_leaking:
        description: Enable bidirectional VRF-to-VPN route leaking on NX-OS border and border-gateway switches of a standalone or child fabric.
        type: bool
        default: false
      disable_rt_auto:
        description: Disable automatic route-target assignment.
        type: bool
        default: false
      import_vpn_rt:
        description:
          - VPN import route targets.
          - Supported on standalone and parent VRF definitions.
        type: list
        elements: str
      export_vpn_rt:
        description:
          - VPN export route targets.
          - Supported on standalone and parent VRF definitions.
        type: list
        elements: str
      import_evpn_rt:
        description:
          - EVPN import route targets.
          - Supported on standalone and parent VRF definitions.
        type: list
        elements: str
      export_evpn_rt:
        description:
          - EVPN export route targets.
          - Supported on standalone and parent VRF definitions.
        type: list
        elements: str
      trm_enable:
        description:
          - Enable Tenant Routed Multicast.
          - Requires TRM support to be enabled in fabric settings.
          - On standalone VRFs, an effective underlay multicast address is required; an internal RP also needs C(rp_address) and C(rp_loopback_id).
          - Not applicable on parent fabrics.
        type: bool
        default: false
      ipv6_trm:
        description:
          - Enable IPv6 Tenant Routed Multicast on a standalone VRF; NX-OS only.
          - Requires IPv6 Tenant Routed Multicast in the fabric settings.
          - An effective underlay multicast address is required; an internal IPv6 RP also needs C(v6_rp_address) and C(rp_loopback_id).
        type: bool
        default: false
      no_rp:
        description: No RP for TRM (SSM only). Requires C(trm_enable=true). Not applicable on parent fabrics.
        type: bool
        default: false
      rp_external:
        description: RP is external to the fabric. Requires C(trm_enable=true). Not applicable on parent fabrics.
        type: bool
        default: false
      rp_address:
        description: IPv4 RP address. Requires C(trm_enable=true). Not applicable on parent fabrics.
        type: str
      v6_no_rp:
        description: Use IPv6 SSM without an RP. Requires C(ipv6_trm=true); incompatible with IPv6 RP settings.
        type: bool
        default: false
      v6_rp_external:
        description: IPv6 RP is external to the fabric. Requires C(ipv6_trm=true); NX-OS only.
        type: bool
        default: false
      v6_rp_address:
        description: IPv6 RP address. Requires C(ipv6_trm=true); NX-OS only.
        type: str
      rp_loopback_id:
        description: Loopback interface ID for RP (0-1023). Requires IPv4 or IPv6 TRM. Not applicable on parent fabrics.
        type: int
      underlay_mcast_ip:
        description: Underlay IPv4 multicast address. Requires IPv4 or IPv6 TRM. Not applicable on parent fabrics.
        type: str
      overlay_mcast_group:
        description: Overlay multicast group (224.0.0.0/4 range). Requires C(trm_enable=true). Not applicable on parent fabrics.
        type: str
      v6_overlay_mcast_group:
        description: Overlay IPv6 multicast group/prefix in CIDR notation. Requires C(ipv6_trm=true); NX-OS only.
        type: str
      mvpn_inter_as:
        description: Use inter-AS MVPN routes when IPv4 or IPv6 TRM is enabled; IOS XE only.
        type: bool
        default: false
      trm_bgw_msite:
        description: Enable IPv4/IPv6 TRM on border gateway multisite. Requires IPv4 or IPv6 TRM. Not applicable on parent fabrics.
        type: bool
        default: false
      import_mvpn_rt:
        description: MVPN import route targets; requires IPv4 or IPv6 TRM and NX-OS. Not applicable on parent fabrics.
        type: list
        elements: str
      export_mvpn_rt:
        description: MVPN export route targets; requires IPv4 or IPv6 TRM and NX-OS. Not applicable on parent fabrics.
        type: list
        elements: str
      adv_host_routes:
        description:
          - Advertise /32 and /128 host routes to edge routers.
          - Not applicable on parent fabrics.
        type: bool
        default: false
      adv_default_routes:
        description:
          - Advertise default route internally.
          - Not applicable on parent fabrics.
        type: bool
        default: true
      static_default_route:
        description:
          - Configure static default route.
          - Not applicable on parent fabrics.
        type: bool
        default: true
      bgp_allow_as_in:
        description: Accept VRF Lite paths containing the local AS on standalone or child VRFs.
        type: bool
        default: false
      bgp_allow_as_in_num:
        description: Allowed local-AS occurrences in the VRF Lite AS path (1-10); requires C(bgp_allow_as_in=true) on a child VRF.
        type: int
        default: 3
      bgp_as_override:
        description: Override matching AS in outbound VRF Lite routes on standalone or child VRFs.
        type: bool
        default: false
      bgp_disable_peer_as_check:
        description: Disable peer-AS check on outbound VRF Lite routes on standalone or child VRFs; NX-OS only.
        type: bool
        default: false
      bgp_soft_reconfig_always:
        description: Always permit inbound BGP soft reconfiguration on standalone or child VRFs.
        type: bool
        default: false
      bgp_password:
        description:
          - VRF-Lite BGP neighbour password as a 4-32 character hexadecimal string.
          - Requires C(bgp_passwd_encrypt), or inherits the existing key type on a sparse standalone C(merged) update.
          - Not applicable on parent fabrics.
        type: str
      bgp_passwd_encrypt:
        description:
          - BGP password key type, C(3des), C(type6), or C(type7).
          - Requires C(bgp_password), or inherits the existing password on a sparse standalone C(merged) update.
          - Not applicable on parent fabrics.
        type: str
        choices: [3des, type6, type7]
      netflow_enable:
        description:
          - Enable VRF-Lite NetFlow; requires fabric and extension NetFlow enablement.
          - Not applicable on parent fabrics.
        type: bool
        default: false
      nf_monitor:
        description:
          - NX-OS NetFlow monitor; required when C(netflow_enable=true).
          - Not applicable on parent fabrics.
        type: str
      deploy:
        description:
          - Deploy pending VRF attachment changes for this VRF.
          - For parent fabrics, deployment is performed once after all child
            fabric tasks complete.
          - Applies only to parent/standalone VRF attachments, not child fabric
            override entries.
          - For C(state=deleted), the C(deploy) value is ignored; the module
            detaches existing attachments, deploys the detach using
            C(deploy_type), and then removes the VRF.
        type: bool
        default: true
      deploy_type:
        description:
          - Scope of the deploy operation when C(deploy=true).
          - C(switch) deploys only the switches affected by this VRF attachment
            operation when switch identifiers are available.
          - C(vrf) deploys the pending VRF changes for this VRF.
        type: str
        default: switch
        choices:
          - switch
          - vrf
      attach:
        description:
          - Parent/standalone switch attachment entries for this VRF.
          - Switches are identified by management IP address and resolved before
            attachment changes are applied.
          - If C(attach) entries are present, the module attaches the VRF to
            those switches.
          - In C(state=replaced), omitting C(attach) deattaches existing
            attachments for the matching VRF.
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
          freeform_config:
            description:
              - Additional free-form CLI configuration for this attachment.
            type: str
          attachment_options:
            description:
              - Attachment-specific options for this switch.
            type: dict
            suboptions:
              dpu_secure:
                description:
                  - Enable DPU secure mode for this attachment; smart switches only.
                type: bool
              dpu_affinity:
                description:
                  - DPU affinity for this attachment; smart switches only.
                type: str
                choices:
                  - dynamic
                  - dpu1
                  - dpu2
                  - dpu3
                  - dpu4
              loopback_id:
                description: Attachment loopback interface identifier, 0-1023.
                type: int
              loopback_ipv4_address:
                description: Attachment loopback IPv4 address.
                type: str
              loopback_ipv6_address:
                description: Attachment loopback IPv6 address.
                type: str
              import_vpn_rt:
                description: Attachment-level VPN import route targets.
                type: list
                elements: str
              export_vpn_rt:
                description: Attachment-level VPN export route targets.
                type: list
                elements: str
              import_evpn_rt:
                description: Attachment-level EVPN import route targets.
                type: list
                elements: str
              export_evpn_rt:
                description: Attachment-level EVPN export route targets.
                type: list
                elements: str
      child_fabric_config:
        description:
          - Per-child-fabric override entries for MSD and MCFG parent fabrics.
          - Each entry targets a child member fabric and may override
            editable Advanced toggles, IPv4/IPv6 TRM, MVPN route targets, and
            VRF Lite advertising, BGP, and NetFlow settings.
          - In C(state=merged), omitted fields retain the existing child VRF setting.
            C(state=replaced) and C(state=overridden) use authoritative state semantics.
          - VRF identity, security, VLAN/SVI and other General fields, Advanced
            text fields and IPv6 link-local, VPN/EVPN targets, RT auto-generation,
            templates, attachments, and deployment are parent-owned or locked.
          - Ignored when C(state=deleted); child fabric tasks are not executed
            for delete operations.
        type: list
        elements: dict
        suboptions:
          fabric_name:
            description: Name of the child fabric.
            type: str
            required: true
          l3vni_wo_vlan:
            description: Enable L3VNI without VLAN; Campus requires N9000 -EX/-FX/-GX and NX-OS 10.3.1 or later.
            type: bool
          bgp_best_path_relax:
            description: Enable BGP best-path AS-path multipath-relax; NX-OS only.
            type: bool
          enable_vrf_vpn_route_leaking:
            description: Enable bidirectional VRF-to-VPN route leaking on NX-OS border and border-gateway switches.
            type: bool
          bgp_log_neighbor_change:
            description: Log BGP neighbor up/down events.
            type: bool
          trm_enable:
            description: Enable IPv4 Tenant Routed Multicast on this child fabric. Requires the feature in child fabric settings.
            type: bool
          ipv6_trm:
            description: Enable IPv6 Tenant Routed Multicast on this child fabric; NX-OS only. Requires the feature in child fabric settings.
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
          v6_no_rp:
            description: Use IPv6 SSM without an RP. Requires C(ipv6_trm=true).
            type: bool
          v6_rp_external:
            description: IPv6 RP is external to the child fabric. Requires C(ipv6_trm=true).
            type: bool
          v6_rp_address:
            description: IPv6 RP address. Required for IPv6 TRM without SSM; NX-OS only.
            type: str
          rp_loopback_id:
            description: Loopback ID for an internal IPv4 or IPv6 RP (0-1023).
            type: int
          underlay_mcast_ip:
            description: Underlay IPv4 multicast address. Required for IPv4 or IPv6 TRM.
            type: str
          overlay_mcast_group:
            description: Overlay multicast group (224.0.0.0/4 range). Requires C(trm_enable=true).
            type: str
          v6_overlay_mcast_group:
            description: Overlay IPv6 multicast group/prefix in CIDR notation. Requires C(ipv6_trm=true); NX-OS only.
            type: str
          mvpn_inter_as:
            description: Use inter-AS MVPN routes when IPv4 or IPv6 TRM is enabled; IOS XE only.
            type: bool
          trm_bgw_msite:
            description: Enable IPv4/IPv6 TRM on border gateway multisite.
            type: bool
          import_mvpn_rt:
            description: MVPN import route targets; requires IPv4 or IPv6 TRM and NX-OS.
            type: list
            elements: str
          export_mvpn_rt:
            description: MVPN export route targets; requires IPv4 or IPv6 TRM and NX-OS.
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
            description: VRF-Lite BGP neighbour password as a 4-32 character hexadecimal string; requires C(bgp_passwd_encrypt).
            type: str
          bgp_passwd_encrypt:
            description: BGP password key type; requires C(bgp_password).
            type: str
            choices: [3des, type6, type7]
          bgp_allow_as_in:
            description: Accept VRF Lite paths containing the local AS.
            type: bool
          bgp_allow_as_in_num:
            description: Allowed local-AS occurrences in the VRF Lite AS path (1-10); requires C(bgp_allow_as_in=true).
            type: int
          bgp_as_override:
            description: Override matching AS in outbound VRF Lite routes.
            type: bool
          bgp_disable_peer_as_check:
            description: Disable peer-AS check on outbound VRF Lite routes; NX-OS only.
            type: bool
          bgp_soft_reconfig_always:
            description: Always permit inbound BGP soft reconfiguration.
            type: bool
          netflow_enable:
            description: Enable VRF-Lite NetFlow; requires child fabric and extension NetFlow enablement.
            type: bool
          nf_monitor:
            description: NX-OS NetFlow monitor; required when C(netflow_enable=true).
            type: str
extends_documentation_fragment:
  - cisco.nd.modules
  - cisco.nd.check_mode
"""

EXAMPLES = r"""
# Standalone fabric - create a VRF and attach it to a switch
- name: Create VRF on standalone fabric and deploy by switch
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: merged
    config:
      - vrf_name: VRF_BLUE
        vrf_id: 50010
        vlan_id: 2001
        vrf_vlan_name: VRF_BLUE_VLAN
        vrf_intf_desc: VRF BLUE SVI
        vrf_description: Blue application VRF
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
            freeform_config: |
              interface loopback101
                description VRF_BLUE attachment
            attachment_options:
              dpu_secure: false
              dpu_affinity: dynamic
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

# Standalone fabric - create VRF with TRM
- name: Create VRF with Tenant Routed Multicast enabled
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: merged
    config:
      - vrf_name: VRF_MCAST
        vrf_id: 50020
        vlan_id: 2002
        trm_enable: true
        rp_address: 10.254.254.1
        rp_loopback_id: 100
        underlay_mcast_ip: 239.1.1.1
        overlay_mcast_group: 239.1.1.2

# Standalone fabric - create user-defined VRF
- name: Create user-defined VRF
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: merged
    config:
      - vrf_name: VRF_CUSTOM
        vrf_template_name: Custom_VRF_Template
        vrf_extension_template_name: Custom_VRF_Extension_Template
        service_vrf_template_name: Custom_Service_VRF_Template
        vrf_template_config:
          VRF_NAME: VRF_CUSTOM
          VRF_ID: "50030"

# MSD parent fabric - create VRF with child fabric-instance overrides
- name: Create VRF on MSD parent with per-child fabric-instance overrides
  cisco.nd.nd_manage_vrfs:
    fabric_name: msd_parent
    state: merged
    config:
      - vrf_name: VRF_BLUE
        vrf_id: 50010
        vlan_id: 2001
        vrf_vlan_name: VRF_BLUE_VLAN
        attach:
          - ip_address: 192.0.2.10
            attachment_options:
              loopback_id: 101
              loopback_ipv4_address: 10.255.101.1
              loopback_ipv6_address: 2001:db8:101::1
        deploy: true
        deploy_type: vrf
        child_fabric_config:
          - fabric_name: child_fabric_1
            l3vni_wo_vlan: false
            adv_host_routes: true
          - fabric_name: child_fabric_2
            adv_default_routes: false
            static_default_route: false
            bgp_password: abcdef12
            bgp_passwd_encrypt: 3des

# MCFG parent fabric - create VRF with child fabric-instance overrides
- name: Create VRF on MCFG parent with child fabric overrides
  cisco.nd.nd_manage_vrfs:
    fabric_name: mcfg_parent
    state: merged
    config:
      - vrf_name: VRF_GREEN
        vrf_id: 50040
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
          - fabric_name: cluster_child_1
            adv_host_routes: true
            netflow_enable: true
            nf_monitor: MON1

# Child fabric - gathered only
- name: Gathered VRFs on a child fabric (write ops must go through parent)
  cisco.nd.nd_manage_vrfs:
    fabric_name: child_fabric_1
    state: gathered
    config: []

# Delete VRFs
- name: Delete a VRF
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: deleted
    config:
      - vrf_name: VRF_BLUE

# Replace VRF configuration
- name: Replace VRF configuration (full replace)
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: replaced
    config:
      - vrf_name: VRF_BLUE
        vrf_id: 50010
        vlan_id: 2001
        vrf_description: "Updated Blue VRF"
        max_bgp_paths: 4
        max_ibgp_paths: 4

# Override VRF configuration
- name: Override VRF configuration
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: overridden
    config:
      - vrf_name: VRF_BLUE
        vrf_id: 50010
        vlan_id: 2001

# ── Stage complete desired VRF attachments without deployment ───────────────
- name: Stage complete desired VRF attachments without deployment
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: staged
    config:
      - vrf_name: VRF_BLUE
        vrf_id: 50010
        vlan_id: 2001
        vrf_description: "Blue VRF"
        deploy: true
        attach:
          - ip_address: 192.0.2.10
      - vrf_name: VRF_GREEN
        vrf_id: 50011
        vlan_id: 2002
        vrf_description: "Green VRF"
        attach:
          - ip_address: 192.0.2.11
"""

RETURN = r"""
changed:
  description: Whether the module changed VRF, attachment, or deployment state.
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
    - VRF configuration present on ND before the operation.
    - Structured in the same user-facing form as O(config) where possible.
  returned: top-level for standalone and parent-only workflows; nested under parent_fabric and child_fabrics when child tasks run
  type: list
  elements: dict
  sample:
    - vrf_name: VRF_BLUE
      vrf_id: 50010
      vlan_id: 2001
after:
  description:
    - VRF configuration present on ND after the operation.
    - In check mode, the configuration that would result had the module run outside check mode.
  returned: top-level for standalone and parent-only workflows; nested under parent_fabric and child_fabrics when child tasks run
  type: list
  elements: dict
  sample:
    - vrf_name: VRF_BLUE
      vrf_id: 50010
      vlan_id: 2001
diff:
  description: Configuration diff calculated by the module.
  returned: when O(state) is not V(gathered)
  type: list
  elements: dict
  sample:
    - vrf_name: VRF_BLUE
      vlan_id: 2001
proposed:
  description: VRF configuration proposed by the module before reconciliation with the controller.
  returned: when O(output_level) is V(info) or V(debug), and on selected check-mode or failure paths.
  type: list
  elements: dict
  sample:
    - vrf_name: VRF_BLUE
      vrf_id: 50010
      vlan_id: 2001
gathered:
  description: VRF configuration returned by the controller in user-facing format.
  returned: when O(state) is V(gathered)
  type: list
  elements: dict
  sample:
    - vrf_name: VRF_BLUE
      vrf_id: 50010
      vlan_id: 2001
workflow_trace:
  description: Internal workflow trace entries collected by the VRF coordinator.
  returned: when O(output_level) is V(debug) or verbosity is 3 or higher
  type: list
  elements: dict
  sample:
    - event: standalone_workflow_start
      state: merged
msg:
  description: Human-readable status or failure message.
  returned: on failure and on selected no-op or child-fabric failure paths
  type: str
  sample: "Unexpected error: controller rejected VRF payload"
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
      result.
  returned: when a parent workflow processes one or more child fabrics
  type: dict
  sample:
    fabric_name: MSD_FABRIC
    changed: true
    before: []
    after: []
child_fabrics:
  description:
    - Per-child-fabric results for MSD or MCFG parent workflows.
    - Each entry contains the same state-machine and API trace fields as a
      standalone result, plus C(fabric_name).
  returned: when a parent workflow processes one or more child fabrics
  type: list
  elements: dict
  sample:
    - fabric_name: child_fabric_1
      changed: true
      before: []
      after: []
api_paths:
  description: REST API paths called by the module.
  returned: with verbosity C(-vv) or C(output_level=debug)
  type: list
  elements: str
  sample:
    - /api/v1/manage/fabrics/fab1/vrfs
api_verbs:
  description: REST API verbs called by the module.
  returned: with verbosity C(-vv) or C(output_level=debug)
  type: list
  elements: str
  sample:
    - POST
api_payload:
  description: REST request payloads sent to ND.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
  sample:
    - vrfs:
        - vrfName: VRF_BLUE
          vrfId: 50010
api_response:
  description: Raw normalized REST responses returned by ND.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
  sample:
    - RETURN_CODE: 200
      MESSAGE: OK
api_result:
  description: Response-handler result for each REST call.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
  sample:
    - success: true
      changed: true
api_diff:
  description: Per-REST-call diff data recorded by the result infrastructure.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
  sample:
    - vrfName: VRF_BLUE
api_metadata:
  description: Per-REST-call metadata recorded by the result infrastructure.
  returned: with verbosity C(-vvv) or C(output_level=debug)
  type: list
  elements: dict
  sample:
    - action: create
      state: merged
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    require_pydantic,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import (
    VrfWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    vrf_parent_argument_spec,
    vrf_standalone_argument_spec,
)

# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------


def main():
    argument_spec = nd_argument_spec()
    config_spec = vrf_parent_argument_spec()
    config_spec.update(vrf_standalone_argument_spec())
    argument_spec.update(
        fabric_name=dict(type="str", required=True),
        state=dict(
            type="str",
            default="merged",
            choices=[
                "merged",
                "replaced",
                "overridden",
                "deleted",
                "gathered",
                "staged",
            ],
        ),
        config=dict(
            type="list",
            elements="dict",
            required=True,
            options=config_spec,
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_vrfs")

    try:
        module_log.debug("main: starting VRF workflow")
        coordinator = VrfWorkflowCoordinator(module=module)
        result = coordinator.run()

        module_log.debug(
            "main: completed VRF workflow changed=%s failed=%s",
            result.get("changed"),
            result.get("failed"),
        )
        module.exit_json(**result)

    except NDStateMachineError as e:
        module.fail_json(msg=str(e))
    except NotImplementedError as e:
        module.fail_json(msg=f"Feature not yet implemented: {str(e)}")
    except Exception as e:
        module.fail_json(msg=f"Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()
