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
      - V(_staged) is an internal/private workflow state. It follows
        V(overridden) attachment handling, suppresses deployment, and does not
        remove omitted VRF definitions.
    type: str
    choices: [ merged, replaced, overridden, deleted, gathered, _staged ]
    default: merged
  config:
    description:
      - List of VRF definition configurations to manage.
      - Each element defines a VRF with identity, template, VLAN/SVI,
        routing, TRM, security, attachment, deployment, and other settings.
      - On standalone fabrics, all VRF definition, attachment, and deployment
        options are applied directly to the target fabric.
      - For parent fabrics each item may include a C(child_fabric_config)
        list to provide per-child-fabric overrides. The parent-level
        C(attach), C(deploy), and C(deploy_type) options are applied only on
        the parent fabric and are not sent to child fabrics.
      - For child fabrics targeted directly, only C(state=gathered) is supported.
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
      vrf_type:
        description:
          - VRF schema type.
          - Leave unset to derive the value from the fabric C(management.type).
          - Set to V(userDefined) to use custom VRF template fields.
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
      vrf_template_name:
        description:
          - Custom VRF template name.
          - Supported only when C(vrf_type=userDefined).
        type: str
      vrf_extension_template_name:
        description:
          - Custom VRF extension template name.
          - Supported only when C(vrf_type=userDefined).
        type: str
      service_vrf_template_name:
        description:
          - Custom service VRF template name.
          - Supported only when C(vrf_type=userDefined).
        type: str
      vrf_template_config:
        description:
          - Custom VRF template parameters.
          - Supported only when C(vrf_type=userDefined).
          - Values must be strings as required by the ND schema.
        type: dict
      default_security_action:
        description:
          - Default security group enforcement action.
          - Requires security group support to be enabled in fabric settings.
          - Supported on standalone and parent VRF definitions.
        type: str
        choices:
          - unenforcedOrNone
          - enforcedPermit
          - enforcedDeny
      default_security_group_tag:
        description:
          - Default security group tag ID (16-65535).
          - Requires security group support to be enabled in fabric settings.
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
          - Supported on standalone and parent VRF definitions.
        type: int
        default: 9216
      l3vni_wo_vlan:
        description:
          - Configure L3VNI without VLAN/SVI.
          - Supported on standalone and parent VRF definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: false
      vrf_description:
        description: Description of the VRF (max 255 characters).
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
        description: Enable IPv6 link-local on VRF SVI.
        type: bool
        default: true
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
          - Supported on standalone and parent VRF definitions.
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
          - Supported on standalone and parent VRF definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: false
      adv_default_routes:
        description:
          - Advertise default route internally.
          - Supported on standalone and parent VRF definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: true
      static_default_route:
        description:
          - Configure static default route.
          - Supported on standalone and parent VRF definitions.
          - May also be overridden per child fabric under C(child_fabric_config).
        type: bool
        default: true
      bgp_password:
        description:
          - BGP neighbour password (4-32 characters).
          - Supported on standalone and parent VRF definitions.
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
          - Enable netflow for the VRF fabric data.
          - Requires netflow support to be enabled in fabric settings.
          - Supported on standalone and parent VRF definitions.
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
          - Switches are identified by management IP address and resolved to
            ND C(switchId) values before the attachment payload is sent.
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
              - These fields are translated to the Manage API
                C(instanceValues) payload internally.
            type: dict
            suboptions:
              dpu_secure:
                description:
                  - Enable DPU secure mode for this attachment.
                  - Translated to C(instanceValues.dpuSecure) in the Manage API
                    payload.
                type: bool
              dpu_affinity:
                description:
                  - DPU affinity for this attachment.
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
            TRM, advertising, BGP auth, netflow, and MVPN route-target settings.
          - Omitted fields inherit the parent VRF setting.
          - C(attach), C(deploy), C(deploy_type), VLAN/SVI fields, VRF
            identity, custom template fields, and security group fields are not
            valid inside C(child_fabric_config).
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
# ── Standalone fabric — create a VRF and attach it to a switch ───────────────
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

# ── Standalone fabric — create VRF with TRM ──────────────────────────────────
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

# ── Standalone fabric — create user-defined VRF template payload ─────────────
- name: Create user-defined VRF
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: merged
    config:
      - vrf_name: VRF_CUSTOM
        vrf_type: userDefined
        vrf_template_name: Custom_VRF_Template
        vrf_extension_template_name: Custom_VRF_Extension_Template
        service_vrf_template_name: Custom_Service_VRF_Template
        vrf_template_config:
          VRF_NAME: VRF_CUSTOM
          VRF_ID: "50030"

# ── MSD parent fabric — create VRF with child fabric-instance overrides ──────
- name: Create VRF on MSD parent with per-child fabric-instance overrides
  cisco.nd.nd_manage_vrfs:
    fabric_name: msd_parent
    state: merged
    config:
      - vrf_name: VRF_BLUE
        vrf_id: 50010
        vlan_id: 2001
        vrf_vlan_name: VRF_BLUE_VLAN
        adv_host_routes: true
        adv_default_routes: false
        static_default_route: false
        bgp_password: abcdef12
        bgp_passwd_encrypt: 3
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
            bgp_passwd_encrypt: 3

# ── MCFG parent fabric — create VRF with child fabric-instance overrides ─────
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

# ── Child fabric — gathered only ────────────────────────────────────────────────
- name: Gathered VRFs on a child fabric (write ops must go through parent)
  cisco.nd.nd_manage_vrfs:
    fabric_name: child_fabric_1
    state: gathered
    config: []

# ── Delete VRFs ──────────────────────────────────────────────────────────────
- name: Delete a VRF
  cisco.nd.nd_manage_vrfs:
    fabric_name: fab1
    state: deleted
    config:
      - vrf_name: VRF_BLUE

# ── Replace VRF configuration ───────────────────────────────────────────────
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
"""

RETURN = r"""
changed:
  description: Whether the module changed VRF, attachment, or deployment state.
  returned: always
  type: bool
before:
  description: VRF configuration present on ND before the operation.
  returned: always
  type: list
  elements: dict
after:
  description: VRF configuration present on ND after the operation.
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
      result.
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
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import (
    VrfWorkflowCoordinator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    vrf_parent_argument_spec,
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
            choices=["merged", "replaced", "overridden", "deleted", "gathered", "_staged"],
        ),
        config=dict(
            type="list",
            elements="dict",
            required=True,
            options=vrf_parent_argument_spec(),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    try:
        coordinator = VrfWorkflowCoordinator(module=module)
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
