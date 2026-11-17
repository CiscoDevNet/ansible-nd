# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)


"""
Argument-spec helpers for nd_manage_vrfs.py.

Defined in module_utils (not in plugins/modules/nd_manage_vrfs.py) so that strategy
files can import them at the top level without creating a circular dependency
(nd_manage_vrfs.py → strategies → nd_manage_vrfs.py).
"""

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.enums import (
    DpuAffinity,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import PARENT_CHILD_ONLY_VRF_FIELDS


def _route_target_spec():
    """Argument spec fragment for a route-target list field."""
    return dict(type="list", elements="str")


def _trm_fields_spec(defaults=True):
    """TRM-related fields. When defaults=True, booleans default to False."""
    if defaults:
        return dict(
            trm_enable=dict(type="bool"),
            no_rp=dict(type="bool"),
            rp_external=dict(type="bool"),
            rp_address=dict(type="str"),
            rp_loopback_id=dict(type="int"),
            underlay_mcast_ip=dict(type="str"),
            overlay_mcast_group=dict(type="str"),
            trm_bgw_msite=dict(type="bool"),
            import_mvpn_rt=_route_target_spec(),
            export_mvpn_rt=_route_target_spec(),
        )
    # Child overrides — all optional, no defaults
    return dict(
        trm_enable=dict(type="bool"),
        no_rp=dict(type="bool"),
        rp_external=dict(type="bool"),
        rp_address=dict(type="str"),
        rp_loopback_id=dict(type="int"),
        underlay_mcast_ip=dict(type="str"),
        overlay_mcast_group=dict(type="str"),
        trm_bgw_msite=dict(type="bool"),
        import_mvpn_rt=_route_target_spec(),
        export_mvpn_rt=_route_target_spec(),
    )


def _attachment_options_spec():
    """Argument spec for one entry's attachment_options."""
    return dict(
        dpu_secure=dict(type="bool"),
        dpu_affinity=dict(type="str", choices=DpuAffinity.choices()),
        loopback_id=dict(type="int"),
        loopback_ipv4_address=dict(type="str"),
        loopback_ipv6_address=dict(type="str"),
        import_vpn_rt=_route_target_spec(),
        export_vpn_rt=_route_target_spec(),
        import_evpn_rt=_route_target_spec(),
        export_evpn_rt=_route_target_spec(),
    )


def _attachment_spec():
    """Argument spec for one entry inside attach."""
    return dict(
        ip_address=dict(type="str", required=True),
        freeform_config=dict(type="str"),
        attachment_options=dict(
            type="dict",
            options=_attachment_options_spec(),
        ),
    )


def vrf_base_argument_spec():
    """Argument spec for a single VRF config entry (standalone fabrics)."""
    spec = dict(
        # Identity
        vrf_name=dict(type="str", required=True),
        vrf_id=dict(type="int"),
        # Custom/user-defined VRF template fields
        vrf_template_name=dict(type="str"),
        vrf_extension_template_name=dict(type="str"),
        service_vrf_template_name=dict(type="str"),
        vrf_template_config=dict(type="dict"),
        # Security group
        default_security_action=dict(
            type="str",
            choices=["unenforcedOrNone", "enforcedPermit", "enforcedDeny"],
        ),
        default_security_group_tag=dict(type="int"),
        # VLAN / SVI
        vlan_id=dict(type="int"),
        vrf_vlan_name=dict(type="str"),
        vrf_intf_desc=dict(type="str"),
        vrf_int_mtu=dict(type="int"),
        l3vni_wo_vlan=dict(type="bool"),
        # Description
        vrf_description=dict(type="str"),
        # Routing
        loopback_route_tag=dict(type="int"),
        redist_direct_rmap=dict(type="str"),
        v6_redist_direct_rmap=dict(type="str"),
        max_bgp_paths=dict(type="int"),
        max_ibgp_paths=dict(type="int"),
        ipv6_linklocal_enable=dict(type="bool"),
        # Route targets
        disable_rt_auto=dict(type="bool"),
        import_vpn_rt=_route_target_spec(),
        export_vpn_rt=_route_target_spec(),
        import_evpn_rt=_route_target_spec(),
        export_evpn_rt=_route_target_spec(),
        # Advertising
        adv_host_routes=dict(type="bool"),
        adv_default_routes=dict(type="bool"),
        static_default_route=dict(type="bool"),
        # BGP authentication
        bgp_password=dict(type="str", no_log=True),
        bgp_passwd_encrypt=dict(type="str", choices=["3des", "type6", "type7"]),
        # Netflow
        netflow_enable=dict(type="bool"),
        nf_monitor=dict(type="str"),
        # Attachment/deploy controls
        deploy=dict(type="bool", default=True),
        deploy_type=dict(type="str", default="switch", choices=["switch", "vrf"]),
        attach=dict(
            type="list",
            elements="dict",
            options=_attachment_spec(),
        ),
    )
    spec.update(_trm_fields_spec(defaults=True))
    return spec


def vrf_standalone_argument_spec():
    """VRF fields verified for direct standalone fabric operations."""
    spec = vrf_base_argument_spec()
    spec.update(
        bgp_best_path_relax=dict(type="bool"),
        bgp_log_neighbor_change=dict(type="bool"),
        route_distinguisher_id=dict(type="int"),
        enable_vrf_vpn_route_leaking=dict(type="bool"),
        bgp_allow_as_in=dict(type="bool"),
        bgp_allow_as_in_num=dict(type="int"),
        bgp_as_override=dict(type="bool"),
        bgp_disable_peer_as_check=dict(type="bool"),
        bgp_soft_reconfig_always=dict(type="bool"),
        ipv6_trm=dict(type="bool"),
        v6_no_rp=dict(type="bool"),
        v6_rp_external=dict(type="bool"),
        v6_rp_address=dict(type="str"),
        v6_overlay_mcast_group=dict(type="str"),
        mvpn_inter_as=dict(type="bool"),
    )
    return spec


def _child_fabric_config_element_spec():
    """Argument spec for one entry inside child_fabric_config."""
    spec = dict(
        # Identity (required)
        fabric_name=dict(type="str", required=True),
        # L3VNI without VLAN
        l3vni_wo_vlan=dict(type="bool"),
        bgp_best_path_relax=dict(type="bool"),
        enable_vrf_vpn_route_leaking=dict(type="bool"),
        bgp_log_neighbor_change=dict(type="bool"),
        # Advertising overrides
        adv_host_routes=dict(type="bool"),
        adv_default_routes=dict(type="bool"),
        static_default_route=dict(type="bool"),
        # BGP authentication overrides
        bgp_password=dict(type="str", no_log=True),
        bgp_passwd_encrypt=dict(type="str", choices=["3des", "type6", "type7"]),
        bgp_allow_as_in=dict(type="bool"),
        bgp_allow_as_in_num=dict(type="int"),
        bgp_as_override=dict(type="bool"),
        bgp_disable_peer_as_check=dict(type="bool"),
        bgp_soft_reconfig_always=dict(type="bool"),
        # Netflow overrides
        netflow_enable=dict(type="bool"),
        nf_monitor=dict(type="str"),
        ipv6_trm=dict(type="bool"),
        v6_no_rp=dict(type="bool"),
        v6_rp_external=dict(type="bool"),
        v6_rp_address=dict(type="str"),
        v6_overlay_mcast_group=dict(type="str"),
        mvpn_inter_as=dict(type="bool"),
    )
    spec.update(_trm_fields_spec(defaults=False))
    return spec


def vrf_parent_argument_spec():
    """Argument spec for a VRF config entry on parent (MSD / MFD) fabrics."""
    spec = vrf_base_argument_spec()
    for field in PARENT_CHILD_ONLY_VRF_FIELDS:
        spec.pop(field, None)
    spec["route_distinguisher_id"] = dict(type="int")
    spec["child_fabric_config"] = dict(
        type="list",
        elements="dict",
        options=_child_fabric_config_element_spec(),
    )
    return spec
