# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Argument-spec helpers for nd_manage_networks.py."""

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    MappingType,
    NetworkAttachmentMode,
    NetworkLayer,
)

NETWORK_TYPE_CHOICES = ["user_defined"]
VLAN_NETWORK_TYPE_CHOICES = [
    "normal",
    "primary",
    "community",
    "isolated",
]


def _dhcp_server_spec():
    return dict(
        server_address=dict(type="str", required=True),
        server_vrf=dict(type="str"),
    )


def _network_interface_spec():
    return dict(
        mode=dict(type="str", required=True, choices=NetworkAttachmentMode.choices()),
        interface_range=dict(type="str", required=True),
        interface_group_name=dict(type="str"),
        native_vlan=dict(type="bool", default=False),
        mapping_type=dict(type="str", choices=MappingType.choices()),
        customer_vlan=dict(type="int"),
    )


def _attachment_spec():
    return dict(
        ip_address=dict(type="str", required=True),
        vlan_id=dict(type="int"),
        interfaces=dict(type="list", elements="dict", default=[], options=_network_interface_spec()),
        deploy=dict(type="bool", default=True),
        attachment_options=dict(type="dict"),
        extra_config=dict(type="str"),
    )


def _shared_network_fields():
    return dict(
        network_id=dict(type="int"),
        net_id=dict(type="int"),
        vlan_id=dict(type="int"),
        vlan_name=dict(type="str"),
        gateway_ipv4_address=dict(type="str"),
        gw_ip_subnet=dict(type="str"),
        gateway_ipv6_address=dict(type="str"),
        gw_ipv6_subnet=dict(type="str"),
        secondary_gateway_ipv4_collection=dict(type="list", elements="str"),
        secondary_ip_gw1=dict(type="str"),
        secondary_ip_gw2=dict(type="str"),
        secondary_ip_gw3=dict(type="str"),
        secondary_ip_gw4=dict(type="str"),
        secondary_gateway_ipv6_collection=dict(type="list", elements="str"),
        vlan_intf_desc=dict(type="str"),
        int_desc=dict(type="str"),
        mtu=dict(type="int"),
        mtu_l3intf=dict(type="int"),
        arp_suppression=dict(type="bool"),
        arp_suppress=dict(type="bool"),
        routing_tag=dict(type="int"),
        dhcp_servers=dict(type="list", elements="dict", options=_dhcp_server_spec()),
        dhcp_srvr1_ip=dict(type="str"),
        dhcp_srvr1_vrf=dict(type="str"),
        dhcp_srvr2_ip=dict(type="str"),
        dhcp_srvr2_vrf=dict(type="str"),
        dhcp_srvr3_ip=dict(type="str"),
        dhcp_srvr3_vrf=dict(type="str"),
        loopback_id=dict(type="int"),
        dhcp_loopback_id=dict(type="int"),
        igmp_version=dict(type="int", choices=[1, 2, 3]),
        trm_enable=dict(type="bool"),
        ipv6_trm=dict(type="bool"),
        route_target_both=dict(type="bool"),
        l2_fabric_data=dict(type="dict"),
        stretch=dict(type="str"),
        enable_ir=dict(type="bool"),
        multicast_group_address=dict(type="str"),
        ds_vni=dict(type="int"),
        netflow_enable=dict(type="bool"),
        intfvlan_nf_monitor=dict(type="str"),
        vlan_nf_monitor=dict(type="str"),
        gateway_on_border=dict(type="bool"),
        l3gw_on_border=dict(type="bool"),
    )


def _child_network_fields():
    return dict(
        l2_fabric_data=dict(type="dict"),
        stretch=dict(type="str"),
        enable_ir=dict(type="bool"),
        multicast_group_address=dict(type="str"),
        ds_vni=dict(type="int"),
        dhcp_servers=dict(type="list", elements="dict", options=_dhcp_server_spec()),
        dhcp_srvr1_ip=dict(type="str"),
        dhcp_srvr1_vrf=dict(type="str"),
        dhcp_srvr2_ip=dict(type="str"),
        dhcp_srvr2_vrf=dict(type="str"),
        dhcp_srvr3_ip=dict(type="str"),
        dhcp_srvr3_vrf=dict(type="str"),
        loopback_id=dict(type="int"),
        dhcp_loopback_id=dict(type="int"),
        igmp_version=dict(type="int", choices=[1, 2, 3]),
        trm_enable=dict(type="bool"),
        ipv6_trm=dict(type="bool"),
        netflow_enable=dict(type="bool"),
        gateway_on_border=dict(type="bool"),
        l3gw_on_border=dict(type="bool"),
    )


def network_base_argument_spec():
    """Argument spec for a single network config entry."""
    spec = dict(
        network_name=dict(type="str"),
        net_name=dict(type="str"),
        network_type=dict(type="str", choices=NETWORK_TYPE_CHOICES),
        vlan_network_type=dict(type="str", choices=VLAN_NETWORK_TYPE_CHOICES),
        primary_network_id=dict(type="int"),
        primary_network_name=dict(type="str"),
        display_name=dict(type="str"),
        vrf_name=dict(type="str"),
        tenant_name=dict(type="str"),
        layer=dict(type="str", choices=NetworkLayer.choices()),
        is_l2only=dict(type="bool"),
        rt_auto=dict(type="bool"),
        x_connect=dict(type="bool"),
        network_template_name=dict(type="str"),
        network_extension_template_name=dict(type="str"),
        network_template_config=dict(type="dict"),
        net_template=dict(type="str"),
        net_extension_template=dict(type="str"),
        deploy=dict(type="bool", default=True),
        deploy_type=dict(type="str", default="switch", choices=["switch", "network"]),
        attach=dict(type="list", elements="dict", options=_attachment_spec()),
    )
    spec.update(_shared_network_fields())
    return spec


def _child_fabric_config_element_spec():
    spec = dict(fabric_name=dict(type="str", required=True))
    spec.update(_child_network_fields())
    return spec


def network_parent_argument_spec():
    """Argument spec for a network config entry on parent fabrics."""
    spec = network_base_argument_spec()
    spec["child_fabric_config"] = dict(
        type="list",
        elements="dict",
        options=_child_fabric_config_element_spec(),
    )
    return spec
