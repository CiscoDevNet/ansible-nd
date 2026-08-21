# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Argument-spec helpers for nd_manage_networks.py."""

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.enums import (
    DpuAffinity,
    MappingType,
    NetworkAttachmentMode,
    NetworkLayer,
)

_VLAN_NETWORK_TYPE_CHOICES = [
    "normal",
    "private_primary",
    "private_secondary_community",
    "private_secondary_isolated",
    "child",
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


def _attachment_options_spec():
    return dict(
        dpu_secure=dict(type="bool"),
        dpu_affinity=dict(type="str", choices=DpuAffinity.choices()),
        svi_enabled=dict(type="bool"),
        switch_route_target_import=dict(type="list", elements="str"),
        switch_route_target_export=dict(type="list", elements="str"),
        is_active=dict(type="bool"),
    )


def _attachment_spec():
    return dict(
        ip_address=dict(type="str", required=True),
        vlan_id=dict(type="int"),
        interfaces=dict(type="list", elements="dict", required=True, options=_network_interface_spec()),
        deploy=dict(type="bool", default=True),
        attachment_options=dict(type="dict", options=_attachment_options_spec()),
        freeform_config=dict(type="str"),
    )


def _shared_network_fields(defaults=True):
    bool_default = False if defaults else None
    return dict(
        network_id=dict(type="int"),
        vlan_id=dict(type="int"),
        vlan_network_type=dict(type="str", choices=_VLAN_NETWORK_TYPE_CHOICES),
        primary_network_id=dict(type="int"),
        vlan_name=dict(type="str"),
        route_target_both=dict(type="bool"),
        gateway_ipv4_address=dict(type="str"),
        gateway_ipv6_address=dict(type="str"),
        secondary_gateway_ipv4_collection=dict(type="list", elements="str"),
        secondary_gateway_ipv6_collection=dict(type="list", elements="str"),
        vlan_intf_desc=dict(type="str"),
        mtu=dict(type="int", default=9216) if defaults else dict(type="int"),
        arp_suppression=dict(type="bool", default=bool_default) if defaults else dict(type="bool"),
        routing_tag=dict(type="int"),
        dhcp_servers=dict(type="list", elements="dict", options=_dhcp_server_spec()),
        loopback_id=dict(type="int"),
        igmp_version=dict(type="int", choices=[1, 2, 3]),
        trm_enable=dict(type="bool"),
        ipv6_trm=dict(type="bool"),
        multicast_group_address=dict(type="str"),
        ds_vni=dict(type="int"),
        netflow_enable=dict(type="bool", default=bool_default) if defaults else dict(type="bool"),
        l2_netflow_monitor=dict(type="str"),
        l3_netflow_monitor=dict(type="str"),
        netflow_sampler=dict(type="str"),
        gateway_on_border=dict(type="bool"),
    )


def _child_network_fields():
    return dict(
        multicast_group_address=dict(type="str"),
        ds_vni=dict(type="int"),
        route_target_both=dict(type="bool"),
        dhcp_servers=dict(type="list", elements="dict", options=_dhcp_server_spec()),
        loopback_id=dict(type="int"),
        igmp_version=dict(type="int", choices=[1, 2, 3]),
        trm_enable=dict(type="bool"),
        ipv6_trm=dict(type="bool"),
        netflow_enable=dict(type="bool"),
        l2_netflow_monitor=dict(type="str"),
        l3_netflow_monitor=dict(type="str"),
        netflow_sampler=dict(type="str"),
        gateway_on_border=dict(type="bool"),
    )


def network_base_argument_spec():
    """Argument spec for a single network config entry."""
    spec = dict(
        network_name=dict(type="str"),
        display_name=dict(type="str"),
        vrf_name=dict(type="str"),
        layer=dict(type="str", choices=NetworkLayer.choices()),
        x_connect=dict(type="bool"),
        network_template_name=dict(type="str"),
        network_extension_template_name=dict(type="str"),
        service_network_template_name=dict(type="str"),
        network_template_config=dict(type="dict"),
        deploy=dict(type="bool", default=True),
        deploy_type=dict(type="str", default="switch", choices=["switch", "network"]),
        attach=dict(type="list", elements="dict", options=_attachment_spec()),
    )
    spec.update(_shared_network_fields(defaults=True))
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
