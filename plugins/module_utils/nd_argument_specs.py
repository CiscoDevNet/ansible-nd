# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


def management_network_spec():
    return dict(
        ipv4_address=dict(type="str", required=True),
        ipv4_gateway=dict(type="str", required=True),
        ipv6_address=dict(type="str"),
        ipv6_gateway=dict(type="str"),
    )


def data_network_spec():
    return dict(
        ipv4_address=dict(type="str", required=True),
        ipv4_gateway=dict(type="str", required=True),
        ipv6_address=dict(type="str"),
        ipv6_gateway=dict(type="str"),
        vlan=dict(type="str"),
    )


def bgp_spec():
    return dict(
        asn=dict(type="int", required=True),
        peers=dict(
            type="list",
            elements="dict",
            options=dict(
                ip=dict(type="str", required=True),
                asn=dict(type="int", required=True),
            ),
        ),
    )
