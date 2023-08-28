# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


def network_spec(vlan=False):
    spec = dict(
        ipv4_address=dict(type="str", required=True),
        ipv4_gateway=dict(type="str", required=True),
        ipv6_address=dict(type="str"),
        ipv6_gateway=dict(type="str"),
    )
    if vlan:
        spec["vlan"] = dict(type="int")
    return spec


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
