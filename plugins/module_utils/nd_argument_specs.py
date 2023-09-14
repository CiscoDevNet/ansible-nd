# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


def ntp_server_spec():
    return dict(
        ntp_host=dict(type="str", required=True),
        ntp_key_id=dict(type="int", no_log=False),
        preferred=dict(type="bool", default=False),
    )


def ntp_keys_spec():
    return dict(
        ntp_key_id=dict(type="int", required=True, no_log=False),
        ntp_key=dict(type="str", required=True, no_log=True),
        authentication_type=dict(type="str", required=True, choices=["AES128CMAC", "SHA1", "MD5"]),
        trusted=dict(type="bool", default=False),
    )


def network_spec(vlan=False):
    spec = dict(
        ipv4_address=dict(type="str", aliases=["ip"], required=True),
        ipv4_gateway=dict(type="str", aliases=["gateway"], required=True),
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
