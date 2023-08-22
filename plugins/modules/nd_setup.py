#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_setup
short_description: Manages setting up ND.
description:
- Manages setting up the Nexus Dashboard.
author:
- Shreyas Srish (@shrsr)
options:
  cluster_name:
    description:
    - The name of a cluster.
    type: str
  ntp_server:
    description:
    - The NTP IP address.
    type: list
    elements: str
    aliases: [ ntp_servers ]
  dns_server:
    description:
    - The DNS provider IP address.
    type: list
    elements: str
    aliases: [ dns_servers ]
  proxy_server:
    description:
    - The proxy server.
    type: str
  proxy_username:
    description:
    - The username of the proxy server.
    type: str
  proxy_password:
    description:
    - The password of the proxy server.
    type: str
  ignore_proxy:
    description:
    - Proxy is ignored for the list of host addresses provided in this option.
    type: list
    elements: str
  dns_search_domain:
    description:
    - The DNS search domains.
    type: list
    elements: str
    aliases: [ dns_search_domains ]
  app_network:
    description:
    - App subnet is 'pod-to-pod' network.
    - This is used to run inter pod traffic.
    type: str
  service_network:
    description:
    - Service subnet is a virtual level subnet used for communication within the cluster.
    type: str
  nodes:
    description:
    - The node details to set up Nexus Dashboard and bring up the User Interface.
    type: list
    elements: dict
    suboptions:
      hostname:
        description:
        - The host name for the node.
        type: str
        required: true
      serial_number:
        description:
        - The serial number of the node.
        type: str
        required: true
      management_ip_address:
        description:
        - The management IP address for adding a node.
        type: str
        required: true
      username:
        description:
        - The username for adding a node.
        type: str
        required: true
      password:
        description:
        - The password for adding a node.
        type: str
        required: true
      management_network:
        description:
        - Used for DNS and NTP communication
        type: dict
        required: true
        suboptions:
          ipv4_address:
            description:
            - The IPv4 address of the management network.
            type: str
            required: true
          ipv4_gateway:
            description:
            - The IPv4 gateway of the management network.
            type: str
            required: true
          ipv6_address:
            description:
            - The IPv6 address of the management network.
            type: str
          ipv6_gateway:
            description:
            - The IPv6 gateway of the management network.
            type: str
      data_network:
        description:
        - Used for clustering and communication between sites and applications.
        type: dict
        required: true
        suboptions:
          ipv4_address:
            description:
            - The IPv4 address of the data network.
            type: str
            required: true
          ipv4_gateway:
            description:
            - The IPv4 gateway of the data network.
            type: str
            required: true
          ipv6_address:
            description:
            - The IPv6 address of the data network.
            type: str
          ipv6_gateway:
            description:
            - The IPv6 gateway of the data network.
            type: str
          vlan:
            description:
            - This can be left empty if connecting through the native VLAN or an access port.
            type: str
      bgp:
        description:
        - This is used for enabling BGP.
        type: dict
        suboptions:
          asn:
            description:
            - The BGP ASN.
            type: int
            required: true
          peers:
            description:
            - BGP peer details.
            type: list
            elements: dict
            suboptions:
              ip:
                description:
                - The peer IPv4 Address.
                type: str
                required: true
              asn:
                description:
                - The peer ASN.
                type: int
                required: true
  state:
    description:
    - Use C(present) for setting up Nexus Dashboard.
    - Use C(query) for checking the installation status of Nexus Dashboard.
    type: str
    default: present
    choices: [ present, query ]
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Setup ND
  cisco.nd.nd_setup:
    cluster_name: cluster1
    ntp_server:
      - 179.37.212.207
    dns_server:
      -  210.69.111.224
    dns_search_domain:
      - cisco.com
    app_network: 192.18.0.1/16
    service_network: 200.90.0.0/16
    nodes:
      - hostname: Test
        serial_number: 3C0A86H4D02E
        management_ip_address: 13.34.56.23
        username: rescue-user
        password: test
        management_network:
          ipv4_address: 13.34.56.23/24
          ipv4_gateway: 13.34.56.1
        data_network:
          ipv4_address: 12.34.56.22/24
          ipv4_gateway: 12.34.56.1
        bgp:
          asn: 2
          peers:
            - ip: 15.36.56.22/24
              asn: 2

- name: Check the installation status of ND
  cisco.nd.nd_setup:
    state: query
"""

RETURN = r"""
"""

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import management_network_spec, data_network_spec, bgp_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        cluster_name=dict(type="str"),
        ntp_server=dict(type="list", aliases=["ntp_servers"], elements="str"),
        dns_server=dict(type="list", aliases=["dns_servers"], elements="str"),
        proxy_server=dict(type="str"),
        proxy_username=dict(type="str"),
        proxy_password=dict(type="str", no_log=True),
        ignore_proxy=dict(type="list", elements="str"),
        dns_search_domain=dict(type="list", aliases=["dns_search_domains"], elements="str"),
        app_network=dict(type="str"),
        service_network=dict(type="str"),
        nodes=dict(
            type="list",
            elements="dict",
            options=dict(
                hostname=dict(type="str", required=True),
                serial_number=dict(type="str", required=True),
                management_ip_address=dict(type="str", required=True),
                username=dict(type="str", required=True),
                password=dict(type="str", required=True, no_log=True),
                management_network=dict(type="dict", required=True, options=management_network_spec()),
                data_network=dict(type="dict", required=True, options=data_network_spec()),
                bgp=dict(type="dict", options=bgp_spec()),
            ),
        ),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["cluster_name", "ntp_server", "dns_server", "app_network", "service_network", "nodes"]],
        ],
        required_together=[
            ["proxy_username", "proxy_password"],
        ],
    )

    nd = NDModule(module)

    cluster_name = nd.params.get("cluster_name")
    ntp_server = nd.params.get("ntp_server")
    dns_server = nd.params.get("dns_server")
    proxy_server = nd.params.get("proxy_server")
    proxy_username = nd.params.get("proxy_username")
    proxy_password = nd.params.get("proxy_password")
    ignore_proxy = nd.params.get("ignore_proxy")
    dns_search_domain = nd.params.get("dns_search_domain")
    app_network = nd.params.get("app_network")
    service_network = nd.params.get("service_network")
    nodes = nd.params.get("nodes")
    state = nd.params.get("state")

    if state == "query":
        nd.existing = nd.request("/clusterstatus/install", method="GET")
    else:
        if len(cluster_name) > 63 or len(re.findall(r'[^a-zA-Z0-9 -]|^-| *-$', cluster_name)) > 0:
            nd.fail_json("A length of 1 to 63 characters is allowed and valid characters include letters, digits and hyphen. "
                         "The name cannot start or end with a hyphen.")

        payload = {
            "clusterConfig": {
                "name": cluster_name,
                "ntpServers": ntp_server,
                "nameServers": dns_server,
                "searchDomains": dns_search_domain,
                "ignoreHosts": ignore_proxy,
                "proxyServers": [
                    {
                        "proxyURL": proxy_server,
                        "username": proxy_username,
                        "password": proxy_password,
                    }
                ],
                "appNetwork": app_network,
                "serviceNetwork": service_network,
            },
            "nodes": [
                {
                    "hostName": node.get("hostname"),
                    "serialNumber": node.get("serial_number"),
                    "dataNetwork": {
                        "ipSubnet": node.get("data_network").get("ipv4_address"),
                        "gateway": node.get("data_network").get("ipv4_gateway"),
                        "ipv6Subnet": node.get("data_network").get("ipv6_address"),
                        "gatewayv6": node.get("data_network").get("ipv6_gateway"),
                    },
                    "managementNetwork": {
                        "ipSubnet": node.get("management_network").get("ipv4_address"),
                        "gateway": node.get("management_network").get("ipv4_gateway"),
                        "ipv6Subnet": node.get("management_network").get("ipv6_address"),
                        "gatewayv6": node.get("management_network").get("ipv6_gateway"),
                    },
                    "bgpConfig": {
                        "as": node.get("bgp").get("asn") if node.get("bgp") is not None else None,
                        "peers": node.get("bgp").get("peers") if node.get("bgp") is not None else None,
                    },
                    "nodeController": {
                        "ipAddress": node.get("management_ip_address"),
                        "loginUser": node.get("username"),
                        "loginPassword": node.get("password"),
                    }
                }
                for node in nodes
            ]
        }

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            nd.request("/bootstrap/cluster", method="POST", data=payload)
        nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
