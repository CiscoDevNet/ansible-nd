#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_setup
version_added: "0.5.0"
short_description: Manages setting up the Nexus Dashboard.
description:
- Manages setting up the Nexus Dashboard (ND).
author:
- Shreyas Srish (@shrsr)
- Gaspard Micol (@gmicol)
options:
  cluster_name:
    description:
    - The name of the ND cluster.
    type: str
  ntp_server:
    description:
    - The IP address of the NTP server.
    - This option is only applicable and required for ND version 2.3.2d and later.
    type: list
    elements: str
    aliases: [ ntp_servers ]
  dns_server:
    description:
    - The IP address of the DNS server.
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
    - The app subnet.
    - This is a 'pod-to-pod' network and is used to run inter pod traffic.
    type: str
  service_network:
    description:
    - The service subnet.
    - This is a virtual level subnet used for communication within the cluster.
    type: str
  app_network_ipv6:
    description:
    - The IPv6 app subnet.
    - This option is only applicable for ND version 3.0.1f and later.
    type: str
  service_network_ipv6:
    description:
    - The IPv6 service subnet.
    - This option is only applicable for ND version 3.0.1f and later.
    type: str
  ntp_config:
    description:
    - This is used for configuring NTP server and its other options.
    - This option is only applicable and required for ND version 3.0.1f and later.
    type: dict
    suboptions:
      servers:
        description:
        - This option is used for setting up the NTP host.
        type: list
        required: true
        elements: dict
        suboptions:
          ntp_host:
            description:
            - The IP address of the NTP server.
            type: str
            required: true
          ntp_key_id:
            description:
            - The NTP Key ID.
            type: int
          preferred:
            description:
            - The preferred status of the NTP host.
            type: bool
            default: false
      keys:
        description:
        - This option is used for setting up the NTP keys.
        type: list
        elements: dict
        suboptions:
          ntp_key_id:
            description:
            - The NTP Key ID.
            type: int
            required: true
          ntp_key:
            description:
            - The value of the NTP key.
            type: str
            required: true
          authentication_type:
            description:
            - The authentication type for the NTP key.
            type: str
            choices: [ AES128CMAC, SHA1, MD5 ]
            required: true
          trusted:
            description:
            - The trusted status of the NTP key.
            type: bool
            default: false
  nodes:
    description:
    - The node details to set up Nexus Dashboard and bring up the User Interface.
    type: list
    elements: dict
    suboptions:
      hostname:
        description:
        - The host name of the node.
        type: str
        required: true
      serial_number:
        description:
        - The serial number of the node.
        type: str
        required: true
      role:
        description:
        - The role of the node.
        type: str
        choices: [ primary, secondary, standby ]
      management_ip_address:
        description:
        - The management IP address of the node.
        type: str
        required: true
      username:
        description:
        - The username of the node.
        type: str
        required: true
      password:
        description:
        - The password of the node.
        type: str
        required: true
      management_network:
        description:
        - The network used for DNS and NTP communication.
        type: dict
        required: true
        suboptions:
          ipv4_address:
            description:
            - The IPv4 address of the management network.
            type: str
            required: true
            aliases: [ ip ]
          ipv4_gateway:
            description:
            - The IPv4 gateway of the management network.
            type: str
            required: true
            aliases: [ gateway ]
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
        - The network used for clustering and communication between sites and applications.
        type: dict
        required: true
        suboptions:
          ipv4_address:
            description:
            - The IPv4 address of the data network.
            type: str
            required: true
            aliases: [ ip ]
          ipv4_gateway:
            description:
            - The IPv4 gateway of the data network.
            type: str
            required: true
            aliases: [ gateway ]
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
            - The VLAN of the data network.
            - Native VLAN or access port does not require VLAN.
            type: int
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
            - The BGP peer details.
            type: list
            elements: dict
            suboptions:
              ip:
                description:
                - The IPv4 Address of the BGP peer.
                type: str
                required: true
              asn:
                description:
                - The ASN of the BGP peer.
                type: int
                required: true
  deployment_mode:
    description:
    - This is used for enabling the services between Orchestrator,
      Fabric Controller and Insights during the initial installation.
    - This option is only applicable for ND version 3.1.1 and later.
    type: list
    elements: str
    choices: [ ndo, ndfc, ndi ]
  external_services:
    description:
    - The persistent Service IPs/Pools to be provided.
    - This can be used when I(deployment_mode) includes C(ndfc) or C(ndi) otherwise it will be ignored.
    - This option is only applicable for ND version 3.1.1 and later.
    type: dict
    suboptions:
      management_service_ips:
        description:
        - The management service IPs/Pools.
        type: list
        elements: str
      data_service_ips:
        description:
        - The data service IPs/Pools.
        type: list
        elements: str
  state:
    description:
    - Use C(present) for setting up Nexus Dashboard.
    - Use C(query) for checking the installation status of Nexus Dashboard.
    type: str
    default: present
    choices: [ present, query ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module only supports setting up the Nexus Dashboard having version 2.3.2d or higher.
"""

EXAMPLES = r"""
- name: Setup ND
  cisco.nd.nd_setup:
    cluster_name: cluster1
    ntp_config:
      servers:
        - ntp_host: 173.36.212.205
          ntp_key_id: 1
          preferred: true
      keys:
        - ntp_key_id: 1
          ntp_key: "1"
          authentication_type: "AES128CMAC"
          trusted: true
    dns_server:
      - 210.69.111.224
    dns_search_domain:
      - cisco.com
    app_network: 192.18.0.1/16
    service_network: 200.90.0.0/16
    nodes:
      - hostname: Test
        serial_number: 3C0A86H4D02E
        role: primary
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
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import network_spec, bgp_spec, ntp_server_spec, ntp_keys_spec
from ansible_collections.cisco.nd.plugins.module_utils.constants import ND_SETUP_NODE_ROLE_MAPPING


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        cluster_name=dict(type="str"),
        deployment_mode=dict(type="list", elements="str", choices=["ndo", "ndfc", "ndi"]),
        external_services=dict(
            type="dict",
            options=dict(
                management_service_ips=dict(type="list", elements="str"),
                data_service_ips=dict(type="list", elements="str"),
            ),
        ),
        ntp_server=dict(type="list", aliases=["ntp_servers"], elements="str"),
        dns_server=dict(type="list", aliases=["dns_servers"], elements="str"),
        proxy_server=dict(type="str"),
        proxy_username=dict(type="str"),
        proxy_password=dict(type="str", no_log=True),
        ignore_proxy=dict(type="list", elements="str"),
        dns_search_domain=dict(type="list", aliases=["dns_search_domains"], elements="str"),
        app_network=dict(type="str"),
        service_network=dict(type="str"),
        app_network_ipv6=dict(type="str"),
        service_network_ipv6=dict(type="str"),
        ntp_config=dict(
            type="dict",
            options=dict(
                servers=dict(type="list", required=True, options=ntp_server_spec(), elements="dict"),
                keys=dict(type="list", options=ntp_keys_spec(), elements="dict", no_log=False),
            ),
        ),
        nodes=dict(
            type="list",
            elements="dict",
            options=dict(
                hostname=dict(type="str", required=True),
                serial_number=dict(type="str", required=True),
                role=dict(type="str", choices=["primary", "secondary", "standby"]),
                management_ip_address=dict(type="str", required=True),
                username=dict(type="str", required=True),
                password=dict(type="str", required=True, no_log=True),
                management_network=dict(type="dict", required=True, options=network_spec()),
                data_network=dict(type="dict", required=True, options=network_spec(vlan=True)),
                bgp=dict(type="dict", options=bgp_spec()),
            ),
        ),
        state=dict(type="str", default="present", choices=["present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["cluster_name", "dns_server", "app_network", "service_network", "nodes"]],
        ],
        required_together=[
            ["proxy_username", "proxy_password"],
        ],
        mutually_exclusive=[
            ["ntp_server", "ntp_config"],
        ],
    )

    nd = NDModule(module)

    cluster_name = nd.params.get("cluster_name")
    deployment_mode = nd.params.get("deployment_mode")
    external_services = nd.params.get("external_services")
    ntp_server = nd.params.get("ntp_server")
    dns_server = nd.params.get("dns_server")
    proxy_server = nd.params.get("proxy_server")
    proxy_username = nd.params.get("proxy_username")
    proxy_password = nd.params.get("proxy_password")
    ignore_proxy = nd.params.get("ignore_proxy")
    dns_search_domain = nd.params.get("dns_search_domain")
    app_network = nd.params.get("app_network")
    service_network = nd.params.get("service_network")
    app_network_ipv6 = nd.params.get("app_network_ipv6")
    service_network_ipv6 = nd.params.get("service_network_ipv6")
    ntp_config = nd.params.get("ntp_config")
    nodes = nd.params.get("nodes")
    state = nd.params.get("state")

    if state == "query":
        nd.existing = nd.request("/clusterstatus/install", method="GET")
    else:
        nd_version = nd.query_obj("/version.json")

        if len(cluster_name) > 63:
            nd.fail_json("A length of 1 to 63 characters is allowed.")
        elif len(re.findall(r"[^a-zA-Z0-9-]", cluster_name)) > 0:
            nd.fail_json("Valid characters include letters, digits and hyphen.")
        elif len(re.findall(r"^-|-$", cluster_name)) > 0:
            nd.fail_json("The name cannot start or end with a hyphen.")

        payload = {
            "clusterConfig": {
                "name": cluster_name,
                "ntpServers": ntp_server,
                "nameServers": dns_server,
                "ntpConfig": {
                    "servers": [
                        {
                            "host": server.get("ntp_host"),
                            "keyID": server.get("ntp_key_id"),
                            "prefer": server.get("preferred"),
                        }
                        for server in ([] if ntp_config is None else ntp_config.get("servers"))
                    ],
                    "keys": [
                        {
                            "id": key.get("ntp_key_id"),
                            "key": key.get("ntp_key"),
                            "authType": key.get("authentication_type"),
                            "trusted": key.get("trusted"),
                        }
                        for key in (ntp_config.get("keys") if ntp_config is not None and ntp_config.get("keys") is not None else [])
                    ],
                },
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
                "appNetworkV6": app_network_ipv6,
                "serviceNetworkV6": service_network_ipv6,
            },
            "nodes": [
                {
                    "hostName": node.get("hostname"),
                    "serialNumber": node.get("serial_number"),
                    "role": ND_SETUP_NODE_ROLE_MAPPING.get(node.get("role")),
                    "dataNetwork": {
                        "ipSubnet": node["data_network"].get("ipv4_address"),
                        "gateway": node["data_network"].get("ipv4_gateway"),
                        "ipv6Subnet": node["data_network"].get("ipv6_address"),
                        "gatewayv6": node["data_network"].get("ipv6_gateway"),
                        "vlan": node["data_network"].get("vlan"),
                    },
                    "managementNetwork": {
                        "ipSubnet": node["management_network"].get("ipv4_address"),
                        "gateway": node["management_network"].get("ipv4_gateway"),
                        "ipv6Subnet": node["management_network"].get("ipv6_address"),
                        "gatewayv6": node["management_network"].get("ipv6_gateway"),
                    },
                    "bgpConfig": {
                        "as": node.get("bgp").get("asn") if node.get("bgp") is not None else None,
                        "peers": node.get("bgp").get("peers") if node.get("bgp") is not None else None,
                    },
                    "nodeController": {
                        "ipAddress": node.get("management_ip_address"),
                        "loginUser": node.get("username"),
                        "loginPassword": node.get("password"),
                    },
                }
                for node in nodes
            ],
        }

        path = "/bootstrap/cluster"

        # Deployment mode options for ND version 3.1.1 and later
        if nd_version["major"] > 3 or (nd_version["major"] == 3 and nd_version["minor"] >= 1):
            if isinstance(deployment_mode, list):
                payload["clusterConfig"]["deploymentMode"] = deployment_mode if len(deployment_mode) > 1 else deployment_mode[0]
                if external_services is not None and any(service in {"ndi", "ndfc"} for service in deployment_mode):
                    payload["clusterConfig"]["externalServices"] = []
                    if external_services.get("management_service_ips") is not None:
                        payload["clusterConfig"]["externalServices"].append(
                            {
                                "target": "Management",
                                "pool": list(external_services.get("management_service_ips")),
                            }
                        )
                    if external_services.get("data_service_ips") is not None:
                        payload["clusterConfig"]["externalServices"].append(
                            {
                                "target": "Data",
                                "pool": list(external_services.get("data_service_ips")),
                            }
                        )
            path = "{0}{1}".format("/v2", path)

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            nd.request(path, method="POST", data=payload)
        nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
