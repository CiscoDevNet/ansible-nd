#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_cluster_config_route
version_added: "0.5.0"
short_description: Manages routes of the cluster config.
description:
- Manages the data and management routes of the cluster configuration.
author:
- Shreyas Srish (@shrsr)
options:
  destination_ip:
    description:
    - The destination address of the target network.
    type: str
  target_network:
    description:
    - Use 'data' to add a data network route.
    - Use 'management' to add a management network route.
    type: str
    choices: [ data, management ]
  state:
    description:
    - Use C(present) for adding a route to the cluster config.
    - Use C(query) for listing all the routes of the cluster config.
    - Use C(absent) for deleting a route of the cluster config.
    type: str
    choices: [ present, query, absent ]
    default: present
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create a data route
  cisco.nd.nd_cluster_config_route:
    destination_ip: 12.23.45.68/32
    target_network: data
    state: present

- name: Query a route
  cisco.nd.nd_cluster_config_route:
    destination_ip: 12.23.45.68/32
    state: query
  register: query_result

- name: Query all the routes
  cisco.nd.nd_cluster_config_route:
    state: query
  register: query_results

- name: Delete a route
  cisco.nd.nd_cluster_config_route:
    destination_ip: 12.23.45.68/32
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict

try:
    from ansible.module_utils.six.moves.urllib.parse import quote

    HAS_QUOTE = True
except Exception:
    HAS_QUOTE = False


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        destination_ip=dict(type="str"),
        target_network=dict(type="str", choices=["data", "management"]),
        state=dict(type="str", default="present", choices=["present", "query", "absent"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["destination_ip", "target_network"]],
            ["state", "absent", ["destination_ip"]],
        ],
    )

    nd = NDModule(module)

    destination_ip = nd.params.get("destination_ip")
    target_network = nd.params.get("target_network").capitalize() if nd.params.get("target_network") else nd.params.get("target_network")
    state = nd.params.get("state")

    path = "/nexus/infra/api/platform/v1/routes"
    route_objs = nd.query_obj(path).get("items")
    if destination_ip:
        if not HAS_QUOTE:
            nd.fail_json(msg="quote is not installed")
        destination_path = "{0}/{1}".format(path, quote(destination_ip, safe=""))
        nd.existing = next((route_dict for route_dict in route_objs if route_dict.get("spec").get("destination") == destination_ip), {})
    else:
        nd.existing = route_objs

    unwanted_keys = ["metadata", "status"]

    nd.previous = sanitize_dict(
        nd.existing if isinstance(nd.existing, dict) else dict((k, v) for element in nd.existing for k, v in element.items()), unwanted_keys
    )

    if state == "absent":
        if nd.existing:
            if not module.check_mode:
                nd.request(destination_path, method="DELETE")
            nd.existing = {}
    elif state == "present":
        payload = {
            "spec": {
                "destination": destination_ip,
                "targetNetwork": target_network,
            }
        }

        nd.sanitize(payload, collate=True, unwanted=unwanted_keys)

        if not module.check_mode:
            if nd.existing and payload != nd.previous:
                nd.request(destination_path, "PUT", data=payload)
            elif nd.existing == {}:
                nd.request(path, "POST", data=payload)
        nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
