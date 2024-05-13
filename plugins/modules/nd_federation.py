#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import base64
import time

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_federation
version_added: "0.3.0"
short_description:
    - Setup multi-federation configuration on Cisco Nexus Dashboard (ND).
description:
    - Connects to another Nexus Dashboard (ND) federation for a single pane of glass view into all federations’ sites and services.
    - M(cisco.nd.nd_federation) can only be used with python 3.7 and higher.
author:
    - Anvitha Jain (@anvjain)
options:
  name:
    description:
      - The name of the federation.
    type: str
    required: true
    aliases: [ federation, federation_name, local_cluster_name ]
  state:
    description:
      - The state of the federation configuration.
    type: str
    default: present
    choices: [ absent, present, query ]
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Setup multi-federation configuration
  cisco.nd.nd_federation:
    name: local_cluster_name
    state: present
"""
RETURN = r"""
"""
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        name=dict(type='str', aliases=["federation", "federation_name", "local_cluster_name"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    name = nd.params.get("name")
    state = nd.params.get("state")

    path = "/nexus/api/federation/v4/federations"
    federation_obj = nd.query_obj(path, ignore_not_found_error=True).get("items")

    if federation_obj:
        federation_info = next((federation_dict for federation_dict in federation_obj if federation_dict.get("spec").get("name") == name), None)
        if federation_info:
            federation_path = "{0}/{1}".format(path, federation_info.get("status").get("federationID"))
            nd.existing = federation_info
    else:
        nd.existing = federation_obj

    nd.previous = nd.existing

    if state == "query":
        nd.exit_json()
    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                nd.request(federation_path, method="DELETE")
            nd.existing = {}
    if state == "present":
        payload = {
            "spec": {
                "name": name,
            },
        }

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            nd.request(path, method="POST", data=payload)
            time.sleep(10)

    nd.existing = nd.proposed

    nd.exit_json()

if __name__ == "__main__":
    main()
