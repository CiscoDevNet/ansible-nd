#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import base64

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_federation_member
version_added: "0.3.0"
short_description:
    - Setup multi-cluster configuration on Cisco Nexus Dashboard (ND).
description:
    - Connects to another Nexus Dashboard (ND) cluster for a single pane of glass view into all clusters’ sites and services.
    - M(cisco.nd.nd_federation_member) can only be used with python 3.7 and higher.
author:
    - Anvitha Jain (@anvjain)
options:
  cluster:
    description:
      - The IP address of the cluster.
    type: str
    required: true
    aliases: [ cluster_ip, hostname, ip_address ]
  cluster_username:
    description:
      - The username for the cluster.
    type: str
    required: true
  cluster_password:
    description:
      - The password for the cluster.
    type: str
    required: true
    no_log: true
  cluster_login_domain:
    description:
      - The login domain ame to use for the cluster.
      - Default value is set to DefaultAuth.
    type: str
    default: "DefaultAuth"
  state:
    description:
      - The state of the cluster configuration.
    type: str
    default: present
    choices: [ absent, present, query ]
extends_documentation_fragment: cisco.nd.modules
notes:
- The C(federation) must exist before using this module in your playbook.
  The M(cisco.aci.nd_federation) module can be used for this.
"""

EXAMPLES = r"""
- name: Setup multi-cluster configuration
  cisco.nd.nd_federation_member:
    cluster: "172.37.20.15"
    username: "admin"
    password: "password"
    login_domain: "default"
    state: present
"""
RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        cluster=dict(type='str', aliases=["cluster_ip", "hostname", "ip_address"]),
        cluster_username=dict(type='str'),
        cluster_password=dict(type='str', no_log=True),
        cluster_login_domain=dict(type='str', default="DefaultAuth"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["cluster"]],
            ["state", "present", ["cluster", "cluster_username", "cluster_password"]],
        ],
    )

    nd = NDModule(module)
    nd.stdout = str("  HI ND  ") 

    cluster = nd.params.get("cluster")
    cluster_username = nd.params.get("cluster_username")
    cluster_password = nd.params.get("cluster_password")
    if cluster_password is not None:
        # Make password base64 encoded
        cluster_password = (base64.b64encode(str.encode(cluster_password))).decode("utf-8")
    cluster_login_domain = nd.params.get("cluster_login_domain")
    state = nd.params.get("state")

    path = "/nexus/api/federation/v4/members"
    cluster_path = path

    cluster_obj = nd.query_obj(path).get("items")
    nd.stdout += str("  cluster_obj") + str(cluster_obj)

    if cluster_obj:
        cluster_info = next((cluster_dict for cluster_dict in cluster_obj if cluster_dict.get("spec").get("host") == cluster), None)
        nd.stdout += str("  cluster_info") + str(cluster_info)
        if cluster_info:
            cluster_path = "{0}/{1}".format(path, cluster_info.get("status").get("memberID"))
            nd.stdout += str("  cluster_path : ") + str(cluster_path)
            nd.existing = cluster_info
    else:
        nd.existing = cluster_obj

    nd.previous = nd.existing

    if state == "query":
        nd.exit_json()
    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                nd.request(cluster_path, method="DELETE")
            nd.existing = {}
    elif state == "present":
        payload = {
            "spec": {
                "host": cluster,
                "userName": cluster_username,
                "password": cluster_password,
                "loginDomain": cluster_login_domain,
            },
        }
        nd.stdout += str("  payload : ") + str(payload)

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            nd.request(cluster_path, method="POST", data=payload)
    
    nd.existing = nd.proposed

    nd.exit_json()

if __name__ == "__main__":
    main()
