#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Anvitha Jain (@anvjain) <anvjain@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_federation_member
version_added: "0.3.0"
short_description: Setup multi-cluster configuration on Cisco Nexus Dashboard (ND).
description:
  - Connects multiple clusters together for a single pane of glass view and administration of the clusters and their sites, services, and configurations.
  - M(cisco.nd.nd_federation_member) can only be used with python 3.7 and higher.
  - Can only be used with Nexus Dashboard versions >= 2.3(2d).
  - The ND version of the local cluster must be greater than or equal to the ND versions of the clusters being added.
author:
  - Anvitha Jain (@anvjain)
options:
  clusters:
    description:
      - The IP address of the cluster.
    type: list
    elements: dict
    suboptions:
      hostname:
        description:
          - The IP address of the federation member/cluster.
        type: str
        required: true
        aliases: [ cluster_ip, ip_address, federation_member ]
      username:
        description:
          - The username for the federation member/cluster.
        type: str
      password:
        description:
          - The password for the federation member/cluster.
        type: str
      login_domain:
        description:
          - The login domain ame to use for the federation member/cluster.
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
- The M(cisco.aci.nd_federation) module can be used for this.
"""

EXAMPLES = r"""
- name: Setup multi-cluster configuration
  cisco.nd.nd_federation_member:
    host: nd
    username: admin
    password: SomeSecretPassword
    clusters:
      - hostname: 172.37.20.15
        username: admin
        password: password
        login_domain: default
    state: present
  delegate_to: localhost

- name: Query all federation members
  cisco.nd.nd_federation_member:
    host: nd
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Query a federation member
  cisco.nd.nd_federation_member:
    host: nd
    username: admin
    password: SomeSecretPassword
    clusters:
      - hostname: 172.37.20.15
    state: query
  delegate_to: localhost

- name: Remove a federation member
  cisco.nd.nd_federation_member:
    host: nd
    username: admin
    password: SomeSecretPassword
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
import base64


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        clusters=dict(
            type="list",
            elements="dict",
            options=dict(
                hostname=dict(type="str", required=True, aliases=["cluster_ip", "ip_address", "federation_member"]),
                username=dict(type="str"),
                password=dict(type="str", no_log=True),
                login_domain=dict(type="str", default="DefaultAuth"),
            ),
        ),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["clusters"]],
        ],
    )

    nd = NDModule(module)

    clusters = nd.params.get("clusters")
    state = nd.params.get("state")

    # validate parameters
    if clusters:
        for cluster in clusters:
            if state == "present":
                if not (cluster.get("username") and cluster.get("password")):
                    nd.fail_json(msg="'username' and 'password' are required when state is present.")

    federation_path = "/nexus/api/federation/v4/federations"
    member_path = "/nexus/api/federation/v4/members"

    # GET local cluster name
    local_cluster_name = ""
    local_cluster_obj = nd.query_obj("/nexus/infra/api/platform/v1/clusters")
    if len(local_cluster_obj.get("items", [])) == 1:
        local_cluster_name = local_cluster_obj.get("items")[0].get("spec", {}).get("name")

    # GET federation
    federation_obj = nd.query_obj(federation_path, ignore_not_found_error=True).get("items")

    # If federation exists, verify if local_cluster is the primary
    if federation_obj:
        federation_info = next((federation_dict for federation_dict in federation_obj if federation_dict.get("spec").get("name") == local_cluster_name), None)
        if not federation_info and state != "query":
            nd.fail_json(msg="Local cluster is not the primary cluster in the federation. Cannot add/remove a member to this federation.")

    # Get federation members
    federation_member_obj = nd.query_obj(member_path, ignore_not_found_error=True).get("items")

    # Query specific member
    if clusters and state == "query" and federation_member_obj:
        for cluster in clusters:
            cluster_info = next(
                (cluster_dict for cluster_dict in federation_member_obj if cluster_dict.get("spec").get("host") == cluster.get("hostname")), None
            )
            if cluster_info:
                nd.existing = cluster_info
    else:
        nd.existing = federation_member_obj

    nd.previous = nd.existing

    if state == "query":
        nd.exit_json()
    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                for member_host in federation_member_obj:
                    if not member_host.get("spec").get("host") == local_cluster_name:
                        cluster_member_path = "{0}/{1}".format(member_path, member_host.get("status").get("memberID"))
                        nd.request(cluster_member_path, method="DELETE")

                # Remove the federation if there are no more members.
                if len(nd.query_obj(member_path, ignore_not_found_error=True).get("items")) == 1:
                    if federation_info:
                        nd.request("{0}/{1}".format(federation_path, federation_info.get("status").get("federationID")), method="DELETE")
            nd.existing = {}

    elif state == "present":
        remove_member_list = []
        add_member_list = []
        payload_dict = {"DELETE": [], "POST": []}
        if len(federation_member_obj) <= 1:
            # if there are no members or just a local member, add all members from users.
            add_member_list = clusters
        else:
            # Remove existing members not specified by the users.
            for existing_member_hosts in federation_member_obj:
                member_host = existing_member_hosts.get("spec").get("host")
                if member_host != local_cluster_name:
                    # Use next() to check if the member exists in user-specified clusters
                    member_exists = next((True for user_member_host in clusters if user_member_host.get("hostname") == member_host), False)
                    if not member_exists:
                        remove_member_list.append(existing_member_hosts)

            # Add members specified by the users.
            for user_member_host in clusters:
                # Use next() to check if the user-specified member exists in existing members
                found = found = next(
                    (
                        True
                        for existing_member_hosts in federation_member_obj
                        if existing_member_hosts.get("spec").get("host") == user_member_host.get("hostname")
                    ),
                    False,
                )
                if not found:
                    add_member_list.append(user_member_host)

        if add_member_list or remove_member_list:
            if remove_member_list:
                for member in remove_member_list:
                    cluster_member_path = "{0}/{1}".format(member_path, member.get("status").get("memberID"))
                    nd.request(cluster_member_path, method="DELETE")
                    payload_dict["DELETE"].append(cluster_member_path)

            if add_member_list:
                for member in add_member_list:
                    cluster_payload = dict(
                        spec=dict(
                            host=member.get("hostname"),
                            userName=member.get("username"),
                            password=(base64.b64encode(str.encode(member.get("password")))).decode("utf-8"),
                            loginDomain=member.get("login_domain"),
                        ),
                    )

                    payload = cluster_payload

                    payload_dict["POST"].append(payload)

                    nd.sanitize(payload, collate=True)

                    if not module.check_mode:
                        # If federation does not exist, create a new federation
                        if not federation_obj:
                            nd.request(federation_path, method="POST", data={"spec": {"name": local_cluster_name}})
                        nd.request(member_path, method="POST", data=payload)

            if not module.check_mode:
                nd.existing = nd.query_obj(member_path, ignore_not_found_error=True).get("items")
                nd.proposed = payload_dict

            else:
                nd.existing = nd.proposed = payload_dict

    nd.exit_json()


if __name__ == "__main__":
    main()
