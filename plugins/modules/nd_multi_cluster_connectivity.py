#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Shreyas Srish (@shrsr) <ssrish@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_multi_cluster_connectivity
version_added: "1.0.0"
short_description: Manages cluster configurations on Cisco Nexus Dashboard.
description:
- This module allows for the management of clusters on Cisco Nexus Dashboard.
- This module is only supported on ND v4.1 and later.
author:
- Shreyas Srish (@shrsr)
options:
  cluster_type:
    description:
    - The type of the cluster.
    type: str
    choices: [ nd, apic ]
  cluster_hostname:
    description:
    - The hostname or IP address of the cluster.
    type: str
  cluster_username:
    description:
    - The username for authenticating with the cluster.
    type: str
  cluster_password:
    description:
    - The password for authenticating with the cluster.
    - This value is not logged in the output.
    type: str
  cluster_login_domain:
    description:
    - The login domain for the cluster.
    type: str
  multi_cluster_login_domain:
    description:
    - The multi-cluster login domain.
    type: str
  fabric_name:
    description:
    - The name of the fabric to which the cluster belongs.
    type: str
  license_tier:
    description:
    - The license tier for the cluster.
    type: str
    choices: [ advantage, essentials, premier ]
  features:
    description:
    - A list of features to enable on the cluster.
    type: list
    elements: str
    choices: [ telemetry, orchestration ]
  inband_epg:
    description:
    - The in-band EPG (Endpoint Group) for the cluster.
    type: str
  outband:
    description:
    - The out-of-band management configuration for the cluster.
    type: str
  orchestration:
    description:
    - Enable or disable orchestration for the cluster.
    type: bool
  security_domain:
    description:
    - The security domain for the cluster.
    type: str
  validate_peer_certificate:
    description:
    - Whether to validate the peer's SSL/TLS certificate.
    type: bool
  state:
    description:
    - Use C(present) to create or update a cluster configuration.
    - Use C(absent) to delete a cluster configuration.
    - Use C(query) to retrieve cluster configurations.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create ND cluster
  cisco.nd.nd_multi_cluster_connectivity:
    cluster_type: nd
    cluster_hostname: cluster-IP
    cluster_username: admin
    cluster_password: cluster-password
    state: present

- name: Connect an ACI cluster with features
  cisco.nd.nd_multi_cluster_connectivity:
    cluster_type: apic
    fabric_name: test_aci
    cluster_hostname: cluster-IP
    cluster_username: admin
    cluster_password: cluster-password
    license_tier: premier
    features:
      - orchestration
    inband_epg: ansible-inband
    state: present

- name: Query ND cluster
  cisco.nd.nd_multi_cluster_connectivity:
    cluster_hostname: cluster-IP
    state: query
  register: query_result

- name: Query an ACI cluster
  cisco.nd.nd_multi_cluster_connectivity:
    fabric_name: test_aci
    state: query
  register: query_result

- name: Query all the clusters
  cisco.nd.nd_multi_cluster_connectivity:
    state: query
  register: query_result

- name: Delete ND cluster
  cisco.nd.nd_multi_cluster_connectivity:
    cluster_hostname: cluster-IP
    state: absent

- name: Delete an ACI cluster
  cisco.nd.nd_multi_cluster_connectivity:
    fabric_name: test_aci
    cluster_username: admin
    cluster_password: cluster-password
    state: absent
"""

RETURN = r"""
"""

from copy import deepcopy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        cluster_type=dict(type="str", choices=["nd", "apic"]),
        cluster_hostname=dict(type="str"),
        cluster_username=dict(type="str"),
        cluster_password=dict(type="str", no_log=True),
        cluster_login_domain=dict(type="str"),
        multi_cluster_login_domain=dict(type="str"),
        fabric_name=dict(type="str"),
        license_tier=dict(type="str", choices=["advantage", "essentials", "premier"]),
        features=dict(type="list", elements="str", choices=["telemetry", "orchestration"]),
        inband_epg=dict(type="str"),
        outband=dict(type="str"),
        orchestration=dict(type="bool"),
        security_domain=dict(type="str"),
        validate_peer_certificate=dict(type="bool"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["cluster_hostname", "cluster_username", "cluster_password", "cluster_type"]],
        ],
    )

    nd = NDModule(module)

    cluster_type = nd.params.get("cluster_type").upper() if nd.params.get("cluster_type") else nd.params.get("cluster_type")
    cluster_hostname = nd.params.get("cluster_hostname")
    cluster_username = nd.params.get("cluster_username")
    cluster_password = nd.params.get("cluster_password")
    cluster_login_domain = nd.params.get("cluster_login_domain")
    multi_cluster_login_domain = nd.params.get("multi_cluster_login_domain")
    license_tier = nd.params.get("license_tier")
    features = nd.params.get("features")
    inband_epg = nd.params.get("inband_epg")
    fabric_name = nd.params.get("fabric_name")
    telemetry = {}
    if features and "telemetry" in features:
        telemetry["status"] = "enabled"
        if inband_epg:
            telemetry["network"] = "inband"
            telemetry["epg"] = "uni/tn-mgmt/mgmtp-default/inb-{0}".format(inband_epg)
        else:
            telemetry["network"] = "outband"
    else:
        telemetry["status"] = "disabled"
    orchestration = {}
    if features and "orchestration" in features:
        orchestration["status"] = "enabled"
    else:
        orchestration["status"] = "disabled"
    security_domain = nd.params.get("security_domain")
    validate_peer_certificate = nd.params.get("validate_peer_certificate")
    state = nd.params.get("state")

    path = "/api/v1/infra/clusters"
    if fabric_name:
        nd.existing = nd.previous = deepcopy(nd.query_obj("{0}/{1}".format(path, fabric_name), ignore_not_found_error=True)) or {}
    elif cluster_hostname:
        nd.existing = nd.previous = (
            deepcopy(nd.get_object_by_nested_key_value(path, nested_key_path="spec.onboardUrl", value=cluster_hostname, data_key="clusters")) or {}
        )
        if nd.existing:
            fabric_name = nd.existing.get("spec").get("name")
    else:
        nd.existing = nd.previous = nd.query_objs(path, key="clusters")

    if state == "present":
        payload = {
            "spec": {
                "clusterType": cluster_type,
                "onboardUrl": cluster_hostname,
                "credentials": {
                    "user": cluster_username,
                    "password": cluster_password,
                    "logindomain": cluster_login_domain,
                },
            }
        }

        if cluster_type == "APIC":
            payload["spec"]["aci"] = {
                "licenseTier": license_tier,
                "name": fabric_name,
                "securityDomain": security_domain,
                "verifyCA": validate_peer_certificate,
                "telemetry": telemetry,
                "orchestration": orchestration,
            }
        elif cluster_type == "ND" and multi_cluster_login_domain:
            payload["spec"]["nd"] = {"multiClusterLoginDomainName": multi_cluster_login_domain}

        nd.sanitize(payload)

        if module.check_mode:
            nd.existing = nd.proposed
        else:
            if not nd.existing:
                nd.existing = nd.request(path, method="POST", data=payload)
            elif nd.get_diff(
                unwanted=[
                    ["spec", "credentials"],
                    ["spec", "aci", "name"],
                    ["spec", "aci", "telemetry"],
                    ["spec", "aci", "orchestration"],
                    ["spec", "aci", "licenseTier"],
                ]
            ):
                payload["spec"]["name"] = fabric_name
                update_path = "{0}/{1}".format(path, fabric_name)
                nd.request(update_path, method="PUT", data=payload)
                nd.existing = nd.query_obj(update_path)

    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                payload = {}
                if cluster_type == "APIC":
                    payload = {
                        "credentials": {
                            "user": cluster_username,
                            "password": cluster_password,
                        }
                    }
                nd.request("{0}/{1}/remove".format(path, fabric_name), method="POST", data=payload)
            nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
