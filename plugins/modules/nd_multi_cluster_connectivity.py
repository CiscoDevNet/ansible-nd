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
  config:
    description:
    - The configuration to manage clusters on Cisco Nexus Dashboard.
    type: list
    elements: dict
    suboptions:
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
      security_domain:
        description:
        - The security domain for the cluster.
        type: str
      validate_peer_certificate:
        description:
        - Whether to validate the peer's SSL/TLS certificate.
        type: bool
    required: true
  state:
    description:
    - The desired state of the network resources on the Cisco Nexus Dashboard.
    - Use O(state=merged) to create new resources and updates existing ones as defined in your configuration.
      Resources on the Cisco Nexus Dashboard that are not specified in the configuration will be left unchanged.
    - Use O(state=replaced) to replace the resources specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      The resources on the Cisco Nexus Dashboard will be modified to exactly match the configuration.
      Any resource existing on the dashboard but not present in the configuration will be deleted. Use with caution.
    - Use O(state=deleted) to remove the resources specified in the configuration from the Cisco Nexus Dashboard.
    type: str
    choices: [ merged, replaced, deleted, overridden ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- If ACI clusters are part of a multi-cluster configuration, overriding the state will cause the module to throw an error.
  This occurs because the API expects a payload containing credentials to process the removal of the ACI clusters.
- An API limitation requires that the features and license tier are configured at the time an ACI cluster is first connected.
  These settings cannot be modified later.
"""

EXAMPLES = r"""
- name: Connect clusters in the config
  cisco.nd.nd_multi_cluster_connectivity:
    config:
      - cluster_type: nd
        cluster_hostname: nd_cluster_host
        cluster_username: nd_cluster_username
        cluster_password: nd_cluster_password
      - cluster_type: apic
        fabric_name: ansible_test_2
        cluster_hostname: aci_cluster_host
        cluster_username: aci_cluster_username
        cluster_password: aci_cluster_password
        license_tier: advantage
        features:
          - orchestration
        inband_epg: ansible-inband
      - cluster_type: apic
        fabric_name: ansible_test
        cluster_hostname: aci_cluster_host2
        cluster_username: aci_cluster_username2
        cluster_password: aci_cluster_password2
        license_tier: advantage
        features:
          - orchestration
        inband_epg: ansible-inband
    state: merged

- name: Delete clusters in the config
  cisco.nd.nd_multi_cluster_connectivity:
    config:
      - cluster_hostname: nd_cluster_host
      - cluster_hostname: aci_cluster_host
        cluster_username: aci_cluster_username
        cluster_password: aci_cluster_password
      - cluster_hostname: aci_cluster_host2
        cluster_username: aci_cluster_username2
        cluster_password: aci_cluster_password2
    state: deleted
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def get_cluster_unique_key(cluster_data):
    return cluster_data.get("spec", {}).get("onboardUrl")


def module_input_to_api_payload(cluster_data_from_module_input):
    cluster_type = cluster_data_from_module_input.get("cluster_type").upper() if cluster_data_from_module_input.get("cluster_type") else None
    payload = {
        "spec": {
            "clusterType": cluster_type,
            "onboardUrl": cluster_data_from_module_input.get("cluster_hostname"),
            "credentials": {
                "user": cluster_data_from_module_input.get("cluster_username"),
                "password": cluster_data_from_module_input.get("cluster_password"),
                "logindomain": cluster_data_from_module_input.get("cluster_login_domain"),
            },
        }
    }
    if cluster_type == "APIC":
        telemetry = {}
        features = cluster_data_from_module_input.get("features", [])
        if features and "telemetry" in features:
            telemetry["status"] = "enabled"
            if cluster_data_from_module_input.get("inband_epg"):
                telemetry["network"] = "inband"
                telemetry["epg"] = "uni/tn-mgmt/mgmtp-default/inb-{0}".format(cluster_data_from_module_input.get("inband_epg"))
            else:
                telemetry["network"] = "outband"
        else:
            telemetry["status"] = "disabled"

        orchestration = {}
        if features and "orchestration" in features:
            orchestration["status"] = "enabled"
        else:
            orchestration["status"] = "disabled"

        payload["spec"]["aci"] = {
            "licenseTier": cluster_data_from_module_input.get("license_tier"),
            "name": cluster_data_from_module_input.get("fabric_name"),
            "securityDomain": cluster_data_from_module_input.get("security_domain"),
            "verifyCA": cluster_data_from_module_input.get("validate_peer_certificate"),
            "telemetry": telemetry,
            "orchestration": orchestration,
        }
    elif cluster_type == "ND" and cluster_data_from_module_input.get("multi_cluster_login_domain"):
        payload["spec"]["nd"] = {"multiClusterLoginDomainName": cluster_data_from_module_input.get("multi_cluster_login_domain")}
    return payload


# def convert_api_response_to_payload_format(api_response_cluster_data):
#     spec = api_response_cluster_data.get("spec", {})
#     cluster_type = spec.get("clusterType")

#     payload = {
#         "spec": {
#             "clusterType": cluster_type,
#             "onboardUrl": spec.get("onboardUrl"),
#             "name": spec.get("name"),
#         }
#     }

#     if cluster_type == "APIC":
#         aci_spec = spec.get("aci", {})
#         telemetry_api = aci_spec.get("telemetry", {})
#         orchestration_api = aci_spec.get("orchestration", {})

#         telemetry_payload = {
#             "status": telemetry_api.get("status", "disabled")
#         }
#         if telemetry_api.get("network"):
#             telemetry_payload["network"] = telemetry_api["network"]
#         if telemetry_api.get("epg"):
#             telemetry_payload["epg"] = telemetry_api["epg"]

#         orchestration_payload = {
#             "status": orchestration_api.get("status", "disabled")
#         }

#         payload["spec"]["aci"] = {
#             "licenseTier": aci_spec.get("licenseTier"),
#             "name": aci_spec.get("name"),
#             "securityDomain": aci_spec.get("securityDomain"),
#             "verifyCA": aci_spec.get("verifyCA"),
#             "telemetry": telemetry_payload,
#             "orchestration": orchestration_payload,
#         }
#     elif cluster_type == "ND":
#         nd_spec = spec.get("nd", {})
#         if nd_spec.get("multiClusterLoginDomainName"):
#             payload["spec"]["nd"] = {"multiClusterLoginDomainName": nd_spec.get("multiClusterLoginDomainName")}

#     return payload


def create_cluster(nd):
    path = "/api/v1/infra/clusters"
    response = nd.proposed
    if not nd.module.check_mode:
        response = nd.request(path, method="POST", data=nd.proposed)
    return response


def update_cluster(nd):
    path = "/api/v1/infra/clusters"
    fabric_name_for_api_path = nd.existing.get("spec", {}).get("name")
    response = payload = nd.proposed
    payload["spec"]["name"] = fabric_name_for_api_path
    if not nd.module.check_mode:
        response = nd.request("{0}/{1}".format(path, fabric_name_for_api_path), method="PUT", data=payload)
    return response


def delete_cluster(nd):
    path = "/api/v1/infra/clusters"
    fabric_name_for_api_path = nd.existing.get("spec", {}).get("name")
    response = payload = {}
    if nd.existing.get("spec", {}).get("clusterType", "").upper() == "APIC":
        payload = {
            "credentials": {
                "user": nd.proposed.get("spec", {}).get("credentials", {}).get("user"),
                "password": nd.proposed.get("spec", {}).get("credentials", {}).get("password"),
            }
        }
    if not nd.module.check_mode:
        response = nd.request("{0}/{1}/remove".format(path, fabric_name_for_api_path), method="POST", data=payload)
    return response


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        config=dict(
            type="list",
            elements="dict",
            options=dict(
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
                security_domain=dict(type="str"),
                validate_peer_certificate=dict(type="bool"),
            ),
            required=True,
        ),
        state=dict(type="str", default="merged", choices=["merged", "replaced", "overridden", "deleted"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    desired_clusters_from_module_input = nd.params.get("config")
    state = nd.params.get("state")

    desired_clusters_map = {}
    for cluster_data_input in desired_clusters_from_module_input:
        normalized_payload = module_input_to_api_payload(cluster_data_input)
        desired_clusters_map[get_cluster_unique_key(normalized_payload)] = normalized_payload

    existing_clusters_raw = nd.query_objs("/api/v1/infra/clusters", key="clusters")

    existing_clusters_map = {}
    for cluster_data_raw in existing_clusters_raw:
        # normalized_payload = convert_api_response_to_payload_format(cluster_data_raw)
        existing_clusters_map[get_cluster_unique_key(cluster_data_raw)] = cluster_data_raw

    callbacks = {
        "update_callback": update_cluster,
        "create_callback": create_cluster,
        "delete_callback": delete_cluster,
    }

    nd.manage_state(
        state,
        desired_clusters_map,
        existing_clusters_map,
        callbacks,
        unwanted_keys=[
            ["spec", "credentials"],
            ["spec", "aci", "name"],
            ["spec", "aci", "telemetry"],
            ["spec", "aci", "orchestration"],
            ["spec", "aci", "licenseTier"],
        ],
    )

    nd.exit_json()


if __name__ == "__main__":
    main()
