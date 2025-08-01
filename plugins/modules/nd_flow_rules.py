#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicolg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_flow_rules
version_added: "0.2.0"
short_description: Manage Flow Rules
description:
- Manage VRF Flow Rules on Cisco Nexus Dashboard Insights (NDI).
author:
- Gaspard Micol (@gmicol)
options:
  insights_group:
    description:
    - The name of the Insights Group.
    - This attribute should only be set for NDI versions prior to 6.3. Later versions require this attribute to be set to default.
    type: str
    default: default
    aliases: [ fab_name, ig_name ]
  fabric:
    description:
    - Name of the fabric.
    type: str
    required: true
    aliases: [ fabric_name, site, site_name ]
  flow_rule:
    description:
    - The name of the Flow Rule.
    type: str
    aliases: [ flow_rule_name, name ]
  tenant:
    description:
    - The name of an existing Tenant.
    - The Flow Rule Tenant cannot be modified.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of an existing VRF under an existing I(tenant).
    - The Flow Rule VRF cannot be modified.
    type: str
    aliases: [ vrf_name ]
  subnets:
    description:
    - The list of subnets to be added or kept in a new or existing Flow Rule.
    - To completely delete all subnets, pass an empty list.
    type: list
    elements: str
  state:
    description:
    - Use C(present) to create or update a Flow Rule.
    - Use C(absent) to delete an existing Flow Rule.
    - Use C(query) for listing all the existing Flow Rules or a specific Flow Rule if I(flow_rule) is specified.
    type: str
    choices: [ present, absent, query ]
    default: present
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Create a VRF Flow Rule with subnet
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    flow_rule: my_FlowRule
    tenant: my_tenant
    vrf: my_vrf
    subnets:
      - 10.10.0.0/24
    state: present

- name: Update a VRF Flow Rule by adding subnet 10.10.1.0/24
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    flow_rule: my_FlowRule
    subnets:
      - 10.10.0.0/24
      - 10.10.1.0/24
    state: present

- name: Update a VRF Flow Rule by deleting subnet 10.10.0.0/24
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    flow_rule: my_FlowRule
    subnets:
      - 10.10.1.0/24
    state: present

- name: Update a VRF Flow Rule by deleting all subnets
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    flow_rule: my_FlowRule
    subnets: []
    state: present

- name: Query a specific VRF Flow Rule
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    flow_rule: my_FlowRule
    state: query

- name: Query all VRF Flow Rules
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    state: query

- name: Delete a VRF Flow Rule
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    fabric: my_fabric
    flow_rule: my_FlowRule
    state: absent
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", default="default", aliases=["fab_name", "ig_name"]),
        fabric=dict(type="str", required=True, aliases=["fabric_name", "site", "site_name"]),
        flow_rule=dict(type="str", aliases=["flow_rule_name", "name"]),  # Not required to query all objects
        tenant=dict(type="str", aliases=["tenant_name"]),
        vrf=dict(type="str", aliases=["vrf_name"]),
        subnets=dict(type="list", elements="str"),
        state=dict(type="str", default="present", choices=["present", "absent", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_if=[
            ["state", "present", ["flow_rule"]],
            ["state", "absent", ["flow_rule"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    state = nd.params.get("state")
    insights_group = nd.params.get("insights_group")
    fabric = nd.params.get("fabric")
    flow_rule = nd.params.get("flow_rule")
    tenant = nd.params.get("tenant")
    vrf = nd.params.get("vrf")
    subnets = nd.params.get("subnets")

    delete_keys = [
        "links",
        "uuid",
        "flowRuleAttributeUuid",
        "fabricName",
    ]

    path = "{0}/{1}".format(ndi.config_ig_path, ndi.flow_rules_path.format(insights_group, fabric))
    flow_rules_history = ndi.query_data(path)
    uuid = None
    existing_subnets = []
    for flow_rules_config in flow_rules_history:
        if flow_rules_config.get("name") == flow_rule:
            nd.existing = sanitize_dict(flow_rules_config, delete_keys)
            uuid = flow_rules_config.get("uuid")
            existing_subnets.extend(flow_rules_config.get("flowRuleAttributeList", []))

    if state == "present":
        nd.previous = nd.existing
        if uuid:
            if isinstance(subnets, list) and [item["subnet"] for item in existing_subnets] != subnets:
                payload = {"flowRuleAttributeList": ndi.create_flow_rules_subnet_payload(subnets, existing_subnets)}
                resp = nd.request("{0}/{1}".format(path, uuid), method="PUT", prefix=ndi.prefix, data=payload)
                nd.existing = sanitize_dict(resp.get("value", {}).get("data", [])[0], delete_keys)
        else:
            subnets_to_add = [{"subnet": subnet} for subnet in subnets] if isinstance(subnets, list) else []
            payload = {"flowRulesList": [{"name": flow_rule, "tenant": tenant, "vrf": vrf, "flowRuleAttributeList": subnets_to_add}]}
            resp = nd.request(path, method="POST", prefix=ndi.prefix, data=payload)
            nd.existing = sanitize_dict(resp.get("value", {}).get("data", [])[0], delete_keys)

    elif state == "query":
        if not flow_rule:
            nd.existing = [sanitize_dict(flow_rules_config, delete_keys) for flow_rules_config in flow_rules_history]

    elif state == "absent":
        nd.previous = nd.existing
        path = "{0}/{1}".format(path, uuid)
        resp = nd.request(path, method="DELETE", prefix=ndi.prefix)
        nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
