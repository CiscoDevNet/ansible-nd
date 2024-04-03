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
    type: str
    required: true
    aliases: [ fab_name, ig_name ]
  site_name:
    description:
    - The name of the Assurance Entity.
    type: str
    required: true
    aliases: [ site ]
  flow_rule:
    description:
    - The name of the Flow Rule.
    type: str
    aliases: [ flow_rule_name, name ]
  tenant:
    description:
    - The name of an existing Tenant.
    - Once the Flow Rule is created, This cannot be modified.
    type: str
    aliases: [ tenant_name ]
  vrf:
    description:
    - The name of an existing VRF under the existing I(tenant).
    - Once the Flow Rule is created, This cannot be modified.
    type; str
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
    - Use C(query) for listing the existing Flow Rules or a specific Flow Rule if I(flow_rule) is specified.
    type: str
    choices: [ present, absent, query ]
    default: present
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Create a VRF Flow Rule with subnet
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    tenant: my_tenant
    vrf: my_vrf
    subnets:
      - 10.10.0.0/24
    state: present

- name: Update a VRF Flow Rule by adding subnet 10.10.1.0/24
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    subnets:
      - 10.10.0.0/24
      - 10.10.1.0/24
    state: present

- name: Update a VRF Flow Rule by deleting subnet 10.10.0.0/24
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    subnets:
      - 10.10.1.0/24
    state: present

- name: Update a VRF Flow Rule by deleting all subnets
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    subnets: []
    state: present

- name: Query a specific VRF Flow Rule
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    state: query

- name: Query all VRF Flow Rules
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
    state: query

- name: Delete a VRF Flow Rule
  cisco.nd.nd_flow_rules:
    insights_group: my_ig
    site_name: my_site
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
        insights_group=dict(type="str", aliases=["fab_name", "ig_name"]),
        site_name=dict(type="str", aliases=["site"]),
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
            ["state", "present", ["insights_group", "site_name", "flow_rule"]],
            ["state", "absent", ["insights_group", "site_name", "flow_rule"]],
            ["state", "query", ["insights_group", "site_name"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    state = nd.params.get("state")
    insights_group = nd.params.get("insights_group")
    site_name = nd.params.get("site_name")
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

    trigger_path = ndi.config_ig_path + "/" + ndi.flow_rules_path.format(insights_group, site_name)
    flow_rules_history = ndi.query_data(trigger_path)
    nd.existing = {}
    uuid = None
    existing_subnets = []
    for flow_rules_config in flow_rules_history:
        if flow_rules_config.get("name") == flow_rule:
            nd.existing = sanitize_dict(flow_rules_config, delete_keys)
            uuid = flow_rules_config.get("uuid")
            existing_subnets.extend(flow_rules_config.get("flowRuleAttributeList", []))

    if state == "present":
        nd.previous = nd.existing
        flow_rule_config = {"name": flow_rule, "tenant": tenant, "vrf": vrf}
        subnets_to_add, subnets_to_update = ndi.create_flow_rules_subnet_payload(subnets, existing_subnets)
        flow_rule_config.update(flowRuleAttributeList=subnets_to_add)
        if flow_rule_config != nd.previous:
            method = "POST"
            payload = {"flowRulesList": [flow_rule_config]}
            if uuid:
                method = "PUT"
                trigger_path = "{0}/{1}".format(trigger_path, uuid)
                payload = {"flowRuleAttributeList": subnets_to_update}
            resp = nd.request(trigger_path, method=method, prefix=ndi.prefix, data=payload)
            nd.existing = sanitize_dict(resp.get("value", {}).get("data", [])[0], delete_keys)

    elif state == "query":
        if not flow_rule:
            nd.existing = [sanitize_dict(flow_rules_config, delete_keys) for flow_rules_config in flow_rules_history]

    elif state == "absent":
        nd.previous = nd.existing
        trigger_path = "{0}/{1}".format(trigger_path, uuid)
        resp = nd.request(trigger_path, method="DELETE", prefix=ndi.prefix)
        nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
