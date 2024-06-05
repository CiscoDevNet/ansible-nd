#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicolg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_interface_flow_rules
version_added: "0.2.0"
short_description: Manage Interface Flow Rules
description:
- Manage Interface Flow Rules on Cisco Nexus Dashboard Insights (NDI).
author:
- Gaspard Micol (@gmicol)
options:
  insights_group:
    description:
    - The name of the insights group.
    type: str
    default: default
    aliases: [ fab_name, ig_name ]
  site:
    description:
    - The name of the Assurance Entity.
    type: str
    required: true
    aliases: [ site_name ]
  flow_rule:
    description:
    - The name of the Interface Flow Rule.
    type: str
    aliases: [ interface_flow_rule, flow_rule_name, name ]
  flow_rule_type:
    description:
    - The type of Interface Flow Rule.
    - It defines what could be configured in I(nodes).
    type: str
    choices: [ port_channel, physical, l3out_sub_interface, l3out_svi ]
    aliases: [ type ]
  flow_rule_status:
    description:
    - The status of the Interface Flow Rule.
    - It can be C(enabled) or C(disabled).
    - If C(disabled), the Interface Flow Rule cannot be modified or updated.
    type: str
    default: enabled
    choices: [ enabled, disabled ]
    aliases: [ status ]
  nodes:
    description:
    - The list of configured nodes on which to apply the Interface Flow Rule.
    - To completely delete all nodes, pass an empty list.
    type: list
    elements: dict
    suboptions:
      node_id:
        description:
        - The node's ID.
        type: str
        required: true
        aliases: [ id ]
      node_name:
        description:
        - The name of the node.
        type: str
        required: true
        aliases: [ name ]
      tenant:
        description:
        - The name of the tenant.
        - It can only be used if O(flow_rule_type=l3out_sub_interface) or O(flow_rule_type=l3out_svi).
        type: str
      l3out:
        description:
        - The name of the L3Out under the tenant.
        - It can only be used if O(flow_rule_type=l3out_sub_interface) or O(flow_rule_type=l3out_svi).
        type: str
      encap:
        description:
        - The name of the encap under the L3Out.
        -  It can only be used if O(flow_rule_type=l3out_sub_interface) or O(flow_rule_type=l3out_svi).
        type: str
      ports:
        description:
        - The list of ports to be added or kept in a new or existing Flow Rule.
        - It cannot be used if O(flow_rule_type=l3out_svi).
        - To completely delete all ports, pass an empty list.
        type: list
        elements: str
  subnets:
    description:
    - The list of subnets to be added or kept in a new or existing Flow Rule.
    - To completely delete all subnets, pass an empty list.
    type: list
    elements: str
  state:
    description:
    - Use C(present) to create or update an Interface Flow Rule.
    - Use C(absent) to delete an existing Interface Flow Rule.
    - Use C(query) for listing all the existing Interface Flow Rules,
      all the existing Interface Flow Rules of a specific type if I(flow_rule_type) is specified
      or a specific Interface Flow Rule if I(flow_rule) is specified.
    type: str
    choices: [ present, absent, query ]
    default: present
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Create a Physical Interface Flow Rule with subnet
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    flow_rule_type: physical
    flow_rule_status: enabled
    nodes:
      - node_id: 1
        node_name: my_node_1
        ports:
          - eth1/1
          - eth1/2
      - node_id: 2
        node_name: my_node_2
        ports:
          - eth1/10
    subnets:
      - 10.10.0.0/24
    state: present

- name: Update a Physical Interface Flow Rule by adding the node my_node_3
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    nodes:
      - node_id: 1
        node_name: my_node_1
        ports:
          - eth1/1
          - eth1/2
      - node_id: 2
        node_name: my_node_2
        ports:
          - eth1/1
      - node_id: 3
        node_name: my_node_3
        ports:
          - eth1/1
    state: present

- name: Update a Physical Interface Flow Rule by removing the node my_node_2
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    nodes:
      - node_id: 1
        node_name: my_node_1
        ports:
          - eth1/1
          - eth1/2
      - node_id: 3
        node_name: my_node_3
        ports:
          - eth1/1
    state: present

- name: Update a Physical Interface Flow Rule by adding port eth1/2 to my_node_3 and removing port eth1/1 from my_node_1
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    nodes:
      - node_id: 1
        node_name: my_node_1
        ports:
          - eth1/2
      - node_id: 3
        node_name: my_node_3
        ports:
          - eth1/1
          - eth1/2
    state: present

- name: Update a Physical Interface Flow Rule by removing all ports from my_node_3
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    nodes:
      - node_id: 1
        node_name: my_node_1
        ports:
          - eth1/2
      - node_id: 3
        node_name: my_node_3
        ports: []
    state: present

- name: Update a Physical Interface Flow Rule by removing all nodes
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    nodes: []
    state: present

- name: Update a Physical Interface Flow Rule by adding subnet 10.10.1.0/24
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    subnets:
      - 10.10.0.0/24
      - 10.10.1.0/24
    state: present

- name: Update a Physical Interface Flow Rule by deleting subnet 10.10.0.0/24
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    subnets:
      - 10.10.1.0/24
    state: present

- name: Update a Physical Interface Flow Rule by deleting all subnets
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    subnets: []
    state: present

- name: Query a specific Physical Interface Flow Rule
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    state: query

- name: Query all Physical Interface Flow Rules
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule_type: physical
    state: query

- name: Query all Interface Flow Rules
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    state: query

- name: Delete a Physical Interface Flow Rule
  cisco.nd.nd_interface_flow_rules:
    insights_group: my_ig
    site_name: my_site
    flow_rule: my_FlowRule
    state: absent
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict, sanitize_list
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.constants import INTERFACE_FLOW_RULES_TYPES_MAPPING, INTERFACE_FLOW_RULES_STATUS_MAPPING


def reformat_nodes_input(nodes=None, flow_rule_type=None):
    nodes_formated = []
    for node in nodes:
        node_formated = {"nodeId": node.get("node_id"), "nodeName": node.get("node_name")}
        if flow_rule_type in ["L3_SUBIF", "SVI"]:
            node_formated.update({"tenant": node.get("tenant"), "l3outName": node.get("l3out"), "encap": node.get("encap")})
        if flow_rule_type in ["PHYSICAL", "PORTCHANNEL", "L3_SUBIF"]:
            ports_formated = [{"port": port} for port in node.get("ports")] if node.get("ports") else []
            node_formated.update({"portsList": ports_formated})
        nodes_formated.append(node_formated)
    return nodes_formated


def create_all_nodes_list(nodes_formated=None, existing_nodes=None):
    nodes_formated_sanitized = sanitize_list(nodes_formated, ["portsList"])
    existing_nodes_sanitized = sanitize_list(existing_nodes, ["portsList", "flowNodeUuid"])
    set_nodes_formated = {tuple(sorted(node.items())) for node in nodes_formated_sanitized}
    set_existing_nodes = {tuple(sorted(node.items())) for node in existing_nodes_sanitized}
    all_nodes_set = sorted(set_existing_nodes.union(set_nodes_formated))
    all_nodes_list = [dict(node) for node in all_nodes_set]
    return nodes_formated_sanitized, existing_nodes_sanitized, all_nodes_list


def update_flow_rules_nodes_payload(nodes=None, existing_nodes=None, flow_rule_type=None):
    nodes_to_update = []
    if isinstance(nodes, list):
        nodes_formated = reformat_nodes_input(nodes, flow_rule_type)
        nodes_formated_sanitized, existing_nodes_sanitized, all_nodes_list = create_all_nodes_list(nodes_formated, existing_nodes)
        for node in all_nodes_list:
            if node in nodes_formated_sanitized and node not in existing_nodes_sanitized:
                node_to_add = next(item for item in nodes_formated if sanitize_dict(item, ["portsList"]) == node)
                node_to_add.update({"operation": "ADD"})
                nodes_to_update.append(node_to_add)

            elif node not in nodes_formated_sanitized and node in existing_nodes_sanitized:
                node_to_remove = next(item for item in existing_nodes if sanitize_dict(item, ["portsList", "flowNodeUuid"]) == node)
                node_to_remove.update({"operation": "DELETE"})
                nodes_to_update.append(node_to_remove)

            elif node in nodes_formated_sanitized and node in existing_nodes_sanitized and flow_rule_type != "SVI":
                ports_input = next(item.get("portsList") for item in nodes_formated if sanitize_dict(item, ["portsList"]) == node)
                ports_input = {item["port"] for item in ports_input}
                existing_node = next(item for item in existing_nodes if sanitize_dict(item, ["portsList", "flowNodeUuid"]) == node)
                existing_ports, node_uuid = existing_node.get("portsList"), existing_node.get("flowNodeUuid")
                existing_port_set = {item["port"] for item in existing_ports}
                if ports_input != existing_port_set:
                    all_port_set = sorted(existing_port_set.union(ports_input))
                    for port in all_port_set:
                        if port in ports_input and port not in existing_port_set:
                            nodes_to_update.append({"flowNodeUuid": node_uuid, "operation": "MODIFY", "portsList": [{"port": port, "operation": "ADD"}]})
                        elif port not in ports_input and port in existing_port_set:
                            port_uuid = next((existing_port["flowPortUuid"] for existing_port in existing_ports if existing_port["port"] == port))
                            nodes_to_update.append(
                                {
                                    "flowNodeUuid": node_uuid,
                                    "operation": "MODIFY",
                                    "portsList": [{"flowPortUuid": port_uuid, "operation": "DELETE"}],
                                }
                            )
    return nodes_to_update


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", default="default", aliases=["fab_name", "ig_name"]),
        site=dict(type="str", required=True, aliases=["site_name"]),
        flow_rule=dict(type="str", aliases=["interface_flow_rule", "flow_rule_name", "name"]),  # Not required to query all objects
        flow_rule_status=dict(type="str", default="enabled", choices=["enabled", "disabled"], aliases=["status"]),
        flow_rule_type=dict(type="str", choices=["port_channel", "physical", "l3out_sub_interface", "l3out_svi"], aliases=["type"]),
        nodes=dict(
            type="list",
            elements="dict",
            options=dict(
                node_id=dict(type="str", required=True, aliases=["id"]),
                node_name=dict(type="str", required=True, aliases=["name"]),
                tenant=dict(type="str"),
                l3out=dict(type="str"),
                encap=dict(type="str"),
                ports=dict(type="list", elements="str"),
            ),
        ),
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
    site = nd.params.get("site")
    flow_rule = nd.params.get("flow_rule")
    flow_rule_status = INTERFACE_FLOW_RULES_STATUS_MAPPING.get(nd.params.get("flow_rule_status"))
    flow_rule_type = INTERFACE_FLOW_RULES_TYPES_MAPPING.get(nd.params.get("flow_rule_type"))
    nodes = nd.params.get("nodes")
    subnets = nd.params.get("subnets")

    delete_keys = [
        "links",
        "uuid",
        "flowRuleAttributeUuid",
        "fabricName",
        "flowNodeUuid",
        "flowPortUuid",
    ]

    path = "{0}/{1}".format(ndi.config_ig_path, ndi.interface_flow_rules_path.format(insights_group, site))
    flow_rules_history = ndi.query_data(path)
    uuid = None
    existing_subnets = []
    existing_nodes = []
    for flow_rules_config in flow_rules_history:
        if flow_rules_config.get("name") == flow_rule:
            nd.existing = sanitize_dict(flow_rules_config, delete_keys)
            uuid = flow_rules_config.get("uuid")
            existing_subnets.extend(flow_rules_config.get("flowRuleAttributeList", []))
            existing_nodes.extend(flow_rules_config.get("nodesList", []))

    if state == "present":
        nd.previous = nd.existing
        if uuid:
            payload = {}
            nodes_to_update = update_flow_rules_nodes_payload(nodes, existing_nodes, flow_rule_type)
            payload.update({"nodesList": nodes_to_update})
            if isinstance(subnets, list) and [item["subnet"] for item in existing_subnets] != subnets:
                payload.update({"flowRuleAttributeList": ndi.create_flow_rules_subnet_payload(subnets, existing_subnets)})
            else:
                payload.update({"flowRuleAttributeList": []})
            if nd.previous.get("state") != flow_rule_status:
                payload.update({"state": flow_rule_status})
            if any(payload.get(k) for k in payload.keys()):
                resp = nd.request("{0}/{1}".format(path, uuid), method="PUT", prefix=ndi.prefix, data=payload)
                nd.existing = sanitize_dict(resp.get("value", {}).get("data", [])[0], delete_keys)
        else:
            nodes_to_add = []
            if isinstance(nodes, list):
                for node in nodes:
                    node_to_add = {"nodeId": node.get("node_id"), "nodeName": node.get("node_name")}
                    if flow_rule_type in ["PHYSICAL", "PORTCHANNEL", "L3_SUBIF"]:
                        ports_to_add = [{"port": port} for port in node.get("ports")] if node.get("ports") else []
                        node_to_add.update({"portsList": ports_to_add})
                    if flow_rule_type in ["SVI", "L3_SUBIF"]:
                        node_to_add.update({"tenant": node.get("tenant"), "l3outName": node.get("l3out"), "encap": node.get("encap")})
                    nodes_to_add.append(node_to_add)
            subnets_to_add = [{"subnet": subnet} for subnet in subnets] if isinstance(subnets, list) else []
            payload = {
                "interfaceFlowRulesList": [
                    {
                        "name": flow_rule,
                        "state": flow_rule_status,
                        "type": flow_rule_type,
                        "nodesList": nodes_to_add,
                        "flowRuleAttributeList": subnets_to_add,
                    },
                ],
            }
            resp = nd.request(path, method="POST", prefix=ndi.prefix, data=payload)
            nd.existing = sanitize_dict(resp.get("value", {}).get("data", [])[0], delete_keys)

    elif state == "query":
        if not flow_rule and not flow_rule_type:
            nd.existing = [sanitize_dict(flow_rules_config, delete_keys) for flow_rules_config in flow_rules_history]
        elif flow_rule_type and not flow_rule:
            nd.existing = [
                sanitize_dict(flow_rules_config, delete_keys)
                for flow_rules_config in flow_rules_history
                if flow_rules_config.get("type", "") == flow_rule_type
            ]

    elif state == "absent":
        nd.previous = nd.existing
        path = "{0}/{1}".format(path, uuid)
        resp = nd.request(path, method="DELETE", prefix=ndi.prefix)
        nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
