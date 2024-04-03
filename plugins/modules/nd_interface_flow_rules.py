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
short_description: Manage Flow Rules
description:
- Manage Interface Flow Rules on Cisco Nexus Dashboard Insights (NDI).
author:
- Gaspard Micol (@gmicol)
options:
  insights_group:
    description:
    - The name of the insights group.
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
  subnets:
    description:
    - The list of the subnets to be added/deleted to a new or existing Flow Rule.
    type: list
    elements: dict
    suboptions:
      subnet:
        description:
        - The IP address of the subnet.
        type: str
      operation:
        description:
        - The type of operation to apply on the subnet.
        - If the I(flow_rule) already exists, C(delete) or C(add) can be used.
        - If not, I(operation) can be left empty if a subnet needs to be added.
        type: str
        choices: [ delete, add ]
        default: add
  state:
    description:
    - Use C(present) to create or update a Flow Rule.
    - Use C(absent) to delete an existing Flow Rule.
    - Use C(query) for listing the existing Flow Rules or a specific Flow rule if I(flow_rule) is specified.
    type: str
    choices: [ present, absent, query ]
    default: query
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
"""

RETURN = r"""
"""

from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.constants import INTERFACE_FLOW_RULES_TYPES_MAPPING, INTERFACE_FLOW_RULES_STATUS_MAPPING
import copy


# Can be moved to ndi.py
def create_flow_rules_node_port(nodes=None, existing_nodes=None, flow_rule_type=None):
    nodes_to_add = []
    nodes_to_update = []
    if isinstance(nodes, list):
        existing_nodes_set = {item["nodeId"] for item in existing_nodes}
        all_nodes_set = existing_nodes_set.union({item["node_id"] for item in nodes})
        for node_id in all_nodes_set:
            check_node_input_id = any(node_input["node_id"] == node_id for node_input in nodes)

            if check_node_input_id and node_id not in existing_nodes_set:
                node_input = next((node for node in nodes if node["node_id"] == node_id))
                node_input_formated = {"nodeId": node_input.get("node_id"), "nodeName": node_input.get("node_name")}
                ports_input_formated = [{"port": port} for port in node_input.get("ports")] if node_input.get("ports") is not None else []
                if flow_rule_type in ["PHYSICAL", "PORTCHANNEL"]:
                    node_input_formated.update({"portsList": ports_input_formated})
                    nodes_to_add.append(copy.deepcopy(node_input_formated))
                    node_input_formated.update({"operation": "ADD"})
                    nodes_to_update.append(node_input_formated)
                else:
                    node_input_formated.update({"tenant": node_input.get("tenant"), "l3outName": node_input.get("l3out"), "encap": node_input.get("encap")})
                    if flow_rule_type == "L3_SUBIF":
                        node_input_formated.update({"portsList": ports_input_formated})
                    nodes_to_add.append(copy.deepcopy(node_input_formated))
                    node_input_formated.update({"operation": "ADD"})
                    nodes_to_update.append(node_input_formated)

            elif not check_node_input_id and node_id in existing_nodes_set:
                node_to_delete = next((existing_node for existing_node in existing_nodes if existing_node["nodeId"] == node_id))
                node_to_delete.update({"operation": "DELETE"})
                nodes_to_update.append(node_to_delete)

            elif check_node_input_id and node_id in existing_nodes_set and flow_rule_type != "SVI":
                ports_input = next((node.get("ports") for node in nodes if node["node_id"] == node_id))
                if isinstance(ports_input, list):
                    existing_node = next((existing_node for existing_node in existing_nodes if existing_node["nodeId"] == node_id))
                    existing_ports, node_uuid = existing_node.get("portsList"), existing_node.get("flowNodeUuid")
                    existing_port_set = {item["port"] for item in existing_ports}
                    all_port_set = existing_port_set.union(ports_input)
                    for port in all_port_set:
                        if port in ports_input and port not in existing_port_set:
                            nodes_to_update.append({"flowNodeUuid": node_uuid, "operation": "MODIFY", "portsList": [{"port": port, "operation": "ADD"}]})
                            nodes_to_add.append(dict(sanitize_dict(existing_node,["flowNodeUuid", "portsList"]), **{"portsList": [{"port": port}]}))
                        elif port not in ports_input and port in existing_port_set:
                            port_uuid = next((existing_port["flowPortUuid"] for existing_port in existing_ports if existing_port["port"] == port))
                            nodes_to_update.append({"flowNodeUuid": node_uuid, "operation": "MODIFY", "portsList": [{"flowPortUuid": port_uuid, "operation": "DELETE"}]})
                        else:
                            nodes_to_add.append(sanitize_dict(existing_node,["flowNodeUuid", "flowPortUuid"]))

            else:
                nodes_to_add.append(sanitize_dict(next((existing_node for existing_node in existing_nodes if existing_node["nodeId"] == node_id)),["flowNodeUuid", "flowPortUuid"]))
    return nodes_to_add, nodes_to_update


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", aliases=["fab_name", "ig_name"]),
        site_name=dict(type="str", aliases=["site"]),
        flow_rule=dict(type="str", aliases=["interface_flow_rule", "flow_rule_name", "name"]),  # Not required to query all objects
        flow_rule_status=dict(type="str",choices=["enabled", "disabled"], aliases=["status"]),
        flow_rule_type=dict(type="str", choices=["port_channel", "physical", "l3out_sub_interface", "l3out_svi"], aliases=["type"]),
        nodes=dict(
            type="list",
            elements="dict",
            options=dict(
                node_id=dict(type="str"),
                node_name=dict(type="str"),
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

    trigger_path = ndi.config_ig_path + "/" + ndi.interface_flow_rules_path.format(insights_group, site_name)
    flow_rules_history = ndi.query_data(trigger_path)
    nd.existing = {}
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
        flow_rule_config = {"name": flow_rule, "state": flow_rule_status, "type": flow_rule_type}
        subnets_to_add, subnets_to_update = ndi.create_flow_rules_subnet_payload(subnets, existing_subnets)
        nodes_to_add, nodes_to_update = create_flow_rules_node_port(nodes, existing_nodes, flow_rule_type)
        flow_rule_config.update(flowRuleAttributeList=subnets_to_add, nodesList=nodes_to_add)
        if flow_rule_config != nd.previous:
            method = "POST"
            payload = {"interfaceFlowRulesList": [flow_rule_config]}
            if uuid:
                method = "PUT"
                trigger_path = "{0}/{1}".format(trigger_path, uuid)
                payload = {"state": flow_rule_status, "nodesList": nodes_to_update, "flowRuleAttributeList": subnets_to_update}
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
