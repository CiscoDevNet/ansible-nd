#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_compliance_requirement_communication
version_added: "0.2.1"
short_description: Manage communication type compliance requirements
description:
- Manage communication type compliance requirements on Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  insights_group:
    description:
    - The name of the insights group.
    type: str
    required: yes
    aliases: [ fab_name, ig_name ]
  name:
    description:
    - The name of the compliance requirement.
    type: str
  description:
    description:
    - The description of the compliance requirement.
    type: str
    aliases: [ descr ]
  enabled:
    description:
    - Enable the compliance requirement.
    type: bool
  sites:
    description:
    - Names of the Assurance Entities.
    type: list
    elements: str
  communication_type:
    description:
    - The communication type of the compliance requirement.
    type: str
    choices: [ must, must_not, may ]
  from_object_type:
    description:
    - The object type of 'from' objects.
    type: str
    choices: [ tenant, epg ]
  from_match_criteria:
    description:
    - Container for all matching criteria attached to the 'from' object.
    type: list
    elements: dict
    suboptions:
      match_criteria_type:
        description:
        - Include or exclude the match criteria.
        type: str
        required: true
        choices: [ include, exclude ]
      matches:
        description:
        - Container for all matches in the match criteria.
        type: list
        required: true
        elements: dict
        suboptions:
          object_type:
            description:
            - The object type of the match.
            type: str
            required: yes
            choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
          object_attribute:
            description:
            - The attribute of the match.
            - The GUI represent this as 'By'.
            type: str
            choices: [ DN ]
            default: DN
          matches_pattern:
            description:
            - Container for all patterns attached to the match.
            type: list
            required: yes
            elements: dict
            suboptions:
              match_type:
                description:
                - The type of the match.
                type: str
                required: yes
                choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
              pattern_type:
                description:
                - The type (operator) of the pattern.
                type: str
                required: yes
                choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with ]
              pattern:
                description:
                - The pattern to match on.
                - Not providing a pattern sets to ANY-STRING.
                type: str
  to_object_type:
    description:
    - The object type of 'to' objects.
    type: str
    choices: [ tenant, epg ]
  to_match_criteria:
    description:
    - Container for all matching criteria attached to the 'to' object.
    type: list
    elements: dict
    suboptions:
      match_criteria_type:
        description:
        - Include or exclude the match criteria.
        type: str
        required: true
        choices: [ include, exclude ]
      matches:
        description:
        - Container for all matches in the match criteria.
        type: list
        required: true
        elements: dict
        suboptions:
          object_type:
            description:
            - The object type of the match.
            type: str
            required: yes
            choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
          object_attribute:
            description:
            - The attribute of the match.
            - The GUI represent this as 'By'.
            type: str
            choices: [ DN ]
            default: DN
          matches_pattern:
            description:
            - Container for all patterns attached to the match.
            type: list
            required: yes
            elements: dict
            suboptions:
              match_type:
                description:
                - The type of the match.
                type: str
                required: yes
                choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
              pattern_type:
                description:
                - The type (operator) of the pattern.
                type: str
                required: yes
                choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with ]
              pattern:
                description:
                - The pattern to match on.
                - Not providing a pattern sets to ANY-STRING.
                type: str
  traffic_selector_rules:
    description:
    - Apply rules to selected traffic.
    type: list
    elements: dict
    suboptions:
      ether_type:
        description:
        - The type of the traffic selector.
        type: str
        required: true
        choices: [ arp, fcoe, ip, mac_security, mpls_unicast, trill ]
      protocol_type:
        description:
        - The type of the traffic protocol.
        - Only significant when 'ip' is selected.
        type: str
        choices: [ all, egp, eigrp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp ]
      reverse_port:
        description:
        - The direction of the IP TCP/UDP rule.
        - Only significant when 'ip' is selected in combination with 'tcp' or 'udp'.
        - When set to true the from_object option are used for both directions.
        type: bool
        default: false
      from_object:
        description:
        - Direction from the object.
        type: dict
        suboptions:
          source:
            description:
            - The source port or port range.
            type: str
          destination:
            description:
            - The destination port or port range.
            type: str
          check_tcp_flags:
            description:
            - Check the tcp flags.
            type: bool
          flags_set:
            description:
            - Confirm these flags are set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
          flags_not_set:
            description:
            - Confirm these flags are not set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
      to_object:
        description:
        - Direction to the object.
        type: dict
        suboptions:
          source:
            description:
            - The source port or port range.
            type: str
          destination:
            description:
            - The destination port or port range.
            type: str
          check_tcp_flags:
            description:
            - Check the tcp flags.
            type: bool
          flags_set:
            description:
            - Confirm these flags are set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
          flags_not_set:
            description:
            - Confirm these flags are not set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
  state:
    description:
    - Use C(query) for retrieving the version object.
    type: str
    choices: [ query, absent, present ]
    default: query
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Get all compliance communication type requirements
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    state: query
  register: query_results
- name: Get a specific compliance communication type requirement
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    name: complianceRequirementName
    state: query
  register: query_results
- name: Create compliance communication type requirement
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    name: complianceRequirementName
    sites:
    - siteName1
    - siteName2
    enabled: false
    communication_type: may
    from_object_type: epg
    from_match_criteria:
    - match_criteria_type: include
      matches:
        - object_type: tenant
          object_attribute: DN
          matches_pattern:
            - match_type: tenant
              pattern_type: begins_with
              pattern: foo
            - match_type: vrf
              pattern_type: contains
              pattern: bar
    - match_criteria_type: include
      matches:
        - object_type: epg
          object_attribute: DN
          matches_pattern:
            - match_type: tenant
              pattern_type: contains
              pattern: foo
            - match_type: ap
              pattern_type: contains
              pattern: bar
            - match_type: epg
              pattern_type: contains
              pattern: foobar
    to_object_type: epg
    to_match_criteria:
    - match_criteria_type: include
      matches:
        - object_type: epg
          matches_pattern:
            - match_type: tenant
              pattern_type: contains
              pattern: foo
            - match_type: ap
              pattern_type: contains
              pattern: bar
            - match_type: epg
              pattern_type: contains
              pattern: bar
    traffic_selector_rules:
    - ether_type: ip
      protocol_type: all
    - ether_type: arp
    - ether_type: ip
      protocol_type: tcp
      from_object:
        source: "1"
        destination: "2"
        flags_set: ["ack", "fin", "res", "syn" ]
    state: present
- name: Delete compliance communication type requirement
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    name: complianceRequirementName
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI, get_object_selector_payload
from ansible_collections.cisco.nd.plugins.module_utils.ndi_argument_specs import compliance_base_spec, compliance_match_criteria_spec, compliance_tcp_spec
from ansible_collections.cisco.nd.plugins.module_utils.constants import ETHER_TYPES, PROTOCOL_TYPES


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(compliance_base_spec())
    argument_spec.update(
        communication_type=dict(type="str", choices=["must", "must_not", "may"]),
        from_object_type=dict(type="str", choices=["tenant", "epg"]),  # sub list of list(OBJECT_TYPES)
        from_match_criteria=dict(type="list", elements="dict", options=compliance_match_criteria_spec()),
        to_object_type=dict(type="str", choices=["tenant", "epg"]),  # sub list of list(OBJECT_TYPES)
        to_match_criteria=dict(type="list", elements="dict", options=compliance_match_criteria_spec()),
        traffic_selector_rules=dict(
            type="list",
            elements="dict",
            options=dict(
                ether_type=dict(type="str", required=True, choices=ETHER_TYPES),
                protocol_type=dict(type="str", choices=PROTOCOL_TYPES),
                reverse_port=dict(type="bool", default=False),
                from_object=dict(type="dict", options=compliance_tcp_spec()),
                to_object=dict(type="dict", options=compliance_tcp_spec()),
            ),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            [
                "state",
                "present",
                ["name", "sites", "enabled", "communication_type", "from_object_type", "from_match_criteria", "to_object_type", "to_match_criteria"],
            ],
            ["communication_type", "must", ["traffic_selector_rules"]],
            ["communication_type", "may", ["traffic_selector_rules"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    insights_group = nd.params.get("insights_group")
    name = nd.params.get("name")
    description = nd.params.get("description")
    enabled = nd.params.get("enabled")
    sites = nd.params.get("sites")
    state = nd.params.get("state")
    communication_type = nd.params.get("communication_type")
    from_object_type = nd.params.get("from_object_type")
    from_match_criteria = nd.params.get("from_match_criteria")
    to_object_type = nd.params.get("to_object_type")
    to_match_criteria = nd.params.get("to_match_criteria")
    traffic_selector_rules = nd.params.get("traffic_selector_rules")

    delete_keys = ["uuid", "insightsGroupName", "isAllTraffic", "lastEditedDate", "links", "removeNonConfigAttributes"]
    path = ndi.requirements_path.format(insights_group)

    requirements = [item for item in ndi.query_requirements(insights_group) if item.get("communicationType")]

    uuid = ndi.set_requirement_details(requirements, name)

    if state == "absent" and uuid:

        nd.previous = sanitize_dict(nd.existing, delete_keys)
        if not module.check_mode:
            nd.request(path, method="DELETE", data={"ids": [uuid]}, prefix=ndi.prefix)
        nd.existing = {}

    elif state == "present":
        nd.previous = sanitize_dict(nd.existing, delete_keys)

        payload = {
            "name": name,
            "enabled": enabled,
            "communicationType": communication_type.upper(),
            "requirementType": get_requirement_type(communication_type, traffic_selector_rules),
            "associatedSites": [{"enabled": True, "uuid": ndi.get_site_id(insights_group, site, prefix=ndi.prefix)} for site in sites],
            "objectSelectorA": get_object_selector_payload(from_match_criteria, from_object_type),
            "objectSelectorB": get_object_selector_payload(to_match_criteria, to_object_type),
        }

        if description:
            payload.update(description=description)
        elif nd.existing.get("description"):
            payload.update(description=" ")

        if traffic_selector_rules:
            payload.update(
                complianceTrafficSelector={"includes": {"selectors": [{"selectors": get_compliance_traffic_selector_payload(traffic_selector_rules)}]}}
            )

        if not module.check_mode and payload != nd.previous:
            method = "POST"
            if uuid:
                method = "PUT"
                path = "{0}/{1}".format(path, uuid)
                payload.update(uuid=uuid)
            response = nd.request(path, method=method, data=payload, prefix=ndi.prefix)
            nd.existing = sanitize_dict(response.get("value", {}).get("data", {}), delete_keys)
        else:
            nd.existing = payload

    nd.exit_json()


def get_requirement_type(communication_type, traffic_selector_rules):
    if communication_type == "must":
        return "SLA"
    elif communication_type == "must_not" and not traffic_selector_rules:
        return "SEGMENTATION"
    else:
        return "TRAFFIC_RESTRICTION"


def get_compliance_traffic_selector_payload(traffic_selector_rules):
    payload = []
    for rule in traffic_selector_rules:
        payload.append(get_rule_payload(rule))
    return payload


def get_rule_payload(rule):
    rule_payload = {"etherType": rule.get("ether_type").upper(), "reversePort": rule.get("reverse_port")}
    if rule.get("protocol_type"):
        rule_payload.update(ipProtocol=rule.get("protocol_type").upper())
        if rule.get("protocol_type") == "tcp" or rule.get("protocol_type") == "udp":
            if rule.get("from_object"):
                rule_payload.update(portSelectorAtoB=get_tcp_payload(rule.get("from_object")))
            if not rule.get("reverse_port") and rule.get("to_object"):
                rule_payload.update(portSelectorBtoA=get_tcp_payload(rule.get("to_object")))
    return rule_payload


def get_tcp_payload(tcp_object):
    return {
        "srcPort": tcp_object.get("source"),
        "dstPort": tcp_object.get("destination"),
        "tcpFlag": tcp_object.get("check_tcp_flags"),
        "tcpFlagsSet": tcp_object.get("flags_set"),
        "tcpFlagsNotSet": tcp_object.get("flags_not_set"),
    }


if __name__ == "__main__":
    main()
