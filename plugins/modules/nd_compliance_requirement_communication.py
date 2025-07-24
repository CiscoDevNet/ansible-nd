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
version_added: "0.3.0"
short_description: Manage communication type compliance requirements
description:
- Manage communication type compliance requirements on Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  type:
    description:
    - The communication type of the compliance requirement.
    type: str
    choices: [ must, must_not, may ]
  from_object:
    description:
    - Container for all matching criteria attached to the object.
    type: dict
    suboptions:
      type:
        description:
        - The object type of the object.
        type: str
        required: true
        choices: [ tenant, epg ]
      includes:
        description:
        - Container for all matching criteria to include.
        type: list
        required: true
        elements: dict
        suboptions:
          type:
            description:
            - The object type of the match.
            type: str
            required: true
            choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
          attribute:
            description:
            - The attribute of the match.
            - The GUI represent this as 'By'.
            type: str
            choices: [ DN ]
            default: DN
          patterns:
            description:
            - Container for all patterns attached to the match.
            type: list
            required: true
            elements: dict
            suboptions:
              type:
                description:
                - The type of the match.
                type: str
                required: true
                choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
              operator:
                description:
                - The operator of the pattern.
                type: str
                required: true
                choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with ]
              value:
                description:
                - The value of the pattern to match on.
                - NDO defaults to a wildcard string, displayed in UI as ANY-STRING, when unset during creation.
                type: str
      excludes:
        description:
        - Container for all matching criteria to exclude.
        type: list
        elements: dict
        suboptions:
          type:
            description:
            - The object type of the match.
            type: str
            required: true
            choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
          attribute:
            description:
            - The attribute of the match.
            - The GUI represent this as 'By'.
            type: str
            choices: [ DN ]
            default: DN
          patterns:
            description:
            - Container for all patterns attached to the match.
            type: list
            required: true
            elements: dict
            suboptions:
              type:
                description:
                - The type of the match.
                type: str
                required: true
                choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
              operator:
                description:
                - The operator of the pattern.
                type: str
                required: true
                choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with ]
              value:
                description:
                - The value of the pattern to match on.
                - NDO defaults to a wildcard string, displayed in UI as ANY-STRING, when unset during creation.
                type: str
  to_object:
    description:
    - Container for all matching criteria attached to the object.
    type: dict
    suboptions:
      type:
        description:
        - The object type of the object.
        type: str
        required: true
        choices: [ tenant, epg ]
      includes:
        description:
        - Container for all matching criteria to include.
        type: list
        required: true
        elements: dict
        suboptions:
          type:
            description:
            - The object type of the match.
            type: str
            required: true
            choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
          attribute:
            description:
            - The attribute of the match.
            - The GUI represent this as 'By'.
            type: str
            choices: [ DN ]
            default: DN
          patterns:
            description:
            - Container for all patterns attached to the match.
            type: list
            required: true
            elements: dict
            suboptions:
              type:
                description:
                - The type of the match.
                type: str
                required: true
                choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
              operator:
                description:
                - The operator of the pattern.
                type: str
                required: true
                choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with ]
              value:
                description:
                - The value of the pattern to match on.
                - NDO defaults to a wildcard string, displayed in UI as ANY-STRING, when unset during creation.
                type: str
      excludes:
        description:
        - Container for all matching criteria to exclude.
        type: list
        elements: dict
        suboptions:
          type:
            description:
            - The object type of the match.
            type: str
            required: true
            choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
          attribute:
            description:
            - The attribute of the match.
            - The GUI represent this as 'By'.
            type: str
            choices: [ DN ]
            default: DN
          patterns:
            description:
            - Container for all patterns attached to the match.
            type: list
            required: true
            elements: dict
            suboptions:
              type:
                description:
                - The type of the match.
                type: str
                required: true
                choices: [ tenant, vrf, bd, epg, ap, l3out, l3instp, l2out, l2instp, filter, subject, contract ]
              operator:
                description:
                - The operator of the pattern.
                type: str
                required: true
                choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with ]
              value:
                description:
                - The value of the pattern to match on.
                - NDO defaults to a wildcard string, displayed in UI as ANY-STRING, when unset during creation.
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
      protocol:
        description:
        - The type of the traffic protocol.
        - Only significant when 'ip' is selected.
        type: str
        choices: [ all, egp, eigrp, icmp, icmpv6, igmp, igp, l2tp, ospfigp, pim, tcp, udp ]
      reverse_port:
        description:
        - The direction of the IP TCP/UDP rule.
        - Only significant when 'ip' is selected in combination with 'tcp' or 'udp'.
        - When set to true the from_object option is used for both directions.
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
          tcp_flags:
            description:
            - Confirm these flags are set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
            aliases: [ tcp_flags_set ]
          tcp_flags_not_set:
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
          tcp_flags:
            description:
            - Confirm these flags are set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
            aliases: [ tcp_flags_set ]
          tcp_flags_not_set:
            description:
            - Confirm these flags are not set.
            type: list
            elements: str
            choices: [ ack, est, fin, res, syn ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
- cisco.nd.ndi_compliance_base
"""

EXAMPLES = r"""
- name: Get all communication type compliance requirements
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    state: query
  register: query_results

- name: Get a specific communication type compliance requirement
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    name: complianceRequirementName
    state: query
  register: query_results

- name: Create communication type compliance requirement
  cisco.nd.nd_compliance_requirement_communication:
    insights_group: igName
    name: complianceRequirementName
    fabrics:
      - fabricName1
      - fabricName2
    enabled: false
    type: may
    from_object:
      type: epg
      includes:
        - type: vrf
          attribute: DN
          patterns:
            - type: tenant
              operator: begins_with
              value: foo
            - type: vrf
              operator: contains
              value: bar
        - type: epg
          attribute: DN
          patterns:
            - type: tenant
              operator: contains
              value: foo
            - type: ap
              operator: contains
              value: bar
            - type: epg
              operator: contains
              value: foobar
    to_object:
      type: epg
      excludes:
        - type: epg
          patterns:
            - type: tenant
              operator: contains
              value: foo
            - type: ap
              operator: contains
              value: bar
            - type: epg
              operator: contains
              value: bar
    traffic_selector_rules:
      - ether_type: ip
        protocol: all
      - ether_type: arp
      - ether_type: ip
        protocol: tcp
        from_object:
          source: "1"
          destination: "2"
          tcp_flags: ["ack", "fin", "res", "syn"]
    state: present

- name: Delete communication type compliance requirement
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
from ansible_collections.cisco.nd.plugins.module_utils.ndi_argument_specs import compliance_base_spec, object_selector_spec, compliance_tcp_spec
from ansible_collections.cisco.nd.plugins.module_utils.constants import ETHER_TYPES, PROTOCOL_TYPES


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
    if rule.get("protocol"):
        rule_payload.update(ipProtocol=rule.get("protocol").upper())
        if rule.get("protocol") == "tcp" or rule.get("protocol") == "udp":
            if rule.get("from_object"):
                rule_payload.update(portSelectorAtoB=get_tcp_payload(rule.get("from_object")))
            if not rule.get("reverse_port") and rule.get("to_object"):
                rule_payload.update(portSelectorBtoA=get_tcp_payload(rule.get("to_object")))
    return rule_payload


def get_tcp_payload(tcp_object):
    return {
        "srcPort": tcp_object.get("source") if tcp_object.get("source") else "",
        "dstPort": tcp_object.get("destination") if tcp_object.get("destination") else "",
        "tcpFlag": True if tcp_object.get("tcp_flags") or tcp_object.get("tcp_flags_not_set") else False,
        "tcpFlagsSet": tcp_object.get("tcp_flags") if tcp_object.get("tcp_flags") else [],
        "tcpFlagsNotSet": tcp_object.get("tcp_flags_not_set") if tcp_object.get("tcp_flags_not_set") else [],
    }


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(compliance_base_spec())
    argument_spec.update(
        type=dict(type="str", choices=["must", "must_not", "may"]),
        from_object=dict(type="dict", options=object_selector_spec(["tenant", "epg"])),
        to_object=dict(type="dict", options=object_selector_spec(["tenant", "epg"])),
        traffic_selector_rules=dict(
            type="list",
            elements="dict",
            options=dict(
                ether_type=dict(type="str", required=True, choices=ETHER_TYPES),
                protocol=dict(type="str", choices=PROTOCOL_TYPES),
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
            ["state", "present", ["name", "fabrics", "enabled", "type", "from_object", "to_object"]],
            ["type", "must", ["traffic_selector_rules"]],
            ["type", "may", ["traffic_selector_rules"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    insights_group = nd.params.get("insights_group")
    name = nd.params.get("name")
    description = nd.params.get("description")
    enabled = nd.params.get("enabled")
    fabrics = nd.params.get("fabrics")
    state = nd.params.get("state")
    communication_type = nd.params.get("type")
    from_object_selector = nd.params.get("from_object")
    to_object_selector = nd.params.get("to_object")
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
            "associatedSites": [{"enabled": True, "uuid": ndi.get_site_id(insights_group, fabric, prefix=ndi.prefix)} for fabric in fabrics],
            "objectSelectorA": get_object_selector_payload(from_object_selector),
            "objectSelectorB": get_object_selector_payload(to_object_selector),
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


if __name__ == "__main__":
    main()
