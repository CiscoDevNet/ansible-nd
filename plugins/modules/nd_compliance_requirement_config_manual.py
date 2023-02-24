#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_compliance_requirement_config_manual
version_added: "0.2.1"
short_description: Manage manual configuration type compliance requirements
description:
- Manage manual configuration type on Cisco Nexus Dashboard Insights (NDI).
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
  from_object_type:
    description:
    - The object type of 'from' objects.
    type: str
    choices: [ tenant, vrf, bd, epg, contract, subject, filter ]
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
  config_rules:
    description:
    - List of compliance configuration rules.
    type: list
    elements: dict
    suboptions:
      attribute:
        description:
        - Attribute of the compliance configuration rule.
        type: str
        required: yes
        choices: [ name, name_alias, enforcement_preference, enforcement_direction, preferred_group, bd_enforcement,
bd_type, l2_unknown_unicast, l3_unknown_unicast_flooding, bd_multi_destination_flooding, pim, arp_flooding,
limit_ip_learning_to_subnet, unicast_routing, epg_association_count, subnets, preferred_group_member, qos_class ]
      operator:
        description:
        - Operation of the compliance configuration rule.
        type: str
        required: yes
        choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with,
regex, exact, at_least, at_most, all, none, at_least_one]
      value:
        description:
        - Value of the compliance configuration rule.
        - WARNING be aware of case sensitivity !!
        type: str
        required: yes
  state:
    description:
    - Use C(query) for retrieving the version object.
    type: str
    choices: [ query, absent, present ]
    default: query
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Get all compliance manual configuration type requirements
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    state: query
  register: query_results
- name: Get a specific compliance manual configuration type requirement
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    name: complianceRequirementName
    state: query
  register: query_results
- name: Create compliance manual configuration type requirement
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    name: complianceRequirementName
    sites:
    - siteName1
    - siteName2
    enabled: false
    communication_type: may
    from_object_type: epg
    from_match_criteria:
    - from_match_criteria: include
      matches:
      - object_type: vrf
        object_attribute: DN
        matches_pattern:
        - match_type: tenant
          pattern_type: BEGINS_WITH
          pattern: foo
        - match_type: vrf
          pattern_type: CONTAINS
          pattern: bar
    config_rules:
    - attribute: name
      operator: CONTAINS
      value: foo
    state: present
- name: Delete compliance manual configuration type requirement
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    name: complianceRequirementName
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI, get_object_selector_payload
from ansible_collections.cisco.nd.plugins.module_utils.ndi_argument_specs import compliance_base_spec, compliance_match_criteria_spec
from ansible_collections.cisco.nd.plugins.module_utils.constants import OBJECT_TYPES, PARAMETER_TYPES, OPERATORS, CONFIG_OPERATORS


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(compliance_base_spec())
    argument_spec.update(
        from_object_type=dict(type="str", choices=list(OBJECT_TYPES)),
        from_match_criteria=dict(type="list", elements="dict", options=compliance_match_criteria_spec()),
        config_rules=dict(
            type="list",
            elements="dict",
            options=dict(
                attribute=dict(type="str", required=True, choices=list(PARAMETER_TYPES)),
                operator=dict(type="str", required=True, choices=OPERATORS + CONFIG_OPERATORS),
                value=dict(type="str", required=True),
            ),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "sites", "enabled", "from_object_type", "from_match_criteria", "config_rules"]],
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
    from_object_type = nd.params.get("from_object_type")
    from_match_criteria = nd.params.get("from_match_criteria")
    config_rules = nd.params.get("config_rules")

    delete_keys = ["uuid", "insightsGroupName", "isAllTraffic", "lastEditedDate", "links", "removeNonConfigAttributes", "uploadedFileUploadDate"]
    path = ndi.requirements_path.format(insights_group)

    requirements = [item for item in ndi.query_requirements(insights_group) if item.get("configurationType") == "MANUAL_CONFIGURATION_COMPLIANCE"]

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
            "configurationType": "MANUAL_CONFIGURATION_COMPLIANCE",
            "requirementType": "CONFIGURATION_COMPLIANCE",
            "associatedSites": [{"enabled": True, "uuid": ndi.get_site_id(insights_group, site, prefix=ndi.prefix)} for site in sites],
            "objectSelectorA": get_object_selector_payload(from_match_criteria, from_object_type),
            "configComplianceParameter": {
                "andParameters": [
                    {
                        "operator": rule.get("operator").upper(),
                        "parameter": PARAMETER_TYPES.get(rule.get("attribute")).get("parameter_value"),
                        "value": rule.get("value"),
                    }
                    for rule in config_rules
                ]
            },
        }

        if description:
            payload.update(description=description)
        elif nd.existing.get("description"):
            payload.update(description=" ")

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
