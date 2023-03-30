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
version_added: "0.3.0"
short_description: Manage manual configuration type compliance requirements
description:
- Manage manual configuration type compliance requirements on Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  object:
    description:
    - Container for all matching criteria attached to the object.
    type: dict
    suboptions:
      type:
        description:
        - The object type of the object.
        type: str
        required: true
        choices: [ tenant, vrf, bd, epg, contract, subject, filter ]
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
        required: true
        choices: [ name, name_alias, enforcement_preference, enforcement_direction, preferred_group, bd_enforcement,
bd_type, l2_unknown_unicast, l3_unknown_unicast_flooding, bd_multi_destination_flooding, pim, arp_flooding,
limit_ip_learning_to_subnet, unicast_routing, epg_association_count, subnets, preferred_group_member, qos_class ]
      operator:
        description:
        - Operation of the compliance configuration rule.
        type: str
        required: true
        choices: [ contains, begins_with, ends_with, equal_to, not_equal_to, not_contains, not_begins_with, not_ends_with,
regex, exact, at_least, at_most, all, none, at_least_one]
      value:
        description:
        - Value of the compliance configuration rule.
        - WARNING be aware of case sensitivity !!
        type: str
        required: true
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.ndi_compliance_base
"""

EXAMPLES = r"""
- name: Get all manual configuration type compliance requirements
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    state: query
  register: query_results

- name: Get a specific manual configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    name: complianceRequirementName
    state: query
  register: query_results

- name: Create manual configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_manual:
    insights_group: igName
    name: complianceRequirementName
    sites:
    - siteName1
    - siteName2
    enabled: false
    object:
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
    config_rules:
    - attribute: name
      operator: CONTAINS
      value: foo
    state: present

- name: Delete manual configuration type compliance requirement
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
from ansible_collections.cisco.nd.plugins.module_utils.ndi_argument_specs import compliance_base_spec, object_selector_spec
from ansible_collections.cisco.nd.plugins.module_utils.constants import PARAMETER_TYPES, OPERATORS, CONFIG_OPERATORS


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(compliance_base_spec())
    argument_spec.update(
        object=dict(type="dict", options=object_selector_spec(["tenant", "vrf", "bd", "epg", "contract", "subject", "filter"])),
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
            ["state", "present", ["name", "sites", "enabled", "object", "config_rules"]],
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
    object_selector = nd.params.get("object")
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
            "objectSelectorA": get_object_selector_payload(object_selector),
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
