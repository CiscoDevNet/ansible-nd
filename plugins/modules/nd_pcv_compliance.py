#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_pcv_compliance
version_added: "0.2.0"
short_description: Query pre-change validation compliance
description:
- Query pre-change validation compliance on Cisco Nexus Dashboard Insights (NDI).
author:
- Cindy Zhao (@cizhao)
options:
  insights_group:
    description:
    - The name of the insights group.
    type: str
    required: yes
    aliases: [ fab_name, ig_name ]
  name:
    description:
    - The name of the pre-change validation.
    type: str
    required: yes
  site_name:
    description:
    - Name of the Assurance Entity.
    type: str
    required: yes
    aliases: [ site ]
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Get prechange validation compliance result
  cisco.nd.nd_pcv_compliance:
    insights_group: exampleIG
    site_name: exampleSite
    name: exampleName
  register: query_results
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", required=True, aliases=["fab_name", "ig_name"]),
        name=dict(type="str", required=True),
        site_name=dict(type="str", required=True, aliases=["site"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    name = nd.params.get("name")
    site_name = nd.params.get("site_name")
    insights_group = nd.params.get("insights_group")

    pcv_result = ndi.query_pcv(insights_group, site_name, name)
    pcv_status = pcv_result.get("analysisStatus")
    if pcv_status != "COMPLETED":
        nd.fail_json(msg="Pre-change validation {0} is not completed".format(name))
    compliance_epoch_id = pcv_result.get("preChangeEpochUUID")
    nd.existing["smart_events"] = ndi.query_compliance_smart_event(insights_group, site_name, compliance_epoch_id)
    nd.existing["events_by_severity"] = ndi.query_msg_with_data(insights_group, site_name, "eventsBySeverity?%24epochId={0}".format(compliance_epoch_id))
    nd.existing["unhealthy_resources"] = ndi.query_unhealthy_resources(insights_group, site_name, compliance_epoch_id)
    nd.existing["compliance_score"] = ndi.query_compliance_score(insights_group, site_name, compliance_epoch_id)
    nd.existing["count"] = ndi.query_compliance_count(insights_group, site_name, compliance_epoch_id)
    nd.existing["result_by_requirement"] = ndi.query_msg_with_data(
        insights_group, site_name, "complianceResultsByRequirement?%24epochId={0}&%24sort=-requirementName&%24page=0&%24size=10".format(compliance_epoch_id)
    )
    nd.exit_json()


if __name__ == "__main__":
    main()
