# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_compliance_analysis
version_added: "0.2.1"
short_description: Query compliance analysis data from Cisco Nexus Dashboard Insights (NDI)
description:
- Query compliance analysis data from Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  insights_group:
    description:
    - The name of the insights group.
    type: str
    required: yes
    aliases: [ fab_name, ig_name ]
  site:
    description:
    - Names of the Assurance Entity.
    type: str
    required: yes
  epoch_id:
    description:
    - The id of the epoch.
    - When epoch id is not provided it will retrieve the latest known epoch id.
    type: str
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Run compliance analysis for latest epoch id
  cisco.nd.nd_compliance_analysis:
    insights_group: igName
    site: siteName
  register: query_results

- name: Run compliance analysis with specified epoch id
  cisco.nd.nd_compliance_analysis:
    insights_group: igName
    site: siteName
    epoch_id: 0e5604f9-373a123c-b535-33fc-8d11-672d08f65fd1
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
        site=dict(type="str", required=True),
        epoch_id=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    insights_group = nd.params.get("insights_group")
    site = nd.params.get("site")
    epoch_id = nd.params.get("epoch_id")

    if not epoch_id:
        epoch_id = ndi.get_last_epoch(insights_group, site).get("epochId")

    nd.existing["smart_events"] = ndi.query_compliance_smart_event(insights_group, site, epoch_id)
    nd.existing["events_by_severity"] = ndi.query_msg_with_data(insights_group, site, "eventsBySeverity?%24epochId={0}".format(epoch_id))
    nd.existing["unhealthy_resources"] = ndi.query_unhealthy_resources(insights_group, site, epoch_id)
    nd.existing["compliance_score"] = ndi.query_compliance_score(insights_group, site, epoch_id)
    nd.existing["count"] = ndi.query_compliance_count(insights_group, site, epoch_id)
    nd.existing["result_by_requirement"] = ndi.query_msg_with_data(
        insights_group, site, "complianceResultsByRequirement?%24epochId={0}&%24sort=-requirementName&%24page=0&%24size=10".format(epoch_id)
    )

    nd.exit_json()


if __name__ == "__main__":
    main()
