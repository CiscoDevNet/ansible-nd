# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: nd_pcv_delta_analysis
version_added: "0.2.0"
short_description: Query delta analysis of pre-change validation
description:
- Query delta analysis of pre-change validation on Cisco Nexus Dashboard Insights (NDI).
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
'''

EXAMPLES = r'''
- name: Get prechange validation delta analysis result
  cisco.nd.nd_pcv_delta_analysis:
    insights_group: exampleIG
    site_name: exampleSite
    name: exampleName
  register: query_results
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI

def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type='str', required=True),
        name=dict(type='str', required=True),
        site_name=dict(type='str', required=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    name = nd.params.get("name")
    site_name = nd.params.get('site_name')
    insights_group = nd.params.get('insights_group')

    pcv_result = ndi.query_pcv(insights_group, site_name, name)
    if pcv_result.get("analysisStatus") != "COMPLETED":
        nd.fail_json(msg="Pre-change validation {0} is not completed".format(name))
    epoch_delta_job_id = pcv_result.get("epochDeltaJobId")
    nd.existing["event_severity"] = ndi.query_event_severity(insights_group, site_name, epoch_delta_job_id)
    nd.existing["impacted_resources"] = ndi.query_impacted_resource(insights_group, site_name, epoch_delta_job_id)
    nd.existing["anomalies"] = ndi.query_entry(insights_group, site_name, epoch_delta_job_id)
    nd.existing["general"] = pcv_result.get("baseEpochCollectionTimeRfc3339")
    nd.exit_json()
if __name__ == "__main__":
    main()