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
module: nd_pcv_compliance
version_added: "0.0.1"
short_description: Manage pre-change validation compliance
description:
- Manage pre-change validation compliance on Cisco Nexus Dashboard Insights (NDI).
author:
- Cindy Zhao (@cizhao)
options:
  ig_name:
    description:
    - The name of the insights group.
    type: str
    required: yes
    aliases: [ fab_name ]
  name:
    description:
    - The name of the pre-change validation.
    type: str
  site_name:
    description:
    - Name of the Assurance Entity.
    type: str
    aliases: [ site ]
extends_documentation_fragment: cisco.nd.modules
'''

EXAMPLES = r'''
- name: Get prechange validation compliance result
  cisco.nd.nd_pcv_compliance:
    ig_name: exampleIG
    site_name: exampleSite
    name: exampleName
  delegate_to: localhost
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
        ig_name=dict(type='str', required=True),
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
    ig_name = nd.params.get('ig_name')

    pcv_result = ndi.query_pcv(ig_name, site_name, name)
    pcv_status = pcv_result.get("analysisStatus")
    if pcv_status != "COMPLETED":
        nd.fail_json(msg="Pre-change validation {0} is not completed".format(name))
    compliance_epoch_id = pcv_result.get("preChangeEpochUUID")
    event_path = "{0}/events/insightsGroup/{1}/fabric/{2}".format(ndi.prefix, ig_name, site_name)
    smart_events_path = "{0}/smartEvents?%24epochId={1}&%24page=0&%24size=10&%24sort=-severity&category=COMPLIANCE".format(event_path, compliance_epoch_id)
    nd.stdout = nd.stdout + "query compliance smart event \n"
    nd.existing["smart_events"] = ndi.query_compliance_smart_event(smart_events_path)
    compliance_path = "{0}/model/aciPolicy/complianceAnalysis".format(event_path)
    events_by_severity_path = "{0}/eventsBySeverity?%24epochId={1}".format(compliance_path, compliance_epoch_id)
    nd.existing["events_by_severity"] = ndi.query_msg_with_data(events_by_severity_path)
    unhealthy_resources_path = "{0}/eventUnhealthyResources?%24epochId={1}".format(compliance_path, compliance_epoch_id)
    nd.existing["unhealthy_resources"] = ndi.query_unhealthy_resources(unhealthy_resources_path)
    compliance_score_path = "{0}/complianceScore?%24epochId={1}".format(compliance_path, compliance_epoch_id)
    nd.existing["compliance_score"] = ndi.query_data(compliance_score_path)
    count_path = "{0}/count?%24epochId={1}".format(compliance_path, compliance_epoch_id)
    nd.existing["count"] = ndi.query_data(count_path)
    result_by_requirement_path = "{0}/complianceResultsByRequirement?%24epochId={1}&%24sort=-requirementName&%24page=0&%24size=10".format(compliance_path, compliance_epoch_id)
    nd.existing["result_by_requirement"] = ndi.query_msg_with_data(result_by_requirement_path)

    nd.exit_json()
if __name__ == "__main__":
    main()