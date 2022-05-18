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
version_added: "0.0.1"
short_description: Manage delta analysis of pre-change validation
description:
- Manage delta analysis of pre-change validation on Cisco Nexus Dashboard Insights (NDI).
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
- name: Get prechange validation delta analysis result
  cisco.nd.nd_pcv_delta_analysis:
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

    name = nd.params.get("name")
    site_name = nd.params.get('site_name')
    ig_name = nd.params.get('ig_name')

    ndi_prefix = '/sedgeapi/v1/cisco-nir/api/api/telemetry/v2'
    path = 'config/insightsGroup'
    pcvs_path = '{0}/{1}/prechangeAnalysis?$sort=-analysisSubmissionTime'.format(path, ig_name)
    pcv_results = nd.get_pcv_results(pcvs_path, prefix=ndi_prefix)
    site_id = nd.get_site_id(path, site_name, prefix=ndi_prefix)
    pcv_path = '{0}/{1}/fabric/{2}/prechangeAnalysis'.format(path, ig_name, site_name)
    pcv_result = nd.get_pre_change_result(pcv_results, name, site_id, pcv_path, prefix=ndi_prefix)
    pcv_status = pcv_result.get("analysisStatus")
    pcv_snapshot_time = pcv_result.get("baseEpochCollectionTimeRfc3339")
    if pcv_status != "COMPLETED":
        nd.fail_json(msg="Pre-change validation {0} is not completed".format(name))
    epoch_delta_job_id = pcv_result.get("epochDeltaJobId")
    delta_analysis_path = "{0}/epochDelta/insightsGroup/{1}/fabric/{2}/job/{3}/health/view".format(ndi_prefix, ig_name, site_name, epoch_delta_job_id)
    event_severity_path = "{0}/eventSeverity".format(delta_analysis_path)
    pcv_event_severity = nd.query_event_severity(event_severity_path)
    nd.existing["event_severity"] = pcv_event_severity
    impacted_resource_path = "{0}/impactedResource".format(delta_analysis_path)
    pcv_impacted_resource = nd.query_impacted_resource(impacted_resource_path)
    nd.existing["impacted_resources"] = pcv_impacted_resource
    pcv_individual_anomalies_path = "{0}/individualTable?epochStatus=BOTH_EPOCHS".format(delta_analysis_path)
    pcv_individual_anomalies = nd.query_entry(pcv_individual_anomalies_path)
    nd.existing["anomalies"] = pcv_individual_anomalies
    nd.existing["general"] = pcv_snapshot_time
    nd.exit_json()
if __name__ == "__main__":
    main()