# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
import json
import os
import time

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: nd_pcv
version_added: "0.2.0"
short_description: Manage pre-change validation job
description:
- Manage pre-change validation job on Cisco Nexus Dashboard Insights (NDI).
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
    - The name of the pre-change validation job.
    type: str
  description:
    description:
    - Description for the pre-change validation job.
    type: str
    aliases: [ descr ]
  site_name:
    description:
    - Name of the Assurance Entity.
    type: str
    aliases: [ site ]
  file:
    description:
    - Optional parameter if creating new pre-change analysis from file.
    type: str
  manual:
    description:
    - Optional parameter if creating new pre-change analysis from change-list (manual)
    type: str
  state:
    description:
    - Use C(query) for retrieving the version object.
    type: str
    choices: [ query ]
    default: query
extends_documentation_fragment: cisco.nd.modules
'''

EXAMPLES = r'''
- name: Get prechange validation result
  cisco.nd.nd_pcv:
    insights_group: exampleIG
    state: query
  register: query_results
- name: Get a specific prechange validation result
  cisco.nd.nd_pcv:
    insights_group: exampleIG
    site_name: siteName
    name: demoName
    state: query
  register: query_result
- name: Create a new Pre-Change analysis from file
  cisco.nd.nd_pcv:
    insights_group: igName
    site_name: siteName
    name: demoName
    file: configFilePath
    state: present
- name: Present Pre-Change analysis from manual changes
  cisco.nd.nd_pcv:
    insights_group: idName
    site_name: SiteName
    name: demoName
    manual: |
        [
            {
              "fvTenant": {
                "attributes": {
                  "name": "AnsibleTest",
                  "dn": "uni/tn-AnsibleTest",
                  "status": "deleted"
                }
              }
            }
        ]
    state: present
  register: present_pcv_manual
- name: Delete Pre-Change analysis
  cisco.nd.nd_pcv:
    insights_group: igName
    site_name: siteName
    name: demoName
    state: absent
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI

def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type='str', required=True, aliases=[ "fab_name", "ig_name" ]),
        name=dict(type='str'),
        description=dict(type='str', aliases=[ "descr" ]),
        site_name=dict(type='str', aliases=[ "site" ]),
        file=dict(type='str'),
        manual=dict(type='str'),
        state=dict(type='str', default='query', choices=['query', 'absent', 'present']),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[['state', 'absent', ['name'], ['site_name']],
                     ['state', 'present', ['name'], ['site_name']]]
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    state = nd.params.get("state")
    name = nd.params.get("name")
    site_name = nd.params.get('site_name')
    insights_group = nd.params.get('insights_group')
    description = nd.params.get('description')
    file = nd.params.get('file')
    manual = nd.params.get('manual')

    path = 'config/insightsGroup'
    if name is None:
        nd.existing = ndi.query_pcvs(insights_group)
    elif site_name is not None:
        nd.existing = ndi.query_pcv(insights_group, site_name, name)

    if state == 'absent':
        nd.previous = nd.existing
        job_id = nd.existing.get('jobId')
        if nd.existing and job_id:
            if module.check_mode:
                nd.existing = {}
            else:
                rm_path = '{0}/{1}/prechangeAnalysis/jobs'.format(path, insights_group)
                rm_payload = [job_id]
                rm_resp = nd.request(rm_path, method='POST', data=rm_payload, prefix=ndi.prefix)
                if rm_resp["success"] == True:
                    nd.existing = {}
                else:
                    nd.fail_json(msg="Pre-change validation {0} is not able to be deleted".format(name))

    elif state == 'present':
        nd.previous = nd.existing
        # if nd.existing:
        #     nd.exit_json()
        base_epoch_data = ndi.get_epochs(insights_group, site_name)

        data = {
            "allowUnsupportedObjectModification": "true",
            "analysisSubmissionTime": round(time.time() * 1000),
            "baseEpochId": base_epoch_data["epochId"],
            "baseEpochCollectionTimestamp": base_epoch_data["collectionTimeMsecs"],
            "fabricUuid": base_epoch_data["fabricId"],
            "description": description,
            "name": name,
            "assuranceEntityName": site_name,
        }
        if file:
            if not os.path.exists(file):
                nd.fail_json(msg="File not found : {0}".format(file))
            # check whether file content is a valid json
            if ndi.is_json(open(file, "rb").read()) is False:
                extract_data = ndi.load(open(file))
            else:
                extract_data = json.loads(open(file, "rb").read())
            if isinstance(extract_data, list):
                ndi.cmap = {}
                tree = ndi.construct_tree(extract_data)
                ndi.create_structured_data(tree, file)
            with open(file, "rt") as old_fobj, open("output.json", "wt") as new_fobj:
                new_fobj.write(old_fobj.read())
            a_file = open("output.json", "r")
            a_json = json.load(a_file)
            pretty_json = json.dumps(a_json, indent=4)
            a_file.close()
            create_pcv_path = '{0}/{1}/fabric/{2}/prechangeAnalysis/fileChanges'.format(path, insights_group, site_name)
            file_resp = nd.request(create_pcv_path, method='POST', file=os.path.abspath(file), data=data, prefix=ndi.prefix)
            if file_resp.get("success") == True:
                nd.existing = file_resp.get("value")["data"]
        elif manual:
            data["imdata"] = json.loads(manual)
            create_pcv_path = '{0}/{1}/fabric/{2}/prechangeAnalysis/manualChanges?action=RUN'.format(path, insights_group, site_name)
            manual_resp = nd.request(create_pcv_path, method='POST', data=data, prefix=ndi.prefix)
            if manual_resp.get("success") == True:
                nd.existing = manual_resp.get("value")["data"]
        else:
            nd.fail_json(msg="either file or manual is required to create pcv job")
    nd.exit_json()
if __name__ == "__main__":
    main()