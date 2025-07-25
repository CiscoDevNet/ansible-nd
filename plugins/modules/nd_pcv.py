#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# Copyright: (c) 2025, Samita Bhattacharjee (@samiib) <samitab@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_pcv
version_added: "0.2.0"
short_description: Manage Pre-change Analysis jobs on Cisco Nexus Dashboard Insights (NDI).
description:
- Manage Pre-change Analysis jobs on Cisco Nexus Dashboard Insights (NDI) and Cisco Nexus Dashboard (ND).
author:
- Cindy Zhao (@cizhao)
- Samita Bhattacharjee (@samiib)
options:
  insights_group:
    description:
    - The name of the Insights Group.
    - This option should only be set for NDI versions prior to 6.3. Later versions require this attribute to be set to default.
    type: str
    default: default
    aliases: [ fab_name, ig_name ]
  name:
    description:
    - The name of the Pre-change Analysis job.
    type: str
  description:
    description:
    - Description for the Pre-change Analysis job.
    type: str
    aliases: [ descr ]
  fabric:
    description:
    - The name of the Fabric.
    type: str
    aliases: [ fabric_name, site_name, site ]
  file:
    description:
    - The path to the file used to create a new Pre-change Analysis job.
    - XML and JSON files are supported. If no file extension is provided, the file is assumed to be JSON.
    - This option or O(manual) is required to create a new Pre-change Analysis job.
    type: str
  manual:
    description:
    - The manual change list used to create new Pre-change Analysis job.
    - This option or O(file) is required to create a new Pre-change Analysis job.
    type: str
  job_wait_delay:
    description:
    - The time to wait in seconds between queries to check for Pre-change Analysis job completion.
    - This option is only used when O(state=wait_and_query).
    type: int
    default: 1
    aliases: [ wait_delay ]
  job_wait_timeout:
    description:
    - The total time in seconds to wait for a Pre-change Analysis job to complete before failing the module.
    - This option is only used when O(state=wait_and_query).
    - When the timeout is C(0), not provided or a negative value the module will wait indefinitely.
    type: int
    aliases: [ wait_timeout ]
  state:
    description:
    - Use C(present) or C(absent) for creating or deleting a Pre-change Analysis.
    - Use C(query) for retrieving the PCV information.
    - Use C(wait_and_query) to execute the query until the Pre-change Analysis jobs' status is COMPLETED or FAILED.
    type: str
    choices: [ absent, present, query, wait_and_query ]
    default: query
seealso:
- module: cisco.nd.nd_pcv_compliance
- module: cisco.nd.nd_pcv_delta_analysis
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create a new Pre-change Analysis from JSON file
  cisco.nd.nd_pcv:
    insights_group: igName
    fabric: fabricName
    name: demoName
    file: config_file.json
    state: present

- name: Create a new Pre-change Analysis job from manual changes
  cisco.nd.nd_pcv:
    insights_group: igName
    fabric: fabricName
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

- name: Query the status of all Pre-change Analysis jobs
  cisco.nd.nd_pcv:
    insights_group: igName
    state: query
  register: query_results

- name: Get a specific Pre-change Analysis job status
  cisco.nd.nd_pcv:
    insights_group: igName
    fabric: fabricName
    name: demoName
    state: query
  register: query_result

- name: Wait until Pre-change Analysis job is completed then query status
  cisco.nd.nd_pcv:
    insights_group: igName
    fabric: fabricName
    name: demoName
    job_wait_delay: 2
    job_wait_timeout: 600
    state: wait_and_query

- name: Delete a Pre-change Analysis job
  cisco.nd.nd_pcv:
    insights_group: igName
    fabric: fabricName
    name: demoName
    state: absent
"""

RETURN = r"""
"""

import time
import os
import json
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible.module_utils.basic import AnsibleModule


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", default="default", aliases=["fab_name", "ig_name"]),
        name=dict(type="str"),
        description=dict(type="str", aliases=["descr"]),
        fabric=dict(type="str", aliases=["site", "site_name", "fabric_name"]),
        file=dict(type="str"),
        manual=dict(type="str"),
        job_wait_delay=dict(type="int", default=1, aliases=["wait_delay"]),
        job_wait_timeout=dict(type="int", aliases=["wait_timeout"]),
        state=dict(type="str", default="query", choices=["query", "absent", "present", "wait_and_query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[
            ["file", "manual"],
        ],
        required_if=[
            ["state", "absent", ["name", "fabric"]],
            ["state", "present", ["name", "fabric"]],
            ["state", "present", ["file", "manual"], True],
            ["state", "wait_and_query", ["name", "fabric"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    state = nd.params.get("state")
    name = nd.params.get("name")
    fabric = nd.params.get("fabric")
    insights_group = nd.params.get("insights_group")
    description = nd.params.get("description")
    file = nd.params.get("file")
    manual = nd.params.get("manual")
    wait_delay = nd.params.get("job_wait_delay")
    wait_timeout = nd.params.get("job_wait_timeout")
    if wait_timeout is None or wait_timeout < 0:
        wait_timeout = 0

    path = "config/insightsGroup"
    if name is None:
        nd.existing = ndi.query_pcvs(insights_group)
    elif fabric is not None:
        nd.existing = ndi.query_pcv(insights_group, fabric, name)

    if state == "wait_and_query" and nd.existing:
        status = nd.existing.get("analysisStatus")
        start_time = time.time()
        while status != "COMPLETED":
            try:
                verified_pcv = ndi.query_pcv(insights_group, fabric, name)
                status = verified_pcv.get("analysisStatus")
                if status == "COMPLETED" or status == "FAILED":
                    nd.existing = verified_pcv
                    break
            except BaseException:
                nd.existing = {}
            if wait_timeout and time.time() - start_time >= wait_timeout:
                nd.fail_json(msg="Timeout occurred after {0} seconds while waiting for Pre-change Analysis {1} to complete".format(wait_timeout, name))
            time.sleep(wait_delay)

    elif state == "absent":
        nd.previous = nd.existing
        job_id = nd.existing.get("jobId")
        if nd.existing and job_id:
            if module.check_mode:
                nd.existing = {}
            else:
                rm_path = "{0}/{1}/prechangeAnalysis/jobs".format(path, insights_group)
                rm_payload = [job_id]
                rm_resp = nd.request(rm_path, method="POST", data=rm_payload, prefix=ndi.prefix)
                if rm_resp["success"] is True:
                    nd.existing = {}
                else:
                    nd.fail_json(msg="Pre-change Analysis {0} is not able to be deleted".format(name))

    elif state == "present":
        nd.previous = nd.existing
        if nd.existing:
            pcv_file_name = nd.existing.get("uploadedFileName")
            if file and pcv_file_name:
                if os.path.basename(file) == pcv_file_name:
                    nd.exit_json()
                else:
                    nd.fail_json(msg="Pre-change Analysis {0} already exists with configuration file {1}".format(name, pcv_file_name))
        base_epoch_data = ndi.get_last_epoch(insights_group, fabric)

        data = {
            "allowUnsupportedObjectModification": "true",
            "analysisSubmissionTime": round(time.time() * 1000),
            "baseEpochId": base_epoch_data["epochId"],
            "baseEpochCollectionTimestamp": base_epoch_data["collectionTimeMsecs"],
            "fabricUuid": base_epoch_data["fabricId"],
            "description": description,
            "name": name,
            "assuranceEntityName": fabric,
        }
        if file is not None:
            if not os.path.exists(file):
                nd.fail_json(msg="File not found : {0}".format(file))
            # Check whether the file is a valid XML file. If it's not, check if it's a valid JSON or else process it as a file from cisco.aci modules.
            if ndi.is_xml(open(file, "rb")):
                file_ext = ".xml"
            else:
                if ndi.is_json(open(file, "rb").read()):
                    file_ext = ".json"
                    extract_data = json.loads(open(file, "rb").read())
                else:
                    try:
                        file_ext = ".json"
                        extract_data = ndi.load(open(file))
                    except BaseException:
                        nd.fail_json(msg="Error processing the file. Check if file content is valid.")

                if isinstance(extract_data, list):
                    ndi.cmap = {}
                    tree = ndi.construct_tree(extract_data)
                    ndi.create_structured_data(tree, file)

            # Send REST API request to create a new PCV job
            create_pcv_path = "{0}/{1}/fabric/{2}/prechangeAnalysis/fileChanges".format(path, insights_group, fabric)
            file_resp = nd.request(create_pcv_path, method="POST", file=os.path.abspath(file), file_ext=file_ext, data=data, prefix=ndi.prefix)
            if file_resp.get("success") is True:
                nd.existing = file_resp.get("value")["data"]
        elif manual is not None:
            data["imdata"] = json.loads(manual)
            create_pcv_path = "{0}/{1}/fabric/{2}/prechangeAnalysis/manualChanges?action=RUN".format(path, insights_group, fabric)
            manual_resp = nd.request(create_pcv_path, method="POST", data=data, prefix=ndi.prefix)
            if manual_resp.get("success") is True:
                nd.existing = manual_resp.get("value")["data"]
    nd.exit_json()


if __name__ == "__main__":
    main()
