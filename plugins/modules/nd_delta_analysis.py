#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Alejandro de Alda (@adealdag) <adealdag@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_delta_analysis
version_added: "0.2.0"
short_description: Manage delta analysis jobs
description:
- Manage delta analysis jobs on Cisco Nexus Dashboard Insights (NDI).
author:
- Alejandro de Alda (@adealdag)
options:
  insights_group:
    description:
    - The name of the insights group.
    - This attribute should only be set for NDI versions prior to 6.3. Later versions require this attribute to be set to default.
    type: str
    default: default
    aliases: [ fab_name, ig_name ]
  site_name:
    description:
    - Name of the Assurance Entity.
    type: str
    required: true
    aliases: [ site ]
  name:
    description:
    - The name of the delta analysis job
    type: str
    aliases: [ job_name, delta_name ]
  earlier_epoch_id:
    description:
    - Epoch UUID for the earlier epoch
    - Ignored if state is C(query) or C(absent)
    type: str
    aliases: [ earlier_epoch_uuid, earlier_epoch ]
  later_epoch_id:
    description:
    - Epoch UUID for the later epoch
    - Ignored if state is C(query) or C(absent)
    type: str
    aliases: [ later_epoch_uuid, later_epoch ]
  earlier_epoch_time:
    description:
    - Epoch collection time, in ISO format, for the earlier epoch
    - Ignored if state is C(query) or C(absent)
    type: str
  later_epoch_time:
    description:
    - Epoch collection time, in ISO format, for the later epoch
    - Ignored if state is C(query) or C(absent)
    type: str
  state:
    description:
    - Use C(present) or C(absent) for creating or deleting a delta analysis job.
    - Use C(query) for querying existing delta analysis jobs.
    - Use C(validate) to wait for completion, validate and return an error if any unacknowledged anomalies (non-info) exist
    type: str
    choices: [ absent, present, query, validate ]
    default: query
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Creates a new delta analysis job using epoch UUIDs
  cisco.nd.nd_delta_analysis:
    insights_group: exampleIG
    site_name: siteName
    name: testDeltaAnalysis
    earlier_epoch_id: 0e5604f9-53b9c234-03dc-3997-9850-501b925f7d65
    later_epoch_id: 0e5604f9-ad5b12ae-9834-348b-aed1-8ca124e32e9b
    state: present
- name: Creates a new delta analysis job using epoch time
  cisco.nd.nd_delta_analysis:
    insights_group: exampleIG
    site_name: siteName
    name: testDeltaAnalysis
    earlier_epoch_time: 2023-01-15T12:24:34Z
    later_epoch_time: 2023-01-17T18:27:34Z
    state: present
- name: Validates a running delta analysis job
  cisco.nd.nd_delta_analysis:
    insights_group: exampleIG
    site_name: siteName
    name: testDeltaAnalysis
    state: validate
- name: Delete an existing delta analysis
  cisco.nd.nd_delta_analysis:
    insights_group: exampleIG
    site_name: siteName
    name: testDeltaAnalysis
    state: absent
- name: Queries existing delta analysis jobs
  cisco.nd.nd_delta_analysis:
    insights_group: exampleIG
    site_name: siteName
    state: query
  register: query_results
- name: Queries an specific delta analysis job
  cisco.nd.nd_delta_analysis:
    insights_group: exampleIG
    site_name: siteName
    name: testDeltaAnalysis
    state: query
  register: query_results
"""

RETURN = r"""
"""

import datetime
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible.module_utils.basic import AnsibleModule

epoch_map = {
    "epoch2": "EPOCH2_ONLY",
    "epoch1": "EPOCH1_ONLY",
    "both_epoch": "BOTH_EPOCHS",
    "all": None,
}


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", default="default", aliases=["fab_name", "ig_name"]),
        site_name=dict(type="str", required=True, aliases=["site"]),
        name=dict(type="str", aliases=["job_name", "delta_name"]),
        earlier_epoch_id=dict(type="str", aliases=["earlier_epoch_uuid", "earlier_epoch"]),
        later_epoch_id=dict(type="str", aliases=["later_epoch_uuid", "later_epoch"]),
        earlier_epoch_time=dict(type="str"),
        later_epoch_time=dict(type="str"),
        state=dict(type="str", default="query", choices=["query", "absent", "present", "validate"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "validate", ["name"]],
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
            ["state", "present", ("earlier_epoch_id", "earlier_epoch_time"), True],
            ["state", "present", ("later_epoch_id", "later_epoch_time"), True],
        ],
        mutually_exclusive=[("earlier_epoch_id", "earlier_epoch_time"), ("later_epoch_id", "later_epoch_time")],
        required_together=[("earlier_epoch_id", "later_epoch_id"), ("earlier_epoch_time", "later_epoch_time")],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    state = nd.params.get("state")
    insights_group = nd.params.get("insights_group")
    site_name = nd.params.get("site_name")
    name = nd.params.get("name")
    earlier_epoch_id = nd.params.get("earlier_epoch_id")
    later_epoch_id = nd.params.get("later_epoch_id")
    earlier_epoch_time = nd.params.get("earlier_epoch_time")
    later_epoch_time = nd.params.get("later_epoch_time")

    if name:
        nd.existing = ndi.query_delta_analysis(insights_group, site_name, jobName=name)
    else:
        nd.existing = {}

    if state == "query":
        if name is None:
            delta_job_list = ndi.query_delta_analysis(insights_group, site_name)
            nd.existing = delta_job_list

    elif state == "present":
        if earlier_epoch_id and later_epoch_id:
            data = {"jobName": name, "priorEpochUuid": earlier_epoch_id, "laterEpochUuid": later_epoch_id}
        elif earlier_epoch_time and later_epoch_time:
            earlier_epoch_dt = datetime.datetime.fromisoformat(earlier_epoch_time.replace("Z", ""))
            later_epoch_dt = datetime.datetime.fromisoformat(later_epoch_time.replace("Z", ""))
            data = {
                "jobName": name,
                "priorEpochTime": round(earlier_epoch_dt.timestamp() * 1000),
                "laterEpochTime": round(later_epoch_dt.timestamp() * 1000),
            }

        if module.check_mode:
            nd.existing = data
            nd.exit_json()

        nd.previous = nd.existing
        if nd.existing:
            nd.exit_json()

        trigger_path = ndi.config_ig_path + "/" + ndi.run_epoch_delta_ig_path.format(insights_group, site_name)
        resp = nd.request(trigger_path, method="POST", data=data, prefix=ndi.prefix)

        if resp["success"] is True:
            job_id = resp["value"]["data"]["configId"]
            delta_job_info = ndi.query_delta_analysis(insights_group, site_name, jobId=job_id)
            nd.existing = delta_job_info
        else:
            nd.fail_json(msg="Creating delta analysis job failed")

    elif state == "validate":
        epoch_choice = "epoch2"
        exclude_ack_anomalies = True
        # Wait for Epoch Delta Analysis to complete
        while nd.existing.get("operSt") not in ["COMPLETE", "FAILED"]:
            try:
                nd.existing = ndi.query_delta_analysis(insights_group, site_name, jobName=name)
                if nd.existing.get("operSt") == "FAILED":
                    nd.fail_json(msg="Epoch Delta Analysis {0} has failed".format(name))
                if nd.existing.get("operSt") == "COMPLETE":
                    break
            except BaseException:
                nd.fail_json(msg="Epoch Delta Analysis {0} not found".format(name))
        # Evaluate Epoch Delta Analysis
        if nd.existing.get("operSt") == "FAILED":
            nd.fail_json(msg="Epoch Delta Analysis {0} has failed".format(name))

        job_id = nd.existing.get("jobId")
        nd.existing["anomaly_count"] = ndi.query_event_severity(insights_group, site_name, job_id)
        anomalies = ndi.query_anomalies(insights_group, site_name, job_id, epoch_map[epoch_choice], exclude_ack_anomalies)
        nd.existing["anomalies"] = anomalies
        # nd.existing["unhealthy_resources"] = ndi.query_impacted_resource(
        #     insights_group, site_name, job_id)
        if anomalies:
            anomalies_count = {"minor": 0, "major": 0, "critical": 0, "warning": 0}
            for anomaly in anomalies:
                severity = anomaly.get("severity")
                if severity in anomalies_count.keys():
                    anomalies_count[severity] += 1
            nd.fail_json(
                msg="Epoch Delta Analysis failed. The above {0} (critical({1})|major({2})|minor({3})|warning({4})) anomalies have been detected.".format(
                    len(anomalies), anomalies_count.get("critical"), anomalies_count.get("major"), anomalies_count.get("minor"), anomalies_count.get("warning")
                )
            )

    elif state == "absent":
        nd.previous = nd.existing
        job_id = nd.existing.get("jobId")
        if nd.existing and job_id:
            if module.check_mode:
                nd.existing = {}
            else:
                rm_path = ndi.config_ig_path + "/" + "{0}/fabric/{1}/deleteEpochDelta".format(insights_group, site_name)
                rm_payload = [job_id]

                rm_resp = nd.request(rm_path, method="POST", data=rm_payload, prefix=ndi.prefix)

                if rm_resp["success"] is True:
                    nd.existing = {}
                else:
                    nd.fail_json(msg="Delta Analysis {0} could not be deleted".format(name))

    nd.exit_json()


if __name__ == "__main__":
    main()
