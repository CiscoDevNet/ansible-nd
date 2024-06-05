#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Cindy Zhao (@cizhao) <cizhao@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
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
    default: default
    aliases: [ fab_name, ig_name ]
  name:
    description:
    - The name of the pre-change validation.
    type: str
    required: true
  site_name:
    description:
    - Name of the Assurance Entity.
    type: str
    required: true
    aliases: [ site ]
  epoch_choice:
    description:
    - Choice of which Epoch to report when querying for anomalies.
    - Use epoch2 to choose anomalies present only in epoch2.
    - Use epoch1 to choose anomalies present only in epoch1.
    - Use both_epoch to choose anomalies common for both epoch1 and epoch2.
    type: str
    default: epoch2
    choices: [ epoch2, epoch1, both_epoch, all ]
  state:
    description:
    - Use C(query) for existing pre-change analysis result.
    - Use C(validate) to execute the query until pre-change verification task status value is COMPLETED
    - Use C(validate) to return an error if any unacknowledged anomalies exist
    type: str
    default: query
    choices: [ query, validate ]
  exclude_ack_anomalies:
    description:
    - Option to exclude anomalies which is acknowledged
    type: bool
    default: false
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Query prechange validation delta analysis result
  cisco.nd.nd_pcv_delta_analysis:
    insights_group: exampleIG
    site_name: exampleSite
    name: exampleName
- name: Query and Validate Pre-Change Analysis results
  cisco.nd.nd_pcv_delta_analysis:
    insights_group: exampleIG
    site_name: exampleSite
    name: exampleName
    state: validate
    exclude_ack_anomalies: 'yes'
    epoch_choice: epoch2
  register: pcv_result
- name: Custom validation of Pre-Change Analysis results
  ansible.builtin.assert:
    that:
      - pcv_result.current.anomaly_count.critical.epoch2_only == 0
      - pcv_result.current.anomaly_count.major.epoch2_only == 0
      - pcv_result.current.anomaly_count.minor.epoch2_only == 0
      - pcv_result.current.anomaly_count.warning.epoch2_only == 0
    success_msg: "Pre-change Analysis successful, no new anomalies found"
    fail_msg: "Pre-change Analysis failed, new anomalies have been found"
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI

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
        name=dict(type="str", required=True),
        site_name=dict(type="str", required=True, aliases=["site"]),
        state=dict(type="str", default="query", choices=["query", "validate"]),
        exclude_ack_anomalies=dict(type="bool", default=False),
        epoch_choice=dict(type="str", default="epoch2", choices=["epoch2", "epoch1", "both_epoch", "all"]),
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
    epoch_choice = nd.params.get("epoch_choice")
    state = nd.params.get("state")
    exclude_ack_anomalies = nd.params.get("exclude_ack_anomalies")

    pcv_result = ndi.query_pcv(insights_group, site_name, name)
    if not pcv_result:
        nd.fail_json(msg="Pre-change validation {0} not found".format(name))
    if state == "validate":
        status = pcv_result.get("analysisStatus")
        while status != "COMPLETED":
            try:
                verified_pcv = ndi.query_pcv(insights_group, site_name, name)
                status = verified_pcv.get("analysisStatus")
                if status == "FAILED":
                    nd.fail_json(msg="Pre-change validation {0} is failed".format(name))
                if status == "COMPLETED":
                    pcv_result = verified_pcv
                    break
            except BaseException:
                nd.fail_json(msg="Pre-change validation {0} not found".format(name))
    else:
        if pcv_result.get("analysisStatus") != "COMPLETED":
            nd.fail_json(msg="Pre-change validation {0} is not completed".format(name))
    epoch_delta_job_id = pcv_result.get("epochDeltaJobId")
    nd.existing["anomaly_count"] = ndi.query_event_severity(insights_group, site_name, epoch_delta_job_id)
    anomalies = ndi.query_anomalies(insights_group, site_name, epoch_delta_job_id, epoch_map[epoch_choice], exclude_ack_anomalies)
    nd.existing["anomalies"] = anomalies
    if state == "validate" and anomalies:
        anomalies_count = {"minor": 0, "major": 0, "critical": 0, "warning": 0}
        for anomaly in anomalies:
            severity = anomaly.get("severity")
            if severity in anomalies_count.keys():
                anomalies_count[severity] += 1
        nd.fail_json(
            msg="Pre-change analysis failed. The above {0} (critical({1})|major({2})|minor({3})|warning({4})) anomalies have been detected.".format(
                len(anomalies), anomalies_count.get("critical"), anomalies_count.get("major"), anomalies_count.get("minor"), anomalies_count.get("warning")
            )
        )
    nd.existing["general"] = pcv_result.get("baseEpochCollectionTimeRfc3339")
    nd.existing["unhealthy_resources"] = ndi.query_impacted_resource(insights_group, site_name, epoch_delta_job_id)
    nd.exit_json()


if __name__ == "__main__":
    main()
