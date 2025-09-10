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
module: nd_pcv_delta_analysis
version_added: "0.2.0"
short_description: Query Delta Analysis in Pre-change Analysis jobs on Cisco Nexus Dashboard Insights (NDI).
description:
- Query Delta Analysis in Pre-change Analysis jobs on Cisco Nexus Dashboard Insights (NDI) and Cisco Nexus Dashboard (ND).
author:
- Cindy Zhao (@cizhao)
- Samita Bhattacharjee (@samiib)
options:
  insights_group:
    description:
    - The name of the insights group.
    - This attribute should only be set for NDI versions prior to 6.3. Later versions require this attribute to be set to default.
    type: str
    default: default
    aliases: [ fab_name, ig_name ]
  name:
    description:
    - The name of the Pre-change Analysis.
    type: str
    required: true
  fabric:
    description:
    - Name of the Fabric.
    type: str
    required: true
    aliases: [ site, site_name, fabric_name ]
  snapshot_choice:
    description:
    - Choice of which Snapshot/Epoch to report when querying for anomalies.
    - Use later_snapshot/epoch2 to choose anomalies present only in the later_snapshot or epoch2.
    - Use earlier_snapshot/epoch1 to choose anomalies present only in the erlier_snapshot or epoch1.
    - Use both_snapshots/both_epoch to choose anomalies common for both epoch1 and epoch2.
    type: str
    default: later_snapshot
    aliases: [ epoch_choice ]
    choices: [ later_snapshot, earlier_snapshot, both_snapshots, epoch2, epoch1, both_epoch, all ]
  exclude_ack_anomalies:
    description:
    - Option to exclude acknowledged anomalies.
    type: bool
    default: false
  job_wait_delay:
    description:
    - The time to wait in seconds between queries to check for Pre-change Analysis job completion.
    - This option is only used when O(state=validate).
    type: int
    default: 5
    aliases: [ wait_delay ]
  job_wait_timeout:
    description:
    - The total time in seconds to wait for a Pre-change Analysis job to complete before validating.
    - This option is only used when O(state=validate).
    - When the timeout is C(0), not provided or a negative value the module will wait indefinitely.
    type: int
    aliases: [ wait_timeout ]
  state:
    description:
    - Use C(query) for existing Pre-change Delta Analysis results.
    - Use C(validate) to execute the query until the Pre-change Analysis jobs' status value is COMPLETED or FAILED
    - and return an error if any unacknowledged anomalies exist.
    type: str
    default: query
    choices: [ query, validate ]
seealso:
- module: cisco.nd.nd_pcv
- module: cisco.nd.nd_pcv_compliance
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Query Pre-change Delta Analysis results
  cisco.nd.nd_pcv_delta_analysis:
    insights_group: exampleIG
    fabric: exampleFabric
    name: exampleName
    state: query
  register: pcv_result

- name: Query and Validate Pre-change Delta Analysis results
  cisco.nd.nd_pcv_delta_analysis:
    insights_group: exampleIG
    fabric: exampleFabric
    name: exampleName
    state: validate
    exclude_ack_anomalies: true
    snapshot_choice: later_snapshot
    job_wait_delay: 5
    job_wait_timeout: 600
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

snapshot_choice_map = {
    "later_snapshot": "EPOCH2_ONLY",
    "earlier_snapshot": "EPOCH1_ONLY",
    "both_snapshots": "BOTH_EPOCHS",
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
        fabric=dict(type="str", required=True, aliases=["site", "site_name", "fabric_name"]),
        state=dict(type="str", default="query", choices=["query", "validate"]),
        exclude_ack_anomalies=dict(type="bool", default=False),
        snapshot_choice=dict(type="str", default="later_snapshot", choices=list(snapshot_choice_map), aliases=["epoch_choice"]),
        job_wait_delay=dict(type="int", default=5, aliases=["wait_delay"]),
        job_wait_timeout=dict(type="int", aliases=["wait_timeout"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    name = nd.params.get("name")
    fabric = nd.params.get("fabric")
    insights_group = nd.params.get("insights_group")
    snapshot_choice = nd.params.get("snapshot_choice")
    state = nd.params.get("state")
    exclude_ack_anomalies = nd.params.get("exclude_ack_anomalies")
    wait_delay = nd.params.get("job_wait_delay")
    wait_timeout = nd.params.get("job_wait_timeout")
    if wait_timeout is None or wait_timeout < 0:
        wait_timeout = 0

    pcv_result = ndi.query_pcv(insights_group, fabric, name)
    if not pcv_result:
        nd.fail_json(msg="Pre-change Analysis {0} not found".format(name))
    if state == "validate":
        pcv_result = ndi.wait_for_pcv_completion(insights_group, fabric, name, pcv_result, wait_timeout, wait_delay, True)
    else:
        if pcv_result.get("analysisStatus") != "COMPLETED":
            nd.fail_json(msg="Pre-change Analysis {0} is not completed".format(name))
    epoch_delta_job_id = pcv_result.get("epochDeltaJobId")
    nd.existing["anomaly_count"] = ndi.query_event_severity(insights_group, fabric, epoch_delta_job_id)
    anomalies = ndi.query_anomalies(insights_group, fabric, epoch_delta_job_id, snapshot_choice_map[snapshot_choice], exclude_ack_anomalies)
    nd.existing["anomalies"] = anomalies
    if state == "validate" and anomalies:
        anomalies_count = {"minor": 0, "major": 0, "critical": 0, "warning": 0}
        for anomaly in anomalies:
            severity = anomaly.get("severity")
            if severity in anomalies_count.keys():
                anomalies_count[severity] += 1
        nd.fail_json(
            msg="Pre-change Analysis failed. The above {0} (critical({1})|major({2})|minor({3})|warning({4})) anomalies have been detected.".format(
                len(anomalies), anomalies_count.get("critical"), anomalies_count.get("major"), anomalies_count.get("minor"), anomalies_count.get("warning")
            )
        )
    nd.existing["general"] = pcv_result.get("baseEpochCollectionTimeRfc3339")
    nd.existing["unhealthy_resources"] = ndi.query_impacted_resource(insights_group, fabric, epoch_delta_job_id)
    nd.exit_json()


if __name__ == "__main__":
    main()
