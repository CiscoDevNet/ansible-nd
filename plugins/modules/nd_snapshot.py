#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>
# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_snapshot
version_added: "0.3.0"
short_description: Query fabric snapshot/epoch data from Cisco Nexus Dashboard Insights (NDI)
description:
- Query fabric snapshot/epoch data from Cisco Nexus Dashboard Insights (NDI).
- M(cisco.nd.nd_snapshot) can only be used with python 3.7 and higher.
author:
- Akini Ross (@akinross)
- Gaspard Micol (@gmicol)
options:
  insights_group:
    description:
    - The name of the insights group.
    - This attribute should only be set for NDI versions prior to 6.3. Later versions require this attribute to be set to default.
    type: str
    default: default
    aliases: [ fab_name, ig_name ]
  fabric:
    description:
    - The name of the fabric.
    type: str
    required: true
    aliases: [ fabric_name, site, site_name ]
  period:
    description:
    - The snapshot/epoch period.
    type: str
    choices: [ latest, last_15_min, last_hour, last_2_hours, last_6_hours, last_day, last_week]
  from_date:
    description:
    - The starting date and time from which to query snapshot/epoch data.
    - This paramater's input should be in ISO 8601 format "YYYY-MM-DDTHH:MM:SS".
    - Minimum required input is "YYYY-MM-DD".
    type: str
  to_date:
    description:
    - The limit date and time to which query snapshot/epoch data.
    - This paramater's input should be in ISO 8601 format "YYYY-MM-DDTHH:MM:SS".
    - Minimum required input is "YYYY-MM-DD".
    type: str
  range:
    description:
    - Set to return a range of snapshot/epoch IDs or just one.
    type: bool
    default: false
  max_snapshots:
    description:
    - The max amount of snapshot/epoch IDs to be returned.
    - This parameter is used when O(range=true), otherwise it will be ignored.
    type: int
    aliases: [ max_epochs ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Get the latest epoch id
  cisco.nd.nd_snapshot:
    insights_group: igName
    fabric: fabricName
    period: latest
  register: query_results

- name: Get the epoch id from period
  cisco.nd.nd_snapshot:
    insights_group: igName
    fabric: fabricName
    period: last_week
  register: period_last_week

- name: Get all epoch ids from last week
  cisco.nd.nd_snapshot:
    insights_group: igName
    fabric: fabricName
    period: last_week
    range: true
  register: period_last_week

- name: Get 3 epoch ids from last week closest to latest
  cisco.nd.nd_snapshot:
    insights_group: igName
    fabric: fabricName
    period: last_week
    range: true
    max_snapshots: 3
  register: period_last_week

- name: Get all epoch ids from date range
  cisco.nd.nd_snapshot:
    insights_group: igName
    fabric: fabricName
    from_date: 2023-01-01T10:00:00
    to_date: 2023-01-02T14:00:00
    range: true
  register: period_last_week
"""

RETURN = r"""
"""

from datetime import datetime as dt, timedelta
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.constants import EPOCH_DELTA_TYPES


def get_collection_times(to_date_time, from_date_time=None):
    return get_time_delta_msec(from_date_time) if from_date_time else 0, get_time_delta_msec(to_date_time)


def get_time_delta_msec(date_time):
    return int((date_time - dt.fromtimestamp(0)).total_seconds() * 1000)


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", default="default", aliases=["fab_name", "ig_name"]),
        fabric=dict(type="str", required=True, aliases=["fabric_name", "site", "site_name"]),
        period=dict(type="str", choices=list(EPOCH_DELTA_TYPES)),
        from_date=dict(type="str"),
        to_date=dict(type="str"),
        range=dict(type="bool", default=False),
        max_snapshots=dict(type="int", aliases=["max_epochs"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    if not (hasattr(dt, "fromisoformat") and callable(getattr(dt, "fromisoformat"))):
        nd.fail_json(msg="M(cisco.nd.nd_snapshot) can only be used with python 3.7 and higher.")

    insights_group = nd.params.get("insights_group")
    fabric = nd.params.get("fabric")
    period = nd.params.get("period")
    from_date = nd.params.get("from_date")
    to_date = nd.params.get("to_date")
    max_snapshots = nd.params.get("max_snapshots")

    if period:
        to_date = dt.today()
        from_date = to_date - timedelta(seconds=EPOCH_DELTA_TYPES[period]) if period != "latest" else dt.fromtimestamp(0)
    else:
        try:
            to_date = dt.fromisoformat(to_date) if to_date else dt.today()
            from_date = dt.fromisoformat(from_date) if from_date else dt.fromtimestamp(0)
        except ValueError as e:
            nd.fail_json(msg="Query epoch data failed due to: {0}".format(e))

    to_collection, from_collection = get_collection_times(to_date, from_date)

    path = (
        "{0}/epochs?%24fromCollectionTimeMsecs={1}&%24toCollectionTimeMsecs={2}&%24status=FINISHED&%24"
        "epochType=ONLINE%2C+OFFLINE&%24sort=-collectionTime%2C-analysisStartTime".format(
            ndi.event_insight_group_path.format(insights_group, fabric), to_collection, from_collection
        )
    )

    results = nd.query_obj(path, prefix=ndi.prefix).get("value", {}).get("data", [])

    nd.existing = {}
    if period == "latest":
        nd.existing = results[0]
    elif nd.params.get("range"):
        nd.existing = results[0:max_snapshots] if max_snapshots else results
    elif results:
        nd.existing = results[-1]

    nd.exit_json()


if __name__ == "__main__":
    main()
