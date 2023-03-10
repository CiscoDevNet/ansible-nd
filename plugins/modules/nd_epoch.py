#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_epoch
version_added: "0.3.0"
short_description: Query epoch data from Cisco Nexus Dashboard Insights (NDI)
description:
- Query epoch data from Cisco Nexus Dashboard Insights (NDI).
- M(cisco.nd.nd_epoch) can only be used with python 3.7 and higher.
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
  period:
    description:
    - Epoch period.
    type: str
    choices: [ latest, last_15_min, last_hour, last_2_hours, last_6_hours, last_day, last_week]
  from_date:
    description:
    - String representing the date and time in ISO 8601 format "YYYY-MM-DDTHH:MM:SS".
    - Minimum required input is "YYYY-MM-DD".
    type: str
  to_date:
    description:
    - String representing the date and time in ISO 8601 format "YYYY-MM-DDTHH:MM:SS".
    - Minimum required input is "YYYY-MM-DD".
    type: str
  range:
    description:
    - Return a range of epoch IDs or just 1.
    type: bool
    default: false
  max_epochs:
    description:
    - When range is selected, max amount epoch IDs to be returned.
    type: int
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Get latest epoch id
  cisco.nd.nd_epoch:
    insights_group: igName
    site: siteName
    period: latest
  register: query_results

- name: Get epoch id from period
  cisco.nd.nd_epoch:
    insights_group: igName
    site: siteName
    period: last_week
  register: period_last_week

- name: Get all epoch id from last week
  cisco.nd.nd_epoch:
    insights_group: igName
    site: siteName
    period: last_week
    range: true
  register: period_last_week

- name: Get 3 epoch id from last week closest to latest
  cisco.nd.nd_epoch:
    insights_group: igName
    site: siteName
    period: last_week
    range: true
    max_epochs: 3
  register: period_last_week

- name: Get all epoch id from date range
  cisco.nd.nd_epoch:
    insights_group: igName
    site: siteName
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


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", required=True, aliases=["fab_name", "ig_name"]),
        site=dict(type="str", required=True),
        period=dict(type="str", choices=list(EPOCH_DELTA_TYPES)),
        from_date=dict(type="str"),
        to_date=dict(type="str"),
        range=dict(type="bool", default=False),
        max_epochs=dict(type="int"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    if not (hasattr(dt, "fromisoformat") and callable(getattr(dt, "fromisoformat"))):
        nd.fail_json(msg="M(cisco.nd.nd_epoch) can only be used with python 3.7 and higher.")

    insights_group = nd.params.get("insights_group")
    site = nd.params.get("site")
    period = nd.params.get("period")
    from_date = nd.params.get("from_date")
    to_date = nd.params.get("to_date")
    max_epochs = nd.params.get("max_epochs")

    if period:
        to_date = dt.today()
        from_date = to_date - timedelta(seconds=EPOCH_DELTA_TYPES[period]) if period != "latest" else dt.fromtimestamp(0)
    else:
        try:
            to_date = dt.fromisoformat(to_date) if to_date else dt.today()
            from_date = dt.fromisoformat(from_date) if from_date else dt.fromtimestamp(0)
        except ValueError as e:
            nd.fail_json(msg="{0}".format(e))

    to_collection, from_collection = get_collection_times(to_date, from_date)

    path = (
        "{0}/epochs?%24fromCollectionTimeMsecs={1}&%24toCollectionTimeMsecs={2}&%24status=FINISHED&%24"
        "epochType=ONLINE%2C+OFFLINE&%24sort=-collectionTime%2CanalysisStartTime".format(
            ndi.event_insight_group_path.format(insights_group, site), to_collection, from_collection
        )
    )

    results = nd.query_obj(path, prefix=ndi.prefix).get("value", {}).get("data", [])

    if period == "latest":
        nd.existing = results[0]
    elif nd.params.get("range"):
        nd.existing = results[0:max_epochs] if max_epochs else results
    elif results:
        nd.existing = results[-1]
    else:
        nd.existing = {}

    nd.exit_json()


def get_collection_times(to_date_time, from_date_time=None):
    return get_time_delta_msec(from_date_time) if from_date_time else 0, get_time_delta_msec(to_date_time)


def get_time_delta_msec(date_time):
    return int((date_time - dt.fromtimestamp(0)).total_seconds() * 1000)


if __name__ == "__main__":
    main()
