#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_backup_schedule
version_added: "0.5.0"
short_description: Manages backup schedule on Cisco Nexus Dashboard.
description:
- Manage backup schedule on Cisco Nexus Dashboard.
- This module is only supported on ND v4.1 and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  name:
    description:
    - The name of the backup schedule.
    type: str
  encryption_key:
    description:
    - The encryption_key for a backup file.
    type: str
  remote_location:
    description:
    - The name of the remote storage location.
    type: str
  frequency:
    description:
    - The frequency at which remote backups are scheduled to occur at specified intervals on selected days.
    type: int
  scheduler_date:
    description:
    - The start date for the backup schedule in the format O(scheduler_date="YYYY-MM-DD").
    type: str
    aliases: [ scheduler_start_date, start_date, date ]
  scheduler_time:
    description:
    - The start time for the backup schedule in the format O(scheduler_date="HH-MM-SS").
    type: str
    aliases: [ scheduler_start_time, start_time, time ]
  backup_type:
    description:
    - This parameter specifies the kind of snapshot created for the Nexus Dashboard.
    - The O(backup_type=config_only) option creates a snapshot that specifically captures the configuration settings of the Nexus Dashboard.
    - The O(backup_type=full) option creates a complete snapshot of the entire Nexus Dashboard.
    type: str
    choices: [ config_only, full ]
    default: config_only
    aliases: [ type ]
  state:
    description:
    - Use C(present) for creating a backup schedule.
    - Use C(query) for listing the backup schedule.
    - Use C(absent) for deleting a backup schedule.
    type: str
    choices: [ present, query, absent ]
    default: present
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create a backup schedule
  cisco.nd.nd_backup_schedule:
    name: backupschedule1
    encryption_key: testtest1
    frequency: 7
    scheduler_date: "2025-01-02"
    scheduler_time: "15:04:05"
    remote_location: test
    state: present

- name: Update a backup schedule
  cisco.nd.nd_backup_schedule:
    name: backupschedule1
    encryption_key: testtest2
    frequency: 30
    remote_location: test
    state: present

- name: Query a backup schedule
  cisco.nd.nd_backup_schedule:
    name: backupschedule1
    state: query
  register: query_one

- name: Query all backup schedules
  cisco.nd.nd_backup_schedule:
    state: query
  register: query_all

- name: Delete a backup schedule
  cisco.nd.nd_backup_schedule:
    name: backupschedule1
    state: absent
"""

RETURN = r"""
"""


import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.utils import snake_to_camel


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        name=dict(type="str"),
        encryption_key=dict(type="str", no_log=True),
        remote_location=dict(type="str"),
        frequency=dict(type="int"),
        scheduler_date=dict(type="str", aliases=["scheduler_start_date", "start_date", "date"]),
        scheduler_time=dict(type="str", aliases=["scheduler_start_time", "start_time", "time"]),
        backup_type=dict(type="str", default="config_only", choices=["config_only", "full"], aliases=["type"]),
        state=dict(type="str", default="present", choices=["present", "query", "absent"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "backup", ["name", "encryption_key"]],
            ["state", "absent", ["name"]],
        ],
    )

    nd = NDModule(module)

    name = nd.params.get("name")
    encryption_key = nd.params.get("encryption_key")
    remote_location = nd.params.get("remote_location")
    frequency = nd.params.get("frequency")
    scheduler_date = nd.params.get("scheduler_date")
    scheduler_time = nd.params.get("scheduler_time")
    backup_type = snake_to_camel(nd.params.get("backup_type"))
    state = nd.params.get("state")

    start_date_time = None
    if scheduler_date and scheduler_time:
        date_object = datetime.datetime.strptime(scheduler_date, "%Y-%m-%d")
        time_object = datetime.datetime.strptime(scheduler_time, "%H:%M:%S")
        start_date_time = "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}Z".format(
            date_object.year, date_object.month, date_object.day, time_object.hour, time_object.minute, time_object.second
        )

    path = "/api/v1/infra/backups/schedules"

    schedules = nd.get_object_by_nested_key_value(path, "name", name, data_key="schedules")

    if name and schedules:
        nd.previous = nd.existing = schedules
        path = "{0}/{1}".format(path, name)
    else:
        nd.existing = schedules

    if state == "present":
        payload = {
            "encryptionKey": encryption_key,
            "name": name,
            "type": backup_type,
            "frequency": frequency,
            "remoteLocation": remote_location,
            "startTime": start_date_time,
        }

        if nd.existing and nd.existing.get("name") == name:
            payload["frequency"] = frequency or nd.existing.get("frequency")
            payload["remoteLocation"] = remote_location or nd.existing.get("remoteLocation")
            payload["startTime"] = start_date_time or nd.existing.get("startTime")

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            if nd.existing and nd.existing.get("name") == name:
                nd.request(path, method="PUT", data=payload)
            else:
                nd.request(path, method="POST", data=payload)
                path = "{0}/{1}".format(path, name)
            nd.existing = nd.request(path, method="GET")
        else:
            nd.existing = payload

    elif state == "absent":
        if not module.check_mode and nd.existing and nd.existing.get("name") == name:
            nd.request(path, method="DELETE")
        nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
