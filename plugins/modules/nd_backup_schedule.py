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
short_description: Manages backup schedules on Cisco Nexus Dashboard.
description:
- Manage backup schedules on Cisco Nexus Dashboard.
- This module is only supported on ND v4.1 and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  config:
    description:
    - The configuration of the backup schedules.
    - Use O(state=overridden) and O(config=[]) to delete all backup schedules.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the backup schedule.
        type: str
        required: true
      encryption_key:
        description:
        - The encryption key for a backup file.
        - This parameter is required when creating or updating the backup schedule.
        type: str
      remote_location:
        description:
        - The name of the remote storage location.
        - This parameter is required when creating the backup schedule.
        type: str
      frequency:
        description:
        - The frequency at which remote backups are scheduled to occur at specified intervals on selected days.
        - This parameter is required when creating the backup schedule.
        type: int
      scheduler_date:
        description:
        - The start date for the backup schedule in the format O(config.scheduler_date="YYYY-MM-DD").
        - This parameter is required when creating the backup schedule.
        type: str
        aliases: [ scheduler_start_date, start_date, date ]
      scheduler_time:
        description:
        - The start time for the backup schedule in the format O(config.scheduler_time="HH-MM-SS").
        - This parameter is required when creating the backup schedule.
        type: str
        aliases: [ scheduler_start_time, start_time, time ]
      backup_type:
        description:
        - This parameter specifies the kind of snapshot created for the Nexus Dashboard.
        - The O(config.backup_type=config_only) option creates a snapshot that specifically captures the configuration settings of the Nexus Dashboard.
        - The O(config.backup_type=full) option creates a complete snapshot of the entire Nexus Dashboard.
        - This parameter is required when creating the backup schedule.
        type: str
        choices: [ config_only, full ]
        aliases: [ type ]
  state:
    description:
    - Use O(state=merged) or O(state=present) to create new objects or update existing objects on the Cisco Nexus Dashboard based on the provided config.
    - Use O(state=replaced) to create or recreate objects on the Cisco Nexus Dashboard, replacing them with those defined in the config.
    - Use O(state=overridden) to keep only the config-specified objects on the Cisco Nexus Dashboard, deleting all others.
    - Use C(query) to retrieve and list the current objects on the Cisco Nexus Dashboard.
    - Use O(state=deleted) or O(state=absent) to remove objects from the Cisco Nexus Dashboard.
    type: str
    choices: [ merged, present, replaced, deleted, absent, overridden, query ]
    default: merged
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create a list of backup schedules
  cisco.nd.nd_backup_schedule:
    state: merged
    config:
      - name: daily
        encryption_key: testtest1
        frequency: 1
        scheduler_date: "2025-01-02"
        scheduler_time: "11:04:05"
        remote_location: test
        backup_type: config_only
      - name: weekly
        encryption_key: testtest1
        frequency: 7
        scheduler_date: "2025-01-02"
        scheduler_time: "12:04:05"
        remote_location: test
        backup_type: config_only

- name: Update a list of backup schedules
  cisco.nd.nd_backup_schedule:
    state: merged
    config:
      - name: daily
        encryption_key: testtest1
        frequency: 2
        scheduler_date: "2025-01-02"
        scheduler_time: "11:10:05"
        remote_location: test
        backup_type: full
      - name: weekly
        encryption_key: testtest1
        frequency: 5
        scheduler_date: "2025-01-02"
        scheduler_time: "12:10:05"
        remote_location: test
        backup_type: full

- name: Query one backup schedule
  cisco.nd.nd_backup_schedule:
    output_level: debug
    state: query
    config:
      - name: monthly
  register: query_one

- name: Query all backup schedules
  cisco.nd.nd_backup_schedule:
    output_level: debug
    state: query
  register: query_all

- name: Delete all backup schedules
  cisco.nd.nd_backup_schedule:
    output_level: debug
    state: overridden
    config: []
"""

RETURN = r"""
"""


import datetime
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.utils import (
    snake_to_camel,
    compare_config_and_remote_objects,
    compare_unordered_list_of_dicts,
    wrap_objects_by_key,
)
import copy


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "replaced", "deleted", "overridden", "query", "present", "absent"],
        ),
        config=dict(
            required=False,
            type="list",
            elements="dict",
            options=dict(
                name=dict(type="str", required=True),
                encryption_key=dict(type="str", no_log=True),
                remote_location=dict(type="str"),
                frequency=dict(type="int"),
                scheduler_date=dict(type="str", aliases=["scheduler_start_date", "start_date", "date"]),
                scheduler_time=dict(type="str", aliases=["scheduler_start_time", "start_time", "time"]),
                backup_type=dict(type="str", choices=["config_only", "full"], aliases=["type"]),
            ),
        ),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)

    base_path = "/api/v1/infra/backups/schedules"

    config = nd.params.get("config")
    state = nd.params.get("state")
    schedules = nd.request(base_path, method="GET").get("schedules")

    remote_schedule_map = wrap_objects_by_key(schedules)

    if state == "query":
        if config:
            for object in config:
                if remote_schedule_map.get(object.get("name")):
                    nd.after.append(remote_schedule_map.get(object.get("name")))
        else:
            nd.after = schedules
        nd.exit_json()

    nd.before = copy.deepcopy(schedules)

    result = compare_config_and_remote_objects(schedules, config)

    if state != "query":
        if state in ["deleted", "absent"]:  # Delete only specified objects in the config
            delete_object_list = config
            nd.after = result.get("remote_data_delete")  # Unmatched objects from ND (name not in Config)
        else:
            delete_object_list = result.get("remote_data_delete")

        for object in delete_object_list:
            if state in ["overridden", "deleted", "absent"]:
                nd.commands.append(nd.delete(module.check_mode, "{0}/{1}".format(base_path, object.get("name"))))
            else:  # Ignore delete operation when the state is merged/present, replaced
                nd.after.append(object)

        if state not in ["deleted", "absent"]:
            for object in result.get("config_data_create"):
                post_backup_schedule_config(nd, module, base_path, object)

            for object in result.get("config_data_update"):
                if remote_schedule_map.get(object.get("name")):
                    if state in ["replaced", "overridden"]:  # Force recreate the object when state is replaced/overridden
                        post_backup_schedule_config(nd, module, base_path, object, None, method="PUT")
                    else:  # Use the existing object value when the optional attribute is None when the state is merged/present
                        post_backup_schedule_config(nd, module, base_path, object, remote_schedule_map.get(object.get("name")), method="PUT")

    if not compare_unordered_list_of_dicts(nd.after, copy.deepcopy(nd.before)):
        nd.result["changed"] = True

    nd.exit_json()


def post_backup_schedule_config(nd, module, path, config_obj, remote_obj=None, method="POST"):
    start_time = get_backup_schedule_time(config_obj.get("scheduler_date"), config_obj.get("scheduler_time"))
    payload = {
        "encryptionKey": config_obj.get("encryption_key"),
        "name": config_obj.get("name"),
        "type": snake_to_camel(config_obj.get("backup_type")),
        "frequency": config_obj.get("frequency"),
        "remoteLocation": config_obj.get("remote_location"),
        "startTime": start_time,
    }

    changed = None
    if method == "PUT":
        path = "{0}/{1}".format(path, payload.get("name"))
        if remote_obj:
            payload["frequency"] = payload["frequency"] or remote_obj.get("frequency")
            payload["remoteLocation"] = payload["remoteLocation"] or remote_obj.get("remoteLocation")
            payload["startTime"] = payload["startTime"] or remote_obj.get("startTime")
            if nd.get_diff(unwanted=["encryptionKey", "user"], previous=copy.deepcopy(remote_obj), payload=copy.deepcopy(payload)):
                changed = True

    nd.sanitize(payload, collate=True)
    nd.commands.append(nd.proposed)

    if not module.check_mode:
        if method == "PUT":
            if changed or remote_obj is None:
                nd.request(path, method=method, data=payload)
                nd.after.append(nd.request(path, method="GET"))
            elif remote_obj and not changed:  # Ignore the PUT call when the object does not have a valid change
                nd.after.append(remote_obj)
        elif method == "POST":
            nd.request(path, method=method, data=payload)
            path = "{0}/{1}".format(path, payload.get("name"))
            nd.after.append(nd.request(path, method="GET"))
    else:
        nd.after.append(payload)


def get_backup_schedule_time(scheduler_date, scheduler_time):
    if scheduler_date and scheduler_time:
        date_object = datetime.datetime.strptime(scheduler_date, "%Y-%m-%d")
        time_object = datetime.datetime.strptime(scheduler_time, "%H:%M:%S")
        return "{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}Z".format(
            date_object.year, date_object.month, date_object.day, time_object.hour, time_object.minute, time_object.second
        )


if __name__ == "__main__":
    main()
