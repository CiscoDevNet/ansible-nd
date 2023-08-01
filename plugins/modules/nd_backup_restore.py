#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_backup_restore
short_description: Manages restore of backup on Nexus Dashboard.
description:
- Manages importing the cluster configuration using a backup.
author:
- Shreyas Srish (@shrsr)
options:
  name:
    description:
    - The name given for a backup to be restored.
    - This can be different from the backup file.
    - This is assigned to the job once the restore is complete.
    aliases: [ restore_name ]
    type: str
  encryption_key:
    description:
    - The encryption_key of a backup file.
    type: str
  file_location:
    description:
    - The path and file name of the backup file to be restored.
    type: str
  restore_key:
    description:
    - The key generated for a restored job by ND during import of a backup.
    - This key is required when querying or deleting a restored job among multiple restored jobs that have the same name.
    - This key can be obtained by querying a restored job.
    type: str
  state:
    description:
    - Use C(restore) for importing a backup of the cluster config.
    - Use C(query) for listing all the restored jobs.
    - Use C(absent) for deleting a restored job.
    type: str
    choices: [ restore, query, absent ]
    default: restore
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Import a Backup
  cisco.nd.nd_backup_restore:
    name: nexus
    encryption_key: testtest
    file_location: ./nexus.tgz
    state: restore

- name: Query a restore job
  cisco.nd.nd_backup_restore:
    name: nexus
    state: query
  register: query_result

- name: Query all restore jobs
  cisco.nd.nd_backup_restore:
    state: query
  register: query_results

- name: Delete a restore job
  cisco.nd.nd_backup_restore:
    name: nexus
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        name=dict(type="str", aliases=["restore_name"]),
        encryption_key=dict(type="str", no_log=False),
        file_location=dict(type="str"),
        restore_key=dict(type="str", no_log=False),
        state=dict(type="str", default="restore", choices=["restore", "query", "absent"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "restore", ["name", "encryption_key", "file_location"]],
            ["state", "absent", ["name"]],
        ],
    )

    nd = NDModule(module)

    name = nd.params.get("name")
    encryption_key = nd.params.get("encryption_key")
    restore_key = nd.params.get("restore_key")
    file_location = nd.params.get("file_location")
    state = nd.params.get("state")

    if encryption_key is not None and len(encryption_key) < 8:
        nd.fail_json("The encryption key must have a minium of 8 characters.")

    path = "/nexus/infra/api/platform/v1/imports"
    # The below path for GET operation is to be replaced by an official documented API endpoint once it becomes available.
    restored_objs = nd.query_obj("/api/config/class/imports")
    restored_info = []
    if name:
        restored_info = [file_dict for file_dict in restored_objs if file_dict.get("description") == name]
        if len(restored_info) > 1 and restore_key is None and encryption_key is None:
            nd.fail_json("Multiple restore jobs with the name '{0}' found. Please provide a restore key for the corresponding restored job.".format(name))
        else:
            restore_keys = [file_dict.get("key") for file_dict in restored_info]
            if len(restored_info) == 1:
                restore_key = restore_keys[0]
            elif restore_key is not None and restore_key not in restore_keys:
                nd.fail_json(
                    "Provided key for the restore '{0}' not found."
                    " Please provide a valid restore key by querying all the restored jobs and looking up the desired restore key.".format(name)
                )
        nd.existing = next((file_dict for file_dict in restored_info if file_dict.get("key") == restore_key), {})
    else:
        nd.existing = restored_objs

    nd.previous = nd.existing

    if state == "absent":
        if nd.existing:
            if not module.check_mode:
                nd.request("{0}/{1}".format(path, restore_key), method="DELETE")
            nd.existing = {}
    elif state == "restore":
        nd.previous = nd.existing = {}

        payload = {
            "description": name,
            "password": encryption_key,
        }

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            nd.request(path, method="POST", data=payload, file=file_location, file_key="importfile", output_format="raw")
        nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
