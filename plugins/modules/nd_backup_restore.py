#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_backup_restore
version_added: "0.5.0"
short_description: Manages restore of backup on Nexus Dashboard.
description:
- Manages importing the cluster configuration using a backup.
author:
- Shreyas Srish (@shrsr)
- Sabari Jaganathan (@sajagana)
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
  ignore_persistent_ips:
    description:
    - When the O(ignore_persistent_ips=true), will overwrite the existing external service IP addresses configured on the Nexus Dashboard.
    type: bool
    aliases: [ ignore_external_service_ip_configuration ]
  restore_type:
    description:
    - This parameter is only supported on ND v3.2.1 and later.
    - The O(restore_type=config_only) option restores only configuration settings of the Nexus Dashboard.
    - The O(restore_type=full) option restores the entire settings of the Nexus Dashboard.
    type: str
    choices: [ config_only, full ]
    default: config_only
    aliases: [ type ]
  remote_location:
    description:
    - The name of the remote storage location. This parameter is only supported on ND v3.2.1 and later.
    type: str
  state:
    description:
    - Use C(restore) for importing a backup of the cluster config.
    - Use C(query) for listing all the restored jobs.
    - Use C(absent) for deleting a restored job.
    type: str
    choices: [ restore, query, absent ]
    default: restore
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
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
from ansible_collections.cisco.nd.plugins.module_utils.utils import snake_to_camel
import time


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        name=dict(type="str", aliases=["restore_name"]),
        encryption_key=dict(type="str", no_log=False),
        file_location=dict(type="str"),
        restore_key=dict(type="str", no_log=False),
        state=dict(type="str", default="restore", choices=["restore", "query", "absent"]),
        ignore_persistent_ips=dict(type="bool", aliases=["ignore_external_service_ip_configuration"]),
        restore_type=dict(type="str", default="config_only", choices=["config_only", "full"], aliases=["type"]),
        remote_location=dict(type="str"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "restore", ["encryption_key"]],
        ],
    )

    nd = NDModule(module)

    name = nd.params.get("name")
    encryption_key = nd.params.get("encryption_key")
    restore_key = nd.params.get("restore_key")
    file_location = nd.params.get("file_location")
    state = nd.params.get("state")
    ignore_persistent_ips = nd.params.get("ignore_persistent_ips")
    restore_type = snake_to_camel(nd.params.get("restore_type"))
    remote_location = nd.params.get("remote_location")

    if encryption_key is not None and len(encryption_key) < 8:
        nd.fail_json("The encryption key must have a minium of 8 characters.")

    if nd.version < "3.2.1":
        nd_backup_restore_before_3_2_1(nd, name, encryption_key, file_location, restore_key, state, module)
    elif nd.version >= "3.2.1":
        nd_backup_restore_from_3_2_1(nd, name, encryption_key, file_location, state, module, ignore_persistent_ips, restore_type, remote_location)
    nd.exit_json()


def nd_backup_restore_from_3_2_1(nd, name, encryption_key, file_location, state, module, ignore_persistent_ips, restore_type, remote_location):
    if name and (remote_location or file_location):
        nd.fail_json("The parameters name and (remote_location or file_location) cannot be specified at the same time.")

    nd.existing = nd.query_obj("/api/v1/infra/backups/status")
    import_path = "/api/v1/infra/backups/actions/import"

    # Remove backup status (not idempotent)
    if state == "absent" and (not nd.existing or nd.existing.get("state") != "processing"):
        nd.previous = nd.existing
        if not module.check_mode:
            nd.request(import_path, method="DELETE")

    # Restore from backup (not idempotent)
    elif state == "restore" and (not nd.existing or nd.existing.get("state") != "processing"):

        if not module.check_mode:  # Need to delete the imported file before starting the restore process
            nd.request(import_path, method="DELETE")

        import_payload = {"encryptionKey": encryption_key}

        if remote_location and file_location and not name:
            import_payload.update({"source": remote_location, "path": file_location})
        elif not (remote_location and name) and file_location:
            # Local file upload
            if not module.check_mode:
                import_payload["path"] = nd.request(
                    "/api/action/class/backuprestore/file-upload", method="POST", data=None, file=file_location, file_key="files", output_format="raw"
                )
        elif name:
            import_payload["name"] = name.split(".")[0]  # Restore operation requires only name of the backup file

        nd.sanitize(import_payload, collate=True)

        restore_payload = {
            "ignorePersistentIPs": ignore_persistent_ips
            or False,  # add note to the document saying that ignore_persistent_ips set to false when it is not specified
            "type": restore_type or "configOnly",  # add note to the document saying that restore_type set to configOnly when it is not specified
        }
        nd_payload = {
            "fileUploadPayload": {"fileLocation": file_location},
            "importPayload": import_payload,
            "restorePayload": restore_payload,
        }
        nd.sanitize(nd_payload, collate=True)

        if not module.check_mode:
            nd.request(import_path, method="POST", data=import_payload)
            time.sleep(10)
            nd.request("/api/v1/infra/backups/actions/restore", method="POST", data=restore_payload)
            nd.existing = nd.query_obj("/api/v1/infra/backups/status")
        else:
            nd.existing = nd.proposed

    # Operation not allowed if backup status is processing
    elif state != "query" and nd.existing and nd.existing.get("state") == "processing":
        nd.fail_json(
            msg="The {0} operation could not proceed because a system {1} is in progress ({2}% complete).".format(
                state, nd.existing.get("operation"), nd.existing.get("details", {}).get("progress")
            )
        )


def nd_backup_restore_before_3_2_1(nd, name, encryption_key, file_location, restore_key, state, module):
    if state == "restore" and not (name and encryption_key and file_location):
        nd.fail_json("state is restore but all/one of the following are missing: name, encryption_key, file_location")

    if state == "absent" and not name:
        nd.fail_json("state is absent but all of the following are missing: name")

    path = "/nexus/infra/api/platform/v1/imports"
    # The below path for GET operation is to be replaced by an official documented API endpoint once it becomes available.
    restored_objs = nd.query_obj("/api/config/class/imports")

    if name:
        restored_info = [file_dict for file_dict in restored_objs if file_dict.get("description") == name]
        if len(restored_info) > 1 and restore_key is None and encryption_key is None:
            nd.fail_json("Multiple restore jobs with the name '{0}' found. Please provide a restore key for the corresponding restored job.".format(name))
        elif len(restored_info) == 1:
            restore_key = restored_info[0].get("key")
        elif restore_key is not None and restore_key not in [file_dict.get("key") for file_dict in restored_info]:
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


if __name__ == "__main__":
    main()
