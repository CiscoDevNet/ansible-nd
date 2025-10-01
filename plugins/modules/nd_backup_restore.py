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
    - The encryption key must contain at least 8 alphanumeric characters.
    type: str
  file_location:
    description:
    - The path and file name of the backup file to be restored.
    - This parameter is required only when restoring the backup file from either a remote or local machine.
    type: str
  restore_key:
    description:
    - The key generated for a restored job by ND during import of a backup.
    - This key is required when querying or deleting a restored job among multiple restored jobs that have the same name.
    - This key can be obtained by querying a restored job.
    type: str
  ignore_persistent_ips:
    description:
    - This parameter is only supported on ND v3.2.1 and later.
    - When O(ignore_persistent_ips=true), the existing external service IP addresses configured on the Nexus Dashboard will be overwritten.
    - When unspecified, the parameter defaults to O(ignore_persistent_ips=false).
    type: bool
    aliases: [ ignore_external_service_ip_configuration ]
  restore_type:
    description:
    - This parameter is only supported on ND v3.2.1 and later.
    - The O(restore_type=config_only) option restores only configuration settings of the Nexus Dashboard.
    - The O(restore_type=full) option restores the entire settings of the Nexus Dashboard.
    - When unspecified, the parameter defaults to O(restore_type=config_only).
    type: str
    choices: [ config_only, full ]
    aliases: [ type ]
  remote_location:
    description:
    - This parameter is only supported on ND v3.2.1 and later.
    - The name of the remote storage location.
    - This parameter is required only when restoring the backup file from a remote location.
    type: str
  import_validation_delay:
    description:
    - This parameter is only supported on ND v3.2.1 and later.
    - This parameter is required only when restoring the backup file.
    - When unspecified, the parameter defaults to O(import_validation_delay=10) seconds.
    type: int
    aliases: [ delay ]
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
from ansible_collections.cisco.nd.plugins.module_utils.constants import BACKUP_TYPE
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
        restore_type=dict(type="str", choices=["config_only", "full"], aliases=["type"]),
        remote_location=dict(type="str"),
        import_validation_delay=dict(type="int", aliases=["delay"]),
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
    ignore_persistent_ips = nd.params.get("ignore_persistent_ips") or False
    restore_type = BACKUP_TYPE.get(nd.params.get("restore_type"))
    remote_location = nd.params.get("remote_location")
    import_validation_delay = nd.params.get("import_validation_delay") or 10

    backup_status_path = "/api/config/class/imports" if nd.version < "3.2.1" else "/api/action/class/backuprestore/status"
    nd.existing = nd.query_obj(backup_status_path)

    import_path = "/nexus/infra/api/platform/v1/imports" if nd.version < "3.2.1" else "/api/action/class/backuprestore/restore/file-import"

    if nd.version < "3.2.1":
        if name:
            restored_info = [file_dict for file_dict in nd.existing if file_dict.get("description") == name]
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

    nd.previous = nd.existing

    if state == "absent":
        if not module.check_mode:
            nd.request("{0}/{1}".format(import_path, restore_key) if nd.version < "3.2.1" else import_path, method="DELETE")
        nd.existing = {}

    elif state == "restore":
        if nd.version < "3.2.1":
            nd.previous = nd.existing = {}

            payload = {
                "description": name,
                "password": encryption_key,
            }

            nd.sanitize(payload, collate=True)

            if not module.check_mode:
                nd.request(import_path, method="POST", data=payload, file=file_location, file_key="importfile", output_format="raw")
            nd.existing = nd.proposed

        else:

            # The imported backup must be cleared before starting the restore process
            if not module.check_mode:
                nd.request(import_path, method="DELETE")

            import_payload = {"encryptionKey": encryption_key}

            if remote_location and file_location:
                import_payload.update({"source": remote_location, "path": file_location})

            elif file_location:
                # Local file upload
                if not module.check_mode:
                    import_payload["path"] = nd.request(
                        "/api/action/class/backuprestore/file-upload", method="POST", data=None, file=file_location, file_key="files", output_format="raw"
                    )

            elif name:
                # The restore operation requires only the backup file name.
                import_payload["name"] = name.split(".")[0]

            nd.sanitize(import_payload, collate=True)

            restore_payload = {
                "ignorePersistentIPs": ignore_persistent_ips,
                "type": restore_type,
            }
            nd_payload = {
                "fileUploadPayload": {"fileLocation": file_location},
                "importPayload": import_payload,
                "restorePayload": restore_payload,
            }
            nd.sanitize(nd_payload, collate=True)

            if not module.check_mode:
                nd.request(import_path, method="POST", data=import_payload)
                # The file upload and validation process takes a few seconds
                time.sleep(import_validation_delay)
                nd.request("/api/action/class/backuprestore/restore", method="POST", data=restore_payload)
                nd.existing = nd.query_obj(backup_status_path)
            else:
                nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
