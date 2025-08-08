#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_remote_storage_location
version_added: "0.5.0"
short_description: Manages remote storage locations on Cisco Nexus Dashboard.
description:
- Manage remote storage locations on Cisco Nexus Dashboard.
- This module is only supported on ND v4.1 and later.
author:
- Sabari Jaganathan (@sajagana)
options:
  name:
    description:
    - The name of the remote storage location.
    type: str
  description:
    description:
    - The description of the remote storage location.
    type: str
  server_port:
    description:
    - The port number of the remote server.
    type: int
  server_name:
    description:
    - The IP address or hostname of the remote server.
    type: str
    aliases: [ ip ]
  path:
    description:
    - The export path of the remote storage location.
    type: str
    aliases: [ default_path, export_path ]
  sftp_scp:
    description:
    - The SFTP/SCP configuration for the remote storage location.
    - This parameter and O(nas) are mutually exclusive.
    type: dict
    suboptions:
      protocol:
        description:
        - The protocol type for the remote storage location.
        - This parameter is required when creating the remote storage location.
        type: str
        aliases: [ type ]
        choices: [ scp, sftp ]
      username:
        description:
        - The username of the remote storage location.
        - This parameter is required when the O(sftp_scp.password) or O(sftp_scp.ssh_key) is set.
        type: str
      password:
        description:
        - The password associated with the user account for the remote storage location.
        - This parameter and O(sftp_scp.ssh_key), O(sftp_scp.passphrase) are mutually exclusive.
        type: str
      ssh_key:
        description:
        - The SSH private key string for the remote storage location.
        - This parameter and O(sftp_scp.password) are mutually exclusive.
        type: str
      passphrase:
        description:
        - The passphrase value of the SSH private key.
        - This parameter and O(sftp_scp.password) are mutually exclusive.
        type: str
  nas:
    description:
    - The Network-attached storage (NAS) configuration for the remote storage location.
    - This parameter and O(sftp_scp) are mutually exclusive.
    type: dict
    aliases: [ nas_storage ]
    suboptions:
      limit:
        description:
        - The maximum NAS storage capacity that can be requested on the remote storage location.
        - The value must be provided in "MB" or "GB" or "Gi" format (e.g., 10MB or 1GB or 1Gi).
        - Defaults to 500Gi when unset during creation.
        type: str
      alert_threshold:
        description:
        - Threshold (percentage) to trigger notification or warning for the remote storage location.
        - The value must be in the range 1 - 100.
        - Defaults to 80 when unset during creation.
        type: int
      read_write:
        description:
        - Indicates whether the storage is mounted with read-write permissions.
        type: bool
  state:
    description:
    - Use C(present) for creating a the remote storage location.
    - Use C(query) for listing the the remote storage location.
    - Use C(absent) for deleting a the remote storage location.
    type: str
    choices: [ present, query, absent ]
    default: present
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create SFTP/SCP remote storage location
  cisco.nd.nd_remote_storage_location:
    name: ansible-test-remote-storage-sftp
    description: sftp
    server_port: 22
    server_name: remote-storage.com
    path: /tmp
    sftp_scp:
      password: pass123
      protocol: sftp
      username: remote_user
    state: present

- name: Create NAS remote storage location
  cisco.nd.nd_remote_storage_location:
    name: ansible-test-remote-storage-nas
    description: nas
    server_port: 22
    server_name: remote-storage.com
    path: /tmp
    nas:
      alert_threshold: 15
      limit: 10MB
      read_write: false
    state: present

- name: Update SFTP/SCP remote storage location
  cisco.nd.nd_remote_storage_location:
    name: ansible-test-remote-storage-sftp
    description: scp
    server_port: 22
    server_name: remote-storage.com
    path: /tmp
    sftp_scp:
      ssh_key: "{{ lookup('file', 'openssh_rsa.key') }}"
      passphrase: passphrase123
      protocol: scp
      username: remote_user
    state: present

- name: Query a remote storage location
  cisco.nd.nd_remote_storage_location:
    name: ansible-test-remote-storage-sftp
    state: query
  register: query_one

- name: Query all remote storage locations
  cisco.nd.nd_remote_storage_location:
    state: query
  register: query_all

- name: Delete a remote storage location
  cisco.nd.nd_remote_storage_location:
    name: ansible-test-remote-storage-sftp
    state: absent
"""

RETURN = r"""
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.utils import check_if_all_elements_are_none, delete_none_values
import copy


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        name=dict(type="str"),
        description=dict(type="str"),
        server_port=dict(type="int"),
        server_name=dict(type="str", aliases=["ip"]),
        path=dict(type="str", aliases=["default_path", "export_path"]),
        sftp_scp=dict(
            type="dict",
            options=dict(
                protocol=dict(type="str", choices=["scp", "sftp"], aliases=["type"]),
                username=dict(type="str"),
                password=dict(type="str", no_log=True),
                ssh_key=dict(type="str", no_log=True),
                passphrase=dict(type="str", no_log=True),
            ),
            required_one_of=[["password", "ssh_key"]],
            mutually_exclusive=[("password", "ssh_key"), ("password", "passphrase")],
            required_by={
                "ssh_key": "username",
                "password": "username",
            },
            required_together=[["ssh_key", "passphrase"]],
        ),
        nas=dict(
            type="dict",
            aliases=["nas_storage"],
            options=dict(
                limit=dict(type="str"),
                alert_threshold=dict(type="int"),
                read_write=dict(type="bool"),
            ),
        ),
        state=dict(type="str", default="present", choices=["present", "query", "absent"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["name"]],
            ["state", "absent", ["name"]],
        ],
        mutually_exclusive=[("nas", "sftp_scp")],
    )

    nd = NDModule(module)

    name = nd.params.get("name")
    description = nd.params.get("description")
    server_port = nd.params.get("server_port")
    server_name = nd.params.get("server_name")
    remote_path = nd.params.get("path")
    sftp_scp = nd.params.get("sftp_scp")
    nas = nd.params.get("nas")
    state = nd.params.get("state")

    path = "/api/v1/infra/remoteStorage"

    # Query a specific remote storage location
    nd.existing = nd.get_object_by_nested_key_value(path, "spec.name", name, data_key="storages") or {}
    if state != "query":
        if nd.existing:
            nd.previous = copy.deepcopy(nd.existing.get("spec"))
            nd.existing = copy.deepcopy(nd.existing.get("spec"))
            path = "{0}/{1}".format(path, name)
    elif not name:
        # Query all remote storage locations
        remote_storage_locations = nd.request(path, method="GET")
        if remote_storage_locations and remote_storage_locations.get("storages"):
            nd.existing = remote_storage_locations.get("storages")

    if state == "present":
        if not nd.existing:
            payload = {
                "name": name,
                "description": description,
                "port": server_port,
                "hostname": server_name,
                "path": remote_path,
            }

            if nas and not check_if_all_elements_are_none(nas):
                payload["type"] = "nfs"
            elif sftp_scp and sftp_scp.get("protocol"):
                payload["type"] = sftp_scp.get("protocol")

            # NAS create
            if payload.get("type") == "nfs":
                payload["alertThreshold"] = nas.get("alert_threshold")
                payload["limit"] = nas.get("limit")
                payload["readWrite"] = nas.get("read_write")
            # SFTP/SCP create
            elif payload.get("type") == "sftp" or payload.get("type") == "scp":
                payload["authentication"] = dict()
                if sftp_scp.get("password"):
                    payload["authentication"]["type"] = "password"
                    payload["authentication"]["username"] = sftp_scp.get("username")
                    payload["authentication"]["password"] = sftp_scp.get("password")
                elif sftp_scp.get("ssh_key"):
                    payload["authentication"]["type"] = "key"
                    payload["authentication"]["username"] = sftp_scp.get("username")
                    payload["authentication"]["sshKey"] = sftp_scp.get("ssh_key")
                    payload["authentication"]["passphrase"] = sftp_scp.get("passphrase")

        else:
            payload = copy.deepcopy(nd.existing)
            payload["description"] = description or payload.get("description")

            # SFTP/SCP update
            if sftp_scp:
                payload["type"] = sftp_scp.get("protocol") or payload.get("type")
                payload["path"] = remote_path or payload.get("path")
                if sftp_scp.get("password"):
                    payload["authentication"]["type"] = "password"
                    payload["authentication"]["password"] = sftp_scp.get("password")
                elif sftp_scp.get("ssh_key"):
                    payload["authentication"]["type"] = "key"
                    payload["authentication"]["sshKey"] = sftp_scp.get("ssh_key")
                    payload["authentication"]["passphrase"] = sftp_scp.get("passphrase")

            # NAS update
            elif payload.get("type") == "nfs":
                payload["limit"] = nas.get("limit") or payload.get("limit")
                payload["readWrite"] = nas.get("read_write") if nas.get("read_write") is not None else payload.get("readWrite")

        delete_none_values(payload, recursive=True)
        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            if nd.existing:
                nd.request(path, method="PUT", data=payload)
            else:
                nd.request("{0}?acceptHostKey=true".format(path), method="POST", data=payload)
                path = "{0}/{1}".format(path, name)

            nd.existing = nd.request(path, method="GET").get("spec")
        else:
            nd.existing = payload

    elif state == "absent":
        if not module.check_mode and nd.existing:
            nd.request(path, method="DELETE")
        nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
