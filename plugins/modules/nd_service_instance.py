#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_service_instance
short_description: Manages Service Instance on Nexus Dashboard.
description:
- Manages Service Instance of the Nexus Dashboard.
author:
- Sabari Jaganathan (@sajagana)
options:
  name:
    description:
    - The name of the Service.
    aliases: [ service_name ]
    type: str
  instance_name:
    description:
    - The name of the Service Instance Profile.
    aliases: [ service_instance_name ]
    type: str
  target_version:
    description:
    - The target version of the Service.
    type: str
  state:
    description:
    - Use C(enable) for enabling a Service Instance.
    - Use C(restart) for restarting a Service Instance.
    - Use C(query) for listing all Service Instance.
    - Use C(disable) for disabling a Service Instance.
    - Use C(delete) for deleting a Service Instance. The C(delete) destroys an active service instance directly.
    type: str
    choices: [ enable, restart, query, disable, delete ]
    default: enable
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Enable a Service Instance
  cisco.nd.nd_service_instance:
    name: "cisco-terraform"
    instance_name: "default"
    target_version: "0.1.15"
    state: enable

- name: Upgrade a Service Instance
  cisco.nd.nd_service_instance:
    name: "cisco-terraform"
    instance_name: "default"
    target_version: "0.1.16"
    state: enable

- name: Restart a Service Instance
  cisco.nd.nd_service_instance:
    name: "cisco-terraform"
    instance_name: "default"
    state: restart

- name: Query a Service Instance with name and instance_name
  cisco.nd.nd_service_instance:
    name: "cisco-terraform"
    instance_name: "default"
    state: query
  register: query_result

- name: Query all Service Instances
  cisco.nd.nd_service_instance:
    state: query
  register: query_results

- name: Disable a Service Instance
  cisco.nd.nd_service_instance:
    name: "cisco-terraform"
    instance_name: "default"
    state: disable

- name: Delete an existing service instance
  cisco.nd.nd_service_instance:
    name: "cisco-terraform"
    target_version: "0.1.16"
    state: delete
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        name=dict(type="str", aliases=["service_name"]),
        instance_name=dict(type="str", aliases=["service_instance_name"]),
        target_version=dict(type="str"),
        state=dict(type="str", default="enable", choices=["enable", "query", "disable", "restart", "delete"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "enable", ["name", "instance_name", "target_version"]],
            ["state", "restart", ["name", "instance_name"]],
            ["state", "disable", ["name", "instance_name"]],
            ["state", "delete", ["name", "target_version"]],
        ],
    )

    nd = NDModule(module)

    name = nd.params.get("name")
    target_version = nd.params.get("target_version")
    instance_name = nd.params.get("instance_name")
    state = nd.params.get("state")

    base_path = "/nexus/infra/api/firmware/v1"
    instance_path = "{0}/serviceinstances".format(base_path)

    # To avoid object not found error while querying the object
    nd.ignore_not_found_error = True

    # Delete part
    if state == "delete":
        service_object = nd.query_obj("/nexus/infra/api/firmware/v1/services/{0}:{1}".format(name, target_version))
        if service_object:
            nd.existing = service_object
        else:
            nd.previous = nd.existing = {}
            nd.exit_json()

    # Enable, Disable and Restart part
    elif name and instance_name:
        absent_instance_path = "{0}/serviceinstances/serviceName/{1}/instanceName/{2}".format(base_path, name, instance_name)
        service_object = nd.query_obj(absent_instance_path)
        if service_object:
            nd.existing = service_object
    else:
        nd.existing = nd.query_obj(instance_path)

    nd.previous = nd.existing
    if state == "query" or ((state == "disable" or state == "restart") and not nd.existing):
        nd.exit_json()

    if state == "restart":
        restart_instance_path = "{0}/serviceinstancerestarts/serviceName/{1}/instanceName/{2}".format(base_path, name, instance_name)

    if state == "enable":
        payload = {"spec": {"name": instance_name, "serviceName": name, "targetVersion": target_version}}
        nd.sanitize(payload, collate=True)
        nd.proposed = payload
        nd.previous = {}
        if not module.check_mode:
            nd.existing = nd.request(instance_path, method="POST", data=payload)
    elif state == "restart":
        payload = {"spec": {"name": instance_name, "serviceName": name}}
        nd.sanitize(payload, collate=True)
        nd.proposed = payload
        if not module.check_mode:
            nd.existing = nd.request(restart_instance_path, method="PUT", data=payload)
    elif state == "disable":
        if not module.check_mode:
            nd.existing = nd.request(absent_instance_path, method="DELETE")
    else:
        if not module.check_mode:
            nd.existing = nd.request("/sedgeapi/v1/firmwared/api/applications/{0}:{1}/cleanup".format(name, target_version), method="POST")

    nd.exit_json()


if __name__ == "__main__":
    main()
