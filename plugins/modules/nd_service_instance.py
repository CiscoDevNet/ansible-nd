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
    - The name of the Service Instance.
    aliases: [ service_instance_name ]
    type: str
    default: default
  target_version:
    description:
    - The target version of the Service.
    type: str
  state:
    description:
    - Use C(enable) for enabling a Service Instance.
    - Use C(query) for listing all Service Instance.
    - Use C(restart) for restarting a Service Instance.
    - Use C(update) for upgrading a Service Instance.
    - Use C(disable) for disabling a Service Instance.
    - Use C(delete) for deleting a Service Instance.
    type: str
    choices: [ enable, query, restart, update, disable, delete]
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
    state: update

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
        instance_name=dict(type="str", default="default", aliases=["service_instance_name"]),
        target_version=dict(type="str"),
        state=dict(type="str", default="enable", choices=["enable", "query", "restart", "update", "disable", "delete"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "enable", ["name", "target_version"]],
            ["state", "update", ["name", "target_version"]],
            ["state", "restart", ["name"]],
            ["state", "disable", ["name"]],
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

    # Delete part
    if state == "delete":
        service_object = nd.query_obj("/nexus/infra/api/firmware/v1/services/{0}:{1}".format(name, target_version), ignore_not_found_error=True)
        if service_object:
            nd.existing = service_object
    elif name and instance_name:
        # Enable, Disable and Restart part
        absent_instance_path = "{0}/serviceinstances/serviceName/{1}/instanceName/{2}".format(base_path, name, instance_name)
        service_object = nd.query_obj(absent_instance_path, ignore_not_found_error=True)
        if service_object:
            nd.existing = service_object
    else:
        # Query all objects
        nd.existing = nd.query_obj(instance_path)

    if state in ("update", "restart", "disable") and not nd.existing:
        if state == "update":
            msg = "The service instance name: {0} and target_version: {1} does not exist to perform: {2} operation".format(name, target_version, state)
        else:
            msg = "The service instance name: {0} does not exist to perform: {1} operation".format(name, state)
        nd.fail_json(msg=msg)

    nd.previous = nd.existing

    unwanted = [
        "metadata",
        "status",
        ["spec", "serviceReference"],
    ]

    if state == "enable" or (state == "update" and nd.existing):
        payload = {"spec": {"name": instance_name, "serviceName": name, "targetVersion": target_version}}
        nd.sanitize(payload, collate=False, required=None, unwanted=unwanted)
        nd.proposed = payload
        method, path = ("POST", instance_path) if state == "enable" else ("PUT", absent_instance_path)
        if not module.check_mode:
            nd.existing = nd.request(path, method=method, data=payload)
        else:
            nd.existing = payload
    elif state == "restart" and nd.existing:
        restart_instance_path = "{0}/serviceinstancerestarts/serviceName/{1}/instanceName/{2}".format(base_path, name, instance_name)
        payload = {"spec": {"name": instance_name, "serviceName": name}}
        nd.sanitize(payload, collate=False, required=None, unwanted=unwanted)
        nd.proposed = payload
        if not module.check_mode:
            nd.existing = nd.request(restart_instance_path, method="PUT", data=payload)
        else:
            nd.existing = payload
    elif state == "disable" and nd.existing and not module.check_mode:
        nd.existing = nd.request(absent_instance_path, method="DELETE")
    elif state == "delete" and nd.existing and not module.check_mode:
        nd.existing = nd.request("/nexus/infra/api/firmware/v1/services/{0}:{1}".format(name, target_version), method="DELETE")

    nd.exit_json()


if __name__ == "__main__":
    main()
