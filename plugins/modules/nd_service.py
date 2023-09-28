#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sabari Jaganathan (@sajagana) <sajagana@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_service
short_description: Manages Service Package on Nexus Dashboard.
description:
- Manages Service Package of the Nexus Dashboard.
author:
- Sabari Jaganathan (@sajagana)
options:
  import_url:
    description:
    - The remote location of the Service Package.
    aliases: [ url ]
    type: str
  import_id:
    description:
    - The ID of the imported Service Package.
    aliases: [ id ]
    type: str
  state:
    description:
    - Use C(present) for importing a Service Package.
    - Use C(query) for listing all Service Packages.
    - Use C(absent) for deleting a Service Package.
    type: str
    choices: [ present, query, absent ]
    default: present
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Import a service package
  cisco.nd.nd_service:
    import_url: "https://nd_service.cisco.com/cisco-terraform-v0.1.16.aci"
    state: present

- name: Query a service package with import_url
  cisco.nd.nd_service:
    import_url: "https://nd_service.cisco.com/cisco-terraform-v0.1.16.aci"
    state: query
  register: query_result

- name: Query a service package with import_id
  cisco.nd.nd_service:
    import_id: "firmware::v1::ServicePackageImport::e5c480e0-71b2-4ccb-9bb0-b9c174a5731b"
    state: query
  register: query_result

- name: Query all service packages
  cisco.nd.nd_service:
    state: query
  register: query_results

- name: Remove a service package with import_id
  cisco.nd.nd_service:
    import_id: "firmware::v1::ServicePackageImport::e5c480e0-71b2-4ccb-9bb0-b9c174a5731b"
    state: absent

- name: Remove a service package with import_url
  cisco.nd.nd_service:
    import_url: "https://nd_service.cisco.com/cisco-terraform-v0.1.16.aci"
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        import_url=dict(type="str", aliases=["url"]),
        import_id=dict(type="str", aliases=["id"]),
        state=dict(type="str", default="present", choices=["present", "query", "absent"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["import_url"]],
            ["state", "absent", ["import_id", "import_url"], True],
        ],
        mutually_exclusive=[
            ("import_url", "import_id"),
        ],
    )

    nd = NDModule(module)

    import_url = nd.params.get("import_url")
    import_id = nd.params.get("import_id")
    state = nd.params.get("state")

    base_path = "/nexus/infra/api/firmware/v1/servicepackageimports"
    if import_id:
        # Query a object with meta id
        service_package = nd.query_obj("{0}/{1}".format(base_path, import_id), ignore_not_found_error=True)
        if service_package:
            nd.existing = service_package
    elif state == "absent" or state == "query":
        service_packages = nd.query_obj(base_path)
        if import_url:
            # Query all objects with import url
            nd.existing = [service_package for service_package in service_packages.get("items") if service_package.get("spec").get("importURL") == import_url]
        else:
            # Query all objects
            nd.existing = service_packages.get("items")

    if state == "present":
        payload = {"spec": {"importURL": import_url}}
        nd.sanitize(payload, collate=True)
        nd.proposed = payload
        if not module.check_mode:
            nd.existing = nd.request(base_path, method="POST", data=payload)
        else:
            nd.existing = payload
    elif state == "absent":
        if len(nd.existing) == 1 or (nd.existing and isinstance(nd.existing, dict)):
            nd.previous = nd.existing
            if not module.check_mode:
                nd.existing = nd.request("{0}/{1}".format(base_path, import_id), method="DELETE")
        elif len(nd.existing) > 1 and (nd.existing and isinstance(nd.existing, list)):
            nd.previous = nd.existing
            nd.fail_json(msg="More than one service package found. Provide a unique import_id to delete the service package")

    nd.exit_json()


if __name__ == "__main__":
    main()
