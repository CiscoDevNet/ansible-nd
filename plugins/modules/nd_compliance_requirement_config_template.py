#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_compliance_requirement_config_template
version_added: "0.3.0"
short_description: Manage template configuration type compliance requirements
description:
- Manage template configuration type compliance requirements on Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  file:
    description:
    - The name of the template file to upload.
    type: str
  selector_based_on_tags:
    description:
    - Enable object selection based on Tag Annotation or Tag Instance.
    type: bool
    default: false
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
- cisco.nd.ndi_compliance_base
"""

EXAMPLES = r"""
- name: Get all template configuration type compliance requirements
  cisco.nd.nd_compliance_requirement_config_template:
    insights_group: igName
    state: query
  register: query_results

- name: Get a specific template configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_template:
    insights_group: igName
    name: complianceRequirementName
    state: query
  register: query_results

- name: Create template configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_template:
    insights_group: igName
    name: complianceRequirementName
    fabrics:
      - siteName1
      - siteName2
    enabled: false
    file: fileName.json
    state: present

- name: Delete template configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_template:
    insights_group: igName
    name: complianceRequirementName
    state: absent
"""

RETURN = r"""
"""

import os
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.ndi_argument_specs import compliance_base_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(compliance_base_spec())
    argument_spec.update(file=dict(type="str"), selector_based_on_tags=dict(type="bool", default=False))

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "fabrics", "enabled", "file"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    insights_group = nd.params.get("insights_group")
    name = nd.params.get("name")
    description = nd.params.get("description")
    enabled = nd.params.get("enabled")
    fabrics = nd.params.get("fabrics")
    state = nd.params.get("state")
    file = nd.params.get("file")
    selector_based_on_tags = nd.params.get("selector_based_on_tags")

    delete_keys = [
        "complianceRequirementAttachments",
        "uuid",
        "insightsGroupName",
        "isAllTraffic",
        "lastEditedDate",
        "removeNonConfigAttributes",
        "uploadedFileSize",
        "uploadedFileUploadDate",
        "links",
        "uploadedFileExtension",
        "uploadedFileName",
    ]
    path = ndi.requirements_path.format(insights_group)

    requirements = [item for item in ndi.query_requirements(insights_group) if item.get("configurationType") == "TEMPLATE_BASED_CONFIGURATION_COMPLIANCE"]

    uuid = ndi.set_requirement_details(requirements, name)

    if state == "absent" and uuid:
        nd.previous = sanitize_dict(nd.existing, delete_keys)
        if not module.check_mode:
            nd.request(path, method="DELETE", data={"ids": [uuid]}, prefix=ndi.prefix)
        nd.existing = {}

    elif state == "present":
        if uuid:
            filename = "{0}.{1}".format(nd.existing.get("uploadedFileName"), nd.existing.get("uploadedFileExtension"))
            if filename != os.path.basename(file):
                module_name = "template configuration type compliance requirement"
                nd.module.fail_json(
                    msg="The provided filename '{0}' is not matching the filename '{1}' uploaded to the existing {2}".format(
                        os.path.basename(file), filename, module_name
                    )
                )

        nd.previous = sanitize_dict(nd.existing, delete_keys)

        payload = {
            "name": name,
            "enabled": enabled,
            "configurationType": "TEMPLATE_BASED_CONFIGURATION_COMPLIANCE",
            "requirementType": "CONFIGURATION_COMPLIANCE",
            "associatedSites": [{"enabled": True, "uuid": ndi.get_site_id(insights_group, fabric, prefix=ndi.prefix)} for fabric in fabrics],
            "enableEqualityCheck": False,
            "uploadFileType": "TEMPLATE_BASED_CONFIG",
            "enableSelectorBasedOnTags": selector_based_on_tags,
        }

        if description:
            payload.update(description=description)
        elif nd.existing.get("description"):
            payload.update(description=" ")

        if not module.check_mode and payload != nd.previous:
            method = "POST"
            if uuid:
                method = "PATCH"
                payload.update(uuid=uuid)
                response = nd.request("{0}/{1}".format(path, uuid), method=method, data=payload, prefix=ndi.prefix)
            else:
                payload.update(uploadedFileName=file)
                response = nd.request("{0}/file".format(path), method=method, file=os.path.abspath(file), data=payload, prefix=ndi.prefix)
            nd.existing = sanitize_dict(response.get("value", {}).get("data", {}), delete_keys)
        else:
            nd.existing = payload

        filename, extension = os.path.basename(file).rsplit(".", 1)
        for dictionary in [nd.previous, nd.existing]:
            dictionary.update(uploadedFileExtension=extension)
            dictionary.update(uploadedFileName=filename)

    nd.exit_json()


if __name__ == "__main__":
    main()
