#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_compliance_requirement_config_snapshot
version_added: "0.3.0"
short_description: Manage snapshot configuration type compliance requirements
description:
- Manage snapshot configuration type compliance requirements on Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  baseline_fabric:
    description:
    - Name of the fabric to set as baseline.
    type: str
    aliases: [ site, site_name, baseline_site, fabric, fabric_name ]
  snapshot_id:
    description:
    - The snapshot/epoch ID.
    - When O(snapshot_id) is not provided it will retrieve the latest known snapshot/epoch ID.
    type: str
    aliases: [ epoch_id ]
  allow_new_configuration_objects:
    description:
    - Allow addition of new configuration objects.
    type: bool
    default: false
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
- cisco.nd.ndi_compliance_base
"""

EXAMPLES = r"""
- name: Get all snapshot configuration type compliance requirements
  cisco.nd.nd_compliance_requirement_config_snapshot:
    insights_group: igName
    state: query
  register: query_results

- name: Get a specific snapshot configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_snapshot:
    insights_group: igName
    name: complianceRequirementName
    state: query
  register: query_results

- name: Create snapshot configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_snapshot:
    insights_group: igName
    name: complianceRequirementName
    fabrics:
      - fabricName1
      - fabricName2
    enabled: false
    snapshot_id: 0e5604f9-373a123c-b535-33fc-8d11-672d08f65fd1
    state: present

- name: Delete snapshot configuration type compliance requirement
  cisco.nd.nd_compliance_requirement_config_snapshot:
    insights_group: igName
    name: complianceRequirementName
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize_dict
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.ndi_argument_specs import compliance_base_spec


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(compliance_base_spec())
    argument_spec.update(
        snapshot_id=dict(type="str", aliases=["epoch_id"]),
        baseline_fabric=dict(type="str", aliases=["site", "site_name", "baseline_site", "fabric", "fabric_name"]),
        allow_new_configuration_objects=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name", "fabrics", "enabled", "baseline_fabric"]],
        ],
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    insights_group = nd.params.get("insights_group")
    name = nd.params.get("name")
    description = nd.params.get("description")
    enabled = nd.params.get("enabled")
    fabrics = nd.params.get("fabrics")
    baseline_fabric = nd.params.get("baseline_fabric")
    snapshot_id = nd.params.get("snapshot_id")
    allow_new_configuration_objects = nd.params.get("allow_new_configuration_objects")
    state = nd.params.get("state")

    delete_keys = [
        "baseEpochCollectionTimestamp",
        "baseEpochCollectionTimestampRFC3339",
        "isAllTraffic",
        "links",
        "complianceRequirementAttachments",
        "insightsGroupName",
        "lastEditedDate",
        "uploadedFileUploadDate",
        "removeNonConfigAttributes",
        "uuid",
    ]
    path = ndi.requirements_path.format(insights_group)

    requirements = [item for item in ndi.query_requirements(insights_group) if item.get("configurationType") == "SNAPSHOT_BASED_CONFIGURATION_COMPLIANCE"]

    uuid = ndi.set_requirement_details(requirements, name)

    if state == "absent" and uuid:
        nd.previous = sanitize_dict(nd.existing, delete_keys)
        if not module.check_mode:
            nd.request(path, method="DELETE", data={"ids": [uuid]}, prefix=ndi.prefix)
        nd.existing = {}

    elif state == "present":
        nd.previous = sanitize_dict(nd.existing, delete_keys)

        if not snapshot_id:
            snapshot_id = ndi.get_last_epoch(insights_group, baseline_fabric).get("epochId")

        payload = {
            "name": name,
            "enabled": enabled,
            "configurationType": "SNAPSHOT_BASED_CONFIGURATION_COMPLIANCE",
            "requirementType": "CONFIGURATION_COMPLIANCE",
            "associatedSites": [{"enabled": True, "uuid": ndi.get_site_id(insights_group, fabric, prefix=ndi.prefix)} for fabric in fabrics],
            "baseEpochId": snapshot_id,
            "enableEqualityCheck": not allow_new_configuration_objects,
        }

        if description:
            payload.update(description=description)
        elif nd.existing.get("description"):
            payload.update(description=" ")

        if not module.check_mode and payload != nd.previous:
            method = "POST"
            if uuid:
                method = "PUT"
                path = "{0}/{1}".format(path, uuid)
                payload.update(uuid=uuid)
            response = nd.request(path, method=method, data=payload, prefix=ndi.prefix)
            nd.existing = sanitize_dict(response.get("value", {}).get("data", {}), delete_keys)
        else:
            nd.existing = payload

    nd.exit_json()


if __name__ == "__main__":
    main()
