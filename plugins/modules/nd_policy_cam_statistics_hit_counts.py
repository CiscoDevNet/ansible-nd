#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_policy_cam_statistics_hit_counts
version_added: "0.4.1"
short_description: Retrieves Policy CAM Statistics Hit Counts
description:
- Retrieves Policy CAM Statistics Hit Counts on Cisco Nexus Dashboard Insights (NDI).
author:
- Akini Ross (@akinross)
options:
  insights_group:
    description:
    - The name of the insights group.
    type: str
    required: true
    aliases: [ fab_name, ig_name ]
  site:
    description:
    - Name of the Assurance Entity to set as baseline.
    type: str
    required: true
    aliases: [ site_name ]
  epoch_id:
    description:
    - The id of the epoch.
    - When epoch id is not provided it will retrieve the latest known epoch id.
    type: str
  epgs:
    description:
    - All Policy CAM Rules by Hit Count by EPGs.
    type: bool
    default: false
  tenants:
    description:
    - All Policy CAM Rules by Hit Count by Tenants.
    type: bool
    default: false
  leafs:
    description:
    - All Policy CAM Rules by Hit Count by Leafs.
    type: bool
    default: false
  contracts:
    description:
    - All Policy CAM Rules by Hit Count by Contracts.
    type: bool
    default: false
  filters:
    description:
    - All Policy CAM Rules by Hit Count by Filters.
    type: bool
    default: false
extends_documentation_fragment:
- cisco.nd.modules
"""

EXAMPLES = r"""
- name: Get Policy CAM Statistics Hit Counts for epgs, tenants, and leafs
  cisco.nd.nd_policy_cam_statistics_hit_counts:
    insights_group: igName
    site: siteName
    epoch_id: 0e5604f9-373a123c-b535-33fc-8d11-672d08f65fd1
    epgs: true
    tenants: true
    leafs: true
    state: query
  register: query_results
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        insights_group=dict(type="str", required=True, aliases=["fab_name", "ig_name"]),
        site=dict(type="str", required=True, aliases=["site_name"]),
        epoch_id=dict(type="str"),
        epgs=dict(type="bool", default=False),
        tenants=dict(type="bool", default=False),
        leafs=dict(type="bool", default=False),
        contracts=dict(type="bool", default=False),
        filters=dict(type="bool", default=False),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    nd = NDModule(module)
    ndi = NDI(nd)

    insights_group = nd.params.get("insights_group")
    site = nd.params.get("site")
    epoch_id = nd.params.get("epoch_id") if nd.params.get("epoch_id") else ndi.get_last_epoch(insights_group, site).get("epochId")
    epgs = nd.params.get("epgs")
    tenants = nd.params.get("tenants")
    leafs = nd.params.get("leafs")
    contracts = nd.params.get("contracts")
    filters = nd.params.get("filters")

    if tenants and (contracts or filters):
        module.fail_json(msg="cannot specify contracts or filters with tenants")
    elif epgs and tenants and leafs:
        hit_count_pair = "hitcountByEpgPairTenantPairLeaf"
    elif epgs and tenants:
        hit_count_pair = "hitcountByEpgpairTenantPair"  # Pair is lower letter for epg on purpose, deviates in API
    elif epgs and leafs and contracts and filters:
        hit_count_pair = "hitcountByEpgPairContractFilterLeaf"
    elif epgs and leafs and contracts:
        hit_count_pair = "hitcountByEpgPairContractLeaf"
    elif epgs and leafs:
        hit_count_pair = "hitcountByEpgPairLeaf"
    elif epgs and contracts and filters:
        hit_count_pair = "hitcountByEpgPairContractFilter"
    elif epgs and contracts:
        hit_count_pair = "hitcountByEpgPairContract"
    elif epgs:
        hit_count_pair = "hitcountByEpgPair"
    elif tenants and leafs:
        hit_count_pair = "hitcountByTenantPairLeaf"
    elif tenants:
        hit_count_pair = "hitcountByTenantPair"
    else:
        module.fail_json(msg="must specify at least epgs or tenants")

    path = "{0}/model/aciPolicy/tcam/hitcountByRules/{1}?%24epochId={2}&%24view=histogram".format(
        ndi.event_insight_group_path.format(insights_group, site), hit_count_pair, epoch_id
    )

    response = nd.request(path, method="GET", prefix=ndi.prefix)

    nd.existing = response.get("value", {})

    nd.exit_json()


if __name__ == "__main__":
    main()
