#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Akini Ross (@akinross) <akinross@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_policy_cam_statistics_hit_counts
version_added: "0.5.0"
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
    - The name of the site.
    type: str
    required: true
    aliases: [ site_name ]
  epoch_id:
    description:
    - The id of the epoch.
    - When epoch id is not provided it will retrieve the latest known epoch id.
    - The M(cisco.nd.nd_epoch) can be used to retrieve a specific epoch id.
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
  filter_by_attributes:
    description:
    - Container for all filter by attributes pairs.
    type: list
    elements: dict
    suboptions:
      key:
        description:
        - The key of the attribute to match.
        type: str
        required: true
        choices: [ provider_epg, consumer_epg, provider_tenant, consumer_tenant, contract, filter, consumer_vrf, action, leaf ]
      value:
        description:
        - The value of the attribute to match.
        type: str
        required: true
  output_csv:
    description:
    - Path to a file to save the generated csv file.
    - When extension is not matching .csv it will be added automatically.
    type: str
extends_documentation_fragment:
- cisco.nd.modules
"""

EXAMPLES = r"""
- name: Get Policy CAM Statistics Hit Counts for epgs, tenants, and leafs
  cisco.nd.nd_policy_cam_statistics_hit_counts:
    insights_group: igName
    site: siteName
    epgs: true
    tenants: true
    leafs: true
  register: query_results

- name: Get Policy CAM Statistics Hit Counts for epgs, with a specific epoch_id
  cisco.nd.nd_policy_cam_statistics_hit_counts:
    insights_group: igName
    site: siteName
    epoch_id: 0e5604f9-373a123c-b535-33fc-8d11-672d08f65fd1
    epgs: true
  register: query_results

- name: Get Policy CAM Statistics Hit Counts for contracts, filters, and a attributes filtering
  cisco.nd.nd_policy_cam_statistics_hit_counts:
    insights_group: igName
    site: siteName
    contracts: true
    filters: true
    filter_by_attributes:
      - key: providerEpgName
        value: log_epg
      - key: consumerEpgName
        value: app_epg
  register: query_results

- name: Get Policy CAM Statistics Hit Counts for epgs, leafs, contracts, filters, and output to csv
  cisco.nd.nd_policy_cam_statistics_hit_counts:
    insights_group: igName
    site: siteName
    epgs: true
    leafs: true
    contracts: true
    filters: true
    output_csv: hits.csv
  register: query_results
"""

RETURN = r"""
"""

import csv

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.ndi import NDI
from ansible_collections.cisco.nd.plugins.module_utils.constants import FILTER_BY_ATTIRBUTES_KEYS


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
        filter_by_attributes=dict(
            type="list",
            elements="dict",
            options=dict(
                key=dict(
                    type="str",
                    required=True,
                    choices=list(FILTER_BY_ATTIRBUTES_KEYS.keys()),
                ),
                value=dict(type="str", required=True),
            ),
        ),
        output_csv=dict(type="str"),
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
    filter_by_attributes = nd.params.get("filter_by_attributes")
    output_csv = nd.params.get("output_csv")

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

    filter_by_attributes_result = ""
    if filter_by_attributes:
        filter_by_attributes_result = "&%24filter="
        filter_by_attributes_result += "%2C".join(
            ["{0}%3A{1}".format(FILTER_BY_ATTIRBUTES_KEYS.get(x.get("key")), x.get("value")) for x in filter_by_attributes]
        )

    path = "{0}/model/aciPolicy/tcam/hitcountByRules/{1}?%24epochId={2}&%24view=histogram{3}".format(
        ndi.event_insight_group_path.format(insights_group, site), hit_count_pair, epoch_id, filter_by_attributes_result
    )

    response = nd.request(path, method="GET", prefix=ndi.prefix)

    nd.existing = response.get("value", {})

    if output_csv:
        output_csv = output_csv if output_csv.endswith(".csv") else "{0}.csv".format(output_csv)
        with open(output_csv, "w") as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=",")
            csv_writer.writerow(get_header_row(epgs, tenants, leafs, contracts, filters))
            for bucket in nd.existing.get("data", []):
                csv_writer.writerow(get_data_row(epgs, tenants, leafs, contracts, filters, bucket))

    nd.exit_json()


def get_header_row(epgs, tenants, leafs, contracts, filters):
    header_row = []
    if epgs:
        header_row.extend(["Provider Epg", "Consumer Epg"])
    if tenants:
        header_row.extend(["Provider Tenant", "Consumer Tenant"])
    if leafs:
        header_row.extend(["Leaf"])
    if contracts:
        header_row.extend(["Contract"])
    if filters:
        header_row.extend(["Filter"])
    header_row.extend(["Consumer VRF", "Action", "Cumulative", "Policy Cam Count"])
    return header_row


def get_data_row(epgs, tenants, leafs, contracts, filters, bucket):
    data_row = []
    if epgs:
        data_row.extend([bucket.get("bucket", {}).get("providerEpg", {}).get("name"), bucket.get("bucket", {}).get("consumerEpg", {}).get("name")])
    if tenants:
        data_row.extend([bucket.get("bucket", {}).get("providerTenant", {}).get("name"), bucket.get("bucket", {}).get("consumerTenant", {}).get("name")])
    if leafs:
        data_row.extend([bucket.get("bucket", {}).get("leaf", {}).get("nodeName")])
    if contracts:
        data_row.extend([bucket.get("bucket", {}).get("contract", {}).get("name")])
    if filters:
        data_row.extend([bucket.get("bucket", {}).get("filter", {}).get("name")])
    data_row.extend(
        [
            bucket.get("bucket", {}).get("consumerVrf", {}).get("name"),
            bucket.get("bucket", {}).get("action"),
            bucket.get("output", {}).get("cumulativeCount"),
            bucket.get("output", {}).get("tcamEntryCount"),
        ]
    )
    return data_row


if __name__ == "__main__":
    main()
