#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_site
short_description: Manage sites on Nexus Dashboard.
description:
- Manage sites on Nexus Dashboard which are then used by Nexus Dashboard Orchestrator (NDO).
author:
- Anvitha Jain (@anvitha-jain)
options:
  site_password:
    description:
    - The password for the APIC.
    type: str
  site_username:
    description:
    - The username for the APIC.
    type: str
  login_domain:
    description:
    - The AAA login domain for the username for the APIC.
    type: str
  inband_epg:
    description:
    - The AAA login domain for the username for the APIC.
    type: str
  site:
    description:
    - The name of the site.
    type: str
    aliases: [ name ]
  security_domains:
    description:
    - The security_domains for this site.
    type: list
    elements: str
  latitude:
    description:
    - The latitude of the location of the site.
    type: float
  longitude:
    description:
    - The longitude of the location of the site.
    type: float
  url:
    description:
    - The URL to reference the APICs.
    type: str
  site_type:
    description:
    - The site type of the APICs.
    type: str
    choices: [ aci, dcnm, third_party, cloud_aci, dcnm_ng ]
  re_register:
    description:
    - To modify the APIC parameters (site_username, site_password and login_domain).
    - This option can be set
    type: bool
    default: false
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.nd.modules
"""

EXAMPLES = r"""
- name: Add a new site
  cisco.nd.nd_site:
    host: nd_host
    username: admin
    password: SomeSecretPassword
    site: north_europe
    description: North European Datacenter
    site_username: nd_admin
    site_password: AnotherSecretPassword
    urls:
    - 10.2.3.4
    labels:
    - NEDC
    - Europe
    - Diegem
    location:
      latitude: 50.887318
      longitude: 4.447084
    state: present
  delegate_to: localhost

- name: Remove a site
  cisco.nd.nd_site:
    host: nd_host
    username: admin
    password: SomeSecretPassword
    site: north_europe
    state: absent
  delegate_to: localhost

- name: Query a site
  cisco.nd.nd_site:
    host: nd_host
    username: admin
    password: SomeSecretPassword
    site: north_europe
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all sites
  cisco.nd.nd_site:
    host: nd_host
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.constants import SITE_TYPE_MAP


def validate_not_none(val):
    return val if val is not None else ""


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        site_password=dict(type="str", no_log=True),
        site_username=dict(type="str"),
        login_domain=dict(type="str"),
        inband_epg=dict(type="str"),
        site=dict(type="str", aliases=["name"]),
        url=dict(type="str"),
        site_type=dict(type="str", choices=["aci", "dcnm", "third_party", "cloud_aci", "dcnm_ng"]),
        security_domains=dict(type="list", elements="str"),
        latitude=dict(type="float"),
        longitude=dict(type="float"),
        re_register=dict(type="bool", default=False),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["site"]],
            ["state", "present", ["site", "site_username", "site_password", "url", "site_type"]],
        ],
    )

    nd = NDModule(module)

    site_username = nd.params.get("site_username")
    site_password = nd.params.get("site_password")
    inband_epg = validate_not_none(nd.params.get("inband_epg"))
    login_domain = validate_not_none(nd.params.get("login_domain"))
    site = nd.params.get("site")
    url = nd.params.get("url")
    site_type = nd.params.get("site_type")
    latitude = validate_not_none(nd.params.get("latitude"))
    longitude = validate_not_none(nd.params.get("longitude"))
    security_domains = nd.params.get("security_domains")
    re_register = nd.params.get("site_type")
    state = nd.params.get("state")

    path = "/api/config/class/v2/sites/"

    if site:
        site_info = next((site_dict.get("name") for site_dict in nd.query_obj(path) if site_dict.get("name") == site), None)
        if site_info:
            path = "/api/config/dn/v2/sites/{0}".format(site)
            nd.existing = nd.query_obj(path)
    else:
        nd.existing = nd.query_obj(path)

    nd.previous = nd.existing

    if state == "query":
        pass
    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                rm_path = "/api/config/v2/deletesite/"
                rm_payload = {
                    "name": site,
                    "aci": {
                        "userName": site_username,
                        "password": site_password,
                        "loginDomain": login_domain,
                    },
                }
                rm_resp = nd.request(rm_path, method="POST", data=rm_payload)
                if rm_resp["response"] is not None:
                    nd.existing = {}
            nd.existing = {}
    elif state == "present":
        add_path = "/api/config/v2/addsite/"
        payload = {
            "name": site,
            "url": url,
            "siteType": SITE_TYPE_MAP.get(site_type),
            "aci": {
                "userName": site_username,
                "password": site_password,
                "loginDomain": login_domain,
                "inbandEpgDN": inband_epg,
            },
            "latitude": str(latitude),
            "longitude": str(longitude),
            "securityDomains": security_domains if security_domains is not None else [],
        }

        nd.sanitize(payload, collate=True)  # check it is applies everything or just modified value.

        if not module.check_mode:
            if nd.existing:
                add_path = "/api/config/v2/modifysite/"

            unwanted = ["url", ["aci", "userName"], ["aci", "password"], ["aci", "loginDomain"], ["aci", "switches"], ["aci", "appUserName"]]
            if nd.get_diff(unwanted):
                nd.existing = nd.request(add_path, method="POST", data=payload)
            else:
                nd.has_modified = True
                nd.result["changed"] = False

    nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
