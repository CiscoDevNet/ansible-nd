#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import base64

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_site
short_description: Manage sites on Nexus Dashboard.
description:
- Manage sites on Nexus Dashboard which are then used by Nexus Dashboard Orchestrator (NDO) >= 2.2(2d).
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
  site_name:
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
    aliases=[ host_name, ip_address]
  site_type:
    description:
    - The site type of the APICs.
    type: str
    choices: [ aci, dcnm, third_party, cloud_aci, dcnm_ng ]
  re_register:
    description:
    - To modify the APIC parameters (site_username, site_password and login_domain).
    - Using this option deletes the existing site and re-creates it.
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
    url: nd_host
    username: admin
    password: SomeSecretPassword
    site_name: north_europe
    site_username: nd_admin
    site_password: SomeSecretPassword
    site_type: aci
    location:
      latitude: 50.887318
      longitude: 4.447084
    login_domain: "DefaultAuth"
    inband_epg: In-Band-EPG
    state: present
  delegate_to: localhost

- name: Remove a site
  cisco.nd.nd_site:
    url: nd_host
    username: admin
    password: SomeSecretPassword
    site_name: north_europe
    state: absent
  delegate_to: localhost

- name: Query a site
  cisco.nd.nd_site:
    url: nd_host
    username: admin
    password: SomeSecretPassword
    site_name: north_europe
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all sites
  cisco.nd.nd_site:
    url: nd_host
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


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        site_password=dict(type="str", no_log=True),
        site_username=dict(type="str"),
        login_domain=dict(type="str"),
        inband_epg=dict(type="str"),
        site_name=dict(type="str", aliases=["name", "fabric_name"]),
        url=dict(type="str", aliases=["host_name", "ip_address"]),
        site_type=dict(type="str", choices=list(SITE_TYPE_MAP.keys())),
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
            ["state", "absent", ["site_name"]],
            ["state", "present", ["site_name", "site_username", "site_password", "url", "site_type"]],
        ],
    )

    nd = NDModule(module)

    site_username = nd.params.get("site_username")

    site_password = nd.params.get("site_password")
    if site_password is not None:
        # Make password base64 encoded
        site_password = (base64.b64encode(str.encode(site_password))).decode("utf-8")

    inband_epg = nd.set_to_empty_string_when_none(nd.params.get("inband_epg"))
    if inband_epg is not "":
        inband_epg = "uni/tn-mgmt/mgmtp-default/inb-{0}".format(inband_epg)

    login_domain = nd.set_to_empty_string_when_none(nd.params.get("login_domain"))
    site_name = nd.params.get("site_name")
    url = nd.params.get("url")
    site_type = nd.params.get("site_type")
    latitude = nd.set_to_empty_string_when_none(nd.params.get("latitude"))
    longitude = nd.set_to_empty_string_when_none(nd.params.get("longitude"))
    security_domains = nd.params.get("security_domains")
    re_register = nd.params.get("re_register")
    state = nd.params.get("state")

    path = "/nexus/api/sitemanagement/v4/sites"

    if site_name:
        site_info = next((site_dict.get("spec").get("name") for site_dict in nd.query_obj(path).get("items") if site_dict.get("spec").get("name") == site_name), None)
        if site_info:
            if re_register:
                nd.request(path, method="DELETE")
            else: 
                path = "{0}/{1}".format(path, site_name)
                nd.existing = nd.query_obj(path)
    else:
        nd.existing = nd.query_obj(path).get('items')

    nd.previous = nd.existing

    if state == "query":
        nd.exit_json()
    elif state == "absent":
        if nd.existing:
            if not module.check_mode:
                rm_resp = nd.request(path, method="DELETE")
                if rm_resp is {}:
                    nd.existing = {}
            nd.existing = {}
    elif state == "present":
        site_configuration = {}
        if site_type == "aci" or site_type == "cloud_aci":
            site_type_param = site_type
            if site_type == "cloud_aci":
                site_type_param = SITE_TYPE_MAP.get(site_type)
            site_configuration.update(
                {
                    site_type_param: {
                        "InbandEPGDN": inband_epg,
                    }
                }
            )
        elif site_type == "ndfc" or site_type == "dcnm":
            site_configuration.update(
                {
                    site_type: {
                        "fabricName": site_name,
                        "fabricTechnology": "External",
                        "fabricType": "External"
                    }
                }
            )

        payload = {
            "spec": {
                "name": site_name,
                "siteType": SITE_TYPE_MAP.get(site_type),
                "host": url,
                "userName": site_username,
                "password": site_password,
                "loginDomain": login_domain,
                "loginDomain": "DefaultAuth",
                "latitude": str(latitude),
                "longitude": str(longitude),
                # "securityDomains": security_domains if security_domains is not None else [],
                "siteConfig": site_configuration
            },
        }
        # ToDo: To avail the securityDomains feature, ND v4 API update is required.

        nd.sanitize(payload, collate=True)

        if not module.check_mode:
            method = "POST"
            if nd.existing:
                method = "PUT"

            unwanted = [
                "metadata",
                "status",
                ["spec", "annotation"],
                ["spec", "host"],
                ["spec", "userName"],
                ["spec", "password"],
                ["spec", "loginDomain"],
                ["spec", "useProxy"],
                ["spec", "secureVerify"],
                ["spec", "internalOnboard"]
            ]
            if nd.get_diff(unwanted):
                nd.existing = nd.request(path, method=method, data=payload)
            else:
                nd.has_modified = True

    nd.existing = nd.proposed

    nd.exit_json()


if __name__ == "__main__":
    main()
