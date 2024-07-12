#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Lionel Hercot (@lhercot) <lhercot@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_version
version_added: "0.1.0"
short_description: Get version of Nexus Dashboard (ND)
description:
- Retrieve the code version of Cisco Nexus Dashboard (ND).
author:
- Lionel Hercot (@lhercot)
options:
  state:
    description:
    - Use C(query) for retrieving the version object.
    type: str
    choices: [ query ]
    default: query
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Get Nexus Dahsboard version
  cisco.nd.nd_version:
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


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(state=dict(type="str", default="query", choices=["query"]))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    nd = NDModule(module)

    path = "/version.json"

    # Query for nd.existing object
    nd.existing = nd.query_obj(path)
    nd.exit_json()


if __name__ == "__main__":
    main()
