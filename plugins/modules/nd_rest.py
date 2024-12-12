#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, Gaspard Micol (@gmicol) <gmicol@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_rest
short_description: Direct access to the Cisco Nexus Dashboard REST API
description:
- Enables the management of Cisco Nexus Dashboard (ND) through direct access to the Cisco ND REST API.
author:
- Gaspard Micol (@gmicol)
options:
  method:
    description:
    - The HTTP method of the request.
    - Using C(delete) is typically used for deleting objects.
    - Using C(get) is typically used for querying objects.
    - Using C(post) is typically used for modifying objects.
    - Using C(put) is typically used for modifying existing objects.
    - Using C(patch) is typically also used for modifying existing objects.
    type: str
    choices: [ delete, get, post, put, patch ]
    default: get
    aliases: [ action ]
  path:
    description:
    - URI being used to execute API calls.
    type: str
    required: true
    aliases: [ uri ]
  content:
    description:
    - Sets the payload of the API request directly.
    - This may be convenient to template simple requests.
    - For anything complex use the C(template) lookup plugin (see examples).
    type: raw
    aliases: [ payload ]
extends_documentation_fragment:
- cisco.nd.modules

notes:
- Some payloads are known not to be idempotent, so be careful when constructing payloads.
"""

EXAMPLES = r"""
- name: Create Security Domain using POST method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains
    method: post
    content:
      {
        "spec": {
          "description": "Security Domain Test for nd_rest module.",
          "name": "ansible_security_domain_test"
        }
      }

- name: Update Security Domain using PUT method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains/ansible_security_domain_test
    method: put
    content:
      {
        "spec": {
          "description": "Updated Security Domain Test for nd_rest module."
        }
      }

- name: Query Security Domain using GET method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains/ansible_security_domain_test
    method: get
  register: quey_one

- name: Query all Security Domains using GET method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains
    method: get
  register: quey_all

- name: Remove Security Domain using DELETE method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains/ansible_security_domain_test
    method: delete
"""

RETURN = r"""
"""

# Optional, only used for YAML validation
try:
    import yaml

    HAS_YAML = True
except Exception:
    HAS_YAML = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec
from ansible.module_utils._text import to_text


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        path=dict(type="str", required=True, aliases=["uri"]),
        method=dict(type="str", default="get", choices=["delete", "get", "post", "put", "patch"], aliases=["action"]),
        content=dict(type="raw", aliases=["payload"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    content = module.params.get("content")
    path = module.params.get("path")

    nd = NDModule(module)

    # Validate content/payload
    if content and isinstance(content, str) and HAS_YAML:
        try:
            # Validate YAML/JSON string
            content = yaml.safe_load(content)
        except Exception as e:
            module.fail_json(msg="Failed to parse provided JSON/YAML payload: %s" % to_text(e), exception=to_text(e), payload=content)

    method = nd.params.get("method").upper()

    # Append previous state of the object
    if method in ("PUT", "DELETE"):
        nd.existing = nd.query_obj(path, ignore_not_found_error=True)
        nd.previous = nd.existing
    if method != "GET":
        nd.result["previous"] = nd.previous

    # Perform request
    if module.check_mode:
        nd.result["jsondata"] = content
    else:
        nd.result["jsondata"] = nd.request(path, method=method, data=content)
        nd.existing = nd.result["jsondata"]

    # Report changes for idempotency depending on methods
    nd.result["status"] = nd.status
    if nd.result["jsondata"] != nd.previous and method != "GET":
        nd.result["changed"] = True

    # Report success
    nd.exit_json(**nd.result)


if __name__ == "__main__":
    main()
