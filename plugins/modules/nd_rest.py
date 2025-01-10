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
    - Using C(delete) is used for deleting objects.
    - Using C(get) is used for querying objects.
    - Using C(post) is used for modifying objects.
    - Using C(put) is used for modifying existing objects.
    - Using C(patch) is also used for modifying existing objects.
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
    type: raw
    aliases: [ payload ]
  file_path:
    description:
    - Name of the absolute path of the filename that includes the body
      of the HTTP request.
    - If templated payload is required, use the C(content) parameter
      together with the C(template) lookup plugin, or use C(template).
    type: path
    aliases: [ config_file ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
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
  register: query_one

- name: Query all Security Domains using GET method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains
    method: get
  register: query_all

- name: Remove Security Domain using DELETE method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /nexus/infra/api/aaa/v4/securitydomains/ansible_security_domain_test
    method: delete

- name: Create a Fabric Policy Template on NDO using POST method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: /mso/api/v1/templates
    method: post
    content:
      {
        "displayName": "ansible_nd_rest_fabric_policies_template",
        "fabricPolicyTemplate": {},
        "templateType": "fabricPolicy"
      }
  register: create_fabric_policies_template

- name: Update Fabric Policy Template on NDO using PATCH method
  cisco.nd.nd_rest:
    host: nd
    username: admin
    password: SomeSecretPassword
    path: "/mso/api/v1/templates/{{ create_fabric_policies_template.current.templateId }}"
    method: patch
    content:
      [
        {
          "op": "replace",
          "path": "/fabricPolicyTemplate/template/domains",
          "value": [
            {
              "name": "ansible_nd_rest_physical_domain",
              "description": "Ansible nd_rest Physical Domain test for PATCH",
              "pool": ""
            }
          ]
        }
      ]
"""

RETURN = r"""
"""

import json
import os

# Optional, only used for YAML validation
try:
    import yaml

    HAS_YAML = True
except Exception:
    HAS_YAML = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec, sanitize
from ansible.module_utils._text import to_text


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        path=dict(type="str", required=True, aliases=["uri"]),
        method=dict(type="str", default="get", choices=["delete", "get", "post", "put", "patch"], aliases=["action"]),
        content=dict(type="raw", aliases=["payload"]),
        file_path=dict(type="path", aliases=["config_file"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    content = module.params.get("content")
    path = module.params.get("path")
    file_path = module.params.get("config_file")

    nd = NDModule(module)

    # Report missing file
    if file_path and not os.path.isfile(file_path):
        module.fail_json(msg="Cannot find/access file '{0}'".format(file_path))

    # Validate payload/content with PyYAML package
    if content and isinstance(content, str) and HAS_YAML:
        try:
            # Validate YAML/JSON string
            content = yaml.safe_load(content)
        except Exception as e:
            module.fail_json(msg="Failed to parse provided YAML/JSON payload: %s" % to_text(e), exception=to_text(e), payload=content)
    # Validate payload/content only with json Python package
    elif content and isinstance(content, str):
        try:
            # Validate JSON object/string
            content = json.loads(content)
        except Exception as e:
            module.fail_json(
                msg="Missing PyYAML package to parse YML payload or failed to parse provided JSON payload: %s" % to_text(e),
                exception=to_text(e),
                payload=content,
            )

    method = nd.params.get("method").upper()
    keys_to_sanitize = ["metadata"]

    # Append previous state of the object
    if method in ("PUT", "DELETE", "PATCH"):
        nd.existing = nd.previous = sanitize(nd.query_obj(path, ignore_not_found_error=True), keys_to_sanitize)
    if method != "GET":
        nd.result["previous"] = nd.previous

    # Perform request
    if module.check_mode:
        nd.result["jsondata"] = content
    else:
        nd.result["jsondata"] = nd.request(path, method=method, data=content, file=file_path)
        nd.existing = sanitize(nd.result["jsondata"], keys_to_sanitize)

    # Report changes for idempotency depending on methods
    nd.result["status"] = nd.status
    if sanitize(nd.result["jsondata"], keys_to_sanitize) != nd.previous and method != "GET":
        nd.result["changed"] = True

    # Report success
    nd.exit_json(**nd.result)


if __name__ == "__main__":
    main()
