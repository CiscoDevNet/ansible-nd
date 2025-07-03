#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Dev Sinha (@DevSinha13) <devsinh@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

from copy import deepcopy
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec

DOCUMENTATION = r"""
---
module: nd_api_key
version_added: "1.4.0"
short_description: Manage API keys in Nexus Dashboard
description:
- This module allows you to manage API keys in Cisco Nexus Dashboard.
- It supports creating, updating, querying, and deleting API keys.
- API key names must be 1-32 characters long and can only contain letters, digits, '_', '.', and '-'.
author:
- Dev Sinha (@DevSinha13)
options:
  api_key_id:
    description:
    - The ID of the API key to manage.
    - Required when state is 'absent' if api_key_name is not specified.
    type: str
  api_key_name:
    description:
    - The name/description of the API key.
    - Required when state is 'present'.
    - Must be 1-32 characters long.
    - Only alphanumeric characters, underscores, periods, and hyphens are allowed.
    type: str
    aliases: [ description ]
  annotations:
    description:
    - Key-value pairs of annotations to add to the API key.
    type: dict
    default: {}
  state:
    description:
    - The desired state of the API key.
    type: str
    choices: [ present, absent, query ]
    default: present
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Create a new API key
  cisco.nd.nd_api_key:
    api_key_name: "ansible_test_key"
    annotations:
      owner: "ansible"
      purpose: "automation"
    state: present
  register: result

- name: Create API key with minimal config
  cisco.nd.nd_api_key:
    api_key_name: "simple_key"
    state: present

- name: Query an existing API key by name
  cisco.nd.nd_api_key:
    api_key_name: "ansible_test_key"
    state: query
  register: query_result

- name: Query all API keys
  cisco.nd.nd_api_key:
    state: query
  register: all_keys

- name: Delete an API key by ID
  cisco.nd.nd_api_key:
    api_key_id: "12345678-1234-1234-1234-1234567890ab"
    state: absent

- name: Delete an API key by name
  cisco.nd.nd_api_key:
    api_key_name: "ansible_test_key"
    state: absent

- name: Update API key annotations
  cisco.nd.nd_api_key:
    api_key_name: "existing_key"
    annotations:
      owner: "updated_owner"
      environment: "production"
    state: present
"""

RETURN = r"""
current:
  description: The current state of the API key after the task has been performed.
  returned: always
  type: dict
  sample:
    apiKeyName: "ansible_test_key"
    id: "12345678-1234-1234-1234-1234567890ab"
    key: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
    annotations:
      owner: "ansible"
      purpose: "automation"
    createdTime: "2025-01-01T12:00:00.000Z"
    lastUsedTime: "2025-01-01T12:30:00.000Z"

previous:
  description: The previous state of the API key before the task was performed.
  returned: when state is changed
  type: dict
  sample:
    apiKeyName: "ansible_test_key"
    id: "12345678-1234-1234-1234-1234567890ab"
    annotations:
      owner: "old_owner"

proposed:
  description: The proposed configuration that would be applied.
  returned: when check_mode is enabled
  type: dict
  sample:
    apiKeyName: "ansible_test_key"
    annotations:
      owner: "ansible"
      purpose: "automation"
"""

def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        api_key_id=dict(type="str"),
        api_key_name=dict(type="str", aliases=["description"]),
        annotations=dict(type="dict", default={}),
        state=dict(type="str", default="present", choices=["present", "absent", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "present", ["api_key_name"]],
            ["state", "absent", ["api_key_name", "api_key_id"], True],
        ],
    )

    nd = NDModule(module)

    api_key_id = nd.params.get("api_key_id")
    api_key_name = nd.params.get("api_key_name")
    annotations = nd.params.get("annotations")
    state = nd.params.get("state")

    path = "/api/v1/infra/aaa/apiKeys"
    nd.stdout = ""
    if api_key_id:
        query_path = "{0}/{1}".format(path, api_key_id)
        nd.existing = nd.previous = deepcopy(nd.query_obj(query_path))
    elif api_key_name:
        nd.existing = nd.previous = deepcopy(nd.get_obj(path, key="apiKeys", apiKeyName=api_key_name))
    else:
        nd.existing = nd.previous = nd.query_objs(path, key="apiKeys")
    
    if state == "present":

        if len(api_key_name) > 32:
            nd.fail_json("A length of 1 to 32 characters is allowed.")
        elif re.search(r'[^a-zA-Z0-9_.-]', api_key_name):
            nd.fail_json("API Key name contains invalid characters. Valid characters include letters, digits, '_', '.', and '-'.")
            
        payload = {
            "apiKeyName": api_key_name,
            "annotations": annotations,
        }

        nd.sanitize(payload)
        
        if not module.check_mode:
            if nd.existing:
                if nd.existing.get("apiKeyName") != api_key_name or nd.existing.get("annotations") != annotations:
                    nd.previous = nd.existing
                    update_path = "{0}/{1}".format(path, api_key_id)
                    nd.request(update_path, method="PUT", data=payload)
                    nd.existing = nd.query_obj(update_path)
            else:
                resp = nd.request(path, method="POST", data=payload)
                if isinstance(resp, dict) and "id" in resp:
                    nd.existing = resp
        else:
            nd.previous = nd.existing
            nd.existing = nd.proposed
            
        if nd.existing != nd.previous:
            nd.changed = True
            
    elif state == "absent":
        if nd.existing:
            nd.previous = nd.existing
            if not module.check_mode:
                delete_path = "{0}/{1}".format(path, nd.existing["id"])
                nd.request(delete_path, method="DELETE")
              
            nd.existing = {}
            nd.changed = True

    nd.exit_json()


if __name__ == "__main__":
    main()
