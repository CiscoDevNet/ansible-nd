#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Dev Sinha (@DevSinha13) <devsinh@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

from datetime import datetime as dt, timedelta
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec

def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        api_key_id=dict(type="str"),
        api_key_name=dict(type="str", aliases=["description"]),
        annotations=dict(type="dict"),
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

    path = "api/v1/infra/aaa/apiKeys"

    if api_key_id:
        # existing_key = next((key for key in keyList if key.get("id") == api_key_id), None)
        query_path = "{0}/{1}".format(path, api_key_id)
        nd.existing = nd.query_obj(query_path)
    elif api_key_name:
        # existing_key = next((key for key in keyList if key.get("apiKeyName") == api_key_name), None)
        nd.existing = nd.get_obj(path, apiKeyName=api_key_name)
    else:
        nd.existing = nd.query_objs(path).get("apiKeys", [])

    if state == "present":
        
        payload = {
            "apiKeyName": api_key_name
        }
                  
        if annotations:
            payload["annotations"] = annotations

        nd.proposed = payload
        nd.sent = payload
        
        if not module.check_mode:
            if nd.existing:
                nd.previous = nd.existing
                if nd.existing.get("apiKeyName") != api_key_name or nd.existing.get("annotations") != annotations:
                    update_path = "{0}/{1}".format(path, api_key_id)
                    nd.request(update_path, method="PUT", data=payload)
                    nd.existing = nd.query_obj(update_path)
            else:
                resp = nd.request(path, method="POST", data=payload)
                if isinstance(resp, dict) and "id" in resp:
                    nd.existing = resp
        else:
            nd.existing = nd.proposed
        
        if nd.existing != nd.previous:
            nd.changed = True
            
    elif state == "absent":
        if nd.existing:
            nd.previous = nd.existing
            delete_path = "{0}/{1}".format(path, nd.existing["id"])
            
            if not module.check_mode:
                nd.request(delete_path, method="DELETE")
              
            nd.changed = True
            nd.existing = {}

    nd.exit_json()


if __name__ == "__main__":
    main()
