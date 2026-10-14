#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Create exactly one L3Out through the controller's create-only endpoint.

This module is intentionally narrow and exists for the ND 4.x integration
harness.  Unlike ``nd_manage_l3out state=merged``, it never performs a
read-before-create.  The controller therefore arbitrates ownership of the
marker when multiple harness workers race to create it.
"""

from __future__ import absolute_import, division, print_function

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection

from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import nd_argument_spec

DOCUMENTATION = r"""
---
module: nd4x_l3out_create_lock
short_description: Atomically claim an ND 4.x L3Out harness marker
version_added: "2.0.0"
description:
  - Sends exactly one create-only POST for an L3Out marker.
  - Does not perform a read-before-create, allowing the controller to arbitrate
    concurrent marker claims.
  - Fails on duplicate-name or other per-item controller failures.
author:
  - Astha Awasthi (@astawast)
options:
  config:
    description:
      - One complete L3Out configuration to create as the ownership marker.
    type: dict
    required: true
notes:
  - This is a harness support module, not a replacement for nd_manage_l3out.
  - The controller's L3Out POST endpoint is responsible for create-only name
    uniqueness and concurrent ownership arbitration.
"""

EXAMPLES = r"""
- name: Claim a controller-side harness marker
  cisco.nd.nd4x_l3out_create_lock:
    config:
      name: ansible-test-l3out-lock-example
      fabric1_name: DC1-Fabric
      fabric2_name: External-Fabric
      configured_fabrics: both
      ip_version: ipv4
      connectivity_details:
        routing_interface_type: routed
        links: []
      routing_details:
        routing_protocol: bgp
"""

RETURN = r"""
status:
  description: HTTP status returned by the controller create request.
  returned: always
  type: int
response:
  description: Controller response body after a successful create request.
  returned: on success
  type: dict
name:
  description: Name of the created L3Out marker.
  returned: always
  type: str
"""


SUCCESS_STATUSES = {"success", "created", "ok", "succeeded"}
FAILURE_STATUSES = {"failed", "failure", "error", "rejected"}


def _response_items(response_body):
    """Return the controller's per-L3Out result list."""
    if not isinstance(response_body, dict):
        return None
    if isinstance(response_body.get("results"), list):
        return response_body["results"]
    data = response_body.get("DATA")
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        return data["results"]
    return None


def _validate_create_response(response, expected_name):
    """Validate HTTP and per-item success for the create-only request."""
    if not isinstance(response, dict):
        return "The controller returned no response metadata."

    status = response.get("status")
    if status not in (200, 201, 202, 207):
        return "L3Out create returned unexpected HTTP status %s." % status

    items = _response_items(response.get("body"))
    if items is None or len(items) != 1:
        return "L3Out create did not return exactly one per-item result."

    item = items[0]
    if not isinstance(item, dict):
        return "L3Out create returned a malformed per-item result."

    item_name = item.get("name", item.get("l3OutName"))
    if item_name != expected_name:
        return "L3Out create returned result for %r, expected %r." % (item_name, expected_name)

    item_status_code = item.get("statusCode", 200)
    try:
        if int(item_status_code) >= 400:
            return "L3Out %r was rejected with statusCode %s: %s" % (
                expected_name,
                item_status_code,
                item.get("message", "no controller message"),
            )
    except (TypeError, ValueError):
        return "L3Out %r returned invalid statusCode %r." % (expected_name, item_status_code)

    item_status = str(item.get("status", "")).strip().lower()
    if item_status in FAILURE_STATUSES:
        return "L3Out %r was rejected with status %r: %s" % (
            expected_name,
            item.get("status"),
            item.get("message", "no controller message"),
        )
    if item_status not in SUCCESS_STATUSES:
        return "L3Out %r returned non-success status %r." % (expected_name, item.get("status"))

    return None


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(
        config=dict(type="dict", required=True),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    config = module.params["config"]
    expected_name = config.get("name")

    if not expected_name:
        module.fail_json(msg="config.name is required for the L3Out create lock.")

    if module.check_mode:
        module.exit_json(changed=True, skipped=True)

    connection = Connection(module._socket_path)
    connection.set_params(module.params)
    request_body = {"l3Outs": [config]}

    try:
        response = connection.send_request(
            "POST",
            "/api/v1/manage/l3Outs",
            json.dumps(request_body),
        )
    except Exception as exc:
        module.fail_json(msg="L3Out create lock request failed: %s" % exc)

    error = _validate_create_response(response, expected_name)
    if error:
        module.fail_json(
            msg=error,
            status=response.get("status") if isinstance(response, dict) else None,
            response=response.get("body") if isinstance(response, dict) else response,
        )

    module.exit_json(
        changed=True,
        status=response.get("status"),
        response=response.get("body"),
        name=expected_name,
    )


if __name__ == "__main__":
    main()
