#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026 Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# pylint: disable=wrong-import-position
"""
Simple demo module for RestSend and Smart Endpoints.
"""
from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

DOCUMENTATION = r"""
---
module: nd_rest_send_test
short_description: Test module for RestSend infrastructure
description:
- A test module to validate Smart Endpoint, RestSend, Sender, ResponseHandler, and Results classes.
- Uses nd_v2.py with exception-based error handling.
author:
- Allen Robel (@arobel)
options:
  state:
    description:
    - The desired state of the operation.
    - C(query) performs a GET request.
    type: str
    choices: [ query ]
    default: query
  output_level:
    description:
    - Influence the output of this module.
    type: str
    choices: [ debug, info, normal ]
    default: normal
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
"""

EXAMPLES = r"""
- name: Query cluster health config (default)
  cisco.nd.nd_rest_send_test:
    state: query

- name: Debug output
  cisco.nd.nd_rest_send_test:
    output_level: debug
    state: query
"""

RETURN = r"""
data:
  description: The response DATA from the controller
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule  # type: ignore
from ansible_collections.cisco.nd.plugins.module_utils.ep.ep_api_v1_infra_aaa import EpApiV1InfraAaaLocalUsersGet
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (  # type: ignore
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.log import Log


def main():
    """
    Main entry point for the nd_rest_send_test module.
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(
        path=dict(type="str"),
        payload=dict(type="dict"),
        state=dict(type="str", default="query", choices=["query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Initialize logging
    try:
        log = Log()
        log.commit()
    except ValueError as error:
        module.fail_json(msg=str(error))

    # Get parameters
    state = module.params.get("state")
    output_level = module.params.get("output_level")

    # Initialize endpoint
    ep = EpApiV1InfraAaaLocalUsersGet()

    # Initialize NDModule (uses RestSend infrastructure internally)
    nd = NDModule(module)

    try:
        data = nd.request(ep.path, ep.verb)
        changed = False

        # Prepare output
        output = {
            "changed": changed,
            "data": data,
        }

        # Add debug info if requested
        if output_level == "debug":
            output["method"] = nd.method
            output["path"] = nd.path
            output["status"] = nd.status
            output["url"] = nd.url
            output["state"] = state

        module.exit_json(**output)

    except NDModuleError as error:
        # Use to_dict() for structured error output
        module.fail_json(**error.to_dict())

    except (TypeError, ValueError) as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
