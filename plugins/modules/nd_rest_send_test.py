#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026 Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# pylint: disable=wrong-import-position

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

DOCUMENTATION = r"""
---
module: nd_rest_send_test
short_description: Test module for RestSend infrastructure
description:
- A simple test module to validate RestSend, Sender, ResponseHandler, and Results classes.
- This module performs a GET request to /api/v1/infra/clusterhealth/config.
- Uses nd_v2.py with exception-based error handling.
author:
- Allen Robel (@arobel)
options:
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
- name: Test RestSend infrastructure
  cisco.nd.nd_rest_send_test:
"""

RETURN = r"""
data:
  description: The response DATA from the controller
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule  # type: ignore
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (  # type: ignore
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum  # type: ignore


def main():
    """
    Main entry point for the nd_rest_send_test module.
    """
    argument_spec = nd_argument_spec()
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Initialize NDModule (uses RestSend infrastructure internally)
    nd = NDModule(module)

    try:
        # Make the request - NDModule handles all the RestSend setup
        data = nd.request("/api/v1/infra/clusterhealth/config", HttpVerbEnum.GET)

        # Prepare output
        output = {
            "changed": False,
            "data": data,
        }

        # Add debug info if requested
        if module.params.get("output_level") == "debug":
            output["method"] = nd.method
            output["path"] = nd.path
            output["status"] = nd.status
            output["url"] = nd.url

        module.exit_json(**output)

    except NDModuleError as error:
        # Use to_dict() for structured error output
        module.fail_json(**error.to_dict())

    except (TypeError, ValueError) as error:
        module.fail_json(msg=str(error))


if __name__ == "__main__":
    main()
