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
- Demonstrates integration with the Results class for proper Ansible output formatting.
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
changed:
  description: Whether any changes were made
  returned: always
  type: bool
  sample: false
failed:
  description: Whether the operation failed
  returned: always
  type: bool
  sample: false
diff:
  description: List of differences (empty for query operations)
  returned: always
  type: list
  elements: dict
response:
  description: List of controller responses
  returned: always
  type: list
  elements: dict
result:
  description: List of operation results
  returned: always
  type: list
  elements: dict
metadata:
  description: List of operation metadata
  returned: always
  type: list
  elements: dict
"""

from ansible.module_utils.basic import AnsibleModule  # type: ignore
from ansible_collections.cisco.nd.plugins.module_utils.enums import OperationType  # type: ignore
from ansible_collections.cisco.nd.plugins.module_utils.ep.ep_api_v1_infra_clusterhealth import EpApiV1InfraClusterhealthConfigGet  # type: ignore
from ansible_collections.cisco.nd.plugins.module_utils.log import Log  # type: ignore
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (  # type: ignore
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.results import Results  # type: ignore


def main():
    """
    Main entry point for the nd_rest_send_test module.

    Demonstrates integration of:
    - Smart Endpoints (EpApiV1InfraClusterhealthConfigGet)
    - NDModule with RestSend infrastructure
    - Results class for proper Ansible output formatting
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(
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

    # Initialize Results - this collects all operation results
    results = Results()
    results.state = state
    results.check_mode = module.check_mode
    results.action = "query_cluster_health"
    results.operation_type = OperationType.QUERY  # Query operations don't change state

    # Initialize endpoint
    ep = EpApiV1InfraClusterhealthConfigGet()

    # Initialize NDModule (uses RestSend infrastructure internally)
    nd = NDModule(module)

    try:
        # Make the request
        data = nd.request(ep.path, ep.verb)

        # Populate Results with the response
        # For query operations, we create a simple result dict
        result = {
            "success": True,
            "found": True
        }

        # Add response information to Results
        # Note: nd_v2's RestSend infrastructure provides these via nd.response
        response = {
            "RETURN_CODE": nd.status,
            "METHOD": nd.method,
            "REQUEST_PATH": nd.path,
            "MESSAGE": nd.response,
            "DATA": data,
        }

        # Register the task result
        results.response_current = response
        results.result_current = result
        results.diff_current = {}  # Query operations have no diff
        results.register_task_result()

        # Build the final result
        results.build_final_result()

        # Add debug info if requested
        if output_level == "debug":
            results.final_result["debug_info"] = {
                "method": nd.method,
                "path": nd.path,
                "status": nd.status,
                "url": nd.url,
                "state": state,
                "endpoint_class": ep.class_name,
            }

        # Exit with the final result
        # Results class sets changed and failed appropriately
        if True in results.failed:
            module.fail_json(**results.final_result)
        module.exit_json(**results.final_result)

    except NDModuleError as error:
        # Create a failed result using Results class
        results.response_current = {
            "RETURN_CODE": error.status if error.status else -1,
            "MESSAGE": error.msg,
            "DATA": error.payload if error.payload else {},
        }
        results.result_current = {
            "success": False,
            "found": False,
        }
        results.diff_current = {}
        results.register_task_result()
        results.build_final_result()

        # Add error details if debug output is requested
        if output_level == "debug":
            results.final_result["error_details"] = error.to_dict()

        module.fail_json(**results.final_result)

    except (TypeError, ValueError) as error:
        # For unexpected errors, use the failed_result from Results
        module.fail_json(msg=str(error), **results.failed_result)


if __name__ == "__main__":
    main()
