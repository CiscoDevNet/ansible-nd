#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat Chengam Saravanan (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "Akshayanat Chengam Saravanan"

DOCUMENTATION = """
---
module: nd_manage_switches
short_description: Manage switches in Cisco Nexus Dashboard (ND).
version_added: "1.0.0"
author: Akshayanat Chengam Saravanan (@achengam)
description:
- Add, delete, override, and query switches in Cisco Nexus Dashboard.
- Supports normal discovery, POAP (bootstrap/preprovision), and RMA operations.
- Uses Pydantic model validation for switch configurations.
- Provides state-based operations with intelligent diff calculation.
options:
    fabric:
        description:
        - Name of the target fabric for switch operations.
        type: str
        required: yes
    state:
        description:
        - The state of ND and switch(es) after module completion.
        - C(merged) and C(query) are the only states supported for POAP.
        - C(merged) is the only state supported for RMA.
        type: str
        default: merged
        choices:
        - merged
        - overridden
        - deleted
        - query
    save:
        description:
        - Save/Recalculate the configuration of the fabric after inventory is updated.
        type: bool
        default: true
    deploy:
        description:
        - Deploy the pending configuration of the fabric after inventory is updated.
        type: bool
        default: true
    config:
        description:
        - List of switch configurations. Optional for state C(deleted).
        type: list
        elements: dict
        suboptions:
            seed_ip:
                description:
                - Seed IP address or DNS name of the switch to manage.
                type: str
                required: true
            auth_proto:
                description:
                - SNMP authentication protocol to use.
                - For POAP and RMA, should be C(MD5).
                type: str
                default: MD5
                choices: ['MD5', 'SHA', 'MD5_DES', 'MD5_AES', 'SHA_DES', 'SHA_AES']
            user_name:
                description:
                - Login username for the switch.
                - For POAP and RMA, should be C(admin).
                type: str
                default: admin
            password:
                description:
                - Login password for the switch.
                type: str
                required: true
            role:
                description:
                - Role to assign to the switch in the fabric.
                type: str
                default: leaf
                choices:
                - leaf
                - spine
                - border
                - border_spine
                - border_gateway
                - border_gateway_spine
                - super_spine
                - border_super_spine
                - border_gateway_super_spine
                - access
                - aggregation
                - edge_router
                - core_router
                - tor
            preserve_config:
                description:
                - Set to C(false) for greenfield deployment, C(true) for brownfield.
                type: bool
                default: false
            poap:
                description:
                - POAP (PowerOn Auto Provisioning) configurations for bootstrap/preprovision.
                - POAP and DHCP must be enabled in fabric before using.
                type: list
                elements: dict
                suboptions:
                    discovery_username:
                        description:
                        - Username for device discovery during POAP.
                        type: str
                    discovery_password:
                        description:
                        - Password for device discovery during POAP.
                        type: str
                        no_log: true
                    serial_number:
                        description:
                        - Serial number of the physical switch to Bootstrap.
                        - When used together with C(preprovision_serial), performs a swap operation
                          that changes the serial number of a pre-provisioned switch and then
                          imports it via bootstrap.
                        type: str
                    preprovision_serial:
                        description:
                        - Serial number of switch to Pre-provision.
                        - When used together with C(serial_number), performs a swap operation
                          that changes the serial number of this pre-provisioned switch to
                          C(serial_number) and then imports it via bootstrap.
                        type: str
                    model:
                        description:
                        - Model of switch to Bootstrap/Pre-provision.
                        type: str
                    version:
                        description:
                        - Software version of switch.
                        type: str
                    hostname:
                        description:
                        - Hostname for the switch.
                        type: str
                    image_policy:
                        description:
                        - Image policy to apply.
                        type: str
                    config_data:
                        description:
                        - Basic configuration data for the switch during Bootstrap/Pre-provision.
                        - C(models) and C(gateway) are mandatory.
                        - C(models) is list of model of modules in switch to Bootstrap/Pre-provision.
                        - C(gateway) is the gateway IP with mask for the switch.
                        type: dict
                        suboptions:
                            models:
                                description:
                                - List of module models in the switch (e.g., N9K-X9364v, N9K-vSUP).
                                type: list
                                elements: str
                            gateway:
                                description:
                                - Gateway IP with subnet mask (e.g., 192.168.0.1/24).
                                type: str
            rma:
                description:
                - RMA an existing switch with a new one.
                - Please note that the existing switch should be configured and deployed in maintenance mode.
                - Please note that the existing switch being replaced should be shutdown state or out of network.
                type: list
                elements: dict
                suboptions:
                    discovery_username:
                        description:
                        - Username for device discovery during POAP and RMA discovery.
                        type: str
                    discovery_password:
                        description:
                        - Password for device discovery during POAP and RMA discovery.
                        type: str
                    serial_number:
                        description:
                        - Serial number of switch to Bootstrap for RMA.
                        type: str
                        required: true
                    old_serial:
                        description:
                        - Serial number of switch to be replaced by RMA.
                        type: str
                        required: true
                    model:
                        description:
                        - Model of switch to Bootstrap for RMA.
                        type: str
                        required: true
                    version:
                        description:
                        - Software version of switch to Bootstrap for RMA.
                        type: str
                        required: true
                    image_policy:
                        description:
                        - Name of the image policy to be applied on switch during Bootstrap for RMA.
                        type: str
                    config_data:
                        description:
                        - Basic config data of switch to Bootstrap for RMA.
                        - C(models) and C(gateway) are mandatory.
                        - C(models) is list of model of modules in switch to Bootstrap for RMA.
                        - C(gateway) is the gateway IP with mask for the switch to Bootstrap for RMA.
                        type: dict
                        required: true
                        suboptions:
                            models:
                                description:
                                - List of module models in the switch.
                                type: list
                                elements: str
                                required: true
                            gateway:
                                description:
                                - Gateway IP with subnet mask (e.g., 192.168.0.1/24).
                                type: str
                                required: true
                        - Serial number of new replacement switch.
                        type: str
                        required: true
                    model:
                        description:
                        - Model of new switch.
                        type: str
                        required: true
                    version:
                        description:
                        - Software version of new switch.
                        type: str
                        required: true
                    hostname:
                        description:
                        - Hostname for the replacement switch.
                        type: str
                        required: true
                    image_policy:
                        description:
                        - Image policy to apply.
                        type: str
                        required: true
                    ip:
                        description:
                        - IP address of the replacement switch.
                        type: str
                        required: true
                    gateway_ip:
                        description:
                        - Gateway IP with subnet mask.
                        type: str
                        required: true
                    discovery_password:
                        description:
                        - Password for device discovery during RMA.
                        type: str
                        required: true
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module requires NDFC 12.x or higher.
- POAP operations require POAP and DHCP to be enabled in fabric settings.
- RMA operations require the old switch to be in a replaceable state.
"""

EXAMPLES = """
- name: Add a switch to fabric
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.201
        user_name: admin
        password: "{{ switch_password }}"
        role: leaf
        preserve_config: false
    state: merged

- name: Add multiple switches
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.201
        user_name: admin
        password: "{{ switch_password }}"
        role: leaf
      - seed_ip: 192.168.10.202
        user_name: admin
        password: "{{ switch_password }}"
        role: spine
    state: merged

- name: Preprovision a switch via POAP
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.1
        user_name: admin
        password: "{{ switch_password }}"
        poap:
          - preprovision_serial: SAL1234ABCD
            model: N9K-C93180YC-EX
            version: "10.3(1)"
            hostname: leaf-preprov
            gateway_ip: 192.168.10.1/24
    state: merged

- name: Bootstrap a switch via POAP
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.1
        user_name: admin
        password: "{{ switch_password }}"
        poap:
          - serial_number: SAL5678EFGH
            model: N9K-C93180YC-EX
            version: "10.3(1)"
            hostname: leaf-bootstrap
            gateway_ip: 192.168.10.1/24
    state: merged

- name: Swap serial number on a pre-provisioned switch (POAP swap)
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.1
        user_name: admin
        password: "{{ switch_password }}"
        poap:
          - serial_number: SAL5678EFGH
            preprovision_serial: SAL1234ABCD
    state: merged

- name: RMA - Replace a switch
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.1
        user_name: admin
        password: "{{ switch_password }}"
        rma:
          - old_serial: SAL1234ABCD
            serial_number: SAL9999ZZZZ
            model: N9K-C93180YC-EX
            version: "10.3(1)"
            hostname: leaf-replaced
            image_policy: my-image-policy
            ip: 192.168.10.50
            gateway_ip: 192.168.10.1/24
            discovery_password: "{{ discovery_password }}"
    state: merged

- name: Remove switches from fabric
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    config:
      - seed_ip: 192.168.10.201
      - seed_ip: 192.168.10.202
    state: deleted

- name: Query all switches in fabric
  cisco.nd.nd_manage_switches:
    fabric: my-fabric
    state: query
  register: switches_result
"""

RETURN = """
previous:
  description: The configuration prior to the module execution.
  returned: always
  type: list
  elements: dict
proposed:
  description: The proposed configuration sent to the API.
  returned: always
  type: list
  elements: dict
sent:
  description: The configuration sent to the API.
  returned: when state is not query
  type: list
  elements: dict
current:
  description: The current configuration after module execution.
  returned: always
  type: list
  elements: dict
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.nd_switch_resources import NDSwitchResourceModule
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


def main():
    """Main entry point for the nd_manage_switches module."""
    
    # Build argument spec
    argument_spec = nd_argument_spec()
    argument_spec.update(
        fabric=dict(type="str", required=True),
        config=dict(
            type="list",
            elements="dict",
            options=dict(
                seed_ip=dict(type="str", required=True),
                auth_proto=dict(
                    type="str",
                    default="MD5",
                    choices=["MD5", "SHA", "MD5_DES", "MD5_AES", "SHA_DES", "SHA_AES"]
                ),
                user_name=dict(type="str", default="admin"),
                password=dict(type="str", no_log=True),
                role=dict(
                    type="str",
                    default="leaf",
                    choices=[
                        "leaf", "spine", "border", "border_spine",
                        "border_gateway", "border_gateway_spine",
                        "super_spine", "border_super_spine",
                        "border_gateway_super_spine", "access",
                        "aggregation", "edge_router", "core_router", "tor"
                    ]
                ),
                preserve_config=dict(type="bool", default=False),
                poap=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        discovery_username=dict(type="str"),
                        discovery_password=dict(type="str", no_log=True),
                        serial_number=dict(type="str"),
                        preprovision_serial=dict(type="str"),
                        model=dict(type="str"),
                        version=dict(type="str"),
                        hostname=dict(type="str"),
                        image_policy=dict(type="str"),
                        config_data=dict(
                            type="dict",
                            options=dict(
                                models=dict(
                                    type="list",
                                    elements="str",
                                ),
                                gateway=dict(
                                    type="str",
                                ),
                            ),
                        ),
                    ),
                ),
                rma=dict(
                    type="list",
                    elements="dict",
                    options=dict(
                        old_serial=dict(type="str", required=True),
                        serial_number=dict(type="str", required=True),
                        model=dict(type="str", required=True),
                        version=dict(type="str", required=True),
                        image_policy=dict(type="str"),
                        discovery_username=dict(type="str"),
                        discovery_password=dict(type="str", no_log=True),
                        config_data=dict(
                            type="dict",
                            required=True,
                            options=dict(
                                models=dict(
                                    type="list",
                                    elements="str",
                                    required=True,
                                ),
                                gateway=dict(
                                    type="str",
                                    required=True,
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        save=dict(type="bool", default=True),
        deploy=dict(type="bool", default=True),
        state=dict(
            type="str",
            default="merged",
            choices=["merged", "overridden", "deleted", "query"]
        ),
    )

    # Create Ansible module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "overridden", ["config"]),
        ],
    )

    # Initialize logging
    try:
        log_config = Log()
        log_config.config = "/Users/achengam/Documents/Ansible_Dev/NDBranch/ansible_collections/cisco/nd/ansible_cisco_log_r.json"
        log_config.commit()
        # Create logger instance for this module
        log = logging.getLogger("nd.nd_manage_switches")
    except ValueError as error:
        module.fail_json(msg=str(error))

    # Get parameters
    state = module.params.get("state")
    fabric = module.params.get("fabric")
    output_level = module.params.get("output_level")

    # Initialize Results - this collects all operation results
    results = Results()
    results.state = state
    results.check_mode = module.check_mode
    results.action = f"manage_switches_{state}"

    try:
        log.info(f"Starting nd_manage_switches module: fabric={fabric}, state={state}")
        
        # Initialize NDModule (uses RestSend infrastructure internally)
        nd = NDModule(module)
        log.info("NDModule initialized successfully")

        # Create NDSwitchResourceModule
        sw_module = NDSwitchResourceModule(
            nd=nd,
            results=results,
            logger=log
        )
        log.info(f"NDSwitchResourceModule initialized for fabric: {fabric}")
        
        # Manage state for merged, overridden, deleted, query
        log.info(f"Managing state: {state}")
        sw_module.manage_state()
        
        # Exit with results
        log.info(f"State management completed successfully. Changed: {results.changed}")
        sw_module.exit_json()

    except NDModuleError as error:
        # NDModule-specific errors (API failures, authentication issues, etc.)
        log.error(f"NDModule error: {error.msg}")
        
        # Try to get response from RestSend if available
        try:
            results.response_current = nd.rest_send.response_current
            results.result_current = nd.rest_send.result_current
        except (AttributeError, ValueError):
            # Fallback if RestSend wasn't initialized or no response available
            results.response_current = {
                "RETURN_CODE": error.status if error.status else -1,
                "MESSAGE": error.msg,
                "DATA": error.response_payload if error.response_payload else {},
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
        
        log.error(f"Module failed: {results.final_result}")
        module.fail_json(msg=error.msg, **results.final_result)

    except Exception as error:
        # Unexpected errors
        log.error(f"Unexpected error during module execution: {str(error)}")
        log.error(f"Error type: {type(error).__name__}")
        
        # Build failed result
        results.response_current = {
            "RETURN_CODE": -1,
            "MESSAGE": f"Unexpected error: {str(error)}",
            "DATA": {},
        }
        results.result_current = {
            "success": False,
            "found": False,
        }
        results.diff_current = {}
        results.register_task_result()
        results.build_final_result()
        
        if output_level == "debug":
            import traceback
            results.final_result["traceback"] = traceback.format_exc()
        
        module.fail_json(msg=str(error), **results.final_result)


if __name__ == "__main__":
    main()
