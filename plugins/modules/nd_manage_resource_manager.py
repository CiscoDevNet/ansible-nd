# Copyright: (c) 2026, Jeet Ram (@jeeram) <jeeram@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
---
module: nd_manage_resource_manager
short_description: Manage resources in Cisco Nexus Dashboard (ND).
version_added: "1.0.0"
author: Jeet Ram (@jeeram) <jeeram@cisco.com>
description:
  - Create, delete, and gather resources in Cisco Nexus Dashboard using smart endpoints and pydantic models.
  - Supports all resource pool types (ID, IP, SUBNET) and scope types (fabric, device, device_interface, device_pair, link).
  - Provides idempotent merged and deleted states.
options:
  fabric:
    description:
      - Name of the target fabric for resource manager operations.
    type: str
    required: true
  state:
    description:
      - The required state of the configuration after module completion.
      - C(merged) creates resources that do not exist and updates those whose value has changed.
        Resources not present in C(config) are left untouched.
      - C(deleted) removes resources that are listed in C(config) from the fabric.
      - C(gathered) reads the current fabric resources and returns them in C(gathered) key
        in config format. No changes are made.
    type: str
    required: false
    choices:
      - merged
      - deleted
      - gathered
    default: merged
  config:
    description:
      - A list of dictionaries containing resource configurations.
      - Optional for state C(gathered) (returns all resources when omitted).
    type: list
    elements: dict
    suboptions:
      entity_name:
        description:
          - A unique name which identifies the entity to which the resource is allocated.
          - The format depends on scope_type.
          - "fabric / device: free-form string, e.g. 'l3_vni_fabric'."
          - "device_pair: two tildes required, e.g. 'SER1~SER2~label'."
          - "device_interface: one tilde required, e.g. 'SER~Ethernet1/13'."
          - "link: three tildes required, e.g. 'SER1~Eth1/3~SER2~Eth1/3'."
        type: str
        required: true
      pool_type:
        description:
          - Type of resource pool.
        type: str
        required: true
        choices:
          - ID
          - IP
          - SUBNET
      pool_name:
        description:
          - Name of the resource pool from which the resource is allocated.
        type: str
        required: true
      scope_type:
        description:
          - Scope of resource allocation.
        type: str
        required: true
        choices:
          - fabric
          - device
          - device_interface
          - device_pair
          - link
      resource:
        description:
          - Value of the resource being allocated.
          - The value will be an integer if C(pool_type=ID).
          - The value will be an IPv4 or IPv6 address if C(pool_type=IP).
          - The value will be an IPv4 or IPv6 address with a net mask if C(pool_type=SUBNET).
          - Required when C(state=merged).
        type: str
        required: false
      switch:
        description:
          - List of switch IP address or DNS name of the management interface of the switch to which the
            allocated resource is assigned.
          - Required when C(scope_type) is not C(fabric).
        type: list
        elements: str
        required: false
extends_documentation_fragment:
  - cisco.nd.modules
notes:
  - Requires Nexus Dashboard 3.x or higher with the ND Manage API (v1).
  - Idempotence checking compares the existing resource value to the desired value.
  - Entity name matching is order-insensitive for tilde-separated serial numbers.
"""

EXAMPLES = """
# Entity name format
# ==================
#
# The format of the entity name depends on the scope_type of the resource being allocated.

# Scope Type                Entity Name
# =====================================
# Fabric                    Eg: My_Network_30000
# Device                    Eg: loopback0
# Device Pair               Eg: 9H1Q6YOL08G~9B4ZC3JGND5~vPC1
# Device Interface          Eg: 9H1Q6YOL08G~Ethernet1/13
# Link                      Eg: 9H1Q6YOL08G~Ethernet1/3~9B4ZC3JGND5~Ethernet1/3

# where 9H1Q6YOL08G and 9B4ZC3JGND5 are switch serial numbers

# This module supports the following states:

# Merged:
#   Resources defined in the playbook will be merged into the target fabric.
#     - If the resource does not exist it will be added.
#     - If the resource exists but properties managed by the playbook are different
#       they will be updated if possible.
#     - Resources that are not specified in the playbook will be untouched.
#
# Deleted:
#   Resources defined in the playbook will be deleted.
#
# Gathered:
#   Returns the current ND state for the resources listed in the playbook.

# CREATING RESOURCES
# ==================
- name: Create Resources
  cisco.nd.nd_manage_resource_manager:
    state: merged                               # choose form [merged, deleted, gathered]
    fabric: test_fabric
    config:
      - entity_name: "l3_vni_fabric"            # A unique name to identify the resource
        pool_type: "ID"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "L3_VNI"                     # Based on the 'poolType', select appropriate name
        scope_type: "fabric"                    # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        resource: "101"                         # The value of the resource being created

      - entity_name: "9H1Q6YOL08G~9B4ZC3JGND5"  # A unique name to identify the resource
        pool_type: "ID"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "VPC_ID"                     # Based on the 'poolType', select appropriate name
        scope_type: "device_pair"               # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        switch:                                 # provide the switch information to which the given resource is to be attached
          - 192.168.10.150
          - 192.168.10.151
        resource: "500"                         # The value of the resource being created

      - entity_name: "mmudigon-2"               # A unique name to identify the resource
        pool_type: "IP"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "LOOPBACK0_IP_POOL"          # Based on the 'poolType', select appropriate name
        scope_type: "fabric"                    # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        resource: "110.1.1.1"                   # The value of the resource being created

      - entity_name: "9H1Q6YOL08G~Ethernet1/10" # A unique name to identify the resource
        pool_type: "IP"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "LOOPBACK1_IP_POOL"          # Based on the 'poolType', select appropriate name
        scope_type: "device_interface"          # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        switch:                                 # provide the switch information to which the given resource is to be attached
          - 192.168.10.150
        resource: "fe:80::04"                   # The value of the resource being created

      - entity_name: "9H1Q6YOL08G~Ethernet1/3~9B4ZC3JGND5~Ethernet1/3"  # A unique name to identify the resource
        pool_type: "SUBNET"                     # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "SUBNET"                     # Based on the 'poolType', select appropriate name
        scope_type: "link"                      # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        switch:                                 # provide the switch information to which the given resource is to be attached
          - 192.168.10.150
        resource: "fe:80:05::05/64"

# DELETING RESOURCES
# ==================

- name: Delete Resources
  cisco.nd.nd_manage_resource_manager:
    state: deleted                              # choose form [merged, deleted, gathered]
    fabric: test_fabric
    config:
      - entity_name: "l3_vni_fabric"            # A unique name to identify the resource
        pool_type: "ID"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "L3_VNI"                     # Based on the 'poolType', select appropriate name
        scope_type: "fabric"                    # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']

      - entity_name: "9H1Q6YOL08G~9B4ZC3JGND5"  # A unique name to identify the resource
        pool_type: "ID"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "VPC_ID"                     # Based on the 'poolType', select appropriate name
        scope_type: "device_pair"               # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150
          - 192.168.10.151

      - entity_name: "mmudigon-2"               # A unique name to identify the resource
        pool_type: "IP"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "LOOPBACK0_IP_POOL"          # Based on the 'poolType', select appropriate name
        scope_type: "fabric"                    # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']

      - entity_name: "9H1Q6YOL08G~Ethernet1/10" # A unique name to identify the resource
        pool_type: "IP"                         # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "LOOPBACK1_IP_POOL"          # Based on the 'poolType', select appropriate name
        scope_type: "device_interface"          # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150

      - entity_name: "9H1Q6YOL08G~Ethernet1/3~9B4ZC3JGND5~Ethernet1/3" # A unique name to identify the resource
        pool_type: "SUBNET"                     # choose from ['ID', 'IP', 'SUBNET']
        pool_name: "SUBNET"                     # Based on the 'poolType', select appropriate name
        scope_type: "link"                      # choose from ['fabric', 'device', 'device_interface', 'device_pair', 'link']
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150

# GATHERING RESOURCES
# ===================

- name: Gather all Resources - no filters
  cisco.nd.nd_manage_resource_manager:
    state: gathered                            # choose form [merged, deleted, gathered]
    fabric: test_fabric

- name: Gather Resources - filter by entity name
  cisco.nd.nd_manage_resource_manager:
    state: gathered                             # choose form [merged, deleted, gathered]
    fabric: test_fabric
    config:
      - entity_name: "l3_vni_fabric"            # A unique name to identify the resource
      - entity_name: "loopback_dev"             # A unique name to identify the resource
      - entity_name: "9H1Q6YOL08G~9B4ZC3JGND5"  # A unique name to identify the resource
      - entity_name: "9H1Q6YOL08G~Ethernet1/10" # A unique name to identify the resource
      - entity_name: "9H1Q6YOL08G~Ethernet1/3~9B4ZC3JGND5~Ethernet1/3" # A unique name to identify the resource

- name: Gather Resources - filter by switch
  cisco.nd.nd_manage_resource_manager:
    state: gathered                             # choose form [merged, deleted, gathered]
    fabric: test_fabric
    config:
      - switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150

- name: Gather Resources - filter by fabric and pool name
  cisco.nd.nd_manage_resource_manager:
    state: gathered                             # choose form [merged, deleted, gathered]
    fabric: test_fabric
    config:
      - pool_name: "L3_VNI"                     # Based on the 'poolType', select appropriate name
      - pool_name: "VPC_ID"                     # Based on the 'poolType', select appropriate name
      - pool_name: "SUBNET"                     # Based on the 'poolType', select appropriate name

- name: Gather Resources - filter by switch and pool name
  cisco.nd.nd_manage_resource_manager:
    state: gathered                             # choose form [merged, deleted, gathered]
    fabric: "{{ ansible_it_fabric }}"
    config:
      - pool_name: "L3_VNI"                     # Based on the 'poolType', select appropriate name
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150
      - pool_name: "LOOPBACK_ID"                # Based on the 'poolType', select appropriate name
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150
      - pool_name: "VPC_ID"                     # Based on the 'poolType', select appropriate name
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.151

- name: Gather Resources - mixed query
  cisco.nd.nd_manage_resource_manager:
    state: gathered                             # choose form [merged, deleted, gathered]
    fabric: test_fabric
    config:
      - entity_name: "l2_vni_fabric"            # A unique name to identify the resource
      - switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150
      - pool_name: "LOOPBACK_ID"                # Based on the 'poolType', select appropriate name
      - pool_name: "VPC_ID"                     # Based on the 'poolType', select appropriate name
        switch:                                 # provide the switch information to which the given resource is attached
          - 192.168.10.150
"""

RETURN = """
changed:
  description: Whether any changes were made.
  returned: when state is not gathered
  type: bool
diff:
  description: Tracking of merged and deleted resources.
  returned: when state is not gathered
  type: list
  elements: dict
  sample: [{"merged": [], "deleted": [], "gathered": [], "debugs": []}]
response:
  description: API responses received during module execution.
  returned: always
  type: list
  elements: dict
before:
  description: State before module execution (always empty list for this module).
  returned: when state is not gathered
  type: list
after:
  description: State after module execution (always empty list for this module).
  returned: when state is not gathered
  type: list
gathered:
  description:
  - The current fabric resource returned.
  - Each entry mirrors the resource data from the ND API.
  returned: when state is gathered
  type: list
  elements: dict
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources import NDResourceManagerModule


def main():
    """Main entry point for the nd_manage_resource_manager module."""

    # Build argument spec
    argument_spec = nd_argument_spec()
    argument_spec.update(ResourceManagerConfigModel.get_argument_spec())

    # Create Ansible module
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ("state", "merged", ["config"]),
            ("state", "delete", ["config"]),
        ],
    )

    # Initialize logging — setup_logging() configures the "nd" logger hierarchy via dictConfig.
    # The config parameter overrides ND_LOGGING_CONFIG env var (useful for local development).
    # logging.getLogger() returns the actual logging.Logger used for .debug()/.info()/.error().
    setup_logging(
        module,
        develop=True,
    )
    log = logging.getLogger("nd.nd_manage_resource_manager")

    log.debug(
        "main: logging initialised (logger='%s', effective_level=%s)",
        log.name,
        logging.getLevelName(log.getEffectiveLevel()),
    )

    # Get parameters
    fabric = module.params.get("fabric")
    output_level = module.params.get("output_level")
    state = module.params.get("state")
    config_count = len(module.params.get("config") or [])
    log.debug(
        "main: resolved module params — fabric='%s', state='%s', output_level='%s', config_count=%s, check_mode=%s",
        fabric,
        state,
        output_level,
        config_count,
        module.check_mode,
    )

    # Initialize Results - this collects all operation results
    results = Results()
    results.check_mode = module.check_mode
    results.action = "manage_resource_manager"

    try:
        # Initialize NDModule (uses RestSend infrastructure internally)
        nd = NDModule(module)
        log.debug(
            "main: NDModule initialised — host='%s', username='%s'",
            module.params.get("host"),
            module.params.get("username"),
        )

        # Create NDResourceManagerModule — switch IP→ID resolution and config translation
        # happen automatically inside __init__ via _get_all_switches / _resolve_switch_ids_in_config
        rm_module = NDResourceManagerModule(nd=nd, results=results, log=log)

        log.debug(
            "main: NDResourceManagerModule created — fabric='%s', state='%s', config_count=%s",
            fabric,
            state,
            len(rm_module.config or []),
        )

        # Manage state for merged, deleted
        log.debug("main: dispatching manage_state() for state='%s'", state)
        rm_module.manage_state()

        # Exit with results
        log.info(
            "main: manage_state() completed successfully — state='%s', fabric='%s', changed=%s",
            state,
            fabric,
            results.changed,
        )
        rm_module.exit_module()

    except NDModuleError as error:
        # NDModule-specific errors (API failures, authentication issues, etc.)
        log.error(
            "main: NDModuleError caught — error_type=NDModuleError, status=%s, msg='%s', fabric='%s', state='%s'",
            getattr(error, "status", None),
            error.msg,
            fabric,
            state,
        )

        # Try to get response from RestSend if available
        try:
            results.response_current = nd.rest_send.response_current
            results.result_current = nd.rest_send.result_current
            log.debug(
                "main: RestSend response captured — RETURN_CODE=%s",
                getattr(nd.rest_send.response_current, "RETURN_CODE", "N/A"),
            )
        except (AttributeError, ValueError) as rest_exc:
            # Fallback if RestSend wasn't initialized or no response available
            log.debug(
                "main: RestSend not available (%s: %s), building fallback response — RETURN_CODE=%s",
                type(rest_exc).__name__,
                rest_exc,
                error.status if error.status else -1,
            )
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
        results.register_api_call()
        results.build_final_result()

        # Add error details if debug output is requested
        if output_level == "debug":
            log.debug(
                "main: output_level='debug' — attaching error_details to final_result (error_type=NDModuleError, msg='%s')",
                error.msg,
            )
            results.final_result["error_details"] = error.to_dict()
        else:
            log.debug(
                "main: output_level='%s' — skipping error_details attachment",
                output_level,
            )

        log.error(
            "main: module failing with NDModuleError — msg='%s', final_result_keys=%s",
            error.msg,
            list(results.final_result.keys()),
        )
        module.fail_json(msg=error.msg, **results.final_result)

    except ValueError as error:
        # Validation errors raised by NDResourceManagerModule (e.g. invalid config,
        # mandatory field missing, pool/scope mismatch, API field mismatch).
        log.error(
            "main: ValueError caught — msg='%s', fabric='%s', state='%s'",
            str(error),
            fabric,
            state,
        )
        results.response_current = {
            "RETURN_CODE": -1,
            "MESSAGE": str(error),
            "DATA": {},
        }
        results.result_current = {
            "success": False,
            "found": False,
        }
        results.diff_current = {}
        results.register_api_call()
        results.build_final_result()
        module.fail_json(msg=str(error), **results.final_result)

    except Exception as error:
        # Unexpected errors
        log.error(
            "main: unexpected exception caught — error_type='%s', msg='%s', fabric='%s', state='%s'",
            type(error).__name__,
            str(error),
            fabric,
            state,
        )

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
        results.register_api_call()
        results.build_final_result()
        log.debug(
            "main: built fallback failed result — RETURN_CODE=-1, error_type='%s'",
            type(error).__name__,
        )

        if output_level == "debug":
            import traceback

            tb_str = traceback.format_exc()
            results.final_result["traceback"] = tb_str
            log.debug(
                "main: output_level='debug' — attaching traceback (%s lines) to final_result",
                len(tb_str.splitlines()),
            )
        else:
            log.debug(
                "main: output_level='%s' — skipping traceback attachment",
                output_level,
            )

        log.error(
            "main: module failing with unexpected error — error_type='%s', msg='%s'",
            type(error).__name__,
            str(error),
        )
        module.fail_json(msg=str(error), **results.final_result)


if __name__ == "__main__":
    main()
