#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__copyright__ = "Copyright (c) 2026 Cisco and/or its affiliates."
__author__ = "Jeet Ram"

DOCUMENTATION = """
---
module: nd_manage_resource_manager
short_description: Manage resources in Cisco Nexus Dashboard (ND).
version_added: "1.0.0"
author: Jeet Ram (@jeetram)
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

import copy
import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_resource_manager.resource_manager_config_model import (
    ResourceManagerConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.base_path import BasePath
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.plugins.module_utils.manage_resource_manager.nd_manage_resource_manager_resources import NDResourceManagerModule


def _resolve_switch_ids(nd, fabric_name, config):
    """Build a switchIp -> switchId map from ND and return a translated deep copy of config.

    Each item's ``switch`` list is translated from management IP strings to
    switchId values.  If an IP is not found in the map it is passed through
    unchanged so the caller can decide how to handle unresolved entries.

    Args:
        nd: Initialised NDModule instance.
        fabric_name: Fabric name used to query the switch inventory.
        config: Raw config list (not mutated — a deep copy is returned).

    Returns:
        A deep copy of ``config`` with switch IPs replaced by switchId values.
    """
    log = logging.getLogger(__name__)

    log.debug(f"_resolve_switch_ids: starting for fabric='{fabric_name}', config_items={len(config or [])}")

    # Build switchIp -> switchId map
    ip_to_switch_id = {}
    raw_switches = _query_fabric_switches(nd, fabric_name)
    log.debug(f"_resolve_switch_ids: retrieved {raw_switches} raw switch(es) from ND")
    for sw_idx, sw in enumerate(raw_switches):
        switch_id = sw.get("switchId") or sw.get("serialNumber")
        switch_ip = sw.get("fabricManagementIp") or sw.get("ip")
        log.debug(
            f"_resolve_switch_ids: switch record [{sw_idx}] — "
            f"switchId='{switch_id}', fabricManagementIp/ip='{switch_ip}', "
            f"raw_keys={list(sw.keys())}"
        )
        if switch_id and switch_ip:
            ip_to_switch_id[str(switch_ip).strip()] = switch_id
            log.debug(
                f"_resolve_switch_ids: [{sw_idx}] mapped switchIp='{switch_ip}' "
                f"-> switchId='{switch_id}' (map_size_now={len(ip_to_switch_id)})"
            )
        else:
            log.debug(
                f"_resolve_switch_ids: [{sw_idx}] skipping — missing id or ip: "
                f"switch_id='{switch_id}', switch_ip='{switch_ip}'"
            )
    log.debug(f"Switch IP-to-ID map built: {len(ip_to_switch_id)} entry/entries")

    # Translate switch IPs to switch IDs in a copy of the config
    config_copy = copy.deepcopy(config or [])
    log.debug(f"_resolve_switch_ids: translating switch lists for {len(config_copy)} config item(s)")
    for cfg_idx, item in enumerate(config_copy):
        raw_switch_list = item.get("switch") or []
        entity_name = item.get("entity_name")
        scope_type = item.get("scope_type")
        log.debug(
            f"_resolve_switch_ids: config item [{cfg_idx}] — "
            f"entity_name='{entity_name}', scope_type='{scope_type}', "
            f"raw_switch_list={raw_switch_list} (count={len(raw_switch_list)})"
        )
        if raw_switch_list:
            resolved = []
            for sw_ip in raw_switch_list:
                sw_key = str(sw_ip).strip()
                sw_id = ip_to_switch_id.get(sw_key, sw_key)
                if sw_id != sw_key:
                    log.debug(
                        f"_resolve_switch_ids: [{cfg_idx}] entity='{entity_name}' "
                        f"switch '{sw_ip}' -> resolved switchId='{sw_id}'"
                    )
                else:
                    log.debug(
                        f"_resolve_switch_ids: [{cfg_idx}] entity='{entity_name}' "
                        f"switch '{sw_ip}' not found in map — passing through unchanged"
                    )
                resolved.append(sw_id)
            item["switch"] = resolved
            log.debug(
                f"_resolve_switch_ids: [{cfg_idx}] entity='{entity_name}' "
                f"final switch list: {raw_switch_list} -> {item['switch']}"
            )
        else:
            log.debug(
                f"_resolve_switch_ids: [{cfg_idx}] entity='{entity_name}' — "
                f"no switch list present (scope_type='{scope_type}'), skipping translation"
            )

    log.debug(f"_resolve_switch_ids: completed, returning {len(config_copy)} translated config item(s)")
    return config_copy


def _query_fabric_switches(nd, fabric_name):
    """Query all switches for a fabric and return raw switch records.

    Uses RestSend save_settings/restore_settings to temporarily force
    check_mode=False so that this read-only GET always hits the controller,
    even when the module is running in Ansible check mode.
    """
    log = logging.getLogger(__name__)
    path = f"{BasePath.path('fabrics', fabric_name, 'switches')}?max=10000"
    log.debug(f"_query_fabric_switches: querying path='{path}' for fabric='{fabric_name}'")

    # Temporarily disable check_mode for this read-only lookup so the
    # controller is queried even when Ansible runs with --check.
    rest_send = nd._get_rest_send()
    rest_send.save_settings()
    rest_send.check_mode = False
    log.debug("_query_fabric_switches: check_mode disabled for read-only GET")
    try:
        response = nd.request(path)
        log.debug(f"_query_fabric_switches: received response type={type(response).__name__}")
    finally:
        rest_send.restore_settings()
        log.debug("_query_fabric_switches: rest_send settings restored")

    if isinstance(response, list):
        log.debug(
            f"_query_fabric_switches: API returned a list of {len(response)} switch(es) "
            f"for fabric='{fabric_name}' — returning list directly"
        )
        return response
    if isinstance(response, dict):
        switches_list = response.get("switches", [])
        dict_keys = list(response.keys())
        log.debug(
            f"_query_fabric_switches: API returned dict with keys={dict_keys} — "
            f"extracted 'switches' list with {len(switches_list)} item(s) "
            f"for fabric='{fabric_name}'"
        )
        return switches_list
    log.warning(
        f"_query_fabric_switches: unexpected response type '{type(response).__name__}' "
        f"(expected list or dict) for fabric='{fabric_name}' — returning empty list"
    )
    return []


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
            ("state", "overridden", ["config"]),
        ],
    )

    # Initialize logging — always get a logger; configure file output if config is available
    try:
        log_config = Log()
        log_config.config = "/Users/jeeram/ansible/collections/ansible_collections/cisco/nd/plugins/module_utils/logging_config.json"
        log_config.commit()
    except (ValueError, Exception) as log_init_exc:
        pass  # logging will fall back to root logger; detailed reason captured below
    log = logging.getLogger("nd.nd_manage_resource_manager")
    log.debug(
        f"main: logging initialised (logger='{log.name}', "
        f"effective_level={logging.getLevelName(log.getEffectiveLevel())})"
    )

    # Get parameters
    fabric = module.params.get("fabric")
    output_level = module.params.get("output_level")
    state = module.params.get("state")
    config_count = len(module.params.get("config") or [])
    log.debug(
        f"main: resolved module params — fabric='{fabric}', state='{state}', "
        f"output_level='{output_level}', config_count={config_count}, "
        f"check_mode={module.check_mode}"
    )

    # Initialize Results - this collects all operation results
    results = Results()
    results.check_mode = module.check_mode
    results.action = "manage_resource_manager"

    try:
        # Initialize NDModule (uses RestSend infrastructure internally)
        nd = NDModule(module)
        log.debug(
            f"main: NDModule initialised — host='{module.params.get('host')}', "
            f"username='{module.params.get('username')}'"
        )

        log.debug(
            f"main: starting switch-ID resolution for fabric='{fabric}', "
            f"raw_config_count={len(module.params.get('config') or [])}"
        )
        config_copy = _resolve_switch_ids(nd, fabric, module.params["config"])
        log.debug(
            f"main: switch-ID resolution complete — "
            f"resolved_config_count={len(config_copy or [])}"
        )

        # Create NDResourceManagerModule
        rm_module = NDResourceManagerModule(
            nd=nd,
            results=results,
            logger=log
        )
        log.debug(
            f"main: NDResourceManagerModule created — fabric='{fabric}', "
            f"state='{state}', config_count={len(config_copy or [])}"
        )
        rm_module.config = config_copy

        # Manage state for merged, overridden, deleted
        log.debug(f"main: dispatching manage_state() for state='{state}'")
        rm_module.manage_state()

        # Exit with results
        log.info(
            f"main: manage_state() completed successfully — state='{state}', "
            f"fabric='{fabric}', changed={results.changed}"
        )
        rm_module.exit_module()

    except NDModuleError as error:
        # NDModule-specific errors (API failures, authentication issues, etc.)
        log.error(
            f"main: NDModuleError caught — error_type=NDModuleError, "
            f"status={getattr(error, 'status', None)}, msg='{error.msg}', "
            f"fabric='{fabric}', state='{state}'"
        )

        # Try to get response from RestSend if available
        try:
            results.response_current = nd.rest_send.response_current
            results.result_current = nd.rest_send.result_current
            log.debug(
                f"main: RestSend response captured — "
                f"RETURN_CODE={getattr(nd.rest_send.response_current, 'RETURN_CODE', 'N/A')}"
            )
        except (AttributeError, ValueError) as rest_exc:
            # Fallback if RestSend wasn't initialized or no response available
            log.debug(
                f"main: RestSend not available ({type(rest_exc).__name__}: {rest_exc}), "
                f"building fallback response — RETURN_CODE={error.status if error.status else -1}"
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
                f"main: output_level='debug' — attaching error_details to final_result "
                f"(error_type=NDModuleError, msg='{error.msg}')"
            )
            results.final_result["error_details"] = error.to_dict()
        else:
            log.debug(
                f"main: output_level='{output_level}' — skipping error_details attachment"
            )

        log.error(
            f"main: module failing with NDModuleError — msg='{error.msg}', "
            f"final_result_keys={list(results.final_result.keys())}"
        )
        module.fail_json(msg=error.msg, **results.final_result)

    except Exception as error:
        # Unexpected errors
        log.error(
            f"main: unexpected exception caught — error_type='{type(error).__name__}', "
            f"msg='{str(error)}', fabric='{fabric}', state='{state}'"
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
            f"main: built fallback failed result — RETURN_CODE=-1, "
            f"error_type='{type(error).__name__}'"
        )

        if output_level == "debug":
            import traceback
            tb_str = traceback.format_exc()
            results.final_result["traceback"] = tb_str
            log.debug(
                f"main: output_level='debug' — attaching traceback "
                f"({len(tb_str.splitlines())} lines) to final_result"
            )
        else:
            log.debug(
                f"main: output_level='{output_level}' — skipping traceback attachment"
            )

        log.error(
            f"main: module failing with unexpected error — "
            f"error_type='{type(error).__name__}', msg='{str(error)}'"
        )
        module.fail_json(msg=str(error), **results.final_result)


if __name__ == "__main__":
    main()
