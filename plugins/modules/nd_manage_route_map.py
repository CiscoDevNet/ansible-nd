# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_route_map
version_added: "2.0.0"
short_description: Manage route maps on Cisco Nexus Dashboard fabrics
description:
- Manage route maps on a Cisco Nexus Dashboard (ND) fabric.
- It supports creating, updating, and deleting route maps.
- Route maps are created and deleted in bulk via dedicated bulk-API endpoints.
- Each route map contains one or more entries, each entry containing
  a sequence number, a permit/deny action, and a list of match/set rule conditions.
author:
- Gaspard Micol (@gmicol)
options:
  fabric_name:
    description:
    - The name of the fabric that owns the route maps.
    - This is a required parameter for all operations.
    type: str
    required: true
  cluster_name:
    description:
    - Target cluster name in a multi-cluster deployment.
    type: str
  config:
    description:
    - The list of route maps to configure.
    type: list
    elements: dict
    required: True
    suboptions:
      name:
        description:
        - The name of the route map.
        - Allowed characters are C([a-zA-Z0-9~_-]).
        - Maximum length is 115 characters (63 for the default tenant).
        type: str
        required: true
      tenant_name:
        description:
        - Optional tenant name for tenant-specific route maps.
        - Maximum length is 63 characters. Allowed characters are C([A-Za-z0-9_-]).
        - When set, O(config.name) may be either the bare route map name or the fully qualified C(tenant~route_map) API name.
        - The module normalizes tenant-scoped route maps to a bare O(config.name) and uses C(tenant~route_map) for API lookups and deletes.
        type: str
        aliases: [ tenantName ]
      entries:
        description:
        - The list of route map entries.
        - Each entry defines a sequence block with a permit/deny action
          and one or more match/set rule conditions.
        - Required when O(state=merged), O(state=replaced), or O(state=overridden).
        - Not required when O(state=deleted); the route map name is enough to delete an existing route map.
        type: list
        elements: dict
        suboptions:
          sequence_number:
            description:
            - The sequence number of the route map entry (0-65535).
            - Lower sequence numbers are evaluated first.
            type: int
            default: 10
          action:
            description:
            - The action to take when the entry matches.
            type: str
            default: permit
            choices: [ permit, deny ]
          rule_entries:
            description:
            - The list of match or set rule conditions for this entry.
            - Each rule is discriminated by O(config.entries.rule_entries.rule_type).
            type: list
            elements: dict
            required: true
            suboptions:
              rule_type:
                description:
                - The type of the rule entry.
                - Determines which additional fields are required.
                type: str
                required: true
                choices:
                - matchIpv4Acl
                - matchIpv6Acl
                - matchIpv4PrefixList
                - matchIpv6PrefixList
                - matchCommunity
                - matchExtendedCommunity
                - matchTag
                - setCommunity
                - setExtendedCommunityList
                - setLocalPreference
                - setIpv4NextHop
                - setIpv6NextHop
                aliases: [ ruleType ]
              access_control_list_name:
                description:
                - Name of the access control list to match.
                - Required when O(config.entries.rule_entries.rule_type=matchIpv4Acl)
                  or O(config.entries.rule_entries.rule_type=matchIpv6Acl).
                type: str
                aliases: [ accessControlListName ]
              prefix_list_names:
                description:
                - Names of the prefix lists to match.
                - Required when O(config.entries.rule_entries.rule_type=matchIpv4PrefixList)
                  or O(config.entries.rule_entries.rule_type=matchIpv6PrefixList).
                type: list
                elements: str
                aliases: [ prefixListNames ]
              community_list_names:
                description:
                - Names of the community lists to match.
                - Required when O(config.entries.rule_entries.rule_type=matchCommunity).
                type: list
                elements: str
                aliases: [ communityListNames ]
              extended_community_list_names:
                description:
                - Names of the extended community lists to match.
                - Required when O(config.entries.rule_entries.rule_type=matchExtendedCommunity).
                type: list
                elements: str
                aliases: [ extendedCommunityListNames ]
              exact_match:
                description:
                - Require an exact match for (extended) community list comparisons.
                - Used with C(matchCommunity) and C(matchExtendedCommunity).
                type: bool
                aliases: [ exactMatch ]
              tags:
                description:
                - List of integer tags to match (0-4294967295).
                - Required when O(config.entries.rule_entries.rule_type=matchTag).
                type: list
                elements: int
              community_numbers:
                description:
                - Community numbers to set, each in ASN2:NN format (e.g. C(65000:100)).
                - Required when O(config.entries.rule_entries.rule_type=setCommunity).
                type: list
                elements: str
                aliases: [ communityNumbers ]
              additive:
                description:
                - Add communities without replacing existing ones.
                - Used with C(setCommunity).
                type: bool
              graceful_restart_shutdown_community:
                description:
                - Set the graceful-restart shutdown community.
                - Used with C(setCommunity).
                type: bool
                aliases: [ gracefulRestartShutdownCommunity ]
              no_advertise_community:
                description:
                - Set the no-advertise community.
                - Used with C(setCommunity).
                type: bool
                aliases: [ noAdvertiseCommunity ]
              no_export_community:
                description:
                - Set the no-export community.
                - Used with C(setCommunity).
                type: bool
                aliases: [ noExportCommunity ]
              local_as_community:
                description:
                - Set the local-AS community.
                - Used with C(setCommunity).
                type: bool
                aliases: [ localAsCommunity ]
              internet_community:
                description:
                - Set the internet community.
                - Used with C(setCommunity).
                type: bool
                aliases: [ internetCommunity ]
              extended_community_list_name:
                description:
                - Name of the extended community list to set.
                - Required when O(config.entries.rule_entries.rule_type=setExtendedCommunityList).
                type: str
                aliases: [ extendedCommunityListName ]
              value:
                description:
                - Local preference value (0-4294967295).
                - Required when O(config.entries.rule_entries.rule_type=setLocalPreference).
                type: int
              next_hop_ip_collection:
                description:
                - List of next-hop IP addresses to set.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: list
                elements: str
                aliases: [ nextHopIpCollection ]
              drop_on_fail:
                description:
                - Drop the packet if the next hop is unavailable.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
                aliases: [ dropOnFail ]
              load_share:
                description:
                - Enable load sharing across multiple next hops.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
                aliases: [ loadShare ]
              enforce_order:
                description:
                - Enforce the order of next-hop IPs.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
                aliases: [ enforceOrder ]
              verify_availability:
                description:
                - Ensure the next hop is reachable before using it.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
                aliases: [ verifyAvailability ]
              use_peer_address:
                description:
                - Use the peer address as the next hop.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
                aliases: [ usePeerAddress ]
              redistribute_unchanged:
                description:
                - Redistribute routes without changing the next hop.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
                aliases: [ redistributeUnchanged ]
              unchanged:
                description:
                - Keep the next hop unchanged.
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: bool
              track_id:
                description:
                - Tracking subsystem object ID (1-512).
                - Used with C(setIpv4NextHop) and C(setIpv6NextHop).
                type: int
                aliases: [ trackId ]
  state:
    description:
    - The desired state of the route map resources on Cisco Nexus Dashboard.
    - Use O(state=merged) to create new route maps and update existing ones
      as defined in your configuration.
      Route maps on ND that are not specified in the configuration are left unchanged.
    - Use O(state=replaced) to replace the route maps specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      Route maps on ND that are not in the configuration will be deleted. Use with caution.
    - Use O(state=deleted) to remove the route maps specified in the configuration
      from Cisco Nexus Dashboard.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
- cisco.nd.verification
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- Route maps are created and deleted in bulk via the API.
  When O(state=overridden) is used, all route maps not present in the configuration
  will be deleted in a single bulk-delete API call.
"""

EXAMPLES = r"""
- name: Create route maps with prefix-list and community match rules
  cisco.nd.nd_manage_route_map:
    fabric_name: my-fabric
    config:
      - name: MY-BGP-ROUTEMAP-1
        entries:
          - sequence_number: 10
            action: permit
            rule_entries:
              - rule_type: matchIpv4PrefixList
                prefix_list_names:
                  - PL-IPV4-1
                  - PL-IPV4-2
          - sequence_number: 20
            action: deny
            rule_entries:
              - rule_type: matchCommunity
                community_list_names:
                  - COMM-LIST-1
                exact_match: true
      - name: MY-BGP-ROUTEMAP-2
        entries:
          - sequence_number: 10
            action: permit
            rule_entries:
              - rule_type: setLocalPreference
                value: 200
    state: merged

- name: Create route map with next-hop set rule
  cisco.nd.nd_manage_route_map:
    fabric_name: my-fabric
    config:
      - name: MY-BGP-ROUTEMAP-3
        entries:
          - sequence_number: 10
            action: permit
            rule_entries:
              - rule_type: setIpv4NextHop
                next_hop_ip_collection:
                  - 192.168.1.1
                  - 192.168.1.2
                drop_on_fail: true
                load_share: true
    state: merged

- name: Update a route map (replace its entries)
  cisco.nd.nd_manage_route_map:
    fabric_name: my-fabric
    config:
      - name: MY-BGP-ROUTEMAP-1
        entries:
          - sequence_number: 10
            action: permit
            rule_entries:
              - rule_type: matchIpv6PrefixList
                prefix_list_names:
                  - PL-IPV6-1
    state: replaced

- name: Delete specific route maps
  cisco.nd.nd_manage_route_map:
    fabric_name: my-fabric
    config:
      - name: MY-BGP-ROUTEMAP-1
      - name: MY-BGP-ROUTEMAP-2
    state: deleted

- name: Override -- enforce exact set of route maps (delete all others)
  cisco.nd.nd_manage_route_map:
    fabric_name: my-fabric
    config:
      - name: MY-BGP-ROUTEMAP-FINAL
        entries:
          - sequence_number: 10
            action: permit
            rule_entries:
              - rule_type: setLocalPreference
                value: 100
    state: overridden
"""

RETURN = r"""
changed:
  description: Whether the module changed, or in check mode would change, the fabric configuration.
  returned: always
  type: bool
  sample: true
output_level:
  description: The output verbosity level in effect for the run, echoing the O(output_level) parameter.
  returned: always
  type: str
  sample: normal
before:
  description:
  - The route map configuration before the module ran, structured the same as the O(config) parameter.
  - An empty list when no route map configuration existed.
  returned: always
  type: list
  elements: dict
  sample:
  - name: RM_EXPORT
    tenant_name: tenantSales
    entries:
    - sequence_number: 10
      action: permit
      rule_entries:
      - rule_type: matchIpv4PrefixList
        prefix_list_names:
        - tenantSales~PL_EXPORT
after:
  description:
  - The route map configuration after the module ran, structured the same as the O(config) parameter.
  - By default, this reflects the predicted post-write state. When O(verify.enabled=true), it is
    replaced by a controller readback after all write actions complete.
  - In check mode, this is the configuration that would result if the module ran outside check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - name: RM_EXPORT
    tenant_name: tenantSales
    entries:
    - sequence_number: 10
      action: permit
      rule_entries:
      - rule_type: setLocalPreference
        value: 200
diff:
  description: The per-route-map difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - name: RM_EXPORT
    tenant_name: tenantSales
    entries:
    - sequence_number: 10
      action: permit
      rule_entries:
      - rule_type: setLocalPreference
        value: 200
proposed:
  description: The route map configuration the module proposed to apply before reconciliation with existing state.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - name: RM_EXPORT
    tenant_name: tenantSales
    entries:
    - sequence_number: 10
      action: permit
      rule_entries:
      - rule_type: setLocalPreference
        value: 200
logs:
  description: Internal diagnostic log messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample:
  - "manage_state begin state=merged check_mode=False"
msg:
  description: A human-readable error message, present only when the module fails.
  returned: on failure
  type: str
  sample: "route map 'RM_EXPORT': entries must contain at least one entry for state 'merged'."
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_route_map.manage_route_map import RouteMapModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import verify_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_route_map import ManageRouteMapOrchestrator


def _validate_route_map_config(module: AnsibleModule) -> None:
    """Reject write-state config entries that cannot produce a RouteMap payload."""
    if module.params.get("state") == "deleted":
        return
    for item in module.params.get("config") or []:
        if not isinstance(item, dict):
            continue
        if not item.get("entries"):
            module.fail_json(msg=f"route map '{item.get('name')}': entries must contain at least one entry for state '{module.params.get('state')}'.")


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(verify_spec())
    argument_spec.update(RouteMapModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    _validate_route_map_config(module)
    module_log = logging.getLogger("nd.nd_manage_route_map")

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageRouteMapOrchestrator,
        )

        module_log.debug("manage_state begin state=%s check_mode=%s", module.params.get("state"), module.check_mode)
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")
        nd_state_machine.finalize_result()

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        module_log.exception("NDStateMachineError during module execution")
        output = nd_state_machine.output.format() if nd_state_machine is not None else {}
        error_msg = f"Module execution failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)

    except Exception as e:
        module_log.exception("Unhandled exception during module execution")
        output = nd_state_machine.output.format() if nd_state_machine is not None else {}
        error_msg = f"Module failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
