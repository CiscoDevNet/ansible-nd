#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_extended_community_list
version_added: "2.0.0"
short_description: Manage BGP extended community lists on Cisco Nexus Dashboard fabrics
description:
- Manage BGP routing-policy extended community lists on a Cisco Nexus Dashboard
  (ND) fabric.
- Both C(standard) and C(expanded) extended community list types are supported.
- Extended community lists are created and deleted in bulk via dedicated API
  endpoints.
author:
- Gaspard Micol (@gmicol)
options:
  fabric_name:
    description:
    - The name of the fabric that owns the extended community lists.
    - Required for all operations.
    type: str
    required: true
  cluster_name:
    description:
    - The target cluster name in a multi-cluster deployment.
    type: str
  config:
    description:
    - The list of extended community lists to configure.
    type: list
    elements: dict
    required: True
    suboptions:
      name:
        description:
        - The name of the extended community list.
        - Allowed characters are C([a-zA-Z0-9~_-]).
        - Maximum length is 115 characters (63 for the default tenant).
        type: str
        required: true
      type:
        description:
        - The type of extended community list.
        - Required for create and update operations; not required when O(state=deleted).
        - C(standard) - matches extended communities using explicit values such
          as route targets, router MACs, site-of-origin, or generic extended
          community values.
        - C(expanded) - matches extended communities using a regular expression.
        type: str
        choices: [ standard, expanded ]
      tenant_name:
        description:
        - The tenant that owns this extended community list.
        - When omitted the default tenant is used.
        - Allowed characters are C([A-Za-z0-9_-]). Max 63 characters.
        - When set, O(config.name) may be the bare list name or the fully qualified C(tenant~name) API name.
        - The module reports the bare O(config.name) and uses C(tenant~name) for API lookups, updates, and deletes.
        type: str
        aliases: [ tenantName ]
      entries:
        description:
        - The ordered list of extended community list entries.
        - Required for create and update operations; not required when O(state=deleted).
        - Each entry defines a permit/deny action and one or more extended
          communities to match.
        type: list
        elements: dict
        suboptions:
          sequence_number:
            description:
            - Sequence number of this entry (1-4294967294).
            - Entries are evaluated in ascending order.
            type: int
            required: true
            aliases: [ sequenceNumber ]
          action:
            description:
            - The action to take when a community matches this entry.
            type: str
            required: true
            choices: [ permit, deny ]
          router_mac_collection:
            description:
            - One or more router MAC addresses to match.
            - Each value must be in C(eeee.eeee.eeee), C(ee:ee:ee:ee:ee:ee),
              or C(ee-ee-ee-ee-ee-ee) format.
            - Only valid when O(config.type=standard).
            type: list
            elements: str
            aliases: [ routerMacCollection ]
          route_target_collection:
            description:
            - One or more route targets to match.
            - Each value must be in C(ASN2:NN), C(ASN4:NN), or C(IPv4:NN)
              format (e.g. C(65000:100) or C(192.168.1.1:200)).
            - Comma-separated route targets in one list item are accepted and normalized to separate values.
            - Only valid when O(config.type=standard).
            type: list
            elements: str
            aliases: [ routeTargetCollection ]
          site_of_origin_collection:
            description:
            - One or more site-of-origin values to match.
            - Each value must be in C(ASN2:NN), C(ASN4:NN), or C(IPv4:NN)
              format (e.g. C(64512:300) or C(10.0.0.1:500)).
            - Only valid when O(config.type=standard).
            type: list
            elements: str
            aliases: [ siteOfOriginCollection ]
          transitive_generic_extended_collection:
            description:
            - One or more transitive generic extended community values to match.
            - Each value must be in C(ASN4:NN) format where the ASN starts with
              a digit 1-9 (e.g. C(65000:123)).
            - Only valid when O(config.type=standard).
            type: list
            elements: str
            aliases: [ transitiveGenericExtendedCollection ]
          non_transitive_generic_extended_collection:
            description:
            - One or more non-transitive generic extended community values to match.
            - Each value must be in C(ASN4:NN) format where the ASN starts with
              a digit 1-9 (e.g. C(64512:789)).
            - Only valid when O(config.type=standard).
            type: list
            elements: str
            aliases: [ nonTransitiveGenericExtendedCollection ]
          community_number_regex:
            description:
            - Regular expression in aa:nn format for matching extended community
              strings.
            - Max 63 characters. Must not start with C([a-zA-Z~!#%@`;]).
            - Required and only valid when O(config.type=expanded).
            type: str
            aliases: [ communityNumberRegex ]
  state:
    description:
    - The desired state of the extended community list resources on Cisco Nexus
      Dashboard.
    - Use O(state=merged) to create new extended community lists and update
      existing ones as defined in the configuration.
      Extended community lists not specified in the configuration are left unchanged.
    - Use O(state=replaced) to replace the extended community lists specified
      in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source
      of truth. All extended community lists on ND not present in the
      configuration will be deleted. Use with caution.
    - Use O(state=deleted) to remove the extended community lists specified in
      the configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard version 4.2.1 or higher.
- Extended community lists are created and deleted in bulk via separate API
  endpoints.
- Standard-type entries may set any combination of O(config.entries.router_mac_collection),
  O(config.entries.route_target_collection), O(config.entries.site_of_origin_collection),
  O(config.entries.transitive_generic_extended_collection), and
  O(config.entries.non_transitive_generic_extended_collection).
- O(config.entries.community_number_regex) is required for every entry when
  O(config.type=expanded); standard-only fields must not be set on expanded entries.
"""

EXAMPLES = r"""
- name: Create a standard extended community list matching route targets
  cisco.nd.nd_manage_extended_community_list:
    fabric_name: my-fabric
    config:
      - name: ECL-RT-PROD
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            route_target_collection:
              - "65000:100,65000:200"
              - "192.168.1.1:300"
          - sequence_number: 20
            action: permit
            router_mac_collection:
              - "d478.1111.57b8"
              - "d4:78:11:11:57:b9"
          - sequence_number: 30
            action: deny
            site_of_origin_collection:
              - "64512:300"
              - "10.0.0.1:500"
    state: merged

- name: Create a standard extended community list with generic extended communities
  cisco.nd.nd_manage_extended_community_list:
    fabric_name: my-fabric
    config:
      - name: ECL-GENERIC
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            transitive_generic_extended_collection:
              - "65000:123"
              - "12345:99"
          - sequence_number: 20
            action: permit
            non_transitive_generic_extended_collection:
              - "64512:789"
    state: merged

- name: Create an expanded extended community list
  cisco.nd.nd_manage_extended_community_list:
    fabric_name: my-fabric
    config:
      - name: ECL-EXPANDED-REGEX
        type: expanded
        entries:
          - sequence_number: 10
            action: permit
            community_number_regex: "65000:.*"
          - sequence_number: 20
            action: deny
            community_number_regex: "64512:.*"
    state: merged

- name: Update an extended community list (replace its entries)
  cisco.nd.nd_manage_extended_community_list:
    fabric_name: my-fabric
    config:
      - name: ECL-RT-PROD
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            route_target_collection:
              - "65001:999"
    state: replaced

- name: Delete specific extended community lists
  cisco.nd.nd_manage_extended_community_list:
    fabric_name: my-fabric
    config:
      - name: ECL-RT-PROD
      - name: ECL-EXPANDED-REGEX
    state: deleted

- name: Override -- enforce exact set of extended community lists (delete all others)
  cisco.nd.nd_manage_extended_community_list:
    fabric_name: my-fabric
    config:
      - name: ECL-FINAL
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            route_target_collection:
              - "65000:1"
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
  - The extended community list configuration before the module ran, structured the same as O(config).
  - An empty list when no extended community lists existed.
  returned: always
  type: list
  elements: dict
  sample:
  - name: ECL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      route_target_collection:
      - "65000:100"
after:
  description:
  - The extended community list configuration after the module ran, structured the same as O(config).
  - This is the predicted post-write state and is not re-read from the controller after writes.
  - In check mode, this is the configuration that would result outside check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - name: ECL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      route_target_collection:
      - "65000:200"
diff:
  description: The per-extended-community-list difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - name: ECL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      route_target_collection:
      - "65000:200"
proposed:
  description: The extended community list configuration proposed before reconciliation with existing state.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - name: ECL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      route_target_collection:
      - "65000:200"
logs:
  description: Internal diagnostic log messages collected during the run.
  returned: when O(output_level) is V(debug)
  type: list
  elements: str
  sample:
  - "manage_state begin state=merged check_mode=False"
msg:
  description: A human-readable error message present only when the module fails.
  returned: on failure
  type: str
  sample: "extended community list 'ECL_EXPORT': 'type, entries' are required for state 'merged'."
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_extended_community_list.manage_extended_community_list import (
    ExtendedCommunityListModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_extended_community_list import (
    ManageExtendedCommunityListOrchestrator,
)


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(ExtendedCommunityListModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_extended_community_list")

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageExtendedCommunityListOrchestrator,
        )

        module_log.debug("manage_state begin state=%s check_mode=%s", module.params.get("state"), module.check_mode)
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")

        module.exit_json(**nd_state_machine.output.format())

    except NDStateMachineError as e:
        module_log.exception("NDStateMachineError during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module execution failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)

    except Exception as e:
        module_log.exception("Unhandled exception during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
