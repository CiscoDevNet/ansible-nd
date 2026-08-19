#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_community_list
version_added: "2.0.0"
short_description: Manage BGP community lists on Cisco Nexus Dashboard fabrics
description:
- Manage BGP routing-policy community lists on a Cisco Nexus Dashboard (ND) fabric.
- Both C(standard) and C(expanded) community list types are supported by this module.
- Community lists are created and deleted in bulk via dedicated API endpoints.
author:
- Gaspard Micol (@gmicol)
options:
  fabric_name:
    description:
    - The name of the fabric that owns the community lists.
    - Required for all operations.
    type: str
    required: true
  cluster_name:
    description:
    - The target cluster name in a multi-cluster deployment.
    type: str
  config:
    description:
    - The list of community lists to configure.
    type: list
    elements: dict
    required: True
    suboptions:
      name:
        description:
        - The name of the community list.
        - Allowed characters are C([a-zA-Z0-9~_-]).
        - Maximum length is 115 characters (63 for the default tenant).
        type: str
        required: true
      type:
        description:
        - The type of community list.
        - Required for create and update operations; not required when O(state=deleted).
        - C(standard) - matches well-known communities and/or explicit community
          numbers in ASN:NN format.
        - C(expanded) - matches community strings using a regular expression.
        type: str
        choices: [ standard, expanded ]
      tenant_name:
        description:
        - The tenant that owns this community list.
        - When omitted the default tenant is used.
        - Allowed characters are C([A-Za-z0-9_-]). Max 63 characters.
        - When set, O(config.name) may be the bare list name or the fully qualified C(tenant~name) API name.
        - The module reports the bare O(config.name) and uses C(tenant~name) for API lookups, updates, and deletes.
        type: str
        aliases: [ tenantName ]
      entries:
        description:
        - The ordered list of community list entries.
        - Required for create and update operations; not required when O(state=deleted).
        - Each entry defines a permit/deny action and the community or regular
          expression to match.
        - Every standard entry must set at least one explicit community number or enable at least one well-known community flag.
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
          no_advertise:
            description:
            - Match the well-known C(NO_ADVERTISE) community (65535:65282).
            - Do not advertise the route to any iBGP or eBGP neighbors.
            - Only valid when O(config.type=standard).
            type: bool
            aliases: [ noAdvertise ]
          blackhole:
            description:
            - Match the well-known C(BLACKHOLE) community (65535:666).
            - Used to drop traffic to a specified destination.
            - Only valid when O(config.type=standard).
            type: bool
            aliases: [ blackhole ]
          no_export:
            description:
            - Match the well-known C(NO_EXPORT) community.
            - Do not export the route to the next AS.
            - Only valid when O(config.type=standard).
            type: bool
            aliases: [ noExport ]
          internet:
            description:
            - Match the well-known C(INTERNET) community.
            - Only valid when O(config.type=standard).
            type: bool
            aliases: [ internet ]
          graceful_shutdown:
            description:
            - Match the well-known C(GRACEFUL_SHUTDOWN) community.
            - Only valid when O(config.type=standard).
            type: bool
            aliases: [ gracefulShutdown ]
          local_asn:
            description:
            - Match the well-known C(NO_ADVERTISE_TO_IBGP) community (65535:65284).
            - Do not advertise the route to an iBGP neighbor if the route was
              received from another iBGP neighbor.
            - Only valid when O(config.type=standard).
            type: bool
            aliases: [ localAsn ]
          community_numbers:
            description:
            - List of explicit community numbers in ASN:NN format.
            - Each part must be in the range 0-65535 (e.g. C(100:200)).
            - Only valid when O(config.type=standard).
            type: list
            elements: str
            aliases: [ communityNumbers ]
          community_number_regex:
            description:
            - Regular expression in aa:nn format for matching community strings.
            - Must not start with C([a-zA-Z~!#%@`;]). Max 63 characters.
            - Required and only valid when O(config.type=expanded).
            type: str
            aliases: [ communityNumberRegex ]
  state:
    description:
    - The desired state of the community list resources on Cisco Nexus Dashboard.
    - Use O(state=merged) to create new community lists and update existing ones
      as defined in the configuration.
      Community lists not specified in the configuration are left unchanged.
    - Use O(state=replaced) to replace the community lists specified in the
      configuration.
    - Use O(state=overridden) to enforce the configuration as the single source
      of truth. All community lists on ND not present in the configuration will
      be deleted. Use with caution.
    - Use O(state=deleted) to remove the community lists specified in the
      configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
- cisco.nd.verification
notes:
- This module is only supported on Nexus Dashboard version 4.2.1 or higher.
- Community lists are created and deleted in bulk via separate API endpoints.
- Every standard entry must set at least one explicit community number or enable
  at least one well-known community flag.
- O(config.entries.community_number_regex) is required for every entry when
  O(config.type=expanded); standard-only fields must not be set on expanded entries.
"""

EXAMPLES = r"""
- name: Create a standard community list
  cisco.nd.nd_manage_community_list:
    fabric_name: my-fabric
    config:
      - name: CL-STANDARD-PROD
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            community_numbers:
              - "100:200"
              - "65000:1"
          - sequence_number: 20
            action: permit
            no_advertise: true
            no_export: true
          - sequence_number: 30
            action: deny
            blackhole: true
    state: merged

- name: Create an expanded community list
  cisco.nd.nd_manage_community_list:
    fabric_name: my-fabric
    config:
      - name: CL-EXPANDED-REGEX
        type: expanded
        entries:
          - sequence_number: 10
            action: permit
            community_number_regex: "100:.*"
          - sequence_number: 20
            action: deny
            community_number_regex: "65000:.*"
    state: merged

- name: Update a standard community list (replace its entries)
  cisco.nd.nd_manage_community_list:
    fabric_name: my-fabric
    config:
      - name: CL-STANDARD-PROD
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            community_numbers:
              - "200:300"
    state: replaced

- name: Delete specific community lists
  cisco.nd.nd_manage_community_list:
    fabric_name: my-fabric
    config:
      - name: CL-STANDARD-PROD
      - name: CL-EXPANDED-REGEX
    state: deleted

- name: Override -- enforce exact set of community lists (delete all others)
  cisco.nd.nd_manage_community_list:
    fabric_name: my-fabric
    config:
      - name: CL-FINAL
        type: standard
        entries:
          - sequence_number: 10
            action: permit
            internet: true
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
  - The community list configuration before the module ran, structured the same as O(config).
  - An empty list when no community lists existed.
  returned: always
  type: list
  elements: dict
  sample:
  - name: CL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      community_numbers:
      - "65000:100"
after:
  description:
  - The community list configuration after the module ran, structured the same as O(config).
  - By default, this is the predicted post-write state. When O(verify.enabled=true), it is replaced
    by a controller readback after all write actions complete.
  - In check mode, this is the configuration that would result outside check mode.
  returned: always
  type: list
  elements: dict
  sample:
  - name: CL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      community_numbers:
      - "65000:200"
diff:
  description: The per-community-list difference between C(before) and C(after).
  returned: always
  type: list
  elements: dict
  sample:
  - name: CL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      community_numbers:
      - "65000:200"
proposed:
  description: The community list configuration proposed before reconciliation with existing state.
  returned: when O(output_level) is V(info) or V(debug)
  type: list
  elements: dict
  sample:
  - name: CL_EXPORT
    tenant_name: tenantSales
    type: standard
    entries:
    - sequence_number: 10
      action: permit
      community_numbers:
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
  sample: "community list 'CL_EXPORT': 'type, entries' are required for state 'merged'."
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_community_list.manage_community_list import CommunityListModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_argument_specs import verify_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_community_list import ManageCommunityListOrchestrator


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(verify_spec())
    argument_spec.update(CommunityListModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_community_list")

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageCommunityListOrchestrator,
        )

        module_log.debug("manage_state begin state=%s check_mode=%s", module.params.get("state"), module.check_mode)
        nd_state_machine.manage_state()
        module_log.debug("manage_state end")
        nd_state_machine.finalize_result()

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
