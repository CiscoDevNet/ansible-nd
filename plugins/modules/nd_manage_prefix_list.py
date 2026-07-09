# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_prefix_list
version_added: "2.0.0"
short_description: Manage IPv4 and IPv6 prefix lists on Cisco Nexus Dashboard fabrics
description:
- Manage IPv4 and IPv6 routing-policy prefix lists on a Cisco Nexus Dashboard (ND) fabric.
- Both address families are handled by this single module; set O(config.ip_version)
  to C(ipv4) or C(ipv6) for each prefix list.
- Prefix lists are created and deleted in bulk via dedicated API endpoints.
- Prefix lists with the same name but different O(config.ip_version) values are treated
  as distinct resources.
author:
- Gaspard Micol (@gmicol)
options:
  fabric_name:
    description:
    - The name of the fabric that owns the prefix lists.
    type: str
    required: true
  cluster_name:
    description:
    - The name of the Nexus Dashboard cluster where the prefix-list operation is executed.
    - Use this option for multi-cluster deployments where the target fabric is managed by a specific cluster.
    type: str
  config:
    description:
    - The list of prefix lists to configure.
    type: list
    elements: dict
    required: True
    suboptions:
      ip_version:
        description:
        - The IP address family of the prefix list.
        - Use C(ipv4) for IPv4 prefix lists and C(ipv6) for IPv6 prefix lists.
        - No default is applied because the address family is part of the resource identity.
        - A prefix list named C(PL-1) with C(ip_version=ipv4) and another with
          C(ip_version=ipv6) are treated as independent resources.
        type: str
        required: true
        choices: [ ipv4, ipv6 ]
        aliases: [ ipVersion ]
      name:
        description:
        - The name of the prefix list.
        - Allowed characters are C([a-zA-Z0-9~_-]).
        - Maximum length is 115 characters (63 for the default tenant).
        - When O(config.tenant_name) is set, the combined C(tenant_name~name)
          value must not exceed 115 characters.
        type: str
        required: true
      description:
        description:
        - A human-readable description of the prefix list.
        - Maximum length is 90 characters.
        type: str
      tenant_name:
        description:
        - The tenant that owns this prefix list.
        - When omitted, the default tenant is used.
        - Prefix lists with the same O(config.ip_version) and O(config.name) but different
          O(config.tenant_name) values are treated as independent resources.
        - Allowed characters are C([A-Za-z0-9_-]).
        type: str
        aliases: [ tenantName ]
      entries:
        description:
        - The list of prefix list entries.
        - Each entry defines a permit/deny action for a specific IP prefix.
        - This list is authoritative whenever a prefix list is created or updated.
          Existing entries that are not present in this list are removed, including
          with O(state=merged). Restate every entry that should remain configured.
        - Required for O(state=merged), O(state=replaced), and O(state=overridden).
        - Optional for O(state=deleted), where identifier-only items
          (O(config.ip_version) + O(config.name)) are accepted.
        type: list
        elements: dict
        required: false
        suboptions:
          sequence_number:
            description:
            - The sequence number of this entry (1-4294967294).
            - Entries are evaluated in ascending sequence order.
            - Values must be unique within each prefix list.
            type: int
            required: true
            aliases: [ sequenceNumber ]
          action:
            description:
            - The action to take when the prefix matches.
            - Defaults to C(permit), matching the Nexus Dashboard UI default.
            type: str
            default: permit
            choices: [ permit, deny ]
          prefix:
            description:
            - The IP prefix in CIDR notation.
            - Must be an IPv4 CIDR (e.g. C(10.0.0.0/8)) when
              O(config.ip_version=ipv4).
            - Must be an IPv6 CIDR (e.g. C(2001:db8::/32)) when
              O(config.ip_version=ipv6).
            type: str
            required: true
          exact_length:
            description:
            - Exact prefix-length to match.
            - Range 1-32 for IPv4, 1-128 for IPv6.
            - Cannot be combined with O(config.entries.min_prefix_length) or
              O(config.entries.max_prefix_length) in the same entry.
            type: int
            aliases: [ exactLength ]
          min_prefix_length:
            description:
            - Minimum prefix-length to match (inclusive).
            - Range 1-32 for IPv4, 1-128 for IPv6.
            - Must be less than or equal to O(config.entries.max_prefix_length) when both are set.
            type: int
            aliases: [ minLength ]
          max_prefix_length:
            description:
            - Maximum prefix-length to match (inclusive).
            - Range 1-32 for IPv4, 1-128 for IPv6.
            - Must be greater than or equal to O(config.entries.min_prefix_length) when both are set.
            type: int
            aliases: [ maxLength ]
          mask:
            description:
            - Optional explicit match mask.
            - For IPv4, use dotted-decimal format (e.g. C(255.255.255.0)).
            - For IPv6, use IPv6 address format (e.g. C(ffff:ffff::)).
            - This value is sent to the API as a separate explicit match mask and is not deduced from O(config.entries.prefix).
            - Must be a valid IPv4 address when O(config.ip_version=ipv4).
            - Must be a valid IPv6 address when O(config.ip_version=ipv6).
            type: str
  state:
    description:
    - The desired state of the prefix list resources on Cisco Nexus Dashboard.
    - Use O(state=merged) to create new prefix lists and update existing ones
      as defined in the configuration.
      Prefix lists on ND that are not specified in the configuration are left unchanged.
      For prefix lists that are specified, O(config.entries) replaces the full
      entry list; entries omitted from O(config.entries) are removed.
    - Use O(state=replaced) to replace the prefix lists specified in the configuration.
    - Use O(state=overridden) to enforce the configuration as the single source of truth.
      All prefix lists (both IPv4 and IPv6) on ND not present in the configuration
      will be deleted. Use with caution.
    - Use O(state=deleted) to remove the prefix lists specified in the configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.2.1 or higher.
- IPv4 and IPv6 prefix lists are created and deleted in bulk via separate API endpoints.
  A single task may contain a mix of IPv4 and IPv6 entries.
- Prefix and mask values are normalized locally for stable idempotency when Nexus Dashboard returns
  equivalent IPv6 values in compressed notation.
"""

EXAMPLES = r"""
- name: Create IPv4 and IPv6 prefix lists
  cisco.nd.nd_manage_prefix_list:
    fabric_name: my-fabric
    config:
      - ip_version: ipv4
        name: PL-IPV4-BORDERS
        description: Border router IPv4 prefixes
        entries:
          - sequence_number: 10
            action: permit
            prefix: 10.0.0.0/8
          - sequence_number: 20
            action: permit
            prefix: 172.16.0.0/12
            min_prefix_length: 24
            max_prefix_length: 32
          - sequence_number: 30
            action: deny
            prefix: 0.0.0.0/0
      - ip_version: ipv6
        name: PL-IPV6-DATACENTER
        description: Datacenter IPv6 prefixes
        entries:
          - sequence_number: 10
            action: permit
            prefix: 2001:db8::/32
            exact_length: 48
          - sequence_number: 20
            action: deny
            prefix: ::/0
    state: merged

- name: Update an IPv4 prefix list
  cisco.nd.nd_manage_prefix_list:
    fabric_name: my-fabric
    config:
      - ip_version: ipv4
        name: PL-IPV4-BORDERS
        entries:
          - sequence_number: 10
            action: permit
            prefix: 192.168.0.0/16
            min_prefix_length: 24
    state: replaced

- name: Delete specific prefix lists
  cisco.nd.nd_manage_prefix_list:
    fabric_name: my-fabric
    config:
      - ip_version: ipv4
        name: PL-IPV4-BORDERS
      - ip_version: ipv6
        name: PL-IPV6-DATACENTER
    state: deleted

- name: Override -- enforce exact set of prefix lists (delete all others)
  cisco.nd.nd_manage_prefix_list:
    fabric_name: my-fabric
    config:
      - ip_version: ipv4
        name: PL-IPV4-FINAL
        entries:
          - sequence_number: 10
            action: permit
            prefix: 10.0.0.0/8
    state: overridden
"""

RETURN = r"""
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import PrefixListModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_prefix_list import ManagePrefixListOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_manage_prefix_list` Ansible module.

    Builds the argument spec from `PrefixListModel.get_argument_spec()` (which contributes the
    top-level `fabric_name` option plus the `config` list of prefix lists) and hands control to
    `NDStateMachine`, passing the `ManagePrefixListOrchestrator` *class*. The state machine builds
    `RestSend` from the validated module params, so the orchestrator reads `fabric_name` from
    `rest_send.params` rather than a constructor argument.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(PrefixListModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_prefix_list")

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManagePrefixListOrchestrator,
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

    except Exception as e:  # pylint: disable=broad-except
        module_log.exception("Unhandled exception during module execution")
        output = nd_state_machine.output.format() if nd_state_machine else {}
        error_msg = f"Module failed: {str(e)}"
        if module.params.get("output_level") == "debug":
            error_msg += f"\nTraceback:\n{traceback.format_exc()}"
        module.fail_json(msg=error_msg, **output)


if __name__ == "__main__":
    main()
