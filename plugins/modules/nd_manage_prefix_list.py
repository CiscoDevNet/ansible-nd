# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_prefix_list
version_added: "1.6.0"
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
    - Required for all operations.
    type: str
    required: true
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
        - Allowed characters are C([A-Za-z0-9_-]).
        type: str
        aliases: [ tenantName ]
      entries:
        description:
        - The list of prefix list entries.
        - Each entry defines a permit/deny action for a specific IP prefix.
        type: list
        elements: dict
        required: true
        suboptions:
          sequence_number:
            description:
            - The sequence number of this entry (1-4294967294).
            - Entries are evaluated in ascending sequence order.
            type: int
            required: true
            aliases: [ sequenceNumber ]
          action:
            description:
            - The action to take when the prefix matches.
            type: str
            required: true
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
            type: int
            aliases: [ exactLength ]
          min_prefix_length:
            description:
            - Minimum prefix-length to match (inclusive).
            - Range 1-32 for IPv4, 1-128 for IPv6.
            type: int
            aliases: [ minLength ]
          max_prefix_length:
            description:
            - Maximum prefix-length to match (inclusive).
            - Range 1-32 for IPv4, 1-128 for IPv6.
            type: int
            aliases: [ maxLength ]
          mask:
            description:
            - Network mask in dotted-decimal format for IPv4
              (e.g. C(255.255.255.0)) or explicit match mask in IPv6
              format (e.g. C(ffff:ffff::)).
            - Must be a valid IPv4 address when O(config.ip_version=ipv4).
            - Must be a valid IPv6 address when O(config.ip_version=ipv6).
            type: str
  state:
    description:
    - The desired state of the prefix list resources on Cisco Nexus Dashboard.
    - Use O(state=merged) to create new prefix lists and update existing ones
      as defined in the configuration.
      Prefix lists on ND that are not specified in the configuration are left unchanged.
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
- O(config.entries.prefix) is validated locally to match the declared O(config.ip_version).
- O(config.entries.exact_length), O(config.entries.min_prefix_length), and
  O(config.entries.max_prefix_length) are validated to be within the
  address-family-appropriate range (1-32 for IPv4, 1-128 for IPv6).
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
        entries:
          - sequence_number: 10
            action: permit
            prefix: 10.0.0.0/8
      - ip_version: ipv6
        name: PL-IPV6-DATACENTER
        entries:
          - sequence_number: 10
            action: permit
            prefix: 2001:db8::/32
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

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_prefix_list.manage_prefix_list import PrefixListModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_prefix_list import ManagePrefixListOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(PrefixListModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    nd_state_machine = None
    try:
        sender = Sender()
        sender.ansible_module = module

        rest_send = RestSend(
            {
                "check_mode": module.check_mode,
                "state": module.params.get("state"),
            }
        )
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()

        orchestrator = ManagePrefixListOrchestrator(
            rest_send=rest_send,
            fabric_name=module.params["fabric_name"],
        )

        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=orchestrator,
        )

        nd_state_machine.manage_state()

        module.exit_json(**nd_state_machine.output.format())

    except Exception as e:
        output = nd_state_machine.output.format() if nd_state_machine is not None else {}
        module.fail_json(msg=f"Module execution failed: {str(e)}", **output)


if __name__ == "__main__":
    main()
