#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski (@skaszlik)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_manage_acl
version_added: "2.0.0"
short_description: Manage IPv4 and IPv6 Access Control Lists on Cisco Nexus Dashboard fabrics
description:
- Manage IPv4 and IPv6 Access Control Lists (ACLs) on a Cisco Nexus Dashboard (ND) fabric.
- Both address families are handled by this single module; set O(config.type)
  to C(ipv4) or C(ipv6) for each ACL.
- ACLs are created and deleted in bulk via dedicated API endpoints.
author:
- Slawomir Kaszlikowski (@skaszlik)
options:
  fabric_name:
    description:
    - The name of the fabric that owns the ACLs.
    type: str
    required: true
  config:
    description:
    - The list of ACLs to configure.
    type: list
    elements: dict
    required: true
    suboptions:
      name:
        description:
        - The name of the ACL.
        - Allowed characters are C([a-zA-Z0-9_~-]).
        - Tenant-qualified names in the form C(<tenant>~<name>) (for example C(tenant1~acl3)) are supported.
        - Maximum length is 115 characters.
        type: str
        required: true
      type:
        description:
        - The IP address family of the ACL.
        - Required for O(state=merged), O(state=replaced), and O(state=overridden).
        - Optional for O(state=deleted), where identifier-only items (O(config.name)) are accepted.
        type: str
        choices: [ ipv4, ipv6 ]
      description:
        description:
        - A human-readable description of the ACL.
        - Maximum length is 90 characters.
        - On Nexus Dashboard 4.1.1, the controller accepts this value but does not
          persist or return it; it is therefore excluded from idempotency
          comparison and a configured description will not appear in the returned
          state.
        type: str
      entries:
        description:
        - The list of ACL entries.
        - Each entry defines a permit, deny, or remark action.
        - Required for O(state=merged), O(state=replaced), and O(state=overridden).
        - Optional for O(state=deleted), where identifier-only items (O(config.name)) are accepted.
        type: list
        elements: dict
        required: false
        suboptions:
          sequence_number:
            description:
            - The sequence number of the entry (1-4294967294).
            - Must be unique within the ACL.
            type: int
            required: true
            aliases: [ sequenceNumber ]
          action:
            description:
            - The action for the entry.
            type: str
            required: true
            choices: [ permit, deny, remark ]
          remark_comment:
            description:
            - The remark text.
            - Required when O(config.entries.action) is C(remark).
            type: str
            aliases: [ remarkComment ]
          protocol:
            description:
            - The protocol matched by the entry.
            - Required for C(permit) and C(deny) entries.
            type: str
            choices: [ ip, ipv6, tcp, udp, icmp, igmp, eigrp, ospf, pim, custom ]
          custom_protocol:
            description:
            - The custom IP protocol number.
            - Required when O(config.entries.protocol) is C(custom).
            type: int
            aliases: [ customProtocol ]
          src:
            description:
            - The source match (address/CIDR or C(any)).
            - Required for C(permit) and C(deny) entries.
            type: str
          dst:
            description:
            - The destination match (address/CIDR or C(any)).
            - Required for C(permit) and C(deny) entries.
            type: str
          src_port_action:
            description:
            - The source port operator (valid for C(tcp) and C(udp)).
            - C(none) is equivalent to omitting the operator.
            type: str
            choices: [ none, equal_to, greater_than, less_than, not_equal_to, port_range ]
            aliases: [ srcPortAction ]
          src_port:
            description:
            - The source port value.
            - Accepts a port number (for example C(80)) or a service name (for example C(www)).
            - Required when O(config.entries.src_port_action) is set to a value other than C(port_range) or C(none).
            type: str
            aliases: [ srcPort ]
          src_port_range_start:
            description:
            - The source port range start.
            - Accepts a port number or a service name.
            - Required when O(config.entries.src_port_action) is C(port_range).
            type: str
            aliases: [ srcPortRangeStart ]
          src_port_range_end:
            description:
            - The source port range end.
            - Accepts a port number or a service name.
            - Required when O(config.entries.src_port_action) is C(port_range).
            type: str
            aliases: [ srcPortRangeEnd ]
          dst_port_action:
            description:
            - The destination port operator (valid for C(tcp) and C(udp)).
            - C(none) is equivalent to omitting the operator.
            type: str
            choices: [ none, equal_to, greater_than, less_than, not_equal_to, port_range ]
            aliases: [ dstPortAction ]
          dst_port:
            description:
            - The destination port value.
            - Accepts a port number (for example C(443)) or a service name (for example C(ftp)).
            - Required when O(config.entries.dst_port_action) is set to a value other than C(port_range) or C(none).
            type: str
            aliases: [ dstPort ]
          dst_port_range_start:
            description:
            - The destination port range start.
            - Accepts a port number or a service name.
            - Required when O(config.entries.dst_port_action) is C(port_range).
            type: str
            aliases: [ dstPortRangeStart ]
          dst_port_range_end:
            description:
            - The destination port range end.
            - Accepts a port number or a service name.
            - Required when O(config.entries.dst_port_action) is C(port_range).
            type: str
            aliases: [ dstPortRangeEnd ]
          icmp_option:
            description:
            - The ICMP option.
            - Only valid when O(config.entries.protocol) is C(icmp).
            type: str
            aliases: [ icmpOption ]
          tcp_option:
            description:
            - The TCP option.
            - Only valid when O(config.entries.protocol) is C(tcp).
            type: str
            aliases: [ tcpOption ]
  state:
    description:
    - Use O(state=merged) to create or update the ACLs specified in the configuration.
    - Use O(state=replaced) to replace each specified ACL with the configuration provided.
    - Use O(state=overridden) to make the ACLs on the fabric exactly match the configuration,
      removing any ACL not present in the configuration.
    - Use O(state=deleted) to remove the ACLs specified in the configuration.
    type: str
    default: merged
    choices: [ merged, replaced, overridden, deleted ]
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1.1 or higher.
- IPv4 and IPv6 ACLs share a single API namespace and are distinguished by O(config.type).
  A single task may contain a mix of IPv4 and IPv6 ACLs.
- ACLs are created and deleted in bulk via dedicated API endpoints.
- O(config.entries.sequence_number) values must be unique within each ACL.
- For C(remark) entries, only O(config.entries.remark_comment) is required.
- For C(permit) and C(deny) entries, O(config.entries.protocol), O(config.entries.src),
  and O(config.entries.dst) are required.
- O(config.entries.icmp_option) is only valid when O(config.entries.protocol) is C(icmp);
  O(config.entries.tcp_option) is only valid when O(config.entries.protocol) is C(tcp).
- Port operators (O(config.entries.src_port_action) and O(config.entries.dst_port_action))
  are accepted in snake_case and stored/returned in the controller's native form.
"""

EXAMPLES = r"""
- name: Create an IPv4 ACL with permit/deny/remark entries
  cisco.nd.nd_manage_acl:
    fabric_name: my-fabric
    state: merged
    config:
      - name: ACL-IPV4-1
        type: ipv4
        description: Example IPv4 ACL
        entries:
          - sequence_number: 10
            action: remark
            remark_comment: Allow web traffic
          - sequence_number: 20
            action: permit
            protocol: tcp
            src: 10.0.0.0/8
            dst: any
            dst_port_action: equal_to
            dst_port: 443
          - sequence_number: 25
            action: permit
            protocol: tcp
            src: 10.0.0.0/8
            dst: any
            dst_port_action: equal_to
            dst_port: www  # service name is also accepted
          - sequence_number: 30
            action: deny
            protocol: ip
            src: any
            dst: any

- name: Create an IPv6 ACL
  cisco.nd.nd_manage_acl:
    fabric_name: my-fabric
    state: merged
    config:
      - name: ACL-IPV6-1
        type: ipv6
        entries:
          - sequence_number: 10
            action: permit
            protocol: tcp
            src: 2001:db8::/32
            dst: any
            dst_port_action: port_range
            dst_port_range_start: 1024
            dst_port_range_end: 2048

- name: Replace an ACL's entries
  cisco.nd.nd_manage_acl:
    fabric_name: my-fabric
    state: replaced
    config:
      - name: ACL-IPV4-1
        type: ipv4
        entries:
          - sequence_number: 10
            action: permit
            protocol: ip
            src: any
            dst: any

- name: Override all ACLs on the fabric to match exactly this configuration
  cisco.nd.nd_manage_acl:
    fabric_name: my-fabric
    state: overridden
    config:
      - name: ACL-IPV4-1
        type: ipv4
        entries:
          - sequence_number: 10
            action: permit
            protocol: ip
            src: any
            dst: any

- name: Delete an ACL (identifier only)
  cisco.nd.nd_manage_acl:
    fabric_name: my-fabric
    state: deleted
    config:
      - name: ACL-IPV4-1
"""

RETURN = r"""
"""

import logging
import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import AclModel
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_acl import ManageAclOrchestrator


def main():
    """
    # Summary

    Entry point for the `nd_manage_acl` Ansible module.

    Builds the argument spec from `AclModel.get_argument_spec()` (which contributes the top-level
    `fabric_name` option plus the `config` list of ACLs) and hands control to `NDStateMachine`,
    passing the `ManageAclOrchestrator` *class*. The state machine builds `RestSend` from the
    validated module params, so the orchestrator reads `fabric_name` from `rest_send.params`
    rather than a constructor argument.

    ## Raises

    None (catches all exceptions and calls `module.fail_json`).
    """
    argument_spec = nd_argument_spec()
    argument_spec.update(AclModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)
    setup_logging(module)
    module_log = logging.getLogger("nd.nd_manage_acl")

    nd_state_machine = None
    try:
        nd_state_machine = NDStateMachine(
            module=module,
            model_orchestrator=ManageAclOrchestrator,
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
