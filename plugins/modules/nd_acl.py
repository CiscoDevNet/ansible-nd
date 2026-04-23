#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_acl
version_added: "1.6.0"
short_description: Manage Access Control Lists (ACLs) on Cisco Nexus Dashboard
description:
- Manage Access Control Lists (ACLs) on Cisco Nexus Dashboard (ND).
- It supports creating, updating, deleting, and querying IPv4 and IPv6 ACLs.
- Requires ND 4.1 or later.
author:
- Slawomir Kaszlikowski
options:
  fabric:
    description:
    - Name of the target fabric for ACL operations.
    type: str
    required: true
  state:
    description:
    - The desired state of the ACL resources on Cisco Nexus Dashboard.
    - Use O(state=merged) to merge ACLs into the fabric.
      If an ACL exists, its entries will be merged with existing entries (want wins on conflict).
      If an ACL does not exist, it will be created.
    - Use O(state=replaced) to completely replace existing ACLs.
      If an ACL exists, it will be fully replaced. If it does not exist, it will be created.
    - Use O(state=deleted) to delete ACLs.
      If no O(config) is provided, all ACLs in the fabric will be deleted.
    - Use O(state=gathered) to retrieve current ACL state from ND without making changes.
      If no O(config) is provided, all ACLs in the fabric will be returned.
    type: str
    choices: [ merged, replaced, deleted, gathered ]
    default: merged
  config:
    description:
    - A list of dictionaries containing ACL configurations.
    type: list
    elements: dict
    default: []
    suboptions:
      name:
        description:
        - Name of the ACL.
        - Must be 1-63 characters, containing only alphanumeric characters, underscores, and hyphens.
        type: str
        required: true
      type:
        description:
        - Type of the ACL.
        - C(ipv4) for IPv4 Access Control Lists.
        - C(ipv6) for IPv6 Access Control Lists.
        - Required when O(state) is C(merged) or C(replaced).
        type: str
        choices: [ ipv4, ipv6 ]
      description:
        description:
        - Optional description of the ACL.
        type: str
      entries:
        description:
        - List of ACL entries (Access Control Entries).
        - Each entry can be a permit, deny, or remark entry.
        type: list
        elements: dict
        default: []
        suboptions:
          sequence_number:
            description:
            - Sequence number of the ACL entry.
            - Must be between 1 and 4294967295.
            type: int
            required: true
          action:
            description:
            - Action for this ACL entry.
            - C(permit) - Allow matching traffic.
            - C(deny) - Deny matching traffic.
            - C(remark) - Add a comment/remark entry.
            type: str
            required: true
            choices: [ permit, deny, remark ]
          remark_comment:
            description:
            - Comment text for remark entries.
            - Required when O(config.entries.action) is C(remark).
            - Maximum 100 characters.
            type: str
          protocol:
            description:
            - IP protocol to match.
            - Required when O(config.entries.action) is C(permit) or C(deny).
            - Use C(custom) to specify a protocol by number via O(config.entries.custom_protocol).
            type: str
            choices: [ ip, ipv6, tcp, udp, icmp, igmp, eigrp, ospf, pim, ahp, gre, nos, esp, custom ]
          custom_protocol:
            description:
            - Custom protocol number when O(config.entries.protocol) is C(custom).
            - Must be between 0 and 255.
            type: int
          src:
            description:
            - Source address specification.
            - Accepts C(any), a host address (e.g. C(host 10.1.1.1)), a network with wildcard
              (e.g. C(10.1.1.0 0.0.0.255)), or an IPv6 prefix (e.g. C(2001:db8::/32)).
            - Required when O(config.entries.action) is C(permit) or C(deny).
            type: str
          dst:
            description:
            - Destination address specification.
            - Accepts C(any), a host address (e.g. C(host 10.1.1.1)), a network with wildcard
              (e.g. C(10.1.1.0 0.0.0.255)), or an IPv6 prefix (e.g. C(2001:db8::/32)).
            - Required when O(config.entries.action) is C(permit) or C(deny).
            type: str
          src_port_action:
            description:
            - Source port matching action for TCP/UDP protocols.
            - C(none) - No source port filtering.
            - C(equal_to) - Match source port equal to O(config.entries.src_port).
            - C(greater_than) - Match source port greater than O(config.entries.src_port).
            - C(less_than) - Match source port less than O(config.entries.src_port).
            - C(not_equal_to) - Match source port not equal to O(config.entries.src_port).
            - C(port_range) - Match source port in range from O(config.entries.src_port_range_start)
              to O(config.entries.src_port_range_end).
            type: str
            choices: [ none, equal_to, greater_than, less_than, not_equal_to, port_range ]
            default: none
          src_port:
            description:
            - Source port number when O(config.entries.src_port_action) is C(equal_to),
              C(greater_than), C(less_than), or C(not_equal_to).
            - Must be between 0 and 65535.
            type: int
          src_port_range_start:
            description:
            - Start of source port range when O(config.entries.src_port_action) is C(port_range).
            - Must be between 0 and 65535.
            type: int
          src_port_range_end:
            description:
            - End of source port range when O(config.entries.src_port_action) is C(port_range).
            - Must be between 0 and 65535.
            type: int
          dst_port_action:
            description:
            - Destination port matching action for TCP/UDP protocols.
            - C(none) - No destination port filtering.
            - C(equal_to) - Match destination port equal to O(config.entries.dst_port).
            - C(greater_than) - Match destination port greater than O(config.entries.dst_port).
            - C(less_than) - Match destination port less than O(config.entries.dst_port).
            - C(not_equal_to) - Match destination port not equal to O(config.entries.dst_port).
            - C(port_range) - Match destination port in range from O(config.entries.dst_port_range_start)
              to O(config.entries.dst_port_range_end).
            type: str
            choices: [ none, equal_to, greater_than, less_than, not_equal_to, port_range ]
            default: none
          dst_port:
            description:
            - Destination port number when O(config.entries.dst_port_action) is C(equal_to),
              C(greater_than), C(less_than), or C(not_equal_to).
            - Must be between 0 and 65535.
            type: int
          dst_port_range_start:
            description:
            - Start of destination port range when O(config.entries.dst_port_action) is C(port_range).
            - Must be between 0 and 65535.
            type: int
          dst_port_range_end:
            description:
            - End of destination port range when O(config.entries.dst_port_action) is C(port_range).
            - Must be between 0 and 65535.
            type: int
          icmp_option:
            description:
            - ICMP message type to match when O(config.entries.protocol) is C(icmp).
            - Examples include C(echo), C(echo-reply), C(unreachable), C(redirect).
            type: str
          tcp_option:
            description:
            - TCP flags to match when O(config.entries.protocol) is C(tcp).
            - Examples include C(established), C(syn), C(ack), C(fin), C(rst).
            type: str
extends_documentation_fragment:
- cisco.nd.modules
- cisco.nd.check_mode
notes:
- This module is only supported on Nexus Dashboard having version 4.1 or higher.
"""

EXAMPLES = r"""
- name: Create IPv4 ACL with permit and deny entries (check mode)
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-ipv4-acl
        type: ipv4
        entries:
          - sequence_number: 10
            action: remark
            remark_comment: "Allow web traffic"
          - sequence_number: 20
            action: permit
            protocol: tcp
            src: any
            dst: 10.1.1.0 0.0.0.255
            dst_port_action: equal_to
            dst_port: 80
          - sequence_number: 100
            action: deny
            protocol: ip
            src: any
            dst: any
  check_mode: true
  register: cm_create_acl

- name: Create IPv4 ACL with permit and deny entries
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-ipv4-acl
        type: ipv4
        entries:
          - sequence_number: 10
            action: remark
            remark_comment: "Allow web traffic"
          - sequence_number: 20
            action: permit
            protocol: tcp
            src: any
            dst: 10.1.1.0 0.0.0.255
            dst_port_action: equal_to
            dst_port: 80
          - sequence_number: 100
            action: deny
            protocol: ip
            src: any
            dst: any
  register: create_acl

- name: Merge additional entries into existing ACL
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-ipv4-acl
        type: ipv4
        entries:
          - sequence_number: 30
            action: permit
            protocol: tcp
            src: any
            dst: 10.1.1.0 0.0.0.255
            dst_port_action: equal_to
            dst_port: 443
  register: merge_acl

- name: Create an IPv6 ACL
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: merged
    config:
      - name: my-ipv6-acl
        type: ipv6
        entries:
          - sequence_number: 10
            action: permit
            protocol: tcp
            src: any
            dst: 2001:db8::/32
            dst_port_action: port_range
            dst_port_range_start: 80
            dst_port_range_end: 443
          - sequence_number: 20
            action: deny
            protocol: ipv6
            src: any
            dst: any

- name: Replace an existing ACL completely
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: replaced
    config:
      - name: my-ipv4-acl
        type: ipv4
        entries:
          - sequence_number: 10
            action: permit
            protocol: ip
            src: 192.168.1.0 0.0.0.255
            dst: any

- name: Gather specific ACLs
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: gathered
    config:
      - name: my-ipv4-acl
  register: gathered_result

- name: Gather all ACLs in fabric
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: gathered
  register: all_acls

- name: Delete specific ACLs
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: deleted
    config:
      - name: my-ipv4-acl
      - name: my-ipv6-acl

- name: Delete all ACLs in fabric
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: deleted
"""

RETURN = r"""
changed:
  description: Whether any changes were made.
  type: bool
  returned: always
diff:
  description: Per-state lists of ACL names that were created, replaced, deleted, or gathered.
  type: list
  elements: dict
  returned: always
  sample:
    - merged: ["my-ipv4-acl"]
      replaced: []
      deleted: []
      gathered: []
response:
  description: Raw API responses for mutating operations.
  type: list
  elements: dict
  returned: always
acls:
  description: List of ACLs returned for O(state=gathered).
  type: list
  elements: dict
  returned: when state is gathered
  contains:
    name:
      description: Name of the ACL.
      type: str
    type:
      description: Type of the ACL (ipv4 or ipv6).
      type: str
    entries:
      description: List of ACL entries.
      type: list
      elements: dict
"""

import traceback
from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import nd_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import require_pydantic
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import AclModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_acl import ManageAclOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def main():
    argument_spec = nd_argument_spec()
    argument_spec.update(AclModel.get_argument_spec())

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    require_pydantic(module)

    fabric_name = module.params["fabric"]
    state = module.params["state"]
    config = deepcopy(module.params.get("config") or [])

    try:
        sender = Sender()
        sender.ansible_module = module

        rest_send = RestSend(
            {
                "check_mode": module.check_mode,
                "state": state,
            }
        )
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()

        orchestrator = ManageAclOrchestrator(
            rest_send=rest_send,
            fabric_name=fabric_name,
        )

        result = orchestrator.run(state=state, config=config, check_mode=module.check_mode)
        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg="Module execution failed: {0}".format(str(e)), exception=traceback.format_exc())


if __name__ == "__main__":
    main()
