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
    - The required state of the configuration after module completion.
    - C(merged) - ACLs defined in the playbook will be merged into the fabric.
      If an ACL exists, its entries will be merged with the existing entries.
      If it does not exist, it will be created.
    - C(replaced) - ACLs defined in the playbook will completely replace existing ACLs.
      If an ACL exists, it will be fully replaced. If it does not exist, it will be created.
    - C(deleted) - ACLs defined in the playbook will be deleted from the fabric.
      If no O(config) is provided, all ACLs in the fabric will be deleted.
    - C(query) - Returns the current ND state for the ACLs listed in O(config).
      If no O(config) is provided, all ACLs in the fabric will be returned.
    type: str
    choices: [ merged, replaced, deleted, query ]
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

- name: Query specific ACLs
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: query
    config:
      - name: my-ipv4-acl
  register: query_result

- name: Query all ACLs in fabric
  cisco.nd.nd_acl:
    fabric: "{{ fabric_name }}"
    state: query
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
  description: Per-state lists of ACL names that were created, replaced, deleted, or queried.
  type: list
  elements: dict
  returned: always
  sample:
    - merged: ["my-ipv4-acl"]
      replaced: []
      deleted: []
      query: []
response:
  description: Raw API responses for mutating operations.
  type: list
  elements: dict
  returned: always
acls:
  description: List of ACLs returned for O(state=query).
  type: list
  elements: dict
  returned: when state is query
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

import re
from copy import deepcopy

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.nd import NDModule, nd_argument_spec


# Parameter name mapping from Ansible (snake_case) to ND API (camelCase)
_PARAM_TO_API = {
    "sequence_number": "sequenceNumber",
    "remark_comment": "remarkComment",
    "custom_protocol": "customProtocol",
    "src_port_action": "srcPortAction",
    "src_port": "srcPort",
    "src_port_range_start": "srcPortRangeStart",
    "src_port_range_end": "srcPortRangeEnd",
    "dst_port_action": "dstPortAction",
    "dst_port": "dstPort",
    "dst_port_range_start": "dstPortRangeStart",
    "dst_port_range_end": "dstPortRangeEnd",
    "icmp_option": "icmpOption",
    "tcp_option": "tcpOption",
}

_API_TO_PARAM = {v: k for k, v in _PARAM_TO_API.items()}

_PORT_ACTION_TO_API = {
    "equal_to": "equalTo",
    "greater_than": "greaterThan",
    "less_than": "lessThan",
    "not_equal_to": "notEqualTo",
    "port_range": "portRange",
    "none": "none",
}

_API_TO_PORT_ACTION = {v: k for k, v in _PORT_ACTION_TO_API.items()}

_ACL_LIST_PATH = "/api/v1/manage/fabrics/{0}/accessControlLists"
_ACL_ITEM_PATH = "/api/v1/manage/fabrics/{0}/accessControlLists/{1}"


class NdAcl(object):
    """Manages Access Control Lists on Cisco Nexus Dashboard."""

    def __init__(self, nd, fabric, state, config):
        self.nd = nd
        self.fabric = fabric
        self.state = state
        self.config = config

        # Desired vs current state
        self.want = []
        self.have = []

        # Diff lists
        self.diff_create = []
        self.diff_replace = []
        self.diff_delete = []
        self.diff_query = []

        self.result = dict(
            changed=False,
            diff=[{"merged": [], "replaced": [], "deleted": [], "query": []}],
            response=[],
            acls=[],
        )

    def _check_nd_version(self):
        """Verify that the ND version is 4.1 or later."""
        version = self.nd.version
        if not version or not isinstance(version, str):
            return
        parts = version.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if major < 4 or (major == 4 and minor < 1):
                self.nd.fail_json(
                    "nd_acl requires ND 4.1 or later. Detected version: {0}".format(version)
                )
        except (ValueError, IndexError):
            pass

    def validate_input(self):
        """Validate the playbook configuration."""
        if not self.config:
            if self.state in ["merged", "replaced"]:
                self.nd.fail_json(
                    "config is required when state is '{0}'".format(self.state)
                )
            return

        for acl in self.config:
            name = acl.get("name", "")

            if not re.match(r"^[a-zA-Z0-9_-]+$", name):
                self.nd.fail_json(
                    "ACL name '{0}' is invalid. Only alphanumeric characters, underscores, "
                    "and hyphens are allowed.".format(name)
                )
            if len(name) > 63:
                self.nd.fail_json(
                    "ACL name '{0}' exceeds the maximum length of 63 characters.".format(name)
                )

            if self.state in ["merged", "replaced"] and not acl.get("type"):
                self.nd.fail_json(
                    "ACL '{0}': 'type' is required when state is '{1}'".format(name, self.state)
                )

            for entry in acl.get("entries", []):
                self._validate_entry(name, entry)

    def _validate_entry(self, acl_name, entry):
        """Validate a single ACL entry for semantic correctness."""
        action = entry.get("action")
        seq_num = entry.get("sequence_number")

        if action == "remark":
            if not entry.get("remark_comment"):
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: 'remark_comment' is required for remark entries".format(
                        acl_name, seq_num
                    )
                )
        else:
            for field in ("protocol", "src", "dst"):
                if not entry.get(field):
                    self.nd.fail_json(
                        "ACL '{0}' entry {1}: '{2}' is required for permit/deny entries".format(
                            acl_name, seq_num, field
                        )
                    )

            protocol = entry.get("protocol")
            if protocol == "custom" and entry.get("custom_protocol") is None:
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: 'custom_protocol' is required when protocol is 'custom'".format(
                        acl_name, seq_num
                    )
                )

            if protocol in ("tcp", "udp"):
                self._validate_port_options(acl_name, entry, "src")
                self._validate_port_options(acl_name, entry, "dst")

            if entry.get("icmp_option") and protocol != "icmp":
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: 'icmp_option' is only valid for icmp protocol".format(
                        acl_name, seq_num
                    )
                )
            if entry.get("tcp_option") and protocol != "tcp":
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: 'tcp_option' is only valid for tcp protocol".format(
                        acl_name, seq_num
                    )
                )

    def _validate_port_options(self, acl_name, entry, prefix):
        """Validate port action and range consistency for a given direction."""
        seq_num = entry.get("sequence_number")
        port_action = entry.get("{0}_port_action".format(prefix))

        if not port_action or port_action == "none":
            return

        if port_action == "port_range":
            start = entry.get("{0}_port_range_start".format(prefix))
            end = entry.get("{0}_port_range_end".format(prefix))
            if start is None or end is None:
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: '{2}_port_range_start' and '{2}_port_range_end' "
                    "are required when {2}_port_action is 'port_range'".format(
                        acl_name, seq_num, prefix
                    )
                )
            if start > end:
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: '{2}_port_range_start' must be less than or equal "
                    "to '{2}_port_range_end'".format(acl_name, seq_num, prefix)
                )
        else:
            if entry.get("{0}_port".format(prefix)) is None:
                self.nd.fail_json(
                    "ACL '{0}' entry {1}: '{2}_port' is required when {2}_port_action "
                    "is '{3}'".format(acl_name, seq_num, prefix, port_action)
                )

    # -------------------------------------------------------------------------
    # Transformation helpers
    # -------------------------------------------------------------------------

    def _entry_to_api(self, entry):
        """Convert an entry dict from Ansible snake_case to API camelCase."""
        api_entry = {}
        for key, value in entry.items():
            if value is None:
                continue
            api_key = _PARAM_TO_API.get(key, key)
            if key in ("src_port_action", "dst_port_action"):
                value = _PORT_ACTION_TO_API.get(value, value)
            api_entry[api_key] = value
        return api_entry

    def _entry_from_api(self, api_entry):
        """Convert an entry dict from API camelCase to Ansible snake_case."""
        entry = {}
        for key, value in api_entry.items():
            if value is None:
                continue
            ansible_key = _API_TO_PARAM.get(key, key)
            if key in ("srcPortAction", "dstPortAction"):
                value = _API_TO_PORT_ACTION.get(value, value)
            entry[ansible_key] = value
        return entry

    def _acl_to_api(self, acl):
        """Convert an ACL dict from Ansible format to API format."""
        return {
            "name": acl["name"],
            "type": acl["type"],
            "entries": [self._entry_to_api(e) for e in acl.get("entries", [])],
        }

    def _acl_from_api(self, api_acl):
        """Convert an ACL dict from API format to Ansible format."""
        return {
            "name": api_acl["name"],
            "type": api_acl["type"],
            "entries": [self._entry_from_api(e) for e in api_acl.get("entries", [])],
        }

    def _process_entry(self, entry):
        """Normalize an entry from module params, stripping injected defaults."""
        processed = {
            "sequence_number": entry["sequence_number"],
            "action": entry["action"],
        }

        if entry["action"] == "remark":
            processed["remark_comment"] = entry.get("remark_comment", "")
            return processed

        processed["protocol"] = entry.get("protocol")
        processed["src"] = entry.get("src")
        processed["dst"] = entry.get("dst")

        if entry.get("custom_protocol") is not None:
            processed["custom_protocol"] = entry["custom_protocol"]

        src_port_action = entry.get("src_port_action") or "none"
        if src_port_action != "none":
            processed["src_port_action"] = src_port_action
            if src_port_action == "port_range":
                processed["src_port_range_start"] = entry.get("src_port_range_start")
                processed["src_port_range_end"] = entry.get("src_port_range_end")
            else:
                processed["src_port"] = entry.get("src_port")

        dst_port_action = entry.get("dst_port_action") or "none"
        if dst_port_action != "none":
            processed["dst_port_action"] = dst_port_action
            if dst_port_action == "port_range":
                processed["dst_port_range_start"] = entry.get("dst_port_range_start")
                processed["dst_port_range_end"] = entry.get("dst_port_range_end")
            else:
                processed["dst_port"] = entry.get("dst_port")

        if entry.get("icmp_option"):
            processed["icmp_option"] = entry["icmp_option"]
        if entry.get("tcp_option"):
            processed["tcp_option"] = entry["tcp_option"]

        return processed

    # -------------------------------------------------------------------------
    # State retrieval
    # -------------------------------------------------------------------------

    def get_have(self):
        """Fetch the current ACL list from ND."""
        path = _ACL_LIST_PATH.format(self.fabric)
        resp = self.nd.request(path, method="GET", ignore_not_found_error=True)

        if not resp:
            return

        # The API may return {"accessControlLists": [...]} or a bare list
        if isinstance(resp, dict):
            acl_list = resp.get("accessControlLists", [])
        elif isinstance(resp, list):
            acl_list = resp
        else:
            acl_list = []

        for api_acl in acl_list:
            self.have.append(self._acl_from_api(api_acl))

    def get_want(self):
        """Build the desired state list from module params."""
        for acl in self.config:
            want_acl = {"name": acl["name"]}
            if acl.get("type"):
                want_acl["type"] = acl["type"]
            want_acl["entries"] = [self._process_entry(e) for e in acl.get("entries", [])]
            self.want.append(want_acl)

    # -------------------------------------------------------------------------
    # Diff helpers
    # -------------------------------------------------------------------------

    def _find_have(self, name):
        """Return the existing ACL with the given name, or None."""
        for acl in self.have:
            if acl["name"] == name:
                return acl
        return None

    def _entries_equal(self, e1, e2):
        """Compare two normalized entry dicts for equality."""
        fields = [
            "sequence_number", "action", "protocol", "src", "dst",
            "remark_comment", "custom_protocol",
            "src_port_action", "src_port", "src_port_range_start", "src_port_range_end",
            "dst_port_action", "dst_port", "dst_port_range_start", "dst_port_range_end",
            "icmp_option", "tcp_option",
        ]
        return all(e1.get(f) == e2.get(f) for f in fields)

    def _acls_equal(self, acl1, acl2):
        """Compare two normalized ACL dicts for equality."""
        if acl1["name"] != acl2["name"] or acl1.get("type") != acl2.get("type"):
            return False
        entries1 = {e["sequence_number"]: e for e in acl1.get("entries", [])}
        entries2 = {e["sequence_number"]: e for e in acl2.get("entries", [])}
        if set(entries1) != set(entries2):
            return False
        return all(self._entries_equal(entries1[s], entries2[s]) for s in entries1)

    def _merge_entries(self, have_acl, want_acl):
        """Return a new ACL whose entries are have merged with want (want wins on conflict)."""
        have_entries = {e["sequence_number"]: e for e in have_acl.get("entries", [])}
        want_entries = {e["sequence_number"]: e for e in want_acl.get("entries", [])}
        merged_seqs = sorted(set(have_entries) | set(want_entries))
        return {
            "name": want_acl["name"],
            "type": want_acl.get("type", have_acl.get("type")),
            "entries": [want_entries[s] if s in want_entries else have_entries[s] for s in merged_seqs],
        }

    # -------------------------------------------------------------------------
    # Diff calculation
    # -------------------------------------------------------------------------

    def get_diff_merged(self):
        for want_acl in self.want:
            have_acl = self._find_have(want_acl["name"])
            if have_acl is None:
                self.diff_create.append(want_acl)
                self.result["diff"][0]["merged"].append(want_acl["name"])
            else:
                merged = self._merge_entries(have_acl, want_acl)
                if not self._acls_equal(have_acl, merged):
                    self.diff_replace.append(merged)
                    self.result["diff"][0]["merged"].append(want_acl["name"])

    def get_diff_replaced(self):
        for want_acl in self.want:
            have_acl = self._find_have(want_acl["name"])
            if have_acl is None:
                self.diff_create.append(want_acl)
                self.result["diff"][0]["replaced"].append(want_acl["name"])
            elif not self._acls_equal(have_acl, want_acl):
                self.diff_replace.append(want_acl)
                self.result["diff"][0]["replaced"].append(want_acl["name"])

    def get_diff_deleted(self):
        targets = self.want if self.want else self.have
        for acl in targets:
            if self._find_have(acl["name"]) is not None:
                self.diff_delete.append(acl["name"])
                self.result["diff"][0]["deleted"].append(acl["name"])

    def get_diff_query(self):
        if not self.want:
            self.diff_query = list(self.have)
            self.result["diff"][0]["query"] = [a["name"] for a in self.have]
        else:
            for want_acl in self.want:
                have_acl = self._find_have(want_acl["name"])
                if have_acl is not None:
                    self.diff_query.append(have_acl)
                    self.result["diff"][0]["query"].append(want_acl["name"])

    # -------------------------------------------------------------------------
    # API write operations
    # -------------------------------------------------------------------------

    def _create_acl(self, acl):
        path = _ACL_LIST_PATH.format(self.fabric)
        data = {"accessControlLists": [self._acl_to_api(acl)]}
        resp = self.nd.request(path, method="POST", data=data)
        self.result["response"].append(deepcopy(resp) if resp else {})
        # Inspect per-item statuses returned in 207 Multi-Status responses
        if resp:
            items = resp.get("accessControlLists", resp if isinstance(resp, list) else [])
            for item in items:
                if isinstance(item, dict) and item.get("statusCode", 200) >= 400:
                    self.nd.fail_json(
                        "Failed to create ACL '{0}': {1}".format(acl["name"], item)
                    )

    def _update_acl(self, acl):
        path = _ACL_ITEM_PATH.format(self.fabric, acl["name"])
        resp = self.nd.request(path, method="PUT", data=self._acl_to_api(acl))
        self.result["response"].append(deepcopy(resp) if resp else {})

    def _delete_acl(self, acl_name):
        path = _ACL_ITEM_PATH.format(self.fabric, acl_name)
        resp = self.nd.request(path, method="DELETE", ignore_not_found_error=True)
        self.result["response"].append(deepcopy(resp) if resp else {})

    # -------------------------------------------------------------------------
    # Main execution
    # -------------------------------------------------------------------------

    def push_to_nd(self):
        """Apply diffs to ND (skipped in check mode)."""
        if self.nd.module.check_mode:
            self.result["changed"] = bool(
                self.diff_create or self.diff_replace or self.diff_delete
            )
            return

        for acl in self.diff_create:
            self._create_acl(acl)
            self.result["changed"] = True

        for acl in self.diff_replace:
            self._update_acl(acl)
            self.result["changed"] = True

        for acl_name in self.diff_delete:
            self._delete_acl(acl_name)
            self.result["changed"] = True

    def run(self):
        """Execute the full module workflow and return the result dict."""
        self._check_nd_version()
        self.validate_input()
        self.get_have()
        self.get_want()

        if self.state == "merged":
            self.get_diff_merged()
        elif self.state == "replaced":
            self.get_diff_replaced()
        elif self.state == "deleted":
            self.get_diff_deleted()
        elif self.state == "query":
            self.get_diff_query()
            self.result["acls"] = self.diff_query
            return self.result

        self.push_to_nd()
        return self.result


def main():
    entry_spec = dict(
        sequence_number=dict(type="int", required=True),
        action=dict(type="str", required=True, choices=["permit", "deny", "remark"]),
        remark_comment=dict(type="str"),
        protocol=dict(
            type="str",
            choices=["ip", "ipv6", "tcp", "udp", "icmp", "igmp", "eigrp", "ospf", "pim", "ahp", "gre", "nos", "esp", "custom"],
        ),
        custom_protocol=dict(type="int"),
        src=dict(type="str"),
        dst=dict(type="str"),
        src_port_action=dict(
            type="str",
            default="none",
            choices=["none", "equal_to", "greater_than", "less_than", "not_equal_to", "port_range"],
        ),
        src_port=dict(type="int"),
        src_port_range_start=dict(type="int"),
        src_port_range_end=dict(type="int"),
        dst_port_action=dict(
            type="str",
            default="none",
            choices=["none", "equal_to", "greater_than", "less_than", "not_equal_to", "port_range"],
        ),
        dst_port=dict(type="int"),
        dst_port_range_start=dict(type="int"),
        dst_port_range_end=dict(type="int"),
        icmp_option=dict(type="str"),
        tcp_option=dict(type="str"),
    )

    acl_spec = dict(
        name=dict(type="str", required=True),
        type=dict(type="str", choices=["ipv4", "ipv6"]),
        entries=dict(type="list", elements="dict", default=[], options=entry_spec),
    )

    argument_spec = nd_argument_spec()
    argument_spec.update(
        fabric=dict(type="str", required=True),
        state=dict(type="str", default="merged", choices=["merged", "replaced", "deleted", "query"]),
        config=dict(type="list", elements="dict", default=[], options=acl_spec),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    nd = NDModule(module)

    nd_acl = NdAcl(
        nd=nd,
        fabric=module.params["fabric"],
        state=module.params["state"],
        config=deepcopy(module.params.get("config", [])),
    )

    result = nd_acl.run()
    module.exit_json(**result)


if __name__ == "__main__":
    main()
