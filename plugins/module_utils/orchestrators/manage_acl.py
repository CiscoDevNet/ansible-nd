# Copyright: (c) 2026, Slawomir Kaszlikowski

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import re
from copy import deepcopy
from typing import Any, ClassVar, Dict, List, Optional, Type

from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_acl import (
    EpManageAclDelete,
    EpManageAclGet,
    EpManageAclPost,
    EpManageAclPut,
    EpManageAclsGet,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.acl.acl import AclModel
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.types import ResponseType

# --- Field-name mapping tables ---

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


class ManageAclOrchestrator(NDBaseOrchestrator[AclModel]):
    """
    Orchestrator for Access Control List (ACL) resources on Nexus Dashboard.

    This API uses the following pattern:
    - List: GET returns {"accessControlLists": [...]} or bare list
    - Create: POST with {"accessControlLists": [...]} body, returns 207 Multi-Status
    - Get: GET single ACL by name
    - Update: PUT single ACL (replaces fully or entry-merged)
    - Delete: DELETE single ACL

    Supports states: merged (entry-level merge), replaced (full replace),
    deleted (whole ACL), gathered (query only).
    """

    model_class: ClassVar[Type[NDBaseModel]] = AclModel

    # Endpoint bindings (required by NDBaseOrchestrator)
    create_endpoint: Type[NDEndpointBaseModel] = EpManageAclPost
    update_endpoint: Type[NDEndpointBaseModel] = EpManageAclPut
    delete_endpoint: Type[NDEndpointBaseModel] = EpManageAclDelete
    query_one_endpoint: Type[NDEndpointBaseModel] = EpManageAclGet
    query_all_endpoint: Type[NDEndpointBaseModel] = EpManageAclsGet

    # Fabric scope injected at orchestrator construction time
    fabric_name: str = ""

    # -------------------------------------------------------------------------
    # Entry / ACL conversion helpers
    # -------------------------------------------------------------------------

    def _entry_to_api(self, entry: Dict[str, Any]) -> Dict[str, Any]:
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

    def _entry_from_api(self, api_entry: Dict[str, Any]) -> Dict[str, Any]:
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

    def _acl_to_api(self, acl: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ACL dict from Ansible format to API format."""
        return {
            "name": acl["name"],
            "type": acl["type"],
            "entries": [self._entry_to_api(e) for e in acl.get("entries", [])],
        }

    def _acl_from_api(self, api_acl: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ACL dict from API format to Ansible format."""
        return {
            "name": api_acl["name"],
            "type": api_acl["type"],
            "description": api_acl.get("description", ""),
            "entries": [self._entry_from_api(e) for e in api_acl.get("entries", [])],
        }

    def _process_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize an entry from module params, stripping argspec-injected
        defaults (e.g. src_port_action="none") so they don't trigger false diffs.
        """
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
    # Input validation
    # -------------------------------------------------------------------------

    def validate_config(self, state: str, config: List[Dict]) -> None:
        """Validate the playbook configuration. Raises ValueError on error."""
        if not config and state in ("merged", "replaced"):
            raise ValueError("config is required when state is '{0}'".format(state))

        for acl in config:
            name = acl.get("name", "")
            if not re.match(r"^[a-zA-Z0-9_-]+$", name):
                raise ValueError(
                    "ACL name '{0}' is invalid. Only alphanumeric characters, "
                    "underscores, and hyphens are allowed.".format(name)
                )
            if len(name) > 63:
                raise ValueError(
                    "ACL name '{0}' exceeds the maximum length of 63 characters.".format(name)
                )
            if state in ("merged", "replaced") and not acl.get("type"):
                raise ValueError(
                    "ACL '{0}': 'type' is required when state is '{1}'".format(name, state)
                )
            for entry in acl.get("entries", []):
                self._validate_entry(name, entry)

    def _validate_entry(self, acl_name: str, entry: Dict[str, Any]) -> None:
        """Validate semantic correctness of a single ACL entry."""
        action = entry.get("action")
        seq_num = entry.get("sequence_number")

        if action == "remark":
            if not entry.get("remark_comment"):
                raise ValueError(
                    "ACL '{0}' entry {1}: 'remark_comment' is required for remark entries".format(acl_name, seq_num)
                )
            return

        for field in ("protocol", "src", "dst"):
            if not entry.get(field):
                raise ValueError(
                    "ACL '{0}' entry {1}: '{2}' is required for permit/deny entries".format(acl_name, seq_num, field)
                )

        protocol = entry.get("protocol")
        if protocol == "custom" and entry.get("custom_protocol") is None:
            raise ValueError(
                "ACL '{0}' entry {1}: 'custom_protocol' is required when protocol is 'custom'".format(acl_name, seq_num)
            )

        if protocol in ("tcp", "udp"):
            self._validate_port_options(acl_name, entry, "src")
            self._validate_port_options(acl_name, entry, "dst")

        if entry.get("icmp_option") and protocol != "icmp":
            raise ValueError(
                "ACL '{0}' entry {1}: 'icmp_option' is only valid for icmp protocol".format(acl_name, seq_num)
            )
        if entry.get("tcp_option") and protocol != "tcp":
            raise ValueError(
                "ACL '{0}' entry {1}: 'tcp_option' is only valid for tcp protocol".format(acl_name, seq_num)
            )

    def _validate_port_options(self, acl_name: str, entry: Dict[str, Any], prefix: str) -> None:
        """Validate port action and range consistency for a given direction."""
        seq_num = entry.get("sequence_number")
        port_action = entry.get("{0}_port_action".format(prefix))

        if not port_action or port_action == "none":
            return

        if port_action == "port_range":
            start = entry.get("{0}_port_range_start".format(prefix))
            end = entry.get("{0}_port_range_end".format(prefix))
            if start is None or end is None:
                raise ValueError(
                    "ACL '{0}' entry {1}: '{2}_port_range_start' and '{2}_port_range_end' "
                    "are required when {2}_port_action is 'port_range'".format(acl_name, seq_num, prefix)
                )
            if start > end:
                raise ValueError(
                    "ACL '{0}' entry {1}: '{2}_port_range_start' must be less than or equal "
                    "to '{2}_port_range_end'".format(acl_name, seq_num, prefix)
                )
        else:
            if entry.get("{0}_port".format(prefix)) is None:
                raise ValueError(
                    "ACL '{0}' entry {1}: '{2}_port' is required when {2}_port_action "
                    "is '{3}'".format(acl_name, seq_num, prefix, port_action)
                )

    # -------------------------------------------------------------------------
    # Current state retrieval
    # -------------------------------------------------------------------------

    def query_all(self, model_instance=None, **kwargs) -> ResponseType:
        """Fetch all ACLs for the fabric and return as a list of API dicts."""
        try:
            ep = self.query_all_endpoint()
            ep.fabric_name = self.fabric_name
            result = self._request(path=ep.path, verb=ep.verb, not_found_ok=True)
            if not result:
                return []
            if isinstance(result, dict):
                return result.get("accessControlLists", []) or []
            if isinstance(result, list):
                return result
            return []
        except Exception as e:
            raise Exception("Query all ACLs failed: {0}".format(e)) from e

    def _get_all_acls(self) -> List[Dict[str, Any]]:
        """Return current ACLs as Ansible-format dicts."""
        return [self._acl_from_api(a) for a in (self.query_all() or [])]

    # -------------------------------------------------------------------------
    # Diff helpers
    # -------------------------------------------------------------------------

    def _find_have(self, name: str, have: List[Dict]) -> Optional[Dict]:
        """Return the existing ACL with the given name, or None."""
        for acl in have:
            if acl["name"] == name:
                return acl
        return None

    def _entries_equal(self, e1: Dict, e2: Dict) -> bool:
        fields = [
            "sequence_number", "action", "protocol", "src", "dst",
            "remark_comment", "custom_protocol",
            "src_port_action", "src_port", "src_port_range_start", "src_port_range_end",
            "dst_port_action", "dst_port", "dst_port_range_start", "dst_port_range_end",
            "icmp_option", "tcp_option",
        ]
        return all(e1.get(f) == e2.get(f) for f in fields)

    def _acls_equal(self, acl1: Dict, acl2: Dict) -> bool:
        if acl1["name"] != acl2["name"] or acl1.get("type") != acl2.get("type"):
            return False
        entries1 = {e["sequence_number"]: e for e in acl1.get("entries", [])}
        entries2 = {e["sequence_number"]: e for e in acl2.get("entries", [])}
        if set(entries1) != set(entries2):
            return False
        return all(self._entries_equal(entries1[s], entries2[s]) for s in entries1)

    def _merge_entries(self, have_acl: Dict, want_acl: Dict) -> Dict:
        """
        Return a new ACL whose entries are have merged with want.
        Want wins on sequence-number conflicts; unmatched have entries are preserved.
        """
        have_entries = {e["sequence_number"]: e for e in have_acl.get("entries", [])}
        want_entries = {e["sequence_number"]: e for e in want_acl.get("entries", [])}
        merged_seqs = sorted(set(have_entries) | set(want_entries))
        return {
            "name": want_acl["name"],
            "type": want_acl.get("type", have_acl.get("type")),
            "entries": [want_entries[s] if s in want_entries else have_entries[s] for s in merged_seqs],
        }

    def _build_want(self, config: List[Dict]) -> List[Dict]:
        """Build the desired-state list from module params (processes entries)."""
        result = []
        for acl in config:
            want_acl = {"name": acl["name"]}
            if acl.get("type"):
                want_acl["type"] = acl["type"]
            want_acl["entries"] = [self._process_entry(e) for e in acl.get("entries", [])]
            result.append(want_acl)
        return result

    # -------------------------------------------------------------------------
    # API write helpers
    # -------------------------------------------------------------------------

    def _create_acl(self, acl: Dict) -> Dict:
        ep = self.create_endpoint()
        ep.fabric_name = self.fabric_name
        data = {"accessControlLists": [self._acl_to_api(acl)]}
        result = self._request(path=ep.path, verb=ep.verb, data=data)
        if result:
            items = result.get("accessControlLists", result if isinstance(result, list) else [])
            for item in items:
                if isinstance(item, dict) and item.get("statusCode", 200) >= 400:
                    raise Exception("Failed to create ACL '{0}': {1}".format(acl["name"], item))
        return result or {}

    def _update_acl(self, acl: Dict) -> Dict:
        ep = self.update_endpoint()
        ep.fabric_name = self.fabric_name
        ep.acl_name = acl["name"]
        return self._request(path=ep.path, verb=ep.verb, data=self._acl_to_api(acl)) or {}

    def _delete_acl(self, acl_name: str) -> Dict:
        ep = self.delete_endpoint()
        ep.fabric_name = self.fabric_name
        ep.acl_name = acl_name
        return self._request(path=ep.path, verb=ep.verb, not_found_ok=True) or {}

    # -------------------------------------------------------------------------
    # State execution
    # -------------------------------------------------------------------------

    def run(self, state: str, config: List[Dict], check_mode: bool = False) -> Dict:
        """
        Execute the full module workflow for the given state and return the
        result dict ready to pass to module.exit_json().
        """
        self.validate_config(state, config)

        have = self._get_all_acls()
        want = self._build_want(config)

        result = dict(
            changed=False,
            diff=[{"merged": [], "replaced": [], "deleted": [], "gathered": []}],
            response=[],
            acls=[],
        )

        if state == "gathered":
            self._run_gathered(have, want, result)
            return result

        # Build diffs
        diff_create: List[Dict] = []
        diff_replace: List[Dict] = []
        diff_delete: List[str] = []

        if state == "merged":
            for want_acl in want:
                have_acl = self._find_have(want_acl["name"], have)
                if have_acl is None:
                    diff_create.append(want_acl)
                    result["diff"][0]["merged"].append(want_acl["name"])
                else:
                    merged = self._merge_entries(have_acl, want_acl)
                    if not self._acls_equal(have_acl, merged):
                        diff_replace.append(merged)
                        result["diff"][0]["merged"].append(want_acl["name"])

        elif state == "replaced":
            for want_acl in want:
                have_acl = self._find_have(want_acl["name"], have)
                if have_acl is None:
                    diff_create.append(want_acl)
                    result["diff"][0]["replaced"].append(want_acl["name"])
                elif not self._acls_equal(have_acl, want_acl):
                    diff_replace.append(want_acl)
                    result["diff"][0]["replaced"].append(want_acl["name"])

        elif state == "deleted":
            targets = want if want else have
            for acl in targets:
                if self._find_have(acl["name"], have) is not None:
                    diff_delete.append(acl["name"])
                    result["diff"][0]["deleted"].append(acl["name"])

        result["changed"] = bool(diff_create or diff_replace or diff_delete)

        if check_mode:
            return result

        for acl in diff_create:
            resp = self._create_acl(acl)
            result["response"].append(deepcopy(resp))

        for acl in diff_replace:
            resp = self._update_acl(acl)
            result["response"].append(deepcopy(resp))

        for acl_name in diff_delete:
            resp = self._delete_acl(acl_name)
            result["response"].append(deepcopy(resp))

        return result

    def _run_gathered(self, have: List[Dict], want: List[Dict], result: Dict) -> None:
        """Populate result with gathered ACL data (no changes)."""
        if not want:
            result["acls"] = list(have)
            result["diff"][0]["gathered"] = [a["name"] for a in have]
        else:
            for want_acl in want:
                have_acl = self._find_have(want_acl["name"], have)
                if have_acl is not None:
                    result["acls"].append(have_acl)
                    result["diff"][0]["gathered"].append(want_acl["name"])
