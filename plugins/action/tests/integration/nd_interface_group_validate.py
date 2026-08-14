# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Validate live Nexus Dashboard Interface Group state in integration tests.

The plugin is intentionally read-only.  It accepts the result of
``cisco.nd.nd4x_module_test`` or ``cisco.nd.nd_rest``, normalizes module,
flattened, and ``interfaceGroupAssociation`` response shapes, and compares the
result with playbook-facing module input.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

DOCUMENTATION = r"""
---
module: nd_interface_group_validate
short_description: Validate live Interface Group state in ND integration tests
version_added: "2.0.0"
description:
- Provides read-only, module-specific assertions for Interface Group integration tests.
- Normalizes shared test-runner output and direct Interface Group read responses.
- This is an integration-test helper and is not part of the public Interface Groups
  module interface.
author:
- L Nikhil Sri Krishna (@nisaikri)
options:
  nd_data:
    description:
    - Registered result from C(cisco.nd.nd4x_module_test) or C(cisco.nd.nd_rest).
    type: raw
    required: true
  test_data:
    description:
    - Expected Interface Groups in C(nd_manage_interface_group) input shape.
    type: list
    elements: dict
  absent:
    description:
    - Interface Group names that must not be present.
    type: list
    elements: raw
  mode:
    description:
    - C(subset) requires supplied networks and members to be present.
    - C(exact) requires supplied network and member collections to match exactly.
    type: str
    default: subset
    choices: [subset, exact]
  scope_prefix:
    description:
    - Restrict validation and invariants to Interface Group names with this prefix.
    type: str
  vpc_peer_switch_ids:
    description:
    - Optional mapping of vPC peer switch IDs used to compare vPC members when
      Nexus Dashboard reports the logical vPC interface under the opposite peer.
    - Ethernet and port-channel members continue to require an exact switch-ID match.
    type: dict
  invariants:
    description:
    - Optional cross-group assertions such as counts, required types, and unique membership.
    type: dict
notes:
- The plugin does not mutate Nexus Dashboard state.
"""

EXAMPLES = r"""
- name: Fetch one Interface Group
  cisco.nd.nd_rest:
    method: GET
    path: /api/v1/manage/fabrics/FABRIC-1/interfaceGroups/ANSIBLE-IG-PC
  register: interface_group_live

- name: Validate exact association state
  cisco.nd.tests.integration.nd_interface_group_validate:
    nd_data: "{{ interface_group_live }}"
    mode: exact
    test_data:
      - interface_group_name: ANSIBLE-IG-PC
        type: portChannel
        networks:
          - Network-A
        switch_interfaces:
          - switch_id: FDO12345678
            interface_names:
              - Port-channel501
"""

RETURN = r"""
changed:
  description: Always C(false), because validation is read-only.
  returned: always
  type: bool
groups:
  description: Normalized Interface Groups considered by the validation.
  returned: always
  type: list
  elements: dict
report:
  description: Structured missing, mismatch, absence, and invariant results.
  returned: always
  type: dict
"""

from typing import Any, Dict, Iterable, List, Set, Tuple

from ansible.plugins.action import ActionBase
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)

_GROUP_LIST_KEYS = (
    "interfaceGroupDetails",
    "interface_group_details",
    "interfaceGroups",
    "interface_groups",
)
_SUPPORTED_MODES = frozenset({"subset", "exact"})
_SUPPORTED_ARGUMENTS = frozenset(
    {
        "nd_data",
        "test_data",
        "absent",
        "mode",
        "scope_prefix",
        "vpc_peer_switch_ids",
        "invariants",
    }
)
_SUPPORTED_INVARIANTS = frozenset(
    {
        "total_count",
        "min_count",
        "max_count",
        "required_types",
        "unique_group_names",
        "unique_members",
        "consistent_counts",
    }
)
_ETHERNET_ATTRIBUTE_KEYS = {
    "adminState": "admin_state",
    "allowedVlans": "allowed_vlans",
    "autoNegotiate": "auto_negotiate",
    "bpduGuard": "bpdu_guard",
    "duplexMode": "duplex_mode",
    "extraConfig": "extra_config",
    "nativeVlan": "native_vlan",
    "netflowMonitor": "netflow_monitor",
    "netflowSampler": "netflow_sampler",
    "orphanPort": "orphan_port",
    "portTypeEdge": "port_type_edge",
    "portTypeEdgeTrunk": "port_type_edge_trunk",
}


def _first(data: Dict[str, Any], *names: str) -> Tuple[Any, bool]:
    """Return the first present alias and whether an alias was present."""
    for name in names:
        if name in data:
            return data[name], True
    return None, False


def _normalise_string_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return sorted({str(item) for item in value})


def _normalise_members(value: Any) -> Dict[str, List[str]]:
    """Normalize switch/interface associations as an order-insensitive map."""
    members: Dict[str, Set[str]] = {}
    if not isinstance(value, list):
        return {}
    for item in value:
        if not isinstance(item, dict):
            continue
        switch_id, _present = _first(item, "switch_id", "switchId")
        interface_names, _present = _first(item, "interface_names", "interfaceNames")
        if switch_id is None:
            continue
        members.setdefault(str(switch_id), set()).update(
            InterfaceGroupValidators.normalize_interface_name(interface_name) for interface_name in _normalise_string_list(interface_names)
        )
    return {switch_id: sorted(interface_names) for switch_id, interface_names in sorted(members.items())}


def _normalise_vpc_peer_switch_ids(value: Any) -> Dict[str, str]:
    """Validate and symmetrize the optional vPC peer switch-ID mapping."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("vpc_peer_switch_ids must be a dictionary")

    peers: Dict[str, str] = {}
    for raw_switch_id, raw_peer_id in value.items():
        if not isinstance(raw_switch_id, str) or not raw_switch_id.strip():
            raise ValueError("vpc_peer_switch_ids keys must be non-empty strings")
        if not isinstance(raw_peer_id, str) or not raw_peer_id.strip():
            raise ValueError("vpc_peer_switch_ids values must be non-empty strings")
        switch_id = raw_switch_id.strip()
        peer_id = raw_peer_id.strip()
        if switch_id == peer_id:
            raise ValueError("vpc_peer_switch_ids cannot map a switch to itself")
        if switch_id in peers and peers[switch_id] != peer_id:
            raise ValueError("vpc_peer_switch_ids contains conflicting peers for {0}".format(switch_id))
        if peer_id in peers and peers[peer_id] != switch_id:
            raise ValueError("vpc_peer_switch_ids contains conflicting peers for {0}".format(peer_id))
        peers[switch_id] = peer_id
        peers[peer_id] = switch_id
    return peers


def _canonicalise_vpc_member_switch_ids(members: Dict[str, List[str]], vpc_peer_switch_ids: Dict[str, str]) -> Dict[str, List[str]]:
    """Canonicalize only vPC member switch IDs across a confirmed peer pair."""
    canonical: Dict[str, Set[str]] = {}
    for switch_id, interface_names in members.items():
        for interface_name in interface_names:
            canonical_switch_id = switch_id
            if InterfaceGroupValidators.interface_kind(interface_name) == "vpc":
                peer_id = vpc_peer_switch_ids.get(switch_id)
                if peer_id is not None:
                    canonical_switch_id = min(switch_id, peer_id)
            canonical.setdefault(canonical_switch_id, set()).add(interface_name)
    return {switch_id: sorted(interface_names) for switch_id, interface_names in sorted(canonical.items())}


def _normalise_ethernet_attributes(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    normalized = {_ETHERNET_ATTRIBUTE_KEYS.get(key, key): item for key, item in value.items()}
    if "allowed_vlans" in normalized:
        normalized["allowed_vlans"] = InterfaceGroupValidators.normalize_allowed_vlans(normalized["allowed_vlans"])
    return normalized


def _normalise_group(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Project API or module-shaped input into a stable comparison shape."""
    raw = InterfaceGroupValidators.normalize_response_group(raw)
    association, _present = _first(raw, "interfaceGroupAssociation", "interface_group_association")
    if not isinstance(association, dict):
        association = {}

    canonical: Dict[str, Any] = {"_fields": set()}
    aliases = {
        "interface_group_name": ("interface_group_name", "interfaceGroupName"),
        "type": ("type",),
        "description": ("description",),
        "networks": ("networks", "networkNames"),
        "switch_interfaces": ("switch_interfaces", "switchInterfaces"),
        "template_name": ("template_name", "templateName"),
        "template_config": ("template_config", "templateConfig"),
        "ethernet_attributes": ("ethernet_attributes", "ethernetAttributes"),
        "interface_count": ("interface_count", "interfaceCount"),
        "network_count": ("network_count", "networkCount"),
    }

    for field_name, field_aliases in aliases.items():
        value, present = _first(raw, *field_aliases)
        if not present and field_name in {"networks", "switch_interfaces"} and association:
            value, present = _first(association, *field_aliases)
        if not present:
            continue
        canonical["_fields"].add(field_name)
        if field_name == "networks":
            canonical[field_name] = _normalise_string_list(value)
        elif field_name == "switch_interfaces":
            canonical[field_name] = _normalise_members(value)
        elif field_name == "ethernet_attributes":
            canonical[field_name] = _normalise_ethernet_attributes(value)
        elif field_name == "template_config":
            canonical[field_name] = value if isinstance(value, dict) else {}
        elif field_name in {"interface_count", "network_count"}:
            try:
                canonical[field_name] = int(value)
            except (TypeError, ValueError):
                canonical[field_name] = value
        elif value is not None:
            canonical[field_name] = str(value)
        else:
            canonical[field_name] = value
    return canonical


def _extract_groups(nd_data: Any) -> List[Dict[str, Any]]:
    """Extract gathered, GET-one, or list Interface Group objects."""
    node = nd_data
    if isinstance(node, dict) and "first_run_result" in node:
        node = node["first_run_result"]
    if isinstance(node, dict) and "gathered" in node:
        node = node["gathered"]
    if isinstance(node, dict) and "result" in node:
        node = node["result"]
    if isinstance(node, dict) and "current" in node:
        node = node["current"]
    if isinstance(node, list):
        return [item for item in node if isinstance(item, dict)]
    if not isinstance(node, dict):
        return []
    if "interfaceGroupName" in node or "interface_group_name" in node:
        return [node]

    groups: List[Dict[str, Any]] = []
    for key in _GROUP_LIST_KEYS:
        value = node.get(key)
        if isinstance(value, list):
            groups.extend(item for item in value if isinstance(item, dict))
    return groups


def _dict_is_subset(want: Dict[str, Any], have: Dict[str, Any]) -> bool:
    """Recursively compare explicitly expected dictionary values."""
    for key, value in want.items():
        if key not in have:
            return False
        if isinstance(value, dict) and isinstance(have[key], dict):
            if not _dict_is_subset(value, have[key]):
                return False
        elif have[key] != value:
            return False
    return True


def _compare_group(
    want: Dict[str, Any],
    have: Dict[str, Any],
    mode: str,
    vpc_peer_switch_ids: Dict[str, str],
) -> List[Dict[str, Any]]:
    """Return field-level mismatches for one expected group."""
    mismatches: List[Dict[str, Any]] = []
    for field_name in sorted(want["_fields"] - {"interface_group_name"}):
        expected = want.get(field_name)
        actual = have.get(field_name)
        compared_expected = expected
        compared_actual = actual
        if field_name == "switch_interfaces":
            compared_expected = _canonicalise_vpc_member_switch_ids(expected or {}, vpc_peer_switch_ids)
            compared_actual = _canonicalise_vpc_member_switch_ids(actual or {}, vpc_peer_switch_ids)
        matches = compared_expected == compared_actual
        if field_name == "networks" and mode == "subset":
            matches = set(expected or []) <= set(actual or [])
        elif field_name == "switch_interfaces" and mode == "subset":
            matches = all(
                set(interface_names) <= set((compared_actual or {}).get(switch_id, [])) for switch_id, interface_names in (compared_expected or {}).items()
            )
        elif field_name == "template_config":
            matches = InterfaceGroupValidators.template_config_is_subset(expected or {}, actual or {})
        elif field_name == "ethernet_attributes":
            matches = _dict_is_subset(expected or {}, actual or {})
        if not matches:
            mismatches.append(
                {
                    "interface_group_name": want.get("interface_group_name"),
                    "field": field_name,
                    "expected": expected,
                    "actual": actual,
                }
            )
    return mismatches


def _normalise_absent(absent: Any) -> List[str]:
    if absent is None:
        return []
    if isinstance(absent, (str, dict)):
        absent = [absent]
    names: List[str] = []
    for item in absent:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name, present = _first(item, "interface_group_name", "interfaceGroupName")
            if present and name is not None:
                names.append(str(name))
    return sorted(set(names))


def _check_invariants(groups: List[Dict[str, Any]], invariants: Dict[str, Any]) -> List[str]:
    unknown = sorted(set(invariants) - _SUPPORTED_INVARIANTS)
    if unknown:
        return ["unsupported invariant(s): {0}".format(", ".join(unknown))]

    failures: List[str] = []
    count = len(groups)
    if "total_count" in invariants and count != int(invariants["total_count"]):
        failures.append("expected total_count={0}, got {1}".format(invariants["total_count"], count))
    if "min_count" in invariants and count < int(invariants["min_count"]):
        failures.append("expected min_count={0}, got {1}".format(invariants["min_count"], count))
    if "max_count" in invariants and count > int(invariants["max_count"]):
        failures.append("expected max_count={0}, got {1}".format(invariants["max_count"], count))

    if invariants.get("required_types"):
        actual_types = {group.get("type") for group in groups}
        missing_types = sorted(set(invariants["required_types"]) - actual_types)
        if missing_types:
            failures.append("missing required type(s): {0}".format(", ".join(missing_types)))

    if invariants.get("unique_group_names", False):
        names = [group.get("interface_group_name") for group in groups]
        duplicates = sorted({name for name in names if name is not None and names.count(name) > 1})
        if duplicates:
            failures.append("duplicate interface group name(s): {0}".format(", ".join(duplicates)))

    if invariants.get("unique_members", False):
        owners: Dict[Tuple[str, str], List[str]] = {}
        for group in groups:
            for switch_id, interface_names in group.get("switch_interfaces", {}).items():
                for interface_name in interface_names:
                    owners.setdefault((switch_id, interface_name), []).append(group.get("interface_group_name"))
        duplicates = [
            "{0}/{1}: {2}".format(switch_id, interface_name, ", ".join(names))
            for (switch_id, interface_name), names in sorted(owners.items())
            if len(set(names)) > 1
        ]
        if duplicates:
            failures.append("members assigned to multiple groups: {0}".format("; ".join(duplicates)))

    if invariants.get("consistent_counts", False):
        for group in groups:
            group_name = group.get("interface_group_name") or "?"
            member_count = sum(len(interface_names) for interface_names in group.get("switch_interfaces", {}).values())
            network_count = len(group.get("networks", []))
            for count_name, expected in (
                ("interface_count", member_count),
                ("network_count", network_count),
            ):
                if count_name not in group.get("_fields", set()):
                    failures.append("{0} missing {1}".format(group_name, count_name))
                elif group.get(count_name) != expected:
                    failures.append(
                        "{0} expected {1}={2}, got {3}".format(
                            group_name,
                            count_name,
                            expected,
                            group.get(count_name),
                        )
                    )
    return failures


class ActionModule(ActionBase):
    """Compare Interface Group controller state with expected module input."""

    TRANSFERS_FILES = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp
        args = self._task.args or {}
        unknown_arguments = sorted(set(args) - _SUPPORTED_ARGUMENTS)
        if unknown_arguments:
            return self._fail(
                result,
                "unsupported argument(s): {0}".format(", ".join(unknown_arguments)),
            )
        nd_data = args.get("nd_data")
        if nd_data is None:
            return self._fail(result, "'nd_data' is required")
        if isinstance(nd_data, dict) and nd_data.get("failed"):
            return self._fail(
                result,
                "upstream ND query failed: {0}".format(nd_data.get("msg", "no message")),
            )

        mode = args.get("mode", "subset")
        if mode not in _SUPPORTED_MODES:
            return self._fail(result, "mode must be one of: {0}".format(", ".join(_SUPPORTED_MODES)))

        try:
            vpc_peer_switch_ids = _normalise_vpc_peer_switch_ids(args.get("vpc_peer_switch_ids"))
        except ValueError as exc:
            return self._fail(result, str(exc))

        raw_groups = _extract_groups(nd_data)
        groups = [_normalise_group(group) for group in raw_groups]
        scope_prefix = args.get("scope_prefix")
        if scope_prefix:
            groups = [group for group in groups if str(group.get("interface_group_name", "")).startswith(str(scope_prefix))]

        by_name = {group.get("interface_group_name"): group for group in groups if group.get("interface_group_name")}
        test_data = args.get("test_data") or []
        if isinstance(test_data, dict):
            test_data = [test_data]
        if not isinstance(test_data, list):
            return self._fail(result, "test_data must be a list or dictionary")

        report = {
            "missing": [],
            "mismatches": [],
            "unexpected_present": [],
            "invariant_failures": [],
        }
        for raw_want in test_data:
            if not isinstance(raw_want, dict):
                return self._fail(result, "test_data entries must be dictionaries")
            want = _normalise_group(raw_want)
            group_name = want.get("interface_group_name")
            have = by_name.get(group_name)
            if have is None:
                report["missing"].append(group_name)
                continue
            report["mismatches"].extend(_compare_group(want, have, mode, vpc_peer_switch_ids))

        absent_names = _normalise_absent(args.get("absent"))
        report["unexpected_present"] = [name for name in absent_names if name in by_name]
        invariants = args.get("invariants")
        if invariants is None:
            invariants = {}
        if not isinstance(invariants, dict):
            return self._fail(result, "invariants must be a dictionary")
        report["invariant_failures"] = _check_invariants(groups, invariants)

        failures = [value for key, value in report.items() if key != "invariant_failures" and value]
        if report["invariant_failures"]:
            failures.append(report["invariant_failures"])

        result.update(changed=False, groups=self._serialise_groups(groups), report=report)
        if failures:
            result.update(
                failed=True,
                msg="Interface Group live-state validation failed: {0}".format(report),
            )
        return result

    @staticmethod
    def _serialise_groups(groups: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        serialised = []
        for group in groups:
            item = dict(group)
            item.pop("_fields", None)
            serialised.append(item)
        return serialised

    @staticmethod
    def _fail(result: Dict[str, Any], message: str) -> Dict[str, Any]:
        result.update(changed=False, failed=True, msg=message)
        return result
