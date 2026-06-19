# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""ND Network validation action plugin for integration tests."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: _nd_network_validate
short_description: Validate ND Networks in integration tests
version_added: "1.0.0"
description:
  - Integration-test helper for validating Network data returned by C(cisco.nd.nd_manage_networks)
    or C(cisco.nd.nd_rest).
  - Expected entries are matched by Network name and compared only for fields
    provided in C(test_data) and known to this helper.
author:
  - Akshayanat C S (@achengam)
options:
  nd_data:
    description:
      - Registered result from a C(cisco.nd.nd_manage_networks) or C(cisco.nd.nd_rest) task.
    type: dict
    required: true
  test_data:
    description:
      - Expected Network entry or list of Network entries.
    type: raw
    required: true
  changed:
    description:
      - Optional assertion that the upstream task changed data.
      - When provided as C(false), validation fails immediately.
    type: bool
    required: false
  present:
    description:
      - Whether the expected Networks must be present or absent.
    type: bool
    default: true
"""

EXAMPLES = r"""
- name: Validate Networks in integration tests
  cisco.nd.tests.integration._nd_network_validate:
    nd_data: "{{ gathered_result }}"
    test_data:
      - network_name: ansible-nd-net-int1
        network_id: 30001

- name: Validate Network removal
  cisco.nd.tests.integration._nd_network_validate:
    nd_data: "{{ gathered_result }}"
    test_data:
      - network_name: ansible-nd-net-int1
    present: false
"""

RETURN = r"""
failed:
  description: Whether validation failed.
  type: bool
  returned: always
msg:
  description: Validation result message.
  type: str
  returned: always
missing_networks:
  description: Expected Network names not found in the ND response.
  type: list
  elements: str
  returned: on validation failure
unexpected_networks:
  description: Network names found when C(present=false).
  type: list
  elements: str
  returned: on validation failure
field_mismatches:
  description: Expected fields that did not match live data.
  type: dict
  returned: on validation failure
"""

import json
from typing import Any

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()


FIELD_PATHS = {
    "network_name": (("network_name",), ("net_name",), ("networkName",), ("parent", "networkName")),
    "net_name": (("network_name",), ("networkName",), ("parent", "networkName")),
    "network_id": (
        ("network_id",),
        ("net_id",),
        ("networkId",),
        ("l2_data", "networkId"),
        ("l2Data", "networkId"),
        ("l3_data", "networkId"),
        ("l3Data", "networkId"),
    ),
    "net_id": (("network_id",), ("networkId",), ("l2_data", "networkId"), ("l2Data", "networkId"), ("l3_data", "networkId"), ("l3Data", "networkId")),
    "network_type": (("network_type",), ("networkType",), ("parent", "networkType")),
    "layer": (("layer",), ("networkMode",), ("parent", "networkMode")),
    "vrf_name": (("vrf_name",), ("vrfName",), ("parent", "vrfName")),
    "vlan_id": (("vlan_id",), ("vlanId",), ("l2_data", "vlanId"), ("l2Data", "vlanId"), ("l3_data", "vlanId"), ("l3Data", "vlanId")),
    "vlan_name": (
        ("vlan_name",),
        ("vlanName",),
        ("l2_data", "vlan_name"),
        ("l2_data", "vlanName"),
        ("l2Data", "vlanName"),
        ("l3_data", "vlan_name"),
        ("l3_data", "vlanName"),
        ("l3Data", "vlanName"),
    ),
    "gateway_ipv4_address": (
        ("gateway_ipv4_address",),
        ("gatewayIpv4Address",),
        ("l3_data", "gatewayIpv4Address"),
        ("l3Data", "gatewayIpv4Address"),
    ),
    "gateway_ipv6_address": (
        ("gateway_ipv6_address",),
        ("gatewayIpv6Address",),
        ("l3_data", "gatewayIpv6Address"),
        ("l3Data", "gatewayIpv6Address"),
    ),
    "secondary_gateway_ipv4_collection": (
        ("secondary_gateway_ipv4_collection",),
        ("secondaryGatewayIpv4Collection",),
        ("l3_data", "secondaryGatewayIpv4Collection"),
        ("l3Data", "secondaryGatewayIpv4Collection"),
    ),
    "vlan_intf_desc": (
        ("vlan_intf_desc",),
        ("vlanIntfDesc",),
        ("l3_data", "vlan_intf_desc"),
        ("l3_data", "vlanIntfDesc"),
        ("l3Data", "vlanIntfDesc"),
    ),
    "mtu": (("mtu",), ("l3_data", "mtu"), ("l3Data", "mtu")),
    "arp_suppression": (
        ("arp_suppression",),
        ("arpSuppression",),
        ("l3_data", "arp_suppression"),
        ("l3_data", "arpSuppression"),
        ("l3Data", "arpSuppression"),
    ),
    "routing_tag": (("routing_tag",), ("routingTag",), ("l3_data", "routing_tag"), ("l3_data", "routingTag"), ("l3Data", "routingTag")),
    "rt_auto": (
        ("rt_auto",),
        ("rtAuto",),
        ("l2_data", "rt_auto"),
        ("l2_data", "rtAuto"),
        ("l2Data", "rtAuto"),
        ("l3_data", "rt_auto"),
        ("l3_data", "rtAuto"),
        ("l3Data", "rtAuto"),
    ),
    "enable_ir": (
        ("enable_ir",),
        ("enableIr",),
        ("l2_data", "fabric_data", "enable_ir"),
        ("l2_data", "fabricData", "enableIr"),
        ("l2Data", "fabricData", "enableIr"),
    ),
    "multicast_group_address": (
        ("multicast_group_address",),
        ("multicastGroup"),
        ("l2_data", "fabric_data", "multicast_group"),
        ("l2_data", "fabricData", "multicastGroup"),
        ("l2Data", "fabricData", "multicastGroup"),
    ),
    "trm_enable": (
        ("trm_enable",),
        ("ipv4Trm",),
        ("l3_data", "fabric_data", "ipv4_trm"),
        ("l3_data", "fabricData", "ipv4Trm"),
        ("l3Data", "fabricData", "ipv4Trm"),
    ),
    "ipv6_trm": (
        ("ipv6_trm",),
        ("ipv6Trm",),
        ("l3_data", "fabric_data", "ipv6_trm"),
        ("l3_data", "fabricData", "ipv6Trm"),
        ("l3Data", "fabricData", "ipv6Trm"),
    ),
    "netflow_enable": (
        ("netflow_enable",),
        ("netflow"),
        ("l3_data", "fabric_data", "netflow"),
        ("l3_data", "fabricData", "netflow"),
        ("l3Data", "fabricData", "netflow"),
    ),
    "gateway_on_border": (
        ("gateway_on_border",),
        ("gatewayOnBorder"),
        ("l3_data", "fabric_data", "gateway_on_border"),
        ("l3_data", "fabricData", "gatewayOnBorder"),
        ("l3Data", "fabricData", "gatewayOnBorder"),
    ),
}

IGNORED_EXPECTED_FIELDS = {
    "attach",
    "child_fabric_config",
    "deploy",
    "deploy_type",
    "is_l2only",
    "network_template_config",
}


def _get_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _first_value(data: dict[str, Any], field: str) -> Any:
    for path in FIELD_PATHS.get(field, ((field,),)):
        value = _get_path(data, path)
        if value is not None:
            return value
    return None


def _network_name(data: dict[str, Any]) -> str | None:
    value = _first_value(data, "network_name")
    return str(value) if value is not None else None


def _is_network_record(data: Any) -> bool:
    return isinstance(data, dict) and _network_name(data) is not None


def _extract_records(data: Any) -> list[dict[str, Any]]:
    if data is None:
        return []

    if isinstance(data, list):
        records: list[dict[str, Any]] = []
        for item in data:
            records.extend(_extract_records(item))
        return records

    if not isinstance(data, dict):
        return []

    if _is_network_record(data):
        return [data]

    for key in ("gathered", "after", "networks", "items", "results"):
        if key in data:
            records = _extract_records(data.get(key))
            if records:
                return records

    current = data.get("current")
    if isinstance(current, dict):
        for key in ("networks", "items", "results"):
            records = _extract_records(current.get(key))
            if records:
                return records
    elif isinstance(current, list):
        records = _extract_records(current)
        if records:
            return records

    for key in ("parent", "children", "response", "result", "DATA"):
        if key in data:
            records = _extract_records(data.get(key))
            if records:
                return records

    return []


def _normalize_expected(test_data: Any) -> list[dict[str, Any]]:
    if isinstance(test_data, dict):
        return [test_data]
    if isinstance(test_data, list):
        return test_data
    return []


def _values_equal(expected: Any, actual: Any) -> bool:
    if isinstance(expected, list):
        return sorted(str(item) for item in expected) == sorted(str(item) for item in (actual or []))
    if isinstance(expected, bool):
        return actual is expected
    if isinstance(actual, bool):
        return expected is actual
    return str(expected) == str(actual)


class ActionModule(ActionBase):
    """Validate Network records from ND integration tests."""

    def run(
        self,
        tmp: Any = None,
        task_vars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        results = super().run(tmp, task_vars)
        results["failed"] = False

        args = self._task.args
        nd_data = args.get("nd_data")
        test_data = _normalize_expected(args.get("test_data"))
        present = args.get("present", True)

        if "changed" in args and not args["changed"]:
            results["failed"] = True
            results["msg"] = 'Changed is "false"'
            return results

        if isinstance(nd_data, dict) and nd_data.get("failed"):
            results["failed"] = True
            results["msg"] = nd_data.get("msg", "ND module returned a failure")
            return results

        records = _extract_records(nd_data)
        live_by_name = {name: record for record in records if (name := _network_name(record))}
        expected_names = [_first_value(entry, "network_name") for entry in test_data]
        expected_names = [str(name) for name in expected_names if name is not None]

        if not present:
            unexpected = [name for name in expected_names if name in live_by_name]
            if unexpected:
                results["failed"] = True
                results["msg"] = "Validation Failed! Expected Networks are still present."
                results["unexpected_networks"] = unexpected
                return results
            results["msg"] = "Validation Successful!"
            return results

        missing = [name for name in expected_names if name not in live_by_name]
        if missing:
            results["failed"] = True
            results["msg"] = "Validation Failed! Expected Networks were not found."
            results["missing_networks"] = missing
            results["available_networks"] = sorted(live_by_name)
            return results

        mismatches: dict[str, dict[str, dict[str, Any]]] = {}
        for expected in test_data:
            name = str(_first_value(expected, "network_name"))
            live = live_by_name[name]
            for field in FIELD_PATHS:
                if field in IGNORED_EXPECTED_FIELDS:
                    continue
                expected_value = _first_value(expected, field)
                if expected_value is None:
                    continue
                actual_value = _first_value(live, field)
                if not _values_equal(expected_value, actual_value):
                    mismatches.setdefault(name, {})[field] = {
                        "expected": expected_value,
                        "actual": actual_value,
                    }

        if mismatches:
            display.display("Network field mismatches:")
            display.display(json.dumps(mismatches, indent=2, sort_keys=True))
            results["failed"] = True
            results["msg"] = "Validation Failed! Please check output above."
            results["field_mismatches"] = mismatches
            return results

        results["msg"] = "Validation Successful!"
        return results
