# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""ND VRF Validation Action Plugin for integration tests."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: _nd_vrf_validate
short_description: Validate ND VRFs in integration tests
version_added: "1.0.0"
description:
  - Integration-test helper for validating VRF data returned by C(cisco.nd.nd_manage_vrfs)
    or C(cisco.nd.nd_rest).
  - Expected entries are matched by VRF name and compared only for fields
    provided in C(test_data).
  - This action plugin is used by the C(nd_manage_vrfs) integration test target.
author:
  - Akshayanat C S (@achengam)
options:
  nd_data:
    description:
      - Registered result from a C(cisco.nd.nd_manage_vrfs) or C(cisco.nd.nd_rest) task.
    type: dict
    required: true
  test_data:
    description:
      - Expected VRF entry or list of VRF entries.
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
      - Whether the expected VRFs must be present or absent.
    type: bool
    default: true
"""

EXAMPLES = r"""
- name: Validate VRFs in integration tests
  cisco.nd.tests.integration._nd_vrf_validate:
    nd_data: "{{ gathered_result }}"
    test_data:
      - vrf_name: ansible-vrf-int1
        vrf_id: 9008011

- name: Validate VRF removal
  cisco.nd.tests.integration._nd_vrf_validate:
    nd_data: "{{ gathered_result }}"
    test_data:
      - vrf_name: ansible-vrf-int1
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
missing_vrfs:
  description: Expected VRF names not found in the ND response.
  type: list
  elements: str
  returned: on validation failure
unexpected_vrfs:
  description: VRF names found when C(present=false).
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
    "vrf_name": (("vrf_name",), ("vrfName",), ("parent", "vrfName")),
    "vrf_id": (("vrf_id",), ("vrfId",), ("parent", "vrfId")),
    "vrf_type": (("vrf_type",), ("vrfType",), ("parent", "vrfType")),
    "vlan_id": (("vlan_id",), ("vlanId",), ("parent", "vlanId")),
    "vrf_description": (
        ("vrf_description",),
        ("vrfDescription",),
        ("core_data", "vrfDescription"),
        ("coreData", "vrfDescription"),
        ("parent", "vrfDescription"),
    ),
    "vrf_vlan_name": (("vrf_vlan_name",), ("vrfVlanName",), ("core_data", "vrfVlanName"), ("coreData", "vrfVlanName")),
    "vrf_intf_desc": (
        ("vrf_intf_desc",),
        ("vrfInterfaceDescription",),
        ("core_data", "vrfInterfaceDescription"),
        ("coreData", "vrfInterfaceDescription"),
    ),
    "vrf_int_mtu": (("vrf_int_mtu",), ("mtu",), ("core_data", "mtu"), ("coreData", "mtu")),
    "loopback_route_tag": (("loopback_route_tag",), ("routingTag",), ("core_data", "routingTag"), ("coreData", "routingTag")),
    "redist_direct_rmap": (("redist_direct_rmap",), ("vrfRouteMap",), ("core_data", "vrfRouteMap"), ("coreData", "vrfRouteMap")),
    "v6_redist_direct_rmap": (
        ("v6_redist_direct_rmap",),
        ("v6VrfRouteMap",),
        ("core_data", "v6VrfRouteMap"),
        ("coreData", "v6VrfRouteMap"),
    ),
    "ipv6_linklocal_enable": (
        ("ipv6_linklocal_enable",),
        ("ipv6LinkLocal",),
        ("core_data", "ipv6LinkLocal"),
        ("coreData", "ipv6LinkLocal"),
    ),
    "l3vni_wo_vlan": (
        ("l3vni_wo_vlan",),
        ("l3VniWithoutVlan",),
        ("fabric_data", "l3VniWithoutVlan"),
        ("fabricData", "l3VniWithoutVlan"),
    ),
    "trm_enable": (("trm_enable",), ("ipv4Trm",), ("fabric_data", "trmData", "ipv4Trm"), ("fabricData", "trmData", "ipv4Trm")),
    "netflow_enable": (("netflow_enable",), ("netflow",), ("fabric_data", "netflow"), ("fabricData", "netflow")),
    "adv_host_routes": (
        ("adv_host_routes",),
        ("advertiseHostRoute",),
        ("fabric_data", "advertiseHostRoute"),
        ("fabricData", "advertiseHostRoute"),
    ),
    "adv_default_routes": (
        ("adv_default_routes",),
        ("advertiseDefaultRoute",),
        ("fabric_data", "advertiseDefaultRoute"),
        ("fabricData", "advertiseDefaultRoute"),
    ),
    "static_default_route": (
        ("static_default_route",),
        ("configureStaticDefaultRoute",),
        ("fabric_data", "configureStaticDefaultRoute"),
        ("fabricData", "configureStaticDefaultRoute"),
    ),
    "max_bgp_paths": (("max_bgp_paths",), ("maxBgpPaths",), ("core_data", "maxBgpPaths"), ("coreData", "maxBgpPaths")),
    "max_ibgp_paths": (("max_ibgp_paths",), ("maxIbgpPaths",), ("core_data", "maxIbgpPaths"), ("coreData", "maxIbgpPaths")),
    "disable_rt_auto": (("disable_rt_auto",), ("disableRtAuto",), ("core_data", "disableRtAuto"), ("coreData", "disableRtAuto")),
    "import_vpn_rt": (("import_vpn_rt",), ("routeTargetImport",), ("core_data", "routeTargetImport"), ("coreData", "routeTargetImport")),
    "export_vpn_rt": (("export_vpn_rt",), ("routeTargetExport",), ("core_data", "routeTargetExport"), ("coreData", "routeTargetExport")),
    "import_evpn_rt": (
        ("import_evpn_rt",),
        ("evpnRouteTargetImport",),
        ("core_data", "evpnRouteTargetImport"),
        ("coreData", "evpnRouteTargetImport"),
    ),
    "export_evpn_rt": (
        ("export_evpn_rt",),
        ("evpnRouteTargetExport"),
        ("core_data", "evpnRouteTargetExport"),
        ("coreData", "evpnRouteTargetExport"),
    ),
}

FABRIC_DATA_FIELDS = {
    "l3vni_wo_vlan",
    "trm_enable",
    "netflow_enable",
    "adv_host_routes",
    "adv_default_routes",
    "static_default_route",
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


def _vrf_name(data: dict[str, Any]) -> str | None:
    value = _first_value(data, "vrf_name")
    return str(value) if value is not None else None


def _is_vrf_record(data: Any) -> bool:
    return isinstance(data, dict) and _vrf_name(data) is not None


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

    if _is_vrf_record(data):
        return [data]

    for key in ("gathered", "after", "vrfs", "items", "results"):
        if key in data:
            records = _extract_records(data.get(key))
            if records:
                return records

    current = data.get("current")
    if isinstance(current, dict):
        for key in ("vrfs", "items", "results"):
            records = _extract_records(current.get(key))
            if records:
                return records

    response = data.get("response")
    if response is not None:
        records = _extract_records(response)
        if records:
            return records

    result = data.get("result")
    if result is not None:
        records = _extract_records(result)
        if records:
            return records

    data_section = data.get("DATA")
    if data_section is not None:
        records = _extract_records(data_section)
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


def _is_parent_vrf_without_fabric_data(data: dict[str, Any]) -> bool:
    return _first_value(data, "vrf_type") == "vxlan" and _get_path(data, ("fabric_data",)) is None and _get_path(data, ("fabricData",)) is None


class ActionModule(ActionBase):
    """Validate VRF records from ND integration tests."""

    def run(
        self,
        tmp: Any = None,
        task_vars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        # pylint: disable=too-many-return-statements
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
        live_by_name = {name: record for record in records if (name := _vrf_name(record))}
        expected_names = [_first_value(entry, "vrf_name") for entry in test_data]
        expected_names = [str(name) for name in expected_names if name is not None]

        if not present:
            unexpected = [name for name in expected_names if name in live_by_name]
            if unexpected:
                results["failed"] = True
                results["msg"] = "Validation Failed! Expected VRFs are still present."
                results["unexpected_vrfs"] = unexpected
                return results
            results["msg"] = "Validation Successful!"
            return results

        missing = [name for name in expected_names if name not in live_by_name]
        if missing:
            results["failed"] = True
            results["msg"] = "Validation Failed! Expected VRFs were not found."
            results["missing_vrfs"] = missing
            results["available_vrfs"] = sorted(live_by_name)
            return results

        mismatches: dict[str, dict[str, dict[str, Any]]] = {}
        for expected in test_data:
            name = str(_first_value(expected, "vrf_name"))
            live = live_by_name[name]
            for field in FIELD_PATHS:
                expected_value = _first_value(expected, field)
                if expected_value is None:
                    continue
                actual_value = _first_value(live, field)
                if actual_value is None and field in FABRIC_DATA_FIELDS and _is_parent_vrf_without_fabric_data(live):
                    continue
                if not _values_equal(expected_value, actual_value):
                    mismatches.setdefault(name, {})[field] = {
                        "expected": expected_value,
                        "actual": actual_value,
                    }

        if mismatches:
            display.display("VRF field mismatches:")
            display.display(json.dumps(mismatches, indent=2, sort_keys=True))
            results["failed"] = True
            results["msg"] = "Validation Failed! Please check output above."
            results["field_mismatches"] = mismatches
            return results

        results["msg"] = "Validation Successful!"
        return results
