# -*- coding: utf-8 -*-

# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Validate read-only Interface configuration previews in integration tests."""

from __future__ import annotations

DOCUMENTATION = r"""
---
module: nd_interface_preview_validate
short_description: Validate interface preview results in ND integration tests
version_added: "2.0.0"
description:
- Validates the result of a read-only Interface configuration preview.
- Confirms every requested interface succeeded and whether pending configuration
  is present or absent.
- Optionally checks expected or running configuration fragments.
author:
- L Nikhil Sri Krishna (@nisaikri)
options:
  nd_data:
    description:
    - Registered C(cisco.nd.nd_rest) result from an Interface preview request.
    type: raw
    required: true
  test_data:
    description:
    - Expected interface preview results.
    type: list
    elements: dict
    required: true
    suboptions:
      switch_id:
        type: str
        required: true
      interface_name:
        type: str
        required: true
      pending:
        description:
        - C(clean) requires a pending configuration entry with zero lines.
        - C(present) requires a pending configuration entry with one or more lines.
        - C(ignore) does not validate the pending configuration entry.
        type: str
        choices: [clean, present, ignore]
        default: clean
      expected_contains:
        type: list
        elements: str
      running_contains:
        type: list
        elements: str
notes:
- This integration-test helper never mutates Nexus Dashboard state.
"""

RETURN = r"""
changed:
  description: Always C(false).
  returned: always
  type: bool
report:
  description: Missing, failed, pending-state, duplicate, and configuration-fragment results.
  returned: always
  type: dict
"""

from typing import Any

from ansible.plugins.action import ActionBase
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_interface_groups.validators import (
    InterfaceGroupValidators,
)

_SUPPORTED_ARGUMENTS = frozenset({"nd_data", "test_data"})
_SUPPORTED_PENDING = frozenset({"clean", "present", "ignore"})


def _unwrap(value: Any) -> Any:
    """Unwrap the common nd_rest result containers."""
    node = value
    for key in ("result", "current"):
        if isinstance(node, dict) and key in node:
            node = node[key]
    return node


def _extract_diffs(value: Any) -> list[dict[str, Any]]:
    """Extract preview entries from documented and direct response shapes."""
    node = _unwrap(value)
    if isinstance(node, list):
        return [item for item in node if isinstance(item, dict)]
    if not isinstance(node, dict):
        return []
    for key in ("configurationDiffs", "configuration_diffs", "items", "results"):
        entries = node.get(key)
        if isinstance(entries, list):
            return [item for item in entries if isinstance(item, dict)]
    if "interfaceName" in node or "interface_name" in node:
        return [node]
    return []


def _first(value: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in value:
            return value[name]
    return None


def _identity(value: dict[str, Any]) -> tuple[str, str]:
    switch_id = str(_first(value, "switch_id", "switchId") or "")
    interface_name = _first(value, "interface_name", "interfaceName")
    return (
        switch_id,
        InterfaceGroupValidators.normalize_interface_name(interface_name or ""),
    )


def _combined_configs(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    configs = _first(value, "combinedConfigs", "combined_configs")
    if not isinstance(configs, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for item in configs:
        if not isinstance(item, dict):
            continue
        config_type = str(_first(item, "configType", "config_type") or "").lower()
        if config_type:
            result[config_type] = item
    return result


def _pending_lines(value: dict[str, Any]) -> int | None:
    pending = _combined_configs(value).get("pending")
    if not isinstance(pending, dict) or "lines" not in pending:
        return None
    lines = pending["lines"]
    if isinstance(lines, bool):
        return None
    try:
        return int(lines)
    except (TypeError, ValueError):
        return None


def _normalise_fragments(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


class ActionModule(ActionBase):
    """Validate Interface preview status, pending lines, and config fragments."""

    TRANSFERS_FILES = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)
        del tmp
        args = self._task.args or {}
        unknown = sorted(set(args) - _SUPPORTED_ARGUMENTS)
        if unknown:
            return self._fail(result, "unsupported argument(s): {0}".format(", ".join(unknown)))
        if args.get("nd_data") is None:
            return self._fail(result, "'nd_data' is required")
        if isinstance(args["nd_data"], dict) and args["nd_data"].get("failed"):
            return self._fail(
                result,
                "upstream Interface preview failed: {0}".format(args["nd_data"].get("msg", "no message")),
            )

        test_data = args.get("test_data")
        if isinstance(test_data, dict):
            test_data = [test_data]
        if not isinstance(test_data, list) or not test_data:
            return self._fail(result, "test_data must be a non-empty list or dictionary")

        entries = _extract_diffs(args["nd_data"])
        by_identity: dict[tuple[str, str], dict[str, Any]] = {}
        duplicate_identities: list[str] = []
        for entry in entries:
            identity = _identity(entry)
            if identity in by_identity:
                duplicate_identities.append("{0}/{1}".format(*identity))
            by_identity[identity] = entry

        report = {
            "missing": [],
            "failed_status": [],
            "pending_mismatches": [],
            "config_fragments_missing": [],
            "duplicates": sorted(set(duplicate_identities)),
        }
        for expected in test_data:
            if not isinstance(expected, dict):
                return self._fail(result, "test_data entries must be dictionaries")
            unknown_expected = sorted(
                set(expected)
                - {
                    "switch_id",
                    "interface_name",
                    "pending",
                    "expected_contains",
                    "running_contains",
                }
            )
            if unknown_expected:
                return self._fail(
                    result,
                    "unsupported test_data key(s): {0}".format(", ".join(unknown_expected)),
                )
            if not expected.get("switch_id") or not expected.get("interface_name"):
                return self._fail(
                    result,
                    "each test_data entry requires switch_id and interface_name",
                )
            pending = expected.get("pending", "clean")
            if pending not in _SUPPORTED_PENDING:
                return self._fail(
                    result,
                    "pending must be one of: {0}".format(", ".join(sorted(_SUPPORTED_PENDING))),
                )

            identity = _identity(expected)
            label = "{0}/{1}".format(*identity)
            actual = by_identity.get(identity)
            if actual is None:
                report["missing"].append(label)
                continue

            status = str(actual.get("status") or "").strip().lower()
            if status not in {"success", "succeeded"}:
                report["failed_status"].append(
                    {
                        "interface": label,
                        "status": status or None,
                        "message": actual.get("message"),
                    }
                )

            lines = _pending_lines(actual)
            if pending != "ignore" and (lines is None or (pending == "clean" and lines != 0) or (pending == "present" and lines <= 0)):
                report["pending_mismatches"].append(
                    {
                        "interface": label,
                        "expected": pending,
                        "pending_lines": lines,
                    }
                )

            configs = _combined_configs(actual)
            for config_type, argument_name in (
                ("expected", "expected_contains"),
                ("running", "running_contains"),
            ):
                config = str(configs.get(config_type, {}).get("config") or "")
                for fragment in _normalise_fragments(expected.get(argument_name)):
                    if fragment not in config:
                        report["config_fragments_missing"].append(
                            {
                                "interface": label,
                                "config_type": config_type,
                                "fragment": fragment,
                            }
                        )

        result.update(changed=False, report=report)
        if any(report.values()):
            result.update(
                failed=True,
                msg="Interface preview validation failed: {0}".format(report),
            )
        return result

    @staticmethod
    def _fail(result: dict[str, Any], message: str) -> dict[str, Any]:
        result.update(changed=False, failed=True, msg=message)
        return result
