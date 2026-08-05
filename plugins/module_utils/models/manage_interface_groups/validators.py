# Copyright: (c) 2026, L Nikhil Sri Krishna (@nisaikri) <nisaikri@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Normalization helpers for Interface Groups playbook and API data."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.constants import (
    SYSTEM_INJECTED_TEMPLATE_KEYS,
)

_INTERFACE_PREFIX_RE = re.compile(r"^([^0-9]+)([0-9].*)$")
_CANONICAL_PREFIXES = {
    "ethernet": ("ethernet", "Ethernet"),
    "port_channel": ("portchannel", "Port-channel"),
    "vpc": ("vpc", "vPC"),
}
_ETHERNET_RESPONSE_ALIASES = {
    "adminState": "adminStatus",
    "allowedVlans": "trunkAllowedVlans",
    "autoNegotiate": "autoNegotiation",
    "duplexMode": "portDuplexMode",
    "orphanPort": "vPCOrphanPort",
    "portTypeEdgeTrunk": "portTypeFast",
}
_ETHERNET_ATTRIBUTE_KEYS = frozenset(
    {
        "adminStatus",
        "autoNegotiation",
        "bpduGuard",
        "cdp",
        "description",
        "extraConfig",
        "fex",
        "mtu",
        "nativeVlan",
        "netflow",
        "netflowMonitor",
        "netflowSampler",
        "portDuplexMode",
        "portTypeFast",
        "ptp",
        "ptpTimestampTagging",
        "speed",
        "trunkAllowedVlans",
        "vPCOrphanPort",
    }
)
_ETHERNET_WITH_POLICY_DEFAULTS = {
    "adminStatus": True,
    "autoNegotiation": "on",
    "bpduGuard": "default",
    "cdp": True,
    "description": "",
    "extraConfig": "",
    "mtu": "jumbo",
    "nativeVlan": 1,
    "netflow": False,
    "netflowMonitor": "",
    "netflowSampler": "",
    "portDuplexMode": "auto",
    "portTypeFast": True,
    "speed": "auto",
    "trunkAllowedVlans": "none",
    "vPCOrphanPort": False,
}


class InterfaceGroupValidators:
    """Stateless normalization and validation helpers."""

    @staticmethod
    def _normalize_template_scalar(value: Any) -> tuple[str, Any]:
        """Return a stable scalar used to compare custom-template echoes."""
        if isinstance(value, bool):
            return ("boolean", value)
        if isinstance(value, (int, float, Decimal)):
            try:
                return ("number", Decimal(str(value)))
            except InvalidOperation:
                return ("value", value)
        if isinstance(value, str):
            normalized = value.strip()
            lowered = normalized.lower()
            if lowered in {"true", "false"}:
                return ("boolean", lowered == "true")
            try:
                return ("number", Decimal(normalized))
            except InvalidOperation:
                return ("value", value)
        return ("value", value)

    @classmethod
    def template_value_matches(cls, expected: Any, actual: Any) -> bool:
        """Compare one custom-template value using controller echo semantics.

        An explicit null delegates selection of the effective value to the
        template/controller. Once the controller returns that key, the value
        is considered reconciled. To force a value, supply it explicitly.
        """
        if expected is None:
            return True
        if isinstance(expected, dict) and isinstance(actual, dict):
            return cls.template_config_is_subset(expected, actual)
        if isinstance(expected, list) and isinstance(actual, list):
            return len(expected) == len(actual) and all(
                cls.template_value_matches(expected_item, actual_item)
                for expected_item, actual_item in zip(expected, actual)
            )
        return cls._normalize_template_scalar(
            expected
        ) == cls._normalize_template_scalar(actual)

    @classmethod
    def template_config_is_subset(
        cls, expected: dict[str, Any], actual: dict[str, Any]
    ) -> bool:
        """Compare customer-supplied custom-template keys semantically."""
        for key, value in expected.items():
            if key not in actual or not cls.template_value_matches(value, actual[key]):
                return False
        return True

    @staticmethod
    def normalize_response_ethernet_attributes(value: dict | None) -> dict | None:
        """Translate controller shared-policy aliases to module attribute aliases."""
        if not isinstance(value, dict):
            return value

        normalized = {}
        for key, item in value.items():
            alias = _ETHERNET_RESPONSE_ALIASES.get(key, key)
            if alias not in _ETHERNET_ATTRIBUTE_KEYS:
                continue
            if alias == "autoNegotiation" and isinstance(item, bool):
                item = "on" if item else "off"
            normalized[alias] = item
        return normalized

    @classmethod
    def normalize_response_group(cls, value: dict) -> dict:
        """Normalize ND's generic Ethernet response into the module shape."""
        if not isinstance(value, dict):
            return value

        normalized = dict(value)
        policy_details = normalized.get("policyDetails")
        if not isinstance(policy_details, dict):
            policy_details = {}

        ethernet_attributes = normalized.get("ethernetAttributes")
        if ethernet_attributes is None:
            ethernet_attributes = policy_details.get("ethernetAttributes")

        if normalized.get("type") == "ethernet":
            policy_type = policy_details.get("policyType")
            if (
                policy_type == "userDefinedSharedTrunk"
                or "templateName" in normalized
                or "templateConfig" in normalized
                or "templateName" in policy_details
                or "templateConfig" in policy_details
            ):
                normalized["type"] = "ethernetCustom"
            elif policy_type == "none":
                normalized["type"] = "ethernetWithoutPolicy"
            elif policy_details or ethernet_attributes:
                normalized["type"] = "ethernetWithPolicy"
            else:
                normalized["type"] = "ethernetWithoutPolicy"

        if ethernet_attributes is not None:
            normalized["ethernetAttributes"] = (
                cls.normalize_response_ethernet_attributes(ethernet_attributes)
            )
        if "policyId" not in normalized and policy_details.get("policyId") is not None:
            normalized["policyId"] = policy_details["policyId"]
        if normalized.get("type") == "ethernetCustom":
            if (
                "templateName" not in normalized
                and policy_details.get("templateName") is not None
            ):
                normalized["templateName"] = policy_details["templateName"]
            if (
                "templateConfig" not in normalized
                and policy_details.get("templateConfig") is not None
            ):
                normalized["templateConfig"] = policy_details["templateConfig"]
            template_config = normalized.get("templateConfig")
            if isinstance(template_config, dict):
                normalized["templateConfig"] = {
                    key: item
                    for key, item in template_config.items()
                    if key not in SYSTEM_INJECTED_TEMPLATE_KEYS
                }
        return normalized

    @staticmethod
    def ethernet_with_policy_defaults() -> dict:
        """Return the controller-required shared Ethernet policy defaults."""
        return dict(_ETHERNET_WITH_POLICY_DEFAULTS)

    @staticmethod
    def to_wire_ethernet_attributes(value: dict | None) -> dict:
        """Build the live controller's nested shared-policy attribute shape."""
        attributes = dict(_ETHERNET_WITH_POLICY_DEFAULTS)
        attributes.update(value or {})
        wire = {}
        reverse_aliases = {
            api_alias: wire_alias
            for wire_alias, api_alias in _ETHERNET_RESPONSE_ALIASES.items()
        }
        for key, item in attributes.items():
            alias = reverse_aliases.get(key, key)
            if key == "autoNegotiation" and isinstance(item, str):
                item = item.strip().lower() == "on"
            wire[alias] = item
        wire.setdefault("portTypeEdge", False)
        return wire

    @classmethod
    def to_wire_group(
        cls, value: dict, *, include_empty_associations: bool = False
    ) -> dict:
        """Translate the module shape to the controller's write shape."""
        normalized = dict(value)
        if include_empty_associations:
            normalized.setdefault("networkNames", [])
            normalized.setdefault("switchInterfaces", [])

        if normalized.get("type") == "ethernetWithPolicy":
            ethernet_attributes = normalized.pop("ethernetAttributes", None)
            normalized["type"] = "ethernet"
            normalized["policyDetails"] = {
                "policyType": "sharedTrunkHost",
                "ethernetAttributes": cls.to_wire_ethernet_attributes(
                    ethernet_attributes
                ),
            }
        elif normalized.get("type") == "ethernetWithoutPolicy":
            normalized.pop("ethernetAttributes", None)
            normalized["type"] = "ethernet"
            normalized["policyDetails"] = {"policyType": "none"}
        elif normalized.get("type") == "ethernetCustom":
            template_name = normalized.pop("templateName", None)
            template_config = normalized.pop("templateConfig", None)
            normalized["type"] = "ethernet"
            normalized["policyDetails"] = {
                "policyType": "userDefinedSharedTrunk",
                "templateName": template_name,
                "templateConfig": template_config or {},
            }
        return normalized

    @staticmethod
    def normalize_interface_name(value: str) -> str:
        """Return the canonical Interface Group member-interface spelling."""
        if not isinstance(value, str):
            return value
        stripped = value.strip()
        match = _INTERFACE_PREFIX_RE.match(stripped)
        if not match:
            return stripped
        prefix, suffix = match.groups()
        compact_prefix = re.sub(r"[\s_-]", "", prefix).lower()
        for expected_prefix, canonical_prefix in _CANONICAL_PREFIXES.values():
            if expected_prefix.startswith(compact_prefix):
                return f"{canonical_prefix}{suffix}"
        return stripped

    @staticmethod
    def interface_kind(value: str) -> str | None:
        """Classify a normalized member name as ethernet, port_channel, or vpc."""
        normalized = InterfaceGroupValidators.normalize_interface_name(value)
        for kind, prefix_data in _CANONICAL_PREFIXES.items():
            canonical_prefix = prefix_data[1]
            if normalized.startswith(canonical_prefix):
                return kind
        return None

    @staticmethod
    def normalize_unique_strings(value: list[str] | None) -> list[str] | None:
        """Strip, de-duplicate, and deterministically sort a string list."""
        if value is None or not isinstance(value, list):
            return value
        normalized = [item.strip() if isinstance(item, str) else item for item in value]
        if any(not isinstance(item, str) or not item for item in normalized):
            raise ValueError("list entries must be non-empty strings")
        return sorted(set(normalized))
