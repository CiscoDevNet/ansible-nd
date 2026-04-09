# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

import json
from typing import Any, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)

DEFAULT_VERIFY_TIMEOUT = 10
DEFAULT_VERIFY_RETRIES = 5
DEFAULT_CONFIG_ACTION_TYPE = "switch"
CONFIG_ACTION_TYPE_CHOICES = ("switch", "global")


def _collection_to_list_flex(collection: Any) -> List[Dict[str, Any]]:
    """
    Serialize NDConfigCollection across old/new framework variants.

    Tries multiple serialization methods in order to support different
    NDConfigCollection implementations.

    Args:
        collection: NDConfigCollection instance or None

    Returns:
        List of dicts from the collection. Empty list if collection is None
        or has no recognized serialization method.
    """
    if collection is None:
        return []
    if hasattr(collection, "to_list"):
        return collection.to_list()
    if hasattr(collection, "to_payload_list"):
        return collection.to_payload_list()
    if hasattr(collection, "to_ansible_config"):
        return collection.to_ansible_config()
    return []


def _raise_vpc_error(msg: str, **details: Any) -> None:
    """
    Raise a structured vpc_pair error for main() to format via fail_json.

    Args:
        msg: Human-readable error message
        **details: Arbitrary keyword args passed to VpcPairResourceError

    Raises:
        VpcPairResourceError: Always raised with msg and details
    """
    raise VpcPairResourceError(msg=msg, **details)


# ===== Helper Functions =====


def _canonicalize_for_compare(value: Any) -> Any:
    """
    Normalize nested payload data for deterministic comparison.

    Lists are sorted by canonical JSON representation so list ordering does
    not trigger false-positive update detection.

    Args:
        value: Any nested data structure (dict, list, or primitive)

    Returns:
        Canonicalized copy with sorted dicts and sorted lists.
    """
    if isinstance(value, dict):
        return {key: _canonicalize_for_compare(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        normalized_items = [_canonicalize_for_compare(item) for item in value]
        return sorted(
            normalized_items,
            key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
        )
    return value


def _is_update_needed(want: Dict[str, Any], have: Dict[str, Any]) -> bool:
    """
    Determine if an update is needed by comparing want and have.

    Uses canonical, order-insensitive comparison that handles:
    - Field additions
    - Value changes
    - Nested structure changes
    - Ignores field order

    Args:
        want: Desired VPC pair configuration (dict)
        have: Current VPC pair configuration (dict)

    Returns:
        bool: True if update is needed, False if already in desired state

    Example:
        >>> want = {"switchId": "FDO123", "useVirtualPeerLink": True}
        >>> have = {"switchId": "FDO123", "useVirtualPeerLink": False}
        >>> _is_update_needed(want, have)
        True
    """
    normalized_want = _canonicalize_for_compare(want)
    normalized_have = _canonicalize_for_compare(have)
    return normalized_want != normalized_have


def _normalize_timeout(value: Optional[Any], fallback: int) -> int:
    """
    Normalize timeout values from module params with sane fallback.

    Args:
        value: Raw timeout input from module params
        fallback: Timeout to use when value is missing/invalid

    Returns:
        Positive integer timeout value.
    """
    try:
        parsed = int(value)
        if parsed > 0:
            return parsed
    except (TypeError, ValueError):
        pass
    return fallback


def _normalize_iteration(value: Optional[Any], fallback: int) -> int:
    """
    Normalize retry iteration count from module params with sane fallback.

    Args:
        value: Raw iteration input from module params
        fallback: Iteration count to use when value is missing/invalid

    Returns:
        Positive integer iteration count.
    """
    try:
        parsed = int(value)
        if parsed > 0:
            return parsed
    except (TypeError, ValueError):
        pass
    return fallback


def _normalize_bool(value: Any, fallback: bool) -> bool:
    """
    Normalize bool-like values with string/int support.

    Args:
        value: Raw input value
        fallback: Default when value is None or unsupported type

    Returns:
        Boolean result.
    """
    if value is None:
        return fallback
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in ("true", "yes", "1", "on"):
            return True
        if normalized in ("false", "no", "0", "off"):
            return False
    return fallback


def get_verify_settings(module: Any) -> Dict[str, Any]:
    """
    Return normalized verification settings.

    Schema:
      verify:
        enabled: bool
        retries: int
        timeout: int
    """
    raw_verify = module.params.get("verify")
    if isinstance(raw_verify, dict):
        return {
            "enabled": _normalize_bool(raw_verify.get("enabled"), True),
            "retries": _normalize_iteration(raw_verify.get("retries"), DEFAULT_VERIFY_RETRIES),
            "timeout": _normalize_timeout(raw_verify.get("timeout"), DEFAULT_VERIFY_TIMEOUT),
        }

    return {
        "enabled": True,
        "retries": DEFAULT_VERIFY_RETRIES,
        "timeout": DEFAULT_VERIFY_TIMEOUT,
    }


def get_config_actions(module: Any) -> Dict[str, Any]:
    """
    Return normalized configuration action controls.

    Preferred schema:
        config_actions:
          save: bool
          deploy: bool
          type: "switch" | "global"

    Legacy fallback:
        deploy: bool
    """
    raw_actions = module.params.get("config_actions")
    if isinstance(raw_actions, dict):
        save = _normalize_bool(raw_actions.get("save"), True)
        deploy = _normalize_bool(raw_actions.get("deploy"), True)
        action_type_raw = raw_actions.get("type", DEFAULT_CONFIG_ACTION_TYPE)
        action_type = str(action_type_raw).strip().lower() if action_type_raw is not None else DEFAULT_CONFIG_ACTION_TYPE
        if action_type not in CONFIG_ACTION_TYPE_CHOICES:
            action_type = DEFAULT_CONFIG_ACTION_TYPE
        return {
            "save": save,
            "deploy": deploy,
            "type": action_type,
        }

    legacy_deploy = _normalize_bool(module.params.get("deploy"), True)
    return {
        "save": legacy_deploy,
        "deploy": legacy_deploy,
        "type": DEFAULT_CONFIG_ACTION_TYPE,
    }


def get_verify_timeout(module: Any) -> int:
    """
    Return normalized read-operation timeout.

    Args:
        module: AnsibleModule with params

    Returns:
        Integer timeout for query/recommendation/verification calls.
    """
    return get_verify_settings(module).get("timeout", DEFAULT_VERIFY_TIMEOUT)


def get_verify_iterations(module: Any) -> int:
    """
    Return normalized verification attempt count.

    Args:
        module: AnsibleModule with params

    Returns:
        Positive integer verification attempt count.
    """
    raw_verify = module.params.get("verify")
    if isinstance(raw_verify, dict) and "retries" in raw_verify:
        return get_verify_settings(module).get("retries", DEFAULT_VERIFY_RETRIES)

    return get_verify_settings(module).get("retries", DEFAULT_VERIFY_RETRIES)
