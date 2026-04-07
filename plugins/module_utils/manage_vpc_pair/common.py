# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

import json
from typing import Any, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)


DEFAULT_VERIFY_TIMEOUT = 5
DEFAULT_VERIFY_ITERATION = 3


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
        return {
            key: _canonicalize_for_compare(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, list):
        normalized_items = [_canonicalize_for_compare(item) for item in value]
        return sorted(
            normalized_items,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ),
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


def _normalize_timeout(
    value: Optional[Any], fallback: int
) -> int:
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


def get_verify_option(module: Any) -> Dict[str, int]:
    """
    Return normalized verify_option dictionary.

    verify_option schema:
    - timeout: per-query timeout in seconds
    - iteration: number of verification attempts

    Invalid or missing values fall back to defaults.
    """
    raw_options = module.params.get("verify_option") or {}
    if not isinstance(raw_options, dict):
        raw_options = {}

    return {
        "timeout": _normalize_timeout(
            raw_options.get("timeout"), DEFAULT_VERIFY_TIMEOUT
        ),
        "iteration": _normalize_iteration(
            raw_options.get("iteration"), DEFAULT_VERIFY_ITERATION
        ),
    }


def get_verify_timeout(module: Any) -> int:
    """
    Return normalized read-operation timeout.

    Policy:
    - When suppress_verification is false (default), query timeout is fixed
      to DEFAULT_VERIFY_TIMEOUT for automatic verification/read paths.
    - When suppress_verification is true, timeout can be tuned via
      verify_option.timeout.

    Args:
        module: AnsibleModule with params

    Returns:
        Integer timeout for query/recommendation/verification calls.
    """
    if not module.params.get("suppress_verification", False):
        return DEFAULT_VERIFY_TIMEOUT
    return get_verify_option(module).get("timeout", DEFAULT_VERIFY_TIMEOUT)


def get_verify_iterations(module: Any, changed_pairs: Optional[int] = None) -> int:
    """
    Return normalized verification attempt count.

    Policy:
    - If suppress_verification is true and verify_option.iteration is provided,
      use that explicit value.
    - Otherwise, for automatic verification, use changed_pairs + 1 when
      changed_pairs is available.
    - Fall back to DEFAULT_VERIFY_ITERATION when changed_pairs is unavailable.

    Args:
        module: AnsibleModule with params
        changed_pairs: Number of create/update/delete items in this run

    Returns:
        Positive integer verification attempt count.
    """
    if module.params.get("suppress_verification", False):
        verify_option = module.params.get("verify_option")
        if isinstance(verify_option, dict) and "iteration" in verify_option:
            return get_verify_option(module).get("iteration", DEFAULT_VERIFY_ITERATION)

    if isinstance(changed_pairs, int) and changed_pairs > 0:
        return changed_pairs + 1

    return DEFAULT_VERIFY_ITERATION
