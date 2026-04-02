# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Sivakami Sivaraman sivakasi@cisco.com
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

import json
from typing import Any, Dict, List, Optional

from ansible_collections.cisco.nd.plugins.module_utils.manage_vpc_pair.exceptions import (
    VpcPairResourceError,
)


DEFAULT_VPC_API_TIMEOUT = 30
DEFAULT_VPC_QUERY_TIMEOUT = 10

def _collection_to_list_flex(collection) -> List[Dict[str, Any]]:
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


def get_api_timeout(module) -> int:
    """
    Return normalized write-operation timeout.

    Args:
        module: AnsibleModule with params

    Returns:
        Integer timeout for create/update/delete calls.
    """
    return _normalize_timeout(
        module.params.get("api_timeout"),
        DEFAULT_VPC_API_TIMEOUT,
    )


def get_query_timeout(module) -> int:
    """
    Return normalized read-operation timeout.

    Simplified policy:
    - If query_timeout is provided, use it.
    - Otherwise inherit api_timeout.

    Args:
        module: AnsibleModule with params

    Returns:
        Integer timeout for query/recommendation/verification calls.
    """
    api_timeout = get_api_timeout(module)
    query_timeout = module.params.get("query_timeout")
    if query_timeout is None:
        return api_timeout
    return _normalize_timeout(
        query_timeout,
        fallback=api_timeout or DEFAULT_VPC_QUERY_TIMEOUT,
    )
