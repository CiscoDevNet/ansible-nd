# Copyright: (c) 2026, Deeksha Pandey (@deekpand) <deekpand@cisco.com>

"""Generic local and server-side filtering helpers for gathered-state responses."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any, Callable, Mapping

from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel

FieldPath = tuple[str, ...]
_MISSING = object()
_SAFE_UNQUOTED = re.compile(r"^[A-Za-z0-9_.]+$")


@dataclass(frozen=True)
class GatheredLuceneSpec:
    """Describe fields supported by an endpoint's Lucene filter.

    ``base_terms`` are included in every generated expression. ``field_map``
    maps structured Ansible config paths to controller-supported field names.
    """

    base_terms: tuple[tuple[str, Any], ...] = ()
    field_map: Mapping[FieldPath, str] = field(default_factory=dict)


def format_lucene_value(value: Any) -> str:
    """Format one value as an exact-match Lucene literal.

    Values are generated from structured module input, never accepted as raw
    Lucene syntax. Strings containing reserved punctuation or whitespace are
    quoted and escaped.
    """
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, (int, float)):
        return str(value)

    text = str(value)
    if _SAFE_UNQUOTED.fullmatch(text):
        return text

    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def get_nested_value(data: dict[str, Any], path: FieldPath) -> Any:
    """Return a nested filter value, or an internal missing-value marker."""
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return _MISSING
        current = current[key]
    return current


def build_lucene_expressions(
    filters: list[dict[str, Any]],
    spec: GatheredLuceneSpec,
) -> list[str]:
    """Build one server-side AND expression per gathered config item.

    Separate config items intentionally remain separate expressions. Callers
    can union and deduplicate their responses to preserve gathered-state OR
    semantics without relying on endpoint-specific Lucene OR support.
    """
    # TODO(4.2.1) interface-lucene-or-silently-empty
    filter_items = filters or [{}]
    expressions: list[str] = []

    for filter_item in filter_items:
        terms = [f"{field_name}:{format_lucene_value(value)}" for field_name, value in spec.base_terms]

        for config_path, api_field in spec.field_map.items():
            value = get_nested_value(filter_item, config_path)
            # False and zero are meaningful criteria and must not be skipped.
            if value is _MISSING or value in (None, ""):
                continue
            terms.append(f"{api_field}:{format_lucene_value(value)}")

        expression = " AND ".join(terms)
        if expression and expression not in expressions:
            expressions.append(expression)

    return expressions


def _contains_active_value(value: Any) -> bool:
    """Return whether a filter value contains an explicitly supplied criterion."""
    if isinstance(value, dict):
        return any(_contains_active_value(item) for item in value.values())

    if isinstance(value, list):
        return bool(value)

    # False and 0 can be meaningful filter values. Empty strings cannot match
    # valid loopback fields and are treated as absent criteria.
    return value not in (None, "")


def _extract_active_leaf_paths(data: dict[str, Any], prefix: str = "") -> set[str]:
    """Return dot-paths for every non-None, non-empty leaf value in a nested dict.

    Given a gathered filter dict (which may be nested due to Ansible's argument
    spec structure), this walks the tree and identifies which properties the user
    actually supplied a value for.

    Ansible pads all omitted suboptions with None after argument validation.
    Those Nones are not user-supplied criteria and are correctly skipped.

    Args:
        data: A (possibly nested) filter dict from the user's config item.
        prefix: Internal recursion prefix — callers should not pass this.

    Returns:
        A set of dot-path strings representing active (non-None) leaf values.

    Examples:
        >>> _extract_active_leaf_paths({"switch_ip": "10.1.1.1", "interface_name": None})
        {"switch_ip"}

        >>> _extract_active_leaf_paths({
        ...     "config_data": {"network_os": {"policy": {"vrf": "mgmt", "ip": None}}}
        ... })
        {"config_data.network_os.policy.vrf"}

        >>> _extract_active_leaf_paths({"login_id": "admin"})
        {"login_id"}

        >>> _extract_active_leaf_paths({"config_data": None})
        set()  # None at any level is skipped
    """
    paths: set[str] = set()
    for key, value in data.items():
        full_path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            paths |= _extract_active_leaf_paths(value, full_path)
        elif value not in (None, "", []):
            # False and 0 ARE active values (e.g., admin_state: false)
            paths.add(full_path)
    return paths


def _reject_unsupported_filter_properties(
    filter_item: dict[str, Any],
    supported_properties: tuple[str, ...],
    index: int,
) -> None:
    """Raise ValueError if a filter item contains properties not in the supported set.

    This is the enforcement function for the model's gathered_filter_properties
    declaration. Called exactly once per filter item during pre-flight validation,
    before any API request or normalization.

    Args:
        filter_item: One raw filter dict from the user's config list.
        supported_properties: The model's declared tuple of allowed dot-paths.
        index: The position of this filter item in the config list (for error messages).

    Raises:
        ValueError: With a message listing unsupported properties and the full
            set of supported properties. Formatted for direct use in Ansible's
            module.fail_json(msg=...).

    Examples:
        # Passes (switch_ip is supported):
        >>> _reject_unsupported_filter_properties(
        ...     {"switch_ip": "10.1.1.1"},
        ...     ("switch_ip", "interface_name"),
        ...     index=0,
        ... )  # No error

        # Fails (extra_config is not supported):
        >>> _reject_unsupported_filter_properties(
        ...     {"config_data": {"network_os": {"policy": {"extra_config": "cli"}}}},
        ...     ("switch_ip", "interface_name", "config_data.network_os.policy.vrf"),
        ...     index=0,
        ... )
        # ValueError: "Gathered filter at index 0 contains unsupported properties:
        #   'config_data.network_os.policy.extra_config'.
        #   Supported gathered filter properties: 'switch_ip', 'interface_name', ..."
    """
    supplied_paths = _extract_active_leaf_paths(filter_item)
    supported_set = set(supported_properties)
    unsupported = sorted(supplied_paths - supported_set)
    if unsupported:
        raise ValueError(
            f"Gathered filter at index {index} contains unsupported properties: "
            f"{', '.join(repr(p) for p in unsupported)}. "
            f"Supported gathered filter properties: "
            f"{', '.join(repr(p) for p in supported_properties)}"
        )


def filter_gathered_response(
    response_data: list[dict[str, Any]],
    filters: list[dict[str, Any]],
    model_class: type[NDBaseModel],
    normalize_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> list[NDBaseModel]:
    """
    Apply gathered filters to raw API objects and return validated models.

    Criteria inside one filter item use AND semantics.
    Multiple filter items use OR semantics.

    Returns validated model instances directly so callers can construct an
    NDConfigCollection without redundant from_response() calls.
    """
    # Validation duplicates validate_gathered_filters() intentionally so this
    # function remains safe to call standalone (e.g., from unit tests).
    active_filters: list[dict[str, Any]] = []
    for filter_item in filters or []:
        if not isinstance(filter_item, dict):
            raise ValueError("Each gathered filter item must be a dictionary.")

        normalized = deepcopy(filter_item)
        if normalize_filter is not None:
            normalized = normalize_filter(normalized)

        if not _contains_active_value(normalized):
            raise ValueError("A gathered filter item must contain at least one filtering criterion.")

        active_filters.append(normalized)

    filtered_models: list[NDBaseModel] = []
    seen_identifiers = set()

    for response_item in response_data:
        model = model_class.from_response(response_item)

        if active_filters:
            candidate = model.to_config()
            if not any(model_class.matches_gathered_filter(criteria, candidate) for criteria in active_filters):
                continue

        identifier = model.get_identifier_value()
        if identifier in seen_identifiers:
            continue

        seen_identifiers.add(identifier)
        filtered_models.append(model)

    return filtered_models


def validate_gathered_filters(
    filters: list[Any],
    normalize_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    supported_properties: tuple[str, ...] = (),
) -> None:
    """
    Pre-flight validation for gathered filter items.

    Validates each filter item through a strict pipeline:
      1. Type check — must be a dict
      2. Property check — all active properties must be in the supported set
      3. Normalize — transform values to canonical form (e.g., lowercase)
      4. Active check — at least one non-None criterion must exist

    Property validation runs BEFORE normalization because:
      - It checks KEYS (property paths), normalization transforms VALUES.
      - Unsupported properties should be rejected without wasting normalization effort.
      - Error messages should show what the user wrote, not the normalized form.

    Args:
        filters: The raw config list from module.params["config"].
            Example: [{"switch_ip": "10.1.1.1", "interface_name": "loopback0"}]

        normalize_filter: Model-specific value transformer (e.g., lowercase interface_name).
            Signature: (dict) -> dict. May be None if no normalization needed.

        supported_properties: The model's gathered_filter_properties tuple.
            Example: ("switch_ip", "interface_name", "config_data.network_os.policy.vrf")
            Empty tuple means property validation is skipped (backward-compatible).

    Raises:
        ValueError: If any filter item fails any validation step.
    """
    for idx, filter_item in enumerate(filters):
        # Step 1: Type check
        if not isinstance(filter_item, dict):
            raise ValueError(f"Each gathered filter item must be a dictionary, " f"got {type(filter_item).__name__} at index {idx}.")

        # Step 2: Property validation (before normalize - checks keys, not values)
        if supported_properties:
            _reject_unsupported_filter_properties(filter_item, supported_properties, idx)

        # Step 3: Normalize values to canonical form
        normalized = deepcopy(filter_item)
        if normalize_filter is not None:
            normalized = normalize_filter(normalized)

        # Step 4: Active value check
        if not _contains_active_value(normalized):
            raise ValueError(f"Gathered filter item at index {idx} must contain " f"at least one filtering criterion.")
