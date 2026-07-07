# Copyright: (c) 2026, Cisco and/or its affiliates.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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
    filter_items = filters or [{}]
    expressions: list[str] = []

    for filter_item in filter_items:
        terms = [
            f"{field_name}:{format_lucene_value(value)}"
            for field_name, value in spec.base_terms
        ]

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


def filter_gathered_response(
    response_data: list[dict[str, Any]],
    filters: list[dict[str, Any]],
    model_class: type[NDBaseModel],
    normalize_filter: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Apply gathered filters to raw API objects.

    Criteria inside one filter item use AND semantics.
    Multiple filter items use OR semantics.
    Returned objects remain in API shape for NDConfigCollection.from_api_response().
    """

    if not filters:
        return response_data

    active_filters: list[dict[str, Any]] = []
    for filter_item in filters:
        if not isinstance(filter_item, dict):
            raise ValueError("Each gathered filter item must be a dictionary.")

        normalized = deepcopy(filter_item)
        if normalize_filter is not None:
            normalized = normalize_filter(normalized)

        if not _contains_active_value(normalized):
            raise ValueError("A gathered filter item must contain at least one filtering criterion.")

        active_filters.append(normalized)

    filtered: list[dict[str, Any]] = []
    seen_identifiers = set()

    for response_item in response_data:
        model = model_class.from_response(response_item)
        candidate = model.to_config()

        if not any(model_class.matches_gathered_filter(criteria, candidate) for criteria in active_filters):
            continue

        identifier = model.get_identifier_value()
        if identifier in seen_identifiers:
            continue

        seen_identifiers.add(identifier)
        filtered.append(response_item)

    return filtered
