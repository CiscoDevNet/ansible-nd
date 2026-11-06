# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Focused tests for interface-scoped offset pagination."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.interface_pagination import (
    InterfaceOffsetPaginator,
    InterfacePaginationError,
)


def _row(name: str, switch_id: str = "SERIAL1") -> dict[str, str]:
    return {"switchId": switch_id, "interfaceName": name}


def _identity(item: Mapping[str, Any]) -> tuple[str, str]:
    return item["switchId"], item["interfaceName"].lower()


def test_collects_short_page_without_metadata() -> None:
    calls: list[tuple[int, int]] = []

    def fetch(offset: int, page_size: int):
        calls.append((offset, page_size))
        return {"interfaces": [_row("Ethernet1/1")]}

    result = InterfaceOffsetPaginator(page_size=2).collect(fetch_page=fetch, identity=_identity)

    assert result == [_row("Ethernet1/1")]
    assert calls == [(0, 2)]


def test_advances_by_actual_rows_when_remaining_reports_more() -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1")], "meta": {"counts": {"total": 2, "remaining": 1}}},
        {"interfaces": [_row("Ethernet1/2")], "meta": {"counts": {"total": 2, "remaining": 0}}},
    ]
    calls: list[tuple[int, int]] = []

    def fetch(offset: int, page_size: int):
        calls.append((offset, page_size))
        return responses.pop(0)

    result = InterfaceOffsetPaginator(page_size=500).collect(fetch_page=fetch, identity=_identity)

    assert [item["interfaceName"] for item in result] == ["Ethernet1/1", "Ethernet1/2"]
    assert calls == [(0, 500), (1, 500)]


@pytest.mark.parametrize("next_link", ["?offset=1", "https://nd.example/api/v1/manage/interfaces?max=10&offset=1"])
def test_accepts_metadata_wrapper_string_counts_and_next_link(next_link: str) -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1")], "metadata": {"counts": {"total": "2", "remaining": "1"}, "links": {"next": next_link}}},
        {"interfaces": [_row("Ethernet1/2")], "metadata": {"counts": {"total": "2", "remaining": "0"}, "links": {"next": None}}},
    ]

    result = InterfaceOffsetPaginator(page_size=10).collect(fetch_page=lambda _offset, _size: responses.pop(0), identity=_identity)

    assert [item["interfaceName"] for item in result] == ["Ethernet1/1", "Ethernet1/2"]


def test_full_page_without_metadata_uses_length_fallback() -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1"), _row("Ethernet1/2")]},
        {"interfaces": [_row("Ethernet1/3")]},
    ]
    offsets: list[int] = []

    def fetch(offset: int, _page_size: int):
        offsets.append(offset)
        return responses.pop(0)

    result = InterfaceOffsetPaginator(page_size=2).collect(fetch_page=fetch, identity=_identity)

    assert [item["interfaceName"] for item in result] == ["Ethernet1/1", "Ethernet1/2", "Ethernet1/3"]
    assert offsets == [0, 2]


@pytest.mark.parametrize(
    "response,match",
    [
        ({"interfaces": "invalid"}, "wrapper type"),
        ({"interfaces": None}, "wrapper type"),
        ({"interfaces": ["invalid"]}, "row 0 has invalid type"),
        ({"interfaces": [], "meta": "invalid"}, "invalid 'meta' type"),
        ({"interfaces": [], "meta": None}, "invalid 'meta' type"),
        ({"interfaces": [], "meta": {"counts": {"remaining": -1}}}, "invalid remaining"),
        ({"interfaces": [], "meta": {"links": {"next": 1}}}, "links.next type"),
        ({"interfaces": [], "meta": {}, "metadata": {}}, "both 'meta' and 'metadata'"),
        ({"meta": {"counts": {"total": 0}}}, "lacks required 'interfaces' wrapper"),
        ({"interfaces": [], "meta": {"counts": {"total": 0}, "total": 1}}, "nested/top-level total"),
    ],
)
def test_rejects_malformed_response_shapes(response, match: str) -> None:
    with pytest.raises(InterfacePaginationError, match=match):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: response, identity=_identity)


def test_rejects_contradictory_metadata() -> None:
    response = {"interfaces": [_row("Ethernet1/1")], "meta": {"counts": {"total": 2, "remaining": 0}}}

    with pytest.raises(InterfacePaginationError, match="contradictory"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: response, identity=_identity)


@pytest.mark.parametrize(
    "next_link,match",
    [
        ("?max=10", "exactly one offset"),
        ("?offset=1&offset=2", "exactly one offset"),
        ("?offset=not-a-number", "invalid offset"),
        ("?offset=0", "does not match actual next offset 1"),
        ("?offset=2", "does not match actual next offset 1"),
    ],
)
def test_rejects_invalid_or_mismatched_next_offset(next_link: str, match: str) -> None:
    response = {"interfaces": [_row("Ethernet1/1")], "meta": {"links": {"next": next_link}}}

    with pytest.raises(InterfacePaginationError, match=match):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: response, identity=_identity)


def test_rejects_total_that_changes_between_pages() -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1")], "meta": {"counts": {"total": 3}}},
        {"interfaces": [_row("Ethernet1/2")], "meta": {"counts": {"total": 4}}},
    ]

    with pytest.raises(InterfacePaginationError, match="total changed from 3 to 4"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: responses.pop(0), identity=_identity)


def test_rejects_remaining_only_inferred_total_that_changes_between_pages() -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1")], "meta": {"counts": {"remaining": 2}}},
        {"interfaces": [_row("Ethernet1/2")], "meta": {"counts": {"remaining": 2}}},
    ]

    with pytest.raises(InterfacePaginationError, match="total changed from 3 to 4"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: responses.pop(0), identity=_identity)


def test_empty_mapping_is_the_only_missing_wrapper_shape_accepted() -> None:
    assert InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: {}, identity=_identity) == []


def test_rejects_empty_page_when_metadata_reports_more() -> None:
    response = {"interfaces": [], "meta": {"counts": {"remaining": 1}}}

    with pytest.raises(InterfacePaginationError, match="empty page"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: response, identity=_identity)


def test_rejects_repeated_or_overlapping_identity() -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1")], "meta": {"counts": {"remaining": 1}}},
        {"interfaces": [_row("ethernet1/1")], "meta": {"counts": {"remaining": 0}}},
    ]

    with pytest.raises(InterfacePaginationError, match="repeated page|duplicate interface identity"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: responses.pop(0), identity=_identity)


def test_rejects_partial_overlap_between_pages() -> None:
    responses = [
        {"interfaces": [_row("Ethernet1/1"), _row("Ethernet1/2")], "meta": {"counts": {"remaining": 1}}},
        {"interfaces": [_row("ethernet1/2"), _row("Ethernet1/3")], "meta": {"counts": {"remaining": 0}}},
    ]

    with pytest.raises(InterfacePaginationError, match="duplicate interface identity"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: responses.pop(0), identity=_identity)


def test_rejects_duplicate_identity_within_one_page() -> None:
    response = {"interfaces": [_row("Ethernet1/1"), _row("ethernet1/1")]}

    with pytest.raises(InterfacePaginationError, match="within one page"):
        InterfaceOffsetPaginator().collect(fetch_page=lambda _offset, _size: response, identity=_identity)


def test_rejects_maximum_page_exhaustion() -> None:
    def fetch(offset: int, _page_size: int):
        return {"interfaces": [_row(f"Ethernet1/{offset + 1}")], "meta": {"counts": {"total": 3, "remaining": 2 - offset}}}

    with pytest.raises(InterfacePaginationError, match="maximum page limit 2"):
        InterfaceOffsetPaginator(page_size=1, max_pages=2).collect(fetch_page=fetch, identity=_identity)


@pytest.mark.parametrize("kwargs", [{"page_size": 0}, {"page_size": True}, {"max_pages": 0}, {"max_pages": False}])
def test_constructor_rejects_invalid_limits(kwargs) -> None:
    with pytest.raises(ValueError):
        InterfaceOffsetPaginator(**kwargs)
