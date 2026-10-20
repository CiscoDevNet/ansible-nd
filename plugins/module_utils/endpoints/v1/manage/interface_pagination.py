# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Safe offset pagination for Nexus Dashboard interface collections.

The helper is intentionally scoped to the interface endpoint family.  It owns
page sequencing and completeness checks while callers retain the endpoint,
query selectors, response wrapper, and complete interface identity.  Keeping
those seams explicit lets the implementation serve the standalone interface
modules and the aggregate interface workflow without prematurely becoming a
collection-wide pagination API.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Mapping
from dataclasses import dataclass
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlsplit


class InterfacePaginationError(RuntimeError):
    """Raised when a complete interface collection cannot be proven."""


@dataclass(frozen=True)
class _PageMetadata:
    """Normalized continuation evidence from one ND collection response."""

    total: int | None = None
    remaining: int | None = None
    next_present: bool | None = None
    next_offset: int | None = None

    @property
    def available(self) -> bool:
        """Return whether the response supplied any recognized page metadata."""

        return self.total is not None or self.remaining is not None or self.next_present is not None


class InterfaceOffsetPaginator:
    """Collect a complete ND interface collection through ``max``/``offset``.

    ``fetch_page`` receives ``(offset, page_size)`` and must issue the request
    through the caller's normal request path. ``identity`` returns the complete
    identity for one row, normally ``(switch_id, lower_interface_name)``.
    Duplicate identities fail closed because current-state and membership
    safety must never depend on an arbitrary first/last copy.
    """

    DEFAULT_PAGE_SIZE = 500
    DEFAULT_MAX_PAGES = 1000

    def __init__(self, *, page_size: int = DEFAULT_PAGE_SIZE, max_pages: int = DEFAULT_MAX_PAGES) -> None:
        if isinstance(page_size, bool) or not isinstance(page_size, int) or page_size < 1:
            raise ValueError("InterfaceOffsetPaginator page_size must be a positive integer.")
        if isinstance(max_pages, bool) or not isinstance(max_pages, int) or max_pages < 1:
            raise ValueError("InterfaceOffsetPaginator max_pages must be a positive integer.")
        self.page_size = page_size
        self.max_pages = max_pages

    def collect(
        self,
        *,
        fetch_page: Callable[[int, int], Any],
        identity: Callable[[Mapping[str, Any]], Hashable],
        collection_key: str = "interfaces",
        context: str = "interface collection",
        require_collection_wrapper: bool = False,
    ) -> list[dict[str, Any]]:
        """Return every interface row or raise instead of returning partial state."""

        if not collection_key:
            raise ValueError("InterfaceOffsetPaginator collection_key must be non-empty.")
        records: list[dict[str, Any]] = []
        identities: set[Hashable] = set()
        signatures: set[tuple[Hashable, ...]] = set()
        offset = 0
        expected_total: int | None = None

        for page_number in range(1, self.max_pages + 1):
            response = fetch_page(offset, self.page_size)
            page, metadata = self._parse_response(response, collection_key, context, offset, page_number, len(records), require_collection_wrapper)
            page_identities = self._page_identities(page, identity, context, offset, page_number, len(records))
            signature = tuple(page_identities)
            if signature and signature in signatures:
                self._raise(
                    context,
                    "repeated page",
                    offset,
                    page_number,
                    len(records),
                    metadata,
                )
            if signature:
                signatures.add(signature)

            duplicates = [item_identity for item_identity in page_identities if item_identity in identities]
            if duplicates:
                self._raise(
                    context,
                    f"duplicate interface identity {duplicates[0]!r}",
                    offset,
                    page_number,
                    len(records),
                    metadata,
                )

            records.extend(page)
            identities.update(page_identities)
            next_offset = offset + len(page)
            more, expected_total = self._more_pages(
                metadata=metadata,
                page_length=len(page),
                offset=offset,
                next_offset=next_offset,
                expected_total=expected_total,
                context=context,
                page_number=page_number,
                record_count=len(records),
            )
            if not more:
                return records
            if not page or next_offset <= offset:
                self._raise(
                    context,
                    "pagination made no progress",
                    offset,
                    page_number,
                    len(records),
                    metadata,
                )
            if page_number == self.max_pages:
                self._raise(
                    context,
                    f"maximum page limit {self.max_pages} reached",
                    offset,
                    page_number,
                    len(records),
                    metadata,
                )
            offset = next_offset

        raise AssertionError("InterfaceOffsetPaginator loop exited without returning or raising")

    def _parse_response(
        self,
        response: Any,
        collection_key: str,
        context: str,
        offset: int,
        page_number: int,
        record_count: int,
        require_collection_wrapper: bool,
    ) -> tuple[list[dict[str, Any]], _PageMetadata]:
        """Validate one response and normalize its rows and page metadata."""

        if not isinstance(response, Mapping):
            self._raise(
                context,
                f"invalid response type {type(response).__name__}",
                offset,
                page_number,
                record_count,
                None,
            )
        if collection_key not in response:
            if response or require_collection_wrapper:
                self._raise(
                    context,
                    f"response lacks required {collection_key!r} wrapper",
                    offset,
                    page_number,
                    record_count,
                    None,
                )
            raw_page: Any = []
        else:
            raw_page = response.get(collection_key)
        if not isinstance(raw_page, list):
            self._raise(
                context,
                f"invalid {collection_key!r} wrapper type {type(raw_page).__name__}",
                offset,
                page_number,
                record_count,
                None,
            )
        page: list[dict[str, Any]] = []
        for index, item in enumerate(raw_page):
            if not isinstance(item, dict):
                self._raise(
                    context,
                    f"row {index} has invalid type {type(item).__name__}",
                    offset,
                    page_number,
                    record_count,
                    None,
                )
            page.append(item)
        metadata = self._metadata(response, context, offset, page_number, record_count)
        return page, metadata

    def _metadata(
        self,
        response: Mapping[str, Any],
        context: str,
        offset: int,
        page_number: int,
        record_count: int,
    ) -> _PageMetadata:
        """Return normalized ``total``, ``remaining``, and ``links.next`` evidence."""

        if "meta" in response and "metadata" in response:
            self._raise(
                context,
                "response supplies both 'meta' and 'metadata' wrappers",
                offset,
                page_number,
                record_count,
                None,
            )
        metadata_key = "meta" if "meta" in response else "metadata" if "metadata" in response else None
        if metadata_key is None:
            return _PageMetadata()
        raw_metadata = response.get(metadata_key)
        if not isinstance(raw_metadata, Mapping):
            self._raise(
                context,
                f"invalid {metadata_key!r} type {type(raw_metadata).__name__}",
                offset,
                page_number,
                record_count,
                None,
            )

        raw_counts = raw_metadata.get("counts")
        if raw_counts is not None and not isinstance(raw_counts, Mapping):
            self._raise(
                context,
                f"invalid {metadata_key}.counts type {type(raw_counts).__name__}",
                offset,
                page_number,
                record_count,
                None,
            )
        counts = raw_counts or {}
        nested_total = self._count_value(counts.get("total"), "total", context, offset, page_number, record_count)
        top_total = self._count_value(
            raw_metadata.get("total"),
            "total",
            context,
            offset,
            page_number,
            record_count,
        )
        nested_remaining = self._count_value(
            counts.get("remaining"),
            "remaining",
            context,
            offset,
            page_number,
            record_count,
        )
        top_remaining = self._count_value(
            raw_metadata.get("remaining"),
            "remaining",
            context,
            offset,
            page_number,
            record_count,
        )
        total = self._coalesce_count(
            nested_total,
            top_total,
            "total",
            context,
            offset,
            page_number,
            record_count,
        )
        remaining = self._coalesce_count(
            nested_remaining,
            top_remaining,
            "remaining",
            context,
            offset,
            page_number,
            record_count,
        )

        raw_links = raw_metadata.get("links")
        if raw_links is not None and not isinstance(raw_links, Mapping):
            self._raise(
                context,
                f"invalid {metadata_key}.links type {type(raw_links).__name__}",
                offset,
                page_number,
                record_count,
                None,
            )
        next_present: bool | None = None
        next_offset: int | None = None
        if isinstance(raw_links, Mapping) and "next" in raw_links:
            next_value = raw_links.get("next")
            if next_value is not None and not isinstance(next_value, str):
                self._raise(
                    context,
                    f"invalid {metadata_key}.links.next type {type(next_value).__name__}",
                    offset,
                    page_number,
                    record_count,
                    None,
                )
            next_present = bool(next_value)
            if next_present:
                next_offset = self._next_link_offset(next_value, context, offset, page_number, record_count)
        return _PageMetadata(
            total=total,
            remaining=remaining,
            next_present=next_present,
            next_offset=next_offset,
        )

    def _coalesce_count(
        self,
        nested: int | None,
        top_level: int | None,
        name: str,
        context: str,
        offset: int,
        page_number: int,
        record_count: int,
    ) -> int | None:
        """Combine nested and top-level count spellings while rejecting disagreement."""

        if nested is not None and top_level is not None and nested != top_level:
            self._raise(
                context,
                f"contradictory nested/top-level {name} metadata ({nested} != {top_level})",
                offset,
                page_number,
                record_count,
                None,
            )
        return nested if nested is not None else top_level

    def _next_link_offset(
        self,
        value: str,
        context: str,
        offset: int,
        page_number: int,
        record_count: int,
    ) -> int:
        """Extract one non-negative ``offset`` query value from a next-page link."""

        query = parse_qs(urlsplit(value).query, keep_blank_values=True)
        values = query.get("offset")
        if values is None or len(values) != 1:
            self._raise(
                context,
                f"links.next must contain exactly one offset query value: {value!r}",
                offset,
                page_number,
                record_count,
                None,
            )
        raw_offset = values[0].strip()
        if not raw_offset.isdigit():
            self._raise(
                context,
                f"links.next has invalid offset {values[0]!r}",
                offset,
                page_number,
                record_count,
                None,
            )
        return int(raw_offset)

    def _count_value(
        self,
        value: Any,
        name: str,
        context: str,
        offset: int,
        page_number: int,
        record_count: int,
    ) -> int | None:
        """Normalize a non-negative integer metadata count."""

        if value is None:
            return None
        if isinstance(value, bool):
            self._raise(
                context,
                f"invalid boolean {name} metadata",
                offset,
                page_number,
                record_count,
                None,
            )
        if isinstance(value, str):
            if not value.strip().isdigit():
                self._raise(
                    context,
                    f"invalid {name} metadata {value!r}",
                    offset,
                    page_number,
                    record_count,
                    None,
                )
            value = int(value.strip())
        if not isinstance(value, int) or value < 0:
            self._raise(
                context,
                f"invalid {name} metadata {value!r}",
                offset,
                page_number,
                record_count,
                None,
            )
        return value

    def _page_identities(
        self,
        page: list[dict[str, Any]],
        identity: Callable[[Mapping[str, Any]], Hashable],
        context: str,
        offset: int,
        page_number: int,
        record_count: int,
    ) -> list[Hashable]:
        """Return validated, unique-within-page identities for one page."""

        identities: list[Hashable] = []
        page_seen: set[Hashable] = set()
        for index, item in enumerate(page):
            try:
                item_identity = identity(item)
                hash(item_identity)
            except Exception as error:
                self._raise(
                    context,
                    f"row {index} has invalid identity: {error}",
                    offset,
                    page_number,
                    record_count,
                    None,
                    cause=error,
                )
            if item_identity in page_seen:
                self._raise(
                    context,
                    f"duplicate interface identity {item_identity!r} within one page",
                    offset,
                    page_number,
                    record_count,
                    None,
                )
            page_seen.add(item_identity)
            identities.append(item_identity)
        return identities

    def _more_pages(
        self,
        *,
        metadata: _PageMetadata,
        page_length: int,
        offset: int,
        next_offset: int,
        expected_total: int | None,
        context: str,
        page_number: int,
        record_count: int,
    ) -> tuple[bool, int | None]:
        """Return continuation and the stable expected total, rejecting contradictions."""

        signals: list[tuple[str, bool]] = []
        if metadata.total is not None:
            if next_offset > metadata.total:
                self._raise(
                    context,
                    "received rows exceed total metadata",
                    offset,
                    page_number,
                    record_count,
                    metadata,
                )
            page_total = metadata.total
        elif metadata.remaining is not None:
            page_total = next_offset + metadata.remaining
        else:
            page_total = None

        if page_total is not None:
            if expected_total is not None and page_total != expected_total:
                self._raise(
                    context,
                    f"pagination total changed from {expected_total} to {page_total}",
                    offset,
                    page_number,
                    record_count,
                    metadata,
                )
            expected_total = page_total
        if expected_total is not None:
            if next_offset > expected_total:
                self._raise(
                    context,
                    "received rows exceed expected total",
                    offset,
                    page_number,
                    record_count,
                    metadata,
                )
            signals.append(("total", next_offset < expected_total))
        if metadata.remaining is not None:
            signals.append(("remaining", metadata.remaining > 0))
        if metadata.next_present is not None:
            signals.append(("links.next", metadata.next_present))
            if metadata.next_present and metadata.next_offset != next_offset:
                self._raise(
                    context,
                    f"links.next offset {metadata.next_offset} does not match actual next offset {next_offset}",
                    offset,
                    page_number,
                    record_count,
                    metadata,
                )

        values = {value for _name, value in signals}
        if len(values) > 1:
            detail = ", ".join(f"{name}={value}" for name, value in signals)
            self._raise(
                context,
                f"contradictory pagination metadata ({detail})",
                offset,
                page_number,
                record_count,
                metadata,
            )
        if metadata.total is not None and metadata.remaining is not None:
            expected_remaining = metadata.total - next_offset
            if metadata.remaining != expected_remaining:
                self._raise(
                    context,
                    f"contradictory total/remaining metadata (expected remaining={expected_remaining})",
                    offset,
                    page_number,
                    record_count,
                    metadata,
                )
        if signals:
            more = signals[0][1]
            if more and page_length == 0:
                self._raise(
                    context,
                    "empty page while metadata reports more records",
                    offset,
                    page_number,
                    record_count,
                    metadata,
                )
            return more, expected_total
        return page_length >= self.page_size, expected_total

    def _raise(
        self,
        context: str,
        reason: str,
        offset: int,
        page_number: int,
        record_count: int,
        metadata: _PageMetadata | None,
        cause: Exception | None = None,
    ) -> NoReturn:
        """Raise a diagnostic pagination error without returning partial state."""

        error = InterfacePaginationError(
            f"Cannot complete {context}: {reason}; offset={offset}, page_size={self.page_size}, "
            f"pages_fetched={page_number}, unique_records={record_count}, metadata={metadata!r}."
        )
        if cause is not None:
            raise error from cause
        raise error
