# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: GPL-3.0-or-later

"""Complete bootstrap observations before making POAP membership decisions."""

from copy import deepcopy
import logging
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.manage_switches import utils as bootstrap_utils
from ansible_collections.cisco.nd.plugins.module_utils.manage_switches.utils import (
    SwitchOperationError,
    query_bootstrap_switches,
)


class BootstrapND:
    """Serve controller pages by offset without simulating any write operation."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = []
        self.module = SimpleNamespace(fail_json=self.unexpected_fail_json)

    @staticmethod
    def unexpected_fail_json(**_kwargs):
        """The resource boundary, not a read helper, must format final failures."""
        raise AssertionError("bootstrap reader called fail_json directly")

    def request(self, *, path, verb):
        """Return exactly one isolated page for the requested offset."""
        self.calls.append((path, verb))
        offset = int(parse_qs(urlsplit(path).query).get("offset", [0])[0])
        response = self.pages[offset]
        if isinstance(response, Exception):
            raise response
        return deepcopy(response)


def switch(serial):
    """Build the smallest useful raw bootstrap record."""
    return {"serialNumber": serial}


def page(serials, *, total=None, remaining=None, next_link=None):
    """Build optional count/link metadata around a bootstrap switch page."""
    result = {"switches": [switch(serial) for serial in serials]}
    meta = {}
    if total is not None or remaining is not None:
        meta["counts"] = {"total": total, "remaining": remaining}
    if next_link is not None:
        meta["links"] = {"next": next_link}
    if meta:
        result["meta"] = meta
    return result


def query(nd):
    """Call the real Native public helper."""
    return query_bootstrap_switches(nd, "FAB1", logging.getLogger(__name__))


@pytest.mark.parametrize("target_first", [False, True])
def test_review_bootstrap_counts_include_candidate_on_either_page(target_first):
    """A later-page recovery candidate cannot look like an offline no-op."""
    serials = ["REAL1", "OTHER1"] if target_first else ["OTHER1", "REAL1"]
    nd = BootstrapND({0: page(serials[:1], total=2, remaining=1), 1: page(serials[1:], total=2, remaining=0)})
    assert query(nd) == [switch(serial) for serial in serials]
    assert [parse_qs(urlsplit(path).query)["offset"] for path, _verb in nd.calls] == [["0"], ["1"]]
    assert all(parse_qs(urlsplit(path).query)["max"] == ["500"] for path, _verb in nd.calls)


@pytest.mark.parametrize(
    "next_link",
    [
        "?offset=1&max=500",
        "bootstrap?offset=1&max=500",
        "/api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
        "https://nd.example/api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
    ],
)
def test_review_bootstrap_next_only_links_are_scoped_local_cursors(next_link):
    """Validated next cursors never forward a response-provided authority."""
    nd = BootstrapND({0: page(["OTHER1"], next_link=next_link), 1: page(["REAL1"])})
    assert query(nd) == [switch("OTHER1"), switch("REAL1")]
    assert len(nd.calls) == 2
    assert all(path.startswith("/api/v1/manage/fabrics/FAB1/bootstrap?") for path, _verb in nd.calls)
    assert all("nd.example" not in path for path, _verb in nd.calls)


def test_review_bootstrap_full_metadata_free_page_is_exhausted():
    """A full requested page needs another observation even without metadata."""
    records = [switch(f"SERIAL{index}") for index in range(500)]
    nd = BootstrapND({0: records, 500: []})
    assert query(nd) == records
    assert len(nd.calls) == 2


def test_review_bootstrap_page_budget_rejects_an_unbounded_changing_scope(monkeypatch):
    """Unique full pages cannot turn a single candidate observation into endless polling."""
    monkeypatch.setattr(bootstrap_utils, "_BOOTSTRAP_MAX_PAGES", 2)
    nd = BootstrapND({offset: [switch(f"SERIAL{index}") for index in range(offset, offset + 500)] for offset in (0, 500)})
    with pytest.raises(SwitchOperationError, match="page budget"):
        query(nd)
    assert len(nd.calls) == 2


@pytest.mark.parametrize("advertised_max,requested_max", [(1, 1), (500, 500), (1000, 500)])
def test_review_bootstrap_next_page_limit_is_honored_with_a_client_cap(advertised_max, requested_max):
    """The response cannot expand the client page size or hide a full small page."""
    nd = BootstrapND(
        {
            0: page(["OTHER1"], total=2, remaining=1, next_link=f"?offset=1&max={advertised_max}"),
            1: page(["REAL1"], total=2, remaining=0),
        }
    )
    assert query(nd) == [switch("OTHER1"), switch("REAL1")]
    assert parse_qs(urlsplit(nd.calls[1][0]).query)["max"] == [str(requested_max)]


def test_review_bootstrap_next_small_full_page_without_counts_is_exhausted():
    """A next cursor's smaller maximum governs metadata-free exhaustion."""
    nd = BootstrapND({0: page(["OTHER1"], next_link="?offset=1&max=1"), 1: page(["REAL1"]), 2: []})
    assert query(nd) == [switch("OTHER1"), switch("REAL1")]
    assert [parse_qs(urlsplit(path).query)["offset"] for path, _verb in nd.calls] == [["0"], ["1"], ["2"]]


def test_review_bootstrap_declared_total_survives_missing_later_metadata():
    """A later short page cannot hide rows from an already observed total."""
    nd = BootstrapND({0: page(["FIRST"], total=3, remaining=2), 1: page(["SECOND"]), 2: page(["REAL1"])})
    assert query(nd) == [switch("FIRST"), switch("SECOND"), switch("REAL1")]
    assert len(nd.calls) == 3


def test_review_bootstrap_legacy_metadata_and_serial_aliases_remain_supported():
    """Legacy wrappers keep their raw list contract once the scope is complete."""
    response = {"switches": [{"serial_number": "REAL1"}], "metadata": {"counts": {"total": 1, "remaining": 0}}}
    assert query(BootstrapND({0: response})) == response["switches"]


@pytest.mark.parametrize("response", [[], [switch("REAL1")], {"switches": []}, {"switches": [switch("REAL1")]}, page(["REAL1"], total=1, remaining=0)])
def test_review_bootstrap_complete_bare_or_wrapped_pages_remain_supported(response):
    """Ordinary bare lists and metadata-free short responses remain valid."""
    nd = BootstrapND({0: response})
    assert query(nd) == ([] if response == [] or response == {"switches": []} else [switch("REAL1")])
    assert len(nd.calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        None,
        "unexpected",
        {},
        {"switches": None},
        {"switches": [None]},
        {"switches": [{}]},
        {"switches": [{"serialNumber": ""}]},
        {"switches": [{"serialNumber": " "}]},
        {"switches": [{"serialNumber": " REAL1 "}]},
        {"switches": [{"serialNumber": False}]},
        {"switches": [switch("REAL1"), switch("REAL1")]},
        {"switches": [], "meta": None},
        {"switches": [], "meta": []},
        {"switches": [], "meta": {"counts": {}}},
        {"switches": [], "meta": {"counts": {"total": True, "remaining": 0}}},
        {"switches": [], "meta": {"counts": {"total": 0, "remaining": -1}}},
        {"switches": [], "meta": {"links": []}},
        {"switches": [], "meta": {"links": {"next": False}}},
        {"switches": [], "meta": {"links": {"next": None}}},
    ],
)
def test_review_bootstrap_malformed_scope_is_not_an_empty_candidate_list(response):
    """Malformed observations cannot authorize an absence or fallback decision."""
    with pytest.raises(SwitchOperationError):
        query(BootstrapND({0: response}))


@pytest.mark.parametrize(
    "pages",
    [
        {0: page(["OTHER1"], total=2, remaining=1), 1: page(["REAL1"], total=3, remaining=1)},
        {0: page(["OTHER1"], total=2, remaining=1), 1: page(["OTHER1"], total=2, remaining=0)},
        {0: page(["OTHER1"], total=2, remaining=1), 1: page([], total=2, remaining=1)},
        {0: page([], total=1, remaining=1)},
        {0: page(["REAL1"], total=1, remaining=0, next_link="?offset=1&max=500")},
        {0: page(["OTHER1"], total=2, remaining=1), 1: {"switches": []}},
    ],
)
def test_review_bootstrap_partial_or_changing_pages_are_rejected(pages):
    """Only a complete stable sequence can become authoritative evidence."""
    with pytest.raises(SwitchOperationError):
        query(BootstrapND(pages))


@pytest.mark.parametrize(
    "next_link",
    [
        "?offset=0&max=500",
        "?offset=2&max=500",
        "?offset=1&offset=2&max=500",
        "?offset=1&max=0",
        "?offset=1&max=500&filter=other",
        "/api/v1/manage/fabrics/OTHER/bootstrap?offset=1&max=500",
        "/api/v1/manage/fabrics/FAB1/switches?offset=1&max=500",
        "https://user:password@nd.example/api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
        "https://nd.example/api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500#fragment",
        "file:///api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
        "https:///api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
        "//nd.example/api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
        "https://nd.example:invalid/api/v1/manage/fabrics/FAB1/bootstrap?offset=1&max=500",
    ],
)
def test_review_bootstrap_next_link_cannot_change_scope_or_skip_rows(next_link):
    """Unsafe or non-progressing cursors fail before a second request."""
    nd = BootstrapND({0: page(["OTHER1"], next_link=next_link)})
    with pytest.raises(SwitchOperationError):
        query(nd)
    assert len(nd.calls) == 1


def test_review_bootstrap_transport_failure_raises_to_the_results_boundary():
    """Read failures do not discard previously accumulated Native mutations."""
    with pytest.raises(SwitchOperationError, match="Failed to query bootstrap switches"):
        query(BootstrapND({0: RuntimeError("read failed")}))
