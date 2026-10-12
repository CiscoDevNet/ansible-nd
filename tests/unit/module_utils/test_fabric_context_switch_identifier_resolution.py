"""Focused tests for filtered, cached IP-or-serial resolution."""

from types import SimpleNamespace
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils import fabric_context as fabric_context_module
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def _context(monkeypatch, *responses):
    rest_send = SimpleNamespace(return_code=200)
    context = FabricContext(rest_send, "fabric_1")
    pending = iter(responses)
    paths = []

    def query_get(path):
        paths.append(path)
        return next(pending)

    monkeypatch.setattr(context, "_query_get", query_get)
    return context, rest_send, paths


def _switch(ip="192.0.2.1", serial="FDO123"):
    return {"fabricManagementIp": ip, "switchId": serial}


def test_serial_identifiers_do_not_query_inventory(monkeypatch):
    context, _, paths = _context(monkeypatch)
    assert context.resolve_switch_identifiers(["FDO123", "FDO123", "  FDO456  "]) == {
        "FDO123": "FDO123",
        "  FDO456  ": "FDO456",
    }
    assert paths == []


def test_filtered_ip_resolution_is_cached_and_does_not_complete_inventory(monkeypatch):
    context, _, paths = _context(monkeypatch, {"switches": [_switch()]})
    assert context.resolve_switch_identifiers(["192.0.2.1", "FDO456", "192.0.2.1"]) == {
        "192.0.2.1": "FDO123",
        "FDO456": "FDO456",
    }
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    assert len(paths) == 1
    url = urlsplit(paths[0])
    assert url.path == "/api/v1/manage/fabrics/fabric_1/switches"
    assert parse_qs(url.query) == {"filter": ["fabricManagementIp:192.0.2.1"], "max": ["1000"], "offset": ["0"]}
    assert context._switches is None
    assert context._switch_map is None
    assert context._switch_map_by_id is None


def test_equivalent_ipv6_spellings_share_one_lookup(monkeypatch):
    context, _, paths = _context(monkeypatch, {"switches": [_switch("2001:0db8:0:0:0:0:0:1")]})
    assert context.resolve_switch_identifiers(["2001:db8::1", "2001:0db8:0:0:0:0:0:1"]) == {
        "2001:db8::1": "FDO123",
        "2001:0db8:0:0:0:0:0:1": "FDO123",
    }
    assert len(paths) == 1


@pytest.mark.parametrize("selectors", ["FDO123", [""], ["  "], [None], [1]])
def test_invalid_selectors_fail_before_lookup(monkeypatch, selectors):
    context, _, paths = _context(monkeypatch)
    with pytest.raises(ValueError, match="switch identifiers"):
        context.resolve_switch_identifiers(selectors)
    assert paths == []


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        {"switches": None},
        {"switches": [None]},
        {"switches": [{"switchId": "FDO123"}]},
        {"switches": [_switch("not-an-ip")]},
        {"switches": [_switch(serial=None)]},
        {"switches": [_switch(serial=" ")]},
    ],
)
def test_malformed_filtered_inventory_is_rejected(monkeypatch, body):
    context, _, _ = _context(monkeypatch, body)
    with pytest.raises(RuntimeError):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert context._resolved_switch_ips == {}


@pytest.mark.parametrize("serials", [("FDO123", "FDO456"), ("FDO123", "FDO123")])
def test_duplicate_matching_rows_are_ambiguous_even_with_the_same_serial(monkeypatch, serials):
    context, _, _ = _context(monkeypatch, {"switches": [_switch(serial=serial) for serial in serials]})
    with pytest.raises(RuntimeError, match="Multiple switches match"):
        context.resolve_switch_identifiers(["192.0.2.1"])


def test_unrelated_filter_rows_cannot_resolve_the_requested_ip(monkeypatch):
    context, _, _ = _context(monkeypatch, {"switches": [_switch("192.0.2.2")]})
    with pytest.raises(RuntimeError, match="No switch found"):
        context.resolve_switch_identifiers(["192.0.2.1"])


@pytest.mark.parametrize("counts", [{"remaining": 1}, {"total": 2}])
def test_metadata_pagination_and_exact_local_matching(monkeypatch, counts):
    context, _, paths = _context(
        monkeypatch,
        {"switches": [_switch("192.0.2.2")], "meta": {"counts": counts}},
        {"switches": [_switch()], "meta": {"counts": {"remaining": 0}}},
    )
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    assert [parse_qs(urlsplit(path).query)["offset"] for path in paths] == [["0"], ["1"]]


def test_full_page_without_metadata_fetches_next_page(monkeypatch):
    context, _, paths = _context(monkeypatch, {"switches": [_switch("192.0.2.2")] * 1000}, {"switches": [_switch()]})
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    assert parse_qs(urlsplit(paths[1]).query)["offset"] == ["1000"]


def test_repeated_page_is_rejected_instead_of_looping(monkeypatch):
    page = {"switches": [_switch("192.0.2.2")], "meta": {"counts": {"remaining": 1}}}
    context, _, paths = _context(monkeypatch, page, page)
    with pytest.raises(RuntimeError, match="repeated a page"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert len(paths) == 2


def test_duplicate_matching_rows_across_pages_are_rejected(monkeypatch):
    context, _, _ = _context(monkeypatch, {"switches": [_switch()], "meta": {"counts": {"remaining": 1}}}, {"switches": [_switch()]})
    with pytest.raises(RuntimeError, match="Multiple switches match"):
        context.resolve_switch_identifiers(["192.0.2.1"])


@pytest.mark.parametrize("meta", [None, {"counts": None}, {"counts": {"remaining": -1}}, {"counts": {"total": True}}])
def test_malformed_pagination_metadata_is_rejected(monkeypatch, meta):
    context, _, _ = _context(monkeypatch, {"switches": [_switch()], "meta": meta})
    with pytest.raises(RuntimeError, match="pagination"):
        context.resolve_switch_identifiers(["192.0.2.1"])


def test_empty_page_cannot_claim_more_results(monkeypatch):
    context, _, _ = _context(monkeypatch, {"switches": [], "meta": {"counts": {"remaining": 1}}})
    with pytest.raises(RuntimeError, match="empty page"):
        context.resolve_switch_identifiers(["192.0.2.1"])


def test_404_does_not_trigger_a_fabric_summary_call(monkeypatch):
    context, rest_send, paths = _context(monkeypatch, {})
    rest_send.return_code = 404
    with pytest.raises(RuntimeError, match="No switch found"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert len(paths) == 1
    assert "/switches?" in paths[0]


def test_invalidate_clears_targeted_cache(monkeypatch):
    context, _, paths = _context(monkeypatch, {"switches": [_switch()]}, {"switches": [_switch(serial="FDO456")]})
    assert context.resolve_switch_identifiers(["192.0.2.1"])["192.0.2.1"] == "FDO123"
    context.invalidate()
    assert context.resolve_switch_identifiers(["192.0.2.1"])["192.0.2.1"] == "FDO456"
    assert len(paths) == 2


def test_existing_full_inventory_lookup_is_not_satisfied_by_partial_cache(monkeypatch):
    context, _, paths = _context(monkeypatch, {"switches": [_switch()]}, {"switches": [_switch(), _switch("192.0.2.2", "FDO456")]})
    context.resolve_switch_identifiers(["192.0.2.1"])
    assert context.get_switch_id("192.0.2.2") == "FDO456"
    assert paths[-1] == "/api/v1/manage/fabrics/fabric_1/switches"


@pytest.mark.parametrize("status, success", [(200, True), (404, False), (500, False)])
def test_optional_observer_sees_completed_queries_before_error_handling(status, success):
    observations = []
    query_errors = []
    rest_send = SimpleNamespace(
        return_code=status,
        response_count=0,
        response_generation=0,
        success=success,
        response_current={"DATA": {"switches": [_switch()]}},
        error_summary="test error",
        commit=lambda: None,
    )
    context = FabricContext(
        rest_send,
        "fabric_1",
        query_observer=lambda path: observations.append((path, rest_send.verb, rest_send.return_code)),
        query_error_observer=lambda *event: query_errors.append(event),
    )
    if status == 500:
        with pytest.raises(RuntimeError, match="GET.*failed"):
            context._query_get("/test/switches")
    else:
        context._query_get("/test/switches")
    assert [(path, verb.value, code) for path, verb, code in observations] == [("/test/switches", "GET", status)]
    assert query_errors == []


class _QueryExceptionSender(Sender):
    """Exercise the real GET retry loop, including a lost later response."""

    def __init__(self, responses):
        super().__init__()
        self.calls = 0
        self.ansible_module = MockAnsibleModule()
        self.gen = ResponseGenerator(iter(responses))

    def commit(self):
        self.calls += 1
        super().commit()

    @property
    def response(self):
        # The base fixture deep-copies values, including exception objects.
        # Preserve the exact raised exception to test the observer's re-raise.
        value = self.gen.next
        if isinstance(value, BaseException):
            raise value
        return value


def _query_transport(*responses):
    sender = _QueryExceptionSender(responses)
    rest_send = RestSend({})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    rest_send.timeout = 10
    rest_send.send_interval = 1
    return rest_send, sender


def test_query_error_observer_reports_timeout_without_fresh_response():
    error = TimeoutError("Switch query response was lost")
    rest_send, sender = _query_transport(error)
    observations = []
    completed = []
    context = FabricContext(
        rest_send,
        "fabric_1",
        query_observer=completed.append,
        query_error_observer=lambda path, exc, fresh: observations.append((path, exc, fresh)),
    )
    with pytest.raises(TimeoutError) as raised:
        context._query_get("/test/switches")
    assert raised.value is error
    assert observations == [("/test/switches", error, False)]
    assert completed == []
    assert sender.calls == 1


def test_query_error_observer_sees_response_received_before_later_retry_timeout():
    first_reply = {"RETURN_CODE": 500, "MESSAGE": "Internal server error", "DATA": {"error": "Retryable query failure"}}
    error = TimeoutError("Later switch query retry response was lost")
    rest_send, sender = _query_transport(first_reply, error)
    observations = []
    context = FabricContext(rest_send, "fabric_1", query_error_observer=lambda path, exc, fresh: observations.append((path, exc, fresh)))
    with pytest.raises(TimeoutError) as raised:
        context._query_get("/test/switches")
    assert raised.value is error
    assert rest_send.response_current == first_reply
    assert observations == [("/test/switches", error, True)]
    assert sender.calls == 2


def test_missing_error_observer_preserves_legacy_timeout_behavior():
    error = TimeoutError("Switch query response was lost")
    rest_send, sender = _query_transport(error)
    completed = []
    context = FabricContext(rest_send, "fabric_1", query_observer=completed.append)
    with pytest.raises(TimeoutError) as raised:
        context._query_get("/test/switches")
    assert raised.value is error
    assert completed == []
    assert sender.calls == 1


def test_error_observer_failure_does_not_mask_primary_timeout():
    error = TimeoutError("Primary switch query response was lost")
    rest_send, sender = _query_transport(error)

    def broken_observer(path, exc, fresh):
        raise ValueError("Diagnostic observer failed")

    context = FabricContext(rest_send, "fabric_1", query_error_observer=broken_observer)
    with pytest.raises(TimeoutError) as raised:
        context._query_get("/test/switches")
    assert raised.value is error
    assert sender.calls == 1


def _platform_switch(serial="FDO123", platform="nx-os", **fields):
    return {"switchId": serial, "additionalData": {"platformType": platform}, **fields}


def test_exact_ip_record_supplies_platform_without_another_get(monkeypatch):
    switch = _platform_switch(fabricManagementIp="192.0.2.1")
    context, _, paths = _context(monkeypatch, {"switches": [switch]})
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    assert context.get_switch_platform_types(["FDO123", " FDO123 "]) == {"FDO123": PlatformType.NX_OS}
    assert len(paths) == 1
    assert context._switches is None
    assert context._switch_map is None
    assert context._switch_map_by_id is None
    switch["additionalData"]["platformType"] = "ios-xe"
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}


def test_ambiguous_ip_lookup_does_not_retain_matching_metadata(monkeypatch):
    switch = _platform_switch(fabricManagementIp="192.0.2.1")
    context, _, _ = _context(monkeypatch, {"switches": [switch, switch]})
    with pytest.raises(RuntimeError, match="Multiple switches match"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert context._resolved_switch_ips == {}
    assert context._resolved_switch_records == {}


def test_later_ip_page_error_does_not_retain_early_matching_metadata(monkeypatch):
    switch = _platform_switch(fabricManagementIp="192.0.2.1")
    context, _, _ = _context(monkeypatch, {"switches": [switch], "meta": {"counts": {"remaining": 1}}}, {"switches": None})
    with pytest.raises(RuntimeError, match="malformed switches list"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert context._resolved_switch_ips == {}
    assert context._resolved_switch_records == {}


def test_already_loaded_full_inventory_supplies_platform_without_a_get(monkeypatch):
    context, _, paths = _context(monkeypatch)
    context._switches = [_platform_switch(), _platform_switch("FDO456", "ios-xe"), {"switchId": "FDO789"}]
    assert context.get_switch_platform_types(["FDO456", "FDO123", "FDO789"]) == {
        "FDO456": PlatformType.IOS_XE,
        "FDO123": PlatformType.NX_OS,
        "FDO789": None,
    }
    assert paths == []
    assert set(context._resolved_switch_records) == {"FDO123", "FDO456", "FDO789"}


def test_duplicate_full_inventory_target_fails_without_partial_cache_commit(monkeypatch):
    context, _, paths = _context(monkeypatch)
    context._switches = [_platform_switch(), _platform_switch("FDO456"), _platform_switch("FDO456")]
    with pytest.raises(RuntimeError, match="Multiple cached switches"):
        context.get_switch_platform_types(["FDO123", "FDO456"])
    assert context._resolved_switch_records == {}
    assert paths == []


@pytest.mark.parametrize("switch_ids", ["FDO123", b"FDO123", [None], [1], [""], ["  "], ["FDO123\nFDO456"], ["FDO123\x00"]])
def test_invalid_platform_selectors_fail_without_a_get(monkeypatch, switch_ids):
    context, _, paths = _context(monkeypatch)
    with pytest.raises(ValueError, match="switch IDs"):
        context.get_switch_platform_types(switch_ids)
    assert paths == []
    assert context._resolved_switch_records == {}


def test_empty_platform_batch_needs_no_get(monkeypatch):
    context, _, paths = _context(monkeypatch)
    assert context.get_switch_platform_types([]) == {}
    assert paths == []


def test_invalidation_clears_targeted_platform_records(monkeypatch):
    context, _, paths = _context(monkeypatch, {"switches": [_platform_switch(fabricManagementIp="192.0.2.1")]})
    context.resolve_switch_identifiers(["192.0.2.1"])
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    context.invalidate()
    assert context._resolved_switch_records == {}
    assert context._resolved_switch_ips == {}
    assert context._switches is None
    assert len(paths) == 1


def test_uncached_platform_batch_uses_one_exact_get_per_distinct_serial(monkeypatch):
    first = _platform_switch("FDO456", "ios-xe")
    second = _platform_switch()
    context, _, paths = _context(monkeypatch, first, second)
    assert context.get_switch_platform_types([" FDO456 ", "FDO123", "FDO456"]) == {
        "FDO456": PlatformType.IOS_XE,
        "FDO123": PlatformType.NX_OS,
    }
    assert paths == ["/api/v1/manage/fabrics/fabric_1/switches/FDO456", "/api/v1/manage/fabrics/fabric_1/switches/FDO123"]
    assert context.get_switch_platform_types(["FDO123", "FDO456"]) == {"FDO123": PlatformType.NX_OS, "FDO456": PlatformType.IOS_XE}
    assert len(paths) == 2
    first["additionalData"]["platformType"] = "nx-os"
    assert context.get_switch_platform_types(["FDO456"]) == {"FDO456": PlatformType.IOS_XE}
    assert context._switches is None
    assert context._switch_map is None
    assert context._switch_map_by_id is None


def test_platform_batch_queries_only_serial_not_already_resolved_from_ip(monkeypatch):
    context, _, paths = _context(
        monkeypatch,
        {"switches": [_platform_switch(fabricManagementIp="192.0.2.1")]},
        _platform_switch("FDO456", "ios-xe"),
    )
    context.resolve_switch_identifiers(["192.0.2.1"])
    assert context.get_switch_platform_types(["FDO123", "FDO456"]) == {"FDO123": PlatformType.NX_OS, "FDO456": PlatformType.IOS_XE}
    assert len(paths) == 2
    assert paths[1] == "/api/v1/manage/fabrics/fabric_1/switches/FDO456"


def test_platform_batch_reuses_full_inventory_and_fetches_only_missing_serial(monkeypatch):
    context, _, paths = _context(monkeypatch, _platform_switch("FDO456", "ios-xe"))
    context._switches = [_platform_switch()]
    assert context.get_switch_platform_types(["FDO123", "FDO456"]) == {"FDO123": PlatformType.NX_OS, "FDO456": PlatformType.IOS_XE}
    assert paths == ["/api/v1/manage/fabrics/fabric_1/switches/FDO456"]


@pytest.mark.parametrize("body", [None, [], {}, {"switches": []}, {"switchId": None}, {"switchId": " "}, {"switchId": "FDO456"}])
def test_platform_detail_requires_an_exact_identified_object(monkeypatch, body):
    context, _, paths = _context(monkeypatch, body)
    with pytest.raises(RuntimeError, match="malformed or unexpected switch identity"):
        context.get_switch_platform_types(["FDO123"])
    assert paths == ["/api/v1/manage/fabrics/fabric_1/switches/FDO123"]
    assert context._resolved_switch_records == {}


def test_platform_detail_404_never_queries_fabric_summary_or_commits_cache(monkeypatch):
    context, rest_send, paths = _context(monkeypatch, {})
    rest_send.return_code = 404
    with pytest.raises(RuntimeError, match="No switch found with switchId 'FDO123'"):
        context.get_switch_platform_types(["FDO123"])
    assert paths == ["/api/v1/manage/fabrics/fabric_1/switches/FDO123"]
    assert context._resolved_switch_records == {}


def test_later_detail_failure_never_commits_earlier_records_in_the_batch(monkeypatch):
    context, _, paths = _context(monkeypatch, _platform_switch(), {"switchId": "WRONG_SERIAL"})
    with pytest.raises(RuntimeError, match="FDO456.*unexpected switch identity"):
        context.get_switch_platform_types(["FDO123", "FDO456"])
    assert len(paths) == 2
    assert context._resolved_switch_records == {}


def test_failed_uncached_batch_preserves_only_prior_successful_ip_cache(monkeypatch):
    context, _, paths = _context(
        monkeypatch,
        {"switches": [_platform_switch(fabricManagementIp="192.0.2.1")]},
        _platform_switch("FDO456"),
        {},
    )
    context.resolve_switch_identifiers(["192.0.2.1"])
    with pytest.raises(RuntimeError, match="FDO789.*unexpected switch identity"):
        context.get_switch_platform_types(["FDO123", "FDO456", "FDO789"])
    assert set(context._resolved_switch_records) == {"FDO123"}
    assert context._resolved_switch_ips == {"192.0.2.1": "FDO123"}
    assert len(paths) == 3


def test_failed_detail_batch_does_not_commit_pending_full_inventory_records(monkeypatch):
    context, _, paths = _context(monkeypatch, {})
    context._switches = [_platform_switch()]
    with pytest.raises(RuntimeError, match="unexpected switch identity"):
        context.get_switch_platform_types(["FDO123", "FDO456"])
    assert context._resolved_switch_records == {}
    assert paths == ["/api/v1/manage/fabrics/fabric_1/switches/FDO456"]


@pytest.mark.parametrize("additional", [None, {}, {"platformType": None}, {"platformType": "future-os"}, {"platformType": []}, "unknown-shape"])
def test_missing_or_unknown_platform_returns_none_without_refetching(monkeypatch, additional):
    context, _, paths = _context(monkeypatch, {"switchId": "FDO123", "additionalData": additional})
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": None}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": None}
    assert len(paths) == 1


@pytest.mark.parametrize("platform", list(PlatformType))
def test_platform_detail_uses_shared_platform_enum(monkeypatch, platform):
    context, _, paths = _context(monkeypatch, _platform_switch(platform=platform.value))
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": platform}
    assert len(paths) == 1


@pytest.mark.parametrize("serial", ["FDO123:USER_VDC", "FDO123 OR switchId:*", 'FDO123/../switchActions/deploy?x=y#z"\\'])
def test_platform_detail_encodes_serial_as_one_path_segment_not_a_filter(monkeypatch, serial):
    context, _, paths = _context(monkeypatch, _platform_switch(serial))
    assert context.get_switch_platform_types([serial]) == {serial: PlatformType.NX_OS}
    assert paths == ["/api/v1/manage/fabrics/fabric_1/switches/" + quote(serial, safe="")]
    assert urlsplit(paths[0]).query == ""


def test_platform_lookup_after_invalidation_refreshes_exact_serial(monkeypatch):
    context, _, paths = _context(monkeypatch, _platform_switch(), _platform_switch(platform="ios-xe"))
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    context.invalidate()
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.IOS_XE}
    assert len(paths) == 2


@pytest.mark.parametrize("failed", [False, True])
def test_query_elapsed_time_is_available_before_completed_or_error_observer(monkeypatch, failed):
    ticks = iter([10.0, 10.125])
    monkeypatch.setattr(fabric_context_module.time, "monotonic", lambda: next(ticks))
    error = TimeoutError("Synthetic elapsed query error")

    def commit():
        if failed:
            raise error

    rest_send = SimpleNamespace(
        return_code=200,
        response_generation=0,
        success=True,
        response_current={"DATA": {}},
        error_summary="",
        commit=commit,
    )
    completed, errors = [], []
    context = FabricContext(
        rest_send,
        "fabric_1",
        query_observer=lambda path: completed.append((path, context.last_query_elapsed_seconds)),
        query_error_observer=lambda path, exc, fresh: errors.append((path, exc, fresh, context.last_query_elapsed_seconds)),
    )
    assert context.last_query_elapsed_seconds == 0.0
    if failed:
        with pytest.raises(TimeoutError) as raised:
            context._query_get("/test/switches")
        assert raised.value is error
        assert errors == [("/test/switches", error, False, 0.125)]
        assert completed == []
    else:
        assert context._query_get("/test/switches") == {}
        assert completed == [("/test/switches", 0.125)]
        assert errors == []
    assert context.last_query_elapsed_seconds == 0.125


@pytest.mark.parametrize("first_platform, second_platform", [("ios-xe", "nx-os"), ("nx-os", "ios-xe"), (None, "nx-os"), ("nx-os", None)])
def test_conflicting_same_serial_ip_platforms_fail_without_overwriting_cache(monkeypatch, first_platform, second_platform):
    first = _platform_switch(platform=first_platform, fabricManagementIp="192.0.2.1")
    second = _platform_switch(platform=second_platform, fabricManagementIp="192.0.2.2")
    context, _, paths = _context(monkeypatch, {"switches": [first]}, {"switches": [second]})
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    with pytest.raises(RuntimeError, match="Conflicting platform.*FDO123"):
        context.resolve_switch_identifiers(["192.0.2.2"])
    assert context._resolved_switch_ips == {"192.0.2.1": "FDO123"}
    assert context._resolved_switch_records == {"FDO123": first}
    assert len(paths) == 2


@pytest.mark.parametrize("platform", ["nx-os", None])
def test_consistent_same_serial_ip_platforms_remain_valid_aliases(monkeypatch, platform):
    first = _platform_switch(platform=platform, fabricManagementIp="192.0.2.1")
    second = _platform_switch(platform=platform, fabricManagementIp="192.0.2.2")
    context, _, paths = _context(monkeypatch, {"switches": [first]}, {"switches": [second]})
    assert context.resolve_switch_identifiers(["192.0.2.1", "192.0.2.2"]) == {"192.0.2.1": "FDO123", "192.0.2.2": "FDO123"}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": None if platform is None else PlatformType.NX_OS}
    assert context._resolved_switch_records == {"FDO123": first}
    assert len(paths) == 2


@pytest.mark.parametrize("cached_platform, ip_platform", [("ios-xe", "nx-os"), ("nx-os", "ios-xe"), (None, "nx-os"), ("nx-os", None)])
def test_ip_platform_conflict_with_loaded_inventory_does_not_commit_partial_cache(monkeypatch, cached_platform, ip_platform):
    ip_record = _platform_switch(platform=ip_platform, fabricManagementIp="192.0.2.1")
    context, _, paths = _context(monkeypatch, {"switches": [ip_record]})
    context._switches = [_platform_switch(platform=cached_platform)]
    with pytest.raises(RuntimeError, match="Conflicting platform.*FDO123"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert context._resolved_switch_ips == {}
    assert context._resolved_switch_records == {}
    assert len(paths) == 1


@pytest.mark.parametrize("ip_platform, inventory_platform", [("ios-xe", "nx-os"), ("nx-os", "ios-xe"), (None, "nx-os"), ("nx-os", None)])
def test_platform_reuse_rejects_conflicting_loaded_and_partial_inventory(monkeypatch, ip_platform, inventory_platform):
    ip_record = _platform_switch(platform=ip_platform, fabricManagementIp="192.0.2.1")
    context, _, paths = _context(monkeypatch, {"switches": [ip_record]})
    context.resolve_switch_identifiers(["192.0.2.1"])
    context._switches = [_platform_switch(platform=inventory_platform)]
    with pytest.raises(RuntimeError, match="Conflicting platform.*FDO123"):
        context.get_switch_platform_types(["FDO123"])
    assert context._resolved_switch_records == {"FDO123": ip_record}
    assert context._resolved_switch_ips == {"192.0.2.1": "FDO123"}
    assert len(paths) == 1


def test_platform_conflict_does_not_commit_other_pending_inventory_records(monkeypatch):
    ip_record = _platform_switch(platform="ios-xe", fabricManagementIp="192.0.2.1")
    context, _, paths = _context(monkeypatch, {"switches": [ip_record]})
    context.resolve_switch_identifiers(["192.0.2.1"])
    context._switches = [_platform_switch("FDO456"), _platform_switch()]
    with pytest.raises(RuntimeError, match="Conflicting platform.*FDO123"):
        context.get_switch_platform_types(["FDO456", "FDO123"])
    assert context._resolved_switch_records == {"FDO123": ip_record}
    assert len(paths) == 1


def test_complete_unique_ip_lookup_precedes_platform_consistency_validation(monkeypatch):
    first = _platform_switch(platform="ios-xe", fabricManagementIp="192.0.2.1")
    conflicting = _platform_switch(fabricManagementIp="192.0.2.2")
    context, _, paths = _context(
        monkeypatch,
        {"switches": [first]},
        {"switches": [conflicting], "meta": {"counts": {"remaining": 1}}},
        {"switches": [conflicting]},
    )
    context.resolve_switch_identifiers(["192.0.2.1"])
    with pytest.raises(RuntimeError, match="Multiple switches match"):
        context.resolve_switch_identifiers(["192.0.2.2"])
    assert context._resolved_switch_records == {"FDO123": first}
    assert context._resolved_switch_ips == {"192.0.2.1": "FDO123"}
    assert len(paths) == 3


def test_invalidate_allows_a_fresh_platform_after_rejecting_an_alias_conflict(monkeypatch):
    first = _platform_switch(platform="ios-xe", fabricManagementIp="192.0.2.1")
    refreshed = _platform_switch(fabricManagementIp="192.0.2.2")
    context, _, paths = _context(monkeypatch, {"switches": [first]}, {"switches": [refreshed]}, {"switches": [refreshed]})
    context.resolve_switch_identifiers(["192.0.2.1"])
    with pytest.raises(RuntimeError, match="Conflicting platform.*FDO123"):
        context.resolve_switch_identifiers(["192.0.2.2"])
    context.invalidate()
    assert context.resolve_switch_identifiers(["192.0.2.2"]) == {"192.0.2.2": "FDO123"}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert context._resolved_switch_ips == {"192.0.2.2": "FDO123"}
    assert len(paths) == 3
