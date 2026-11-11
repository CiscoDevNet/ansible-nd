"""Breakout-owned validation and tracing over the shared cached fabric inventory."""

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import PlatformType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators import breakout_fabric_context as context_module
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.breakout_fabric_context import BreakoutFabricContext
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

_INVENTORY_PATH = "/api/v1/manage/fabrics/fabric_1/switches"


def _switch(ip="192.0.2.1", serial="FDO123", platform="nx-os"):
    return {"fabricManagementIp": ip, "switchId": serial, "additionalData": {"platformType": platform}}


def _context(monkeypatch, *responses):
    rest_send = SimpleNamespace(return_code=200)
    context = BreakoutFabricContext(rest_send, "fabric_1")
    pending = iter(responses)
    paths = []

    def query_get(path):
        paths.append(path)
        return next(pending)

    monkeypatch.setattr(context, "_query_get", query_get)
    return context, rest_send, paths


def test_serial_selectors_pass_through_without_identity_lookup(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch)
    assert context.resolve_switch_identifiers(["FDO123", "FDO123", "  FDO456  "]) == {"FDO123": "FDO123", "  FDO456  ": "FDO456"}
    assert paths == []


def test_single_ip_and_platform_share_existing_inventory(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch()]})
    assert context.resolve_switch_identifiers(["192.0.2.1", "192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert context.get_switch_id("192.0.2.1") == "FDO123"
    assert context.get_switch_ip("FDO123") == "192.0.2.1"
    assert context.get_platform_type("192.0.2.1") == PlatformType.NX_OS
    assert paths == [_INVENTORY_PATH]


def test_multiple_ips_serials_and_platforms_share_one_inventory(monkeypatch):
    rows = [_switch(), _switch("192.0.2.2", "FDO456", "ios-xe"), _switch("192.0.2.3", "FDO789", None)]
    context, _rest_send, paths = _context(monkeypatch, {"switches": rows})
    assert context.resolve_switch_identifiers(["192.0.2.1", " FDO789 ", "192.0.2.2"]) == {
        "192.0.2.1": "FDO123",
        " FDO789 ": "FDO789",
        "192.0.2.2": "FDO456",
    }
    assert context.get_switch_platform_types(["FDO123", "FDO789", "FDO456"]) == {
        "FDO123": PlatformType.NX_OS,
        "FDO789": None,
        "FDO456": PlatformType.IOS_XE,
    }
    assert context.resolve_switch_identifiers(["192.0.2.3"]) == {"192.0.2.3": "FDO789"}
    assert paths == [_INVENTORY_PATH]


def test_single_serial_platform_uses_the_same_inventory_endpoint(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch()]})
    assert context.get_switch_platform_types([" FDO123 ", "FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert paths == [_INVENTORY_PATH]


def test_equivalent_ipv6_spellings_use_raw_inventory_key_in_shared_translator(monkeypatch):
    raw_ip = "2001:0db8:0:0:0:0:0:1"
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch(raw_ip)]})
    translated = []
    original = context.get_switch_id

    def translate(switch_ip):
        translated.append(switch_ip)
        return original(switch_ip)

    monkeypatch.setattr(context, "get_switch_id", translate)
    assert context.resolve_switch_identifiers(["2001:db8::1", raw_ip]) == {"2001:db8::1": "FDO123", raw_ip: "FDO123"}
    assert translated and set(translated) == {raw_ip}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert paths == [_INVENTORY_PATH]


@pytest.mark.parametrize("selectors", ["FDO123", b"FDO123", [""], ["  "], [None], [1], ["192.0.2.1", ""], ["192.0.2.1", None]])
def test_invalid_identity_selectors_fail_before_get(monkeypatch, selectors):
    context, _rest_send, paths = _context(monkeypatch)
    with pytest.raises(ValueError, match="switch identifiers"):
        context.resolve_switch_identifiers(selectors)
    assert paths == []


def test_invalid_generator_is_consumed_before_get(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch)
    with pytest.raises(ValueError, match="switch identifiers"):
        context.resolve_switch_identifiers(value for value in ("192.0.2.1", None))
    assert paths == []


@pytest.mark.parametrize("selectors", ["FDO123", b"FDO123", [None], [1], [""], ["  "], ["FDO123\nFDO456"], ["FDO123\x00"]])
def test_invalid_platform_selectors_fail_before_get(monkeypatch, selectors):
    context, _rest_send, paths = _context(monkeypatch)
    with pytest.raises(ValueError, match="switch IDs"):
        context.get_switch_platform_types(selectors)
    assert paths == []


def test_empty_batches_do_not_read_inventory(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch)
    assert context.resolve_switch_identifiers([]) == {}
    assert context.get_switch_platform_types([]) == {}
    assert paths == []


@pytest.mark.parametrize("serials", [("FDO123", "FDO456"), ("FDO123", "FDO123")])
def test_duplicate_requested_ip_rows_remain_ambiguous(monkeypatch, serials):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch(serial=serial) for serial in serials]})
    with pytest.raises(RuntimeError, match="Multiple switches match"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert paths == [_INVENTORY_PATH]


def test_duplicate_canonical_ipv6_rows_remain_ambiguous(monkeypatch):
    rows = [_switch("2001:db8::1"), _switch("2001:0db8:0:0:0:0:0:1", "FDO456")]
    context, _rest_send, paths = _context(monkeypatch, {"switches": rows})
    with pytest.raises(RuntimeError, match="Multiple switches match"):
        context.resolve_switch_identifiers(["2001:db8::1"])
    assert paths == [_INVENTORY_PATH]


def test_missing_ip_is_not_resolved_by_unrelated_inventory(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch("192.0.2.2")]})
    with pytest.raises(RuntimeError, match="No switch found.*192.0.2.1"):
        context.resolve_switch_identifiers(["192.0.2.1"])
    assert paths == [_INVENTORY_PATH]


def test_missing_serial_is_not_satisfied_by_other_platform_metadata(monkeypatch):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch()]})
    with pytest.raises(RuntimeError, match="No switch found.*FDO456"):
        context.get_switch_platform_types(["FDO123", "FDO456"])
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert paths == [_INVENTORY_PATH]


@pytest.mark.parametrize("platform", ["nx-os", None])
def test_consistent_ip_aliases_for_same_serial_are_allowed(monkeypatch, platform):
    rows = [_switch(platform=platform), _switch("192.0.2.2", platform=platform)]
    context, _rest_send, paths = _context(monkeypatch, {"switches": rows})
    assert context.resolve_switch_identifiers(["192.0.2.1", "192.0.2.2"]) == {"192.0.2.1": "FDO123", "192.0.2.2": "FDO123"}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": None if platform is None else PlatformType.NX_OS}
    assert paths == [_INVENTORY_PATH]


@pytest.mark.parametrize("platforms", [("nx-os", "ios-xe"), ("ios-xe", "nx-os"), (None, "nx-os"), ("nx-os", None)])
def test_conflicting_same_serial_alias_platforms_fail(monkeypatch, platforms):
    rows = [_switch(platform=platforms[0]), _switch("192.0.2.2", platform=platforms[1])]
    context, _rest_send, paths = _context(monkeypatch, {"switches": rows})
    with pytest.raises(RuntimeError, match="Conflicting platform.*FDO123"):
        context.get_switch_platform_types(["FDO123"])
    assert paths == [_INVENTORY_PATH]


def test_duplicate_serial_without_distinct_ip_aliases_is_ambiguous(monkeypatch):
    rows = [{"switchId": "FDO123", "additionalData": {"platformType": "nx-os"}}] * 2
    context, _rest_send, paths = _context(monkeypatch, {"switches": rows})
    with pytest.raises(RuntimeError, match="Multiple.*switch"):
        context.get_switch_platform_types(["FDO123"])
    assert paths == [_INVENTORY_PATH]


def test_single_serial_metadata_does_not_require_a_management_ip(monkeypatch):
    row = {"switchId": "FDO123", "additionalData": {"platformType": "nx-os"}}
    context, _rest_send, paths = _context(monkeypatch, {"switches": [row]})
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    assert paths == [_INVENTORY_PATH]


@pytest.mark.parametrize("additional", [None, {}, {"platformType": None}, {"platformType": "future-os"}, {"platformType": []}])
def test_unknown_platform_is_not_requeried(monkeypatch, additional):
    row = {**_switch(), "additionalData": additional}
    context, _rest_send, paths = _context(monkeypatch, {"switches": [row]})
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": None}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": None}
    assert paths == [_INVENTORY_PATH]


@pytest.mark.parametrize("platform", list(PlatformType))
def test_platform_values_use_existing_enum(monkeypatch, platform):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch(platform=platform.value)]})
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": platform}
    assert paths == [_INVENTORY_PATH]


@pytest.mark.parametrize("serial", ["FDO123:USER_VDC", "FDO123 OR switchId:*", 'FDO123/../switchActions/deploy?x=y#z"\\'])
def test_serials_are_exact_local_matches_never_query_syntax(monkeypatch, serial):
    context, _rest_send, paths = _context(monkeypatch, {"switches": [_switch(serial=serial)]})
    assert context.get_switch_platform_types([serial]) == {serial: PlatformType.NX_OS}
    assert paths == [_INVENTORY_PATH]


def test_invalidation_refreshes_identity_and_platform_together(monkeypatch):
    context, _rest_send, paths = _context(
        monkeypatch,
        {"switches": [_switch()]},
        {"switches": [_switch(serial="FDO456", platform="ios-xe")]},
    )
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO123"}
    assert context.get_switch_platform_types(["FDO123"]) == {"FDO123": PlatformType.NX_OS}
    context.invalidate()
    assert context.resolve_switch_identifiers(["192.0.2.1"]) == {"192.0.2.1": "FDO456"}
    assert context.get_switch_platform_types(["FDO456"]) == {"FDO456": PlatformType.IOS_XE}
    assert paths == [_INVENTORY_PATH, _INVENTORY_PATH]


class _QueryExceptionSender(Sender):
    """Exercise the real GET loop, including a lost response."""

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


def test_query_error_observer_reports_timeout_without_stale_response():
    error = TimeoutError("Switch query response was lost")
    rest_send, sender = _query_transport(error)
    observed, completed = [], []
    context = BreakoutFabricContext(
        rest_send,
        "fabric_1",
        query_observer=completed.append,
        query_error_observer=lambda path, exc, fresh: observed.append((path, exc, fresh)),
    )
    with pytest.raises(TimeoutError) as raised:
        context._query_get(_INVENTORY_PATH)
    assert raised.value is error
    assert observed == [(_INVENTORY_PATH, error, False)]
    assert completed == []
    assert sender.calls == 1


def test_error_observer_cannot_replace_original_timeout():
    error = TimeoutError("Primary switch query response was lost")
    rest_send, sender = _query_transport(error)

    def broken_observer(path, exc, fresh):
        raise ValueError("Diagnostic observer failed")

    context = BreakoutFabricContext(rest_send, "fabric_1", query_error_observer=broken_observer)
    with pytest.raises(TimeoutError) as raised:
        context._query_get(_INVENTORY_PATH)
    assert raised.value is error
    assert sender.calls == 1


@pytest.mark.parametrize("status, success", [(200, True), (404, False), (500, False)])
def test_completed_http_query_is_observed_even_when_status_fails(status, success):
    completed, errors = [], []
    rest_send = SimpleNamespace(
        return_code=status,
        response_count=0,
        success=success,
        response_current={"DATA": {"switches": [_switch()]}},
        error_summary="test error",
        commit=lambda: None,
    )
    context = BreakoutFabricContext(
        rest_send,
        "fabric_1",
        query_observer=lambda path: completed.append((path, rest_send.verb.value, status)),
        query_error_observer=lambda *event: errors.append(event),
    )
    if status == 500:
        with pytest.raises(RuntimeError, match="GET.*failed"):
            context._query_get(_INVENTORY_PATH)
    else:
        context._query_get(_INVENTORY_PATH)
    assert completed == [(_INVENTORY_PATH, "GET", status)]
    assert errors == []


@pytest.mark.parametrize("failed", [False, True])
def test_elapsed_time_is_available_to_query_observers(monkeypatch, failed):
    ticks = iter([10.0, 10.125])
    monkeypatch.setattr(context_module.time, "monotonic", lambda: next(ticks))
    error = TimeoutError("Synthetic elapsed query error")

    def commit():
        if failed:
            raise error

    rest_send = SimpleNamespace(return_code=200, response_count=0, success=True, response_current={"DATA": {}}, error_summary="", commit=commit)
    completed, errors = [], []
    context = BreakoutFabricContext(
        rest_send,
        "fabric_1",
        query_observer=lambda path: completed.append((path, context.last_query_elapsed_seconds)),
        query_error_observer=lambda path, exc, fresh: errors.append((path, exc, fresh, context.last_query_elapsed_seconds)),
    )
    if failed:
        with pytest.raises(TimeoutError) as raised:
            context._query_get(_INVENTORY_PATH)
        assert raised.value is error
        assert errors == [(_INVENTORY_PATH, error, False, 0.125)]
        assert completed == []
    else:
        assert context._query_get(_INVENTORY_PATH) == {}
        assert completed == [(_INVENTORY_PATH, 0.125)]
        assert errors == []


def test_real_transport_observes_one_inventory_for_ip_and_platform():
    response = {
        "RETURN_CODE": 200,
        "METHOD": "GET",
        "REQUEST_PATH": _INVENTORY_PATH,
        "MESSAGE": "OK",
        "DATA": {"switches": [_switch(), _switch("192.0.2.2", "FDO456")]},
    }
    rest_send, sender = _query_transport(response)
    observations = []
    context = BreakoutFabricContext(rest_send, "fabric_1", query_observer=observations.append)
    assert context.resolve_switch_identifiers(["192.0.2.1", "192.0.2.2"]) == {"192.0.2.1": "FDO123", "192.0.2.2": "FDO456"}
    assert context.get_switch_platform_types(["FDO123", "FDO456"]) == {"FDO123": PlatformType.NX_OS, "FDO456": PlatformType.NX_OS}
    assert observations == [_INVENTORY_PATH]
    assert sender.calls == 1
