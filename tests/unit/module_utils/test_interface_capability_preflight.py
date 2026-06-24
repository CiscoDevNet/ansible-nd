# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for interface_capability_preflight.py.

Verifies that `InterfaceCapabilityPreflight` drives `RestSend` correctly for the capableSwitches endpoint,
caches results per `(interface_type, mode)`, enforces the taxonomy table client-side, and raises
`RuntimeError` from `validate` with an aggregate message listing offending switches.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_capability_preflight import InterfaceCapabilityPreflight
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_preflight(key: str):
    """Load fixture data for interface_capability_preflight tests."""
    return load_fixture("test_interface_capability_preflight")[key]


def _build_rest_send(gen_responses: ResponseGenerator) -> RestSend:
    """Build a RestSend instance wired to a file-based Sender and ResponseHandler."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


# =============================================================================
# Test: Initialization
# =============================================================================


def test_interface_capability_preflight_00010() -> None:
    """
    # Summary

    Verify `InterfaceCapabilityPreflight` initializes with `rest_send` and `fabric_name` without fetching.

    ## Test

    - `fabric_name` returns the value passed at construction
    - Internal cache is empty
    - No HTTP calls are made during `__init__`

    ## Classes and Methods

    - InterfaceCapabilityPreflight.__init__()
    - InterfaceCapabilityPreflight.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")

    assert instance.fabric_name == "fabric_1"
    assert instance._cache == {}  # pylint: disable=protected-access


# =============================================================================
# Test: Taxonomy enforcement
# =============================================================================


@pytest.mark.parametrize(
    "interface_type,mode",
    [
        ("loopback", "managed"),
        ("svi", "managed"),
        ("tunnel", "managed"),
        ("ethernet", "trunk"),
        ("ethernet", "access"),
        ("ethernet", "routed"),
        ("ethernet", "fex"),
        ("ethernet", "pvlan"),
        ("ethernet", "dot1qTunnel"),
        ("ethernet", "unmanaged"),
        ("portChannel", "trunk"),
        ("portChannel", "access"),
        ("portChannel", "routed"),
        ("portChannel", "fex"),
        ("portChannel", "pvlan"),
        ("portChannel", "dot1qTunnel"),
        ("portChannel", "unmanaged"),
    ],
    ids=lambda v: v,
)
def test_interface_capability_preflight_00050_taxonomy_valid(interface_type: str, mode: str) -> None:
    """
    # Summary

    Verify `_check_taxonomy` accepts every valid `(interface_type, mode)` pair from the captured ND 4.2 taxonomy.

    ## Test

    - Each parametrized pair raises nothing when passed to `_check_taxonomy`

    ## Classes and Methods

    - InterfaceCapabilityPreflight._check_taxonomy
    """
    with does_not_raise():
        InterfaceCapabilityPreflight._check_taxonomy(interface_type, mode)  # pylint: disable=protected-access


@pytest.mark.parametrize(
    "interface_type,mode,match",
    [
        ("vpc", "managed", r"Unsupported interface_type 'vpc'"),
        ("breakout", "managed", r"Unsupported interface_type 'breakout'"),
        ("subinterface", "routed", r"Unsupported interface_type 'subinterface'"),
        ("loopback", "trunk", r"Unsupported mode 'trunk' for interface_type 'loopback'"),
        ("svi", "access", r"Unsupported mode 'access' for interface_type 'svi'"),
        ("ethernet", "managed", r"Unsupported mode 'managed' for interface_type 'ethernet'"),
        ("portChannel", "bogusMode", r"Unsupported mode 'bogusMode' for interface_type 'portChannel'"),
    ],
    ids=lambda v: v if isinstance(v, str) and "Unsupported" not in v else "",
)
def test_interface_capability_preflight_00060_taxonomy_invalid(interface_type: str, mode: str, match: str) -> None:
    """
    # Summary

    Verify `_check_taxonomy` raises `ValueError` for unsupported interface types and unsupported modes.

    ## Test

    - Unsupported interface_type raises ValueError mentioning the type
    - Unsupported mode for a known type raises ValueError mentioning the mode and the type

    ## Classes and Methods

    - InterfaceCapabilityPreflight._check_taxonomy
    """
    with pytest.raises(ValueError, match=match):
        InterfaceCapabilityPreflight._check_taxonomy(interface_type, mode)  # pylint: disable=protected-access


# =============================================================================
# Test: get_capable_switches / get_capable_switch_ids
# =============================================================================


def test_interface_capability_preflight_00100() -> None:
    """
    # Summary

    Verify `get_capable_switches` fetches and caches the switch list for `(loopback, managed)`.

    ## Test

    - GET to `/api/v1/manage/fabrics/{fabric}/capableSwitches?interfaceType=loopback&mode=managed` returns 200 with two switches
    - `get_capable_switches` returns the full record list
    - `get_capable_switch_ids` derives the set of switchIds

    ## Classes and Methods

    - InterfaceCapabilityPreflight.get_capable_switches
    - InterfaceCapabilityPreflight.get_capable_switch_ids
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
        records = instance.get_capable_switches("loopback", "managed")
        ids = instance.get_capable_switch_ids("loopback", "managed")

    assert records == [
        {"model": "N9K-C9300v", "switchId": "FDO12345ABC", "switchName": "BG1"},
        {"model": "N9K-C9300v", "switchId": "FDO12345ABD", "switchName": "BG2"},
    ]
    assert ids == {"FDO12345ABC", "FDO12345ABD"}


def test_interface_capability_preflight_00110() -> None:
    """
    # Summary

    Verify a second access to `get_capable_switches` for the same `(interface_type, mode)` is a cache hit (does not re-fetch).

    ## Test

    - Single response yielded by the generator
    - First call to `get_capable_switches("loopback", "managed")` consumes the response
    - Second call returns equal data from cache without consuming another response
    - Each call returns a fresh list object (defensive copy; see test_00310)

    ## Classes and Methods

    - InterfaceCapabilityPreflight.get_capable_switches
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
        first = instance.get_capable_switches("loopback", "managed")
        cached = instance.get_capable_switches("loopback", "managed")

    assert first == cached
    assert cached is not first


def test_interface_capability_preflight_00120() -> None:
    """
    # Summary

    Verify `get_capable_switches` issues a separate request per `(interface_type, mode)` pair and caches each independently.

    ## Test

    - First call for `(loopback, managed)` and second call for `(ethernet, trunk)` produce two different cache entries
    - Each is a separate API call

    ## Classes and Methods

    - InterfaceCapabilityPreflight.get_capable_switches
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_preflight(f"{method_name}a")
        yield responses_preflight(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
        loopback_switches = instance.get_capable_switches("loopback", "managed")
        ethernet_switches = instance.get_capable_switches("ethernet", "trunk")

    assert {sw["switchId"] for sw in loopback_switches} == {"FDO12345ABC", "FDO12345ABD"}
    assert {sw["switchId"] for sw in ethernet_switches} == {"FDO12345ABC", "FDO12345ABD", "FDO12345ABE"}


def test_interface_capability_preflight_00130() -> None:
    """
    # Summary

    Verify `invalidate` drops cached state so the next access re-fetches.

    ## Test

    - First `get_capable_switches("loopback", "managed")` returns one-switch response and caches it
    - `invalidate()` clears the cache
    - Second `get_capable_switches("loopback", "managed")` returns two-switch response

    ## Classes and Methods

    - InterfaceCapabilityPreflight.invalidate
    - InterfaceCapabilityPreflight.get_capable_switches
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_preflight(f"{method_name}a")
        yield responses_preflight(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
    with does_not_raise():
        first = instance.get_capable_switch_ids("loopback", "managed")
        instance.invalidate()
        second = instance.get_capable_switch_ids("loopback", "managed")

    assert first == {"FDO12345ABC"}
    assert second == {"FDO12345ABC", "FDO12345ABD"}


# =============================================================================
# Test: validate()
# =============================================================================


def test_interface_capability_preflight_00200() -> None:
    """
    # Summary

    Verify `validate` returns silently when every requested switch_id is in the capable set.

    ## Test

    - capableSwitches returns two switches: FDO12345ABC, FDO12345ABD
    - `validate("loopback", "managed", {"FDO12345ABC"})` does not raise

    ## Classes and Methods

    - InterfaceCapabilityPreflight.validate
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
        instance.validate("loopback", "managed", {"FDO12345ABC"})


def test_interface_capability_preflight_00210() -> None:
    """
    # Summary

    Verify `validate` raises `RuntimeError` listing the offending switch_id when `fabric_context` is not injected.

    ## Test

    - capableSwitches returns one switch: FDO12345ABC
    - `validate("loopback", "managed", {"FDO12345ABC", "FDO99999XYZ"})` raises with FDO99999XYZ named
    - Error message references the fabric, the (interface_type, mode), and the endpoint path

    ## Classes and Methods

    - InterfaceCapabilityPreflight.validate
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
    match = r"interface_type='loopback'.*mode='managed'.*fabric_1.*switchId=FDO99999XYZ"
    with pytest.raises(RuntimeError, match=match):
        instance.validate("loopback", "managed", {"FDO12345ABC", "FDO99999XYZ"})


def test_interface_capability_preflight_00220() -> None:
    """
    # Summary

    Verify `validate` enriches the offender description with `switch_ip` when `fabric_context` is injected.

    ## Test

    - capableSwitches returns one switch: FDO12345ABC
    - fabric_context maps FDO99999XYZ -> 10.0.0.99 (via fabric switches list)
    - `validate("loopback", "managed", {"FDO99999XYZ"})` raises with "switch_ip=10.0.0.99" in the message

    ## Classes and Methods

    - InterfaceCapabilityPreflight.validate
    """
    method_name = inspect.stack()[0][3]

    def responses():
        # First: capableSwitches GET
        yield responses_preflight(f"{method_name}a")
        # Second: fabric switches list GET (driven by FabricContext.switch_map_by_id lookup)
        yield responses_preflight(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    fabric_context = FabricContext(rest_send=rest_send, fabric_name="fabric_1")
    instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1", fabric_context=fabric_context)
    match = r"switchId=FDO99999XYZ, switch_ip=10\.0\.0\.99"
    with pytest.raises(RuntimeError, match=match):
        instance.validate("loopback", "managed", {"FDO99999XYZ"})


def test_interface_capability_preflight_00230() -> None:
    """
    # Summary

    Verify `validate` raises `ValueError` on an unsupported `(interface_type, mode)` pair before any HTTP call.

    ## Test

    - No response yielded (no HTTP call should be made)
    - `validate("loopback", "trunk", {"FDO12345ABC"})` raises ValueError mentioning the unsupported mode

    ## Classes and Methods

    - InterfaceCapabilityPreflight.validate
    - InterfaceCapabilityPreflight._check_taxonomy
    """
    gen_responses = ResponseGenerator(iter([]))
    rest_send = _build_rest_send(gen_responses)

    instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
    match = r"Unsupported mode 'trunk' for interface_type 'loopback'"
    with pytest.raises(ValueError, match=match):
        instance.validate("loopback", "trunk", {"FDO12345ABC"})


# =============================================================================
# Test: HTTP 404 from the capableSwitches endpoint
# =============================================================================


def test_interface_capability_preflight_00300() -> None:
    """
    # Summary

    Verify a 404 response from the capableSwitches endpoint raises `RuntimeError` rather than caching
    an empty capable set (which would mislabel every requested switch as "not capable").

    ## Test

    - GET capableSwitches returns 404
    - `get_capable_switches` raises RuntimeError mentioning the path and issue #273

    ## Classes and Methods

    - InterfaceCapabilityPreflight._query_get
    - InterfaceCapabilityPreflight.get_capable_switches
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
    match = r"GET /api/v1/manage/fabrics/fabric_1/capableSwitches.*failed.*issue #273"
    with pytest.raises(RuntimeError, match=match):
        instance.get_capable_switches("loopback", "managed")


# =============================================================================
# Test: returned collections are defensive copies
# =============================================================================


def test_interface_capability_preflight_00310() -> None:
    """
    # Summary

    Verify `get_capable_switches` and `get_capable_switch_ids` return fresh collections per call so a caller
    that mutates the result cannot corrupt cached state for subsequent callers.

    ## Test

    - First `get_capable_switches` returns two-switch list; mutate the returned list (`.append(...)`)
    - Second `get_capable_switches` returns the original (un-mutated) two-switch list from cache
    - Same for `get_capable_switch_ids` (mutate the returned set)

    ## Classes and Methods

    - InterfaceCapabilityPreflight.get_capable_switches
    - InterfaceCapabilityPreflight.get_capable_switch_ids
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
        first_list = instance.get_capable_switches("loopback", "managed")
        first_list.append({"switchId": "BOGUS", "switchName": "BOGUS", "model": "BOGUS"})
        first_list.clear()
        second_list = instance.get_capable_switches("loopback", "managed")

        first_ids = instance.get_capable_switch_ids("loopback", "managed")
        first_ids.add("BOGUS")
        first_ids.clear()
        second_ids = instance.get_capable_switch_ids("loopback", "managed")

    assert second_list == [
        {"model": "N9K-C9300v", "switchId": "FDO12345ABC", "switchName": "BG1"},
        {"model": "N9K-C9300v", "switchId": "FDO12345ABD", "switchName": "BG2"},
    ]
    assert second_ids == {"FDO12345ABC", "FDO12345ABD"}


def test_interface_capability_preflight_00320() -> None:
    """
    # Summary

    Verify `get_capable_switches` deep-copies cached records, so mutating a returned record dict cannot corrupt
    cached state or the derived `get_capable_switch_ids` set. Regression guard for the shallow-copy defect: a
    `list(self._cache[key])` copy shares the record dicts by reference (PR #275 review).

    ## Test

    - First `get_capable_switches` call returns two records; mutate a returned record in place (`["switchId"] = "HACKED"`)
    - Second `get_capable_switches` returns the original, un-mutated records from cache
    - `get_capable_switch_ids` (built after the mutation) yields the original IDs, proving the mutation did not
      leak into the cache used to derive them

    ## Classes and Methods

    - InterfaceCapabilityPreflight.get_capable_switches
    - InterfaceCapabilityPreflight.get_capable_switch_ids
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        yield responses_preflight(key)

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = InterfaceCapabilityPreflight(rest_send=rest_send, fabric_name="fabric_1")
        first_list = instance.get_capable_switches("loopback", "managed")
        # Mutate the returned record dicts in place -- must not touch the cache.
        first_list[0]["switchId"] = "HACKED"
        first_list[1]["switchName"] = "HACKED"
        del first_list[0]["model"]

        second_list = instance.get_capable_switches("loopback", "managed")
        # ids are derived from the cache *after* the mutation above
        ids = instance.get_capable_switch_ids("loopback", "managed")

    assert second_list == [
        {"model": "N9K-C9300v", "switchId": "FDO12345ABC", "switchName": "BG1"},
        {"model": "N9K-C9300v", "switchId": "FDO12345ABD", "switchName": "BG2"},
    ]
    assert ids == {"FDO12345ABC", "FDO12345ABD"}
