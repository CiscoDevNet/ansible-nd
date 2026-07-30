# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Cisco Systems, Inc.

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `L3OutOrchestrator`.

Verifies that the orchestrator drives `RestSend` correctly for L3Out CRUD operations,
wraps create payloads in the `{"l3Outs": [...]}` envelope, validates 207 multi-status
bulk responses, and filters `query_all` results by fabric name.

Scope: methods defined in `manage_l3out.py` only.
"""

# pylint: disable=disallowed-name,protected-access,redefined-outer-name,too-many-lines
# pylint: disable=assignment-from-no-return,use-implicit-booleaness-not-comparison

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.l3out.l3out import (
    ConnectivityDetailsModel,
    L3OutModel,
    LinkModel,
    SwitchDetailsModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.manage_l3out import (
    L3OutOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import (
    ResponseHandler,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import (
    does_not_raise,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import (
    load_fixture,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import (
    ResponseGenerator,
)
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_l3out(key: str):
    """Load fixture data for test_l3out tests."""
    return load_fixture("test_l3out")[key]


def _build_rest_send(gen_responses: ResponseGenerator) -> RestSend:
    """Build a `RestSend` wired to a file-based `Sender` and `ResponseHandler`."""
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": "test_fabric"})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _build_l3out_model(
    name: str = "test-l3out-bgp",
    include_config: bool = True,
) -> L3OutModel:
    """Build a minimal `L3OutModel` instance for tests."""
    kwargs: dict = {"name": name}
    if include_config:
        kwargs.update(
            {
                "fabric1_name": "DC1-Fabric",
                "fabric2_name": "External-Fabric",
                "vrf1_name": "production",
                "vrf2_name": "external",
                "configured_fabrics": "both",
                "ip_version": "ipv4",
            }
        )
    return L3OutModel(**kwargs)


# =============================================================================
# Test: initialization
# =============================================================================


def test_l3out_00010() -> None:
    """
    # Summary

    Verify `L3OutOrchestrator` instantiates without HTTP and exposes the expected ClassVars.

    ## Test

    - `model_class` is `L3OutModel`
    - `supports_bulk_create` and `supports_bulk_delete` are True
    - `fabric_name` reads from `rest_send.params`

    ## Classes and Methods

    - L3OutOrchestrator.__init__()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)

    with does_not_raise():
        instance = L3OutOrchestrator(rest_send=rest_send)

    assert instance.model_class is L3OutModel
    assert instance.supports_bulk_create is True
    assert instance.supports_bulk_delete is True


def test_l3out_00020() -> None:
    """
    # Summary

    Verify `fabric_name` is read from `rest_send.params`.

    ## Test

    - Orchestrator is constructed with a `RestSend` whose params include `fabric_name: test_fabric`
    - `instance.fabric_name` returns `"test_fabric"`

    ## Classes and Methods

    - L3OutOrchestrator.fabric_name
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    assert instance.fabric_name == "test_fabric"


# =============================================================================
# Test: create
# =============================================================================


def test_l3out_00100() -> None:
    """
    # Summary

    Verify `create` wraps the payload in `{"l3Outs": [...]}` envelope and issues POST.

    ## Test

    - POST is issued against `/api/v1/manage/l3Outs`
    - Request body is `{"l3Outs": [{...payload...}]}`
    - Payload uses camelCase keys
    - `attach` field is excluded from payload

    ## Classes and Methods

    - L3OutOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model()

    with does_not_raise():
        instance.create(model)

    assert rest_send.path == "/api/v1/manage/l3Outs"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert "l3Outs" in body
    assert len(body["l3Outs"]) == 1
    payload_item = body["l3Outs"][0]
    assert payload_item["name"] == "test-l3out-bgp"
    assert payload_item["fabric1Name"] == "DC1-Fabric"
    assert "attach" not in payload_item


def test_l3out_00110() -> None:
    """
    # Summary

    Verify `create` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - POST returns 500
    - `RuntimeError` is raised; message matches `Create failed for .*test-l3out-bgp`

    ## Classes and Methods

    - L3OutOrchestrator.create()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model()

    match = r"Create failed for .*test-l3out-bgp"
    with pytest.raises(RuntimeError, match=match):
        instance.create(model)


def test_l3out_00120() -> None:
    """
    # Summary

    Verify `create` detects a per-item failure in a multi-status response body.

    ## Test

    - POST returns 200 but response body has item with status "failed"
    - `RuntimeError` is raised surfacing the per-item failure message (now via the centralized
      `NdV1Strategy` per-item failure detection in RestSend, which scans the body on any
      success code, not only 207)

    ## Classes and Methods

    - L3OutOrchestrator.create()
    - NdV1Strategy.is_success()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model()

    match = r"Create failed for .*L3Out already exists"
    with pytest.raises(RuntimeError, match=match):
        instance.create(model)


# =============================================================================
# Test: update
# =============================================================================


def test_l3out_00200() -> None:
    """
    # Summary

    Verify `update` issues a PUT against the per-L3Out URL.

    ## Test

    - PUT is issued against `/api/v1/manage/l3Outs/test-l3out-bgp`
    - Payload uses camelCase keys

    ## Classes and Methods

    - L3OutOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model()

    with does_not_raise():
        instance.update(model)

    assert rest_send.path == "/api/v1/manage/l3Outs/test-l3out-bgp"
    assert rest_send.verb == HttpVerbEnum.PUT.value
    body = rest_send.committed_payload
    assert isinstance(body, dict)
    assert body["name"] == "test-l3out-bgp"


def test_l3out_00210() -> None:
    """
    # Summary

    Verify `update` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - PUT returns 500
    - `RuntimeError` matches `Update failed for .*test-l3out-bgp`

    ## Classes and Methods

    - L3OutOrchestrator.update()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model()

    match = r"Update failed for .*test-l3out-bgp"
    with pytest.raises(RuntimeError, match=match):
        instance.update(model)


# =============================================================================
# Test: delete
# =============================================================================


def test_l3out_00300() -> None:
    """
    # Summary

    Verify `delete` issues a DELETE against the per-L3Out URL.

    ## Test

    - DELETE is issued against `/api/v1/manage/l3Outs/test-l3out-bgp`

    ## Classes and Methods

    - L3OutOrchestrator.delete()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model(include_config=False)

    with does_not_raise():
        instance.delete(model)

    assert rest_send.path == "/api/v1/manage/l3Outs/test-l3out-bgp"
    assert rest_send.verb == HttpVerbEnum.DELETE.value


def test_l3out_00310() -> None:
    """
    # Summary

    Verify `delete` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - DELETE returns 500
    - `RuntimeError` matches `Delete failed for .*test-l3out-bgp`

    ## Classes and Methods

    - L3OutOrchestrator.delete()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model(include_config=False)

    match = r"Delete failed for .*test-l3out-bgp"
    with pytest.raises(RuntimeError, match=match):
        instance.delete(model)


# =============================================================================
# Test: create_bulk
# =============================================================================


def test_l3out_00400() -> None:
    """
    # Summary

    Verify `create_bulk` wraps multiple payloads in a single `{"l3Outs": [...]}` envelope.

    ## Test

    - Two L3Outs are submitted in one POST
    - Request body contains both payloads in the l3Outs array

    ## Classes and Methods

    - L3OutOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    models = [
        _build_l3out_model(name="test-l3out-bgp"),
        _build_l3out_model(name="test-l3out-static"),
    ]

    with does_not_raise():
        instance.create_bulk(models)

    assert rest_send.path == "/api/v1/manage/l3Outs"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert "l3Outs" in body
    assert len(body["l3Outs"]) == 2
    names = [item["name"] for item in body["l3Outs"]]
    assert "test-l3out-bgp" in names
    assert "test-l3out-static" in names


def test_l3out_00410() -> None:
    """
    # Summary

    Verify `create_bulk` wraps a `_request` failure in `RuntimeError` matching `Bulk create failed`.

    ## Test

    - POST returns 500
    - `RuntimeError` matches `Bulk create failed`

    ## Classes and Methods

    - L3OutOrchestrator.create_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    models = [
        _build_l3out_model(name="test-l3out-bgp"),
        _build_l3out_model(name="test-l3out-static"),
    ]

    match = r"Bulk create failed"
    with pytest.raises(RuntimeError, match=match):
        instance.create_bulk(models)


# =============================================================================
# Test: delete_bulk
# =============================================================================


def test_l3out_00500() -> None:
    """
    # Summary

    Verify `delete_bulk` sends POST to /l3OutActions/remove with `{"l3OutNames": [...]}`.

    ## Test

    - POST is issued against `/api/v1/manage/l3OutActions/remove`
    - Request body contains L3Out names

    ## Classes and Methods

    - L3OutOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    models = [
        _build_l3out_model(name="test-l3out-bgp", include_config=False),
        _build_l3out_model(name="test-l3out-static", include_config=False),
    ]

    with does_not_raise():
        instance.delete_bulk(models)

    assert rest_send.path == "/api/v1/manage/l3OutActions/remove"
    assert rest_send.verb == HttpVerbEnum.POST.value
    body = rest_send.committed_payload
    assert "l3OutNames" in body
    assert sorted(body["l3OutNames"]) == ["test-l3out-bgp", "test-l3out-static"]


def test_l3out_00510() -> None:
    """
    # Summary

    Verify `delete_bulk` wraps a `_request` failure in `RuntimeError` matching `Bulk delete failed`.

    ## Test

    - POST returns 500
    - `RuntimeError` matches `Bulk delete failed`

    ## Classes and Methods

    - L3OutOrchestrator.delete_bulk()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    models = [
        _build_l3out_model(name="test-l3out-bgp", include_config=False),
        _build_l3out_model(name="test-l3out-static", include_config=False),
    ]

    match = r"Bulk delete failed"
    with pytest.raises(RuntimeError, match=match):
        instance.delete_bulk(models)


def test_l3out_00520() -> None:
    """
    # Summary

    Verify `delete_bulk` detects a per-item failure in a multi-status response body.

    ## Test

    - POST returns 200 but response body has one item with status "failed"
    - `RuntimeError` is raised surfacing the per-item failure message (now via the centralized
      `NdV1Strategy` per-item failure detection in RestSend, which scans the body on any
      success code, not only 207)

    ## Classes and Methods

    - L3OutOrchestrator.delete_bulk()
    - NdV1Strategy.is_success()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    models = [
        _build_l3out_model(name="test-l3out-bgp", include_config=False),
        _build_l3out_model(name="test-l3out-static", include_config=False),
    ]

    match = r"Bulk delete failed.*L3Out not found"
    with pytest.raises(RuntimeError, match=match):
        instance.delete_bulk(models)


# =============================================================================
# Test: query_one
# =============================================================================


def test_l3out_00600() -> None:
    """
    # Summary

    Verify `query_one` issues a GET against the per-L3Out URL and returns the DATA dict.

    ## Test

    - GET hits `/api/v1/manage/l3Outs/test-l3out-bgp`
    - Returned DATA matches the fixture

    ## Classes and Methods

    - L3OutOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model(include_config=False)

    with does_not_raise():
        result = instance.query_one(model)

    assert rest_send.path == "/api/v1/manage/l3Outs/test-l3out-bgp"
    assert rest_send.verb == HttpVerbEnum.GET.value
    assert result["name"] == "test-l3out-bgp"
    assert result["fabric1Name"] == "DC1-Fabric"
    assert result["routingDetails"]["routingProtocol"] == "bgp"


def test_l3out_00610() -> None:
    """
    # Summary

    Verify `query_one` wraps a `_request` failure in `RuntimeError` mentioning the identifier.

    ## Test

    - GET returns 500
    - `RuntimeError` matches `Query failed for .*test-l3out-bgp`

    ## Classes and Methods

    - L3OutOrchestrator.query_one()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)
    model = _build_l3out_model(include_config=False)

    match = r"Query failed for .*test-l3out-bgp"
    with pytest.raises(RuntimeError, match=match):
        instance.query_one(model)


# =============================================================================
# Test: query_all
# =============================================================================


def test_l3out_00700() -> None:
    """
    # Summary

    Verify `query_all` sets fabric_name on endpoint, unwraps l3Outs from response.

    ## Test

    - POST hits `/api/v1/manage/l3Outs?fabricName=test_fabric`
    - Result is a list of L3Out dicts unwrapped from the `l3Outs` envelope
    - Two items returned

    ## Classes and Methods

    - L3OutOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert rest_send.path == "/api/v1/manage/l3Outs?fabricName=test_fabric"
    assert isinstance(result, list)
    assert len(result) == 2
    names = [item["name"] for item in result]
    assert "l3out-bgp" in names
    assert "l3out-static" in names


def test_l3out_00710() -> None:
    """
    # Summary

    Verify `query_all` returns empty list when no L3Outs exist.

    ## Test

    - Response has empty l3Outs array
    - `query_all` returns []

    ## Classes and Methods

    - L3OutOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


def test_l3out_00720() -> None:
    """
    # Summary

    Verify `query_all` wraps a `_request` failure in `RuntimeError`.

    ## Test

    - POST returns 500
    - `RuntimeError` matches `Query all failed`

    ## Classes and Methods

    - L3OutOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    match = r"Query all failed"
    with pytest.raises(RuntimeError, match=match):
        instance.query_all()


def test_l3out_00730() -> None:
    """
    # Summary

    Verify `query_all` returns empty list on 404 (not_found_ok).

    ## Test

    - POST returns 404
    - `query_all` returns [] (not an error)

    ## Classes and Methods

    - L3OutOrchestrator.query_all()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        yield responses_l3out(f"{method_name}a")

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.query_all()

    assert result == []


# =============================================================================
# Test: _validate_bulk_response (static method)
# =============================================================================


def test_l3out_00800() -> None:
    """
    # Summary

    Verify `_validate_bulk_response` does nothing for success responses.

    ## Test

    - All items have status "success"
    - No exception raised

    ## Classes and Methods

    - L3OutOrchestrator._validate_bulk_response()
    """
    result = {
        "results": [
            {"name": "l3out-1", "status": "success", "statusCode": 200},
            {"name": "l3out-2", "status": "success", "statusCode": 200},
        ]
    }
    with does_not_raise():
        L3OutOrchestrator._validate_bulk_response(result, "Test operation")


def test_l3out_00810() -> None:
    """
    # Summary

    Verify `_validate_bulk_response` raises RuntimeError for failed items.

    ## Test

    - One item has status "failed" with statusCode 409
    - RuntimeError raised with "partially failed" and the item name

    ## Classes and Methods

    - L3OutOrchestrator._validate_bulk_response()
    """
    result = {
        "results": [
            {"name": "l3out-1", "status": "success", "statusCode": 200},
            {"name": "l3out-2", "status": "failed", "statusCode": 409, "message": "Already exists"},
        ]
    }
    match = r"partially failed.*l3out-2.*Already exists"
    with pytest.raises(RuntimeError, match=match):
        L3OutOrchestrator._validate_bulk_response(result, "Test operation")


def test_l3out_00820() -> None:
    """
    # Summary

    Verify `_validate_bulk_response` handles None and empty inputs gracefully.

    ## Test

    - None input: no exception
    - Empty dict: no exception
    - Dict without results: no exception

    ## Classes and Methods

    - L3OutOrchestrator._validate_bulk_response()
    """
    with does_not_raise():
        L3OutOrchestrator._validate_bulk_response(None, "op")
        L3OutOrchestrator._validate_bulk_response({}, "op")
        L3OutOrchestrator._validate_bulk_response({"other": "data"}, "op")


def test_l3out_00830() -> None:
    """
    # Summary

    Verify `_validate_bulk_response` detects failures via statusCode >= 400 even without status field.

    ## Test

    - Item has statusCode 500 but no "status" field
    - RuntimeError raised

    ## Classes and Methods

    - L3OutOrchestrator._validate_bulk_response()
    """
    result = {
        "results": [
            {"name": "l3out-1", "statusCode": 500, "message": "Internal error"},
        ]
    }
    match = r"partially failed.*l3out-1"
    with pytest.raises(RuntimeError, match=match):
        L3OutOrchestrator._validate_bulk_response(result, "Test operation")


# =============================================================================
# Test: switch_id resolution helpers
# =============================================================================


def test_l3out_00900() -> None:
    """
    # Summary

    Verify `_is_ip_address` correctly identifies IPv4 addresses.

    ## Test

    - "10.1.1.11" → True
    - "FDO12345678" → False
    - "192.168.1.1" → True
    - "not-an-ip" → False

    ## Classes and Methods

    - L3OutOrchestrator._is_ip_address()
    """
    assert L3OutOrchestrator._is_ip_address("10.1.1.11") is True
    assert L3OutOrchestrator._is_ip_address("192.168.1.1") is True
    assert L3OutOrchestrator._is_ip_address("FDO12345678") is False
    assert L3OutOrchestrator._is_ip_address("not-an-ip") is False


def test_l3out_00910() -> None:
    """
    # Summary

    Verify `_is_ip_address` correctly identifies IPv6 addresses.

    ## Test

    - "2001:db8::1" → True
    - "::1" → True
    - "fe80::1%eth0" → True (zone IDs are valid in Python 3.9+)

    ## Classes and Methods

    - L3OutOrchestrator._is_ip_address()
    """
    assert L3OutOrchestrator._is_ip_address("2001:db8::1") is True
    assert L3OutOrchestrator._is_ip_address("::1") is True
    assert L3OutOrchestrator._is_ip_address("fe80::1%eth0") is True


def test_l3out_00920() -> None:
    """
    # Summary

    Verify `_resolve_switch_id` returns serial numbers unchanged.

    ## Test

    - Serial number "FDO12345678" passes through without calling FabricContext

    ## Classes and Methods

    - L3OutOrchestrator._resolve_switch_id()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    result = instance._resolve_switch_id("DC1-Fabric", "FDO12345678")
    assert result == "FDO12345678"


def test_l3out_00930() -> None:
    """
    # Summary

    Verify `_resolve_switch_id` resolves a management IP to serial number via FabricContext.

    ## Test

    - Given IP "10.1.1.11", FabricContext resolves to "FDO11111111"
    - Uses mocked switch_map

    ## Classes and Methods

    - L3OutOrchestrator._resolve_switch_id()
    - FabricContext.get_switch_id()
    """
    from unittest.mock import MagicMock, patch

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    mock_ctx = MagicMock()
    mock_ctx.get_switch_id.return_value = "FDO11111111"

    with patch.object(instance, "_get_fabric_context", return_value=mock_ctx):
        result = instance._resolve_switch_id("DC1-Fabric", "10.1.1.11")

    assert result == "FDO11111111"
    mock_ctx.get_switch_id.assert_called_once_with("10.1.1.11")


def test_l3out_00940() -> None:
    """
    # Summary

    Verify `_resolve_switch_id` raises RuntimeError when IP is not found in fabric.

    ## Test

    - FabricContext.get_switch_id raises RuntimeError for unknown IP
    - Error propagates from _resolve_switch_id

    ## Classes and Methods

    - L3OutOrchestrator._resolve_switch_id()
    """
    from unittest.mock import MagicMock, patch

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    mock_ctx = MagicMock()
    mock_ctx.get_switch_id.side_effect = RuntimeError("No switch found with fabricManagementIp '10.99.99.99' in fabric 'DC1-Fabric'.")

    with patch.object(instance, "_get_fabric_context", return_value=mock_ctx):
        with pytest.raises(RuntimeError, match=r"No switch found.*10\.99\.99\.99"):
            instance._resolve_switch_id("DC1-Fabric", "10.99.99.99")


def test_l3out_00950() -> None:
    """
    # Summary

    Verify `_resolve_links` resolves IP addresses in switch1_details and switch2_details.

    ## Test

    - Model with links containing IPs in switch_id fields
    - After _resolve_links, switch_id values are replaced with serial numbers
    - switch1 resolves against fabric1_name, switch2 against fabric2_name

    ## Classes and Methods

    - L3OutOrchestrator._resolve_links()
    """
    from unittest.mock import MagicMock, patch

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    model = L3OutModel(
        name="test-l3out",
        fabric1_name="DC1-Fabric",
        fabric2_name="External-Fabric",
        connectivity_details=ConnectivityDetailsModel(
            routing_interface_type="routed",
            links=[
                LinkModel(
                    switch1_details=SwitchDetailsModel(
                        switch_id="10.1.1.11",
                        interface_name="Ethernet1/1",
                    ),
                    switch2_details=SwitchDetailsModel(
                        switch_id="10.2.2.22",
                        interface_name="Ethernet1/2",
                    ),
                )
            ],
        ),
    )

    mock_ctx_dc1 = MagicMock()
    mock_ctx_dc1.get_switch_id.return_value = "FDO11111111"
    mock_ctx_ext = MagicMock()
    mock_ctx_ext.get_switch_id.return_value = "FDO22222222"

    def mock_get_context(fabric_name):
        if fabric_name == "DC1-Fabric":
            return mock_ctx_dc1
        return mock_ctx_ext

    with patch.object(instance, "_get_fabric_context", side_effect=mock_get_context):
        instance._resolve_links(model)

    assert model.connectivity_details.links[0].switch1_details.switch_id == "FDO11111111"
    assert model.connectivity_details.links[0].switch2_details.switch_id == "FDO22222222"
    mock_ctx_dc1.get_switch_id.assert_called_once_with("10.1.1.11")
    mock_ctx_ext.get_switch_id.assert_called_once_with("10.2.2.22")


def test_l3out_00960() -> None:
    """
    # Summary

    Verify `_resolve_links` is a no-op when switch_id values are already serial numbers.

    ## Test

    - Model with serial numbers in switch_id fields
    - After _resolve_links, values are unchanged
    - FabricContext is never queried

    ## Classes and Methods

    - L3OutOrchestrator._resolve_links()
    """
    from unittest.mock import patch

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    model = L3OutModel(
        name="test-l3out",
        fabric1_name="DC1-Fabric",
        fabric2_name="External-Fabric",
        connectivity_details=ConnectivityDetailsModel(
            routing_interface_type="routed",
            links=[
                LinkModel(
                    switch1_details=SwitchDetailsModel(
                        switch_id="FDO11111111",
                        interface_name="Ethernet1/1",
                    ),
                    switch2_details=SwitchDetailsModel(
                        switch_id="FDO22222222",
                        interface_name="Ethernet1/2",
                    ),
                )
            ],
        ),
    )

    with patch.object(instance, "_get_fabric_context") as mock_get_ctx:
        instance._resolve_links(model)

    # FabricContext should never be called for serial numbers
    mock_get_ctx.assert_not_called()
    assert model.connectivity_details.links[0].switch1_details.switch_id == "FDO11111111"
    assert model.connectivity_details.links[0].switch2_details.switch_id == "FDO22222222"


def test_l3out_00970() -> None:
    """
    # Summary

    Verify `_resolve_links` is a no-op when connectivity_details is None.

    ## Test

    - Model without connectivity_details
    - No error raised

    ## Classes and Methods

    - L3OutOrchestrator._resolve_links()
    """

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    instance = L3OutOrchestrator(rest_send=rest_send)

    model = L3OutModel(name="test-l3out")
    with does_not_raise():
        instance._resolve_links(model)


def test_l3out_00980() -> None:
    """
    # Summary

    Verify a terminal per-item attach failure is submitted exactly once (no inner or outer replay).

    ## Test

    - attach POST returns 207 with a non-not-found per-item failure
    - RestSend timeout (10) exceeds send_interval (1), so only the terminal break prevents inner replay
    - attach_l3outs re-raises immediately (message lacks "not found"), so the outer loop does not retry
    - Exactly one response is consumed: the generator holds only one, and a replay would exhaust it with a different error

    ## Classes and Methods

    - L3OutOrchestrator.attach_l3outs()
    - RestSend._commit_normal_mode()
    """

    def responses():
        yield {
            "RETURN_CODE": 207,
            "MESSAGE": "Multi-Status",
            "DATA": {"results": [{"name": "L3Out1", "status": "failed", "message": "L3Out already attached"}]},
        }

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    rest_send.timeout = 10
    rest_send.send_interval = 1
    instance = L3OutOrchestrator(rest_send=rest_send)

    match = r"already attached"
    with pytest.raises(Exception, match=match):
        instance.attach_l3outs([{"name": "L3Out1", "attach": True}], max_retries=2, retry_delay=0)


def test_l3out_00990() -> None:
    """
    # Summary

    Verify the eventual-consistency outer retry still works for not-found per-item failures.

    ## Test

    - First attach POST returns 207 whose per-item failure message contains "not found"
    - attach_l3outs catches the raised failure, retries the outer loop, and the second POST succeeds
    - Each outer attempt submits exactly once (two responses total)

    ## Classes and Methods

    - L3OutOrchestrator.attach_l3outs()
    - RestSend._commit_normal_mode()
    """

    def responses():
        yield {
            "RETURN_CODE": 207,
            "MESSAGE": "Multi-Status",
            "DATA": {"results": [{"name": "L3Out1", "status": "failed", "message": "L3Out L3Out1 not found"}]},
        }
        yield {
            "RETURN_CODE": 200,
            "MESSAGE": "OK",
            "DATA": {"results": [{"name": "L3Out1", "status": "success"}]},
        }

    gen_responses = ResponseGenerator(responses())
    rest_send = _build_rest_send(gen_responses)
    rest_send.timeout = 10
    rest_send.send_interval = 1
    instance = L3OutOrchestrator(rest_send=rest_send)

    with does_not_raise():
        result = instance.attach_l3outs([{"name": "L3Out1", "attach": True}], max_retries=1, retry_delay=0)

    assert result.get("results", [{}])[0].get("status") == "success"
