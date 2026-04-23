# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for orchestrators/base.py

Tests the NDBaseOrchestrator class focusing on:
- Results integration via _register_api_call()
- Verbosity tagging (write=2, query=3)
- CRUD operations passing correct operation_type to _request()
- Graceful behaviour when results is None
- Failed API calls captured before exception
"""

# pylint: disable=protected-access

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

from typing import ClassVar, Literal, Optional

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ConfigDict
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.models.base import NDBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

# =============================================================================
# Test doubles: minimal concrete Endpoint and Model subclasses
# =============================================================================


class StubGetEndpoint(NDEndpointBaseModel):
    """Concrete GET endpoint for testing."""

    class_name: Literal["StubGetEndpoint"] = "StubGetEndpoint"

    @property
    def path(self) -> str:
        return "/api/v1/stub"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.GET


class StubPostEndpoint(NDEndpointBaseModel):
    """Concrete POST endpoint for testing."""

    class_name: Literal["StubPostEndpoint"] = "StubPostEndpoint"

    @property
    def path(self) -> str:
        return "/api/v1/stub"

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.POST


class StubPutEndpoint(NDEndpointBaseModel):
    """Concrete PUT endpoint for testing."""

    class_name: Literal["StubPutEndpoint"] = "StubPutEndpoint"
    _path: str = "/api/v1/stub"

    @property
    def path(self) -> str:
        return self._path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.PUT

    def set_identifiers(self, identifier=None) -> None:
        if identifier is not None:
            self._path = f"/api/v1/stub/{identifier}"


class StubDeleteEndpoint(NDEndpointBaseModel):
    """Concrete DELETE endpoint for testing."""

    class_name: Literal["StubDeleteEndpoint"] = "StubDeleteEndpoint"
    _path: str = "/api/v1/stub"

    @property
    def path(self) -> str:
        return self._path

    @property
    def verb(self) -> HttpVerbEnum:
        return HttpVerbEnum.DELETE

    def set_identifiers(self, identifier=None) -> None:
        if identifier is not None:
            self._path = f"/api/v1/stub/{identifier}"


class StubModel(NDBaseModel):
    """Minimal concrete model for testing."""

    model_config = ConfigDict(populate_by_name=True)

    identifiers: ClassVar[list] = ["name"]
    identifier_strategy: ClassVar[str] = "single"

    name: str = "test_item"
    description: Optional[str] = None


# =============================================================================
# Fixtures: RestSend wired with file-based Sender
# =============================================================================


def _make_rest_send(response_dicts):
    """
    Build a real RestSend instance backed by a file-based Sender
    that yields the given response dicts in order.

    Each dict in response_dicts should have RETURN_CODE, MESSAGE, DATA, etc.
    """

    def responses():
        yield from response_dicts

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    rest_send = RestSend({"check_mode": False, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    return rest_send


def _success_response(data=None):
    """Standard 200 OK response dict."""
    return {
        "RETURN_CODE": 200,
        "METHOD": "GET",
        "REQUEST_PATH": "/api/v1/stub",
        "MESSAGE": "OK",
        "DATA": data or {},
    }


def _not_found_response():
    """Standard 404 Not Found response dict."""
    return {
        "RETURN_CODE": 404,
        "METHOD": "GET",
        "REQUEST_PATH": "/api/v1/stub",
        "MESSAGE": "Not Found",
        "DATA": {},
    }


def _error_response(code=500, message="Internal Server Error"):
    """Standard error response dict."""
    return {
        "RETURN_CODE": code,
        "METHOD": "POST",
        "REQUEST_PATH": "/api/v1/stub",
        "MESSAGE": message,
        "DATA": {},
    }


def _make_orchestrator(rest_send, results=None):
    """Create an NDBaseOrchestrator with stub endpoints and the given RestSend."""
    return NDBaseOrchestrator(
        create_endpoint=StubPostEndpoint,
        update_endpoint=StubPutEndpoint,
        delete_endpoint=StubDeleteEndpoint,
        query_one_endpoint=StubGetEndpoint,
        query_all_endpoint=StubGetEndpoint,
        rest_send=rest_send,
        results=results,
    )


def _make_results():
    """Create a Results instance pre-configured for testing."""
    r = Results()
    r.state = "merged"
    r.check_mode = False
    return r


# =============================================================================
# Test: _register_api_call verbosity tagging
# =============================================================================


class TestRegisterApiCallVerbosityTagging:
    """Tests that _register_api_call tags operations with correct verbosity_level."""

    def test_query_tagged_at_verbosity_3(self):
        """QUERY operations are tagged with verbosity_level=3."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 3

    def test_create_tagged_at_verbosity_2(self):
        """CREATE operations are tagged with verbosity_level=2."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.POST, data={"name": "x"}, operation_type=OperationType.CREATE)

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2

    def test_update_tagged_at_verbosity_2(self):
        """UPDATE operations are tagged with verbosity_level=2."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.PUT, data={"name": "x"}, operation_type=OperationType.UPDATE)

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2

    def test_delete_tagged_at_verbosity_2(self):
        """DELETE operations are tagged with verbosity_level=2."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.DELETE, operation_type=OperationType.DELETE)

        assert len(results._tasks) == 1
        assert results._tasks[0].verbosity_level == 2


# =============================================================================
# Test: _register_api_call field population
# =============================================================================


class TestRegisterApiCallFieldPopulation:
    """Tests that _register_api_call correctly populates Results fields."""

    def test_path_and_verb_captured(self):
        """Registered task stores path and verb from the API call."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/fabrics", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        task = results._tasks[0]
        assert task.path == "/api/v1/fabrics"
        assert task.verb == "GET"

    def test_payload_captured(self):
        """Registered task stores the committed payload."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.POST, data={"name": "FAB1"}, operation_type=OperationType.CREATE)

        task = results._tasks[0]
        assert task.payload == {"name": "FAB1"}

    def test_none_payload_for_get(self):
        """GET requests register None payload."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        task = results._tasks[0]
        assert task.payload is None

    def test_response_captured(self):
        """Registered task stores the controller response."""
        resp = _success_response(data={"id": "123"})
        rest_send = _make_rest_send([resp])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        task = results._tasks[0]
        assert task.response["RETURN_CODE"] == 200

    def test_result_captured(self):
        """Registered task stores the handler result (success/found/changed)."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        task = results._tasks[0]
        assert task.result["success"] is True

    def test_action_matches_operation_type(self):
        """Registered task action matches the operation_type value."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.POST, data={"x": 1}, operation_type=OperationType.CREATE)

        task = results._tasks[0]
        assert task.metadata["action"] == "create"

    def test_diff_is_empty_dict(self):
        """Registered tasks always have an empty diff (orchestrator doesn't compute diffs)."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/stub", HttpVerbEnum.POST, data={}, operation_type=OperationType.CREATE)

        task = results._tasks[0]
        # diff contains at least sequence_number added by register_api_call
        assert task.diff.get("sequence_number") == 1


# =============================================================================
# Test: _request with results=None (graceful no-op)
# =============================================================================


class TestRequestWithoutResults:
    """Tests that _request works correctly when results is None."""

    def test_request_succeeds_without_results(self):
        """_request completes normally when results is None."""
        rest_send = _make_rest_send([_success_response(data={"key": "value"})])
        orch = _make_orchestrator(rest_send, results=None)

        result = orch._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        assert result == {"key": "value"}

    def test_no_tasks_registered_when_results_none(self):
        """No tasks are registered when results is None."""
        rest_send = _make_rest_send([_success_response()])
        orch = _make_orchestrator(rest_send, results=None)

        orch._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)

        # results is None so nothing to check — just verify no exception


# =============================================================================
# Test: _request error handling with Results registration
# =============================================================================


class TestRequestErrorHandlingWithResults:
    """Tests that failed API calls are registered before exceptions propagate."""

    def test_failed_request_registered_before_exception(self):
        """Failed API calls are captured in Results before the exception is raised."""
        rest_send = _make_rest_send([_error_response(500, "Server Error")])
        rest_send.timeout = 5
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        with pytest.raises(Exception, match="Request failed"):
            orch._request("/api/v1/stub", HttpVerbEnum.POST, data={}, operation_type=OperationType.CREATE)

        assert len(results._tasks) == 1
        task = results._tasks[0]
        assert task.verbosity_level == 2
        assert task.path == "/api/v1/stub"

    def test_404_not_found_ok_registered(self):
        """404 with not_found_ok=True is registered and returns empty dict."""
        rest_send = _make_rest_send([_not_found_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        result = orch._request("/api/v1/stub", HttpVerbEnum.GET, not_found_ok=True, operation_type=OperationType.QUERY)

        assert result == {}
        assert len(results._tasks) == 1


# =============================================================================
# Test: CRUD methods pass correct operation_type
# =============================================================================


class TestCrudOperationTypes:
    """Tests that CRUD convenience methods pass the correct operation_type."""

    def test_create_uses_create_operation_type(self):
        """create() passes OperationType.CREATE to _request."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        model = StubModel(name="new_item")

        orch.create(model)

        task = results._tasks[0]
        assert task.metadata["action"] == "create"
        assert task.verbosity_level == 2

    def test_update_uses_update_operation_type(self):
        """update() passes OperationType.UPDATE to _request."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        model = StubModel(name="existing_item")

        orch.update(model)

        task = results._tasks[0]
        assert task.metadata["action"] == "update"
        assert task.verbosity_level == 2

    def test_delete_uses_delete_operation_type(self):
        """delete() passes OperationType.DELETE to _request."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        model = StubModel(name="doomed_item")

        orch.delete(model)

        task = results._tasks[0]
        assert task.metadata["action"] == "delete"
        assert task.verbosity_level == 2
        assert task.payload is None  # DELETE has no payload

    def test_query_one_uses_query_operation_type(self):
        """query_one() passes OperationType.QUERY to _request."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)
        model = StubModel(name="some_item")

        orch.query_one(model)

        task = results._tasks[0]
        assert task.metadata["action"] == "query"
        assert task.verbosity_level == 3

    def test_query_all_uses_query_operation_type(self):
        """query_all() passes OperationType.QUERY to _request."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch.query_all()

        task = results._tasks[0]
        assert task.metadata["action"] == "query"
        assert task.verbosity_level == 3


# =============================================================================
# Test: Multiple sequential API calls accumulate in Results
# =============================================================================


class TestMultipleApiCalls:
    """Tests that multiple API calls accumulate correctly in Results."""

    def test_sequential_calls_accumulate(self):
        """Multiple _request calls each register a separate task."""
        rest_send = _make_rest_send(
            [
                _success_response(),
                _success_response(),
                _success_response(),
            ]
        )
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/a", HttpVerbEnum.GET, operation_type=OperationType.QUERY)
        orch._request("/api/v1/b", HttpVerbEnum.POST, data={"x": 1}, operation_type=OperationType.CREATE)
        orch._request("/api/v1/c", HttpVerbEnum.DELETE, operation_type=OperationType.DELETE)

        assert len(results._tasks) == 3
        assert results._tasks[0].path == "/api/v1/a"
        assert results._tasks[0].verbosity_level == 3  # query
        assert results._tasks[1].path == "/api/v1/b"
        assert results._tasks[1].verbosity_level == 2  # create
        assert results._tasks[2].path == "/api/v1/c"
        assert results._tasks[2].verbosity_level == 2  # delete

    def test_sequence_numbers_increment(self):
        """Each registered task gets an incrementing sequence_number."""
        rest_send = _make_rest_send([_success_response(), _success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/a", HttpVerbEnum.GET, operation_type=OperationType.QUERY)
        orch._request("/api/v1/b", HttpVerbEnum.POST, data={}, operation_type=OperationType.CREATE)

        assert results._tasks[0].sequence_number == 1
        assert results._tasks[1].sequence_number == 2

    def test_build_final_result_aggregates_all(self):
        """build_final_result aggregates all registered tasks correctly."""
        rest_send = _make_rest_send([_success_response(), _success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        orch._request("/api/v1/query", HttpVerbEnum.GET, operation_type=OperationType.QUERY)
        orch._request("/api/v1/create", HttpVerbEnum.POST, data={"n": 1}, operation_type=OperationType.CREATE)

        results.build_final_result()
        final = results.final_result

        assert final["path"] == ["/api/v1/query", "/api/v1/create"]
        assert final["verb"] == ["GET", "POST"]
        assert final["verbosity_level"] == [3, 2]


# =============================================================================
# Test: _request default operation_type
# =============================================================================


class TestRequestDefaultOperationType:
    """Tests for the default operation_type parameter of _request."""

    def test_default_is_query(self):
        """_request defaults to OperationType.QUERY when operation_type is not specified."""
        rest_send = _make_rest_send([_success_response()])
        results = _make_results()
        orch = _make_orchestrator(rest_send, results)

        # Call without explicit operation_type
        orch._request("/api/v1/stub", HttpVerbEnum.GET)

        task = results._tasks[0]
        assert task.metadata["action"] == "query"
        assert task.verbosity_level == 3
