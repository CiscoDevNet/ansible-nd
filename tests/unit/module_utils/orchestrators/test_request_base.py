# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for orchestrators/request_base.py

Tests the `NDRequestBase` class focusing on:
- `_request` returning the response `DATA` and raising `RuntimeError` on failure
- `not_found_ok` short-circuiting a 404 to an empty dict
- `_register_api_call` populating `Results` (verbosity, state, check_mode) and no-op when `results` is None
- The class carrying no endpoint / CRUD fields
- `NDBaseOrchestrator` and `FabricPrepareUpdateOrchestrator` inheriting the helpers rather than carrying copies
"""

# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument
# pylint: disable=invalid-name
# pylint: disable=line-too-long

from __future__ import absolute_import, annotations, division, print_function

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum, OperationType
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.fabric_prepare_update import FabricPrepareUpdateOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.request_base import NDRequestBase
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

# =============================================================================
# Helpers: RestSend wired with a file-based Sender
# =============================================================================


def _make_rest_send(response_dicts, params=None):
    """
    Build a real `RestSend` backed by a file-based `Sender` that yields `response_dicts` in order.
    """

    def responses():
        yield from response_dicts

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    rest_send = RestSend(params if params is not None else {"check_mode": False, "state": "merged"})
    rest_send.sender = sender
    rest_send.response_handler = ResponseHandler()
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _response(code=200, method="GET", message="OK", data=None):
    """Build a response dict in the collection's standard shape."""
    return {
        "RETURN_CODE": code,
        "METHOD": method,
        "REQUEST_PATH": "/api/v1/stub",
        "MESSAGE": message,
        "DATA": data if data is not None else {},
    }


# =============================================================================
# Tests: class shape
# =============================================================================


def test_request_base_00000() -> None:
    """
    # Summary

    Verify `NDRequestBase` carries only the REST plumbing fields and no endpoint or CRUD surface.

    ## Test

    - The declared model fields are exactly `rest_send` and `results`
    - `results` defaults to None
    - No `create` / `update` / `delete` / `query_one` / `query_all` attributes exist

    ## Classes and Methods

    - NDRequestBase
    """
    assert set(NDRequestBase.model_fields) == {"rest_send", "results"}

    instance = NDRequestBase(rest_send=_make_rest_send([]))
    assert instance.results is None
    for name in ("create", "update", "delete", "query_one", "query_all", "create_endpoint", "query_all_endpoint"):
        assert not hasattr(instance, name)


def test_request_base_00001() -> None:
    """
    # Summary

    Verify `_request` and `_register_api_call` are defined in exactly one place: `NDRequestBase`.

    ## Test

    - `NDBaseOrchestrator` and `FabricPrepareUpdateOrchestrator` are subclasses of `NDRequestBase`
    - Neither subclass defines its own `_request` or `_register_api_call`

    ## Classes and Methods

    - NDRequestBase._request()
    - NDRequestBase._register_api_call()
    """
    for cls in (NDBaseOrchestrator, FabricPrepareUpdateOrchestrator):
        assert issubclass(cls, NDRequestBase)
        assert "_request" not in vars(cls)
        assert "_register_api_call" not in vars(cls)
        assert cls._request is NDRequestBase._request
        assert cls._register_api_call is NDRequestBase._register_api_call


# =============================================================================
# Tests: _request
# =============================================================================


def test_request_base_00100() -> None:
    """
    # Summary

    Verify `_request` returns the response `DATA` on success.

    ## Test

    - A 200 response with a DATA body is committed
    - `_request` returns the DATA body

    ## Classes and Methods

    - NDRequestBase._request()
    """
    instance = NDRequestBase(rest_send=_make_rest_send([_response(data={"key": "value"})]))

    result = instance._request("/api/v1/stub", HttpVerbEnum.GET)

    assert result == {"key": "value"}


def test_request_base_00110() -> None:
    """
    # Summary

    Verify `_request` forwards the payload to `RestSend` and registers the committed payload.

    ## Test

    - A POST with `data` is sent
    - The registered task carries the payload and verbosity 2

    ## Classes and Methods

    - NDRequestBase._request()
    - NDRequestBase._register_api_call()
    """
    results = Results()
    instance = NDRequestBase(rest_send=_make_rest_send([_response(method="POST")]), results=results)

    instance._request("/api/v1/stub", HttpVerbEnum.POST, data={"name": "x"}, operation_type=OperationType.CREATE)

    task = results._tasks[0]
    assert task.payload == {"name": "x"}
    assert task.verb == "POST"
    assert task.verbosity_level == 2
    assert task.metadata["action"] == "create"


def test_request_base_00120() -> None:
    """
    # Summary

    Verify `_request` raises `RuntimeError` on a non-success response, after registering the call.

    ## Test

    - A 500 response is committed
    - `RuntimeError` matching `Request failed` is raised
    - The failed call is still registered with `Results`

    ## Classes and Methods

    - NDRequestBase._request()
    """
    results = Results()
    instance = NDRequestBase(rest_send=_make_rest_send([_response(code=500, method="POST", message="Server Error")]), results=results)

    with pytest.raises(RuntimeError, match=r"Request failed"):
        instance._request("/api/v1/stub", HttpVerbEnum.POST, data={}, operation_type=OperationType.CREATE)

    assert len(results._tasks) == 1
    assert results._tasks[0].path == "/api/v1/stub"


def test_request_base_00130() -> None:
    """
    # Summary

    Verify `_request` returns an empty dict for a 404 when `not_found_ok` is True.

    ## Test

    - A 404 response is committed with `not_found_ok=True`
    - `_request` returns `{}` and the call is registered

    ## Classes and Methods

    - NDRequestBase._request()
    """
    results = Results()
    instance = NDRequestBase(rest_send=_make_rest_send([_response(code=404, message="Not Found")]), results=results)

    result = instance._request("/api/v1/stub", HttpVerbEnum.GET, not_found_ok=True)

    assert result == {}
    assert len(results._tasks) == 1


def test_request_base_00140() -> None:
    """
    # Summary

    Verify `_request` works with no `Results` attached.

    ## Test

    - `results` is None
    - `_request` returns DATA without raising

    ## Classes and Methods

    - NDRequestBase._request()
    - NDRequestBase._register_api_call()
    """
    instance = NDRequestBase(rest_send=_make_rest_send([_response(data={"a": 1})]))

    assert instance._request("/api/v1/stub", HttpVerbEnum.GET) == {"a": 1}


# =============================================================================
# Tests: _register_api_call
# =============================================================================


def test_request_base_00200() -> None:
    """
    # Summary

    Verify query operations are tagged verbosity 3 and write operations verbosity 2.

    ## Test

    - A GET QUERY and a DELETE are sent
    - The registered tasks carry verbosity 3 and 2 respectively

    ## Classes and Methods

    - NDRequestBase._register_api_call()
    """
    results = Results()
    instance = NDRequestBase(rest_send=_make_rest_send([_response(), _response(method="DELETE")]), results=results)

    instance._request("/api/v1/stub", HttpVerbEnum.GET, operation_type=OperationType.QUERY)
    instance._request("/api/v1/stub", HttpVerbEnum.DELETE, operation_type=OperationType.DELETE)

    assert [task.verbosity_level for task in results._tasks] == [3, 2]


def test_request_base_00210() -> None:
    """
    # Summary

    Verify every registration reapplies `state` and `check_mode` from the module params, so a multi-call workflow keeps its metadata after
    `Results` resets its current task.

    ## Test

    - `params` carry state `overridden` and check_mode True, `rest_send.check_mode` is overridden to False (read-only POST)
    - Two requests are sent against a fresh `Results`
    - Both tasks carry the params' state and check_mode

    ## Classes and Methods

    - NDRequestBase._register_api_call()
    """
    rest_send = _make_rest_send([_response(), _response()], params={"check_mode": True, "state": "overridden"})
    rest_send.check_mode = False
    results = Results()
    instance = NDRequestBase(rest_send=rest_send, results=results)

    instance._request("/api/v1/stub?offset=0", HttpVerbEnum.GET)
    instance._request("/api/v1/stub?offset=500", HttpVerbEnum.GET)

    assert [task.metadata["state"] for task in results._tasks] == ["overridden", "overridden"]
    assert [task.metadata["check_mode"] for task in results._tasks] == [True, True]
