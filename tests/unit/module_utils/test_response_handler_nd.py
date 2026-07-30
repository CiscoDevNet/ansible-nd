# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for response_handler_nd.py

Tests the ResponseHandler class for handling ND controller responses.
"""

# pylint: disable=unused-import
# pylint: disable=redefined-outer-name
# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=unused-variable
# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_strategies.nd_v1_strategy import NdV1Strategy
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: ResponseHandler initialization
# =============================================================================


def test_response_handler_nd_00010():
    """
    # Summary

    Verify ResponseHandler initialization with default values.

    ## Test

    - Instance can be created
    - _response defaults to None
    - _result defaults to None
    - _verb defaults to None
    - _strategy defaults to NdV1Strategy instance

    ## Classes and Methods

    - ResponseHandler.__init__()
    """
    with does_not_raise():
        instance = ResponseHandler()
    assert instance._response is None
    assert instance._result is None
    assert instance._verb is None
    assert isinstance(instance._strategy, NdV1Strategy)


def test_response_handler_nd_00015():
    """
    # Summary

    Verify validation_strategy getter returns the default NdV1Strategy and
    setter accepts a valid strategy.

    ## Test

    - Default strategy is NdV1Strategy
    - Setting a new NdV1Strategy instance is accepted
    - Getter returns the newly set strategy

    ## Classes and Methods

    - ResponseHandler.validation_strategy (getter/setter)
    """
    instance = ResponseHandler()
    assert isinstance(instance.validation_strategy, NdV1Strategy)

    new_strategy = NdV1Strategy()
    with does_not_raise():
        instance.validation_strategy = new_strategy
    assert instance.validation_strategy is new_strategy


def test_response_handler_nd_00020():
    """
    # Summary

    Verify validation_strategy setter raises TypeError for invalid type.

    ## Test

    - Setting validation_strategy to a non-strategy object raises TypeError

    ## Classes and Methods

    - ResponseHandler.validation_strategy (setter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.validation_strategy:.*Expected ResponseValidationStrategy"
    with pytest.raises(TypeError, match=match):
        instance.validation_strategy = "not a strategy"  # type: ignore[assignment]


# =============================================================================
# Test: ResponseHandler.response property
# =============================================================================


def test_response_handler_nd_00100():
    """
    # Summary

    Verify response getter raises ValueError when not set.

    ## Test

    - Accessing response before setting raises ValueError

    ## Classes and Methods

    - ResponseHandler.response (getter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.response:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.response


def test_response_handler_nd_00110():
    """
    # Summary

    Verify response setter/getter with valid dict.

    ## Test

    - response can be set with a valid dict containing RETURN_CODE and MESSAGE
    - response getter returns the set value

    ## Classes and Methods

    - ResponseHandler.response (setter/getter)
    """
    instance = ResponseHandler()
    response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {"key": "value"}}
    with does_not_raise():
        instance.response = response
        result = instance.response
    assert result["RETURN_CODE"] == 200
    assert result["MESSAGE"] == "OK"


def test_response_handler_nd_00120():
    """
    # Summary

    Verify response setter raises TypeError for non-dict.

    ## Test

    - Setting response to a non-dict raises TypeError

    ## Classes and Methods

    - ResponseHandler.response (setter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.response.*must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.response = "not a dict"  # type: ignore[assignment]


def test_response_handler_nd_00130():
    """
    # Summary

    Verify response setter raises ValueError when MESSAGE key is missing.

    ## Test

    - Setting response without MESSAGE raises ValueError

    ## Classes and Methods

    - ResponseHandler.response (setter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.response:.*must have a MESSAGE key"
    with pytest.raises(ValueError, match=match):
        instance.response = {"RETURN_CODE": 200}


def test_response_handler_nd_00140():
    """
    # Summary

    Verify response setter raises ValueError when RETURN_CODE key is missing.

    ## Test

    - Setting response without RETURN_CODE raises ValueError

    ## Classes and Methods

    - ResponseHandler.response (setter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.response:.*must have a RETURN_CODE key"
    with pytest.raises(ValueError, match=match):
        instance.response = {"MESSAGE": "OK"}


# =============================================================================
# Test: ResponseHandler.verb property
# =============================================================================


def test_response_handler_nd_00200():
    """
    # Summary

    Verify verb getter raises ValueError when not set.

    ## Test

    - Accessing verb before setting raises ValueError

    ## Classes and Methods

    - ResponseHandler.verb (getter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.verb is not set"
    with pytest.raises(ValueError, match=match):
        result = instance.verb


def test_response_handler_nd_00210():
    """
    # Summary

    Verify verb setter/getter with valid HttpVerbEnum.

    ## Test

    - verb can be set and retrieved with HttpVerbEnum values

    ## Classes and Methods

    - ResponseHandler.verb (setter/getter)
    """
    instance = ResponseHandler()
    with does_not_raise():
        instance.verb = HttpVerbEnum.GET
        result = instance.verb
    assert result == HttpVerbEnum.GET

    with does_not_raise():
        instance.verb = HttpVerbEnum.POST
        result = instance.verb
    assert result == HttpVerbEnum.POST


# =============================================================================
# Test: ResponseHandler.result property
# =============================================================================


def test_response_handler_nd_00300():
    """
    # Summary

    Verify result getter raises ValueError when commit() not called.

    ## Test

    - Accessing result before calling commit() raises ValueError

    ## Classes and Methods

    - ResponseHandler.result (getter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.result:.*must be set before accessing.*commit"
    with pytest.raises(ValueError, match=match):
        result = instance.result


def test_response_handler_nd_00310():
    """
    # Summary

    Verify result setter raises TypeError for non-dict.

    ## Test

    - Setting result to non-dict raises TypeError

    ## Classes and Methods

    - ResponseHandler.result (setter)
    """
    instance = ResponseHandler()
    match = r"ResponseHandler\.result.*must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.result = "not a dict"  # type: ignore[assignment]


# =============================================================================
# Test: ResponseHandler.commit() validation
# =============================================================================


def test_response_handler_nd_00400():
    """
    # Summary

    Verify commit() raises ValueError when response is not set.

    ## Test

    - Calling commit() without setting response raises ValueError

    ## Classes and Methods

    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.verb = HttpVerbEnum.GET
    match = r"ResponseHandler\.response:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_response_handler_nd_00410():
    """
    # Summary

    Verify commit() raises ValueError when verb is not set.

    ## Test

    - Calling commit() without setting verb raises ValueError

    ## Classes and Methods

    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    match = r"ResponseHandler\.verb is not set"
    with pytest.raises(ValueError, match=match):
        instance.commit()


# =============================================================================
# Test: ResponseHandler._handle_get_response()
# =============================================================================


def test_response_handler_nd_00500():
    """
    # Summary

    Verify GET response with 200 OK.

    ## Test

    - GET with RETURN_CODE 200 sets found=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00510():
    """
    # Summary

    Verify GET response with 201 Created.

    ## Test

    - GET with RETURN_CODE 201 sets found=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 201, "MESSAGE": "Created"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00520():
    """
    # Summary

    Verify GET response with 202 Accepted.

    ## Test

    - GET with RETURN_CODE 202 sets found=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 202, "MESSAGE": "Accepted"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00530():
    """
    # Summary

    Verify GET response with 204 No Content.

    ## Test

    - GET with RETURN_CODE 204 sets found=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 204, "MESSAGE": "No Content"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00535():
    """
    # Summary

    Verify GET response with 207 Multi-Status.

    ## Test

    - GET with RETURN_CODE 207 sets found=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 207, "MESSAGE": "Multi-Status"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00540():
    """
    # Summary

    Verify GET response with 404 Not Found.

    ## Test

    - GET with RETURN_CODE 404 sets found=False, success=True
    - 404 is treated as "not found but not an error"

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 404, "MESSAGE": "Not Found"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is False
    assert instance.result["success"] is True


def test_response_handler_nd_00550():
    """
    # Summary

    Verify GET response with 500 Internal Server Error.

    ## Test

    - GET with RETURN_CODE 500 sets found=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 500, "MESSAGE": "Internal Server Error"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00560():
    """
    # Summary

    Verify GET response with 400 Bad Request.

    ## Test

    - GET with RETURN_CODE 400 sets found=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 400, "MESSAGE": "Bad Request"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00570():
    """
    # Summary

    Verify GET response with 401 Unauthorized.

    ## Test

    - GET with RETURN_CODE 401 sets found=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 401, "MESSAGE": "Unauthorized"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00575():
    """
    # Summary

    Verify GET response with 405 Method Not Allowed.

    ## Test

    - GET with RETURN_CODE 405 sets found=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 405, "MESSAGE": "Method Not Allowed"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00580():
    """
    # Summary

    Verify GET response with 409 Conflict.

    ## Test

    - GET with RETURN_CODE 409 sets found=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 409, "MESSAGE": "Conflict"}
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["found"] is False
    assert instance.result["success"] is False


# =============================================================================
# Test: ResponseHandler._handle_post_put_delete_response()
# =============================================================================


def test_response_handler_nd_00600():
    """
    # Summary

    Verify POST response with 200 OK (no errors).

    ## Test

    - POST with RETURN_CODE 200 and no errors sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {"status": "created"}}
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00610():
    """
    # Summary

    Verify PUT response with 200 OK.

    ## Test

    - PUT with RETURN_CODE 200 and no errors sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {"status": "updated"}}
    instance.verb = HttpVerbEnum.PUT
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00620():
    """
    # Summary

    Verify DELETE response with 200 OK.

    ## Test

    - DELETE with RETURN_CODE 200 and no errors sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
    instance.verb = HttpVerbEnum.DELETE
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00630():
    """
    # Summary

    Verify POST response with 201 Created.

    ## Test

    - POST with RETURN_CODE 201 sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 201, "MESSAGE": "Created", "DATA": {}}
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00640():
    """
    # Summary

    Verify POST response with 202 Accepted.

    ## Test

    - POST with RETURN_CODE 202 sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 202, "MESSAGE": "Accepted", "DATA": {}}
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00650():
    """
    # Summary

    Verify DELETE response with 204 No Content.

    ## Test

    - DELETE with RETURN_CODE 204 sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 204, "MESSAGE": "No Content", "DATA": {}}
    instance.verb = HttpVerbEnum.DELETE
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00655():
    """
    # Summary

    Verify POST response with 207 Multi-Status.

    ## Test

    - POST with RETURN_CODE 207 and no errors sets changed=True, success=True

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 207, "MESSAGE": "Multi-Status", "DATA": {"status": "partial"}}
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is True
    assert instance.result["success"] is True


def test_response_handler_nd_00660():
    """
    # Summary

    Verify POST response with explicit ERROR key.

    ## Test

    - Response containing ERROR key sets changed=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "ERROR": "Something went wrong",
        "DATA": {},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00670():
    """
    # Summary

    Verify POST response with DATA.error (ND error format).

    ## Test

    - Response with DATA containing error key sets changed=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"error": "ND error occurred"},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00680():
    """
    # Summary

    Verify POST response with 500 error status code.

    ## Test

    - POST with RETURN_CODE 500 sets changed=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00690():
    """
    # Summary

    Verify POST response with 400 Bad Request.

    ## Test

    - POST with RETURN_CODE 400 and no explicit errors sets changed=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00695():
    """
    # Summary

    Verify POST response with 405 Method Not Allowed.

    ## Test

    - POST with RETURN_CODE 405 sets changed=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 405,
        "MESSAGE": "Method Not Allowed",
        "DATA": {},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is False
    assert instance.result["success"] is False


def test_response_handler_nd_00705():
    """
    # Summary

    Verify POST response with 409 Conflict.

    ## Test

    - POST with RETURN_CODE 409 sets changed=False, success=False

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 409,
        "MESSAGE": "Conflict",
        "DATA": {"reason": "resource exists"},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["changed"] is False
    assert instance.result["success"] is False


# =============================================================================
# Test: ResponseHandler.error_message property
# =============================================================================


def test_response_handler_nd_00700():
    """
    # Summary

    Verify error_message returns None on successful response.

    ## Test

    - error_message is None when result indicates success

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.error_message is None


def test_response_handler_nd_00710():
    """
    # Summary

    Verify error_message returns None when commit() not called.

    ## Test

    - error_message is None when _result is None (commit not called)

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    assert instance.error_message is None


def test_response_handler_nd_00720():
    """
    # Summary

    Verify error_message for raw_response format (non-JSON response).

    ## Test

    - When DATA contains raw_response key, error_message indicates non-JSON response

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {"raw_response": "<html>Error</html>"},
    }
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.error_message is not None
    assert "could not be parsed as JSON" in instance.error_message


def test_response_handler_nd_00730():
    """
    # Summary

    Verify error_message for code/message format.

    ## Test

    - When DATA contains code and message keys, error_message includes both

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {"code": "INVALID_INPUT", "message": "Field X is required"},
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "INVALID_INPUT" in instance.error_message
    assert "Field X is required" in instance.error_message


def test_response_handler_nd_00740():
    """
    # Summary

    Verify error_message for messages array format.

    ## Test

    - When DATA contains messages array with code/severity/message,
      error_message includes all three fields

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {
            "messages": [
                {
                    "code": "ERR_001",
                    "severity": "ERROR",
                    "message": "Validation failed",
                }
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "ERR_001" in instance.error_message
    assert "ERROR" in instance.error_message
    assert "Validation failed" in instance.error_message


def test_response_handler_nd_00750():
    """
    # Summary

    Verify error_message for errors array format.

    ## Test

    - When DATA contains errors array, error_message includes the first error

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {"errors": ["First error message", "Second error message"]},
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "First error message" in instance.error_message


def test_response_handler_nd_00760():
    """
    # Summary

    Verify error_message when DATA is None (connection failure).

    ## Test

    - When DATA is None, error_message includes REQUEST_PATH and MESSAGE

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Connection refused",
        "REQUEST_PATH": "/api/v1/some/endpoint",
    }
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.error_message is not None
    assert "Connection failed" in instance.error_message
    assert "/api/v1/some/endpoint" in instance.error_message
    assert "Connection refused" in instance.error_message


def test_response_handler_nd_00770():
    """
    # Summary

    Verify error_message with non-dict DATA.

    ## Test

    - When DATA is a non-dict value, error_message includes stringified DATA

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": "Unexpected string error",
    }
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.error_message is not None
    assert "Unexpected string error" in instance.error_message


def test_response_handler_nd_00780():
    """
    # Summary

    Verify error_message fallback for unknown dict format.

    ## Test

    - When DATA is a dict with no recognized error format,
      error_message falls back to including RETURN_CODE

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 503,
        "MESSAGE": "Service Unavailable",
        "DATA": {"some_unknown_key": "some_value"},
    }
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.error_message is not None
    assert "503" in instance.error_message


def test_response_handler_nd_00790():
    """
    # Summary

    Verify error_message returns None when result success is True.

    ## Test

    - Even with error-like DATA, if result is success, error_message is None

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"errors": ["Some error"]},
    }
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    # For GET with 200, success is True regardless of DATA content
    assert instance.result["success"] is True
    assert instance.error_message is None


def test_response_handler_nd_00800():
    """
    # Summary

    Verify error_message for connection failure with no REQUEST_PATH.

    ## Test

    - When DATA is None and REQUEST_PATH is missing, error_message uses "unknown"

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Connection timed out",
    }
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.error_message is not None
    assert "unknown" in instance.error_message
    assert "Connection timed out" in instance.error_message


def test_response_handler_nd_00810():
    """
    # Summary

    Verify error_message for messages array with empty array.

    ## Test

    - When DATA contains an empty messages array, messages format is skipped
      and fallback is used

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {"messages": []},
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "400" in instance.error_message


def test_response_handler_nd_00820():
    """
    # Summary

    Verify error_message for errors array with empty array.

    ## Test

    - When DATA contains an empty errors array, errors format is skipped
      and fallback is used

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {"errors": []},
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "400" in instance.error_message


# =============================================================================
# Test: ResponseHandler._handle_response() routing
# =============================================================================


def test_response_handler_nd_00900():
    """
    # Summary

    Verify _handle_response routes GET to _handle_get_response.

    ## Test

    - GET verb produces result with "found" key (not "changed")

    ## Classes and Methods

    - ResponseHandler._handle_response()
    - ResponseHandler._handle_get_response()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert "found" in instance.result
    assert "changed" not in instance.result


def test_response_handler_nd_00910():
    """
    # Summary

    Verify _handle_response routes POST to _handle_post_put_delete_response.

    ## Test

    - POST verb produces result with "changed" key (not "found")

    ## Classes and Methods

    - ResponseHandler._handle_response()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert "changed" in instance.result
    assert "found" not in instance.result


def test_response_handler_nd_00920():
    """
    # Summary

    Verify _handle_response routes PUT to _handle_post_put_delete_response.

    ## Test

    - PUT verb produces result with "changed" key (not "found")

    ## Classes and Methods

    - ResponseHandler._handle_response()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
    instance.verb = HttpVerbEnum.PUT
    instance.commit()
    assert "changed" in instance.result
    assert "found" not in instance.result


def test_response_handler_nd_00930():
    """
    # Summary

    Verify _handle_response routes DELETE to _handle_post_put_delete_response.

    ## Test

    - DELETE verb produces result with "changed" key (not "found")

    ## Classes and Methods

    - ResponseHandler._handle_response()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
    instance.verb = HttpVerbEnum.DELETE
    instance.commit()
    assert "changed" in instance.result
    assert "found" not in instance.result


# =============================================================================
# Test: ResponseHandler with code/message + messages array in same response
# =============================================================================


def test_response_handler_nd_01000():
    """
    # Summary

    Verify error_message prefers code/message format over messages array.

    ## Test

    - When DATA contains both code/message and messages array,
      code/message takes priority

    ## Classes and Methods

    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 400,
        "MESSAGE": "Bad Request",
        "DATA": {
            "code": "PRIMARY_ERROR",
            "message": "Primary error message",
            "messages": [
                {
                    "code": "SECONDARY",
                    "severity": "WARNING",
                    "message": "Secondary message",
                }
            ],
        },
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "PRIMARY_ERROR" in instance.error_message
    assert "Primary error message" in instance.error_message


# =============================================================================
# Test: Multi-Status per-item failure detection (issue #295)
#
# ND reports per-item outcomes for batch operations in a DATA envelope array whose
# items carry status: "success" | "failed" | "failure" | "error". The two known
# envelope shapes are DATA.results[] (batch interface / breakout) and
# DATA.switchIds[] (switchActions/deploy). ND sends these bodies on HTTP 207 and,
# for some endpoints, on plain HTTP 200 -- so any success-code response whose body
# contains a failing item must NOT be classified as success.
# =============================================================================


def test_response_handler_nd_01200():
    """
    # Summary

    Verify 207 with a failed `DATA.results[]` item is not success.

    ## Test

    - POST with RETURN_CODE 207 and a results[] item status "failed"
      sets success=False, changed=False

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {
                    "name": "Port-channel1.999",
                    "status": "failed",
                    "message": "Sub-interface can be created only on routed interfaces",
                }
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["changed"] is False


def test_response_handler_nd_01210():
    """
    # Summary

    Verify 207 with an errored `DATA.results[]` item is not success.

    ## Test

    - POST with RETURN_CODE 207 and a results[] item status "error"
      (breakout-style literal) sets success=False

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {
                    "name": "Ethernet1/1",
                    "status": "error",
                    "message": "Breakout not supported on this port",
                }
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False


def test_response_handler_nd_01220():
    """
    # Summary

    Verify 207 with a failed `DATA.switchIds[]` item is not success.

    ## Test

    - POST with RETURN_CODE 207 and a switchIds[] item status "failed"
      (switchActions/deploy shape) sets success=False

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "switchIds": [
                {"switchId": "FDO1234ABCD", "status": "success"},
                {"switchId": "FDO5678WXYZ", "status": "failed", "message": "Deploy failed on peer"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False


def test_response_handler_nd_01230():
    """
    # Summary

    Verify 207 whose per-item statuses all succeed remains success.

    ## Test

    - POST with RETURN_CODE 207 and results[] items all status "success"
      sets success=True, changed=True (no failing item present)
    - retryable is False (key present on every mutation result)

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {"name": "Ethernet1/1", "status": "success"},
                {"name": "Ethernet1/2", "status": "success"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is True
    assert instance.result["changed"] is True
    assert instance.result["retryable"] is False


def test_response_handler_nd_01240():
    """
    # Summary

    Verify error_message aggregates failed `DATA.results[]` items.

    ## Test

    - A 207 with a failed results[] item exposes an error_message
      naming the item and its per-item message

    ## Classes and Methods

    - NdV1Strategy.extract_error_message()
    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {
                    "name": "Port-channel1.999",
                    "status": "failed",
                    "message": "Sub-interface can be created only on routed interfaces",
                }
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "Port-channel1.999" in instance.error_message
    assert "Sub-interface can be created only on routed interfaces" in instance.error_message


def test_response_handler_nd_01250():
    """
    # Summary

    Verify error_message aggregates failed `DATA.switchIds[]` items.

    ## Test

    - A 207 with a failed switchIds[] item exposes an error_message
      naming the switch and its per-item message

    ## Classes and Methods

    - NdV1Strategy.extract_error_message()
    - ResponseHandler.error_message
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "switchIds": [
                {"switchId": "FDO5678WXYZ", "status": "failed", "message": "Deploy failed on peer"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.error_message is not None
    assert "FDO5678WXYZ" in instance.error_message
    assert "Deploy failed on peer" in instance.error_message


def test_response_handler_nd_01260():
    """
    # Summary

    Verify a mixed 207 (one ok, one failed) fails and names only the failure.

    ## Test

    - A 207 with one success item and one failed item sets success=False
    - error_message names only the failed item, not the successful one

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - NdV1Strategy.extract_error_message()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "switchIds": [
                {"switchId": "FDO1111AAAA", "status": "success"},
                {"switchId": "FDO2222BBBB", "status": "failed", "message": "peer deploy failed"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message is not None
    assert "FDO2222BBBB" in instance.error_message
    assert "FDO1111AAAA" not in instance.error_message


def test_response_handler_nd_01270():
    """
    # Summary

    Verify the `failure` per-item literal (not just `failed`) is detected.

    ## Test

    - A 207 with a results[] item status "failure" sets success=False

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {"results": [{"name": "acl-1", "status": "failure", "message": "rejected"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False


def test_response_handler_nd_01280():
    """
    # Summary

    Verify a per-item status with surrounding whitespace and mixed case still counts as a failure.

    ## Test

    - A 207 with a results[] item status "  Failed  " (padded, mixed case) sets success=False

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {"results": [{"name": "eth1/1", "status": "  Failed  ", "message": "rejected"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False


def test_response_handler_nd_01290():
    """
    # Summary

    Verify a 207 whose per-item `status` is None (or a non-failure value) remains success.

    ## Test

    - A 207 with a results[] item whose status is None does not flip success

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {"results": [{"name": "eth1/1", "status": None, "message": "no status key"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is True


def test_response_handler_nd_01300():
    """
    # Summary

    Verify an empty-string label key is skipped rather than used as the label.

    ## Test

    - A 207 whose failing item carries name="" falls through to the next label key (switchId)
    - The message is labelled "FDO5678WXYZ: ...", not ": ..."

    ## Classes and Methods

    - NdV1Strategy._format_multistatus_failure()
    - NdV1Strategy.extract_error_message()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {"results": [{"name": "", "switchId": "FDO5678WXYZ", "status": "failed", "message": "Deploy failed"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message is not None
    assert "FDO5678WXYZ: Deploy failed" in instance.error_message
    assert not instance.error_message.startswith("ND Error: : ")


def test_response_handler_nd_01310():
    """
    # Summary

    Verify `warningMessage` is used as the per-item detail when no `message` key is present.

    ## Test

    - A 207 failing item carrying warningMessage (fabric update-group shape) surfaces that text

    ## Classes and Methods

    - NdV1Strategy._format_multistatus_failure()
    - NdV1Strategy.extract_error_message()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {"results": [{"name": "leaf_group", "status": "failed", "warningMessage": "Switch not found"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message is not None
    assert "leaf_group: Switch not found" in instance.error_message


def test_response_handler_nd_01320():
    """
    # Summary

    Verify a failing item with neither a label key nor a detail key yields the generic literal.

    ## Test

    - A 207 failing item carrying only status="failed" surfaces "ND Error: failed"

    ## Classes and Methods

    - NdV1Strategy._format_multistatus_failure()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {"results": [{"status": "failed"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message == "ND Error: failed"


# =============================================================================
# Test: Null-valued DATA keys do not crash error-message extraction
#
# ND may send `messages` or `errors` with an explicit null value. The key is
# present, so a bare `"messages" in data_dict and len(data_dict["messages"])`
# raises TypeError on the very path that reports an error to the user.
# =============================================================================


def test_response_handler_nd_01330():
    """
    # Summary

    Verify a null `DATA.messages` does not raise and falls back to the generic message.

    ## Test

    - A 500 whose DATA carries messages=None commits without raising
    - error_message is the generic status fallback

    ## Classes and Methods

    - NdV1Strategy._extract_dict_error_message()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {"messages": None},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message == "ND Error: Request failed with status 500"


def test_response_handler_nd_01340():
    """
    # Summary

    Verify a null `DATA.errors` does not raise and falls back to the generic message.

    ## Test

    - A 500 whose DATA carries errors=None commits without raising
    - error_message is the generic status fallback

    ## Classes and Methods

    - NdV1Strategy._extract_dict_error_message()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {"errors": None},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message == "ND Error: Request failed with status 500"


# =============================================================================
# Test: DATA.error text is surfaced, not dropped
#
# is_success() classifies a response carrying DATA.error as a failure. Without a
# matching branch in the error-message extractor, the text ND actually sent was
# dropped in favour of the generic "Request failed with status <code>" fallback.
# =============================================================================


def test_response_handler_nd_01350():
    """
    # Summary

    Verify the scalar `DATA.error` value is surfaced in error_message.

    ## Test

    - A 200 whose DATA carries error="ND error occurred" sets success=False
    - error_message carries the error text rather than the generic fallback

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - NdV1Strategy._extract_dict_error_message()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"error": "ND error occurred"},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message == "ND Error: ND error occurred"


# =============================================================================
# Test: links[] Multi-Status envelope (bulk link create / delete)
#
# POST /api/v1/manage/links and POST /api/v1/manage/linkActions/remove return
# HTTP 207 with {"links": [{"linkId", "message", "status"}]}, status
# success|failure. The GET /links list body rides the same `links` envelope,
# but its link objects carry no top-level `status` key, so queries must not
# false-positive. See PR #398 discussion.
# =============================================================================


def test_response_handler_nd_01360():
    """
    # Summary

    Verify a 207 `links[]` envelope with a failing item is classified as failure and labelled by linkId.

    ## Test

    - A 207 links body with one success and one failure item sets success=False
    - The failing item is labelled by its linkId in error_message
    - The succeeding item does not appear in error_message

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - NdV1Strategy._format_multistatus_failure()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "links": [
                {"linkId": "LINK-UUID-8540", "message": "LINK-UUID-8540 deleted successfully", "status": "success"},
                {"linkId": "LINK-UUID-8541", "message": "Deletion of link with id:LINK-UUID-8541 failed due to invalid linkId.", "status": "failure"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message is not None
    assert "LINK-UUID-8541: Deletion of link with id:LINK-UUID-8541 failed due to invalid linkId." in instance.error_message
    assert "LINK-UUID-8540" not in instance.error_message


def test_response_handler_nd_01370():
    """
    # Summary

    Verify a 207 `links[]` envelope whose items all succeed is classified as success.

    ## Test

    - A 207 links body with only success items sets success=True

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "links": [
                {"linkId": "LINK-UUID-8540", "message": "LINK-UUID-8540 created successfully", "status": "success"},
                {"linkId": "LINK-UUID-8541", "message": "LINK-UUID-8541 created successfully", "status": "success"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is True


def test_response_handler_nd_01380():
    """
    # Summary

    Verify a failing links item carrying linkId="" yields an unlabelled message rather than ": <message>".

    ## Test

    - A 207 links failure item with an empty linkId (the bulk-create OpenAPI example: the link was
      never created, so ND has no id to report) surfaces the message without a label prefix

    ## Classes and Methods

    - NdV1Strategy._format_multistatus_failure()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "links": [
                {"linkId": "LINK-UUID-8540", "message": "LINK-UUID-8540 created successfully", "status": "success"},
                {"linkId": "", "message": "PTI POLICY-14240 already associated for the link LINK-UUID-15010.", "status": "failure"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.error_message == "ND Error: PTI POLICY-14240 already associated for the link LINK-UUID-15010."


def test_response_handler_nd_01390():
    """
    # Summary

    Verify a GET-shaped `links[]` list body (link objects, no `status` key) is not a false positive.

    ## Test

    - A 200 GET /links body whose link objects carry linkId but no status sets success=True

    ## Classes and Methods

    - NdV1Strategy.is_success()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {
            "links": [
                {"linkId": "LINK-UUID-8540", "linkType": "lan_neighbor_link", "srcInterfaceName": "Ethernet1/2", "dstInterfaceName": "Ethernet1/9"},
                {"linkId": "LINK-UUID-48060", "linkType": "lan_planned_link", "srcInterfaceName": "Ethernet1/16", "dstInterfaceName": "Ethernet1/16"},
            ],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        },
    }
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is True
    assert instance.result["found"] is True


# =============================================================================
# Test: ResponseHandler commit() can be called multiple times
# =============================================================================


def test_response_handler_nd_01100():
    """
    # Summary

    Verify commit() can be called with different responses.

    ## Test

    - First commit with 200 success
    - Second commit with 500 error
    - result reflects the most recent commit

    ## Classes and Methods

    - ResponseHandler.commit()
    """
    instance = ResponseHandler()

    # First commit - success
    instance.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.result["success"] is True
    assert instance.result["found"] is True

    # Second commit - failure
    instance.response = {"RETURN_CODE": 500, "MESSAGE": "Internal Server Error"}
    instance.verb = HttpVerbEnum.GET
    instance.commit()
    assert instance.result["success"] is False
    assert instance.result["found"] is False


def test_response_handler_nd_01400():
    """
    # Summary

    Verify a mixed 207 POST (one success, one failed item) is classified as a terminal failure.

    ## Test

    - POST 207 with results[] holding one success and one failed item
    - success is False and retryable is False (success-code response with embedded per-item failure cannot succeed on replay)

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {"name": "acl_new", "status": "success", "message": "created successfully"},
                {"name": "acl_seed", "status": "failed", "message": "ACL already exists"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["retryable"] is False


def test_response_handler_nd_01410():
    """
    # Summary

    Verify a POST failing with a non-success HTTP code remains retryable.

    ## Test

    - POST returns 500
    - success is False and retryable is True (transient transport-level failures keep today's retry behavior)
    - changed is False (a pure transport failure changed nothing)

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {"error": "backend unavailable"},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["retryable"] is True
    assert instance.result["changed"] is False


def test_response_handler_nd_01420():
    """
    # Summary

    Verify a fully successful POST carries retryable=False.

    ## Test

    - POST 200 with all items succeeding
    - success is True and retryable is False (key present on every mutation result for a consistent shape)

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"results": [{"name": "acl_new", "status": "success"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is True
    assert instance.result["retryable"] is False


def test_response_handler_nd_01430():
    """
    # Summary

    Verify DATA.error on a success code is classified as a terminal failure.

    ## Test

    - POST 200 with DATA.error set (pre-existing embedded-error shape)
    - success is False and retryable is False — the application definitively rejected the request

    ## Classes and Methods

    - ResponseHandler._handle_post_put_delete_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"error": "VRF does not exist"},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["retryable"] is False


def test_response_handler_nd_01440():
    """
    # Summary

    Verify GET results carry no retryable key (GET retry semantics are unchanged).

    ## Test

    - GET returns 500
    - result has no "retryable" key, so RestSend's .get("retryable", True) default preserves today's GET retry behavior

    ## Classes and Methods

    - ResponseHandler._handle_get_response()
    - ResponseHandler.commit()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": {},
    }
    instance.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert "retryable" not in instance.result


def test_response_handler_nd_01450():
    """
    # Summary

    Verify a mixed 207 POST reports changed=True (a member succeeded, so controller state changed).

    ## Test

    - POST 207 with one success and one failed item
    - success is False, changed is True

    ## Classes and Methods

    - NdV1Strategy.is_changed_on_failure()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {"name": "acl_new", "status": "success", "message": "created successfully"},
                {"name": "acl_seed", "status": "failed", "message": "ACL already exists"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["changed"] is True


def test_response_handler_nd_01460():
    """
    # Summary

    Verify an all-failed 207 POST reports changed=False.

    ## Test

    - POST 207 where every results[] item failed
    - success is False, changed is False

    ## Classes and Methods

    - NdV1Strategy.is_changed_on_failure()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "DATA": {
            "results": [
                {"name": "acl_new", "status": "failed", "message": "invalid entry"},
                {"name": "acl_seed", "status": "failed", "message": "ACL already exists"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["changed"] is False


def test_response_handler_nd_01470():
    """
    # Summary

    Verify the modified header overrides the per-item scan on failure (header says false).

    ## Test

    - Mixed 207 POST whose modified header is "false"
    - changed is False even though one item succeeded (the header is authoritative)

    ## Classes and Methods

    - NdV1Strategy.is_changed_on_failure()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "modified": "false",
        "DATA": {
            "results": [
                {"name": "acl_new", "status": "success"},
                {"name": "acl_seed", "status": "failed", "message": "ACL already exists"},
            ]
        },
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["changed"] is False


def test_response_handler_nd_01480():
    """
    # Summary

    Verify the modified header overrides the per-item scan on failure (header says true).

    ## Test

    - All-failed 207 POST whose modified header is "true"
    - changed is True even though no item succeeded (the header is authoritative)

    ## Classes and Methods

    - NdV1Strategy.is_changed_on_failure()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 207,
        "MESSAGE": "Multi-Status",
        "modified": "true",
        "DATA": {"results": [{"name": "acl_seed", "status": "failed", "message": "ACL already exists"}]},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["changed"] is True


def test_response_handler_nd_01490():
    """
    # Summary

    Verify a non-itemized embedded error (DATA.error on 200) keeps changed=False.

    ## Test

    - POST 200 with DATA.error, no modified header, no per-item envelope
    - success is False, changed is False (conservative default preserved)

    ## Classes and Methods

    - NdV1Strategy.is_changed_on_failure()
    - ResponseHandler._handle_post_put_delete_response()
    """
    instance = ResponseHandler()
    instance.response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"error": "VRF does not exist"},
    }
    instance.verb = HttpVerbEnum.POST
    with does_not_raise():
        instance.commit()
    assert instance.result["success"] is False
    assert instance.result["changed"] is False
