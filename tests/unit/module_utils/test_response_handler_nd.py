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
from ansible_collections.cisco.nd.plugins.module_utils.response_handler_nd import ResponseHandler
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
    - RETURN_CODES_SUCCESS contains expected status codes
    - RETURN_CODE_NOT_FOUND is 404

    ## Classes and Methods

    - ResponseHandler.__init__()
    """
    with does_not_raise():
        instance = ResponseHandler()
    assert instance._response is None
    assert instance._result is None
    assert instance._verb is None
    assert instance.RETURN_CODES_SUCCESS == {200, 201, 202, 204}
    assert instance.RETURN_CODE_NOT_FOUND == 404


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
