# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for sender_nd.py

Tests the Sender class for sending REST requests via the Ansible HttpApi plugin.
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

from unittest.mock import MagicMock, patch

import pytest
from ansible.module_utils.connection import ConnectionError as AnsibleConnectionError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise

# =============================================================================
# Test: Sender initialization
# =============================================================================


def test_sender_nd_00010():
    """
    # Summary

    Verify Sender initialization with default values.

    ## Test

    - Instance can be created with no arguments
    - All attributes default to None

    ## Classes and Methods

    - Sender.__init__()
    """
    with does_not_raise():
        instance = Sender()
    assert instance._ansible_module is None
    assert instance._connection is None
    assert instance._path is None
    assert instance._payload is None
    assert instance._response is None
    assert instance._verb is None


def test_sender_nd_00020():
    """
    # Summary

    Verify Sender initialization with all parameters.

    ## Test

    - Instance can be created with all optional constructor arguments

    ## Classes and Methods

    - Sender.__init__()
    """
    mock_module = MagicMock()
    with does_not_raise():
        instance = Sender(
            ansible_module=mock_module,
            verb=HttpVerbEnum.GET,
            path="/api/v1/test",
            payload={"key": "value"},
        )
    assert instance._ansible_module is mock_module
    assert instance._path == "/api/v1/test"
    assert instance._payload == {"key": "value"}
    assert instance._verb == HttpVerbEnum.GET


# =============================================================================
# Test: Sender.ansible_module property
# =============================================================================


def test_sender_nd_00100():
    """
    # Summary

    Verify ansible_module getter raises ValueError when not set.

    ## Test

    - Accessing ansible_module before setting raises ValueError

    ## Classes and Methods

    - Sender.ansible_module (getter)
    """
    instance = Sender()
    match = r"Sender\.ansible_module:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.ansible_module


def test_sender_nd_00110():
    """
    # Summary

    Verify ansible_module setter/getter.

    ## Test

    - ansible_module can be set and retrieved

    ## Classes and Methods

    - Sender.ansible_module (setter/getter)
    """
    instance = Sender()
    mock_module = MagicMock()
    with does_not_raise():
        instance.ansible_module = mock_module
        result = instance.ansible_module
    assert result is mock_module


# =============================================================================
# Test: Sender.path property
# =============================================================================


def test_sender_nd_00200():
    """
    # Summary

    Verify path getter raises ValueError when not set.

    ## Test

    - Accessing path before setting raises ValueError

    ## Classes and Methods

    - Sender.path (getter)
    """
    instance = Sender()
    match = r"Sender\.path:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.path


def test_sender_nd_00210():
    """
    # Summary

    Verify path setter/getter.

    ## Test

    - path can be set and retrieved

    ## Classes and Methods

    - Sender.path (setter/getter)
    """
    instance = Sender()
    with does_not_raise():
        instance.path = "/api/v1/test/endpoint"
        result = instance.path
    assert result == "/api/v1/test/endpoint"


# =============================================================================
# Test: Sender.verb property
# =============================================================================


def test_sender_nd_00300():
    """
    # Summary

    Verify verb getter raises ValueError when not set.

    ## Test

    - Accessing verb before setting raises ValueError

    ## Classes and Methods

    - Sender.verb (getter)
    """
    instance = Sender()
    match = r"Sender\.verb:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.verb


def test_sender_nd_00310():
    """
    # Summary

    Verify verb setter/getter with valid HttpVerbEnum.

    ## Test

    - verb can be set and retrieved with all HttpVerbEnum values

    ## Classes and Methods

    - Sender.verb (setter/getter)
    """
    instance = Sender()
    for verb in (HttpVerbEnum.GET, HttpVerbEnum.POST, HttpVerbEnum.PUT, HttpVerbEnum.DELETE):
        with does_not_raise():
            instance.verb = verb
            result = instance.verb
        assert result == verb


def test_sender_nd_00320():
    """
    # Summary

    Verify verb setter raises TypeError for invalid value.

    ## Test

    - Setting verb to a value not in HttpVerbEnum.values() raises TypeError

    ## Classes and Methods

    - Sender.verb (setter)
    """
    instance = Sender()
    match = r"Sender\.verb:.*must be one of"
    with pytest.raises(TypeError, match=match):
        instance.verb = "INVALID"  # type: ignore[assignment]


# =============================================================================
# Test: Sender.payload property
# =============================================================================


def test_sender_nd_00400():
    """
    # Summary

    Verify payload defaults to None.

    ## Test

    - payload is None by default

    ## Classes and Methods

    - Sender.payload (getter)
    """
    instance = Sender()
    with does_not_raise():
        result = instance.payload
    assert result is None


def test_sender_nd_00410():
    """
    # Summary

    Verify payload setter/getter with valid dict.

    ## Test

    - payload can be set and retrieved

    ## Classes and Methods

    - Sender.payload (setter/getter)
    """
    instance = Sender()
    with does_not_raise():
        instance.payload = {"name": "test", "config": {"key": "value"}}
        result = instance.payload
    assert result == {"name": "test", "config": {"key": "value"}}


def test_sender_nd_00420():
    """
    # Summary

    Verify payload setter raises TypeError for non-dict.

    ## Test

    - Setting payload to a non-dict raises TypeError

    ## Classes and Methods

    - Sender.payload (setter)
    """
    instance = Sender()
    match = r"Sender\.payload:.*must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.payload = "not a dict"  # type: ignore[assignment]


def test_sender_nd_00430():
    """
    # Summary

    Verify payload setter raises TypeError for list.

    ## Test

    - Setting payload to a list raises TypeError

    ## Classes and Methods

    - Sender.payload (setter)
    """
    instance = Sender()
    match = r"Sender\.payload:.*must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.payload = [1, 2, 3]  # type: ignore[assignment]


# =============================================================================
# Test: Sender.response property
# =============================================================================


def test_sender_nd_00500():
    """
    # Summary

    Verify response getter raises ValueError when not set.

    ## Test

    - Accessing response before commit raises ValueError

    ## Classes and Methods

    - Sender.response (getter)
    """
    instance = Sender()
    match = r"Sender\.response:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.response


def test_sender_nd_00510():
    """
    # Summary

    Verify response getter returns deepcopy.

    ## Test

    - response getter returns a deepcopy of the internal response

    ## Classes and Methods

    - Sender.response (getter)
    """
    instance = Sender()
    instance._response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {"key": "value"}}
    result = instance.response
    # Modify the copy
    result["MODIFIED"] = True
    # Verify original is unchanged
    assert "MODIFIED" not in instance._response


def test_sender_nd_00520():
    """
    # Summary

    Verify response setter raises TypeError for non-dict.

    ## Test

    - Setting response to a non-dict raises TypeError

    ## Classes and Methods

    - Sender.response (setter)
    """
    instance = Sender()
    match = r"Sender\.response:.*must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.response = "not a dict"  # type: ignore[assignment]


def test_sender_nd_00530():
    """
    # Summary

    Verify response setter accepts valid dict.

    ## Test

    - response can be set with a valid dict

    ## Classes and Methods

    - Sender.response (setter/getter)
    """
    instance = Sender()
    response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    with does_not_raise():
        instance.response = response
        result = instance.response
    assert result["RETURN_CODE"] == 200
    assert result["MESSAGE"] == "OK"


# =============================================================================
# Test: Sender._normalize_response()
# =============================================================================


def test_sender_nd_00600():
    """
    # Summary

    Verify _normalize_response with normal JSON response.

    ## Test

    - Response with valid DATA passes through unchanged

    ## Classes and Methods

    - Sender._normalize_response()
    """
    instance = Sender()
    response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"status": "success"},
    }
    result = instance._normalize_response(response)
    assert result["DATA"] == {"status": "success"}
    assert result["MESSAGE"] == "OK"


def test_sender_nd_00610():
    """
    # Summary

    Verify _normalize_response when DATA is None and raw is present.

    ## Test

    - When DATA is None and raw is present, DATA is populated with raw_response
    - MESSAGE is set to indicate JSON parsing failure

    ## Classes and Methods

    - Sender._normalize_response()
    """
    instance = Sender()
    response = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": None,
        "raw": "<html>Not JSON</html>",
    }
    result = instance._normalize_response(response)
    assert result["DATA"] == {"raw_response": "<html>Not JSON</html>"}
    assert result["MESSAGE"] == "Response could not be parsed as JSON"


def test_sender_nd_00620():
    """
    # Summary

    Verify _normalize_response when DATA is None, raw is present,
    and MESSAGE is None.

    ## Test

    - When MESSAGE is None, it is set to indicate JSON parsing failure

    ## Classes and Methods

    - Sender._normalize_response()
    """
    instance = Sender()
    response = {
        "RETURN_CODE": 200,
        "MESSAGE": None,
        "DATA": None,
        "raw": "raw content",
    }
    result = instance._normalize_response(response)
    assert result["DATA"] == {"raw_response": "raw content"}
    assert result["MESSAGE"] == "Response could not be parsed as JSON"


def test_sender_nd_00630():
    """
    # Summary

    Verify _normalize_response when DATA is None and raw is also None.

    ## Test

    - When both DATA and raw are None, response is not modified

    ## Classes and Methods

    - Sender._normalize_response()
    """
    instance = Sender()
    response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": None,
    }
    result = instance._normalize_response(response)
    assert result["DATA"] is None
    assert result["MESSAGE"] == "Internal Server Error"


def test_sender_nd_00640():
    """
    # Summary

    Verify _normalize_response preserves non-OK MESSAGE when raw is present.

    ## Test

    - When DATA is None and raw is present, MESSAGE is only overwritten
      if it was "OK" or None

    ## Classes and Methods

    - Sender._normalize_response()
    """
    instance = Sender()
    response = {
        "RETURN_CODE": 500,
        "MESSAGE": "Internal Server Error",
        "DATA": None,
        "raw": "raw error content",
    }
    result = instance._normalize_response(response)
    assert result["DATA"] == {"raw_response": "raw error content"}
    # MESSAGE is NOT overwritten because it's not "OK" or None
    assert result["MESSAGE"] == "Internal Server Error"


# =============================================================================
# Test: Sender.commit() with mocked Connection
# =============================================================================


def test_sender_nd_00700():
    """
    # Summary

    Verify commit() with successful GET request (no payload).

    ## Test

    - commit() calls Connection.send_request with verb and path
    - response is populated from the Connection response

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.return_value = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"status": "success"},
    }

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        with does_not_raise():
            instance.commit()

    assert instance.response["RETURN_CODE"] == 200
    assert instance.response["DATA"]["status"] == "success"
    mock_connection.send_request.assert_called_once_with("GET", "/api/v1/test")


def test_sender_nd_00710():
    """
    # Summary

    Verify commit() with POST request including payload.

    ## Test

    - commit() calls Connection.send_request with verb, path, and JSON payload

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.return_value = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"status": "created"},
    }

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test/create"
    instance.verb = HttpVerbEnum.POST
    instance.payload = {"name": "test"}

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        with does_not_raise():
            instance.commit()

    assert instance.response["RETURN_CODE"] == 200
    assert instance.response["DATA"]["status"] == "created"
    mock_connection.send_request.assert_called_once_with(
        "POST",
        "/api/v1/test/create",
        '{"name": "test"}',
    )


def test_sender_nd_00720():
    """
    # Summary

    Verify commit() raises ValueError on connection failure.

    ## Test

    - When Connection.send_request raises AnsibleConnectionError,
      commit() re-raises as ValueError

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.side_effect = AnsibleConnectionError("Connection refused")

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        match = r"Sender\.commit:.*ConnectionError occurred"
        with pytest.raises(ValueError, match=match):
            instance.commit()


def test_sender_nd_00730():
    """
    # Summary

    Verify commit() raises ValueError on unexpected exception.

    ## Test

    - When Connection.send_request raises an unexpected Exception,
      commit() wraps it in ValueError

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.side_effect = RuntimeError("Unexpected error")

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        match = r"Sender\.commit:.*Unexpected error occurred"
        with pytest.raises(ValueError, match=match):
            instance.commit()


def test_sender_nd_00740():
    """
    # Summary

    Verify commit() reuses existing connection on second call.

    ## Test

    - First commit creates a new Connection
    - Second commit reuses the existing connection
    - Connection constructor is called only once

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.return_value = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {},
    }

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ) as mock_conn_class:
        instance = Sender()
        instance.ansible_module = mock_module
        instance.path = "/api/v1/test"
        instance.verb = HttpVerbEnum.GET

        instance.commit()
        instance.commit()

        # Connection constructor should only be called once
        mock_conn_class.assert_called_once()
        # send_request should be called twice
        assert mock_connection.send_request.call_count == 2


def test_sender_nd_00750():
    """
    # Summary

    Verify commit() normalizes non-JSON responses.

    ## Test

    - When Connection returns DATA=None with raw content,
      commit() normalizes the response

    ## Classes and Methods

    - Sender.commit()
    - Sender._normalize_response()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.return_value = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": None,
        "raw": "<html>Non-JSON response</html>",
    }

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        with does_not_raise():
            instance.commit()

    assert instance.response["DATA"] == {"raw_response": "<html>Non-JSON response</html>"}
    assert instance.response["MESSAGE"] == "Response could not be parsed as JSON"


def test_sender_nd_00760():
    """
    # Summary

    Verify commit() with PUT request including payload.

    ## Test

    - commit() calls Connection.send_request with PUT verb, path, and JSON payload

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.return_value = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"status": "updated"},
    }

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test/update/12345"
    instance.verb = HttpVerbEnum.PUT
    instance.payload = {"status": "active"}

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        with does_not_raise():
            instance.commit()

    assert instance.response["RETURN_CODE"] == 200
    mock_connection.send_request.assert_called_once_with(
        "PUT",
        "/api/v1/test/update/12345",
        '{"status": "active"}',
    )


def test_sender_nd_00770():
    """
    # Summary

    Verify commit() with DELETE request (no payload).

    ## Test

    - commit() calls Connection.send_request with DELETE verb and path

    ## Classes and Methods

    - Sender.commit()
    """
    mock_module = MagicMock()
    mock_module._socket_path = "/tmp/test_socket"
    mock_module.params = {"config": {}}

    mock_connection = MagicMock()
    mock_connection.send_request.return_value = {
        "RETURN_CODE": 200,
        "MESSAGE": "OK",
        "DATA": {"status": "deleted"},
    }

    instance = Sender()
    instance.ansible_module = mock_module
    instance.path = "/api/v1/test/delete/12345"
    instance.verb = HttpVerbEnum.DELETE

    with patch(
        "ansible_collections.cisco.nd.plugins.module_utils.sender_nd.Connection",
        return_value=mock_connection,
    ):
        with does_not_raise():
            instance.commit()

    assert instance.response["RETURN_CODE"] == 200
    mock_connection.send_request.assert_called_once_with("DELETE", "/api/v1/test/delete/12345")
