# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for rest_send.py

Tests the RestSend class for sending REST requests with retries
"""

# pylint: disable=disallowed-name,protected-access,too-many-lines

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import inspect

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender


def responses_rest_send(key: str):
    """
    Load fixture data for rest_send tests
    """
    return load_fixture("test_rest_send")[key]


# =============================================================================
# Test: RestSend initialization
# =============================================================================


def test_rest_send_00010():
    """
    # Summary

    Verify RestSend initialization with default values

    ## Test

    - Instance can be created with params dict
    - check_mode defaults to False
    - timeout defaults to 300
    - send_interval defaults to 5
    - unit_test defaults to False

    ## Classes and Methods

    - RestSend.__init__()
    """
    params = {"check_mode": False, "state": "merged"}
    with does_not_raise():
        instance = RestSend(params)
    assert instance.check_mode is False
    assert instance.timeout == 300
    assert instance.send_interval == 5
    assert instance.unit_test is False


def test_rest_send_00020():
    """
    # Summary

    Verify RestSend initialization with check_mode True

    ## Test

    - check_mode can be set via params

    ## Classes and Methods

    - RestSend.__init__()
    """
    params = {"check_mode": True, "state": "merged"}
    with does_not_raise():
        instance = RestSend(params)
    assert instance.check_mode is True


def test_rest_send_00030():
    """
    # Summary

    Verify RestSend raises TypeError for invalid check_mode

    ## Test

    - check_mode setter raises TypeError if not bool

    ## Classes and Methods

    - RestSend.check_mode
    """
    params = {"check_mode": False}
    instance = RestSend(params)
    match = r"RestSend\.check_mode:.*must be a boolean"
    with pytest.raises(TypeError, match=match):
        instance.check_mode = "invalid"  # type: ignore[assignment]


# =============================================================================
# Test: RestSend property setters/getters
# =============================================================================


def test_rest_send_00100():
    """
    # Summary

    Verify path property getter/setter

    ## Test

    - path can be set and retrieved
    - ValueError raised if accessed before being set

    ## Classes and Methods

    - RestSend.path
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test ValueError when accessing before setting
    match = r"RestSend\.path:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.path  # pylint: disable=pointless-statement

    # Test setter/getter
    with does_not_raise():
        instance.path = "/api/v1/test/endpoint"
        result = instance.path
    assert result == "/api/v1/test/endpoint"


def test_rest_send_00110():
    """
    # Summary

    Verify verb property getter/setter

    ## Test

    - verb can be set and retrieved with HttpVerbEnum
    - verb has default value of HttpVerbEnum.GET
    - TypeError raised if not HttpVerbEnum

    ## Classes and Methods

    - RestSend.verb
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test default value
    with does_not_raise():
        result = instance.verb
    assert result == HttpVerbEnum.GET

    # Test TypeError for invalid type
    match = r"RestSend\.verb:.*must be an instance of HttpVerbEnum"
    with pytest.raises(TypeError, match=match):
        instance.verb = "GET"  # type: ignore[assignment]

    # Test setter/getter with valid HttpVerbEnum
    with does_not_raise():
        instance.verb = HttpVerbEnum.POST
        result = instance.verb
    assert result == HttpVerbEnum.POST


def test_rest_send_00120():
    """
    # Summary

    Verify payload property getter/setter

    ## Test

    - payload can be set and retrieved
    - payload defaults to None
    - TypeError raised if not dict

    ## Classes and Methods

    - RestSend.payload
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test default value
    with does_not_raise():
        result = instance.payload
    assert result is None

    # Test TypeError for invalid type
    match = r"RestSend\.payload:.*must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.payload = "invalid"  # type: ignore[assignment]

    # Test setter/getter with dict
    with does_not_raise():
        instance.payload = {"key": "value"}
        result = instance.payload
    assert result == {"key": "value"}


def test_rest_send_00130():
    """
    # Summary

    Verify timeout property getter/setter

    ## Test

    - timeout can be set and retrieved
    - timeout defaults to 300
    - TypeError raised if not int

    ## Classes and Methods

    - RestSend.timeout
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test default value
    assert instance.timeout == 300

    # Test TypeError for boolean (bool is subclass of int)
    match = r"RestSend\.timeout:.*must be an integer"
    with pytest.raises(TypeError, match=match):
        instance.timeout = True  # type: ignore[assignment]

    # Test TypeError for string
    with pytest.raises(TypeError, match=match):
        instance.timeout = "300"  # type: ignore[assignment]

    # Test setter/getter with int
    with does_not_raise():
        instance.timeout = 600
    assert instance.timeout == 600


def test_rest_send_00140():
    """
    # Summary

    Verify send_interval property getter/setter

    ## Test

    - send_interval can be set and retrieved
    - send_interval defaults to 5
    - TypeError raised if not int

    ## Classes and Methods

    - RestSend.send_interval
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test default value
    assert instance.send_interval == 5

    # Test TypeError for boolean
    match = r"RestSend\.send_interval:.*must be an integer"
    with pytest.raises(TypeError, match=match):
        instance.send_interval = False  # type: ignore[assignment]

    # Test setter/getter with int
    with does_not_raise():
        instance.send_interval = 10
    assert instance.send_interval == 10


def test_rest_send_00150():
    """
    # Summary

    Verify unit_test property getter/setter

    ## Test

    - unit_test can be set and retrieved
    - unit_test defaults to False
    - TypeError raised if not bool

    ## Classes and Methods

    - RestSend.unit_test
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test default value
    assert instance.unit_test is False

    # Test TypeError for non-bool
    match = r"RestSend\.unit_test:.*must be a boolean"
    with pytest.raises(TypeError, match=match):
        instance.unit_test = "true"  # type: ignore[assignment]

    # Test setter/getter with bool
    with does_not_raise():
        instance.unit_test = True
    assert instance.unit_test is True


def test_rest_send_00160():
    """
    # Summary

    Verify sender property getter/setter

    ## Test

    - sender must be set before accessing
    - sender must implement SenderProtocol
    - ValueError raised if accessed before being set
    - TypeError raised if not SenderProtocol

    ## Classes and Methods

    - RestSend.sender
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test ValueError when accessing before setting
    match = r"RestSend\.sender:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.sender  # pylint: disable=pointless-statement

    # Test TypeError for invalid type
    match = r"RestSend\.sender:.*must implement SenderProtocol"
    with pytest.raises(TypeError, match=match):
        instance.sender = "invalid"  # type: ignore[assignment]

    # Test setter/getter with valid Sender
    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET
    with does_not_raise():
        instance.sender = sender
        result = instance.sender
    assert result is sender


def test_rest_send_00170():
    """
    # Summary

    Verify response_handler property getter/setter

    ## Test

    - response_handler must be set before accessing
    - response_handler must implement ResponseHandlerProtocol
    - ValueError raised if accessed before being set
    - TypeError raised if not ResponseHandlerProtocol

    ## Classes and Methods

    - RestSend.response_handler
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Test ValueError when accessing before setting
    match = r"RestSend\.response_handler:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        result = instance.response_handler  # pylint: disable=pointless-statement

    # Test TypeError for invalid type
    match = r"RestSend\.response_handler:.*must implement ResponseHandlerProtocol"
    with pytest.raises(TypeError, match=match):
        instance.response_handler = "invalid"  # type: ignore[assignment]

    # Test setter/getter with valid ResponseHandler
    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET
    instance.sender = sender

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    with does_not_raise():
        instance.response_handler = response_handler
        result = instance.response_handler
    assert result is response_handler


# =============================================================================
# Test: RestSend save_settings() and restore_settings()
# =============================================================================


def test_rest_send_00200():
    """
    # Summary

    Verify save_settings() and restore_settings()

    ## Test

    - save_settings() saves current check_mode and timeout
    - restore_settings() restores saved values

    ## Classes and Methods

    - RestSend.save_settings()
    - RestSend.restore_settings()
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Set initial values
    instance.check_mode = False
    instance.timeout = 300

    # Save settings
    with does_not_raise():
        instance.save_settings()

    # Modify values
    instance.check_mode = True
    instance.timeout = 600

    # Verify modified values
    assert instance.check_mode is True
    assert instance.timeout == 600

    # Restore settings
    with does_not_raise():
        instance.restore_settings()

    # Verify restored values
    assert instance.check_mode is False
    assert instance.timeout == 300


def test_rest_send_00210():
    """
    # Summary

    Verify restore_settings() when save_settings() not called

    ## Test

    - restore_settings() does nothing if save_settings() not called

    ## Classes and Methods

    - RestSend.restore_settings()
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    # Set values without saving
    instance.check_mode = True
    instance.timeout = 600

    # Call restore_settings without prior save
    with does_not_raise():
        instance.restore_settings()

    # Values should remain unchanged
    assert instance.check_mode is True
    assert instance.timeout == 600


# =============================================================================
# Test: RestSend commit() in check mode
# =============================================================================


def test_rest_send_00300():
    """
    # Summary

    Verify commit() in check_mode for GET request bypasses simulation.

    ## Test

    - GET requests in check_mode go through normal mode (real controller call)
    - response_current contains actual controller data, not simulated data
    - result_current shows success

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    params = {"check_mode": True}

    def responses():
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.path = "/api/v1/test/checkmode"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    # Verify real response (not simulated check_mode response)
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["METHOD"] == "GET"
    assert instance.response_current["DATA"]["status"] == "success"
    assert instance.response_current.get("CHECK_MODE") is None
    assert instance.result_current["success"] is True
    assert instance.result_current["found"] is True


def test_rest_send_00310():
    """
    # Summary

    Verify commit() in check_mode for POST request

    ## Test

    - POST requests in check_mode return simulated success response
    - changed flag is True for write operations

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_check_mode()
    """
    params = {"check_mode": True}

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}
        response_handler.verb = HttpVerbEnum.POST
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.path = "/api/v1/test/create"
        instance.verb = HttpVerbEnum.POST
        instance.payload = {"name": "test"}
        instance.commit()

    # Verify check mode response for write operation
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["METHOD"] == HttpVerbEnum.POST
    assert instance.response_current["CHECK_MODE"] is True
    assert instance.result_current["success"] is True
    assert instance.result_current["changed"] is True


# =============================================================================
# Test: RestSend commit() in normal mode with successful responses
# =============================================================================


def test_rest_send_00400():
    """
    # Summary

    Verify commit() with successful GET request

    ## Test

    - GET request returns successful response
    - response_current and result_current are populated
    - response and result lists contain the responses

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide an extra response entry for potential retry scenarios
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.path = "/api/v1/test/endpoint"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    # Verify response
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["METHOD"] == "GET"
    assert instance.response_current["DATA"]["status"] == "success"

    # Verify result (GET requests return "found", not "changed")
    assert instance.result_current["success"] is True
    assert instance.result_current["found"] is True

    # Verify response and result lists
    assert len(instance.responses) == 1
    assert len(instance.results) == 1


def test_rest_send_00410():
    """
    # Summary

    Verify commit() with successful POST request

    ## Test

    - POST request with payload returns successful response
    - changed flag is True for write operations

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide an extra response entry for potential retry scenarios
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.path = "/api/v1/test/create"
        instance.verb = HttpVerbEnum.POST
        instance.payload = {"name": "test"}
        instance.commit()

    # Verify response
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["DATA"]["status"] == "created"

    # Verify result
    assert instance.result_current["success"] is True
    assert instance.result_current["changed"] is True


def test_rest_send_00420():
    """
    # Summary

    Verify commit() with successful PUT request

    ## Test

    - PUT request returns successful response

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide an extra response entry for potential retry scenarios
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.path = "/api/v1/test/update/12345"
        instance.verb = HttpVerbEnum.PUT
        instance.payload = {"status": "updated"}
        instance.commit()

    # Verify response
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["DATA"]["status"] == "updated"

    # Verify result
    assert instance.result_current["success"] is True
    assert instance.result_current["changed"] is True


def test_rest_send_00430():
    """
    # Summary

    Verify commit() with successful DELETE request

    ## Test

    - DELETE request returns successful response

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide an extra response entry for potential retry scenarios
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.path = "/api/v1/test/delete/12345"
        instance.verb = HttpVerbEnum.DELETE
        instance.commit()

    # Verify response
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["DATA"]["status"] == "deleted"

    # Verify result
    assert instance.result_current["success"] is True
    assert instance.result_current["changed"] is True


# =============================================================================
# Test: RestSend commit() with failed responses
# =============================================================================


def test_rest_send_00500():
    """
    # Summary

    Verify commit() with 404 Not Found response

    ## Test

    - Failed GET request returns 404 response
    - result shows success=False

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide an extra response entry for potential retry scenarios
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.timeout = 1
        instance.path = "/api/v1/test/notfound"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    # Verify error response (GET with 404 returns "found": False)
    assert instance.response_current["RETURN_CODE"] == 404
    assert instance.result_current["success"] is True
    assert instance.result_current["found"] is False


def test_rest_send_00510():
    """
    # Summary

    Verify commit() with 400 Bad Request response

    ## Test

    - Failed POST request returns 400 response
    - Loop retries until timeout is exhausted

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide responses for multiple retry attempts (60 retries * 5 second interval = 300 seconds)
        for _ in range(60):
            yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.timeout = 10
        instance.send_interval = 5
        instance.path = "/api/v1/test/badrequest"
        instance.verb = HttpVerbEnum.POST
        instance.payload = {"invalid": "data"}
        instance.commit()

    # Verify error response
    assert instance.response_current["RETURN_CODE"] == 400
    assert instance.result_current["success"] is False


def test_rest_send_00520():
    """
    # Summary

    Verify commit() with 500 Internal Server Error response

    ## Test

    - Failed GET request returns 500 response
    - Loop retries until timeout is exhausted

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide responses for multiple retry attempts (60 retries * 5 second interval = 300 seconds)
        for _ in range(60):
            yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.timeout = 10
        instance.send_interval = 5
        instance.path = "/api/v1/test/servererror"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    # Verify error response
    assert instance.response_current["RETURN_CODE"] == 500
    assert instance.result_current["success"] is False


# =============================================================================
# Test: RestSend commit() with retry logic
# =============================================================================


def test_rest_send_00600():
    """
    # Summary

    Verify commit() retries on failure then succeeds

    ## Test

    - First response is 500 error
    - Second response is 200 success
    - Final result is success

    ## Classes and Methods

    - RestSend.commit()
    - RestSend._commit_normal_mode()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        # Retry test sequence: error then success
        yield responses_rest_send(f"{method_name}a")
        yield responses_rest_send(f"{method_name}a")
        yield responses_rest_send(f"{method_name}b")

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    with does_not_raise():
        instance = RestSend(params)
        instance.sender = sender
        response_handler = ResponseHandler()
        response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
        response_handler.verb = HttpVerbEnum.GET
        response_handler.commit()
        instance.response_handler = response_handler
        instance.unit_test = True
        instance.timeout = 10
        instance.send_interval = 1
        instance.path = "/api/v1/test/retry"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    # Verify final successful response
    assert instance.response_current["RETURN_CODE"] == 200
    assert instance.response_current["DATA"]["status"] == "success"
    assert instance.result_current["success"] is True


# =============================================================================
# Test: RestSend multiple sequential commits
# =============================================================================


def test_rest_send_00700():
    """
    # Summary

    Verify multiple sequential commit() calls

    ## Test

    - Multiple commits append to response and result lists
    - Each commit populates response_current and result_current

    ## Classes and Methods

    - RestSend.commit()
    """
    method_name = inspect.stack()[0][3]

    def responses():
        # 3 sequential commits
        yield responses_rest_send(f"{method_name}a")
        yield responses_rest_send(f"{method_name}b")
        yield responses_rest_send(f"{method_name}c")

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    instance = RestSend(params)
    instance.sender = sender
    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    instance.response_handler = response_handler
    instance.unit_test = True

    # First commit - GET
    with does_not_raise():
        instance.path = "/api/v1/test/multi/1"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    assert instance.response_current["DATA"]["id"] == 1
    assert len(instance.responses) == 1
    assert len(instance.results) == 1

    # Second commit - GET
    with does_not_raise():
        instance.path = "/api/v1/test/multi/2"
        instance.verb = HttpVerbEnum.GET
        instance.commit()

    assert instance.response_current["DATA"]["id"] == 2
    assert len(instance.responses) == 2
    assert len(instance.results) == 2

    # Third commit - POST
    with does_not_raise():
        instance.path = "/api/v1/test/multi/create"
        instance.verb = HttpVerbEnum.POST
        instance.payload = {"name": "third"}
        instance.commit()

    assert instance.response_current["DATA"]["id"] == 3
    assert instance.response_current["DATA"]["status"] == "created"
    assert len(instance.responses) == 3
    assert len(instance.results) == 3


# =============================================================================
# Test: RestSend error conditions
# =============================================================================


def test_rest_send_00800():
    """
    # Summary

    Verify commit() raises ValueError when path not set

    ## Test

    - commit() raises ValueError if path not set

    ## Classes and Methods

    - RestSend.commit()
    """
    params = {"check_mode": False}

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    instance = RestSend(params)
    instance.sender = sender
    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    instance.response_handler = response_handler
    instance.verb = HttpVerbEnum.GET

    # Don't set path - should raise ValueError
    match = r"RestSend\.path:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_rest_send_00810():
    """
    # Summary

    Verify commit() raises ValueError when verb not set

    ## Test

    - commit() raises ValueError if verb not set

    ## Classes and Methods

    - RestSend.commit()
    """
    params = {"check_mode": False}

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    instance = RestSend(params)
    instance.sender = sender
    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    instance.response_handler = response_handler
    instance.path = "/api/v1/test"

    # Reset verb to None to test ValueError
    instance._verb = None  # type: ignore[assignment]

    match = r"RestSend\.verb:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_rest_send_00820():
    """
    # Summary

    Verify commit() raises ValueError when sender not set

    ## Test

    - commit() raises ValueError if sender not set

    ## Classes and Methods

    - RestSend.commit()
    """
    params = {"check_mode": False}

    instance = RestSend(params)
    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    instance.response_handler = response_handler
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    # Don't set sender - should raise ValueError
    match = r"RestSend\.sender:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_rest_send_00830():
    """
    # Summary

    Verify commit() raises ValueError when response_handler not set

    ## Test

    - commit() raises ValueError if response_handler not set

    ## Classes and Methods

    - RestSend.commit()
    """
    params = {"check_mode": False}

    def responses():
        # Stub responses (not consumed in this test)
        yield {}
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    instance = RestSend(params)
    instance.sender = sender
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    # Don't set response_handler - should raise ValueError
    match = r"RestSend\.response_handler:.*must be set before accessing"
    with pytest.raises(ValueError, match=match):
        instance.commit()


# =============================================================================
# Test: RestSend response and result properties
# =============================================================================


def test_rest_send_00900():
    """
    # Summary

    Verify response and result properties return copies

    ## Test

    - response returns deepcopy of response list
    - result returns deepcopy of result list
    - Modifying returned values doesn't affect internal state

    ## Classes and Methods

    - RestSend.response
    - RestSend.result
    - RestSend.response_current
    - RestSend.result_current
    """
    method_name = inspect.stack()[0][3]
    key = f"{method_name}a"

    def responses():
        # Provide an extra response entry for potential retry scenarios
        yield responses_rest_send(key)
        yield responses_rest_send(key)

    gen_responses = ResponseGenerator(responses())

    params = {"check_mode": False}
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    instance = RestSend(params)
    instance.sender = sender
    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    instance.response_handler = response_handler
    instance.unit_test = True
    instance.path = "/api/v1/test/endpoint"
    instance.verb = HttpVerbEnum.GET
    instance.commit()

    # Get response and result
    response_copy = instance.responses
    result_copy = instance.results
    response_current_copy = instance.response_current
    result_current_copy = instance.result_current

    # Modify copies
    response_copy[0]["MODIFIED"] = True
    result_copy[0]["MODIFIED"] = True
    response_current_copy["MODIFIED"] = True
    result_current_copy["MODIFIED"] = True

    # Verify original values unchanged
    assert "MODIFIED" not in instance._response[0]
    assert "MODIFIED" not in instance._result[0]
    assert "MODIFIED" not in instance._response_current
    assert "MODIFIED" not in instance._result_current


def test_rest_send_00910():
    """
    # Summary

    Verify failed_result property

    ## Test

    - failed_result returns a failure dict with changed=False

    ## Classes and Methods

    - RestSend.failed_result
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    with does_not_raise():
        result = instance.failed_result

    assert result["failed"] is True
    assert result["changed"] is False


# =============================================================================
# Test: RestSend with sender exception simulation
# =============================================================================


def test_rest_send_01000():
    """
    # Summary

    Verify commit() handles sender exceptions

    ## Test

    - Sender.commit() can raise exceptions
    - RestSend.commit() propagates the exception

    ## Classes and Methods

    - RestSend.commit()
    - Sender.commit()
    - Sender.raise_exception
    - Sender.raise_method
    """
    params = {"check_mode": False}

    def responses():
        yield {}

    gen_responses = ResponseGenerator(responses())
    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = gen_responses
    sender.path = "/api/v1/test"
    sender.verb = HttpVerbEnum.GET

    # Configure sender to raise exception
    sender.raise_method = "commit"
    sender.raise_exception = ValueError("Simulated sender error")

    instance = RestSend(params)
    instance.sender = sender
    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()
    instance.response_handler = response_handler
    instance.path = "/api/v1/test"
    instance.verb = HttpVerbEnum.GET

    # commit() should raise ValueError
    match = r"Simulated sender error"
    with pytest.raises(ValueError, match=match):
        instance.commit()


# =============================================================================
# Test: RestSend.add_response()
# =============================================================================


def test_rest_send_add_response_success():
    """
    # Summary

    Verify add_response() appends a valid dict to the response list.

    ## Test

    - add_response() with a valid dict appends to the response list

    ## Classes and Methods

    - RestSend.add_response
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    with does_not_raise():
        instance.add_response({"RETURN_CODE": 200})
        instance.add_response({"RETURN_CODE": 404})

    assert len(instance.responses) == 2
    assert instance.responses[0] == {"RETURN_CODE": 200}
    assert instance.responses[1] == {"RETURN_CODE": 404}


def test_rest_send_add_response_type_error():
    """
    # Summary

    Verify add_response() raises TypeError for non-dict value.

    ## Test

    - add_response() raises TypeError if value is not a dict

    ## Classes and Methods

    - RestSend.add_response
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    match = r"RestSend\.add_response:.*value must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.add_response("invalid")  # type: ignore[arg-type]


# =============================================================================
# Test: RestSend.add_result()
# =============================================================================


def test_rest_send_add_result_success():
    """
    # Summary

    Verify add_result() appends a valid dict to the result list.

    ## Test

    - add_result() with a valid dict appends to the result list

    ## Classes and Methods

    - RestSend.add_result
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    with does_not_raise():
        instance.add_result({"changed": True})
        instance.add_result({"changed": False})

    assert len(instance.results) == 2
    assert instance.results[0] == {"changed": True}
    assert instance.results[1] == {"changed": False}


def test_rest_send_add_result_type_error():
    """
    # Summary

    Verify add_result() raises TypeError for non-dict value.

    ## Test

    - add_result() raises TypeError if value is not a dict

    ## Classes and Methods

    - RestSend.add_result
    """
    params = {"check_mode": False}
    instance = RestSend(params)

    match = r"RestSend\.add_result:.*value must be a dict"
    with pytest.raises(TypeError, match=match):
        instance.add_result("invalid")  # type: ignore[arg-type]
