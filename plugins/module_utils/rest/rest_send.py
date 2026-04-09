# pylint: disable=wrong-import-position
# pylint: disable=missing-module-docstring
# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# isort: off
# fmt: off
from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
# fmt: on
# isort: on


import copy
import inspect
import json
import logging
from time import sleep
from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.protocols.response_handler import ResponseHandlerProtocol
from ansible_collections.cisco.nd.plugins.module_utils.rest.protocols.sender import SenderProtocol
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import Results


class RestSend:
    """
    # Summary

    -   Send REST requests to the controller with retries.
    -   Accepts a `Sender()` class that implements SenderProtocol.
            -   The sender interface is defined in
                `module_utils/rest/protocols/sender.py`
    -   Accepts a `ResponseHandler()` class that implements the response
        handler interface.
            -   The response handler interface is defined in
                `module_utils/rest/protocols/response_handler.py`

    ## Raises

    -   `ValueError` if:
            -   ResponseHandler() raises `TypeError` or `ValueError`
            -   Sender().commit() raises `ValueError`
            -   `verb` is not a valid verb (GET, POST, PUT, DELETE)
    -  `TypeError` if:
            -   `check_mode` is not a `bool`
            -   `path` is not a `str`
            -   `payload` is not a `dict`
            -   `add_response()` value is not a `dict`
            -   `response_current` is not a `dict`
            -   `response_handler` is not an instance of
                `ResponseHandler()`
            -   `add_result()` value is not a `dict`
            -   `result_current` is not a `dict`
            -   `send_interval` is not an `int`
            -   `sender` is not an instance of `SenderProtocol`
            -   `timeout` is not an `int`
            -   `unit_test` is not a `bool`

    ## Usage discussion

    -   A Sender() class is used in the usage example below that requires an
        instance of `AnsibleModule`, and uses the connection plugin (plugins/httpapi.nd.py)
        to send requests to the controller.
        -   See ``module_utils/rest/protocols/sender.py`` for details about
            implementing `Sender()` classes.
    -   A `ResponseHandler()` class is used in the usage example below that
        abstracts controller response handling.  It accepts a controller
        response dict and returns a result dict.
        -   See `module_utils/rest/protocols/response_handler.py` for details
            about implementing `ResponseHandler()` classes.

    ## Usage example

    ```python
    params = {"check_mode": False, "state": "merged"}
    sender = Sender() # class that implements SenderProtocol
    sender.ansible_module = ansible_module

    try:
        rest_send = RestSend(params)
        rest_send.sender = sender
        rest_send.response_handler = ResponseHandler()
        rest_send.unit_test = True # optional, use in unit tests for speed
        rest_send.path = "/rest/top-down/fabrics"
        rest_send.verb = HttpVerbEnum.GET
        rest_send.payload = my_payload # optional
        rest_send.save_settings() # save current check_mode and timeout
        rest_send.timeout = 300 # optional
        rest_send.check_mode = True
        # Do things with rest_send...
        rest_send.commit()
        rest_send.restore_settings() # restore check_mode and timeout
    except (TypeError, ValueError) as error:
        # Handle error

    # list of responses from the controller for this session
    responses = rest_send.responses
    # dict containing the current controller response
    response_current = rest_send.response_current
    # list of results from the controller for this session
    results = rest_send.results
    # dict containing the current controller result
    result_current = rest_send.result_current
    ```
    """

    def __init__(self, params) -> None:
        self.class_name = self.__class__.__name__

        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.params = params
        msg = "ENTERED RestSend(): "
        msg += f"params: {self.params}"
        self.log.debug(msg)

        self._check_mode: bool = False
        self._committed_payload: Optional[dict] = None
        self._path: Optional[str] = None
        self._payload: Optional[dict] = None
        self._response: list[dict[str, Any]] = []
        self._response_current: dict[str, Any] = {}
        self._response_handler: Optional[ResponseHandlerProtocol] = None
        self._result: list[dict] = []
        self._result_current: dict = {}
        self._send_interval: int = 5
        self._sender: Optional[SenderProtocol] = None
        self._timeout: int = 300
        self._unit_test: bool = False
        self._verb: HttpVerbEnum = HttpVerbEnum.GET

        # See save_settings() and restore_settings()
        self.saved_timeout: Optional[int] = None
        self.saved_check_mode: Optional[bool] = None

        self.check_mode = self.params.get("check_mode", False)

        msg = "ENTERED RestSend(): "
        msg += f"check_mode: {self.check_mode}"
        self.log.debug(msg)

    def restore_settings(self) -> None:
        """
        # Summary

        Restore `check_mode` and `timeout` to their saved values.

        ## Raises

        None

        ## See also

        -   `save_settings()`

        ## Discussion

        This is useful when a task needs to temporarily set `check_mode`
        to False, (or change the timeout value) and then restore them to
        their original values.

        -   `check_mode` is not restored if `save_settings()` has not
            previously been called.
        -   `timeout` is not restored if `save_settings()` has not
            previously been called.
        """
        if self.saved_check_mode is not None:
            self.check_mode = self.saved_check_mode
        if self.saved_timeout is not None:
            self.timeout = self.saved_timeout

    def save_settings(self) -> None:
        """
        # Summary

        Save the current values of `check_mode` and `timeout` for later
        restoration.

        ## Raises

        None

        ## See also

        -   `restore_settings()`

        ## NOTES

        -   `check_mode` is not saved if it has not yet been initialized.
        -   `timeout` is not saved if it has not yet been initialized.
        """
        if self.check_mode is not None:
            self.saved_check_mode = self.check_mode
        if self.timeout is not None:
            self.saved_timeout = self.timeout

    def commit(self) -> None:
        """
        # Summary

        Send the REST request to the controller

        ## Raises

        -   `ValueError` if:
                -   RestSend()._commit_normal_mode() raises
                    `ValueError`
                -   ResponseHandler() raises `TypeError` or `ValueError`
                -   Sender().commit() raises `ValueError`
                -   `verb` is not a valid verb (GET, POST, PUT, DELETE)
        -  `TypeError` if:
                -   `check_mode` is not a `bool`
                -   `path` is not a `str`
                -   `payload` is not a `dict`
                -   `response` is not a `dict`
                -   `response_current` is not a `dict`
                -   `response_handler` is not an instance of
                    `ResponseHandler()`
                -   `result` is not a `dict`
                -   `result_current` is not a `dict`
                -   `send_interval` is not an `int`
                -   `sender` is not an instance of `Sender()`
                -   `timeout` is not an `int`
                -   `unit_test` is not a `bool`

        """
        method_name = "commit"
        msg = f"{self.class_name}.{method_name}: "
        msg += f"check_mode: {self.check_mode}, "
        msg += f"verb: {self.verb}, "
        msg += f"path: {self.path}."
        self.log.debug(msg)

        try:
            if self.check_mode is True:
                self._commit_check_mode()
            else:
                self._commit_normal_mode()
        except (TypeError, ValueError) as error:
            msg = f"{self.class_name}.{method_name}: "
            msg += "Error during commit. "
            msg += f"Error details: {error}"
            raise ValueError(msg) from error

    def _commit_check_mode(self) -> None:
        """
        # Summary

        Simulate a controller request for check_mode.

        ## Raises

        -   `ValueError` if:
            -   ResponseHandler() raises `TypeError` or `ValueError`
            -   self.response_current raises `TypeError`
            -   self.result_current raises `TypeError`


        ## Properties read:

        -   `verb`: HttpVerbEnum e.g. HttpVerb.DELETE, HttpVerb.GET, etc.
        -   `path`: HTTP path e.g. http://controller_ip/path/to/endpoint
        -   `payload`: Optional HTTP payload

        ## Properties written:

        -   `response_current`: raw simulated response
        -   `result_current`: result from self._handle_response() method
        """
        method_name = "_commit_check_mode"

        msg = f"{self.class_name}.{method_name}: "
        msg += f"verb {self.verb}, path {self.path}."
        self.log.debug(msg)

        # GET is read-only: execute against the real API so check-mode diffs
        # reflect actual controller state rather than a fake empty response.
        if self.verb == HttpVerbEnum.GET:
            self._commit_normal_mode()
            return

        response_current: dict = {}
        response_current["RETURN_CODE"] = 200
        response_current["METHOD"] = self.verb
        response_current["REQUEST_PATH"] = self.path
        response_current["MESSAGE"] = "OK"
        response_current["CHECK_MODE"] = True
        response_current["DATA"] = {"simulated": "check-mode-response", "status": "Success"}

        try:
            self.response_current = response_current
            self.response_handler.response = self.response_current
            self.response_handler.verb = self.verb
            self.response_handler.commit()
            self.result_current = self.response_handler.result
            self._response.append(self.response_current)
            self._result.append(self.result_current)
            self._committed_payload = copy.deepcopy(self._payload)
        except (TypeError, ValueError) as error:
            msg = f"{self.class_name}.{method_name}: "
            msg += "Error building response/result. "
            msg += f"Error detail: {error}"
            raise ValueError(msg) from error

    def _commit_normal_mode(self) -> None:
        """
        # Summary

        Call sender.commit() with retries until successful response or timeout is exceeded.

        ## Raises

        -   `ValueError` if:
            -   HandleResponse() raises `ValueError`
            -   Sender().commit() raises `ValueError`
            -   `verb` is not a valid verb (GET, POST, PUT, DELETE)"""
        method_name = "_commit_normal_mode"
        timeout = copy.copy(self.timeout)

        msg = "Entering commit loop. "
        msg += f"timeout: {timeout}, unit_test: {self.unit_test}."
        self.log.debug(msg)

        self.sender.path = self.path
        self.sender.verb = self.verb
        if self.payload is not None:
            self.sender.payload = self.payload
        success = False
        while timeout > 0 and success is False:
            msg = f"{self.class_name}.{method_name}: "
            msg += "Calling sender.commit(): "
            msg += f"timeout {timeout}, success {success}, verb {self.verb}, path {self.path}."
            self.log.debug(msg)

            try:
                self.sender.commit()
            except ValueError as error:
                raise ValueError(error) from error

            self.response_current = self.sender.response
            # Handle controller response and derive result
            try:
                self.response_handler.response = self.response_current
                self.response_handler.verb = self.verb
                self.response_handler.commit()
                self.result_current = self.response_handler.result
            except (TypeError, ValueError) as error:
                msg = f"{self.class_name}.{method_name}: "
                msg += "Error building response/result. "
                msg += f"Error detail: {error}"
                self.log.debug(msg)
                raise ValueError(msg) from error

            msg = f"{self.class_name}.{method_name}: "
            msg += f"timeout: {timeout}. "
            msg += f"result_current: {json.dumps(self.result_current, indent=4, sort_keys=True)}."
            self.log.debug(msg)

            msg = f"{self.class_name}.{method_name}: "
            msg += f"timeout: {timeout}. "
            msg += "response_current: "
            msg += f"{json.dumps(self.response_current, indent=4, sort_keys=True)}."
            self.log.debug(msg)

            success = self.result_current["success"]
            if success is False:
                if self.unit_test is False:
                    sleep(self.send_interval)
                timeout -= self.send_interval
                msg = f"{self.class_name}.{method_name}: "
                msg += f"Subtracted {self.send_interval} from timeout. "
                msg += f"timeout: {timeout}."
                self.log.debug(msg)

        self._response.append(self.response_current)
        self._result.append(self.result_current)
        self._committed_payload = copy.deepcopy(self._payload)
        self._payload = None

    @property
    def check_mode(self) -> bool:
        """
        # Summary

        Determines if changes should be made on the controller.

        ## Raises

        -   `TypeError` if value is not a `bool`

        ## Default

        `False`

        -   If `False`, write operations, if any, are made on the controller.
        -   If `True`, write operations are not made on the controller.
            Instead, controller responses for write operations are simulated
            to be successful (200 response code) and these simulated responses
            are returned by RestSend().  Read operations are not affected
            and are sent to the controller and real responses are returned.

        ## Discussion

        We want to be able to read data from the controller for read-only
        operations (i.e. to set check_mode to False temporarily, even when
        the user has set check_mode to True).  For example, SwitchDetails
        is a read-only operation, and we want to be able to read this data to
        provide a real controller response to the user.
        """
        return self._check_mode

    @check_mode.setter
    def check_mode(self, value: bool) -> None:
        method_name = "check_mode"
        if not isinstance(value, bool):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a boolean. Got {value}."
            raise TypeError(msg)
        self._check_mode = value

    @property
    def committed_payload(self) -> Optional[dict]:
        """
        # Summary

        Return the payload that was sent in the most recent commit, or None.

        ## Raises

        None

        ## Description

        After `commit()`, `self.payload` is reset to None. This property
        preserves the payload that was actually sent, so consumers can
        read it for registration in Results.
        """
        return self._committed_payload

    @property
    def failed_result(self) -> dict:
        """
        Return a result for a failed task with no changes
        """
        return Results().failed_result

    @property
    def path(self) -> str:
        """
        # Summary

        Endpoint path for the REST request.

        ## Raises

        -   getter: `ValueError` if `path` is not set before accessing.

        ## Example

        `/appcenter/cisco/ndfc/api/v1/...etc...`
        """
        if self._path is None:
            msg = f"{self.class_name}.path: path must be set before accessing."
            raise ValueError(msg)
        return self._path

    @path.setter
    def path(self, value: str) -> None:
        self._path = value

    @property
    def payload(self) -> Optional[dict]:
        """
        # Summary

        Return the payload to send to the controller, or None.

        ## Raises

        -   setter: `TypeError` if value is not a `dict`
        """
        return self._payload

    @payload.setter
    def payload(self, value: dict):
        method_name = "payload"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a dict. Got {value}."
            raise TypeError(msg)
        self._payload = value

    @property
    def response_current(self) -> dict:
        """
        # Summary

        Return the current response from the controller as a `dict`.
        `commit()` must be called first.

        ## Raises

        -   setter: `TypeError` if value is not a `dict`
        """
        return copy.deepcopy(self._response_current)

    @response_current.setter
    def response_current(self, value):
        method_name = "response_current"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a dict. "
            msg += f"Got type {type(value).__name__}, "
            msg += f"Value: {value}."
            raise TypeError(msg)
        self._response_current = value

    @property
    def responses(self) -> list[dict]:
        """
        # Summary

        The aggregated list of responses from the controller.

        `commit()` must be called first.
        """
        return copy.deepcopy(self._response)

    def add_response(self, value: dict) -> None:
        """
        # Summary

        Append a response dict to the response list.

        ## Raises

        -   `TypeError` if value is not a `dict`
        """
        method_name = "add_response"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += "value must be a dict. "
            msg += f"Got type {type(value).__name__}, "
            msg += f"Value: {value}."
            raise TypeError(msg)
        self._response.append(value)

    @property
    def response_handler(self) -> ResponseHandlerProtocol:
        """
        # Summary

        A class that implements ResponseHandlerProtocol.

        ## Raises

        -   getter: `ValueError` if `response_handler` is not set before accessing.
        -   setter: `TypeError` if `value` does not implement `ResponseHandlerProtocol`.

        ## NOTES

        -   See module_utils/rest/protocols/response_handler.py for the protocol definition.
        """
        if self._response_handler is None:
            msg = f"{self.class_name}.response_handler: "
            msg += "response_handler must be set before accessing."
            raise ValueError(msg)
        return self._response_handler

    @staticmethod
    def _has_member_static(obj: Any, member: str) -> bool:
        """
        Check whether an object has a member without triggering descriptors.

        This avoids invoking property getters during dependency validation.
        """
        try:
            inspect.getattr_static(obj, member)
            return True
        except AttributeError:
            return False

    @response_handler.setter
    def response_handler(self, value: ResponseHandlerProtocol):
        required_members = (
            "response",
            "result",
            "verb",
            "commit",
            "error_message",
        )
        missing_members = [member for member in required_members if not self._has_member_static(value, member)]
        if missing_members:
            msg = f"{self.class_name}.response_handler: "
            msg += "value must implement ResponseHandlerProtocol. "
            msg += f"Missing members: {missing_members}. "
            msg += f"Got type {type(value).__name__}."
            raise TypeError(msg)
        if not callable(getattr(value, "commit", None)):
            msg = f"{self.class_name}.response_handler: "
            msg += "value.commit must be callable. "
            msg += f"Got type {type(value).__name__}."
            raise TypeError(msg)
        self._response_handler = value

    @property
    def results(self) -> list[dict]:
        """
        # Summary

        The aggregated list of results from the controller.

        `commit()` must be called first.
        """
        return copy.deepcopy(self._result)

    def add_result(self, value: dict) -> None:
        """
        # Summary

        Append a result dict to the result list.

        ## Raises

        -   `TypeError` if value is not a `dict`
        """
        method_name = "add_result"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += "value must be a dict. "
            msg += f"Got type {type(value).__name__}, "
            msg += f"Value: {value}."
            raise TypeError(msg)
        self._result.append(value)

    @property
    def result_current(self) -> dict:
        """
        # Summary

        The current result from the controller

        `commit()` must be called first.

        This is a dict containing the current result.

        ## Raises

        -   setter: `TypeError` if value is not a `dict`

        """
        return copy.deepcopy(self._result_current)

    @result_current.setter
    def result_current(self, value: dict):
        method_name = "result_current"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a dict. "
            msg += f"Got {value}."
            raise TypeError(msg)
        self._result_current = value

    @property
    def send_interval(self) -> int:
        """
        # Summary

        Send interval, in seconds, for retrying responses from the controller.

        ## Raises

        -   setter: ``TypeError`` if value is not an `int`

        ## Default

        `5`
        """
        return self._send_interval

    @send_interval.setter
    def send_interval(self, value: int) -> None:
        method_name = "send_interval"
        msg = f"{self.class_name}.{method_name}: "
        msg += f"{method_name} must be an integer. "
        msg += f"Got type {type(value).__name__}, "
        msg += f"value {value}."
        # Check explicit boolean first since isinstance(True, int) is True
        if isinstance(value, bool):
            raise TypeError(msg)
        if not isinstance(value, int):
            raise TypeError(msg)
        self._send_interval = value

    @property
    def sender(self) -> SenderProtocol:
        """
        # Summary

        A class implementing the SenderProtocol.

        See module_utils/rest/protocols/sender.py for SenderProtocol definition.

        ## Raises

        -   getter: ``ValueError`` if sender is not set before accessing.
        -   setter: ``TypeError`` if value does not implement SenderProtocol.
        """
        if self._sender is None:
            msg = f"{self.class_name}.sender: "
            msg += "sender must be set before accessing."
            raise ValueError(msg)
        return self._sender

    @sender.setter
    def sender(self, value: SenderProtocol):
        required_members = (
            "path",
            "verb",
            "payload",
            "response",
            "commit",
        )
        missing_members = [member for member in required_members if not self._has_member_static(value, member)]
        if missing_members:
            msg = f"{self.class_name}.sender: "
            msg += "value must implement SenderProtocol. "
            msg += f"Missing members: {missing_members}. "
            msg += f"Got type {type(value).__name__}."
            raise TypeError(msg)
        if not callable(getattr(value, "commit", None)):
            msg = f"{self.class_name}.sender: "
            msg += "value.commit must be callable. "
            msg += f"Got type {type(value).__name__}."
            raise TypeError(msg)
        self._sender = value

    @property
    def timeout(self) -> int:
        """
        # Summary

        Timeout, in seconds, for retrieving responses from the controller.

        ## Raises

        -   setter: ``TypeError`` if value is not an ``int``

        ## Default

        `300`
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        method_name = "timeout"
        msg = f"{self.class_name}.{method_name}: "
        msg += f"{method_name} must be an integer. "
        msg += f"Got type {type(value).__name__}, "
        msg += f"value {value}."
        if isinstance(value, bool):
            raise TypeError(msg)
        if not isinstance(value, int):
            raise TypeError(msg)
        self._timeout = value

    @property
    def unit_test(self) -> bool:
        """
        # Summary

        Is RestSend being called from a unit test.
        Set this to True in unit tests to speed the test up.

        ## Raises

        -   setter: `TypeError` if value is not a `bool`

        ## Default

        `False`
        """
        return self._unit_test

    @unit_test.setter
    def unit_test(self, value: bool) -> None:
        method_name = "unit_test"
        if not isinstance(value, bool):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a boolean. "
            msg += f"Got type {type(value).__name__}, "
            msg += f"value {value}."
            raise TypeError(msg)
        self._unit_test = value

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        HTTP method for the REST request e.g. HttpVerbEnum.GET, HttpVerbEnum.POST, etc.

        ## Raises

        -   setter: `TypeError` if value is not an instance of HttpVerbEnum
        -   getter: `ValueError` if verb is not set before accessing.
        """
        if self._verb is None:
            msg = f"{self.class_name}.verb: "
            msg += "verb must be set before accessing."
            raise ValueError(msg)
        return self._verb

    @verb.setter
    def verb(self, value: HttpVerbEnum):
        if not isinstance(value, HttpVerbEnum):
            msg = f"{self.class_name}.verb: "
            msg += "verb must be an instance of HttpVerbEnum. "
            msg += f"Got type {type(value).__name__}."
            raise TypeError(msg)
        self._verb = value
