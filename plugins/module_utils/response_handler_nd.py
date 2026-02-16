# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# response_handler_nd.py

Implements the ResponseHandler interface for handling Nexus Dashboard controller responses.

This handler processes responses from the ND HttpApi plugin which provides:
-   RETURN_CODE: HTTP status code (e.g., 200, 404, 500)
-   MESSAGE: HTTP reason phrase (e.g., "OK", "Not Found", "Internal Server Error")
-   DATA: Parsed JSON body (or dict with raw_response if parsing failed)
-   REQUEST_PATH: The request URL
-   METHOD: The HTTP method used

TODO: Should response be converted to a Pydantic model by this class?
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import copy
import logging
from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class ResponseHandler:
    """
    # Summary

    Implement the response handler interface for injection into RestSend().

    ## Raises

    -   `TypeError` if:
            -   `response` is not a dict.
    -   `ValueError` if:
            -   `response` is missing any fields required by the handler
                to calculate the result.
                -   Required fields:
                        -   `RETURN_CODE`
                        -   `MESSAGE`
            -   `response` is not set prior to calling `commit()`.
            -   `verb` is not set prior to calling `commit()`.

    ## Interface specification

    -   `response` setter property
            -   Accepts a dict containing the controller response.
            -   Raises `TypeError` if:
                    -   `response` is not a dict.
            -   Raises `ValueError` if:
                    -   `response` is missing any fields required by the handler
                        to calculate the result, for example `RETURN_CODE` and
                        `MESSAGE`.
    -   `result` getter property
            -   Returns a dict containing the calculated result based on the
                controller response and the request verb.
            -   Raises `ValueError` if `result` is accessed before calling
                `commit()`.
    -   `result` setter property
            -   Set internally by the handler based on the response and verb.
    -   `verb` setter property
            -   Accepts an HttpVerbEnum enum defining the request verb.
            -   Valid verb: One of "DELETE", "GET", "POST", "PUT".
            -   e.g. HttpVerbEnum.GET, HttpVerbEnum.POST, etc.
            -   Raises `ValueError` if verb is not set prior to calling `commit()`.
    -   `commit()` method
            -   Parse `response` and set `result`.
            -   Raise `ValueError` if:
                    -   `response` is not set.
                    -   `verb` is not set.

    ## Usage example

    ```python
    # import and instantiate the class
    from ansible_collections.cisco.nd.plugins.module_utils.response_handler_nd import \
        ResponseHandler
    response_handler = ResponseHandler()

    try:
        # Set the response from the controller
        response_handler.response = controller_response

        # Set the request verb
        response_handler.verb = HttpVerbEnum.GET

        # Call commit to parse the response
        response_handler.commit()

        # Access the result
        result = response_handler.result
    except (TypeError, ValueError) as error:
        handle_error(error)
    ```

    """

    # HTTP status codes considered successful
    # 200: OK, 201: Created, 202: Accepted, 204: No Content
    RETURN_CODES_SUCCESS: set[int] = {200, 201, 202, 204}
    # 404 is handled separately as "not found but not an error"
    RETURN_CODE_NOT_FOUND: int = 404

    def __init__(self) -> None:
        self.class_name = self.__class__.__name__
        method_name = "__init__"

        self.log = logging.getLogger(f"dcnm.{self.class_name}")

        self._response: Optional[dict[str, Any]] = None
        self._result: Optional[dict[str, Any]] = None
        self._verb: Optional[HttpVerbEnum] = None

        msg = f"ENTERED {self.class_name}.{method_name}"
        self.log.debug(msg)

    def _handle_response(self) -> None:
        """
        # Summary

        Call the appropriate handler for response based on the value of self.verb
        """
        if self.verb == HttpVerbEnum.GET:
            self._handle_get_response()
        else:
            self._handle_post_put_delete_response()

    def _handle_get_response(self) -> None:
        """
        # Summary

        Handle GET responses from the controller and set self.result.

        -	self.result is a dict containing:
            -   found:
                    -   False if RETURN_CODE == 404
                    -   True otherwise (when successful)
            -   success:
                    -   True if RETURN_CODE in (200, 201, 202, 204, 404)
                    -   False otherwise (error status codes)
        """
        result = {}
        return_code = self.response.get("RETURN_CODE")

        # 404 Not Found - resource doesn't exist, but request was successful
        if return_code == self.RETURN_CODE_NOT_FOUND:
            result["found"] = False
            result["success"] = True
        # Success codes - resource found
        elif return_code in self.RETURN_CODES_SUCCESS:
            result["found"] = True
            result["success"] = True
        # Error codes - request failed
        else:
            result["found"] = False
            result["success"] = False

        self.result = copy.copy(result)

    def _handle_post_put_delete_response(self) -> None:
        """
        # Summary

        Handle POST, PUT, DELETE responses from the controller and set
        self.result.

        -	self.result is a dict containing:
            -   changed:
                -   True if RETURN_CODE in (200, 201, 202, 204) and no ERROR
                -   False otherwise
            -   success:
                -   True if RETURN_CODE in (200, 201, 202, 204) and no ERROR
                -   False otherwise
        """
        result = {}
        return_code = self.response.get("RETURN_CODE")

        # Check for explicit error in response
        if self.response.get("ERROR") is not None:
            result["success"] = False
            result["changed"] = False
        # Check for error in response data (ND error format)
        elif self.response.get("DATA", {}).get("error") is not None:
            result["success"] = False
            result["changed"] = False
        # Success codes indicate the operation completed
        elif return_code in self.RETURN_CODES_SUCCESS:
            result["success"] = True
            result["changed"] = True
        # Any other status code is an error
        else:
            result["success"] = False
            result["changed"] = False

        self.result = copy.copy(result)

    def commit(self) -> None:
        """
        # Summary

        Parse the response from the controller and set self.result
        based on the response.

        ## Raises

        -   ``ValueError`` if:
                -   ``response`` is not set.
                -   ``verb`` is not set.
        """
        method_name = "commit"
        msg = f"{self.class_name}.{method_name}: "
        msg += f"response {self.response}, verb {self.verb}"
        self.log.debug(msg)
        self._handle_response()

    @property
    def response(self) -> dict[str, Any]:
        """
        # Summary

        The controller response.

        ## Raises

        -   getter: ``ValueError`` if response is not set.
        -   setter: ``TypeError`` if ``response`` is not a dict.
        -   setter: ``ValueError`` if ``response`` is missing required fields
            (``RETURN_CODE``, ``MESSAGE``).
        """
        if self._response is None:
            msg = f"{self.class_name}.response: "
            msg += "response must be set before accessing."
            raise ValueError(msg)
        return self._response

    @response.setter
    def response(self, value: dict[str, Any]) -> None:
        method_name = "response"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{self.class_name}.{method_name} must be a dict. "
            msg += f"Got {value}."
            raise TypeError(msg)
        if value.get("MESSAGE", None) is None:
            msg = f"{self.class_name}.{method_name}: "
            msg += "response must have a MESSAGE key. "
            msg += f"Got: {value}."
            raise ValueError(msg)
        if value.get("RETURN_CODE", None) is None:
            msg = f"{self.class_name}.{method_name}: "
            msg += "response must have a RETURN_CODE key. "
            msg += f"Got: {value}."
            raise ValueError(msg)
        self._response = value

    @property
    def result(self) -> dict[str, Any]:
        """
        # Summary

        The result calculated by the handler based on the controller response.

        ## Raises

        -   getter: ``ValueError`` if result is not set (commit() not called).
        -   setter: ``TypeError`` if result is not a dict.
        """
        if self._result is None:
            msg = f"{self.class_name}.result: "
            msg += "result must be set before accessing. Call commit() first."
            raise ValueError(msg)
        return self._result

    @result.setter
    def result(self, value: dict[str, Any]) -> None:
        method_name = "result"
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{self.class_name}.{method_name} must be a dict. "
            msg += f"Got {value}."
            raise TypeError(msg)
        self._result = value

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        HTTP method for the REST request e.g. HttpVerbEnum.GET, HttpVerbEnum.POST, etc.

        ## Raises

        -   ``ValueError`` if value is not set.
        """
        if self._verb is None:
            raise ValueError(f"{self.class_name}.verb is not set.")
        return self._verb

    @verb.setter
    def verb(self, value: HttpVerbEnum) -> None:
        self._verb = value

    @property
    def error_message(self) -> Optional[str]:
        """
        # Summary

        Extract a human-readable error message from the response DATA based on
        ND error formats.

        Returns None if result indicates success or if commit() has not been called.

        ## ND Error Formats Handled

        1. raw_response: Non-JSON response stored in DATA.raw_response
        2. code/message: DATA.code and DATA.message
        3. messages array: DATA.messages[0].{code, severity, message}
        4. errors array: DATA.errors[0]
        5. No DATA: Connection failure with REQUEST_PATH and MESSAGE
        6. Non-dict DATA: Stringified DATA value
        7. Unknown: Fallback with RETURN_CODE

        ## Returns

        -   str: Human-readable error message if an error occurred.
        -   None: If the request was successful or commit() not called.
        """
        msg: Optional[str] = None

        # Return None if result not set (commit not called) or success
        if self._result is not None and not self._result.get("success", True):
            response_data = self._response.get("DATA") if self._response else None
            return_code = self._response.get("RETURN_CODE", -1) if self._response else -1

            # No response data - connection failure
            if response_data is None:
                request_path = self._response.get("REQUEST_PATH", "unknown") if self._response else "unknown"
                message = self._response.get("MESSAGE", "Unknown error") if self._response else "Unknown error"
                msg = f"Connection failed for {request_path}. {message}"
            # Dict response data - check various ND error formats
            elif isinstance(response_data, dict):
                # Type-narrow response_data to dict[str, Any] for pylint
                # pylint: disable=unsupported-membership-test,unsubscriptable-object
                # Added pylint directive above since pylint is still flagging these errors.
                data_dict: dict[str, Any] = response_data
                # Raw response (non-JSON)
                if "raw_response" in data_dict:
                    msg = "ND Error: Response could not be parsed as JSON"
                # code/message format
                elif "code" in data_dict and "message" in data_dict:
                    msg = f"ND Error {data_dict['code']}: {data_dict['message']}"

                # messages array format
                if msg is None and "messages" in data_dict and len(data_dict.get("messages", [])) > 0:
                    first_msg = data_dict["messages"][0]
                    if all(k in first_msg for k in ("code", "severity", "message")):
                        msg = f"ND Error {first_msg['code']} ({first_msg['severity']}): {first_msg['message']}"

                # errors array format
                if msg is None and "errors" in data_dict and len(data_dict.get("errors", [])) > 0:
                    msg = f"ND Error: {data_dict['errors'][0]}"

                # Unknown dict format - fallback
                if msg is None:
                    msg = f"ND Error: Request failed with status {return_code}"
            # Non-dict response data
            else:
                msg = f"ND Error: {response_data}"

        return msg
