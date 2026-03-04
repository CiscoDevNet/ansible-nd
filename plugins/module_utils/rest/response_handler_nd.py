# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# response_handler_nd.py

Implements the ResponseHandler interface for handling Nexus Dashboard controller responses.

## Version Compatibility

This handler is designed for ND API v1 responses (ND 4.2+).

### Status Code Assumptions

Status codes are defined by the injected `ResponseValidationStrategy`, defaulting
to `NdV1Strategy` (ND 4.2+):

- Success: 200, 201, 202, 204, 207
- Not Found: 404 (treated as success for GET)
- Error: 405, 409

If ND API v2 uses different codes, inject a new strategy via the
`validation_strategy` property rather than modifying this class.

### Response Format

Expects ND HttpApi plugin to provide responses with these keys:

- RETURN_CODE (int): HTTP status code (e.g., 200, 404, 500)
- MESSAGE (str): HTTP reason phrase (e.g., "OK", "Not Found")
- DATA (dict): Parsed JSON body or dict with raw_response if parsing failed
- REQUEST_PATH (str): The request URL path
- METHOD (str): The HTTP method used (GET, POST, PUT, DELETE, PATCH)

### Supported Error Formats

The error_message property handles multiple ND API v1 error response formats:

1. code/message dict: {"code": <int>, "message": <str>}
2. messages array: {"messages": [{"code": <int>, "severity": <str>, "message": <str>}]}
3. errors array: {"errors": [<str>, ...]}
4. raw_response: {"raw_response": <str>} for non-JSON responses

If ND API v2 changes error response structures, error extraction logic will need updates.

## Future v2 Considerations

If ND API v2 changes response format or status codes, implement a new strategy
class (e.g. `NdV2Strategy`) conforming to `ResponseValidationStrategy` and inject
it via `response_handler.validation_strategy = NdV2Strategy()`.

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
from ansible_collections.cisco.nd.plugins.module_utils.rest.protocols.response_validation import ResponseValidationStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_strategies.nd_v1_strategy import NdV1Strategy


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
    from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import \
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

    def __init__(self) -> None:
        self.class_name = self.__class__.__name__
        method_name = "__init__"

        self.log = logging.getLogger(f"nd.{self.class_name}")

        self._response: Optional[dict[str, Any]] = None
        self._result: Optional[dict[str, Any]] = None
        self._strategy: ResponseValidationStrategy = NdV1Strategy()
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
                    -   True if RETURN_CODE in (200, 201, 202, 204, 207, 404)
                    -   False otherwise (error status codes)
        """
        result = {}
        return_code = self.response.get("RETURN_CODE")

        # 404 Not Found - resource doesn't exist, but request was successful
        if self._strategy.is_not_found(return_code):
            result["found"] = False
            result["success"] = True
        # Success codes - resource found
        elif self._strategy.is_success(return_code):
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
                -   True if RETURN_CODE in (200, 201, 202, 204, 207) and no ERROR
                -   False otherwise
            -   success:
                -   True if RETURN_CODE in (200, 201, 202, 204, 207) and no ERROR
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
        elif self._strategy.is_success(return_code):
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

        Extract a human-readable error message from the response DATA.

        Delegates to the injected `ResponseValidationStrategy`. Returns None if
        result indicates success or if `commit()` has not been called.

        ## Returns

        -   str: Human-readable error message if an error occurred.
        -   None: If the request was successful or `commit()` not called.

        ## Raises

        None
        """
        if self._result is not None and not self._result.get("success", True):
            return self._strategy.extract_error_message(self._response)
        return None

    @property
    def validation_strategy(self) -> ResponseValidationStrategy:
        """
        # Summary

        The response validation strategy used to check status codes and extract
        error messages.

        ## Returns

        - `ResponseValidationStrategy`: The current strategy instance.

        ## Raises

        None
        """
        return self._strategy

    @validation_strategy.setter
    def validation_strategy(self, value: ResponseValidationStrategy) -> None:
        """
        # Summary

        Set the response validation strategy.

        ## Raises

        ### TypeError

        - If `value` does not implement `ResponseValidationStrategy`.
        """
        method_name = "validation_strategy"
        if not isinstance(value, ResponseValidationStrategy):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"Expected ResponseValidationStrategy. Got {type(value)}."
            raise TypeError(msg)
        self._strategy = value
