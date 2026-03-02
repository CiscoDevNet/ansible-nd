# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

ND API v1 response validation strategy.

## Description

Implements status code validation and error message extraction for ND API v1
responses (ND 3.0+, NDFC 12+).

This strategy encapsulates the response handling logic previously hardcoded
in ResponseHandler, enabling version-specific behavior to be injected.
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Any, Optional


class NdV1Strategy:
    """
    # Summary

    Response validation strategy for ND API v1.

    ## Description

    Implements status code validation and error message extraction
    for ND API v1 (ND 3.0+, NDFC 12+).

    ## Status Codes

    - Success: 200, 201, 202, 204, 207
    - Not Found: 404 (treated as success for GET)
    - Error: 405, 409

    ## Error Formats Supported

    1. raw_response: Non-JSON response stored in DATA.raw_response
    2. code/message: DATA.code and DATA.message
    3. messages array: DATA.messages[0].{code, severity, message}
    4. errors array: DATA.errors[0]
    5. Connection failure: No DATA with REQUEST_PATH and MESSAGE
    6. Non-dict DATA: Stringified DATA value
    7. Unknown: Fallback with RETURN_CODE

    ## Raises

    None
    """

    @property
    def success_codes(self) -> set[int]:
        """
        # Summary

        Return v1 success codes.

        ## Returns

        - Set of integers: {200, 201, 202, 204, 207}

        ## Raises

        None
        """
        return {200, 201, 202, 204, 207}

    @property
    def not_found_code(self) -> int:
        """
        # Summary

        Return v1 not found code.

        ## Returns

        - Integer: 404

        ## Raises

        None
        """
        return 404

    @property
    def error_codes(self) -> set[int]:
        """
        # Summary

        Return v1 error codes.

        ## Returns

        - Set of integers: {405, 409}

        ## Raises

        None
        """
        return {405, 409}

    def is_success(self, return_code: int) -> bool:
        """
        # Summary

        Check if return code indicates success (v1).

        ## Parameters

        - return_code: HTTP status code to check

        ## Returns

        - True if code is in success_codes, False otherwise

        ## Raises

        None
        """
        return return_code in self.success_codes

    def is_not_found(self, return_code: int) -> bool:
        """
        # Summary

        Check if return code indicates not found (v1).

        ## Parameters

        - return_code: HTTP status code to check

        ## Returns

        - True if code matches not_found_code, False otherwise

        ## Raises

        None
        """
        return return_code == self.not_found_code

    def is_error(self, return_code: int) -> bool:
        """
        # Summary

        Check if return code indicates error (v1).

        ## Parameters

        - return_code: HTTP status code to check

        ## Returns

        - True if code is in error_codes, False otherwise

        ## Raises

        None
        """
        return return_code in self.error_codes

    def extract_error_message(self, response: dict) -> Optional[str]:
        """
        # Summary

        Extract error message from v1 response DATA.

        ## Description

        Handles multiple ND API v1 error formats in priority order:

        1. Connection failure (no DATA)
        2. Non-JSON response (raw_response in DATA)
        3. code/message dict
        4. messages array with code/severity/message
        5. errors array
        6. Unknown dict format
        7. Non-dict DATA

        ## Parameters

        - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, REQUEST_PATH

        ## Returns

        - Error message string if found, None otherwise

        ## Raises

        None - returns None gracefully if error message cannot be extracted
        """
        msg: Optional[str] = None

        response_data = response.get("DATA") if response else None
        return_code = response.get("RETURN_CODE", -1) if response else -1

        # No response data - connection failure
        if response_data is None:
            request_path = response.get("REQUEST_PATH", "unknown") if response else "unknown"
            message = response.get("MESSAGE", "Unknown error") if response else "Unknown error"
            msg = f"Connection failed for {request_path}. {message}"
        # Dict response data - check various ND error formats
        elif isinstance(response_data, dict):
            # Type-narrow response_data to dict[str, Any] for pylint
            # pylint: disable=unsupported-membership-test,unsubscriptable-object
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
