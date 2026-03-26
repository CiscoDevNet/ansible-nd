# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

ND API v1 response validation strategy.

## Description

Implements status code validation and error message extraction for ND API v1
responses (ND 4.2).

This strategy encapsulates the response handling logic previously hardcoded
in ResponseHandler, enabling version-specific behavior to be injected.
"""

# isort: off
# fmt: off
from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
# fmt: on
# isort: on

# pylint: disable=invalid-name

# pylint: enable=invalid-name

from typing import Any, Optional


class NdV1Strategy:
    """
    # Summary

    Response validation strategy for ND API v1.

    ## Description

    Implements status code validation and error message extraction
    for ND API v1 (ND 4.2+).

    ## Status Codes

    - Success: 200, 201, 202, 204, 207
    - Not Found: 404 (treated as success for GET)
    - Error: anything not in success codes and not 404

    ## Error Formats Supported

    1. raw_response: Non-JSON response stored in DATA.raw_response
    2. code/message: DATA.code and DATA.message
    3. messages array: all DATA.messages[].{code, severity, message} joined with "; "
    4. errors array: all DATA.errors[] joined with "; "
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

    def is_success(self, response: dict) -> bool:
        """
        # Summary

        Check if the full response indicates success (v1).

        ## Description

        Returns True only when both conditions hold:

        1. `RETURN_CODE` is in `success_codes`
        2. The response body contains no embedded error indicators

        Embedded error indicators checked:

        - Top-level `ERROR` key is present
        - `DATA.error` key is present

        ## Parameters

        - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, etc.

        ## Returns

        - True if the response is fully successful, False otherwise

        ## Raises

        None
        """
        return_code = response.get("RETURN_CODE", -1)
        if return_code not in self.success_codes:
            return False
        if response.get("ERROR") is not None:
            return False
        data = response.get("DATA")
        if isinstance(data, dict) and data.get("error") is not None:
            return False
        return True

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

    def is_changed(self, response: dict) -> bool:
        """
        # Summary

        Check if a successful mutation request actually changed state (v1).

        ## Description

        ND API v1 may include a `modified` response header (forwarded by the HttpAPI
        plugin as a lowercase key in the response dict) with string values `"true"` or
        `"false"`. When present, this header is the authoritative signal for whether
        the operation mutated any state on the controller.

        When the header is absent the method defaults to `True`, preserving the
        historical behaviour for verbs (DELETE, POST, PUT) where ND does not send it.

        ## Parameters

        - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, and any HTTP
          response headers (lowercased) forwarded by the HttpAPI plugin.

        ## Returns

        - False if the `modified` header is present and equals `"false"` (case-insensitive)
        - True otherwise

        ## Raises

        None
        """
        modified = response.get("modified")
        if modified is None:
            return True
        return str(modified).lower() != "false"

    def extract_error_message(self, response: dict) -> Optional[str]:
        """
        # Summary

        Extract error message from v1 response DATA.

        ## Description

        Handles multiple ND API v1 error formats in priority order:

        1. Connection failure (no DATA)
        2. Non-JSON response (raw_response in DATA)
        3. code/message dict
        4. messages array with code/severity/message (all items joined)
        5. errors array (all items joined)
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
                parts = []
                for m in data_dict["messages"]:
                    if all(k in m for k in ("code", "severity", "message")):
                        parts.append(f"ND Error {m['code']} ({m['severity']}): {m['message']}")
                if parts:
                    msg = "; ".join(parts)

            # errors array format
            if msg is None and "errors" in data_dict and len(data_dict.get("errors", [])) > 0:
                msg = f"ND Error: {'; '.join(str(e) for e in data_dict['errors'])}"

            # Unknown dict format - fallback
            if msg is None:
                msg = f"ND Error: Request failed with status {return_code}"
        # Non-dict response data
        else:
            msg = f"ND Error: {response_data}"

        return msg
