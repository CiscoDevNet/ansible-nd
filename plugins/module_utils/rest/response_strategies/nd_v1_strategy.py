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

from collections.abc import Iterable, Mapping
from typing import Any, Optional, TypeVar

T = TypeVar("T")

# Per-item status literals that mark a failure inside a Multi-Status body. ND sends these
# on HTTP 207 and, for some endpoints, on HTTP 200 as well, so the body is scanned on any
# success code. ND is also inconsistent about the literal across endpoints: "failed" (batch
# interface / switchActions/deploy), "error" (breakout), and "failure" (acl / maintenance_mode).
_MULTISTATUS_FAILURE_STATUSES = frozenset({"failed", "failure", "error"})

# DATA envelope keys whose items carry a per-item `status`. Two known shapes:
# - `results`   -> batch interface POST / breakout action
# - `switchIds` -> switchActions/deploy (per-switch outcome)
_MULTISTATUS_ITEM_KEYS = ("results", "switchIds")

# Item keys, in priority order, used to label a failing item in an error message.
_MULTISTATUS_ITEM_LABEL_KEYS = ("name", "switchId", "serialNumber", "id")

# Item keys, in priority order, carrying the per-item failure detail. ND is not consistent
# across endpoints: `message` (batch interface / switchActions/deploy) and `warningMessage`
# (fabric update-group attach) are both in use.
_MULTISTATUS_ITEM_MESSAGE_KEYS = ("message", "warningMessage", "status")


def _get_typed_value(mapping: Mapping[str, Any], key: str, expected_type: type[T], default: T) -> T:
    """
    # Summary

    Return `mapping[key]` when it is an instance of `expected_type`, else `default`.

    ## Description

    ND bodies are not schema-guaranteed: a key may be absent, or present with a `null` (or otherwise unexpected) value. `dict.get(key, default)`
    only covers the absent case -- it returns `None` for an explicit `null` -- so callers that go on to index, iterate, or call `len()` need this
    type-checked accessor instead.

    ## Parameters

    - mapping: The dict to read from
    - key: The key to read
    - expected_type: The type the value must be an instance of
    - default: The value returned when the key is absent or the value has the wrong type

    ## Returns

    - The value at `key` when it is an instance of `expected_type`, otherwise `default`

    ## Raises

    None
    """
    value = mapping.get(key)
    return value if isinstance(value, expected_type) else default


def _first_non_empty(mapping: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    """
    # Summary

    Return the first non-empty value in `mapping` among `keys`, as a string.

    ## Description

    Keys are tried in the order given. A key whose value is absent, `None`, or stringifies to an empty (or whitespace-only) string is skipped, so an
    item such as `{"name": "", "switchId": "FDO123"}` labels as `FDO123` rather than as the empty string.

    ## Parameters

    - mapping: The dict to read from
    - keys: Candidate keys, in priority order

    ## Returns

    - The first non-empty value as a string, or None when every candidate key is absent or empty

    ## Raises

    None
    """
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _failed_multistatus_items(response: dict) -> list[dict[str, Any]]:
    """
    # Summary

    Return the per-item entries reporting a failure in a Multi-Status body.

    ## Description

    Scans the known ND Multi-Status envelope arrays (`DATA.results[]` and `DATA.switchIds[]`) and returns every item whose `status` is a failure
    literal (`failed`/`failure`/`error`, case-insensitive, whitespace-tolerant). Returns an empty list when `DATA` is not a dict, neither array is
    present, or every item succeeded.

    ## Parameters

    - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, etc.

    ## Returns

    - List of failing item dicts (empty list when none fail)

    ## Raises

    None
    """
    failed: list[dict[str, Any]] = []
    data = _get_typed_value(response, "DATA", dict, {})
    for key in _MULTISTATUS_ITEM_KEYS:
        items = _get_typed_value(data, key, list, [])
        failed.extend(item for item in items if isinstance(item, dict) and str(item.get("status") or "").strip().lower() in _MULTISTATUS_FAILURE_STATUSES)
    return failed


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
    3. error: Scalar DATA.error value
    4. messages array: all DATA.messages[].{code, severity, message} joined with "; "
    5. errors array: all DATA.errors[] joined with "; "
    6. Multi-Status per-item failures: DATA.results[]/DATA.switchIds[] failing items joined with "; "
    7. Connection failure: No DATA with REQUEST_PATH and MESSAGE
    8. Non-dict DATA: Stringified DATA value
    9. Unknown: Fallback with RETURN_CODE

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
        - A Multi-Status body reports a per-item failure in `DATA.results[]` or
          `DATA.switchIds[]` (status `failed`/`failure`/`error`). This is checked on any
          success code, not only 207: ND sends per-item statuses on HTTP 200 for some
          endpoints (e.g. the L3Out batch POST).

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
        # ND reports per-item outcomes for batch operations in DATA.results[]/DATA.switchIds[]
        # items carrying status: success|failed|failure|error. The HTTP status alone does not
        # indicate every item succeeded -- ND sends these bodies on 207 and, for some endpoints,
        # on plain 200 -- so any success-code response with a failing item must not be
        # classified as success. See issue #295.
        if _failed_multistatus_items(response):
            return False
        return True

    @staticmethod
    def _format_multistatus_failure(item: dict[str, Any]) -> str:
        """
        # Summary

        Format a single failing Multi-Status item as `label: message`.

        ## Description

        Labels the item by the first non-empty identifier key (`_MULTISTATUS_ITEM_LABEL_KEYS`) and appends the first non-empty detail key
        (`_MULTISTATUS_ITEM_MESSAGE_KEYS`, which falls back to `status` when no message key is present). Empty and whitespace-only values are skipped
        rather than used, so an item carrying `{"name": ""}` is not labelled with the empty string. When no identifier key is present, only the
        detail is returned; when no detail key is present either, the generic literal `failed` is used.

        ## Parameters

        - item: A per-item dict from `DATA.results[]` or `DATA.switchIds[]`

        ## Returns

        - A human-readable `label: message` string (or just the message when unlabeled)

        ## Raises

        None
        """
        label = _first_non_empty(item, _MULTISTATUS_ITEM_LABEL_KEYS)
        detail = _first_non_empty(item, _MULTISTATUS_ITEM_MESSAGE_KEYS) or "failed"
        return f"{label}: {detail}" if label is not None else detail

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
        4. Scalar error key (DATA.error)
        5. messages array with code/severity/message (all items joined)
        6. errors array (all items joined)
        7. Multi-Status per-item failures (results[]/switchIds[], all joined)
        8. Unknown dict format
        9. Non-dict DATA

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
            msg = self._extract_dict_error_message(response_data, response, return_code)
        # Non-dict response data
        else:
            msg = f"ND Error: {response_data}"

        return msg

    def _extract_dict_error_message(self, data_dict: dict[str, Any], response: dict, return_code: int) -> str:
        """
        # Summary

        Extract an error message from a dict `DATA` body across the known ND v1 formats.

        ## Description

        Checks, in priority order: `raw_response`, `code`/`message`, the scalar `error` key, the `messages[]` array, the `errors[]` array, and
        Multi-Status per-item failures (`results[]`/`switchIds[]`). Falls back to a generic status message when no specific format matches.

        The `messages` and `errors` arrays are read through `_get_typed_value` because ND may send either key with an explicit `null` value, which a
        bare `data_dict[key]` would iterate (or `len()`) into a `TypeError` on the very path that reports an error to the user.

        ## Parameters

        - data_dict: The response `DATA` dict
        - response: The full response dict (needed to scan Multi-Status envelopes)
        - return_code: The response `RETURN_CODE`, used in the fallback message

        ## Returns

        - A human-readable error message string (never None)

        ## Raises

        None
        """
        msg: Optional[str] = None
        # Raw response (non-JSON)
        if "raw_response" in data_dict:
            msg = "ND Error: Response could not be parsed as JSON"
        # code/message format
        elif "code" in data_dict and "message" in data_dict:
            msg = f"ND Error {data_dict['code']}: {data_dict['message']}"

        # Scalar error key. `is_success()` already classifies a response carrying DATA.error as a
        # failure; without this branch the error ND actually sent is dropped and the user is shown
        # only the generic "Request failed with status <code>" fallback below.
        if msg is None and data_dict.get("error") is not None:
            msg = f"ND Error: {data_dict['error']}"

        # messages array format
        if msg is None:
            parts = []
            for m in _get_typed_value(data_dict, "messages", list, []):
                if isinstance(m, dict) and all(k in m for k in ("code", "severity", "message")):
                    parts.append(f"ND Error {m['code']} ({m['severity']}): {m['message']}")
            if parts:
                msg = "; ".join(parts)

        # errors array format
        if msg is None:
            errors = _get_typed_value(data_dict, "errors", list, [])
            if errors:
                msg = f"ND Error: {'; '.join(str(e) for e in errors)}"

        # Multi-Status per-item failures (results[]/switchIds[])
        if msg is None:
            failed_items = _failed_multistatus_items(response)
            if failed_items:
                parts = [self._format_multistatus_failure(item) for item in failed_items]
                msg = f"ND Error: {'; '.join(parts)}"

        # Unknown dict format - fallback
        if msg is None:
            msg = f"ND Error: Request failed with status {return_code}"
        return msg
