# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# Summary

Protocol definition for version-specific response validation strategies.

## Description

This module defines the ResponseValidationStrategy protocol which specifies
the interface for handling version-specific differences in ND API responses,
including status code validation and error message extraction.

When ND API v2 is released with different status codes or response formats,
implementing a new strategy class allows clean separation of v1 and v2 logic.
"""

# isort: off
# fmt: off
from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
# fmt: on
# isort: on

# pylint: disable=invalid-name

# pylint: enable=invalid-name

try:
    from typing import Protocol, runtime_checkable
except ImportError:
    try:
        from typing_extensions import Protocol, runtime_checkable  # type: ignore[assignment]
    except ImportError:

        class Protocol:  # type: ignore[no-redef]
            """Stub for Python < 3.8 without typing_extensions."""

        def runtime_checkable(cls):  # type: ignore[no-redef]
            return cls


from typing import Optional

# pylint: disable=unnecessary-ellipsis


@runtime_checkable
class ResponseValidationStrategy(Protocol):
    """
    # Summary

    Protocol for version-specific response validation.

    ## Description

    This protocol defines the interface for handling version-specific
    differences in ND API responses, including status code validation
    and error message extraction.

    Implementations of this protocol enable injecting version-specific
    behavior into ResponseHandler without modifying the handler itself.

    ## Methods

    See property and method definitions below.

    ## Raises

    None - implementations may raise exceptions per their logic
    """

    @property
    def success_codes(self) -> set[int]:
        """
        # Summary

        Return set of HTTP status codes considered successful.

        ## Returns

        - Set of integers representing success status codes
        """
        ...

    @property
    def not_found_code(self) -> int:
        """
        # Summary

        Return HTTP status code for resource not found.

        ## Returns

        - Integer representing not-found status code (typically 404)
        """
        ...

    def is_success(self, response: dict) -> bool:
        """
        # Summary

        Check if the full response indicates success.

        ## Description

        Implementations must check both the HTTP status code and any embedded error
        indicators in the response body, since some ND API endpoints return a
        successful status code (e.g. 200) while embedding an error in the payload.

        ## Parameters

        - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, etc.

        ## Returns

        - True if the response is fully successful (good status code and no embedded error), False otherwise

        ## Raises

        None
        """
        ...

    def is_not_found(self, return_code: int) -> bool:
        """
        # Summary

        Check if return code indicates not found.

        ## Parameters

        - return_code: HTTP status code to check

        ## Returns

        - True if code matches not_found_code, False otherwise

        ## Raises

        None
        """
        ...

    def is_changed(self, response: dict) -> bool:
        """
        # Summary

        Check if a successful mutation request actually changed state.

        ## Description

        Some ND API endpoints include a `modified` response header (string `"true"` or
        `"false"`) that explicitly signals whether the operation mutated any state.
        Implementations should honour this header when present and default to `True`
        when it is absent (matching the historical behaviour for PUT/POST/DELETE).

        This method should only be called after `is_success` has returned `True`.

        ## Parameters

        - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, and any HTTP
          response headers (lowercased) forwarded by the HttpAPI plugin.

        ## Returns

        - True if the operation changed state (or if the `modified` header is absent)
        - False if the `modified` header is explicitly `"false"`

        ## Raises

        None
        """
        ...

    def extract_error_message(self, response: dict) -> Optional[str]:
        """
        # Summary

        Extract error message from response DATA.

        ## Parameters

        - response: Response dict with keys RETURN_CODE, MESSAGE, DATA, etc.

        ## Returns

        - Error message string if found, None otherwise

        ## Raises

        None - should return None gracefully if error message cannot be extracted
        """
        ...
