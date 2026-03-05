# -*- coding: utf-8 -*-

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
from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
# isort: on

# pylint: disable=invalid-name
__metaclass__ = type
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

    @property
    def error_codes(self) -> set[int]:
        """
        # Summary

        Return set of HTTP status codes considered errors.

        ## Returns

        - Set of integers representing error status codes
        """
        ...

    def is_success(self, return_code: int) -> bool:
        """
        # Summary

        Check if return code indicates success.

        ## Parameters

        - return_code: HTTP status code to check

        ## Returns

        - True if code is in success_codes, False otherwise

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

    def is_error(self, return_code: int) -> bool:
        """
        # Summary

        Check if return code indicates error.

        ## Parameters

        - return_code: HTTP status code to check

        ## Returns

        - True if code is in error_codes, False otherwise

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
