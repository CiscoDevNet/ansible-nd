"""
Protocol definition for ResponseHandler classes.
"""

# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# pylint: disable=unnecessary-ellipsis

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

from typing import Optional, Protocol, runtime_checkable

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@runtime_checkable
class ResponseHandlerProtocol(Protocol):
    """
    # Summary

    Protocol defining the interface for response handlers in RestSend.

    Any class implementing this protocol must provide:

    -   `response` property (getter/setter): The controller response dict.
    -   `result` property (getter): The calculated result based on response and verb.
    -   `verb` property (getter/setter): The HTTP method (GET, POST, PUT, DELETE, etc.).
    -   `commit()` method: Parses response and sets result.

    ## Notes

    -   Getters for `response`, `result`, and `verb` should raise `ValueError` if
        accessed before being set.

    ## Example Implementations

    -   `ResponseHandler` in `response_handler_nd.py`: Handles Nexus Dashboard responses.
    -   Future: `ResponseHandlerApic` for APIC controller responses.
    """

    @property
    def response(self) -> dict:
        """
        # Summary

        The controller response.

        ## Raises

        - ValueError: If accessed before being set.
        """
        ...

    @response.setter
    def response(self, value: dict) -> None:
        pass

    @property
    def result(self) -> dict:
        """
        # Summary

        The calculated result based on response and verb.

        ## Raises

        - ValueError: If accessed before commit() is called.
        """
        ...

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        HTTP method for the request.

        ## Raises

        - ValueError: If accessed before being set.
        """
        ...

    @verb.setter
    def verb(self, value: HttpVerbEnum) -> None:
        pass

    def commit(self) -> None:
        """
        # Summary

        Parse the response and set the result.

        ## Raises

        - ValueError: If response or verb is not set.
        """
        ...

    @property
    def error_message(self) -> Optional[str]:
        """
        # Summary

        Human-readable error message extracted from response.

        ## Returns

        - str: Error message if an error occurred.
        - None: If the request was successful or commit() not called.
        """
        ...
