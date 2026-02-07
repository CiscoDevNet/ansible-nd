"""
Protocol definition for ResponseHandler classes.
"""

#
# Copyright (c) 2026 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

from typing import Optional, Protocol, runtime_checkable

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum  # type: ignore

# from enums import HttpVerbEnum


@runtime_checkable
class ResponseHandlerProtocol(Protocol):
    """
    ### Summary
    Protocol defining the response handler interface for RestSend.

    Any class implementing this protocol must provide:
    -   `response` property (getter/setter): The controller response dict.
    -   `result` property (getter): The calculated result based on response and verb.
    -   `verb` property (getter/setter): The HTTP method (GET, POST, PUT, DELETE, etc.).
    -   `commit()` method: Parses response and sets result.

    ### Notes
    -   Getters for `response`, `result`, and `verb` should raise `ValueError` if
        accessed before being set.

    ### Example Implementations
    -   `ResponseHandler` in `response_handler_nd.py`: Handles Nexus Dashboard responses.
    -   Future: `ResponseHandlerApic` for APIC controller responses.
    """

    @property
    def response(self) -> dict:
        """
        The controller response.

        Raises:
            ValueError: If accessed before being set.
        """
        ...

    @response.setter
    def response(self, value: dict) -> None: ...

    @property
    def result(self) -> dict:
        """
        The calculated result based on response and verb.

        Raises:
            ValueError: If accessed before commit() is called.
        """
        ...

    @property
    def verb(self) -> HttpVerbEnum:
        """
        HTTP method for the request.

        Raises:
            ValueError: If accessed before being set.
        """
        ...

    @verb.setter
    def verb(self, value: HttpVerbEnum) -> None: ...

    def commit(self) -> None:
        """
        Parse the response and set the result.

        Raises:
            ValueError: If response or verb is not set.
        """
        ...

    @property
    def error_message(self) -> Optional[str]:
        """
        Human-readable error message extracted from response.

        Returns:
            str: Error message if an error occurred.
            None: If the request was successful or commit() not called.
        """
        ...
