"""
Protocol definition for Sender classes.
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
class SenderProtocol(Protocol):
    """
    ### Summary
    Protocol defining the sender interface for RestSend.

    Any class implementing this protocol must provide:
    -   `path` property (getter/setter): The endpoint path for the REST request.
    -   `verb` property (getter/setter): The HTTP method (GET, POST, PUT, DELETE, etc.).
    -   `payload` property (getter/setter): Optional request payload as a dict.
    -   `response` property (getter): The response from the controller.
    -   `commit()` method: Sends the request to the controller.

    ### Example Implementations
    -   `Sender` in `sender_nd.py`: Uses Ansible HttpApi plugin.
    -   `Sender` in `sender_file.py`: Reads responses from files (for testing).
    """

    @property
    def path(self) -> str:
        """Endpoint path for the REST request."""
        ...

    @path.setter
    def path(self, value: str) -> None: ...

    @property
    def verb(self) -> HttpVerbEnum:
        """HTTP method for the REST request."""
        ...

    @verb.setter
    def verb(self, value: HttpVerbEnum) -> None: ...

    @property
    def payload(self) -> Optional[dict]:
        """Optional payload to send to the controller."""
        ...

    @payload.setter
    def payload(self, value: dict) -> None: ...

    @property
    def response(self) -> dict:
        """The response from the controller."""
        ...

    def commit(self) -> None:
        """
        Send the request to the controller.

        Raises:
            ConnectionError: If there is an error with the connection.
        """
        ...
