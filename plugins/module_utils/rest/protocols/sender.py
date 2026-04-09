# pylint: disable=wrong-import-position
# pylint: disable=missing-module-docstring
# pylint: disable=unnecessary-ellipsis


# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


@runtime_checkable
class SenderProtocol(Protocol):
    """
    # Summary

    Protocol defining the sender interface for RestSend.

    Any class implementing this protocol must provide:

    -   `path` property (getter/setter): The endpoint path for the REST request.
    -   `verb` property (getter/setter): The HTTP method (GET, POST, PUT, DELETE, etc.).
    -   `payload` property (getter/setter): Optional request payload as a dict.
    -   `response` property (getter): The response from the controller.
    -   `commit()` method: Sends the request to the controller.

    ## Example Implementations

    -   `Sender` in `sender_nd.py`: Uses Ansible HttpApi plugin.
    -   `Sender` in `sender_file.py`: Reads responses from files (for testing).
    """

    @property
    def path(self) -> str:
        """Endpoint path for the REST request."""
        ...

    @path.setter
    def path(self, value: str) -> None:
        """Set the endpoint path for the REST request."""
        ...

    @property
    def verb(self) -> HttpVerbEnum:
        """HTTP method for the REST request."""
        ...

    @verb.setter
    def verb(self, value: HttpVerbEnum) -> None:
        """Set the HTTP method for the REST request."""
        ...

    @property
    def payload(self) -> Optional[dict]:
        """Optional payload to send to the controller."""
        ...

    @payload.setter
    def payload(self, value: dict) -> None:
        """Set the optional payload for the REST request."""
        ...

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
