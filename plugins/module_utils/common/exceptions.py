# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>
# Copyright: (c) 2026, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# exceptions.py

Exception classes for the cisco.nd Ansible collection.
"""

# isort: off
# fmt: off
from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
# fmt: on
# isort: on

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

from typing import Any, Optional

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    BaseModel,
    ConfigDict,
)


class NDErrorData(BaseModel):
    """
    # Summary

    Pydantic model for structured error data from NDModule requests.

    This model provides type-safe error information that can be serialized
    to a dict for use with Ansible's fail_json.

    ## Attributes

    - msg: Human-readable error message (required)
    - status: HTTP status code as integer (optional)
    - request_payload: Request payload that was sent (optional)
    - response_payload: Response payload from controller (optional)
    - raw: Raw response content for non-JSON responses (optional)

    ## Raises

    - None
    """

    model_config = ConfigDict(extra="forbid")

    msg: str
    status: Optional[int] = None
    request_payload: Optional[dict[str, Any]] = None
    response_payload: Optional[dict[str, Any]] = None
    raw: Optional[Any] = None


class NDModuleError(Exception):
    """
    # Summary

    Exception raised by NDModule when a request fails.

    This exception wraps an NDErrorData Pydantic model, providing structured
    error information that can be used by callers to build appropriate error
    responses (e.g., Ansible fail_json).

    ## Usage Example

    ```python
    try:
        data = nd.request("/api/v1/endpoint", HttpVerbEnum.POST, payload)
    except NDModuleError as e:
        print(f"Error: {e.msg}")
        print(f"Status: {e.status}")
        if e.response_payload:
            print(f"Response: {e.response_payload}")
        # Use to_dict() for fail_json
        module.fail_json(**e.to_dict())
    ```

    ## Raises

    - None
    """

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        msg: str,
        status: Optional[int] = None,
        request_payload: Optional[dict[str, Any]] = None,
        response_payload: Optional[dict[str, Any]] = None,
        raw: Optional[Any] = None,
    ) -> None:
        self.error_data = NDErrorData(
            msg=msg,
            status=status,
            request_payload=request_payload,
            response_payload=response_payload,
            raw=raw,
        )
        super().__init__(msg)

    @property
    def msg(self) -> str:
        """Human-readable error message."""
        return self.error_data.msg

    @property
    def status(self) -> Optional[int]:
        """HTTP status code."""
        return self.error_data.status

    @property
    def request_payload(self) -> Optional[dict[str, Any]]:
        """Request payload that was sent."""
        return self.error_data.request_payload

    @property
    def response_payload(self) -> Optional[dict[str, Any]]:
        """Response payload from controller."""
        return self.error_data.response_payload

    @property
    def raw(self) -> Optional[Any]:
        """Raw response content for non-JSON responses."""
        return self.error_data.raw

    def to_dict(self) -> dict[str, Any]:
        """
        # Summary

        Convert exception attributes to a dict for use with fail_json.

        Returns a dict containing only non-None attributes.

        ## Raises

        - None
        """
        return self.error_data.model_dump(exclude_none=True)


class NDStateMachineError(Exception):
    """
    Raised when NDStateMachine is failing.
    """

    pass
