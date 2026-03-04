# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
# nd_v2.py

Simplified NDModule using RestSend infrastructure with exception-based error handling.

This module provides a streamlined interface for interacting with Nexus Dashboard
controllers. Unlike the original nd.py which uses Ansible's fail_json/exit_json,
this module raises Python exceptions, making it:

- Easier to unit test
- Reusable with non-Ansible code (e.g., raw Python Requests)
- More Pythonic in error handling

## Usage Example

```python
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import (
    NDModule,
    NDModuleError,
    nd_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

def main():
    argument_spec = nd_argument_spec()
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    nd = NDModule(module)

    try:
        data = nd.request("/api/v1/some/endpoint", HttpVerbEnum.GET)
        module.exit_json(changed=False, data=data)
    except NDModuleError as e:
        module.fail_json(msg=e.msg, status=e.status, response_payload=e.response_payload)
```
"""

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import logging
from typing import Any, Optional

from ansible.module_utils.basic import env_fallback
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDModuleError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.rest.protocols.response_handler import ResponseHandlerProtocol
from ansible_collections.cisco.nd.plugins.module_utils.rest.protocols.sender import SenderProtocol
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.sender_nd import Sender


def nd_argument_spec() -> dict[str, Any]:
    """
    Return the common argument spec for ND modules.

    This function provides the standard arguments that all ND modules
    should accept for connection and authentication.
    """
    return dict(
        host=dict(type="str", required=False, aliases=["hostname"], fallback=(env_fallback, ["ND_HOST"])),
        port=dict(type="int", required=False, fallback=(env_fallback, ["ND_PORT"])),
        username=dict(type="str", fallback=(env_fallback, ["ND_USERNAME", "ANSIBLE_NET_USERNAME"])),
        password=dict(type="str", required=False, no_log=True, fallback=(env_fallback, ["ND_PASSWORD", "ANSIBLE_NET_PASSWORD"])),
        output_level=dict(type="str", default="normal", choices=["debug", "info", "normal"], fallback=(env_fallback, ["ND_OUTPUT_LEVEL"])),
        timeout=dict(type="int", default=30, fallback=(env_fallback, ["ND_TIMEOUT"])),
        use_proxy=dict(type="bool", fallback=(env_fallback, ["ND_USE_PROXY"])),
        use_ssl=dict(type="bool", fallback=(env_fallback, ["ND_USE_SSL"])),
        validate_certs=dict(type="bool", fallback=(env_fallback, ["ND_VALIDATE_CERTS"])),
        login_domain=dict(type="str", fallback=(env_fallback, ["ND_LOGIN_DOMAIN"])),
    )


class NDModule:
    """
    # Summary

    Simplified NDModule using RestSend infrastructure with exception-based error handling.

    This class provides a clean interface for making REST API requests to Nexus Dashboard
    controllers. It uses the RestSend/Sender/ResponseHandler infrastructure for
    separation of concerns and testability.

    ## Key Differences from nd.py NDModule

    1. Uses exceptions (NDModuleError) instead of fail_json/exit_json
    2. No Connection class dependency - uses Sender for HTTP operations
    3. Minimal state - only tracks request/response metadata
    4. request() leverages RestSend -> Sender -> ResponseHandler

    ## Usage Example

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModule, NDModuleError
    from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum

    nd = NDModule(module)

    try:
        # GET request
        data = nd.request("/api/v1/endpoint")

        # POST request with payload
        result = nd.request("/api/v1/endpoint", HttpVerbEnum.POST, {"key": "value"})
    except NDModuleError as e:
        module.fail_json(**e.to_dict())
    ```

    ## Raises

    - NDModuleError: When a request fails (replaces fail_json)
    - ValueError: When RestSend encounters configuration errors
    - TypeError: When invalid types are passed to RestSend
    """

    def __init__(self, module) -> None:
        """
        Initialize NDModule with an AnsibleModule instance.

        Args:
            module: AnsibleModule instance (or compatible mock for testing)
        """
        self.class_name = self.__class__.__name__
        self.module = module
        self.params: dict[str, Any] = module.params

        self.log = logging.getLogger(f"nd.{self.class_name}")

        # Request/response state (for debugging and error reporting)
        self.method: Optional[str] = None
        self.path: Optional[str] = None
        self.response: Optional[str] = None
        self.status: Optional[int] = None
        self.url: Optional[str] = None

        # RestSend infrastructure (lazy initialized)
        self._rest_send: Optional[RestSend] = None
        self._sender: Optional[SenderProtocol] = None
        self._response_handler: Optional[ResponseHandlerProtocol] = None

        if self.module._debug:
            self.module.warn("Enable debug output because ANSIBLE_DEBUG was set.")
            self.params["output_level"] = "debug"

    def _get_rest_send(self) -> RestSend:
        """
        # Summary

        Lazy initialization of RestSend and its dependencies.

        ## Returns

        -   RestSend: Configured RestSend instance ready for use.
        """
        method_name = "_get_rest_send"
        params = {}
        if self._rest_send is None:
            params = {
                "check_mode": self.module.check_mode,
                "state": self.params.get("state"),
            }
            self._sender = Sender()
            self._sender.ansible_module = self.module
            self._response_handler = ResponseHandler()
            self._rest_send = RestSend(params)
            self._rest_send.sender = self._sender
            self._rest_send.response_handler = self._response_handler

            msg = f"{self.class_name}.{method_name}: "
            msg += "Initialized RestSend instance with params: "
            msg += f"{params}"
            self.log.debug(msg)
        return self._rest_send

    @property
    def rest_send(self) -> RestSend:
        """
        # Summary

        Access to the RestSend instance used by this NDModule.

        ## Returns

        -   RestSend: The RestSend instance.

        ## Raises

        -   `ValueError`: If accessed before `request()` has been called.

        ## Usage

        ```python
        nd = NDModule(module)
        data = nd.request("/api/v1/endpoint")

        # Access RestSend response/result
        response = nd.rest_send.response_current
        result = nd.rest_send.result_current
        ```
        """
        if self._rest_send is None:
            msg = f"{self.class_name}.rest_send: "
            msg += "rest_send must be initialized before accessing. "
            msg += "Call request() first."
            raise ValueError(msg)
        return self._rest_send

    def request(
        self,
        path: str,
        verb: HttpVerbEnum = HttpVerbEnum.GET,
        data: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """
        # Summary

        Make a REST API request to the Nexus Dashboard controller.

        This method uses the RestSend infrastructure for improved separation
        of concerns and testability.

        ## Args

        - path: The fully-formed API endpoint path including query string
                (e.g., "/appcenter/cisco/ndfc/api/v1/endpoint?param=value")
        - verb: HTTP verb as HttpVerbEnum (default: HttpVerbEnum.GET)
        - data: Optional request payload as a dict

        ## Returns

        The response DATA from the controller (parsed JSON body).

        For full response metadata (status, message, etc.), access
        `rest_send.response_current` and `rest_send.result_current`
        after calling this method.

        ## Raises

        - `NDModuleError`: If the request fails (with status, payload, etc.)
        - `ValueError`: If RestSend encounters configuration errors
        - `TypeError`: If invalid types are passed
        """
        method_name = "request"
        # If PATCH with empty data, return early (existing behavior)
        if verb == HttpVerbEnum.PATCH and not data:
            return {}

        rest_send = self._get_rest_send()

        # Send the request
        try:
            rest_send.path = path
            rest_send.verb = verb  # type: ignore[assignment]
            msg = f"{self.class_name}.{method_name}: "
            msg += "Sending request "
            msg += f"verb: {verb}, "
            msg += f"path: {path}"
            if data:
                rest_send.payload = data
                msg += f", data: {data}"
            self.log.debug(msg)
            rest_send.commit()
        except (TypeError, ValueError) as error:
            raise ValueError(f"Error in request: {error}") from error

        # Get response and result from RestSend
        response = rest_send.response_current
        result = rest_send.result_current

        # Update state for debugging/error reporting
        self.method = verb.value
        self.path = path
        self.response = response.get("MESSAGE")
        self.status = response.get("RETURN_CODE", -1)
        self.url = response.get("REQUEST_PATH")

        # Handle errors based on result
        if not result.get("success", False):
            response_data = response.get("DATA")

            # Get error message from ResponseHandler
            error_msg = self._response_handler.error_message if self._response_handler else "Unknown error"

            # Build exception with available context
            raw = None
            payload = None

            if isinstance(response_data, dict):
                if "raw_response" in response_data:
                    raw = response_data["raw_response"]
                else:
                    payload = response_data

            raise NDModuleError(
                msg=error_msg if error_msg else "Unknown error",
                status=self.status,
                request_payload=data,
                response_payload=payload,
                raw=raw,
            )

        # Return the response data on success
        return response.get("DATA", {})
