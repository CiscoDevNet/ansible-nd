"""
Sender module conforming to SenderProtocol.

See plugins/module_utils/protocol_sender.py for the protocol definition.
"""

# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name
__author__ = "Allen Robel"

import copy
import inspect
import json
import logging

# TODO: Review typing imports after we drop support for Python 3.8
from typing import Any, Dict, Optional

from ansible.module_utils.basic import AnsibleModule  # type: ignore
from ansible.module_utils.connection import Connection  # type: ignore
from ansible.module_utils.connection import ConnectionError as AnsibleConnectionError
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum


class Sender:
    """
    # Summary

    An injected dependency for `RestSend` which implements the
    `sender` interface.  Responses are retrieved using the Ansible HttpApi plugin.

    For the `sender` interface definition, see `plugins/module_utils/protocol_sender.py`.

    ## Raises

    -   `ValueError` if:
            -   `ansible_module` is not set.
            -   `path` is not set.
            -   `verb` is not set.
    -   `TypeError` if:
            -   `ansible_module` is not an instance of AnsibleModule.
            -   `payload` is not a `dict`.
            -   `response` is not a `dict`.

    ## Usage

    `ansible_module` is an instance of `AnsibleModule`.

    ```python
    sender = Sender()
    try:
        sender.ansible_module = ansible_module
        rest_send = RestSend()
        rest_send.sender = sender
    except (TypeError, ValueError) as error:
        handle_error(error)
    # etc...
    # See rest_send.py for RestSend() usage.
    ```
    """

    def __init__(
        self,
        ansible_module: Optional[AnsibleModule] = None,
        verb: Optional[HttpVerbEnum] = None,
        path: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.class_name = self.__class__.__name__

        self.log = logging.getLogger(f"nd.{self.class_name}")

        self._ansible_module: Optional[AnsibleModule] = ansible_module
        self._connection: Optional[Connection] = None

        self._path: Optional[str] = path
        self._payload: Optional[Dict[str, Any]] = payload
        self._response: Optional[Dict[str, Any]] = None
        self._verb: Optional[HttpVerbEnum] = verb

        msg = "ENTERED Sender(): "
        self.log.debug(msg)

    def commit(self) -> None:
        """
        # Summary

        Send the request to the controller

        ## Raises

        -  `ConnectionError` if there is an error with the connection to the controller.

        ## Properties read

        -   `verb`: HTTP verb e.g. GET, POST, PATCH, PUT, DELETE
        -   `path`: HTTP path e.g. /api/v1/some_endpoint
        -   `payload`: Optional HTTP payload

        ## Properties written

        -   `response`: raw response from the controller
        """
        method_name = "commit"
        caller = inspect.stack()[1][3]

        if self._connection is None:
            self._connection = Connection(self.ansible_module._socket_path)  # pylint: disable=protected-access
            self._connection.set_params(self.ansible_module.params)

        msg = f"{self.class_name}.{method_name}: "
        msg += f"caller: {caller}.  "
        msg += "Calling Connection().send_request: "
        msg += f"verb {self.verb.value}, path {self.path}"
        try:
            if self.payload is None:
                self.log.debug(msg)
                response = self._connection.send_request(self.verb.value, self.path)
            else:
                msg += ", payload: "
                msg += f"{json.dumps(self.payload, indent=4, sort_keys=True)}"
                self.log.debug(msg)
                response = self._connection.send_request(
                    self.verb.value,
                    self.path,
                    json.dumps(self.payload),
                )
            # Normalize response: if JSON parsing failed, DATA will be None
            # and raw content will be in the "raw" key. Convert to consistent format.
            response = self._normalize_response(response)
            self.response = response
        except AnsibleConnectionError as error:
            msg = f"{self.class_name}.{method_name}: "
            msg += f"ConnectionError occurred: {error}"
            self.log.error(msg)
            raise AnsibleConnectionError(msg) from error
        except Exception as error:
            msg = f"{self.class_name}.{method_name}: "
            msg += f"Unexpected error occurred: {error}"
            self.log.error(msg)
            raise AnsibleConnectionError(msg) from error

    def _normalize_response(self, response: dict) -> dict:
        """
        # Summary

        Normalize the HttpApi response to ensure consistent format.

        If the HttpApi plugin failed to parse the response as JSON, the
        `DATA` key will be None and the raw response content will be in
        the `raw` key. This method converts such responses to a consistent
        format where `DATA` contains a dict with the raw content.

        ## Parameters

        -   `response`: The response dict from the HttpApi plugin.

        ## Returns

        The normalized response dict.
        """
        if response.get("DATA") is None and response.get("raw") is not None:
            response["DATA"] = {"raw_response": response.get("raw")}
            # If MESSAGE is just the HTTP reason phrase, enhance it
            if response.get("MESSAGE") in ("OK", None):
                response["MESSAGE"] = "Response could not be parsed as JSON"
        return response

    @property
    def ansible_module(self) -> AnsibleModule:
        """
        # Summary

        The AnsibleModule instance to use for this sender.

        ## Raises

        -   `ValueError` if ansible_module is not set.
        """
        if self._ansible_module is None:
            msg = f"{self.class_name}.ansible_module: "
            msg += "ansible_module must be set before accessing ansible_module."
            raise ValueError(msg)
        return self._ansible_module

    @ansible_module.setter
    def ansible_module(self, value: AnsibleModule):
        self._ansible_module = value

    @property
    def path(self) -> str:
        """
        # Summary

        Endpoint path for the REST request.

        ## Raises

        None

        ## Example

        ``/appcenter/cisco/ndfc/api/v1/...etc...``
        """
        if self._path is None:
            msg = f"{self.class_name}.path: "
            msg += "path must be set before accessing path."
            raise ValueError(msg)
        return self._path

    @path.setter
    def path(self, value: str):
        self._path = value

    @property
    def payload(self) -> Optional[Dict[str, Any]]:
        """
        # Summary

        Return the payload to send to the controller

        ## Raises
        -   `TypeError` if value is not a `dict`.
        """
        return self._payload

    @payload.setter
    def payload(self, value: dict):
        method_name = inspect.stack()[0][3]
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a dict. "
            msg += f"Got type {type(value).__name__}, "
            msg += f"value {value}."
            raise TypeError(msg)
        self._payload = value

    @property
    def response(self) -> dict:
        """
        # Summary

        The response from the controller.

        -   getter: Return a deepcopy of `response`
        -   setter: Set `response`

        ## Raises

        -   getter: `ValueError` if response is not set.
        -   setter: `TypeError` if value is not a `dict`.
        """
        if self._response is None:
            msg = f"{self.class_name}.response: "
            msg += "response must be set before accessing response."
            raise ValueError(msg)
        return copy.deepcopy(self._response)

    @response.setter
    def response(self, value: dict):
        method_name = inspect.stack()[0][3]
        if not isinstance(value, dict):
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be a dict. "
            msg += f"Got type {type(value).__name__}, "
            msg += f"value {value}."
            raise TypeError(msg)
        self._response = value

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        HTTP method for the REST request.

        ## Raises

        -   getter: `ValueError` if verb is not set.
        -   setter: `TypeError` if value is not a `HttpVerbEnum`.
        """
        if self._verb is None:
            msg = f"{self.class_name}.verb: "
            msg += "verb must be set before accessing verb."
            raise ValueError(msg)
        return self._verb

    @verb.setter
    def verb(self, value: HttpVerbEnum):
        method_name = inspect.stack()[0][3]
        if value not in HttpVerbEnum.values():
            msg = f"{self.class_name}.{method_name}: "
            msg += f"{method_name} must be one of {HttpVerbEnum.values()}. "
            msg += f"Got {value}."
            raise TypeError(msg)
        self._verb = value
