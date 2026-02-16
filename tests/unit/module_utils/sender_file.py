# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Sender module conforming to SenderProtocol for file-based mock responses.

See plugins/module_utils/protocol_sender.py for the protocol definition.
"""

from __future__ import absolute_import, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import copy
import inspect
import logging

# TODO: Review typing imports after we drop support for Python 3.8
from typing import Any, Dict, Optional

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator


class Sender:
    """
    # Summary

    An injected dependency for `RestSend` which implements the
    `sender` interface.  Responses are read from JSON files.

    ## Raises

    -   `ValueError` if:
            -   `gen` is not set.
    -   `TypeError` if:
            -   `gen` is not an instance of ResponseGenerator()

    ## Usage

    -   `gen` is an instance of `ResponseGenerator()` which yields simulated responses.
        In the example below, `responses()` is a generator that yields dictionaries.
        However, in practice, it would yield responses read from JSON files.
    -   `responses()` is a coroutine that yields controller responses.
        In the example below, it yields to dictionaries.  However, in
        practice, it would yield responses read from JSON files.

    ```python
    def responses():
        yield {"key1": "value1"}
        yield {"key2": "value2"}

    sender = Sender()
    sender.gen = ResponseGenerator(responses())

    try:
        rest_send = RestSend()
        rest_send.sender = sender
    except (TypeError, ValueError) as error:
        handle_error(error)
    # etc...
    # See rest_send.py for RestSend() usage.
    ```
    """

    def __init__(self) -> None:
        self.class_name = self.__class__.__name__

        self.log = logging.getLogger(f"nd.{self.class_name}")

        self._ansible_module: Optional[MockAnsibleModule] = None
        self._gen: Optional[ResponseGenerator] = None
        self._path: Optional[str] = None
        self._payload: Optional[Dict[str, Any]] = None
        self._response: Optional[Dict[str, Any]] = None
        self._verb: Optional[HttpVerbEnum] = None

        self._raise_method: Optional[str] = None
        self._raise_exception: Optional[BaseException] = None

        msg = "ENTERED Sender(): "
        self.log.debug(msg)

    def commit(self) -> None:
        """
        # Summary

        - Simulate a commit to a controller (does nothing).
        - Allows to simulate exceptions for testing error handling in RestSend by setting the `raise_exception` and `raise_method` properties.

        ## Raises

        -   `ValueError` if `gen` is not set.
        -   `self.raise_exception` if set and
            `self.raise_method` == "commit"
        """
        method_name = "commit"

        if self.raise_method == method_name and self.raise_exception is not None:
            msg = f"{self.class_name}.{method_name}: "
            msg += f"Simulated {type(self.raise_exception).__name__}."
            raise self.raise_exception

        caller = inspect.stack()[1][3]
        msg = f"{self.class_name}.{method_name}: "
        msg += f"caller {caller}"
        self.log.debug(msg)

    @property
    def ansible_module(self) -> Optional[MockAnsibleModule]:
        """
        # Summary

        Mock ansible_module
        """
        return self._ansible_module

    @ansible_module.setter
    def ansible_module(self, value: Optional[MockAnsibleModule]):
        self._ansible_module = value

    @property
    def gen(self) -> ResponseGenerator:
        """
        # Summary

        The `ResponseGenerator()` instance which yields simulated responses.

        ## Raises

        -   `ValueError` if `gen` is not set.
        -   `TypeError` if value is not a class implementing the `response_generator` interface.
        """
        if self._gen is None:
            msg = f"{self.class_name}.gen: gen must be set to a class implementing the response_generator interface."
            raise ValueError(msg)
        return self._gen

    @gen.setter
    def gen(self, value: ResponseGenerator) -> None:
        method_name = inspect.stack()[0][3]
        msg = f"{self.class_name}.{method_name}: "
        msg += "Expected a class implementing the "
        msg += "response_generator interface. "
        msg += f"Got {value}."
        try:
            implements = value.implements
        except AttributeError as error:
            raise TypeError(msg) from error
        if implements != "response_generator":
            raise TypeError(msg)
        self._gen = value

    @property
    def path(self) -> str:
        """
        # Summary

        Dummy path.

        ## Raises

        None

        ## Example

        ``/appcenter/cisco/ndfc/api/v1/...etc...``
        """
        if self._path is None:
            msg = f"{self.class_name}.path: path must be set before accessing."
            raise ValueError(msg)
        return self._path

    @path.setter
    def path(self, value: str):
        self._path = value

    @property
    def payload(self) -> Optional[Dict[str, Any]]:
        """
        # Summary

        Dummy payload.

        ## Raises

        None
        """
        return self._payload

    @payload.setter
    def payload(self, value: Optional[Dict[str, Any]]):
        self._payload = value

    @property
    def raise_exception(self) -> Optional[BaseException]:
        """
        # Summary

        The exception to raise when calling the method specified in `raise_method`.

        ## Raises

        -   `TypeError` if value is not a subclass of `BaseException`.

        ## Usage

        ```python
        instance = Sender()
        instance.raise_method = "commit"
        instance.raise_exception = ValueError
        instance.commit() # will raise a simulated ValueError
        ```

        ## Notes

        -   No error checking is done on the input to this property.
        """
        if self._raise_exception is not None and not issubclass(type(self._raise_exception), BaseException):
            msg = f"{self.class_name}.raise_exception: "
            msg += "raise_exception must be a subclass of BaseException. "
            msg += f"Got {self._raise_exception} of type {type(self._raise_exception).__name__}."
            raise TypeError(msg)
        return self._raise_exception

    @raise_exception.setter
    def raise_exception(self, value: Optional[BaseException]):
        if value is not None and not issubclass(type(value), BaseException):
            msg = f"{self.class_name}.raise_exception: "
            msg += "raise_exception must be a subclass of BaseException. "
            msg += f"Got {value} of type {type(value).__name__}."
            raise TypeError(msg)
        self._raise_exception = value

    @property
    def raise_method(self) -> Optional[str]:
        """
        ## Summary

        The method in which to raise exception `raise_exception`.

        ## Raises

        None

        ## Usage

        See `raise_exception`.
        """
        return self._raise_method

    @raise_method.setter
    def raise_method(self, value: Optional[str]) -> None:
        self._raise_method = value

    @property
    def response(self) -> Dict[str, Any]:
        """
        # Summary

        The simulated response from a file.

        Returns a deepcopy to prevent mutation of the response object.

        ## Raises

        None
        """
        return copy.deepcopy(self.gen.next)

    @property
    def verb(self) -> HttpVerbEnum:
        """
        # Summary

        Dummy Verb.

        ## Raises

        -   `ValueError` if verb is not set.
        """
        if self._verb is None:
            msg = f"{self.class_name}.verb: verb must be set before accessing."
            raise ValueError(msg)
        return self._verb

    @verb.setter
    def verb(self, value: HttpVerbEnum) -> None:
        self._verb = value
