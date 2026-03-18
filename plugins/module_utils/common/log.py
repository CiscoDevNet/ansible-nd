# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

import json
import logging
from enum import Enum
from logging.config import dictConfig
from os import environ
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ansible.module_utils.basic import AnsibleModule


class ValidLogHandlers(str, Enum):
    """Valid logging handler classes (must not log to console)."""

    FILE_HANDLER = "logging.FileHandler"
    ROTATING_FILE_HANDLER = "logging.handlers.RotatingFileHandler"
    TIMED_ROTATING_FILE_HANDLER = "logging.handlers.TimedRotatingFileHandler"
    WATCHED_FILE_HANDLER = "logging.handlers.WatchedFileHandler"


class Log:
    """
    # Summary

    Create the base nd logging object.

    ## Raises

    -   `ValueError` if:
            -   An error is encountered reading the logging config file.
            -   An error is encountered parsing the logging config file.
            -   An invalid handler is found in the logging config file.
                    -   Valid handlers are defined in `ValidLogHandlers`.
            -   No formatters are found in the logging config file that
                are associated with the configured handlers.
    -   `TypeError` if:
            -   `develop` is not a boolean.

    ## Usage

    By default, Log() does the following:

    1.  Reads the environment variable `ND_LOGGING_CONFIG` to determine
        the path to the logging config file.  If the environment variable is
        not set, then logging is disabled.
    2.  Sets `develop` to False.  This disables exceptions raised by the
        logging module itself.

    Hence, the simplest usage for Log() is:

    -   Set the environment variable `ND_LOGGING_CONFIG` to the
        path of the logging config file.  `bash` shell is used in the
        example below.

    ```bash
    export ND_LOGGING_CONFIG="/path/to/logging_config.json"
    ```

    -   Instantiate a Log() object instance and call `commit()` on the instance:

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
    try:
        log = Log()
        log.commit()
    except ValueError as error:
        # handle error
    ```

    To later disable logging, unset the environment variable.
    `bash` shell is used in the example below.

    ```bash
    unset ND_LOGGING_CONFIG
    ```

    To enable exceptions from the logging module (not recommended, unless needed for
    development), set `develop` to True:

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
    try:
        log = Log()
        log.develop = True
        log.commit()
    except ValueError as error:
        # handle error
    ```

    To directly set the path to the logging config file, overriding the
    `ND_LOGGING_CONFIG` environment variable, set the `config`
    property prior to calling `commit()`:

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log
    try:
        log = Log()
        log.config = "/path/to/logging_config.json"
        log.commit()
    except ValueError as error:
        # handle error
    ```

    At this point, a base/parent logger is created for which all other
    loggers throughout the nd collection will be children.
    This allows for a single logging config to be used for all modules in the
    collection, and allows for the logging config to be specified in a
    single place external to the code.

    ## Example module code using the Log() object

    The `setup_logging()` helper is the recommended way to configure logging in module `main()` functions.
    It handles exceptions internally by calling `module.fail_json()`.

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging

    def main():
        module = AnsibleModule(...)
        log = setup_logging(module)

        task = AnsibleTask()
    ```

    To enable logging exceptions during development, pass `develop=True`:

    ```python
    log = setup_logging(module, develop=True)
    ```

    Alternatively, `Log()` can be used directly when finer control is needed:

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log

    def main():
        try:
            log = Log()
            log.commit()
        except ValueError as error:
            ansible_module.fail_json(msg=str(error))

        task = AnsibleTask()
    ```

    In the AnsibleTask() class (or any other classes running in the
    main() function's call stack i.e. classes instantiated in either
    main() or in AnsibleTask()).

    ```python
    class AnsibleTask:
        def __init__(self):
            self.class_name = self.__class__.__name__
            self.log = logging.getLogger(f"nd.{self.class_name}")
        def some_method(self):
            self.log.debug("This is a debug message.")
    ```

    ## Logging Config File

    The logging config file MUST conform to `logging.config.dictConfig`
    from Python's standard library and MUST NOT contain any handlers or
    that log to stdout or stderr.  The logging config file MUST only
    contain handlers that log to files.

    An example logging config file is shown below:

    ```json
    {
        "version": 1,
        "formatters": {
            "standard": {
                "class": "logging.Formatter",
                "format": "%(asctime)s - %(levelname)s - [%(name)s.%(funcName)s.%(lineno)d] %(message)s"
            }
        },
        "handlers": {
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "standard",
                "level": "DEBUG",
                "filename": "/tmp/nd.log",
                "mode": "a",
                "encoding": "utf-8",
                "maxBytes": 50000000,
                "backupCount": 4
            }
        },
        "loggers": {
            "nd": {
                "handlers": [
                    "file"
                ],
                "level": "DEBUG",
                "propagate": false
            }
        },
        "root": {
            "level": "INFO",
            "handlers": [
                "file"
            ]
        }
    }
    ```
    """

    def __init__(self, config: Optional[str] = None, develop: bool = False):
        self.class_name = self.__class__.__name__
        # Disable exceptions raised by the logging module.
        # Set this to True during development to catch logging errors.
        logging.raiseExceptions = False

        self._config: Optional[str] = environ.get("ND_LOGGING_CONFIG", None)
        self._develop: bool = False
        if config is not None:
            self.config = config
        self.develop = develop

    def disable_logging(self) -> None:
        """
        # Summary

        Disable logging by removing all handlers from the base logger.

        ## Raises

        None
        """
        logger = logging.getLogger()
        for handler in logger.handlers.copy():
            try:
                logger.removeHandler(handler)
            except ValueError:  # if handler already removed
                pass
        logger.addHandler(logging.NullHandler())
        logger.propagate = False

    def enable_logging(self) -> None:
        """
        # Summary

        Enable logging by reading the logging config file and configuring
        the base logger instance.

        ## Raises
        -   `ValueError` if:
            -   An error is encountered reading the logging config file.
        """
        if self.config is None or self.config.strip() == "":
            return

        try:
            with open(self.config, "r", encoding="utf-8") as file:
                try:
                    logging_config = json.load(file)
                except json.JSONDecodeError as error:
                    msg = f"error parsing logging config from {self.config}. "
                    msg += f"Error detail: {error}"
                    raise ValueError(msg) from error
        except IOError as error:
            msg = f"error reading logging config from {self.config}. "
            msg += f"Error detail: {error}"
            raise ValueError(msg) from error

        try:
            self._validate_logging_config(logging_config)
        except ValueError as error:
            raise ValueError(str(error)) from error

        try:
            dictConfig(logging_config)
        except (RuntimeError, TypeError, ValueError) as error:
            msg = "logging.config.dictConfig: "
            msg += f"Unable to configure logging from {self.config}. "
            msg += f"Error detail: {error}"
            raise ValueError(msg) from error

    def _validate_logging_config(self, logging_config: dict) -> None:
        """
        # Summary

        -   Validate the logging config file.
        -   Ensure that the logging config file does not contain any handlers
            that log to console, stdout, or stderr.

        ## Raises

        -   `ValueError` if:
            -   The logging config file contains no handlers.
            -   Any handler's `class` property is not one of the classes
                defined in `ValidLogHandlers`.

        ## Usage

        ```python
        log = Log()
        log.config = "/path/to/logging_config.json"
        log.commit()
        ```
        """
        msg = ""
        if len(logging_config.get("handlers", {})) == 0:
            msg = "logging.config.dictConfig: "
            msg += "No file handlers found. "
            msg += "Add a file handler to the logging config file "
            msg += f"and try again: {self.config}"
            raise ValueError(msg)
        bad_handlers = []
        for handler_name, handler_config in logging_config.get("handlers", {}).items():
            handler_class = handler_config.get("class", "")
            if handler_class not in set(ValidLogHandlers):
                msg = "logging.config.dictConfig: "
                msg += "handlers found that may interrupt Ansible module "
                msg += "execution. "
                msg += "Remove these handlers from the logging config file "
                msg += "and try again. "
                bad_handlers.append(handler_name)
        if len(bad_handlers) > 0:
            msg += f"Handlers: {','.join(bad_handlers)}. "
            msg += f"Logging config file: {self.config}."
            raise ValueError(msg)

    def commit(self) -> None:
        """
        # Summary

        -   If `config` is None, disable logging.
        -   If `config` is a JSON file conformant with
            `logging.config.dictConfig` from Python's standard library, read the file and configure the
            base logger instance from the file's contents.

        ## Raises

        -   `ValueError` if:
                -   An error is encountered reading the logging config file.

        ## Notes

        1.  If self.config is None, then logging is disabled.
        2.  If self.config is a path to a JSON file, then the file is read
            and logging is configured from the file.

        ## Usage

        ```python
        log = Log()
        log.config = "/path/to/logging_config.json"
        log.commit()
        ```
        """
        if self.config is None:
            self.disable_logging()
        else:
            self.enable_logging()

    @property
    def config(self) -> Optional[str]:
        """
        ## Summary

        Path to a JSON file from which logging config is read.
        JSON file must conform to `logging.config.dictConfig` from Python's
        standard library.

        ## Default

        If the environment variable `ND_LOGGING_CONFIG` is set, then
        the value of that variable is used.  Otherwise, None.

        The environment variable can be overridden by directly setting
        `config` to one of the following prior to calling `commit()`:

        1.  None.  Logging will be disabled.
        2.  Path to a JSON file from which logging config is read.
            Must conform to `logging.config.dictConfig` from Python's
            standard library.
        """
        return self._config

    @config.setter
    def config(self, value: Optional[str]) -> None:
        self._config = value

    @property
    def develop(self) -> bool:
        """
        # Summary

        Disable or enable exceptions raised by the logging module.

        ## Default

        `False`

        ## Valid Values

        -   `True`:  Exceptions will be raised by the logging module.
        -   `False`: Exceptions will not be raised by the logging module.
        """
        return self._develop

    @develop.setter
    def develop(self, value: bool) -> None:
        method_name = "develop"
        if not isinstance(value, bool):
            msg = f"{self.class_name}.{method_name}: Expected boolean for develop. "
            msg += f"Got: type {type(value).__name__} for value {value}."
            raise TypeError(msg)
        self._develop = value
        logging.raiseExceptions = value


def setup_logging(module: "AnsibleModule", develop: bool = False) -> Log:
    """
    # Summary

    Configure nd collection logging and return the `Log` instance.

    Intended for use in each Ansible module's `main()` function after
    `AnsibleModule` is instantiated.

    ## Raises

    None

    ## Notes

    -   Calls `module.fail_json()` if logging configuration fails, which
        exits the module with an error message rather than raising an exception.

    ## Usage

    ```python
    from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging

    def main():
        module = AnsibleModule(...)
        log = setup_logging(module)
    ```

    To enable logging exceptions during development, pass `develop=True`:

    ```python
    log = setup_logging(module, develop=True)
    ```
    """
    try:
        log = Log(develop=develop)
        log.commit()
    except ValueError as error:
        module.fail_json(msg=str(error))
    return log
