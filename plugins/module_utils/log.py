# -*- coding: utf-8 -*-

# Copyright: (c) 2025, Gaspard Micol (@gmicol) <gmicol@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import inspect
import json
import logging
from logging.config import dictConfig
from os import environ


class Log:

    def __init__(self):
        self.class_name = self.__class__.__name__
        logging.raiseExceptions = False

        self.valid_handlers = set()
        self.valid_handlers.add("file")

        self._build_properties()

    def _build_properties(self) -> None:
        self.properties = {}
        self.properties["config"] = environ.get("ND_LOGGING_CONFIG", None)
        self.properties["develop"] = False

    def disable_logging(self):
        logger = logging.getLogger()
        for handler in logger.handlers.copy():
            try:
                logger.removeHandler(handler)
            except ValueError:
                pass
        logger.addHandler(logging.NullHandler())
        logger.propagate = False

    def enable_logging(self):
        if str(self.config).strip() == "":
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
            self.validate_logging_config(logging_config)
        except ValueError as error:
            raise ValueError(str(error)) from error

        try:
            dictConfig(logging_config)
        except (RuntimeError, TypeError, ValueError) as error:
            msg = "logging.config.dictConfig: "
            msg += f"Unable to configure logging from {self.config}. "
            msg += f"Error detail: {error}"
            raise ValueError(msg) from error

    def validate_logging_config(self, logging_config: dict) -> None:
        if len(logging_config.get("handlers", {})) == 0:
            msg = "logging.config.dictConfig: "
            msg += "No file handlers found. "
            msg += "Add a file handler to the logging config file "
            msg += f"and try again: {self.config}"
            raise ValueError(msg)
        bad_handlers = []
        for handler in logging_config.get("handlers", {}):
            if handler not in self.valid_handlers:
                msg = "logging.config.dictConfig: "
                msg += "handlers found that may interrupt Ansible module "
                msg += "execution. "
                msg += "Remove these handlers from the logging config file "
                msg += "and try again. "
                bad_handlers.append(handler)
        if len(bad_handlers) > 0:
            msg += f"Handlers: {','.join(bad_handlers)}. "
            msg += f"Logging config file: {self.config}."
            raise ValueError(msg)

    def commit(self):
        if self.config is None:
            self.disable_logging()
        else:
            self.enable_logging()

    @property
    def config(self):
        return self.properties["config"]

    @config.setter
    def config(self, value):
        self.properties["config"] = value

    @property
    def develop(self):
        return self.properties["develop"]

    @develop.setter
    def develop(self, value):
        method_name = inspect.stack()[0][3]
        if not isinstance(value, bool):
            msg = f"{self.class_name}.{method_name}: Expected boolean for develop. "
            msg += f"Got: type {type(value).__name__} for value {value}."
            raise TypeError(msg)
        self.properties["develop"] = value
        logging.raiseExceptions = value
