#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: nd_log
version_added: "1.6.0"
short_description: Log messages from a playbook via the standard Python logging module.
description:
- Emit a log record under the C(nd) parent logger using the standard Python C(logging) module.
- Logging is configured by the C(ND_LOGGING_CONFIG) environment variable, which must point to a JSON file consumable by C(logging.config.dictConfig).
  When the variable is unset, the C(nd) logger is a no-op and the module exits successfully without writing anything.
- Useful for correlating playbook task execution with the C(nd.*) log records emitted internally by other modules in this collection.
options:
  msg:
    description:
    - The message to log.
    required: true
    type: str
  severity:
    description:
    - Case-sensitive logging severity (must be UPPERCASE) at which to log C(msg).
    - The record is only written if O(severity) is greater than or equal to both the level of the C(nd) logger and the level of every
      handler attached to it, as configured in the JSON file referenced by C(ND_LOGGING_CONFIG). If either level is more restrictive,
      the call is silently discarded and the module still reports C(changed=false, failed=false).
    - For example, setting O(severity=INFO) while the JSON config has C(loggers.nd.level) set to C(WARNING) will not write anything.
    required: false
    default: DEBUG
    choices: ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'WARNING']
    type: str
notes:
- The Python C(logging) module applies level checks at both the logger and the handler. A record is emitted only when its severity
  is greater than or equal to the most restrictive level along the chain (C(nd) logger, any ancestor loggers consulted for the
  effective level, and each handler). To make C(nd_log) messages visible, ensure both C(loggers.nd.level) (or the inherited level)
  and the relevant handler's C(level) in C(ND_LOGGING_CONFIG) are at or below O(severity).
author:
- Allen Robel (@quantumonion)
"""

EXAMPLES = r"""
# This module can be used to correlate Ansible task execution with the
# log records emitted by other cisco.nd modules when the ND_LOGGING_CONFIG
# environment variable is set to a valid Python logging configuration file.

- name: Log start of work
  cisco.nd.nd_log:
    msg: Starting Nexus Dashboard version query
    severity: INFO

- name: Query Nexus Dashboard version
  cisco.nd.nd_version:
    host: nd_host
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost
  register: query_result

- name: Log completion
  cisco.nd.nd_log:
    msg: Nexus Dashboard version query complete
    severity: INFO
"""

RETURN = r"""
"""

import logging

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.nd.plugins.module_utils.common.log import setup_logging


class NDLog:
    """
    # Summary

    Log a message via the standard Python `logging` module under the `nd` parent logger.

    The severity selects which `logging.Logger` method is called (`debug`, `info`, `warning`, `error`, or `critical`).

    ## Raises

    ### ValueError

    - If `msg` is not provided in `params`.
    """

    def __init__(self, params: dict) -> None:
        """
        # Summary

        Initialize the `NDLog` instance from an Ansible module's `params` dict.

        ## Raises

        ### ValueError

        - If `params["msg"]` is `None`.
        """
        self.class_name = self.__class__.__name__
        self.log = logging.getLogger(f"nd.{self.class_name}")

        self.params = params
        self.message = self.params.get("msg")
        self.severity = self.params.get("severity")

        if self.message is None:
            raise ValueError("Exiting. Missing mandatory parameter: msg")

        if self.severity is None:
            self.severity = "DEBUG"

        self.result: dict = {"changed": False, "failed": False}

    def msg(self) -> None:
        """
        # Summary

        Emit `self.message` at severity `self.severity` on the `nd.NDLog` logger.

        ## Raises

        None
        """
        if self.severity == "CRITICAL":
            self.log.critical(self.message)
        elif self.severity == "DEBUG":
            self.log.debug(self.message)
        elif self.severity == "ERROR":
            self.log.error(self.message)
        elif self.severity == "INFO":
            self.log.info(self.message)
        elif self.severity == "WARNING":
            self.log.warning(self.message)


def main() -> None:
    """
    # Summary

    Entry point for module execution.

    ## Raises

    None
    """
    argument_spec = {
        "msg": {"required": True, "type": "str"},
        "severity": {
            "required": False,
            "default": "DEBUG",
            "choices": ["CRITICAL", "DEBUG", "ERROR", "INFO", "WARNING"],
            "type": "str",
        },
    }

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    setup_logging(module)

    try:
        nd_log = NDLog(module.params)
        nd_log.msg()
    except ValueError as error:
        module.fail_json(msg=str(error))

    module.exit_json(**nd_log.result)


if __name__ == "__main__":
    main()
