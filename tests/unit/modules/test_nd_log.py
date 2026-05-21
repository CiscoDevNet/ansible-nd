# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@allenrobel) <arobel@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for plugins/modules/nd_log.py
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long

from __future__ import annotations

import logging

import pytest
from ansible_collections.cisco.nd.plugins.modules.nd_log import log_message


@pytest.mark.parametrize(
    "severity, expected_level",
    [
        ("CRITICAL", logging.CRITICAL),
        ("DEBUG", logging.DEBUG),
        ("ERROR", logging.ERROR),
        ("INFO", logging.INFO),
        ("WARNING", logging.WARNING),
    ],
    ids=["CRITICAL", "DEBUG", "ERROR", "INFO", "WARNING"],
)
def test_nd_log_00100(caplog: pytest.LogCaptureFixture, severity: str, expected_level: int) -> None:
    """
    # Summary

    Verify each severity dispatches to the corresponding `logging.Logger` level.

    ## Test

    - `log_message(<severity>, <msg>)` produces a single log record at the matching level
      on logger `nd.nd_log` with the expected message body.

    ## Classes and Methods

    - log_message()
    """
    message = f"hello-{severity.lower()}"

    with caplog.at_level(logging.DEBUG, logger="nd.nd_log"):
        log_message(severity, message)

    matching = [r for r in caplog.records if r.name == "nd.nd_log" and r.message == message]
    assert len(matching) == 1
    assert matching[0].levelno == expected_level
