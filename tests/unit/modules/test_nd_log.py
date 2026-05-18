# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@quantumonion) <arobel@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for plugins/modules/nd_log.py
"""

# pylint: disable=unused-import
# pylint: disable=redefined-outer-name
# pylint: disable=protected-access
# pylint: disable=unused-argument
# pylint: disable=unused-variable
# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=too-many-lines

from __future__ import annotations

import logging

import pytest
from ansible_collections.cisco.nd.plugins.modules.nd_log import NDLog
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def test_nd_log_00000() -> None:
    """
    # Summary

    Verify initialization defaults when only `msg` is provided.

    ## Test

    - `NDLog({"msg": "hello"})` does not raise.
    - `class_name` is `"NDLog"`.
    - `result["changed"]` is `False`.
    - `result["failed"]` is `False`.
    - `severity` defaults to `"DEBUG"` when omitted from params.
    - `message` round-trips through to the instance.

    ## Classes and Methods

    - NDLog.__init__()
    """
    with does_not_raise():
        instance = NDLog({"msg": "hello"})

    assert instance.class_name == "NDLog"
    assert instance.result["changed"] is False
    assert instance.result["failed"] is False
    assert instance.severity == "DEBUG"
    assert instance.message == "hello"


def test_nd_log_00010() -> None:
    """
    # Summary

    Verify `ValueError` when `msg` is missing.

    ## Test

    - `NDLog({"msg": None})` raises `ValueError` matching "Missing mandatory parameter: msg".

    ## Classes and Methods

    - NDLog.__init__()
    """
    match = r"Missing mandatory parameter: msg"
    with pytest.raises(ValueError, match=match):
        result = NDLog({"msg": None})  # pylint: disable=pointless-statement


def test_nd_log_00020() -> None:
    """
    # Summary

    Verify that omitting `msg` entirely (key absent) also raises `ValueError`.

    ## Test

    - `NDLog({})` raises `ValueError` matching "Missing mandatory parameter: msg".

    ## Classes and Methods

    - NDLog.__init__()
    """
    match = r"Missing mandatory parameter: msg"
    with pytest.raises(ValueError, match=match):
        result = NDLog({})  # pylint: disable=pointless-statement


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

    - `NDLog({"msg": <m>, "severity": <s>}).msg()` produces a log record at the matching level
      on logger `nd.NDLog` with the expected message body.

    ## Classes and Methods

    - NDLog.__init__()
    - NDLog.msg()
    """
    message = f"hello-{severity.lower()}"
    instance = NDLog({"msg": message, "severity": severity})

    with caplog.at_level(logging.DEBUG, logger="nd.NDLog"):
        instance.msg()

    matching = [r for r in caplog.records if r.name == "nd.NDLog" and r.message == message]
    assert len(matching) == 1
    assert matching[0].levelno == expected_level


def test_nd_log_00110(caplog: pytest.LogCaptureFixture) -> None:
    """
    # Summary

    Verify that explicit `severity="DEBUG"` and default severity behave identically.

    ## Test

    - Two `NDLog` instances — one with `severity` omitted, one with `severity="DEBUG"` — both
      emit a DEBUG-level record on logger `nd.NDLog` with the supplied message.

    ## Classes and Methods

    - NDLog.__init__()
    - NDLog.msg()
    """
    with caplog.at_level(logging.DEBUG, logger="nd.NDLog"):
        NDLog({"msg": "default-severity"}).msg()
        NDLog({"msg": "explicit-debug", "severity": "DEBUG"}).msg()

    debug_records = [r for r in caplog.records if r.name == "nd.NDLog" and r.levelno == logging.DEBUG]
    messages = {r.message for r in debug_records}
    assert {"default-severity", "explicit-debug"}.issubset(messages)
