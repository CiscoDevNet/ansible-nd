# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Allen Robel (@arobel) <arobel@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for plugins/module_utils/log.py
"""

# See the following regarding *_fixture imports
# https://pylint.pycqa.org/en/latest/user_guide/messages/warning/redefined-outer-name.html
# Due to the above, we also need to disable unused-import
# pylint: disable=unused-import
# Some fixtures need to use *args to match the signature of the function they are mocking
# pylint: disable=unused-argument
# Some tests require calling protected methods
# pylint: disable=protected-access
# pylint: disable=unused-variable
# pylint: disable=line-too-long
# pylint: disable=too-many-lines

from __future__ import absolute_import, annotations, division, print_function

# pylint: disable=invalid-name
__metaclass__ = type
# pylint: enable=invalid-name

import inspect
import json
import logging
from unittest.mock import MagicMock

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.log import Log, setup_logging
from ansible_collections.cisco.nd.tests.unit.module_utils.common_utils import does_not_raise


def logging_config(logging_config_file) -> dict:
    """
    ### Summary
    Return a logging configuration conformant with logging.config.dictConfig.
    """
    return {
        "version": 1,
        "formatters": {
            "standard": {
                "class": "logging.Formatter",
                "format": "%(asctime)s - %(levelname)s - [%(name)s.%(funcName)s.%(lineno)d] %(message)s",
            }
        },
        "handlers": {
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "standard",
                "level": "DEBUG",
                "filename": logging_config_file,
                "mode": "a",
                "encoding": "utf-8",
                "maxBytes": 500000,
                "backupCount": 4,
            }
        },
        "loggers": {"nd": {"handlers": ["file"], "level": "DEBUG", "propagate": False}},
        "root": {"level": "INFO", "handlers": ["file"]},
    }


def test_log_00000(monkeypatch) -> None:
    """
    # Summary

    Verify default state of `Log()` when `ND_LOGGING_CONFIG` is not set.

    ## Test

    - `ND_LOGGING_CONFIG` is not set.
    - `instance.config` is `None`.
    - `instance.develop` is `False`.
    - `logging.raiseExceptions` is `False`.

    ## Classes and Methods

    - `Log.__init__()`
    """
    monkeypatch.delenv("ND_LOGGING_CONFIG", raising=False)

    with does_not_raise():
        instance = Log()

    assert instance.config is None
    assert instance.develop is False
    assert logging.raiseExceptions is False


def test_log_00010(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify Log().commit() happy path. log.<level> logs to the logfile and the log message contains the calling method's name.

    ## Test

    - Log().commit() is called with a valid logging config.
    - log.info(), log.debug(), log.warning(), log.critical() all write to the logfile.
    - The log message contains the calling method's name.

    ## Classes and Methods

    - Log().commit()
    """
    method_name = inspect.stack()[0][3]
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()
        instance.commit()

    info_msg = "foo"
    debug_msg = "bing"
    warning_msg = "bar"
    critical_msg = "baz"
    log = logging.getLogger("nd.test_logger")
    log.info(info_msg)
    log.debug(debug_msg)
    log.warning(warning_msg)
    log.critical(critical_msg)
    assert logging.getLevelName(log.getEffectiveLevel()) == "DEBUG"
    assert info_msg in log_file.read_text(encoding="UTF-8")
    assert debug_msg in log_file.read_text(encoding="UTF-8")
    assert warning_msg in log_file.read_text(encoding="UTF-8")
    assert critical_msg in log_file.read_text(encoding="UTF-8")
    # test that the log message includes the method name
    assert method_name in log_file.read_text(encoding="UTF-8")


def test_log_00020(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `Log(config=...)` constructor parameter enables logging without setting `ND_LOGGING_CONFIG`.

    ## Test

    - `ND_LOGGING_CONFIG` is not set.
    - A valid config path is passed directly to `Log(config=...)`.
    - `commit()` succeeds and messages appear in the log file.

    ## Classes and Methods

    - `Log.__init__()`
    - `Log.commit()`
    """
    monkeypatch.delenv("ND_LOGGING_CONFIG", raising=False)
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    with does_not_raise():
        instance = Log(config=str(config_file))
        instance.commit()

    msg = "hello_from_test_log_00020"
    log = logging.getLogger("nd.test_log_00020")
    log.info(msg)
    assert msg in log_file.read_text(encoding="UTF-8")


def test_log_00030(monkeypatch) -> None:
    """
    # Summary

    Verify `Log(develop=True)` constructor parameter sets `develop` and `logging.raiseExceptions`.

    ## Test

    - `Log(develop=True)` is instantiated.
    - `instance.develop` is `True`.
    - `logging.raiseExceptions` is `True`.

    ## Classes and Methods

    - `Log.__init__()`
    """
    monkeypatch.delenv("ND_LOGGING_CONFIG", raising=False)

    with does_not_raise():
        instance = Log(develop=True)

    assert instance.develop is True
    assert logging.raiseExceptions is True


def test_log_00100(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify nothing is logged when ND_LOGGING_CONFIG is not set.

    ## Test

    - ND_LOGGING_CONFIG is not set.
    - Log().commit() succeeds.
    - No logfile is created.

    ## Classes and Methods

    - Log().commit()
    """
    monkeypatch.delenv("ND_LOGGING_CONFIG", raising=False)
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    with does_not_raise():
        instance = Log()
        instance.commit()

    info_msg = "foo"
    debug_msg = "bing"
    warning_msg = "bar"
    critical_msg = "baz"
    log = logging.getLogger("nd.test_logger")
    log.info(info_msg)
    log.debug(debug_msg)
    log.warning(warning_msg)
    log.critical(critical_msg)
    # test that nothing was logged (file was not created)
    with pytest.raises(FileNotFoundError):
        log_file.read_text(encoding="UTF-8")


@pytest.mark.parametrize("env_var", [(""), ("   ")])
def test_log_00110(tmp_path, monkeypatch, env_var) -> None:
    """
    # Summary

    Verify nothing is logged when ND_LOGGING_CONFIG is set to an empty string or whitespace.

    ## Test

    - ND_LOGGING_CONFIG is set to an empty string or whitespace.
    - Log().commit() succeeds.
    - No logfile is created.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", env_var)

    with does_not_raise():
        instance = Log()
        instance.commit()

    info_msg = "foo"
    debug_msg = "bing"
    warning_msg = "bar"
    critical_msg = "baz"
    log = logging.getLogger("nd.test_logger")
    log.info(info_msg)
    log.debug(debug_msg)
    log.warning(warning_msg)
    log.critical(critical_msg)
    # test that nothing was logged (file was not created)
    with pytest.raises(FileNotFoundError):
        log_file.read_text(encoding="UTF-8")


def test_log_00120(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify nothing is logged when Log().config is set to None, overriding ND_LOGGING_CONFIG.

    ## Test Setup

    - ND_LOGGING_CONFIG is set to a file that exists, which would normally enable logging.
    - Log().config is set to None, which overrides ND_LOGGING_CONFIG.

    ## Test

    - Nothing is logged because Log().config overrides ND_LOGGING_CONFIG.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()
        instance.config = None
        instance.commit()

    info_msg = "foo"
    debug_msg = "bing"
    warning_msg = "bar"
    critical_msg = "baz"
    log = logging.getLogger("nd.test_logger")
    log.info(info_msg)
    log.debug(debug_msg)
    log.warning(warning_msg)
    log.critical(critical_msg)
    # test that nothing was logged (file was not created)
    with pytest.raises(FileNotFoundError):
        log_file.read_text(encoding="UTF-8")


def test_log_00130(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `instance.config` set to a file path overrides `ND_LOGGING_CONFIG`, logging to the new file.

    ## Test Setup

    - `ND_LOGGING_CONFIG` points to config A (log file A).
    - `instance.config` is set to config B (log file B) after instantiation.

    ## Test

    - Messages appear in log file B, not log file A.

    ## Classes and Methods

    - `Log.config` (setter)
    - `Log.commit()`
    """
    log_dir_a = tmp_path / "log_dir_a"
    log_dir_a.mkdir()
    config_file_a = log_dir_a / "logging_config_a.json"
    log_file_a = log_dir_a / "nd_a.log"
    config_a = logging_config(str(log_file_a))
    with open(config_file_a, "w", encoding="UTF-8") as fp:
        json.dump(config_a, fp)

    log_dir_b = tmp_path / "log_dir_b"
    log_dir_b.mkdir()
    config_file_b = log_dir_b / "logging_config_b.json"
    log_file_b = log_dir_b / "nd_b.log"
    config_b = logging_config(str(log_file_b))
    with open(config_file_b, "w", encoding="UTF-8") as fp:
        json.dump(config_b, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file_a))

    with does_not_raise():
        instance = Log()
        instance.config = str(config_file_b)
        instance.commit()

    msg = "hello_from_test_log_00130"
    log = logging.getLogger("nd.test_log_00130")
    log.info(msg)
    assert msg in log_file_b.read_text(encoding="UTF-8")
    assert not log_file_a.exists()


def test_log_00200(monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised if logging config file does not exist.

    ## Classes and Methods

    - Log().commit()
    """
    config_file = "DOES_NOT_EXIST.json"
    monkeypatch.setenv("ND_LOGGING_CONFIG", config_file)

    with does_not_raise():
        instance = Log()

    match = rf"error reading logging config from {config_file}\.\s+"
    match += r"Error detail:\s+\[Errno 2\]\s+No such file or directory:\s+"
    match += rf"\'{config_file}\'"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00210(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised if logging config file contains invalid JSON.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump({"BAD": "JSON"}, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()

    match = r"logging.config.dictConfig:\s+"
    match += r"No file handlers found\.\s+"
    match += r"Add a file handler to the logging config file\s+"
    match += rf"and try again: {config_file}"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00220(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised if logging config file does not contain JSON.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    with open(config_file, "w", encoding="UTF-8") as fp:
        fp.write("NOT JSON")

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()

    match = rf"error parsing logging config from {config_file}\.\s+"
    match += r"Error detail: Expecting value: line 1 column 1 \(char 0\)"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00230(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised if logging config file contains handler(s) that emit to non-file destinations.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    config["handlers"]["console"] = {
        "class": "logging.StreamHandler",
        "formatter": "standard",
        "level": "DEBUG",
        "stream": "ext://sys.stdout",
    }
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()

    match = r"logging.config.dictConfig:\s+"
    match += r"handlers found that may interrupt Ansible module\s+"
    match += r"execution\.\s+"
    match += r"Remove these handlers from the logging config file and\s+"
    match += r"try again\.\s+"
    match += r"Handlers:\s+.*\.\s+"
    match += r"Logging config file:\s+.*\."
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00231(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify no `ValueError` is raised when a handler uses a non-standard name but a valid handler class (e.g. `logging.handlers.RotatingFileHandler`).

    ## Test

    - Previously, validation checked the handler key name rather than the class, so `"my_file_handler"` would have been incorrectly rejected.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    # Rename the handler key from "file" to a non-standard name.
    config["handlers"]["my_file_handler"] = config["handlers"].pop("file")
    config["loggers"]["nd"]["handlers"] = ["my_file_handler"]
    config["root"]["handlers"] = ["my_file_handler"]
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()
        instance.commit()


def test_log_00232(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised when a handler is named `"file"` but its `class` property is `logging.StreamHandler`.

    ## Test

    - Previously, validation checked the handler key name rather than the class, so a `StreamHandler` named `"file"` would have been incorrectly accepted.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    # Keep the key name "file" but switch to a disallowed handler class.
    config["handlers"]["file"]["class"] = "logging.StreamHandler"
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()

    match = r"logging.config.dictConfig:\s+"
    match += r"handlers found that may interrupt Ansible module\s+"
    match += r"execution\.\s+"
    match += r"Remove these handlers from the logging config file and\s+"
    match += r"try again\.\s+"
    match += r"Handlers:\s+.*\.\s+"
    match += r"Logging config file:\s+.*\."
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00233(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `commit()` does not raise when the handler class is `logging.FileHandler`.

    ## Test

    - Config uses `logging.FileHandler` (a valid handler class per `ValidLogHandlers`).
    - `commit()` succeeds without raising.

    ## Classes and Methods

    - `Log.commit()`
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    config["handlers"]["file"]["class"] = "logging.FileHandler"
    del config["handlers"]["file"]["maxBytes"]
    del config["handlers"]["file"]["backupCount"]
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()
        instance.commit()


def test_log_00234(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `commit()` does not raise when the handler class is `logging.handlers.TimedRotatingFileHandler`.

    ## Test

    - Config uses `logging.handlers.TimedRotatingFileHandler` (a valid handler class per `ValidLogHandlers`).
    - `commit()` succeeds without raising.

    ## Classes and Methods

    - `Log.commit()`
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    config["handlers"]["file"]["class"] = "logging.handlers.TimedRotatingFileHandler"
    config["handlers"]["file"]["when"] = "midnight"
    del config["handlers"]["file"]["maxBytes"]
    del config["handlers"]["file"]["mode"]
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()
        instance.commit()


def test_log_00235(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `commit()` does not raise when the handler class is `logging.handlers.WatchedFileHandler`.

    ## Test

    - Config uses `logging.handlers.WatchedFileHandler` (a valid handler class per `ValidLogHandlers`).
    - `commit()` succeeds without raising.

    ## Classes and Methods

    - `Log.commit()`
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    config["handlers"]["file"]["class"] = "logging.handlers.WatchedFileHandler"
    del config["handlers"]["file"]["maxBytes"]
    del config["handlers"]["file"]["backupCount"]
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()
        instance.commit()


def test_log_00240(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised if logging config file does not contain any handlers.

    ## Notes

    - `test_log_00210` raises the same error message in the case where the logging config file contains JSON that is not conformant with dictConfig.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    del config["handlers"]
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()

    match = r"logging.config.dictConfig:\s+"
    match += r"No file handlers found\.\s+"
    match += r"Add a file handler to the logging config file\s+"
    match += rf"and try again: {config_file}"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00250(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `ValueError` is raised if logging config file does not contain any formatters or contains formatters that are not associated with handlers.

    ## Classes and Methods

    - Log().commit()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    del config["formatters"]
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    with does_not_raise():
        instance = Log()

    match = r"logging.config.dictConfig:\s+"
    match += r"Unable to configure logging from\s+.*\.\s+"
    match += r"Error detail: Unable to configure handler.*"
    with pytest.raises(ValueError, match=match):
        instance.commit()


def test_log_00300() -> None:
    """
    # Summary

    Verify `TypeError` is raised if develop is set to a non-bool.

    ## Classes and Methods

    - Log().develop (setter)
    """
    with does_not_raise():
        instance = Log()

    match = r"Log\.develop:\s+"
    match += r"Expected boolean for develop\.\s+"
    match += r"Got: type str for value FOO\."
    with pytest.raises(TypeError, match=match):
        instance.develop = "FOO"  # type: ignore[assignment]


@pytest.mark.parametrize("develop", [(True), (False)])
def test_log_00310(develop) -> None:
    """
    # Summary

    Verify develop is set correctly if passed a bool and no exceptions are raised.

    ## Classes and Methods

    - Log().develop (setter)
    """
    with does_not_raise():
        instance = Log()
        instance.develop = develop
    assert instance.develop == develop


@pytest.mark.parametrize("develop", [(True), (False)])
def test_log_00320(develop) -> None:
    """
    # Summary

    Verify `Log.develop` setter side effect: `logging.raiseExceptions` is updated to match `develop`.

    ## Test

    - `instance.develop` is set to `develop`.
    - `instance.develop == develop`.
    - `logging.raiseExceptions == develop`.

    ## Classes and Methods

    - `Log.develop` (setter)
    """
    with does_not_raise():
        instance = Log()
        instance.develop = develop
    assert instance.develop == develop
    assert logging.raiseExceptions == develop


def test_setup_logging_00010(tmp_path, monkeypatch) -> None:
    """
    # Summary

    Verify `setup_logging()` returns a `Log` instance when the config is valid.

    ## Test

    - `ND_LOGGING_CONFIG` points to a valid logging config file.
    - `setup_logging()` returns a `Log` instance.
    - `module.fail_json()` is not called.

    ## Classes and Methods

    - setup_logging()
    """
    log_dir = tmp_path / "log_dir"
    log_dir.mkdir()
    config_file = log_dir / "logging_config.json"
    log_file = log_dir / "nd.log"
    config = logging_config(str(log_file))
    with open(config_file, "w", encoding="UTF-8") as fp:
        json.dump(config, fp)

    monkeypatch.setenv("ND_LOGGING_CONFIG", str(config_file))

    mock_module = MagicMock()

    with does_not_raise():
        result = setup_logging(mock_module)

    assert isinstance(result, Log)
    mock_module.fail_json.assert_not_called()


def test_setup_logging_00020(monkeypatch) -> None:
    """
    # Summary

    Verify `setup_logging()` calls `module.fail_json()` when the config file does not exist.

    ## Test

    - `ND_LOGGING_CONFIG` points to a nonexistent file.
    - `setup_logging()` calls `module.fail_json()` with an error message describing the failure.

    ## Classes and Methods

    - setup_logging()
    """
    config_file = "DOES_NOT_EXIST.json"
    monkeypatch.setenv("ND_LOGGING_CONFIG", config_file)

    mock_module = MagicMock()
    mock_module.fail_json.side_effect = SystemExit

    with pytest.raises(SystemExit):
        setup_logging(mock_module)

    mock_module.fail_json.assert_called_once()
    call_kwargs = mock_module.fail_json.call_args.kwargs
    assert "error reading logging config" in call_kwargs["msg"]


def test_setup_logging_00030(monkeypatch) -> None:
    """
    # Summary

    Verify `setup_logging()` returns a `Log` instance with logging disabled when `ND_LOGGING_CONFIG` is not set.

    ## Test

    - `ND_LOGGING_CONFIG` is not set.
    - `setup_logging()` returns a `Log` instance.
    - `module.fail_json()` is not called.

    ## Classes and Methods

    - `setup_logging()`
    """
    monkeypatch.delenv("ND_LOGGING_CONFIG", raising=False)

    mock_module = MagicMock()

    with does_not_raise():
        result = setup_logging(mock_module)

    assert isinstance(result, Log)
    mock_module.fail_json.assert_not_called()
