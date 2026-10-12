# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for `fail_from_exception`, the shared `main()` failure handler (issue #556).

Every `NDStateMachine`-based module used to carry its own copy of the `except NDStateMachineError` / `except Exception` block.
These tests pin the single standard shape the helper produces: tiered log line and message prefix, module output merged into
`fail_json`, a formatting failure that cannot mask the original error, the debug traceback, and the interface finalizer note.
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-few-public-methods
# pylint: disable=unused-argument
# pylint: disable=use-implicit-booleaness-not-comparison

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.module_failure import fail_from_exception
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

ACCEPTED_PAIR = ("Ethernet1/1", "FDO12345ABC")
ACCEPTED_NOTE = (
    " NOTE: before the failure, the controller had already accepted changes for interface(s) "
    "[Ethernet1/1 (switchId FDO12345ABC)]; those changes were deployed."
)


class _FailJson(Exception):
    """
    # Summary

    Raised by the `AnsibleModule` stand-in's `fail_json` so the test can capture the failure keyword arguments.

    ## Raises

    None
    """


class _FakeAnsibleModule:
    """
    # Summary

    Minimal `AnsibleModule` stand-in: carries `params` and `check_mode`, and turns `fail_json` into an exception.

    ## Raises

    None
    """

    def __init__(self, *, output_level: str = "normal", check_mode: bool = False) -> None:
        self.params: dict[str, Any] = {"output_level": output_level}
        self.check_mode = check_mode
        self.fail_json_calls = 0

    def fail_json(self, **kwargs: Any) -> None:
        """
        # Summary

        Capture the failure keyword arguments.

        ## Raises

        ### _FailJson

        - Always, carrying `kwargs`
        """
        self.fail_json_calls += 1
        raise _FailJson(kwargs)


class _RecordingOrchestrator(NDBaseInterfaceOrchestrator):
    """
    # Summary

    Concrete `NDBaseInterfaceOrchestrator` whose `_deploy_interfaces` records the deployed pairs instead of calling the controller.

    ## Raises

    None
    """

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet

    def model_post_init(self, __context) -> None:
        super().model_post_init(__context)
        self._deployed: list[list[tuple[str, str]]] = []  # pylint: disable=attribute-defined-outside-init

    def _deploy_interfaces(self, pairs: list[tuple[str, str]]) -> dict[str, Any]:
        """
        # Summary

        Record `pairs` instead of sending `interfaceActions/deploy`.

        ## Raises

        None
        """
        self._deployed.append(list(pairs))
        return {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}


def _state_machine(output: dict[str, Any] | None = None, *, format_failure: Exception | None = None, orchestrator: Any = None) -> SimpleNamespace:
    """
    # Summary

    Build an `NDStateMachine` stand-in whose `output.format()` returns `output`, or raises `format_failure` when set.

    ## Raises

    None
    """

    def _format() -> dict[str, Any]:
        if format_failure is not None:
            raise format_failure
        return dict(output or {})

    return SimpleNamespace(output=SimpleNamespace(format=_format), model_orchestrator=orchestrator)


def _fail(module: _FakeAnsibleModule, nd_state_machine: Any, error: BaseException, module_log: logging.Logger) -> dict[str, Any]:
    """
    # Summary

    Raise `error`, call `fail_from_exception` from inside the `except` clause (the contract every module `main()` follows), and
    return the captured `fail_json` kwargs.

    ## Raises

    ### AssertionError

    - If `fail_json` was not called exactly once
    """
    with pytest.raises(_FailJson) as exc_info:
        try:
            raise error
        except Exception as caught:  # pylint: disable=broad-except
            fail_from_exception(module, module_log, nd_state_machine, caught)
    assert module.fail_json_calls == 1
    return exc_info.value.args[0]


def test_module_failure_00000(caplog: pytest.LogCaptureFixture) -> None:
    """
    # Summary

    Verify an `NDStateMachineError` is reported as a controller- or validation-reported failure.

    ## Test

    - `fail_from_exception` is called with an `NDStateMachineError`
    - `fail_json` receives `Module execution failed: <error>`
    - The log carries `NDStateMachineError during module execution` at ERROR level with the exception attached

    ## Classes and Methods

    - fail_from_exception()
    """
    module_log = logging.getLogger("nd.test_module_failure_00000")
    caplog.set_level(logging.DEBUG, logger=module_log.name)

    kwargs = _fail(_FakeAnsibleModule(), _state_machine(), NDStateMachineError("controller said no"), module_log)

    assert kwargs == {"msg": "Module execution failed: controller said no"}
    records = [record for record in caplog.records if record.name == module_log.name]
    assert [record.getMessage() for record in records] == ["NDStateMachineError during module execution"]
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None


def test_module_failure_00010(caplog: pytest.LogCaptureFixture) -> None:
    """
    # Summary

    Verify any other exception is reported as an unhandled failure (the maintainer's grep for a bug in our code).

    ## Test

    - `fail_from_exception` is called with a `RuntimeError`
    - `fail_json` receives `Module failed: <error>`
    - The log carries `Unhandled exception during module execution` at ERROR level with the exception attached

    ## Classes and Methods

    - fail_from_exception()
    """
    module_log = logging.getLogger("nd.test_module_failure_00010")
    caplog.set_level(logging.DEBUG, logger=module_log.name)

    kwargs = _fail(_FakeAnsibleModule(), _state_machine(), RuntimeError("unexpected"), module_log)

    assert kwargs == {"msg": "Module failed: unexpected"}
    records = [record for record in caplog.records if record.name == module_log.name]
    assert [record.getMessage() for record in records] == ["Unhandled exception during module execution"]
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None


def test_module_failure_00020() -> None:
    """
    # Summary

    Verify the state machine's formatted output is merged into the `fail_json` call.

    ## Test

    - The state machine's `output.format()` returns `changed`, `before`, and `after`
    - `fail_json` receives those keys alongside `msg`

    ## Classes and Methods

    - fail_from_exception()
    """
    output = {"changed": True, "before": [{"name": "Ethernet1/1"}], "after": []}

    kwargs = _fail(_FakeAnsibleModule(), _state_machine(output), NDStateMachineError("later operation failed"), logging.getLogger("nd.test"))

    assert kwargs == {"msg": "Module execution failed: later operation failed", **output}


def test_module_failure_00030() -> None:
    """
    # Summary

    Verify a failure that precedes state machine construction reports only the message.

    ## Test

    - `nd_state_machine` is `None`
    - `fail_json` receives only `msg`

    ## Classes and Methods

    - fail_from_exception()
    """
    kwargs = _fail(_FakeAnsibleModule(), None, NDStateMachineError("bad config"), logging.getLogger("nd.test"))

    assert kwargs == {"msg": "Module execution failed: bad config"}


def test_module_failure_00040(caplog: pytest.LogCaptureFixture) -> None:
    """
    # Summary

    Verify a failure inside `output.format()` cannot mask the original error.

    ## Test

    - The state machine's `output.format()` raises
    - `fail_json` still receives the original error message, with no output keys
    - The formatting failure is logged with its exception attached

    ## Classes and Methods

    - fail_from_exception()
    """
    module_log = logging.getLogger("nd.test_module_failure_00040")
    caplog.set_level(logging.DEBUG, logger=module_log.name)

    kwargs = _fail(_FakeAnsibleModule(), _state_machine(format_failure=KeyError("diff")), NDStateMachineError("original"), module_log)

    assert kwargs == {"msg": "Module execution failed: original"}
    records = [record for record in caplog.records if record.name == module_log.name]
    assert [record.getMessage() for record in records] == [
        "NDStateMachineError during module execution",
        "Formatting module output for the failure result failed; reporting the original error without it",
    ]
    assert records[1].exc_info is not None


def test_module_failure_00050() -> None:
    """
    # Summary

    Verify the traceback is appended to the message only when `output_level` is `debug`.

    ## Test

    - With `output_level: debug`, `msg` ends with a `Traceback:` section naming the raised error
    - With `output_level: normal`, `msg` carries no traceback

    ## Classes and Methods

    - fail_from_exception()
    """
    debug = _fail(_FakeAnsibleModule(output_level="debug"), _state_machine(), RuntimeError("boom"), logging.getLogger("nd.test"))
    normal = _fail(_FakeAnsibleModule(output_level="normal"), _state_machine(), RuntimeError("boom"), logging.getLogger("nd.test"))

    assert debug["msg"].startswith("Module failed: boom\nTraceback:\n")
    assert "RuntimeError: boom" in debug["msg"]
    assert normal["msg"] == "Module failed: boom"


def test_module_failure_00060() -> None:
    """
    # Summary

    Verify controller-accepted interface mutations are deployed and named in the message when the orchestrator is an
    `NDBaseInterfaceOrchestrator`.

    ## Test

    - The state machine's orchestrator is an interface orchestrator with `deploy` enabled and one accepted pair queued
    - `fail_json` receives the original error followed by the accepted-interface NOTE
    - The orchestrator deployed exactly the accepted pair, once

    ## Classes and Methods

    - fail_from_exception()
    - finalize_accepted_intent()
    """
    orchestrator = _RecordingOrchestrator(rest_send=RestSend({"check_mode": False, "fabric_name": "fabric_1"}))
    orchestrator.deploy = True
    orchestrator._queue_deploy(*ACCEPTED_PAIR)

    kwargs = _fail(
        _FakeAnsibleModule(), _state_machine(orchestrator=orchestrator), NDStateMachineError("later operation failed"), logging.getLogger("nd.test")
    )

    assert kwargs == {"msg": f"Module execution failed: later operation failed{ACCEPTED_NOTE}"}
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]
    assert orchestrator._pending_deploys == []


def test_module_failure_00070() -> None:
    """
    # Summary

    Verify the finalizer is skipped in check mode: nothing is deployed and the message carries no NOTE.

    ## Test

    - `check_mode` is true, `deploy` is enabled, and one accepted pair is queued on an interface orchestrator
    - `fail_json` receives only the original error
    - No deploy was issued and the pair remains queued

    ## Classes and Methods

    - fail_from_exception()
    - finalize_accepted_intent()
    """
    orchestrator = _RecordingOrchestrator(rest_send=RestSend({"check_mode": True, "fabric_name": "fabric_1"}))
    orchestrator.deploy = True
    orchestrator._queue_deploy(*ACCEPTED_PAIR)

    kwargs = _fail(_FakeAnsibleModule(check_mode=True), _state_machine(orchestrator=orchestrator), RuntimeError("unexpected"), logging.getLogger("nd.test"))

    assert kwargs == {"msg": "Module failed: unexpected"}
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]
