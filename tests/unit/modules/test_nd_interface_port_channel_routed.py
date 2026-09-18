# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `nd_interface_port_channel_routed` module wrapper (`main()`; issue #549).

Covers the argument spec the module assembles, the `config_actions.deploy` contract (opt-in deploy: omitted / explicit true / check
mode), the delete-side flush ordering (`remove_pending` before `deploy_pending`), and the failure-path finalizer
(`finalize_accepted_intent`) for both exception kinds. `main()` is driven with stand-ins for `AnsibleModule` and `NDStateMachine`;
live ND interaction is exercised by the integration target.
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-few-public-methods
# pylint: disable=unused-argument

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.port_channel_routed_interface import PortChannelRoutedInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.modules import nd_interface_port_channel_routed as module

ACCEPTED_PAIR = ("port-channel20", "FDO11111AAA")
ACCEPTED_NOTE = (
    " NOTE: before the failure, the controller had already accepted changes for interface(s) "
    "[port-channel20 (switchId FDO11111AAA)]; those changes were deployed."
)

# Sentinel meaning "the user did not supply config_actions at all" (Ansible passes None for an unset dict option).
OMITTED = object()


class _FailJson(Exception):
    """
    # Summary

    Raised by the `AnsibleModule` stand-in's `fail_json` so the test can capture the failure keyword arguments.

    ## Raises

    None
    """


class _ExitJson(BaseException):
    """
    # Summary

    Raised by the `AnsibleModule` stand-in's `exit_json` so the test can capture the success keyword arguments. Derives from
    `BaseException` (like the `SystemExit` the real `exit_json` raises) so the module's broad `except Exception` handler does not
    turn a successful exit into a failure.

    ## Raises

    None
    """


class _FakeAnsibleModule:
    """
    # Summary

    Minimal `AnsibleModule` stand-in for driving `main()`: records the `argument_spec` it was built with, carries `params` and
    `check_mode`, and turns `fail_json` / `exit_json` into exceptions.

    ## Raises

    None
    """

    last_argument_spec: dict[str, Any] = {}

    def __init__(self, *, config_actions: Any, check_mode: bool, argument_spec: dict[str, Any], **kwargs: Any) -> None:
        type(self).last_argument_spec = argument_spec
        self.supports_check_mode = kwargs.get("supports_check_mode")
        self.params: dict[str, Any] = {
            "config": [],
            "state": "merged",
            "config_actions": None if config_actions is OMITTED else config_actions,
            "output_level": "normal",
        }
        self.check_mode = check_mode

    def fail_json(self, **kwargs: Any) -> None:
        """
        # Summary

        Capture the failure keyword arguments.

        ## Raises

        ### _FailJson

        - Always, carrying `kwargs`
        """
        raise _FailJson(kwargs)

    def exit_json(self, **kwargs: Any) -> None:
        """
        # Summary

        Capture the success keyword arguments.

        ## Raises

        ### _ExitJson

        - Always, carrying `kwargs`
        """
        raise _ExitJson(kwargs)


class _RecordingOrchestrator(PortChannelRoutedInterfaceOrchestrator):
    """
    # Summary

    The real routed port-channel orchestrator with its two controller-facing flush requests replaced by recorders, so the test
    observes which pairs the module removed and deployed, and in which order, without a controller.

    ## Raises

    None
    """

    def model_post_init(self, __context) -> None:
        super().model_post_init(__context)
        self._calls: list[tuple[str, list[tuple[str, str]]]] = []  # pylint: disable=attribute-defined-outside-init

    def _remove_interfaces(self) -> dict[str, Any]:
        """
        # Summary

        Record the queued removes instead of sending `interfaceActions/remove`, reporting every item accepted.

        ## Raises

        None
        """
        self._calls.append(("remove", list(self._pending_removes)))
        return {"results": [{"interfaceName": name, "switchId": switch_id, "status": "success"} for name, switch_id in self._pending_removes]}

    def _deploy_interfaces(self, pairs: list[tuple[str, str]]) -> dict[str, Any]:
        """
        # Summary

        Record `pairs` instead of sending `interfaceActions/deploy`.

        ## Raises

        None
        """
        self._calls.append(("deploy", list(pairs)))
        return {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}


class _FakeStateMachine:
    """
    # Summary

    `NDStateMachine` stand-in: records the orchestrator class the module asked for, builds a `_RecordingOrchestrator` with one
    controller-accepted pair queued for deploy, then either returns from `manage_state` or raises the configured exception.

    ## Raises

    None
    """

    failure: Exception | None = None
    last_instance: _FakeStateMachine | None = None

    def __init__(self, module: Any, model_orchestrator: Any) -> None:
        self.requested_orchestrator = model_orchestrator
        self.model_orchestrator = _RecordingOrchestrator(rest_send=RestSend({"check_mode": False, "fabric_name": "fabric_1"}))
        self.model_orchestrator._queue_deploy(*ACCEPTED_PAIR)
        self.output = SimpleNamespace(format=lambda: {})
        type(self).last_instance = self

    def manage_state(self) -> None:
        """
        # Summary

        Raise the configured failure (if any) after the accepted pair has been queued.

        ## Raises

        ### Exception

        - The class-level `failure`, when set
        """
        if self.failure is not None:
            raise self.failure


def _run_main(
    monkeypatch: pytest.MonkeyPatch, *, config_actions: Any = OMITTED, check_mode: bool = False, failure: Exception | None = None
) -> tuple[type[BaseException], dict[str, Any], _FakeStateMachine]:
    """
    # Summary

    Drive `main()` with the stand-ins and return the exit kind (`_ExitJson` or `_FailJson`), its keyword arguments, and the state
    machine stand-in the module built.

    ## Raises

    ### AssertionError

    - If `main()` neither exited nor failed through the stand-in
    """

    class _StateMachine(_FakeStateMachine):
        pass

    _StateMachine.failure = failure
    monkeypatch.setattr(module, "AnsibleModule", lambda **kwargs: _FakeAnsibleModule(config_actions=config_actions, check_mode=check_mode, **kwargs))
    monkeypatch.setattr(module, "NDStateMachine", _StateMachine)
    monkeypatch.setattr(module, "require_pydantic", lambda module: None)
    monkeypatch.setattr(module, "setup_logging", lambda module: None)

    with pytest.raises((_ExitJson, _FailJson)) as exc_info:
        module.main()
    assert _StateMachine.last_instance is not None
    return type(exc_info.value), exc_info.value.args[0], _StateMachine.last_instance


# =============================================================================
# Test: wiring
# =============================================================================


def test_nd_interface_port_channel_routed_00000(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify `main()` wires the routed orchestrator and assembles the argument spec from the connection options, the routed model and
    the deploy-only `config_actions` contract.

    ## Test

    - `NDStateMachine` is built with `PortChannelRoutedInterfaceOrchestrator`
    - The argument spec carries `fabric_name`, `config`, `state`, and a `config_actions` whose only action is `deploy`
    - `network_os_type` is a required option

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    """
    _kind, _kwargs, state_machine = _run_main(monkeypatch)

    assert state_machine.requested_orchestrator is PortChannelRoutedInterfaceOrchestrator
    spec = _FakeAnsibleModule.last_argument_spec
    assert {"fabric_name", "config", "state", "config_actions"} <= set(spec)
    assert set(spec["config_actions"]["options"]) == {"deploy"}
    network_os = spec["config"]["options"]["config_data"]["options"]["network_os"]["options"]
    assert network_os["network_os_type"]["required"] is True


# =============================================================================
# Test: config_actions.deploy contract (opt-in)
# =============================================================================


def test_nd_interface_port_channel_routed_00010(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify deploy is opt-in: with `config_actions` omitted, the queued mutation is staged and no deploy is issued.

    ## Test

    - `main()` exits successfully; the orchestrator's `deploy` flag is False
    - No `interfaceActions/deploy` call was made; the accepted pair remains queued

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    """
    kind, kwargs, state_machine = _run_main(monkeypatch)
    orchestrator = state_machine.model_orchestrator

    assert kind is _ExitJson
    assert kwargs == {}
    assert orchestrator.deploy is False
    assert orchestrator._calls == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]


def test_nd_interface_port_channel_routed_00020(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify an explicit `config_actions.deploy: true` deploys the queued mutation once at the end of the run.

    ## Test

    - `main()` exits successfully; exactly one deploy call carrying the accepted pair was made; the queue is drained

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    - NDBaseInterfaceOrchestrator.deploy_pending()
    """
    kind, _kwargs, state_machine = _run_main(monkeypatch, config_actions={"deploy": True})
    orchestrator = state_machine.model_orchestrator

    assert kind is _ExitJson
    assert orchestrator.deploy is True
    assert orchestrator._calls == [("deploy", [ACCEPTED_PAIR])]
    assert orchestrator._pending_deploys == []


def test_nd_interface_port_channel_routed_00030(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify check mode never flushes, even with `config_actions.deploy: true`: the post-`manage_state` remove and deploy are skipped.

    ## Test

    - Check mode is on and `config_actions: {deploy: true}`
    - `main()` exits successfully; no remove or deploy call was made

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    """
    kind, _kwargs, state_machine = _run_main(monkeypatch, config_actions={"deploy": True}, check_mode=True)

    assert kind is _ExitJson
    assert state_machine.model_orchestrator._calls == []


def test_nd_interface_port_channel_routed_00040(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify the delete-side flush runs before the deploy: a port-channel queued for removal is removed first, then deployed together
    with the accepted mutation in a single deploy call.

    ## Test

    - A delete-path pair is queued (remove + deploy) on top of the accepted pair
    - Calls are `remove` then one `deploy`; both queues are drained

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    - NDBaseInterfaceOrchestrator.remove_pending()
    - NDBaseInterfaceOrchestrator.deploy_pending()
    """
    removed = ("Port-channel120", "FDO11111AAA")

    class _DeletingStateMachine(_FakeStateMachine):
        def manage_state(self) -> None:
            self.model_orchestrator._queue_remove(*removed)
            self.model_orchestrator._queue_deploy(*removed)

    monkeypatch.setattr(module, "AnsibleModule", lambda **kwargs: _FakeAnsibleModule(config_actions={"deploy": True}, check_mode=False, **kwargs))
    monkeypatch.setattr(module, "NDStateMachine", _DeletingStateMachine)
    monkeypatch.setattr(module, "require_pydantic", lambda module: None)
    monkeypatch.setattr(module, "setup_logging", lambda module: None)
    with pytest.raises(_ExitJson):
        module.main()
    assert _DeletingStateMachine.last_instance is not None
    orchestrator = _DeletingStateMachine.last_instance.model_orchestrator

    assert orchestrator._calls == [("remove", [removed]), ("deploy", [ACCEPTED_PAIR, removed])]
    assert orchestrator._pending_removes == []
    assert orchestrator._pending_deploys == []


# =============================================================================
# Test: failure-path finalizer (finalize_accepted_intent)
# =============================================================================


@pytest.mark.parametrize(
    "failure, prefix",
    [
        (NDStateMachineError("later operation failed"), "Module execution failed: later operation failed"),
        (RuntimeError("unexpected"), "Module failed: unexpected"),
    ],
    ids=["state_machine_error", "unexpected_exception"],
)
def test_nd_interface_port_channel_routed_00100(monkeypatch: pytest.MonkeyPatch, failure: Exception, prefix: str) -> None:
    """
    # Summary

    Verify a failure after the controller accepted a mutation still deploys that mutation and names it in the failure message, for
    both the state-machine error and an unexpected exception (issue #546: a stranded accepted mutation is invisible to a retry).

    ## Test

    - `config_actions.deploy` is true and one accepted pair is queued when `manage_state` raises
    - `fail_json` is called with the original error plus the accepted-interface NOTE
    - The orchestrator deployed exactly the accepted pair, once

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    - fail_from_exception()
    """
    kind, kwargs, state_machine = _run_main(monkeypatch, config_actions={"deploy": True}, failure=failure)
    orchestrator = state_machine.model_orchestrator

    assert kind is _FailJson
    assert kwargs["msg"] == f"{prefix}{ACCEPTED_NOTE}"
    assert orchestrator._calls == [("deploy", [ACCEPTED_PAIR])]
    assert orchestrator._pending_deploys == []


def test_nd_interface_port_channel_routed_00110(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify the failure path honors the opt-in contract: with `config_actions` omitted the accepted pair stays staged and the message
    carries no NOTE.

    ## Test

    - `config_actions` omitted and one accepted pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with only the original error; no deploy was issued and the pair remains queued

    ## Classes and Methods

    - nd_interface_port_channel_routed.main()
    - fail_from_exception()
    """
    kind, kwargs, state_machine = _run_main(monkeypatch, failure=NDStateMachineError("later operation failed"))
    orchestrator = state_machine.model_orchestrator

    assert kind is _FailJson
    assert kwargs["msg"] == "Module execution failed: later operation failed"
    assert orchestrator._calls == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]
