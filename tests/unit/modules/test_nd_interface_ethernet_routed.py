# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `nd_interface_ethernet_routed` module wrapper (`main()`).

Covers the `config_actions.deploy` contract (opt-in deploy: omitted / explicit true / explicit false / check mode) and the
failure-path finalizer in both `except` handlers (`finalize_accepted_intent`). `main()` is driven with stand-ins for
`AnsibleModule` and `NDStateMachine`; live ND interaction is exercised by the integration target.
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
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import NDEndpointBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.modules import nd_interface_ethernet_routed as module

ACCEPTED_PAIR = ("Ethernet1/7", "FDO12345ABC")
ACCEPTED_NOTE = (
    " NOTE: before the failure, the controller had already accepted changes for interface(s) "
    "[Ethernet1/7 (switchId FDO12345ABC)]; those changes were deployed."
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

    Minimal `AnsibleModule` stand-in for driving `main()`: carries `params` and `check_mode`, and turns `fail_json` / `exit_json`
    into exceptions.

    ## Raises

    None
    """

    def __init__(self, *, config_actions: Any, check_mode: bool, **kwargs: Any) -> None:
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


class _FakeStateMachine:
    """
    # Summary

    `NDStateMachine` stand-in: builds a `_RecordingOrchestrator` with one controller-accepted pair queued for deploy, then either
    returns from `manage_state` or raises the configured exception to simulate a later operation failing.

    ## Raises

    None
    """

    failure: Exception | None = None
    last_instance: _FakeStateMachine | None = None

    def __init__(self, module: Any, model_orchestrator: Any) -> None:
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
) -> tuple[type[Exception], dict[str, Any], _RecordingOrchestrator]:
    """
    # Summary

    Drive `main()` with the stand-ins and return the exit kind (`_ExitJson` or `_FailJson`), its keyword arguments, and the
    orchestrator the module used.

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
    return type(exc_info.value), exc_info.value.args[0], _StateMachine.last_instance.model_orchestrator


# =============================================================================
# Test: config_actions.deploy contract (opt-in)
# =============================================================================


def test_nd_interface_ethernet_routed_00000(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify deploy is opt-in: with `config_actions` omitted, the queued mutation is staged and no deploy is issued.

    ## Test

    - `config_actions` is absent from the params (Ansible passes None for an unset dict option)
    - `main()` exits successfully; the orchestrator's `deploy` flag is False
    - No `interfaceActions/deploy` call was made; the accepted pair remains queued

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    """
    kind, kwargs, orchestrator = _run_main(monkeypatch)

    assert kind is _ExitJson
    assert kwargs == {}
    assert orchestrator.deploy is False
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]


def test_nd_interface_ethernet_routed_00010(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify an explicit `config_actions.deploy: true` deploys the queued mutation once at the end of the run.

    ## Test

    - `config_actions: {deploy: true}`
    - `main()` exits successfully; the orchestrator's `deploy` flag is True
    - Exactly one deploy call carrying the accepted pair was made; the queue is drained

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - NDBaseInterfaceOrchestrator.deploy_pending()
    """
    kind, _kwargs, orchestrator = _run_main(monkeypatch, config_actions={"deploy": True})

    assert kind is _ExitJson
    assert orchestrator.deploy is True
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]
    assert orchestrator._pending_deploys == []


def test_nd_interface_ethernet_routed_00020(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify an explicit `config_actions.deploy: false` stages the mutation without deploying.

    ## Test

    - `config_actions: {deploy: false}`
    - `main()` exits successfully; the orchestrator's `deploy` flag is False
    - No deploy call was made; the accepted pair remains queued

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    """
    kind, _kwargs, orchestrator = _run_main(monkeypatch, config_actions={"deploy": False})

    assert kind is _ExitJson
    assert orchestrator.deploy is False
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]


def test_nd_interface_ethernet_routed_00030(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify check mode never deploys, even with `config_actions.deploy: true`: the post-`manage_state` flush is skipped.

    ## Test

    - Check mode is on and `config_actions: {deploy: true}`
    - `main()` exits successfully
    - No deploy call was made; the queued pair is untouched

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    """
    kind, _kwargs, orchestrator = _run_main(monkeypatch, config_actions={"deploy": True}, check_mode=True)

    assert kind is _ExitJson
    assert orchestrator.deploy is True
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]


# =============================================================================
# Test: failure-path finalizer (finalize_accepted_intent) in both handlers
# =============================================================================


def test_nd_interface_ethernet_routed_00100(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify the `NDStateMachineError` handler deploys the controller-accepted pair and names it in the failure message.

    ## Test

    - `config_actions.deploy` is true and one accepted pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with the original error plus the accepted-interface NOTE
    - The orchestrator deployed exactly the accepted pair, once

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    """
    kind, kwargs, orchestrator = _run_main(monkeypatch, config_actions={"deploy": True}, failure=NDStateMachineError("later operation failed"))

    assert kind is _FailJson
    assert kwargs["msg"] == f"Module execution failed: later operation failed{ACCEPTED_NOTE}"
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]
    assert orchestrator._pending_deploys == []


def test_nd_interface_ethernet_routed_00110(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify the broad `Exception` handler also deploys the controller-accepted pair and names it in the failure message.

    ## Test

    - `config_actions.deploy` is true and one accepted pair is queued when `manage_state` raises a plain `RuntimeError`
    - `fail_json` is called with the original error plus the accepted-interface NOTE
    - The orchestrator deployed exactly the accepted pair, once

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    """
    kind, kwargs, orchestrator = _run_main(monkeypatch, config_actions={"deploy": True}, failure=RuntimeError("unexpected"))

    assert kind is _FailJson
    assert kwargs["msg"] == f"Module failed: unexpected{ACCEPTED_NOTE}"
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]


def test_nd_interface_ethernet_routed_00120(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify the failure path honors the opt-in contract: with `config_actions` omitted the accepted pair stays staged and the
    message carries no NOTE.

    ## Test

    - `config_actions` omitted and one accepted pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with only the original error
    - No deploy was issued and the pair remains queued

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    """
    kind, kwargs, orchestrator = _run_main(monkeypatch, failure=NDStateMachineError("later operation failed"))

    assert kind is _FailJson
    assert kwargs["msg"] == "Module execution failed: later operation failed"
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]


def test_nd_interface_ethernet_routed_00130(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    Verify the failure path issues no deploy in check mode (no mutations were sent, so nothing was accepted).

    ## Test

    - Check mode is on, `config_actions.deploy` is true, and one pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with only the original error
    - No deploy was issued

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    """
    kind, kwargs, orchestrator = _run_main(
        monkeypatch, config_actions={"deploy": True}, check_mode=True, failure=NDStateMachineError("later operation failed")
    )

    assert kind is _FailJson
    assert kwargs["msg"] == "Module execution failed: later operation failed"
    assert orchestrator._deployed == []
