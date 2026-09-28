# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests verifying every `nd_interface_*` module finalizes controller-accepted mutations on its failure path.

When a module fails after the controller has already accepted some interface mutations (for example a later grouped create is
rejected), the accepted subset would otherwise remain staged-but-undeployed: a retry classifies those interfaces as unchanged and
never re-queues their deploy. Each module's `except` handlers must therefore call `finalize_accepted_intent`, which deploys the
accepted subset (honoring `config_actions.deploy` and check mode) and names it in the failure message. These tests drive each
module's `main()` with stand-ins for `AnsibleModule` and `NDStateMachine` so the handlers themselves are exercised.
"""

# pylint: disable=invalid-name
# pylint: disable=line-too-long
# pylint: disable=protected-access
# pylint: disable=redefined-outer-name
# pylint: disable=too-few-public-methods
# pylint: disable=unused-argument

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any, ClassVar

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

# Every interface module delegates its single `except Exception` clause to `fail_from_exception` (issue #556), which handles
# both the `NDStateMachineError` tier and the unhandled-exception tier.
INTERFACE_MODULES = (
    "nd_interface_ethernet_access",
    "nd_interface_ethernet_routed",
    "nd_interface_ethernet_trunk_host",
    "nd_interface_loopback",
    "nd_interface_port_channel_access",
    "nd_interface_port_channel_trunk_host",
    "nd_interface_subinterface_managed",
    "nd_interface_subinterface_unmanaged",
    "nd_interface_svi",
    "nd_interface_vpc_access",
    "nd_interface_vpc_trunk_host",
)

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


class _ExitJson(Exception):
    """
    # Summary

    Raised by the `AnsibleModule` stand-in's `exit_json`; reaching it means the module did not fail as the test expected.

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

    def __init__(self, *, deploy: bool, check_mode: bool, **kwargs: Any) -> None:
        self.params: dict[str, Any] = {
            "config": [],
            "state": "merged",
            "config_actions": {"deploy": deploy},
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

        Signal an unexpected success exit.

        ## Raises

        ### _ExitJson

        - Always
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

    deploy_failure: ClassVar[Exception | None] = None

    def _deploy_interfaces(self, pairs: list[tuple[str, str]]) -> dict[str, Any]:
        """
        # Summary

        Record `pairs` instead of sending `interfaceActions/deploy`, then raise the class-level `deploy_failure` if one is set.

        ## Raises

        ### Exception

        - The class-level `deploy_failure`, when set (simulates a rejected deploy request)
        """
        self._deployed.append(list(pairs))
        if self.deploy_failure is not None:
            raise self.deploy_failure
        return {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}


class _FakeStateMachine:
    """
    # Summary

    `NDStateMachine` stand-in: builds a `_RecordingOrchestrator` with one controller-accepted pair queued for deploy, then raises
    the configured exception from `manage_state` to simulate a later operation failing.

    ## Raises

    None
    """

    failure: Exception | None = NDStateMachineError("later operation failed")
    deploy_failure: Exception | None = None
    last_instance: _FakeStateMachine | None = None

    def __init__(self, module: Any, model_orchestrator: Any) -> None:
        class _Orchestrator(_RecordingOrchestrator):
            deploy_failure = self.deploy_failure

        self.model_orchestrator = _Orchestrator(rest_send=RestSend({"check_mode": False, "fabric_name": "fabric_1"}))
        self.model_orchestrator._queue_deploy(*ACCEPTED_PAIR)
        self.output = SimpleNamespace(format=lambda: {})
        type(self).last_instance = self

    def manage_state(self) -> None:
        """
        # Summary

        Raise the configured failure after the accepted pair has been queued; return normally when `failure` is `None`.

        ## Raises

        ### Exception

        - The class-level `failure`, when set
        """
        if self.failure is not None:
            raise self.failure


def _run_main(  # pylint: disable=too-many-arguments
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    *,
    failure: Exception | None,
    deploy: bool = True,
    check_mode: bool = False,
    deploy_failure: Exception | None = None,
) -> tuple[dict[str, Any], _RecordingOrchestrator]:
    """
    # Summary

    Drive `module_name.main()` with the stand-ins and return the captured `fail_json` kwargs plus the orchestrator the module used.
    `failure` is raised from `manage_state` (`None` lets it succeed); `deploy_failure` is raised from the orchestrator's deploy request.

    ## Raises

    ### AssertionError

    - If `main()` did not call `fail_json`
    """
    module = importlib.import_module(f"ansible_collections.cisco.nd.plugins.modules.{module_name}")

    class _StateMachine(_FakeStateMachine):
        pass

    _StateMachine.failure = failure
    _StateMachine.deploy_failure = deploy_failure
    monkeypatch.setattr(module, "AnsibleModule", lambda **kwargs: _FakeAnsibleModule(deploy=deploy, check_mode=check_mode, **kwargs))
    monkeypatch.setattr(module, "NDStateMachine", _StateMachine)
    monkeypatch.setattr(module, "require_pydantic", lambda module: None)
    monkeypatch.setattr(module, "setup_logging", lambda module: None)

    with pytest.raises(_FailJson) as exc_info:
        module.main()
    assert _StateMachine.last_instance is not None
    return exc_info.value.args[0], _StateMachine.last_instance.model_orchestrator


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_finalize_accepted_intent_00000(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify the `NDStateMachineError` tier of each interface module's handler deploys the controller-accepted pair and names it in the
    failure message.

    ## Test

    - `config_actions.deploy` is true and one accepted pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with the original error plus the accepted-interface NOTE
    - The orchestrator deployed exactly the accepted pair, once

    ## Classes and Methods

    - nd_interface_*.main()
    - finalize_accepted_intent()
    """
    kwargs, orchestrator = _run_main(monkeypatch, module_name, failure=NDStateMachineError("later operation failed"))

    assert kwargs["msg"] == f"Module execution failed: later operation failed{ACCEPTED_NOTE}"
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]
    assert orchestrator._pending_deploys == []


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_finalize_accepted_intent_00010(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify the unhandled-exception tier of each interface module's handler also deploys the controller-accepted pair and names
    it in the failure message.

    ## Test

    - `config_actions.deploy` is true and one accepted pair is queued when `manage_state` raises a plain `RuntimeError`
    - `fail_json` is called with the original error plus the accepted-interface NOTE
    - The orchestrator deployed exactly the accepted pair, once

    ## Classes and Methods

    - nd_interface_*.main()
    - finalize_accepted_intent()
    """
    kwargs, orchestrator = _run_main(monkeypatch, module_name, failure=RuntimeError("unexpected"))

    assert kwargs["msg"] == f"Module failed: unexpected{ACCEPTED_NOTE}"
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_finalize_accepted_intent_00020(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify the failure path honors `config_actions.deploy: false`: the accepted pair stays staged and the message carries no NOTE.

    ## Test

    - `config_actions.deploy` is false and one accepted pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with only the original error
    - No deploy was issued and the pair remains queued

    ## Classes and Methods

    - nd_interface_*.main()
    - finalize_accepted_intent()
    """
    kwargs, orchestrator = _run_main(monkeypatch, module_name, failure=NDStateMachineError("later operation failed"), deploy=False)

    assert kwargs["msg"] == "Module execution failed: later operation failed"
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_finalize_accepted_intent_00030(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify the failure path issues no deploy in check mode (no mutations were sent, so nothing was accepted).

    ## Test

    - Check mode is on, `config_actions.deploy` is true, and one pair is queued when `manage_state` raises `NDStateMachineError`
    - `fail_json` is called with only the original error
    - No deploy was issued

    ## Classes and Methods

    - nd_interface_*.main()
    - finalize_accepted_intent()
    """
    kwargs, orchestrator = _run_main(monkeypatch, module_name, failure=NDStateMachineError("later operation failed"), check_mode=True)

    assert kwargs["msg"] == "Module execution failed: later operation failed"
    assert orchestrator._deployed == []


@pytest.mark.parametrize("module_name", INTERFACE_MODULES)
def test_nd_interface_finalize_accepted_intent_00040(monkeypatch: pytest.MonkeyPatch, module_name: str) -> None:
    """
    # Summary

    Verify that when the normal `deploy_pending` request itself fails, the broad handler's finalizer does not resubmit the same
    deployment: exactly one deploy request is made, the message reports the deploy failure without an accepted-interface NOTE,
    and the pair stays queued (PR #547 review).

    ## Test

    - `config_actions.deploy` is true, `manage_state` succeeds, and the deploy request raises `RuntimeError`
    - `fail_json` is called with the wrapped `Bulk deploy failed` message only
    - The orchestrator issued exactly one deploy request, for the queued pair

    ## Classes and Methods

    - nd_interface_*.main()
    - finalize_accepted_intent()
    - NDBaseInterfaceOrchestrator.deploy_pending()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """
    kwargs, orchestrator = _run_main(monkeypatch, module_name, failure=None, deploy_failure=RuntimeError("deploy rejected"))

    assert kwargs["msg"] == f"Module failed: Bulk deploy failed for interfaces [{ACCEPTED_PAIR!r}]: deploy rejected"
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]
