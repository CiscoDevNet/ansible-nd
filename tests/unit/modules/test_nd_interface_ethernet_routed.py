# Copyright: (c) 2026, Allen Robel (@allenrobel)

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for the `nd_interface_ethernet_routed` module wrapper (`main()`).

Covers the `config_actions.deploy` contract (opt-in deploy: omitted / explicit true / explicit false / check mode), the
failure-path finalizer in both `except` handlers (`finalize_accepted_intent`), and the end-to-end composition of a deferred
delete-side failure (`remove_pending`) with that finalizer through a real orchestrator. `main()` is driven with stand-ins for
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
from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.ethernet_routed_interface import EthernetRoutedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_routed_interface import EthernetRoutedInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.modules import nd_interface_ethernet_routed as module
from ansible_collections.cisco.nd.tests.unit.module_utils.fixtures.load_fixture import load_fixture
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.response_generator import ResponseGenerator
from ansible_collections.cisco.nd.tests.unit.module_utils.sender_file import Sender

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


# =============================================================================
# Test: end-to-end delete-path failure finalization through main() (PR #550 review)
# =============================================================================


def _routed_rest_send(keys: list[str], config: list[dict[str, Any]]) -> RestSend:
    """
    # Summary

    Build a `RestSend` wired to the file-based `Sender` over the routed orchestrator fixture file, with `state: deleted` params.

    ## Raises

    None
    """

    def responses():
        for key in keys:
            yield load_fixture("test_ethernet_routed_interface")[key]

    sender = Sender()
    sender.ansible_module = MockAnsibleModule()
    sender.gen = ResponseGenerator(responses())

    response_handler = ResponseHandler()
    response_handler.response = {"RETURN_CODE": 200, "MESSAGE": "OK"}
    response_handler.verb = HttpVerbEnum.GET
    response_handler.commit()

    rest_send = RestSend({"check_mode": False, "fabric_name": "fabric_1", "state": "deleted", "config": config})
    rest_send.sender = sender
    rest_send.response_handler = response_handler
    rest_send.unit_test = True
    rest_send.timeout = 1
    return rest_send


def _existing_model(switch_ip: str, interface_name: str, os_type: str, policy: dict[str, Any]) -> EthernetRoutedInterfaceModel:
    """
    # Summary

    Build an existing-side routed model as the state machine would hand it to `delete_bulk`.

    ## Raises

    None
    """
    return EthernetRoutedInterfaceModel.from_response(
        {
            "switchIp": switch_ip,
            "interfaceName": interface_name,
            "interfaceType": "ethernet",
            "configData": {"mode": "routed", "networkOS": {"networkOSType": os_type, "policy": policy}},
        }
    )


class _DeleteStateMachine:
    """
    # Summary

    `NDStateMachine` stand-in whose orchestrator is a REAL `EthernetRoutedInterfaceOrchestrator` over the file-based sender, and whose
    `manage_state` runs the real `delete_bulk` for the configured models. `main()` then flushes `remove_pending()` itself, so the
    reset failure and the failure-path finalizer compose exactly as they do in production.

    ## Raises

    None
    """

    fixture_keys: list[str] = []
    models: list[EthernetRoutedInterfaceModel] = []
    last_instance: _DeleteStateMachine | None = None

    def __init__(self, module: Any, model_orchestrator: Any) -> None:
        config = [{"switch_ip": m.switch_ip, "interface_name": m.interface_name} for m in self.models]
        self.model_orchestrator = EthernetRoutedInterfaceOrchestrator(rest_send=_routed_rest_send(self.fixture_keys, config))
        self.output = SimpleNamespace(format=lambda: {})
        type(self).last_instance = self

    def manage_state(self) -> None:
        """
        # Summary

        Queue the configured models for deferred delete via the real `delete_bulk`.

        ## Raises

        ### RuntimeError

        - Propagated from `delete_bulk`
        """
        self.model_orchestrator.delete_bulk(list(self.models), existing_data={"interfaceName": "probe"})


def _run_delete_main(
    monkeypatch: pytest.MonkeyPatch, *, fixture_keys: list[str], models: list[EthernetRoutedInterfaceModel]
) -> tuple[dict[str, Any], EthernetRoutedInterfaceOrchestrator]:
    """
    # Summary

    Drive `main()` (deploy on, normal mode) with `_DeleteStateMachine` and return the `fail_json` kwargs plus the real orchestrator.

    ## Raises

    ### AssertionError

    - If `main()` did not fail through the stand-in
    """

    class _StateMachine(_DeleteStateMachine):
        pass

    _StateMachine.fixture_keys = fixture_keys
    _StateMachine.models = models
    monkeypatch.setattr(module, "AnsibleModule", lambda **kwargs: _FakeAnsibleModule(config_actions={"deploy": True}, check_mode=False, **kwargs))
    monkeypatch.setattr(module, "NDStateMachine", _StateMachine)
    monkeypatch.setattr(module, "require_pydantic", lambda module: None)
    monkeypatch.setattr(module, "setup_logging", lambda module: None)

    with pytest.raises(_FailJson) as exc_info:
        module.main()
    assert _StateMachine.last_instance is not None
    return exc_info.value.args[0], _StateMachine.last_instance.model_orchestrator


def test_nd_interface_ethernet_routed_00200(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    End-to-end: three IOS-XE resets under `state: deleted` with `config_actions.deploy: true`; the first reset PUT succeeds, the
    second fails, the third is never attempted. `main()`'s `remove_pending()` raises into the broad handler, whose finalizer must
    deploy ONLY GigabitEthernet3 and name only it in the NOTE, while the error text still reports Gi4 failed / Gi5 not attempted.

    ## Test

    - Fixtures: switches list, PUT 204 (Gi3), PUT 500 (Gi4), deploy 200
    - `fail_json` msg carries the partial-state detail and a NOTE naming only Gi3
    - The deploy payload contains only Gi3; Gi4 and Gi5 remain queued for deploy and reset

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    - EthernetRoutedInterfaceOrchestrator.remove_pending()
    - NDBaseInterfaceOrchestrator.deploy_accepted_mutations()
    """
    models = [
        _existing_model("192.168.1.2", name, "ios-xe", {"policyType": "iosXeRoutedHost", "ip": ip, "prefix": 30})
        for name, ip in (("GigabitEthernet3", "10.10.3.1"), ("GigabitEthernet4", "10.10.4.1"), ("GigabitEthernet5", "10.10.5.1"))
    ]
    kwargs, orchestrator = _run_delete_main(
        monkeypatch,
        fixture_keys=["test_wrapper_xe_reset_00200a", "test_wrapper_xe_reset_00200b", "test_wrapper_xe_reset_00200c", "test_wrapper_xe_reset_00200d"],
        models=models,
    )

    msg = kwargs["msg"]
    assert msg.startswith("Module failed: IOS-XE reset failed at GigabitEthernet4 on FDO22222BBB: ")
    assert "Successfully reset before failure: ['GigabitEthernet3']. Not attempted: ['GigabitEthernet5']." in msg
    note = msg[msg.index(" NOTE:") :]
    assert note == (
        " NOTE: before the failure, the controller had already accepted changes for interface(s) "
        "[GigabitEthernet3 (switchId FDO22222BBB)]; those changes were deployed."
    )
    assert orchestrator.rest_send.committed_payload == {"interfaces": [{"interfaceName": "GigabitEthernet3", "switchId": "FDO22222BBB"}]}
    assert orchestrator._pending_xe_resets == [("GigabitEthernet4", "FDO22222BBB"), ("GigabitEthernet5", "FDO22222BBB")]
    assert orchestrator._pending_deploys == [("GigabitEthernet4", "FDO22222BBB"), ("GigabitEthernet5", "FDO22222BBB")]


def test_nd_interface_ethernet_routed_00210(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    End-to-end: an NX-OS bulk normalize failure under `state: deleted` with `config_actions.deploy: true` must deploy nothing —
    the normalize is all-or-nothing, so no interface's reset was accepted — and the failure message carries no NOTE.

    ## Test

    - Fixtures: switches list, normalize POST 500 (no deploy fixture: a deploy request would exhaust the generator and fail)
    - `fail_json` msg reports the bulk normalize failure with no NOTE appended
    - Both pairs remain queued for normalize and deploy

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    - EthernetBaseOrchestrator.remove_pending()
    """
    models = [
        _existing_model("192.168.1.1", name, "nx-os", {"policyType": "routedHost", "ip": ip, "prefix": 30})
        for name, ip in (("Ethernet1/31", "10.99.31.1"), ("Ethernet1/32", "10.99.32.1"))
    ]
    kwargs, orchestrator = _run_delete_main(monkeypatch, fixture_keys=["test_wrapper_nx_normalize_00210a", "test_wrapper_nx_normalize_00210b"], models=models)

    msg = kwargs["msg"]
    assert msg.startswith("Module failed: Bulk normalize failed for ['Ethernet1/31', 'Ethernet1/32']")
    assert "NOTE:" not in msg
    assert orchestrator._pending_normalizes == [("Ethernet1/31", "FDO11111AAA"), ("Ethernet1/32", "FDO11111AAA")]
    assert orchestrator._pending_deploys == [("Ethernet1/31", "FDO11111AAA"), ("Ethernet1/32", "FDO11111AAA")]


def test_nd_interface_ethernet_routed_00220(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    # Summary

    End-to-end: an NX-OS bulk normalize under `state: deleted` with `config_actions.deploy: true` that fails with a MIXED HTTP 207
    (Ethernet1/31 accepted, Ethernet1/32 rejected). `main()`'s finalizer must deploy Ethernet1/31 and name it in the NOTE, while
    Ethernet1/32 stays queued for normalize and deploy; a later run converges it.

    ## Test

    - Fixtures: switches list, normalize POST 207 mixed, deploy 200
    - `fail_json` msg names Ethernet1/32 as failed and Ethernet1/31 as accepted, then a NOTE naming only Ethernet1/31
    - The deploy payload contains only Ethernet1/31; Ethernet1/32 remains queued for normalize and deploy

    ## Classes and Methods

    - nd_interface_ethernet_routed.main()
    - finalize_accepted_intent()
    - EthernetBaseOrchestrator.remove_pending()
    - EthernetBaseOrchestrator._dequeue_accepted_normalizes()
    """
    models = [
        _existing_model("192.168.1.1", name, "nx-os", {"policyType": "routedHost", "ip": ip, "prefix": 30})
        for name, ip in (("Ethernet1/31", "10.99.31.1"), ("Ethernet1/32", "10.99.32.1"))
    ]
    kwargs, orchestrator = _run_delete_main(
        monkeypatch,
        fixture_keys=["test_wrapper_nx_normalize_00220a", "test_wrapper_nx_normalize_00220b", "test_wrapper_nx_normalize_00220c"],
        models=models,
    )

    msg = kwargs["msg"]
    assert msg.startswith("Module failed: Bulk normalize failed for ['Ethernet1/32']: ")
    assert "The controller accepted ['Ethernet1/31'] from the same request; their deploy stays queued." in msg
    note = msg[msg.index(" NOTE:") :]
    assert note == (
        " NOTE: before the failure, the controller had already accepted changes for interface(s) "
        "[Ethernet1/31 (switchId FDO11111AAA)]; those changes were deployed."
    )
    assert orchestrator.rest_send.committed_payload == {"interfaces": [{"interfaceName": "Ethernet1/31", "switchId": "FDO11111AAA"}]}
    assert orchestrator._pending_normalizes == [("Ethernet1/32", "FDO11111AAA")]
    assert orchestrator._pending_deploys == [("Ethernet1/32", "FDO11111AAA")]
