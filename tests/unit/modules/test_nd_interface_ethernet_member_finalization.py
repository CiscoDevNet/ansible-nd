# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Failure-path deployment parity for access/trunk member updates (IFACE-004)."""

# pylint: disable=protected-access,too-few-public-methods,unused-argument

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import (
    NDStateMachineError,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.base import (
    NDEndpointBaseModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.modules import (
    nd_interface_ethernet_access,
    nd_interface_ethernet_trunk_host,
)

ACCEPTED_PAIR = ("Ethernet1/24", "FDO12345ABC")
ACCEPTED_NOTE = (
    " NOTE: before the failure, the controller had already accepted changes for interface(s) "
    "[Ethernet1/24 (switchId FDO12345ABC)]; those changes were deployed."
)
MODULES = (
    nd_interface_ethernet_access,
    nd_interface_ethernet_trunk_host,
)


class _FailJson(Exception):
    """Capture module failure output."""


class _FakeAnsibleModule:
    """Small AnsibleModule stand-in for the two wrapper entrypoints."""

    def __init__(
        self,
        *,
        config_actions: dict[str, bool] | None,
        check_mode: bool,
        **_kwargs: Any,
    ) -> None:
        self.params = {
            "config": [],
            "state": "merged",
            "config_actions": config_actions,
            "output_level": "normal",
        }
        self.check_mode = check_mode

    def fail_json(self, **kwargs: Any) -> None:
        """Raise the captured failure payload."""
        raise _FailJson(kwargs)

    def exit_json(self, **_kwargs: Any) -> None:
        """A failure test must never reach successful exit."""
        raise AssertionError("unexpected successful module exit")


class _RecordingOrchestrator(NDBaseInterfaceOrchestrator):
    """Record finalizer deploys without contacting a controller."""

    create_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPost
    update_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesPut
    delete_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesDelete
    query_one_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesGet
    query_all_endpoint: type[NDEndpointBaseModel] = EpManageInterfacesListGet

    def model_post_init(self, __context) -> None:
        super().model_post_init(__context)
        self._deployed: list[list[tuple[str, str]]] = []  # pylint: disable=attribute-defined-outside-init

    def _deploy_interfaces(self, pairs: list[tuple[str, str]]) -> dict[str, Any]:
        self._deployed.append(list(pairs))
        return {"RETURN_CODE": 200, "MESSAGE": "OK", "DATA": {}}


class _FakeStateMachine:
    """Queue one accepted mutation, then simulate a later operation failure."""

    failure: Exception
    last_instance: _FakeStateMachine | None = None

    def __init__(self, module: Any, model_orchestrator: Any) -> None:
        del module, model_orchestrator
        self.model_orchestrator = _RecordingOrchestrator(rest_send=RestSend({"check_mode": False, "fabric_name": "fabric_1"}))
        self.model_orchestrator._queue_deploy(*ACCEPTED_PAIR)
        self.output = SimpleNamespace(format=lambda: {})
        type(self).last_instance = self

    def manage_state(self) -> None:
        raise self.failure


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    module_under_test,
    *,
    failure: Exception,
    deploy: bool,
    check_mode: bool = False,
) -> tuple[dict[str, Any], _RecordingOrchestrator]:
    class _StateMachine(_FakeStateMachine):
        pass

    _StateMachine.failure = failure
    monkeypatch.setattr(
        module_under_test,
        "AnsibleModule",
        lambda **kwargs: _FakeAnsibleModule(
            config_actions={"deploy": deploy},
            check_mode=check_mode,
            **kwargs,
        ),
    )
    monkeypatch.setattr(module_under_test, "NDStateMachine", _StateMachine)
    monkeypatch.setattr(module_under_test, "require_pydantic", lambda module: None)
    monkeypatch.setattr(module_under_test, "setup_logging", lambda module: None)

    with pytest.raises(_FailJson) as exc_info:
        module_under_test.main()
    assert _StateMachine.last_instance is not None
    return (
        exc_info.value.args[0],
        _StateMachine.last_instance.model_orchestrator,
    )


@pytest.mark.parametrize("module_under_test", MODULES)
@pytest.mark.parametrize(
    "failure,prefix",
    (
        (NDStateMachineError("later update failed"), "Module execution failed"),
        (RuntimeError("unexpected update failure"), "Module failed"),
    ),
)
def test_failure_handlers_deploy_earlier_accepted_member(
    monkeypatch: pytest.MonkeyPatch,
    module_under_test,
    failure: Exception,
    prefix: str,
) -> None:
    """Both failure handlers finalize an earlier successful member PUT."""
    output, orchestrator = _run_main(
        monkeypatch,
        module_under_test,
        failure=failure,
        deploy=True,
    )

    assert output["msg"] == f"{prefix}: {failure}{ACCEPTED_NOTE}"
    assert orchestrator._deployed == [[ACCEPTED_PAIR]]
    assert orchestrator._pending_deploys == []


@pytest.mark.parametrize("module_under_test", MODULES)
@pytest.mark.parametrize(
    "deploy,check_mode",
    ((False, False), (True, True)),
)
def test_failure_finalizer_respects_staging_and_check_mode(
    monkeypatch: pytest.MonkeyPatch,
    module_under_test,
    deploy: bool,
    check_mode: bool,
) -> None:
    """Deploy false remains staged, and check mode never sends a deploy."""
    failure = NDStateMachineError("later update failed")
    output, orchestrator = _run_main(
        monkeypatch,
        module_under_test,
        failure=failure,
        deploy=deploy,
        check_mode=check_mode,
    )

    assert output["msg"] == f"Module execution failed: {failure}"
    assert orchestrator._deployed == []
    assert orchestrator._pending_deploys == [ACCEPTED_PAIR]
