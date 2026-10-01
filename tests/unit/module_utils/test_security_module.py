"""Focused tests for the shared security module runner."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from ansible_collections.cisco.nd.plugins.module_utils import security_module
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import (
    ConfigActionStepResult,
    ConfigActions,
    ConfigActionsExecutionError,
    ConfigActionsResult,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.security.groups import (
    SecurityGroupModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.security import (
    SecurityGroupOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import (
    MockAnsibleModule,
)


def _rest_send(state: str = "merged", check_mode: bool = False) -> RestSend:
    instance = RestSend(
        {
            "check_mode": check_mode,
            "fabric_name": "SITE1",
            "cluster_name": "cluster-a",
            "state": state,
            "config": [],
        }
    )
    instance.controller_version = "4.3.1"
    return instance


def _generated_id_state_machine(state: str, check_mode: bool, config: dict) -> tuple[NDStateMachine, SecurityGroupOrchestrator]:
    """Build a group state machine whose current object has an ND 4.3-generated ID."""
    module = MockAnsibleModule()
    module.check_mode = check_mode
    module.params = {
        "state": state,
        "config": [config],
        "output_level": "normal",
        "ignore_errors": False,
        "fabric_name": "SITE1",
        "cluster_name": "cluster-a",
    }
    orchestrator = SecurityGroupOrchestrator(rest_send=_rest_send(state=state, check_mode=check_mode))
    current_data = [
        {
            "name": "generated",
            "id": 4201,
            "vrfNames": ["vrf1"],
            "attach": True,
            "description": "before",
        }
    ]
    with patch.object(SecurityGroupOrchestrator, "query_all", return_value=current_data):
        instance = NDStateMachine(module=module, model_orchestrator=orchestrator)
    current = instance.existing.get("generated")
    orchestrator._existing_by_identifier[current.get_identifier_value()] = current  # pylint: disable=protected-access
    return instance, orchestrator


def _group(name: str, group_id: int, attach: bool | None = None) -> SecurityGroupModel:
    config = {"name": name, "id": group_id, "vrf_names": ["vrf1"]}
    if attach is not None:
        config["attach"] = attach
    return SecurityGroupModel.from_config(config, context={"controller_version": "4.3.1"})


def _state_machine(orchestrator: SecurityGroupOrchestrator, before_items=()):
    before = NDConfigCollection(model_class=SecurityGroupModel, items=list(before_items))
    return SimpleNamespace(
        model_orchestrator=orchestrator,
        model_class=SecurityGroupModel,
        module=SimpleNamespace(params={"fabric_name": "SITE1"}),
        before=before,
        existing=before.copy(),
        sent=NDConfigCollection(model_class=SecurityGroupModel),
        removed=NDConfigCollection(model_class=SecurityGroupModel),
        output=Mock(),
    )


def _record_response(rest_send: RestSend, data: dict) -> None:
    response = {"RETURN_CODE": 207, "MESSAGE": "Multi-Status", "DATA": data}
    rest_send.response_current = response
    rest_send.add_response(response)


def test_security_module_00010(monkeypatch):
    """Verify config is required for every write state and optional for gathered."""
    captured = {}

    class ConstructorReached(Exception):
        """Stop after capturing the AnsibleModule constructor contract."""

    def ansible_module(**kwargs):
        captured.update(kwargs)
        raise ConstructorReached

    monkeypatch.setattr(security_module, "AnsibleModule", ansible_module)

    with pytest.raises(ConstructorReached):
        security_module.run_security_module(SecurityGroupModel, SecurityGroupOrchestrator, "nd.test")

    assert captured["supports_check_mode"] is True
    assert captured["required_if"] == [
        ("state", "merged", ["config"]),
        ("state", "replaced", ["config"]),
        ("state", "overridden", ["config"]),
        ("state", "deleted", ["config"]),
    ]


def test_security_module_00020():
    """Verify failure reconciliation reports only exact controller-accepted upserts and deletes."""
    orchestrator = SecurityGroupOrchestrator(rest_send=_rest_send())
    kept = _group("kept", 100)
    deleted = _group("deleted", 101)
    accepted = _group("accepted", 102)
    speculative = _group("rejected", 103)
    instance = _state_machine(orchestrator, before_items=[kept, deleted])
    instance.existing.add(accepted)
    instance.existing.add(speculative)
    orchestrator._record_upserts([accepted])  # pylint: disable=protected-access
    orchestrator._record_deletes([deleted])  # pylint: disable=protected-access

    security_module._reconcile_accepted_mutations(instance)  # pylint: disable=protected-access

    assert set(instance.existing.keys()) == {"kept", "accepted"}
    assert instance.sent.keys() == ["accepted"]
    assert instance.removed.keys() == ["deleted"]
    instance.output.assign.assert_called_once_with(after=instance.existing)


def test_security_module_00030():
    """Verify a mixed resource failure still attaches accepted items and runs requested config save."""
    orchestrator = SecurityGroupOrchestrator(rest_send=_rest_send())
    accepted = _group("accepted", 101, attach=True)
    rejected = _group("rejected", 102, attach=True)
    orchestrator._record_upserts([accepted])  # pylint: disable=protected-access
    orchestrator._pending_attach = [
        "accepted",
        "rejected",
    ]  # pylint: disable=protected-access
    instance = _state_machine(orchestrator)
    security_module._reconcile_accepted_mutations(instance)  # pylint: disable=protected-access
    events = []
    config_result = Mock()
    config_result.to_result.return_value = {"status": "completed"}

    def request_action(_endpoint, names):
        events.append(("attach", list(names)))
        return {"securityGroups": [{"securityGroupName": names[0], "status": "success"}]}

    def run_config_actions(**_kwargs):
        events.append(("config", None))
        return config_result

    with (
        patch.object(orchestrator, "_request_action", side_effect=request_action),
        patch.object(
            SecurityGroupOrchestrator,
            "run_config_actions",
            side_effect=run_config_actions,
        ),
    ):
        errors = security_module._run_final_actions(  # pylint: disable=protected-access
            nd_state_machine=instance,
            config_actions=ConfigActions(save=True, deploy=False, type="switch", provided=True),
            state="merged",
            check_mode=False,
            accepted_only=True,
        )

    assert errors == []
    assert events == [("attach", ["accepted"]), ("config", None)]
    assert orchestrator._pending_attach == ["rejected"]  # pylint: disable=protected-access
    assigned = {key: value for call in instance.output.assign.call_args_list for key, value in call.kwargs.items()}
    assert assigned["security_actions_result"]["attach"]
    assert assigned["config_actions_result"] == {"status": "completed"}


def test_security_module_00040():
    """Verify a mixed attach is aggregated only after config finalization runs."""
    rest_send = _rest_send()
    orchestrator = SecurityGroupOrchestrator(rest_send=rest_send)
    first = _group("first", 101, attach=True)
    second = _group("second", 102, attach=True)
    orchestrator._record_upserts([first, second])  # pylint: disable=protected-access
    orchestrator._pending_attach = [
        "first",
        "second",
    ]  # pylint: disable=protected-access
    instance = _state_machine(orchestrator)
    security_module._reconcile_accepted_mutations(instance)  # pylint: disable=protected-access
    events = []

    def request_action(_endpoint, _names):
        events.append("attach")
        _record_response(
            rest_send,
            {
                "securityGroups": [
                    {"securityGroupName": "first", "status": "success"},
                    {
                        "securityGroupName": "second",
                        "status": "failed",
                        "message": "rejected",
                    },
                ]
            },
        )
        raise RuntimeError("mixed attach")

    def run_config_actions(**_kwargs):
        events.append("config")
        return None

    with (
        patch.object(orchestrator, "_request_action", side_effect=request_action),
        patch.object(
            SecurityGroupOrchestrator,
            "run_config_actions",
            side_effect=run_config_actions,
        ),
    ):
        errors = security_module._run_final_actions(  # pylint: disable=protected-access
            nd_state_machine=instance,
            config_actions=ConfigActions(save=True, deploy=False, type="switch", provided=True),
            state="merged",
            check_mode=False,
            accepted_only=True,
        )

    assert events == ["attach", "config"]
    assert len(errors) == 1
    assert "controller accepted ['first']" in str(errors[0])
    assert orchestrator._pending_attach == ["second"]  # pylint: disable=protected-access
    assert {item.name: item.attach for item in instance.existing} == {
        "first": True,
        "second": True,
    }
    assert {item.name: item.attach for item in instance.sent} == {
        "first": True,
        "second": True,
    }
    after_assignments = [call.kwargs["after"] for call in instance.output.assign.call_args_list if "after" in call.kwargs]
    assert {item.name: item.attach for item in after_assignments[-1]} == {
        "first": True,
        "second": True,
    }


def test_security_module_00050():
    """Verify a failed config-action result remains structured in module output."""
    orchestrator = SecurityGroupOrchestrator(rest_send=_rest_send())
    accepted = _group("accepted", 101)
    orchestrator._record_upserts([accepted])  # pylint: disable=protected-access
    instance = _state_machine(orchestrator)
    actions = ConfigActions(save=True, deploy=False, type="switch", provided=True)
    failed_result = ConfigActionsResult(
        requested=actions,
        effective=actions,
        status="failed",
        reason="action_failed",
        targets={"fabrics": ("SITE1",)},
        actions=(
            ConfigActionStepResult(
                action="save",
                status="failed",
                target="SITE1",
                error="controller rejected configSave",
            ),
        ),
    )
    failure = ConfigActionsExecutionError("Config action 'save' failed for 'SITE1'", failed_result)

    with patch.object(SecurityGroupOrchestrator, "run_config_actions", side_effect=failure):
        errors = security_module._run_final_actions(  # pylint: disable=protected-access
            nd_state_machine=instance,
            config_actions=actions,
            state="merged",
            check_mode=False,
            accepted_only=False,
        )

    assert errors == [failure]
    assigned = {key: value for call in instance.output.assign.call_args_list for key, value in call.kwargs.items()}
    assert assigned["config_actions_result"] == failed_result.to_result()


@pytest.mark.parametrize("state", ["replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_security_module_00060(state, check_mode):
    """Verify ND 4.3 generated group IDs converge when replacement intent omits ID."""
    instance, orchestrator = _generated_id_state_machine(
        state,
        check_mode,
        {"name": "generated", "vrf_names": ["vrf1"], "description": "before"},
    )

    with patch.object(
        SecurityGroupOrchestrator,
        "update",
        side_effect=AssertionError("unexpected update"),
    ) as update:
        instance.manage_state()

    update.assert_not_called()
    assert instance.proposed.get("generated").id == 4201
    assert len(instance.sent) == 0


def test_security_module_00070():
    """Verify a replacement update sends the preserved ND 4.3 generated group ID."""
    instance, orchestrator = _generated_id_state_machine(
        "replaced",
        False,
        {"name": "generated", "vrf_names": ["vrf1"], "description": "after"},
    )

    with patch.object(SecurityGroupOrchestrator, "_request", return_value={}) as request:
        instance.manage_state()

    assert request.call_count == 1
    assert request.call_args.kwargs["data"]["id"] == 4201
    assert instance.proposed.get("generated").id == 4201
