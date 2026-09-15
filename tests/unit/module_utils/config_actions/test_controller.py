# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config_actions.controller.
"""

from __future__ import annotations

from typing import Any

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.controller import ConfigActionsController
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import RESOURCE_CONFIG_ACTIONS, SWITCH_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext
from ansible_collections.cisco.nd.plugins.module_utils.nd_v2 import NDModuleError


class RecordingBackend:
    """
    # Summary

    Backend test double that records action calls.

    ## Raises

    None
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def save(self, context: ConfigActionsContext, fabric_name: str) -> dict[str, str]:
        self.calls.append(("save", (fabric_name, context.state)))
        return {"saved": fabric_name}

    def deploy_global(self, context: ConfigActionsContext, fabric_name: str) -> dict[str, str]:
        self.calls.append(("deploy_global", (fabric_name, context.state)))
        return {"deployed": fabric_name}

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> dict[str, object]:
        self.calls.append(("deploy_switches", (fabric_name, switch_ids)))
        return {"fabric": fabric_name, "switch_ids": list(switch_ids)}

    def deploy_resources(self, context: ConfigActionsContext, fabric_name: str, resources: tuple[str, ...]) -> dict[str, object]:
        self.calls.append(("deploy_resources", (fabric_name, resources)))
        return {"fabric": fabric_name, "resources": list(resources)}


class FailingDeployBackend(RecordingBackend):
    """
    # Summary

    Backend test double that fails during deploy after save succeeds.

    ## Raises

    None
    """

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> dict[str, object]:
        self.calls.append(("deploy_switches", (fabric_name, switch_ids)))
        raise RuntimeError("deploy failed")


class StructuredFailureBackend(RecordingBackend):
    """
    # Summary

    Backend test double that raises NDModuleError with structured context.

    ## Raises

    None
    """

    def __init__(self, fail_action: str) -> None:
        super().__init__()
        self.fail_action = fail_action

    def save(self, context: ConfigActionsContext, fabric_name: str) -> dict[str, str]:
        self.calls.append(("save", (fabric_name, context.state)))
        if self.fail_action == "save":
            raise NDModuleError(
                "save rejected",
                status=409,
                request_payload={"save": fabric_name},
                response_payload={"errors": [{"message": "save conflict"}]},
                raw="raw-save-body",
            )
        return {"saved": fabric_name}

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> dict[str, object]:
        self.calls.append(("deploy_switches", (fabric_name, switch_ids)))
        if self.fail_action == "deploy":
            raise NDModuleError(
                "deploy rejected",
                status=500,
                request_payload={"switchIds": list(switch_ids)},
                response_payload={"errors": [{"message": "deploy failed"}]},
                raw="raw-deploy-body",
            )
        return {"fabric": fabric_name, "switch_ids": list(switch_ids)}


class FabricScopedFailureBackend(RecordingBackend):
    """
    # Summary

    Backend test double that fails deploy for one selected fabric.

    ## Raises

    None
    """

    def __init__(self, fail_fabric: str) -> None:
        super().__init__()
        self.fail_fabric = fail_fabric

    def deploy_switches(self, context: ConfigActionsContext, fabric_name: str, switch_ids: tuple[str, ...]) -> dict[str, object]:
        self.calls.append(("deploy_switches", (fabric_name, switch_ids)))
        if fabric_name == self.fail_fabric:
            raise RuntimeError(f"{fabric_name} deploy failed")
        return {"fabric": fabric_name, "switch_ids": list(switch_ids)}


def test_config_actions_controller_00000() -> None:
    """
    # Summary

    Verify check mode returns a plan and does not call the backend.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = RecordingBackend()
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), check_mode=True, switch_ids=("SER1",)),
    )
    assert result.status == "planned"
    assert backend.calls == []
    assert result.actions[0].action == "save"
    assert result.actions[1].scope == "switch"


def test_config_actions_controller_00010() -> None:
    """
    # Summary

    Verify switch deploy with empty targets is not silently expanded to global.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = RecordingBackend()
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), switch_ids=()),
    )
    assert ("deploy_global", ("FAB1", None)) not in backend.calls
    assert backend.calls == [("save", ("FAB1", None))]
    assert result.actions[-1].status == "skipped"
    assert result.actions[-1].scope == "switch"
    assert result.reason == "actions_executed_with_skips"


def test_config_actions_controller_00020() -> None:
    """
    # Summary

    Verify resource deploy calls the resource backend with explicit resources.

    ## Raises

    None
    """
    actions = parse_config_actions(
        params={"config_actions": {"deploy": True, "type": "resource"}},
        raw_args={"config_actions": {"deploy": True, "type": "resource"}},
        policy=RESOURCE_CONFIG_ACTIONS,
    )
    backend = RecordingBackend()
    result = ConfigActionsController(RESOURCE_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), resources=("BLUE",)),
    )
    assert backend.calls == [("deploy_resources", ("FAB1", ("BLUE",)))]
    assert result.status == "completed"
    assert result.actions[0].scope == "resource"


def test_config_actions_controller_00025() -> None:
    """
    # Summary

    Verify explicit resource deploy overrides are honored when top-level deploy is false.

    ## Raises

    None
    """
    actions = parse_config_actions(
        params={
            "config_actions": {"deploy": False, "type": "resource"},
            "config": [{"name": "BLUE", "deploy": True}],
        },
        raw_args={
            "config_actions": {"deploy": False, "type": "resource"},
            "config": [{"name": "BLUE", "deploy": True}],
        },
        policy=RESOURCE_CONFIG_ACTIONS,
    )
    backend = RecordingBackend()
    result = ConfigActionsController(RESOURCE_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), resources=("BLUE",)),
    )
    assert actions.deploy is False
    assert actions.resource_deploy_enabled(0) is True
    assert backend.calls == [("deploy_resources", ("FAB1", ("BLUE",)))]
    assert result.status == "completed"
    assert result.reason == "actions_executed"


def test_config_actions_controller_00030() -> None:
    """
    # Summary

    Verify duplicate switch and resource targets are removed before backend execution.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = RecordingBackend()
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1", "FAB1"), switch_ids=("SER1", "SER1", "SER2")),
    )
    assert backend.calls == [
        ("save", ("FAB1", None)),
        ("deploy_switches", ("FAB1", ("SER1", "SER2"))),
    ]
    assert result.targets["fabrics"] == ("FAB1",)
    assert result.targets["switches"] == ("SER1", "SER2")


def test_config_actions_controller_00035() -> None:
    """
    # Summary

    Verify switch deploy targets are scoped to each fabric.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = RecordingBackend()
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(
            fabric_names=("FAB1", "FAB2"),
            switch_ids_by_fabric={
                "FAB1": ("FAB1-S1", "FAB1-S2", "FAB1-S1"),
                "FAB2": ("FAB2-S1",),
            },
        ),
    )
    assert backend.calls == [
        ("save", ("FAB1", None)),
        ("deploy_switches", ("FAB1", ("FAB1-S1", "FAB1-S2"))),
        ("save", ("FAB2", None)),
        ("deploy_switches", ("FAB2", ("FAB2-S1",))),
    ]
    assert result.status == "completed"
    assert result.targets["fabrics"] == ("FAB1", "FAB2")
    assert result.targets["switches"] == ("FAB1-S1", "FAB1-S2", "FAB2-S1")


def test_config_actions_controller_00036() -> None:
    """
    # Summary

    Verify resource deploy targets are scoped to each fabric.

    ## Raises

    None
    """
    actions = parse_config_actions(
        params={"config_actions": {"deploy": True, "type": "resource"}},
        raw_args={"config_actions": {"deploy": True, "type": "resource"}},
        policy=RESOURCE_CONFIG_ACTIONS,
    )
    backend = RecordingBackend()
    result = ConfigActionsController(RESOURCE_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(
            fabric_names=("FAB1", "FAB2"),
            resources_by_fabric={
                "FAB1": ("BLUE", "GREEN", "BLUE"),
                "FAB2": ("RED",),
            },
        ),
    )
    assert backend.calls == [
        ("deploy_resources", ("FAB1", ("BLUE", "GREEN"))),
        ("deploy_resources", ("FAB2", ("RED",))),
    ]
    assert result.status == "completed"
    assert result.targets["resources"] == ("BLUE", "GREEN", "RED")


def test_config_actions_controller_00037() -> None:
    """
    # Summary

    Verify flat scoped targets are rejected for multi-fabric deploy.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = RecordingBackend()
    with pytest.raises(ValueError, match="requires switch_ids_by_fabric"):
        ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
            actions,
            ConfigActionsContext(fabric_names=("FAB1", "FAB2"), switch_ids=("FAB1-S1", "FAB2-S1")),
        )
    assert backend.calls == []


def test_config_actions_controller_00038() -> None:
    """
    # Summary

    Verify multi-fabric scoped deploy preserves ordered partial-failure results.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = FabricScopedFailureBackend("FAB2")
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(
            fabric_names=("FAB1", "FAB2"),
            switch_ids_by_fabric={
                "FAB1": ("FAB1-S1",),
                "FAB2": ("FAB2-S1",),
            },
        ),
    )
    assert backend.calls == [
        ("save", ("FAB1", None)),
        ("deploy_switches", ("FAB1", ("FAB1-S1",))),
        ("save", ("FAB2", None)),
        ("deploy_switches", ("FAB2", ("FAB2-S1",))),
    ]
    assert result.status == "failed"
    assert result.reason == "action_failed"
    assert [(step.action, step.target, step.status) for step in result.actions] == [
        ("save", "FAB1", "completed"),
        ("deploy", "FAB1", "completed"),
        ("save", "FAB2", "completed"),
        ("deploy", "FAB2", "failed"),
    ]
    assert result.actions[-1].error == "FAB2 deploy failed"


def test_config_actions_controller_00040() -> None:
    """
    # Summary

    Verify deploy failure preserves the completed save step in the returned result.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = FailingDeployBackend()
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), switch_ids=("SER1",)),
    )
    assert result.status == "failed"
    assert result.reason == "action_failed"
    assert result.actions[0].action == "save"
    assert result.actions[0].status == "completed"
    assert result.actions[1].action == "deploy"
    assert result.actions[1].status == "failed"
    assert result.actions[1].error == "deploy failed"


def test_config_actions_controller_00045() -> None:
    """
    # Summary

    Verify save failures preserve structured backend exception details.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = StructuredFailureBackend("save")
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), switch_ids=("SER1",)),
    )
    step = result.actions[0]
    serialized_step = step.to_result()
    assert result.status == "failed"
    assert result.reason == "action_failed"
    assert step.action == "save"
    assert step.error == "save rejected"
    assert step.error_type == "NDModuleError"
    assert step.http_status == 409
    assert step.request_payload == {"save": "FAB1"}
    assert step.response_payload == {"errors": [{"message": "save conflict"}]}
    assert step.raw == "raw-save-body"
    assert serialized_step["http_status"] == 409
    assert serialized_step["response_payload"] == {"errors": [{"message": "save conflict"}]}


def test_config_actions_controller_00046() -> None:
    """
    # Summary

    Verify deploy failures preserve completed save and structured backend exception details.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = StructuredFailureBackend("deploy")
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), switch_ids=("SER1",)),
    )
    deploy_step = result.actions[1]
    serialized_step = deploy_step.to_result()
    assert result.status == "failed"
    assert result.reason == "action_failed"
    assert result.actions[0].action == "save"
    assert result.actions[0].status == "completed"
    assert deploy_step.action == "deploy"
    assert deploy_step.scope == "switch"
    assert deploy_step.error == "deploy rejected"
    assert deploy_step.error_type == "NDModuleError"
    assert deploy_step.http_status == 500
    assert deploy_step.request_payload == {"switchIds": ["SER1"]}
    assert deploy_step.response_payload == {"errors": [{"message": "deploy failed"}]}
    assert deploy_step.raw == "raw-deploy-body"
    assert serialized_step["http_status"] == 500
    assert serialized_step["request_payload"] == {"switchIds": ["SER1"]}


def test_config_actions_controller_00050() -> None:
    """
    # Summary

    Verify check-mode switch deploy with no targets returns a planned result with a skipped deploy step.

    ## Raises

    None
    """
    actions = parse_config_actions(params={}, raw_args={}, policy=SWITCH_CONFIG_ACTIONS)
    backend = RecordingBackend()
    result = ConfigActionsController(SWITCH_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), check_mode=True),
    )
    assert not backend.calls
    assert result.status == "planned"
    assert result.actions[0].status == "planned"
    assert result.actions[1].status == "skipped"
    assert result.actions[1].error == "no_targets"


def test_config_actions_controller_00060() -> None:
    """
    # Summary

    Verify check mode plans resource deploy when only an item override enables it.

    ## Raises

    None
    """
    actions = parse_config_actions(
        params={
            "config_actions": {"deploy": False, "type": "resource"},
            "config": [{"name": "BLUE", "deploy": True}],
        },
        raw_args={
            "config_actions": {"deploy": False, "type": "resource"},
            "config": [{"name": "BLUE", "deploy": True}],
        },
        policy=RESOURCE_CONFIG_ACTIONS,
    )
    backend = RecordingBackend()
    result = ConfigActionsController(RESOURCE_CONFIG_ACTIONS, backend).execute(
        actions,
        ConfigActionsContext(fabric_names=("FAB1",), check_mode=True, resources=("BLUE",)),
    )
    assert not backend.calls
    assert result.status == "planned"
    assert len(result.actions) == 1
    assert result.actions[0].action == "deploy"
    assert result.actions[0].scope == "resource"
    assert result.actions[0].status == "planned"
