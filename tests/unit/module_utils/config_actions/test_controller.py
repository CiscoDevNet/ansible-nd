# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
# Summary

Unit tests for config_actions.controller.
"""

from __future__ import annotations

from typing import Any

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.controller import ConfigActionsController
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import RESOURCE_CONFIG_ACTIONS, SWITCH_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActionsContext


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
