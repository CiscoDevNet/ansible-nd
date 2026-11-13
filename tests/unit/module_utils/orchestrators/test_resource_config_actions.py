# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Tests for VRF/Network adapters to the common config-actions controller."""

from __future__ import annotations

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions, ConfigActionsContext
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.parser import parse_config_actions
from ansible_collections.cisco.nd.plugins.module_utils.config_actions.policies import RESOURCE_CONFIG_ACTIONS
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.config_actions.backends.resource import ResourceConfigActionsBackend
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator


class _Module:
    def __init__(self, check_mode: bool = False) -> None:
        self.params = {"state": "merged", "config": []}
        self.check_mode = check_mode
        self._verbosity = 0

    def fail_json(self, **kwargs):
        raise AssertionError(kwargs)


class _Strategy:
    fabric_name = "fab1"
    fabric_type = "standalone"
    is_child = False
    is_parent = False


def test_resource_backend_builds_switch_and_resource_payloads():
    payloads = []
    backend = ResourceConfigActionsBackend("vrfNames", payloads.append)
    context = ConfigActionsContext(fabric_names=("fab1",), resources=("BLUE",))

    backend.deploy_switches(context, "fab1", ("SERIAL1",))
    backend.deploy_resources(context, "fab1", ("BLUE",))
    attached_resource_context = ConfigActionsContext(fabric_names=("fab1",), resources=("GREEN",), switch_ids=("SERIAL2",))
    backend.deploy_resources(attached_resource_context, "fab1", ("GREEN",))
    switch_only_calls = []
    switch_backend = ResourceConfigActionsBackend("networkNames", payloads.append, switch_deploy=switch_only_calls.append)
    switch_backend.deploy_switches(attached_resource_context, "fab1", ("SERIAL2",))

    assert payloads == [
        {"vrfNames": ["BLUE"], "switchIds": ["SERIAL1"]},
        {"vrfNames": ["BLUE"]},
        {"vrfNames": ["GREEN"], "switchIds": ["SERIAL2"]},
    ]
    assert switch_only_calls == [{"switchIds": ["SERIAL2"]}]
    with pytest.raises(ValueError, match="save is not supported"):
        backend.save(context, "fab1")
    with pytest.raises(ValueError, match="global deploy is not supported"):
        backend.deploy_global(context, "fab1")


def test_resource_policy_defaults_to_deploy_by_resource_name():
    actions = parse_config_actions(params={}, raw_args={}, policy=RESOURCE_CONFIG_ACTIONS)

    assert actions.deploy is True
    assert actions.type == "resource"


def test_item_deploy_override_is_rejected_for_switch_scope_before_mutation():
    with pytest.raises(ValueError, match="allowed only when config_actions.type='resource'"):
        parse_config_actions(
            params={"config_actions": {"deploy": True, "type": "switch"}, "config": [{"vrf_name": "BLUE", "deploy": False}]},
            raw_args={"config_actions": {"deploy": True, "type": "switch"}, "config": [{"vrf_name": "BLUE", "deploy": False}]},
            policy=RESOURCE_CONFIG_ACTIONS,
        )


def test_vrf_switch_deploy_runs_through_common_controller():
    coordinator = VrfWorkflowCoordinator(module=_Module(), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="switch", provided=True)
    payloads = []
    coordinator._deploy_vrf_switches = lambda _args, _strategy, payload: payloads.append(payload) or {"changed": True, "failed": False}

    trace = coordinator._run_vrf_config_actions(
        {"state": "merged"},
        coordinator.strategy,
        {"vrfNames": ["BLUE"], "switchIds": ["SERIAL1"]},
    )

    assert payloads == [{"switchIds": ["SERIAL1"]}]
    assert trace["config_actions"][0]["status"] == "completed"
    assert trace["config_actions"][0]["targets"] == {
        "fabrics": ["fab1"],
        "switches": ["SERIAL1"],
        "resources": ["BLUE"],
    }


def test_vrf_switch_deploy_check_mode_plans_switch_ids_only():
    coordinator = VrfWorkflowCoordinator(module=_Module(check_mode=True), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="switch", provided=True)
    coordinator._deploy_vrf_switches = lambda *_args: pytest.fail("check mode must not call the deploy endpoint")

    trace = coordinator._run_vrf_config_actions(
        {"state": "merged"},
        coordinator.strategy,
        {"switchIds": ["SERIAL1", "SERIAL2"]},
    )

    assert trace["check_mode_deploy_payloads"] == [{"switchIds": ["SERIAL1", "SERIAL2"]}]
    assert trace["config_actions"][0]["status"] == "planned"


def test_network_resource_deploy_is_planned_in_check_mode():
    coordinator = NetworkWorkflowCoordinator(module=_Module(check_mode=True), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)
    coordinator._deploy_network_attachments = lambda *_args: pytest.fail("check mode must not call the deploy endpoint")
    payload = {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]}

    trace = coordinator._run_network_config_actions({"state": "merged"}, coordinator.strategy, payload)

    assert trace["changed"] is True
    assert trace["check_mode_deploy_payloads"] == [payload]
    assert trace["config_actions"][0]["status"] == "planned"


def test_network_switch_scope_deploy_sends_only_switch_ids():
    coordinator = NetworkWorkflowCoordinator(module=_Module(), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="switch", provided=True)
    payloads = []
    coordinator._deploy_network_switches = lambda _args, _strategy, payload: payloads.append(payload) or {"changed": True, "failed": False}

    trace = coordinator._run_network_config_actions(
        {"state": "merged"},
        coordinator.strategy,
        {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]},
    )

    assert payloads == [{"switchIds": ["SERIAL1"]}]
    assert trace["config_actions"][0]["status"] == "completed"


def test_switch_deploy_without_targets_is_a_structured_skip():
    coordinator = NetworkWorkflowCoordinator(module=_Module(), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="switch", provided=True)
    coordinator._deploy_network_attachments = lambda *_args: pytest.fail("no-target switch deploy must not call the endpoint")

    trace = coordinator._run_network_config_actions({"state": "merged"}, coordinator.strategy, {"networkNames": ["BLUE_NET"]})

    assert trace["config_actions"][0]["status"] == "skipped"
    assert trace["config_actions"][0]["reason"] == "no_targets"
    assert trace["config_actions"][0]["actions"][0]["error"] == "no_targets"


@pytest.mark.parametrize("coordinator_class,payload_key", [(NetworkWorkflowCoordinator, "networkNames"), (VrfWorkflowCoordinator, "vrfNames")])
@pytest.mark.parametrize("check_mode", [False, True])
def test_resource_deploy_without_attachments_is_a_structured_skip(coordinator_class, payload_key, check_mode):
    coordinator = coordinator_class(module=_Module(check_mode=check_mode), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=False)
    if payload_key == "networkNames":
        coordinator._deploy_network_attachments = lambda *_args: pytest.fail("unattached Network must not invoke endpoint")
        run = coordinator._run_network_config_actions
    else:
        coordinator._deploy_vrf_attachments = lambda *_args: pytest.fail("unattached VRF must not invoke endpoint")
        run = coordinator._run_vrf_config_actions

    trace = run({"state": "merged"}, coordinator.strategy, {payload_key: ["BLUE"]})

    assert trace["config_actions"][0]["status"] == "skipped"
    assert trace["config_actions"][0]["reason"] == "no_targets"
    assert not trace.get("check_mode_deploy_payloads")


def test_network_backend_failure_is_preserved_by_controller_facade():
    coordinator = NetworkWorkflowCoordinator(module=_Module(), strategy=_Strategy())
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)

    def fail(*_args):
        raise RuntimeError("controller rejected deploy")

    coordinator._deploy_network_attachments = fail
    with pytest.raises(RuntimeError, match="Network config action deploy failed: controller rejected deploy"):
        coordinator._run_network_config_actions(
            {"state": "merged"},
            coordinator.strategy,
            {"networkNames": ["BLUE_NET"], "switchIds": ["SERIAL1"]},
        )


@pytest.mark.parametrize("coordinator_class", [VrfWorkflowCoordinator, NetworkWorkflowCoordinator])
def test_staged_state_reports_shared_config_action_skip(coordinator_class):
    module = _Module()
    module.params.update(fabric_name="fab1", state="staged")
    coordinator = coordinator_class(module=module, strategy=_Strategy())
    coordinator._handle_standalone_workflow = lambda *_args: {"changed": True, "failed": False}

    result = coordinator.run()

    assert result["config_actions"][0]["status"] == "skipped"
    assert result["config_actions"][0]["reason"] == "staged_state"
