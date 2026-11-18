# Copyright: (c) 2026, Cisco and contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""VRF resource targets and resource-filtered delete readiness."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager import VrfAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import MultisiteParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator


def _manager(scope="resource"):
    actions = ConfigActions(save=False, deploy=True, type=scope, provided=True)
    coordinator = SimpleNamespace(config_actions=actions)
    return VrfAttachmentManager(coordinator)


@pytest.mark.parametrize("scope", ["resource", "switch"])
def test_vrf_targets_do_not_cross_resource_boundaries(scope):
    manager = _manager(scope)
    config = [{"vrf_name": "BLUE"}, {"vrf_name": "RED"}]
    payloads = manager.build_deploy_payloads(config, {"BLUE": {"SW1", "SW2"}, "RED": {"SW2"}})
    if scope == "resource":
        assert payloads == [
            {"vrfNames": ["BLUE"], "switchIds": ["SW1", "SW2"]},
            {"vrfNames": ["RED"], "switchIds": ["SW2"]},
        ]
    else:
        assert payloads == [{"switchIds": ["SW1", "SW2"]}]


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
def test_pending_resource_definition_selects_its_current_attachments(topology):
    manager = _manager()
    strategy = SimpleNamespace(is_parent=topology != "standalone", is_multisite=topology == "msd", is_multicluster=topology == "mcfg")
    rows = [
        {"vrfName": "BLUE", "switchId": "SW1", "attach": True, "status": "inSync"},
        {"vrfName": "BLUE", "switchId": "SW2", "attach": True, "status": "inSync"},
        {"vrfName": "RED", "switchId": "SW3", "attach": True, "status": "inSync"},
    ]
    queries = []
    manager.coordinator._current_attachment_details = lambda _args, _strategy, names: queries.append(names) or rows
    config = [{"vrf_name": "BLUE"}, {"vrf_name": "RED"}]
    result = {"after": [{"vrf_name": "BLUE", "vrf_status": "pending"}, {"vrf_name": "RED", "vrf_status": "deployed"}]}
    targets = manager.build_pending_vrf_deploy_targets(result, config, {}, strategy, {"BLUE", "RED"})
    assert queries == [["BLUE", "RED"]]
    assert targets == {"BLUE": {"SW1", "SW2"}}
    assert manager.build_deploy_payloads(config, targets) == [{"vrfNames": ["BLUE"], "switchIds": ["SW1", "SW2"]}]


@pytest.mark.parametrize("scope", ["resource", "switch"])
@pytest.mark.parametrize("with_id", [False, True])
def test_delete_readiness_retries_are_resource_filtered_and_never_widen(scope, with_id, monkeypatch):
    manager = _manager(scope)
    strategy = SimpleNamespace(fabric_name="FAB1")
    row = {"vrfName": "BLUE", "attach": False, "status": "pending"}
    if with_id:
        row["switchId"] = "SW1"
    attachment_reads = iter([[row], []])
    vrf_reads = iter([[{"vrfName": "BLUE", "vrfStatus": "pending"}], []])
    manager.current_attachment_details_ignore_missing = lambda *_args: next(attachment_reads)
    manager.coordinator._query_current_vrfs_by_names = lambda *_args: next(vrf_reads)
    calls = []
    manager.deploy_vrf_attachments = lambda _args, _strategy, payload: calls.append(payload)
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager.time.sleep", lambda _seconds: None)

    manager.wait_for_vrfs_delete_ready({"config": [{"vrf_name": "BLUE"}]}, strategy)

    assert calls == ([{"vrfNames": ["BLUE"], "switchIds": ["SW1"]}] if with_id else [])


@pytest.mark.parametrize("top_level_deploy", [False, True])
@pytest.mark.parametrize("state", ["replaced", "staged"])
def test_pre_detach_records_cleanup_targets_when_optional_deploy_is_disabled(top_level_deploy, state):
    manager = _manager()
    manager.coordinator.config_actions = ConfigActions(save=False, deploy=top_level_deploy, type="resource", provided=True, resource_deploy_overrides=(False,))
    row = {"vrfName": "BLUE", "switchId": "SW1", "attach": False}
    manager.coordinator._planned_detach_payloads = lambda *_args: [row]
    manager.coordinator._record_deploy_target = manager.record_deploy_target
    manager.coordinator._post_vrf_attachments = lambda _args, _strategy, _payloads, targets, _operation: {"deploy_targets": targets}

    result = manager.apply_phase(
        {"state": state, "config": [{"vrf_name": "BLUE", "deploy": False}]},
        SimpleNamespace(),
        phase="pre",
        desired={},
        current_vrf_names=["BLUE"],
        current={("BLUE", "SW1"): {"vrfName": "BLUE", "switchId": "SW1", "attach": True}},
        attachment_details=[],
    )

    assert result["deploy_targets"] == {"BLUE": {"SW1"}}


@pytest.mark.parametrize("deferred", [False, True])
@pytest.mark.parametrize("top_level_deploy", [False, True])
def test_disabled_optional_deploy_keeps_detach_resource_scoped_and_deferred(deferred, top_level_deploy):
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import VrfStateMachine

    manager = _manager()
    manager.coordinator.config_actions = ConfigActions(save=False, deploy=top_level_deploy, type="resource", provided=True, resource_deploy_overrides=(False,))
    coordinator = manager.coordinator
    coordinator.module = SimpleNamespace(check_mode=False)
    coordinator._build_detach_deploy_payloads = manager.build_detach_deploy_payloads
    coordinator._build_deploy_payloads = manager.build_deploy_payloads
    coordinator._build_pending_vrf_deploy_targets = lambda *_args: {}
    coordinator._build_pending_vrf_deploy_payloads = lambda *_args: []
    calls = []
    coordinator._deploy_vrf_attachments = lambda _args, _strategy, payload: calls.append(payload) or {"changed": True, "failed": False}
    coordinator._merge_api_trace = lambda _result, _trace: None
    machine = VrfStateMachine(coordinator)
    result = machine._deploy_after_attachment_changes(
        {"changed": True, "failed": False},
        [{"vrf_name": "BLUE", "deploy": False}],
        {"state": "replaced"},
        SimpleNamespace(fabric_name="FAB1"),
        {"deploy_targets": {"BLUE": {"SW1"}}},
        {},
        deferred,
    )
    payload = {"vrfNames": ["BLUE"], "switchIds": ["SW1"]}
    if deferred:
        assert calls == []
        assert result["_deferred_deploy_payloads"] == [{"_vrf_detach_cleanup": True, **payload}]
    else:
        assert calls == [payload]


def test_staged_state_never_runs_pre_detach_deployment():
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import VrfStateMachine

    manager = _manager()
    coordinator = manager.coordinator
    sm = SimpleNamespace(existing=[], manage_state=lambda: None)
    coordinator.strategy = SimpleNamespace()
    coordinator._configured_vrf_names = lambda _config: ["BLUE"]
    coordinator._new_state_machine = lambda *_args: (sm, None, None)
    coordinator._desired_attachment_map = lambda *_args: {}
    coordinator._attachment_map_from_details = lambda *_args: {}
    coordinator._preflight_fabric_features = lambda *_args, **_kwargs: None
    coordinator._apply_attachment_phase = lambda *_args, **kwargs: {"deploy_targets": {"BLUE": {"SW1"}}} if kwargs["phase"] == "pre" else {}
    coordinator._format_state_machine_output = lambda _sm: {"changed": True, "failed": False}
    coordinator._merge_api_trace = lambda *_args, **_kwargs: None
    coordinator._restore_state_machine_params = lambda *_args: None
    machine = VrfStateMachine(coordinator)
    machine._deploy_after_attachment_changes = lambda *_args, **_kwargs: pytest.fail("staged must not deploy detach cleanup")

    result = machine._run_state_machine_aware_with_attachments({"state": "staged", "config": [{"vrf_name": "BLUE"}]}, coordinator.strategy, True)

    assert result["changed"]


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
def test_changed_definition_targets_existing_attached_switch_even_if_status_is_stale(topology):
    manager = _manager()
    strategy = SimpleNamespace(is_parent=topology != "standalone", is_multisite=topology == "msd", is_multicluster=topology == "mcfg")
    rows = [
        {"vrfName": "BLUE", "switchId": "SW1", "attach": True, "status": "inSync"},
        {"vrfName": "RED", "switchId": "SW2", "attach": True, "status": "inSync"},
    ]
    manager.coordinator._current_attachment_details = lambda *_args: rows
    config = [{"vrf_name": "BLUE"}, {"vrf_name": "RED"}]
    result = {"after": [{"vrf_name": "BLUE", "vrf_status": "deployed"}, {"vrf_name": "RED", "vrf_status": "deployed"}]}

    targets = manager.build_pending_vrf_deploy_targets(result, config, {}, strategy, {"BLUE", "RED"}, changed_names={"BLUE"})

    assert targets == {"BLUE": {"SW1"}}
    assert manager.build_deploy_payloads(config, targets) == [{"vrfNames": ["BLUE"], "switchIds": ["SW1"]}]


@pytest.mark.parametrize("scope", ["resource", "switch"])
@pytest.mark.parametrize("attached", [False, True])
def test_in_sync_resource_only_reports_no_targets_when_unattached(scope, attached):
    manager = _manager(scope)
    rows = [{"vrfName": "BLUE", "switchId": "SW1", "attach": True, "status": "inSync"}] if attached else []
    manager.coordinator._current_attachment_details = lambda *_args: rows
    config = [{"vrf_name": "BLUE"}]
    result = {"after": [{"vrf_name": "BLUE", "vrf_status": "deployed"}]}

    targets = manager.build_pending_vrf_deploy_targets(result, config, {}, SimpleNamespace(), {"BLUE"})

    assert targets == ({} if attached else {"BLUE": set()})
    assert manager.build_deploy_payloads(config, targets) == ([] if attached else [{"vrfNames": ["BLUE"]}])


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("scope", ["resource", "switch"])
def test_in_sync_unattached_resource_emits_skipped_no_targets(check_mode, scope):
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import VrfStateMachine
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator

    module = SimpleNamespace(params={"state": "merged", "config": [], "output_level": "normal"}, check_mode=check_mode, _verbosity=0)
    strategy = StandaloneVrfStrategy(fabric_name="FAB1", fabric_data={"managementType": "vxlanIbgp", "members": []})
    coordinator = VrfWorkflowCoordinator(module, strategy)
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type=scope, provided=True)
    coordinator._current_attachment_details = lambda *_args: []
    coordinator._deploy_vrf_attachments = lambda *_args: pytest.fail("unattached VRF must not be deployed")
    coordinator._deploy_vrf_switches = lambda *_args: pytest.fail("unattached VRF must not be deployed")
    config = [{"vrf_name": "BLUE"}]
    result = {"changed": False, "failed": False, "after": [{"vrf_name": "BLUE", "vrf_status": "deployed"}]}

    result = VrfStateMachine(coordinator)._deploy_after_attachment_changes(
        result, config, {"fabric_name": "FAB1", "state": "merged", "config": config}, strategy, {}, {}, False
    )

    assert not result["changed"]
    assert result["config_actions"][0]["status"] == "skipped"
    assert result["config_actions"][0]["reason"] == "no_targets"
    assert not result.get("check_mode_deploy_payloads")


def test_changed_disabled_vrf_does_not_report_unrelated_no_targets():
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import VrfStateMachine
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator

    module = SimpleNamespace(params={"state": "merged", "config": [], "output_level": "normal"}, check_mode=False, _verbosity=0)
    strategy = StandaloneVrfStrategy(fabric_name="FAB1", fabric_data={"managementType": "vxlanIbgp", "members": []})
    coordinator = VrfWorkflowCoordinator(module, strategy)
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True, resource_deploy_overrides=(False, True))
    coordinator._current_attachment_details = lambda *_args: [
        {"vrfName": "BLUE", "switchId": "SW1", "attach": True, "status": "inSync"},
        {"vrfName": "RED", "switchId": "SW2", "attach": True, "status": "inSync"},
    ]
    coordinator._deploy_vrf_attachments = lambda *_args: pytest.fail("disabled or unchanged VRF must not be deployed")
    config = [{"vrf_name": "BLUE", "deploy": False}, {"vrf_name": "RED", "deploy": True}]
    result = {"changed": True, "failed": False, "after": [{"vrf_name": name, "vrf_status": "deployed"} for name in ("BLUE", "RED")]}

    result = VrfStateMachine(coordinator)._deploy_after_attachment_changes(
        result, config, {"fabric_name": "FAB1", "state": "merged", "config": config}, strategy, {}, {}, False, changed_vrf_names={"BLUE"}
    )

    assert result["changed"]
    assert not result.get("config_actions")


@pytest.mark.parametrize("scope", ["resource", "switch"])
@pytest.mark.parametrize(
    ("attached", "status", "expected_targets"),
    [(True, "inSync", {"SW1"}), (False, "na", set()), (False, "notDeployed", set()), (False, "pending", {"SW1"})],
)
def test_pending_definition_ignores_terminal_detached_switches_but_keeps_pending_detach(scope, attached, status, expected_targets):
    manager = _manager(scope)
    row = {"vrfName": "BLUE", "switchId": "SW1", "attach": attached, "status": status}
    manager.coordinator._current_attachment_details = lambda *_args: [row]
    config = [{"vrf_name": "BLUE"}]
    result = {"after": [{"vrf_name": "BLUE", "vrf_status": "pending"}]}

    targets = manager.build_pending_vrf_deploy_targets(result, config, {}, SimpleNamespace(), {"BLUE"})

    assert targets == {"BLUE": expected_targets}
    if expected_targets:
        assert manager.build_deploy_payloads(config, targets) == (
            [{"vrfNames": ["BLUE"], "switchIds": ["SW1"]}] if scope == "resource" else [{"switchIds": ["SW1"]}]
        )
    else:
        assert manager.build_deploy_payloads(config, targets) == [{"vrfNames": ["BLUE"]}]


def test_pending_unattached_vrf_before_delete_does_not_send_placeholder():
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import VrfStateMachine

    coordinator = SimpleNamespace(
        module=SimpleNamespace(check_mode=False),
        _build_pending_vrf_deploy_payloads=lambda *_args, **_kwargs: [{"vrfNames": ["BLUE"]}],
        _deploy_vrf_attachments=lambda *_args: pytest.fail("unattached VRF must not be deployed"),
        _wait_for_vrfs_delete_ready=lambda *_args: pytest.fail("nothing was deployed to wait for"),
    )
    model = SimpleNamespace(to_config=lambda: {"vrf_name": "BLUE", "vrf_status": "pending"})

    traces = VrfStateMachine(coordinator)._deploy_pending_vrfs_before_delete({}, SimpleNamespace(), [model], ["BLUE"])

    assert traces == []


def _module(check_mode=False, params=None):
    return SimpleNamespace(params=params or {"state": "merged", "config": []}, check_mode=check_mode, _verbosity=0, fail_json=Mock())


def test_invalid_per_item_deploy_is_rejected_before_the_vrf_workflow(monkeypatch):
    args = {"fabric_name": "FAB1", "state": "merged", "config_actions": {"type": "switch"}, "config": [{"vrf_name": "BLUE", "deploy": False}]}
    module = _module(params=args)
    coordinator = VrfWorkflowCoordinator(module, SimpleNamespace())
    coordinator._handle_standalone_workflow = Mock()
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator.get_raw_module_args", lambda: args)

    with pytest.raises(ValueError, match="allowed only when config_actions.type='resource'"):
        coordinator.run()

    assert module.fail_json.call_count == 1
    assert "Invalid config_actions" in module.fail_json.call_args.kwargs["msg"]
    coordinator._handle_standalone_workflow.assert_not_called()


def test_merged_workflow_does_not_append_staged_action_result(monkeypatch):
    args = {"fabric_name": "FAB1", "state": "merged", "config": []}
    module = _module(params=args)
    strategy = SimpleNamespace(fabric_type="standalone", is_child=False, is_parent=False)
    coordinator = VrfWorkflowCoordinator(module, strategy)
    coordinator._validate_topology_argument_scope = Mock()
    coordinator._handle_standalone_workflow = Mock(return_value={"changed": False, "failed": False})
    monkeypatch.setattr("ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator.get_raw_module_args", lambda: args)

    result = coordinator.run()

    assert result == {"changed": False, "failed": False}
    coordinator._handle_standalone_workflow.assert_called_once_with(args, "standalone")


@pytest.mark.parametrize("check_mode", [False, True])
def test_switch_deploy_facade_only_calls_endpoint_outside_check_mode(check_mode):
    module = _module(check_mode=check_mode)
    coordinator = VrfWorkflowCoordinator(module, SimpleNamespace(fabric_name="FAB1"))
    coordinator.attachments.deploy_vrf_switches = Mock(return_value={"changed": True, "failed": False})
    payload = {"switchIds": ["SW1", "SW2"]}

    result = coordinator._deploy_vrf_switches(module.params, coordinator.strategy, payload)

    if check_mode:
        assert result == {"changed": True, "failed": False, "check_mode_deploy_payloads": [payload]}
        coordinator.attachments.deploy_vrf_switches.assert_not_called()
    else:
        assert result == {"changed": True, "failed": False}
        coordinator.attachments.deploy_vrf_switches.assert_called_once_with(module.params, coordinator.strategy, payload)


def test_controller_deploy_failure_is_reported_by_vrf_facade():
    module = _module()
    coordinator = VrfWorkflowCoordinator(module, SimpleNamespace(fabric_name="FAB1"))
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)
    coordinator._deploy_vrf_attachments = Mock(side_effect=RuntimeError("controller rejected VRF deployment"))

    with pytest.raises(RuntimeError, match="VRF config action deploy failed: controller rejected VRF deployment"):
        coordinator._run_vrf_config_actions(module.params, coordinator.strategy, {"vrfNames": ["BLUE"], "switchIds": ["SW1"]})


@pytest.mark.parametrize("targets", [{"BLUE": set()}, {"BLUE": {""}}, {"": {"SW1"}}])
def test_vrf_detach_cleanup_rejects_missing_resource_or_switch_targets(targets):
    with pytest.raises(ValueError, match="without VRF names and affected switch IDs"):
        VrfAttachmentManager.build_detach_deploy_payloads(targets)


def test_vrf_switch_deploy_rejects_missing_switch_targets_without_endpoint_request():
    coordinator = SimpleNamespace(_new_vrf_orchestrator=Mock())
    manager = VrfAttachmentManager(coordinator)
    with pytest.raises(ValueError, match="requires affected switch IDs"):
        manager.deploy_vrf_switches({}, SimpleNamespace(), {"switchIds": []})
    coordinator._new_vrf_orchestrator.assert_not_called()


def test_pending_vrf_attachment_without_switch_id_is_not_deployed():
    coordinator = SimpleNamespace(config_actions=ConfigActions(save=False, deploy=True, type="resource", provided=True))
    coordinator._current_attachment_details = lambda *_args: [{"vrfName": "BLUE", "attach": True, "status": "pending"}]
    manager = VrfAttachmentManager(coordinator)
    config = [{"vrf_name": "BLUE"}]
    result = {"after": [{"vrf_name": "BLUE", "vrf_status": "pending"}]}

    targets = manager.build_pending_vrf_deploy_targets(result, config, {}, SimpleNamespace())

    assert targets == {"BLUE": set()}
    assert manager.build_deploy_payloads(config, targets) == [{"vrfNames": ["BLUE"]}]


def test_parent_check_mode_reports_deferred_detach_without_calling_deploy():
    args = {"fabric_name": "PARENT", "state": "replaced", "config": [{"vrf_name": "BLUE"}], "output_level": "normal"}
    module = _module(check_mode=True, params=args)
    strategy = MultisiteParentVrfStrategy(fabric_name="PARENT", fabric_data={"managementType": "vxlanIbgp", "members": []})
    coordinator = VrfWorkflowCoordinator(module, strategy)
    coordinator._parse_config = lambda entries, *_args: entries
    coordinator._preflight_child_feature_tasks = Mock()
    coordinator._run_state_machine_with_attachments = Mock(
        return_value={
            "changed": True,
            "failed": False,
            "_deferred_deploy_payloads": [{"_vrf_detach_cleanup": True, "vrfNames": ["BLUE"], "switchIds": ["SW1"]}],
        }
    )
    coordinator._deploy_vrf_attachments = Mock()
    coordinator._run_vrf_config_actions = Mock()

    result = coordinator._handle_parent_workflow(args, strategy.fabric_type)

    assert result["check_mode_deploy_payloads"] == [{"vrfNames": ["BLUE"], "switchIds": ["SW1"]}]
    coordinator._deploy_vrf_attachments.assert_not_called()
    coordinator._run_vrf_config_actions.assert_not_called()
