# Copyright: (c) 2026, Cisco and contributors
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Regression coverage for requested VRF and Network switch deploy targets."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.config_actions.types import ConfigActions
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_state_machine import NetworkStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import MulticlusterParentNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import MulticlusterParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import MultisiteParentNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import MultisiteParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_state_machine import VrfStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator


class _Module:
    def __init__(self, check_mode: bool):
        self.params = {"state": "merged", "config": [], "output_level": "normal"}
        self.check_mode = check_mode
        self._verbosity = 0

    @staticmethod
    def fail_json(**kwargs):
        raise AssertionError(kwargs)


_STRATEGIES = {
    "vrf": {
        "standalone": StandaloneVrfStrategy,
        "msd": MultisiteParentVrfStrategy,
        "mcfg": MulticlusterParentVrfStrategy,
    },
    "network": {
        "standalone": StandaloneNetworkStrategy,
        "msd": MultisiteParentNetworkStrategy,
        "mcfg": MulticlusterParentNetworkStrategy,
    },
}


def _attachment(kind: str, name: str, switch_id: str, peer: str | None = None) -> dict:
    row = {f"{kind}Name": name, "switchId": switch_id, "attach": True, "status": "pending"}
    if peer:
        row["peerSwitchId"] = peer
    return row


def _requested(kind: str, *pairs: tuple[str, str]) -> dict:
    return {(name, switch_id): _attachment(kind, name, switch_id) for name, switch_id in pairs}


def _case(kind: str, topology: str, check_mode: bool, rows: list[dict]):
    """Use real planning and controller code with in-memory controller reads."""
    module = _Module(check_mode)
    strategy = _STRATEGIES[kind][topology](fabric_name="FAB1", fabric_data={"managementType": "vxlanIbgp", "members": []})
    coordinator_cls = VrfWorkflowCoordinator if kind == "vrf" else NetworkWorkflowCoordinator
    machine_cls = VrfStateMachine if kind == "vrf" else NetworkStateMachine
    coordinator = coordinator_cls(module, strategy)
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="switch", provided=True)
    switch_calls = []
    attachment_deploy_calls = []
    coordinator._test_deploy_order = []

    def current_attachments(*_args, **_kwargs):
        return deepcopy(rows)

    def switch_deploy(_args, _strategy, payload):
        switch_calls.append(deepcopy(payload))
        coordinator._test_deploy_order.append(("switch", deepcopy(payload)))
        return {"changed": True, "failed": False}

    def attachment_deploy(_args, _strategy, payload, **kwargs):
        attachment_deploy_calls.append((deepcopy(payload), kwargs))
        coordinator._test_deploy_order.append(("attachment", deepcopy(payload), kwargs))
        return {"changed": True, "failed": False}

    def no_attachment_post(*_args, **_kwargs):
        pytest.fail("idempotent merged attachment must not be changed")

    switch_ids_by_ip = {"192.0.2.1": "SW1", "192.0.2.2": "SW2", "192.0.2.3": "SW3", "192.0.2.4": "SW4"}
    coordinator._current_attachment_details = current_attachments
    coordinator._current_attachment_details_ignore_missing = current_attachments
    if kind == "vrf":
        coordinator._resolve_switch_ids = lambda *_args: switch_ids_by_ip
        coordinator._post_vrf_attachments = no_attachment_post
        coordinator._deploy_vrf_switches = switch_deploy
        coordinator._deploy_vrf_attachments = attachment_deploy
    else:
        coordinator.attachments.current_attachment_details = current_attachments
        coordinator.attachments.current_attachment_details_ignore_missing = current_attachments
        coordinator.attachments.resolve_switch_ids = lambda *_args: switch_ids_by_ip
        coordinator.attachments.post_network_attachments = no_attachment_post
        coordinator._deploy_network_switches = switch_deploy
        coordinator._deploy_network_attachments = attachment_deploy
        coordinator._query_current_networks_with_trace = lambda *_args: ([], {"changed": False, "failed": False})
    return coordinator, machine_cls(coordinator), strategy, switch_calls, attachment_deploy_calls


def _result(kind: str, *names: str) -> dict:
    return {
        "changed": False,
        "failed": False,
        "after": [{f"{kind}_name": name, f"{kind}_status": "pending"} for name in names],
    }


def _assert_switch_payload(result: dict, switch_calls: list, ids: list[str], mode: str) -> None:
    payload = {"switchIds": ids}
    if mode == "check":
        assert switch_calls == []
        assert result["check_mode_deploy_payloads"] == [payload]
    elif mode == "deferred":
        assert switch_calls == []
        assert result["_deferred_deploy_payloads"] == [payload]
    else:
        assert switch_calls == [payload]


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize(
    ("topology", "mode"),
    [
        ("standalone", "normal"),
        ("standalone", "check"),
        ("msd", "normal"),
        ("msd", "check"),
        ("msd", "deferred"),
        ("mcfg", "normal"),
        ("mcfg", "check"),
        ("mcfg", "deferred"),
    ],
)
def test_pending_resource_deploys_only_the_switch_in_the_current_task(kind, topology, mode):
    rows = [_attachment(kind, "BLUE", "SW1", "SW2"), _attachment(kind, "BLUE", "SW2", "SW1")]
    before = deepcopy(rows)
    coordinator, machine, strategy, switch_calls, attachment_deploy_calls = _case(kind, topology, mode == "check", rows)
    config = [{f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}]
    module_args = {"fabric_name": "FAB1", "state": "merged", "config": config}
    coordinator.module.params.update(module_args)

    class Crud:
        existing = [SimpleNamespace(**{f"{kind}_name": "BLUE"})]

        @staticmethod
        def manage_state():
            pass

    coordinator._new_state_machine = lambda *_args: (Crud(), None, None)
    coordinator._preflight_fabric_features = lambda *_args, **_kwargs: None
    coordinator._format_state_machine_output = lambda _sm: _result(kind, "BLUE")
    coordinator._restore_state_machine_params = lambda *_args: None

    result = machine.run(module_args, strategy, defer_deploy=mode == "deferred")

    _assert_switch_payload(result, switch_calls, ["SW1"], mode)
    assert attachment_deploy_calls == []
    assert rows == before


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_new_attachment_and_other_pending_resource_share_one_scoped_deploy(kind, check_mode):
    rows = [
        _attachment(kind, "BLUE", "SW1"),
        _attachment(kind, "BLUE", "SW2"),
        _attachment(kind, "RED", "SW3"),
        _attachment(kind, "RED", "SW4"),
    ]
    coordinator, machine, strategy, switch_calls, _attachment_calls = _case(kind, "standalone", check_mode, rows)
    config = [
        {f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]},
        {f"{kind}_name": "RED", "attach": [{"ip_address": "192.0.2.3"}]},
    ]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(
        _result(kind, "BLUE", "RED"),
        config,
        args,
        strategy,
        {},
        {"deploy_targets": {"BLUE": {"SW1"}}},
        False,
        requested_attachments=_requested(kind, ("BLUE", "SW1"), ("RED", "SW3")),
    )

    _assert_switch_payload(result, switch_calls, ["SW1", "SW3"], "check" if check_mode else "normal")


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_does_not_deploy_in_sync_requested_switch_for_another_pending_switch(kind, check_mode):
    rows = [_attachment(kind, "BLUE", "SW1"), _attachment(kind, "BLUE", "SW2")]
    rows[0]["status"] = "inSync"
    _coordinator, machine, strategy, switch_calls, attachment_deploy_calls = _case(kind, "standalone", check_mode, rows)
    config = [{f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}
    existing = {"changed": False, "failed": False, "after": [{f"{kind}_name": "BLUE", f"{kind}_status": "deployed"}]}

    result = machine._deploy_after_attachment_changes(existing, config, args, strategy, {}, {}, False, requested_attachments=_requested(kind, ("BLUE", "SW1")))

    assert result["changed"] is False
    assert switch_calls == []
    assert attachment_deploy_calls == []
    assert not result.get("check_mode_deploy_payloads")
    assert result["config_actions"][0]["status"] == "skipped"
    assert result["config_actions"][0]["reason"] == "no_targets"


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_resource_without_attach_does_not_widen_an_explicit_task_switch_selection(kind, check_mode):
    rows = [
        _attachment(kind, "BLUE", "SW1"),
        _attachment(kind, "BLUE", "SW2"),
        _attachment(kind, "RED", "SW1"),
        _attachment(kind, "RED", "SW2"),
    ]
    _coordinator, machine, strategy, switch_calls, _attachment_calls = _case(kind, "standalone", check_mode, rows)
    config = [{f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}, {f"{kind}_name": "RED"}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(
        _result(kind, "BLUE", "RED"), config, args, strategy, {}, {}, False, requested_attachments=_requested(kind, ("BLUE", "SW1"))
    )

    _assert_switch_payload(result, switch_calls, ["SW1"], "check" if check_mode else "normal")


@pytest.mark.parametrize("kind", ["vrf", "network"])
def test_vpc_peer_in_attachment_changes_is_not_an_unrequested_deploy_target(kind):
    rows = [_attachment(kind, "BLUE", "SW1", "SW2"), _attachment(kind, "BLUE", "SW2", "SW1")]
    _coordinator, machine, strategy, switch_calls, _attachment_calls = _case(kind, "standalone", False, rows)
    config = [{f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(
        _result(kind, "BLUE"),
        config,
        args,
        strategy,
        {},
        {"deploy_targets": {"BLUE": {"SW1", "SW2"}}},
        False,
        requested_attachments=_requested(kind, ("BLUE", "SW1")),
    )

    _assert_switch_payload(result, switch_calls, ["SW1"], "normal")


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_detach_only_deployment_keeps_the_detached_switch(kind, check_mode):
    _coordinator, machine, strategy, switch_calls, attachment_deploy_calls = _case(kind, "standalone", check_mode, [])
    config = [{f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}]
    args = {"fabric_name": "FAB1", "state": "replaced", "config": config}

    result = machine._deploy_after_attachment_changes(
        {"changed": True, "failed": False, "after": []},
        config,
        args,
        strategy,
        {"deploy_targets": {"BLUE": {"SW2"}}},
        {},
        False,
        requested_attachments=_requested(kind, ("BLUE", "SW1")),
    )

    payload = {f"{kind}Names": ["BLUE"], "switchIds": ["SW2"]}
    assert switch_calls == []
    if check_mode:
        assert attachment_deploy_calls == []
        assert result["check_mode_deploy_payloads"] == [payload]
    else:
        expected_kwargs = {"undeploy": True} if kind == "network" else {}
        assert attachment_deploy_calls == [(payload, expected_kwargs)]


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("mode", ["normal", "check", "deferred"])
def test_detach_cleanup_precedes_deploy_for_an_already_attached_pending_switch(kind, mode):
    detached = _attachment(kind, "BLUE", "SW2")
    detached["attach"] = False
    rows = [_attachment(kind, "BLUE", "SW1"), detached]
    coordinator, machine, strategy, switch_calls, attachment_calls = _case(kind, "msd", mode == "check", rows)
    config = [{f"{kind}_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}]
    args = {"fabric_name": "FAB1", "state": "replaced", "config": config}

    result = machine._deploy_after_attachment_changes(
        _result(kind, "BLUE"),
        config,
        args,
        strategy,
        {"deploy_targets": {"BLUE": {"SW2"}}},
        {},
        mode == "deferred",
        requested_attachments=_requested(kind, ("BLUE", "SW1")),
    )

    cleanup = {f"{kind}Names": ["BLUE"], "switchIds": ["SW2"]}
    deploy = {"switchIds": ["SW1"]}
    if mode == "deferred":
        marker = "_vrf_detach_cleanup" if kind == "vrf" else "_undeploy"
        assert result["_deferred_deploy_payloads"] == [{marker: True, **cleanup}, deploy]
        assert switch_calls == attachment_calls == []
    elif mode == "check":
        assert result["check_mode_deploy_payloads"] == [cleanup, deploy]
        assert switch_calls == attachment_calls == []
    else:
        cleanup_kwargs = {"undeploy": True} if kind == "network" else {}
        assert coordinator._test_deploy_order == [("attachment", cleanup, cleanup_kwargs), ("switch", deploy)]


@pytest.mark.parametrize("mode", ["normal", "check", "deferred"])
def test_network_detach_does_not_hide_pending_work_for_another_requested_network(mode):
    detached = _attachment("network", "BLUE", "SW2")
    detached["attach"] = False
    rows = [detached, _attachment("network", "RED", "SW1"), _attachment("network", "RED", "SW3")]
    coordinator, machine, strategy, switch_calls, attachment_calls = _case("network", "msd", mode == "check", rows)
    config = [{"network_name": "BLUE"}, {"network_name": "RED", "attach": [{"ip_address": "192.0.2.1"}]}]
    args = {"fabric_name": "FAB1", "state": "replaced", "config": config}

    result = machine._deploy_after_attachment_changes(
        _result("network", "BLUE", "RED"),
        config,
        args,
        strategy,
        {"deploy_targets": {"BLUE": {"SW2"}}},
        {},
        mode == "deferred",
        requested_attachments=_requested("network", ("RED", "SW1")),
    )

    cleanup = {"networkNames": ["BLUE"], "switchIds": ["SW2"]}
    deploy = {"switchIds": ["SW1"]}
    if mode == "deferred":
        assert result["_deferred_deploy_payloads"] == [{"_undeploy": True, **cleanup}, deploy]
        assert switch_calls == attachment_calls == []
    elif mode == "check":
        assert result["check_mode_deploy_payloads"] == [cleanup, deploy]
        assert switch_calls == attachment_calls == []
    else:
        assert coordinator._test_deploy_order == [("attachment", cleanup, {"undeploy": True}), ("switch", deploy)]


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("topology", ["msd", "mcfg"])
def test_parent_dispatches_real_deferred_cleanup_after_child_before_selected_switch(kind, topology):
    detached = _attachment(kind, "BLUE", "SW2")
    detached["attach"] = False
    rows = [_attachment(kind, "BLUE", "SW1"), detached]
    coordinator, machine, strategy, _switch_calls, _attachment_calls = _case(kind, topology, False, rows)
    strategy.fabric_data["members"] = [{"fabricName": "CHILD"}]
    child_option = {"l3vni_wo_vlan": True} if kind == "vrf" else {"multicast_group_address": "239.1.1.53"}
    config = [
        {
            f"{kind}_name": "BLUE",
            "attach": [{"ip_address": "192.0.2.1"}],
            "child_fabric_config": [{"fabric_name": "CHILD", **child_option}],
        }
    ]
    args = {"fabric_name": "FAB1", "state": "replaced", "config": config}
    coordinator.module.params.update(args)
    coordinator._parse_config = lambda entries, *_args: deepcopy(entries)
    coordinator._preflight_child_feature_tasks = lambda *_args: None
    if kind == "network":
        coordinator._validate_parent_network_capabilities = lambda *_args: None

    def add_child(_parent, _child, tasks, _data, _state):
        tasks["CHILD"] = {"fabric": "CHILD", "module_args": {"config": []}}
        return tasks

    def run_parent(parent_args, defer_deploy=False):
        assert defer_deploy
        return machine._deploy_after_attachment_changes(
            _result(kind, "BLUE"),
            parent_args["config"],
            parent_args,
            strategy,
            {"deploy_targets": {"BLUE": {"SW2"}}},
            {},
            defer_deploy,
            requested_attachments=_requested(kind, ("BLUE", "SW1")),
        )

    def run_child(_task):
        coordinator._test_deploy_order.append(("child",))
        return {"changed": False, "failed": False, "before": [], "after": [], "diff": [], "fabric_type": "child"}

    coordinator._accumulate_child_task = add_child
    coordinator._run_state_machine_with_attachments = run_parent
    coordinator._run_child_task = run_child

    result = coordinator._handle_parent_workflow(args, strategy.fabric_type)

    cleanup = {f"{kind}Names": ["BLUE"], "switchIds": ["SW2"]}
    cleanup_kwargs = {"undeploy": True} if kind == "network" else {}
    assert not result.get("failed", False)
    assert coordinator._test_deploy_order == [("child",), ("attachment", cleanup, cleanup_kwargs), ("switch", {"switchIds": ["SW1"]})]


@pytest.mark.parametrize("deferred", [False, True])
def test_failed_vrf_detach_cleanup_stops_optional_switch_deploy(deferred):
    """A failed resource-scoped cleanup must stop the subsequent switch deploy."""
    rows = [_attachment("vrf", "BLUE", "SW1")]
    coordinator, machine, strategy, switch_calls, _attachment_calls = _case("vrf", "msd", False, rows)
    config = [{"vrf_name": "BLUE", "attach": [{"ip_address": "192.0.2.1"}]}]
    args = {"fabric_name": "FAB1", "state": "replaced", "config": config}
    coordinator.module.params.update(args)
    cleanup_calls = []

    def fail_cleanup(_args, _strategy, payload):
        cleanup_calls.append(payload)
        return {"changed": False, "failed": True}

    coordinator._deploy_vrf_attachments = fail_cleanup

    def plan(parent_args, defer_deploy=False):
        return machine._deploy_after_attachment_changes(
            _result("vrf", "BLUE"),
            parent_args["config"],
            parent_args,
            strategy,
            {"deploy_targets": {"BLUE": {"SW2"}}},
            {},
            defer_deploy,
            requested_attachments=_requested("vrf", ("BLUE", "SW1")),
        )

    if deferred:
        coordinator._parse_config = lambda entries, *_args: deepcopy(entries)
        coordinator._preflight_child_feature_tasks = lambda *_args: None
        coordinator._run_state_machine_with_attachments = plan
        result = coordinator._handle_parent_workflow(args, strategy.fabric_type)
    else:
        result = plan(args)

    assert result["failed"] is True
    assert cleanup_calls == [{"vrfNames": ["BLUE"], "switchIds": ["SW2"]}]
    assert switch_calls == []


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("status", ["inSync", None])
def test_pending_network_definition_without_attach_targets_current_attached_switches(check_mode, status):
    rows = [_attachment("network", "BLUE", "SW1"), _attachment("network", "BLUE", "SW2")]
    for row in rows:
        if status is None:
            row.pop("status")
        else:
            row["status"] = status
    _coordinator, machine, strategy, switch_calls, _attachment_calls = _case("network", "standalone", check_mode, rows)
    config = [{"network_name": "BLUE"}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(_result("network", "BLUE"), config, args, strategy, {}, {}, False)

    _assert_switch_payload(result, switch_calls, ["SW1", "SW2"], "check" if check_mode else "normal")


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
def test_pending_network_resource_scope_includes_attached_switches_when_attachments_are_in_sync(check_mode, topology):
    rows = [_attachment("network", "BLUE", "SW1"), _attachment("network", "BLUE", "SW2")]
    for row in rows:
        row["status"] = "inSync"
    coordinator, machine, strategy, switch_calls, attachment_calls = _case("network", topology, check_mode, rows)
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)
    config = [{"network_name": "BLUE"}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(_result("network", "BLUE"), config, args, strategy, {}, {}, False)

    payload = {"networkNames": ["BLUE"], "switchIds": ["SW1", "SW2"]}
    assert switch_calls == []
    if check_mode:
        assert attachment_calls == []
        assert result["check_mode_deploy_payloads"] == [payload]
    else:
        assert attachment_calls == [(payload, {})]


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("include_pending_detach", [False, True])
def test_pending_vrf_resource_scope_keeps_attachment_targets(check_mode, topology, include_pending_detach):
    rows = [_attachment("vrf", "BLUE", "SW1"), _attachment("vrf", "BLUE", "SW2")]
    for row in rows:
        row["status"] = "inSync"
    if include_pending_detach:
        pending_detach = _attachment("vrf", "BLUE", "SW3")
        pending_detach["attach"] = False
        rows.append(pending_detach)
    coordinator, machine, strategy, switch_calls, attachment_calls = _case("vrf", topology, check_mode, rows)
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)
    config = [{"vrf_name": "BLUE"}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(_result("vrf", "BLUE"), config, args, strategy, {}, {}, False)

    payload = {"vrfNames": ["BLUE"], "switchIds": ["SW1", "SW2"] + (["SW3"] if include_pending_detach else [])}
    assert switch_calls == []
    if check_mode:
        assert attachment_calls == []
        assert result["check_mode_deploy_payloads"] == [payload]
    else:
        assert attachment_calls == [(payload, {})]


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_pending_unattached_resource_scope_skips_deploy(kind, topology, check_mode):
    coordinator, machine, strategy, switch_calls, attachment_calls = _case(kind, topology, check_mode, [])
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)
    config = [{f"{kind}_name": "BLUE"}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(_result(kind, "BLUE"), config, args, strategy, {}, {}, False)

    assert switch_calls == []
    assert attachment_calls == []
    assert not result.get("check_mode_deploy_payloads")
    assert result["config_actions"][0]["status"] == "skipped"
    assert result["config_actions"][0]["reason"] == "no_targets"


@pytest.mark.parametrize("kind", ["vrf", "network"])
@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_resource_scope_keeps_target_groups_and_reports_unattached_resource(kind, topology, check_mode):
    rows = [_attachment(kind, "BLUE", "SW1"), _attachment(kind, "RED", "SW2")]
    coordinator, machine, strategy, switch_calls, attachment_calls = _case(kind, topology, check_mode, rows)
    coordinator.config_actions = ConfigActions(save=False, deploy=True, type="resource", provided=True)
    config = [{f"{kind}_name": name} for name in ("BLUE", "RED", "EMPTY")]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(_result(kind, "BLUE", "RED", "EMPTY"), config, args, strategy, {}, {}, False)

    name_key = f"{kind}Names"
    payloads = [{name_key: ["BLUE"], "switchIds": ["SW1"]}, {name_key: ["RED"], "switchIds": ["SW2"]}]
    assert switch_calls == []
    if check_mode:
        assert attachment_calls == []
        assert result["check_mode_deploy_payloads"] == payloads
    else:
        assert attachment_calls == [(payload, {}) for payload in payloads]
    skipped = [action for action in result["config_actions"] if action["status"] == "skipped"]
    assert len(skipped) == 1
    assert skipped[0]["reason"] == "no_targets"
    assert skipped[0]["targets"]["resources"] == ["EMPTY"]


@pytest.mark.parametrize("state", ["deleted", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_vrf_delete_cleanup_targets_only_detached_resources_and_switches(state, check_mode):
    coordinator, machine, strategy, switch_calls, attachment_calls = _case("vrf", "standalone", check_mode, [])
    coordinator._wait_for_vrfs_delete_ready = lambda *_args: None
    config = [{"vrf_name": "BLUE"}, {"vrf_name": "RED"}]
    args = {"fabric_name": "FAB1", "state": state, "config": config}
    detach_trace = {"deploy_targets": {"BLUE": {"SW1", "SW2"}, "RED": {"SW2"}}}

    traces = machine._deploy_detach_traces(args, args, strategy, config, detach_trace, ["BLUE", "RED"])

    payloads = [{"vrfNames": ["BLUE"], "switchIds": ["SW1", "SW2"]}, {"vrfNames": ["RED"], "switchIds": ["SW2"]}]
    assert switch_calls == []
    if check_mode:
        assert attachment_calls == []
        assert traces[-1]["check_mode_deploy_payloads"] == payloads
    else:
        assert attachment_calls == [(payload, {}) for payload in payloads]


@pytest.mark.parametrize("kind", ["vrf", "network"])
def test_no_explicit_attachment_keeps_existing_pending_target_selection(kind):
    rows = [_attachment(kind, "BLUE", "SW1"), _attachment(kind, "BLUE", "SW2")]
    _coordinator, machine, strategy, switch_calls, _attachment_calls = _case(kind, "standalone", False, rows)
    config = [{f"{kind}_name": "BLUE"}]
    args = {"fabric_name": "FAB1", "state": "merged", "config": config}

    result = machine._deploy_after_attachment_changes(_result(kind, "BLUE"), config, args, strategy, {}, {}, False, requested_attachments=None)

    _assert_switch_payload(result, switch_calls, ["SW1", "SW2"], "normal")
