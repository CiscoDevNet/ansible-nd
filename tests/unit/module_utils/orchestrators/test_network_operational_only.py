"""Operational-only Network requests must not reconcile Network definitions."""

from __future__ import annotations

from typing import ClassVar

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.common.exceptions import NDStateMachineError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_networks.network_data_models import NetworkBaseModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators import network_workflow_coordinator as coordinator_module
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_workflow_coordinator import NetworkWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_state_machine import NetworkStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.staged_state_helpers import prepare_crud_state
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_network import MulticlusterParentNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_network import MultisiteParentNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy


class _Module:
    def __init__(self, state, config, check_mode):
        self.params = {"state": state, "config": config, "output_level": "normal"}
        self.check_mode = check_mode
        self._verbosity = 0

    def warn(self, _message):
        pass


class _InventoryOrchestrator(NDNetworkOrchestrator):
    inventory: ClassVar[list[dict]] = []
    writes: ClassVar[list] = []

    def query_all(self, **_kwargs):
        return self.inventory

    def update(self, model_instance, **_kwargs):
        self.writes.append(model_instance)
        return {}

    def create_bulk(self, model_instances, **_kwargs):
        self.writes.extend(model_instances)
        return {}


_EXISTING = {
    "fabricName": "fab1",
    "networkName": "N",
    "networkType": "vxlanIbgp",
    "networkMode": "layer2",
    "networkId": 30001,
    "vlanId": 101,
    "vrfName": "NA",
}


def test_shared_network_diff_rejects_incompatible_models():
    existing = NetworkBaseModel.from_response(_EXISTING)
    proposed = NetworkBaseModel.from_config({"fabric_name": "fab1", "network_name": "N"})
    with pytest.raises(TypeError, match="Both must be the same type"):
        existing.get_diff(proposed)


def test_mixed_operational_and_sparse_networks_resolve_from_one_inventory(monkeypatch):
    entries = [{"network_name": "N", "deploy": False}, {"network_name": "M", "vlan_name": "UPDATED"}]
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    coordinator = NetworkWorkflowCoordinator(_Module("merged", entries, False), strategy)
    _InventoryOrchestrator.inventory = [dict(_EXISTING), {**_EXISTING, "networkName": "M", "l2Data": {"vlanName": "OLD"}}]
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    parsed = coordinator._parse_config(entries, strategy.config_model_cls, "merged")
    sm, original_config, original_state = coordinator._new_state_machine({"state": "merged", "config": parsed}, strategy)
    try:
        assert type(sm.proposed.get("N")) is type(sm.existing.get("N"))
        assert sm.existing.get("N").get_diff(sm.proposed.get("N"), exclude_unset=True)
        assert sm.proposed.get("M").layer == "layer2"
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)


@pytest.mark.parametrize("strategy_cls", [StandaloneNetworkStrategy, MultisiteParentNetworkStrategy, MulticlusterParentNetworkStrategy])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("action", ["attach", "deploy"])
def test_existing_operational_only_network_does_not_write_definition(monkeypatch, strategy_cls, state, check_mode, action):
    entry = {"network_name": "N", action: True if action == "deploy" else [{"ip_address": "192.0.2.1"}]}
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module(state, [entry], check_mode)
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    _InventoryOrchestrator.inventory = [dict(_EXISTING)]
    _InventoryOrchestrator.writes = []
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    parsed = coordinator._parse_config([entry], strategy.config_model_cls, state)
    assert action in parsed[0]
    sm, original_config, original_state = coordinator._new_state_machine({"state": state, "config": parsed}, strategy)
    try:
        existing = sm.existing.get("N")
        proposed = sm.proposed.get("N")
        assert type(proposed) is type(existing)
        assert existing.get_diff(proposed, exclude_unset=state == "merged")
        prepare_crud_state(sm, state)
        sm.manage_state()
        assert not _InventoryOrchestrator.writes
        assert not sm.sent
        assert sm.output.format()["changed"] is False
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)


@pytest.mark.parametrize("strategy_cls", [MultisiteParentNetworkStrategy, MulticlusterParentNetworkStrategy])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_child_only_request_preserves_parent_definition(monkeypatch, strategy_cls, state, check_mode):
    entry = {"network_name": "N", "child_fabric_config": [{"fabric_name": "child1", "x_connect": False}]}
    strategy = strategy_cls(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module(state, [entry], check_mode)
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    _InventoryOrchestrator.inventory = [dict(_EXISTING)]
    _InventoryOrchestrator.writes = []
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    parsed = coordinator._parse_config([entry], strategy.config_model_cls, state)
    assert parsed[0]["child_fabric_config"][0]["x_connect"] is False
    assert parsed[0].get("layer") is None
    parent_entry = dict(parsed[0])
    parent_entry.pop("child_fabric_config")
    sm, original_config, original_state = coordinator._new_state_machine({"state": state, "config": [parent_entry]}, strategy)
    try:
        assert type(sm.proposed.get("N")) is type(sm.existing.get("N"))
        sm.manage_state()
        assert not _InventoryOrchestrator.writes
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)


@pytest.mark.parametrize("check_mode", [False, True])
def test_operational_only_request_requires_existing_network(monkeypatch, check_mode):
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    entry = {"network_name": "MISSING", "deploy": True}
    module = _Module("merged", [entry], check_mode)
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    _InventoryOrchestrator.inventory = []
    _InventoryOrchestrator.writes = []
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    with pytest.raises(NDStateMachineError, match="must already exist"):
        coordinator._new_state_machine({"state": "merged", "config": [entry]}, strategy)
    assert not _InventoryOrchestrator.writes


@pytest.mark.parametrize("check_mode", [False, True])
def test_deploy_only_request_reaches_deploy_phase(monkeypatch, check_mode):
    entry = {"network_name": "N", "deploy": True}
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module("merged", [entry], check_mode)
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    _InventoryOrchestrator.inventory = [dict(_EXISTING)]
    _InventoryOrchestrator.writes = []
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    deployed = []
    monkeypatch.setattr(coordinator, "_build_pending_network_deploy_payloads", lambda *_args: [{"networkNames": ["N"]}])
    monkeypatch.setattr(coordinator, "_deploy_network_attachments", lambda *_args, **_kwargs: deployed.append(True) or {"changed": True})
    result = NetworkStateMachine(coordinator).run({"state": "merged", "config": [entry]}, strategy)
    assert result["changed"] is True
    assert deployed == ([] if check_mode else [True])
    assert not _InventoryOrchestrator.writes


@pytest.mark.parametrize("check_mode", [False, True])
def test_attachment_only_request_reaches_post_attach_phase(monkeypatch, check_mode):
    entry = {"network_name": "N", "attach": [{"ip_address": "192.0.2.1"}]}
    strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
    module = _Module("merged", [entry], check_mode)
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    _InventoryOrchestrator.inventory = [dict(_EXISTING)]
    _InventoryOrchestrator.writes = []
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    monkeypatch.setattr(coordinator, "_desired_attachment_map", lambda *_args: {("N", "192.0.2.1"): {"attach": True}})
    monkeypatch.setattr(coordinator, "_current_attachment_details_ignore_missing", lambda *_args: [])
    monkeypatch.setattr(coordinator, "_attachment_map_from_details", lambda *_args: {})
    monkeypatch.setattr(coordinator, "_preflight_fabric_features", lambda *_args, **_kwargs: None)
    phases = []

    def apply_phase(*_args, **kwargs):
        phases.append(kwargs["phase"])
        return {"changed": kwargs["phase"] == "post", "payloads": [], "deploy_targets": {}, "current": {}}

    monkeypatch.setattr(coordinator, "_apply_attachment_phase", apply_phase)
    monkeypatch.setattr(coordinator, "_build_deploy_payloads", lambda *_args: [])
    monkeypatch.setattr(coordinator, "_build_pending_network_deploy_payloads", lambda *_args: [])
    monkeypatch.setattr(NetworkStateMachine, "_should_query_pending_networks", lambda *_args: False)
    result = NetworkStateMachine(coordinator).run({"state": "merged", "config": [entry]}, strategy)
    assert phases == ["pre", "post"]
    assert result["changed"] is True
    assert not _InventoryOrchestrator.writes


@pytest.mark.parametrize("strategy_cls", [MultisiteParentNetworkStrategy, MulticlusterParentNetworkStrategy])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_parent_child_only_request_dispatches_child_without_parent_definition_write(monkeypatch, strategy_cls, state, check_mode):
    entry = {"network_name": "N", "child_fabric_config": [{"fabric_name": "child1", "x_connect": False}]}
    member_type = "multicluster_child" if strategy_cls is MulticlusterParentNetworkStrategy else "multisite_child"
    strategy = strategy_cls(
        fabric_name="fab1",
        fabric_data={"managementType": "vxlanIbgp", "members": [{"fabricName": "child1", "fabric_type": member_type}]},
    )
    module = _Module(state, [entry], check_mode)
    coordinator = NetworkWorkflowCoordinator(module=module, strategy=strategy)
    _InventoryOrchestrator.inventory = [dict(_EXISTING)]
    _InventoryOrchestrator.writes = []
    monkeypatch.setattr(coordinator_module, "NDNetworkOrchestrator", _InventoryOrchestrator)
    monkeypatch.setattr(coordinator, "_preflight_child_feature_tasks", lambda *_args: None)
    monkeypatch.setattr(coordinator, "_current_attachment_details_ignore_missing", lambda *_args: [])
    monkeypatch.setattr(coordinator, "_attachment_map_from_details", lambda *_args: {})
    monkeypatch.setattr(
        coordinator,
        "_apply_attachment_phase",
        lambda *_args, **_kwargs: {"changed": False, "payloads": [], "deploy_targets": {}, "current": {}},
    )
    monkeypatch.setattr(coordinator, "_build_pending_network_deploy_payloads", lambda *_args: [])
    monkeypatch.setattr(NetworkStateMachine, "_should_query_pending_networks", lambda *_args: False)
    dispatched = []

    def run_child(task):
        dispatched.append(task["module_args"]["config"])
        return {"changed": True, "failed": False}

    monkeypatch.setattr(coordinator, "_run_child_task", run_child)
    result = coordinator._handle_parent_workflow({"state": state, "fabric_name": "fab1", "config": [entry]}, strategy.fabric_type)
    assert dispatched[0][0]["x_connect"] is False
    assert result["changed"] is True
    assert not _InventoryOrchestrator.writes
