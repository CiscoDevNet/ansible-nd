# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the Phase 3 public interface workflow coordinator."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_family_adapters import INTERFACE_FAMILY_ADAPTERS
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import (
    InterfaceWorkflowCoordinator,
    InterfaceWorkflowExecutionFailed,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowPlanner,
    InterfaceWorkflowValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.interface_default_config import InterfaceDefaultConfig
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import NDConfigCollection
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

COMPACT_RESULT_KEYS = {
    "changed",
    "planned_changed",
    "mutation_count",
    "target_switch_ids",
    "resources",
    "request_stats",
    "execution",
}
COMPACT_RESOURCE_KEYS = {
    "resource_index",
    "type",
    "module",
    "state",
    "changed",
    "planned_changed",
    "before",
    "after",
    "after_verified",
    "operations",
}


class FakeCollection:
    """Small NDConfigCollection-compatible serializer for coordinator output tests."""

    def __init__(self, config):
        self._items = [FakeModel(item) for item in config]

    def __iter__(self):
        return iter(self._items)

    def get(self, key):
        return next((item for item in self._items if item.get_identifier_value() == key), None)

    def to_ansible_config(self):
        return [item.to_config() for item in self._items]

    def get_diff_collection(self, other):
        return self.to_ansible_config() != other.to_ansible_config()


class FakeModel:
    """Small model serializer for action output."""

    def __init__(self, value):
        self.value = value

    @property
    def interface_name(self):
        return self.value["interface_name"]

    @property
    def switch_ip(self):
        return self.value.get("switch_ip", "192.0.2.1")

    def get_identifier_value(self):
        return self.value["interface_name"]

    def to_config(self):
        return {"switch_ip": self.switch_ip, **self.value}

    def to_payload(self):
        return {}


class FakeTransition:
    """Small transition serializer that keeps raw desired/current state internal."""

    def __init__(self, desired):
        self.desired = desired
        self.switch_ip = "192.0.2.1"
        self.switch_id = "SERIAL1"
        self.interface_name = "Ethernet1/1"
        self.from_policy_type = "routedHost"
        self.to_policy_type = "accessHost"

    def to_dict(self):
        return {
            "action": "transition",
            "switch_ip": "192.0.2.1",
            "switch_id": "SERIAL1",
            "interface_name": "Ethernet1/1",
            "from_policy_type": "routedHost",
            "to_policy_type": "accessHost",
        }


class FakeModule:
    """Module shape needed by the coordinator."""

    def __init__(self, *, check_mode, output_level="normal"):
        self.check_mode = check_mode
        self.params = {
            "fabric_name": "FABRIC1",
            "resources": [],
            "config_actions": {"deploy": True},
            "output_level": output_level,
        }


def resource(index, *, changed=True, transition=False):
    """Return one InterfaceResourcePlan-shaped object."""
    before_config = [{"interface_name": f"Ethernet1/{index + 1}", "value": "old"}]
    after_config = [{"interface_name": f"Ethernet1/{index + 1}", "value": "new"}] if changed else before_config
    before = FakeCollection(before_config)
    after = FakeCollection(after_config)
    operations = SimpleNamespace(
        after=after,
        creates=(() if transition or not changed else (FakeModel({"interface_name": f"Ethernet1/{index + 1}"}),)),
        updates=(),
        deletes=(),
    )
    return SimpleNamespace(
        resource_index=index,
        resource_type="ethernet_access",
        adapter=SimpleNamespace(module_name="cisco.nd.nd_interface_ethernet_access", ownership_domain="switch"),
        orchestrator=SimpleNamespace(fabric_context=FakeFabricContext()),
        state="merged",
        changed=changed,
        transitions=((FakeTransition(FakeModel({"interface_name": f"Ethernet1/{index + 1}"})),) if transition else ()),
        before=before,
        proposed=FakeCollection(after_config),
        operations=operations,
    )


def plan(*, changed=True, transition=False):
    """Return one InterfaceWorkflowPlan-shaped object with repeated family types."""
    resources = (resource(0, changed=changed, transition=transition), resource(1, changed=False))
    return SimpleNamespace(
        changed=changed,
        fabric_name="FABRIC1",
        mutation_count=1 if changed else 0,
        target_switch_ids=("SERIAL1", "SERIAL2"),
        resources=resources,
        request_stats={"switches": 2, "interface_inventory_gets": 2},
    )


class FakeExecutionItem:
    """Small execution-item result used to qualify operation status merging."""

    def __init__(self, **data):
        self.__dict__.update(data)

    def to_dict(self):
        """Return the public execution item shape."""
        return dict(self.__dict__)


class FakeExecution:
    """InterfaceWorkflowExecution-compatible result for coordinator wiring tests."""

    def __init__(self, workflow_plan, *, deploy, deployment_targets=(), failed=False):
        self.deployment_targets = tuple(deployment_targets)
        deployment_sent = deploy and bool(workflow_plan.changed or self.deployment_targets) and not failed
        self.changed = not failed and bool(workflow_plan.changed or deployment_sent)
        self.failed = failed
        self.message = "execution failed" if failed else ""
        self.mutation_requests = int(workflow_plan.changed)
        self.deploy_requests = int(deployment_sent)
        self.deploy = deploy
        self.actual_after_by_resource = {item.resource_index: item.operations.after if not failed else item.before for item in workflow_plan.resources}
        status = "failed" if failed else "succeeded"
        items = []
        for resource_plan in workflow_plan.resources:
            for transition in resource_plan.transitions:
                items.append(
                    FakeExecutionItem(
                        resource_index=resource_plan.resource_index,
                        type=resource_plan.resource_type,
                        status=status,
                        **transition.to_dict(),
                    )
                )
            for action, models in (
                ("create", resource_plan.operations.creates),
                ("update", resource_plan.operations.updates),
                ("delete", resource_plan.operations.deletes),
            ):
                for model in models:
                    items.append(
                        FakeExecutionItem(
                            resource_index=resource_plan.resource_index,
                            type=resource_plan.resource_type,
                            action=action,
                            switch_ip=model.switch_ip,
                            switch_id=resource_plan.orchestrator.fabric_context.get_switch_id(model.switch_ip),
                            interface_name=model.interface_name,
                            status=status,
                        )
                    )
        self.items = tuple(items)

    def to_dict(self):
        if self.failed:
            status = "failed"
        elif self.deploy:
            status = "completed"
        else:
            status = "staged"
        return {
            "status": status,
            "mutations_sent": self.mutation_requests,
            "deployments_sent": self.deploy_requests,
            "affected_switch_ids": ["SERIAL1"] if self.mutation_requests else [],
            "items": [item.to_dict() for item in self.items],
            "deployment": {
                "requested": self.deploy,
                "status": "succeeded" if self.deploy_requests else ("not_attempted" if self.failed else "not_needed"),
                "targets": [{"interface_name": name, "switch_id": switch_id, "status": "succeeded"} for name, switch_id in self.deployment_targets],
            },
            "errors": [self.message] if self.failed else [],
        }


class FakeExecutor:
    """Capture coordinator execution settings and return a configured result."""

    def __init__(self, calls, *, failed=False, **kwargs):
        self.calls = calls
        self.failed = failed
        self.deploy = kwargs["deploy"]
        self.calls.append(("init", kwargs))

    def execute(self, workflow_plan, deployment_targets=()):
        self.calls.append(("execute", workflow_plan, tuple(deployment_targets)))
        return FakeExecution(workflow_plan, deploy=self.deploy, deployment_targets=deployment_targets, failed=self.failed)


def test_check_mode_result_retains_repeated_groups_and_reports_planned_change():
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    result = coordinator._format_result(plan())

    assert set(result) == COMPACT_RESULT_KEYS
    assert result["changed"] is True
    assert result["planned_changed"] is True
    assert result["execution"]["status"] == "check_mode"
    assert result["execution"]["mutations_sent"] == 0
    assert [item["resource_index"] for item in result["resources"]] == [0, 1]
    assert [item["type"] for item in result["resources"]] == [
        "ethernet_access",
        "ethernet_access",
    ]
    resource_result = result["resources"][0]
    assert set(resource_result) == COMPACT_RESOURCE_KEYS
    assert resource_result["before"] == [{"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/1", "value": "old"}]
    assert resource_result["after"] == [{"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/1", "value": "new"}]
    assert resource_result["operations"] == [
        {
            "action": "create",
            "switch_ip": "192.0.2.1",
            "switch_id": "SERIAL1",
            "interface_name": "Ethernet1/1",
            "status": "planned",
        }
    ]
    assert resource_result["after_verified"] is False
    assert "proposed" not in resource_result
    assert result["request_stats"]["interface_inventory_gets"] == 2
    assert "mutation_requests" not in result["request_stats"]
    assert "deploy_requests" not in result["request_stats"]


def test_check_mode_result_exposes_transition_metadata_without_raw_state():
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))

    result = coordinator._format_result(plan(transition=True))

    resource_result = result["resources"][0]
    assert "allow_policy_transition" not in resource_result
    assert resource_result["operations"] == [
        {
            "action": "transition",
            "switch_ip": "192.0.2.1",
            "switch_id": "SERIAL1",
            "interface_name": "Ethernet1/1",
            "status": "planned",
            "from_policy_type": "routedHost",
            "to_policy_type": "accessHost",
            "changes": [{"path": "value", "before": "old", "after": "new"}],
        }
    ]


def test_check_mode_update_operation_reports_only_leaf_changes():
    workflow_plan = plan()
    resource_plan = workflow_plan.resources[0]
    resource_plan.operations.creates = ()
    resource_plan.operations.updates = (FakeModel({"interface_name": "Ethernet1/1", "value": "new"}),)
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))

    result = coordinator._format_result(workflow_plan)

    assert result["resources"][0]["operations"] == [
        {
            "action": "update",
            "switch_ip": "192.0.2.1",
            "switch_id": "SERIAL1",
            "interface_name": "Ethernet1/1",
            "status": "planned",
            "changes": [{"path": "value", "before": "old", "after": "new"}],
        }
    ]


def test_info_output_includes_normalized_proposed_config():
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True, output_level="info"))
    result = coordinator._format_result(plan())
    resource_result = result["resources"][0]

    assert set(result) == COMPACT_RESULT_KEYS
    assert set(resource_result) == COMPACT_RESOURCE_KEYS | {"proposed"}
    assert resource_result["proposed"][0]["value"] == "new"


def test_check_mode_run_returns_complete_plan_without_execution(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(coordinator, "_build_plan", plan)
    result = coordinator.run()
    assert result["changed"] is True
    assert result["execution"]["status"] == "check_mode"


def test_normal_no_change_run_succeeds_without_execution(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=False))
    monkeypatch.setattr(coordinator, "_build_plan", lambda: plan(changed=False))
    result = coordinator.run()
    assert result["changed"] is False
    assert result["planned_changed"] is False
    assert result["execution"]["status"] == "no_change"


def test_normal_no_change_defaults_deploy_to_false_when_omitted(monkeypatch):
    module = FakeModule(check_mode=False)
    module.params["config_actions"] = {}
    coordinator = InterfaceWorkflowCoordinator(module)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: plan(changed=False))

    result = coordinator.run()

    assert "config_actions" not in result
    assert result["execution"]["deployment"]["requested"] is False


def test_normal_changing_run_executes_and_reports_actual_state(monkeypatch):
    calls = []
    coordinator = InterfaceWorkflowCoordinator(
        FakeModule(check_mode=False),
        executor_factory=lambda **kwargs: FakeExecutor(calls, **kwargs),
    )
    coordinator._snapshot = SimpleNamespace(request_stats={"switches": 2, "interface_inventory_gets": 2})
    workflow_plan = plan()
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)

    result = coordinator.run()

    assert [call[0] for call in calls] == ["init", "execute"]
    assert calls[0][1]["deploy"] is True
    assert result["changed"] is True
    assert result["execution"]["status"] == "completed"
    assert result["resources"][0]["after_verified"] is True
    assert result["resources"][0]["operations"][0]["status"] == "succeeded"
    assert result["execution"]["mutations_sent"] == 1
    assert result["execution"]["deployments_sent"] == 1
    assert "mutation_requests" not in result["request_stats"]
    assert "deploy_requests" not in result["request_stats"]


def test_normal_changing_run_defaults_deploy_to_false_when_omitted(monkeypatch):
    calls = []
    module = FakeModule(check_mode=False)
    module.params["config_actions"] = {}
    coordinator = InterfaceWorkflowCoordinator(
        module,
        executor_factory=lambda **kwargs: FakeExecutor(calls, **kwargs),
    )
    coordinator._snapshot = SimpleNamespace(request_stats={"switches": 2, "interface_inventory_gets": 2})
    workflow_plan = plan()
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)

    coordinator.run()

    assert calls[0][1]["deploy"] is False


def test_normal_execution_failure_preserves_structured_result(monkeypatch):
    calls = []
    coordinator = InterfaceWorkflowCoordinator(
        FakeModule(check_mode=False),
        executor_factory=lambda **kwargs: FakeExecutor(calls, failed=True, **kwargs),
    )
    coordinator._snapshot = SimpleNamespace(request_stats={"switches": 2, "interface_inventory_gets": 2})
    monkeypatch.setattr(coordinator, "_build_plan", plan)

    with pytest.raises(InterfaceWorkflowExecutionFailed) as exc_info:
        coordinator.run()

    assert exc_info.value.result["failed"] is True
    assert exc_info.value.result["execution"]["status"] == "failed"
    assert exc_info.value.result["execution"]["mutations_sent"] == 1
    assert exc_info.value.result["resources"][0]["operations"][0]["status"] == "failed"


class FakeFabricContext:
    fabric_name = "FABRIC1"

    switch_ip_by_id = {
        "SERIAL1": "192.0.2.1",
        "SERIAL2": "192.0.2.2",
        "SERIAL3": "192.0.2.3",
        "SERIAL4": "192.0.2.4",
    }
    switch_id_by_ip = {switch_ip: switch_id for switch_id, switch_ip in switch_ip_by_id.items()}

    def __init__(self, sync_status_by_id=None):
        self.sync_status_by_id = dict(sync_status_by_id or {switch_id: True for switch_id in self.switch_ip_by_id})
        self.sync_status_reads = []

    def switch_config_in_sync(self, switch_id):
        self.sync_status_reads.append(switch_id)
        return self.sync_status_by_id.get(switch_id)

    def get_switch_ip(self, switch_id):
        try:
            return self.switch_ip_by_id[switch_id]
        except KeyError as exc:
            raise RuntimeError("unknown switch") from exc

    def get_switch_id(self, switch_ip):
        try:
            return self.switch_id_by_ip[switch_ip]
        except KeyError as exc:
            raise RuntimeError("unknown switch") from exc


def _deployment_only_plan(resource_type, sync_status_by_id, *, mutation=False, state="merged"):
    adapter = INTERFACE_FAMILY_ADAPTERS[resource_type]
    config = {"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/40", "value": "same"}
    model = FakeModel(config)
    proposed = FakeCollection([config])
    before = FakeCollection([config])
    operations = SimpleNamespace(
        after=FakeCollection([config]),
        creates=(),
        updates=(model,) if mutation else (),
        deletes=(),
    )
    context = FakeFabricContext(sync_status_by_id)
    peer_cache = {"SERIAL1": "SERIAL2"} if adapter.ownership_domain == "vpc" else {}
    resource_plan = SimpleNamespace(
        resource_index=0,
        resource_type=resource_type,
        adapter=adapter,
        orchestrator=SimpleNamespace(fabric_context=context, _peer_serial_cache=peer_cache),
        state=state,
        changed=mutation,
        transitions=(),
        before=before,
        proposed=proposed,
        operations=operations,
    )
    target_switch_ids = ("SERIAL1", "SERIAL2") if adapter.ownership_domain == "vpc" else ("SERIAL1",)
    workflow_plan = SimpleNamespace(
        changed=mutation,
        fabric_name="FABRIC1",
        mutation_count=int(mutation),
        target_switch_ids=target_switch_ids,
        resources=(resource_plan,),
        request_stats={"switches": len(target_switch_ids), "interface_inventory_gets": len(target_switch_ids)},
    )
    return workflow_plan, context


@pytest.mark.parametrize("resource_type", sorted(INTERFACE_FAMILY_ADAPTERS))
def test_pending_deployment_selection_covers_all_ten_explicit_interface_types(resource_type):
    adapter = INTERFACE_FAMILY_ADAPTERS[resource_type]
    statuses = {"SERIAL1": False, "SERIAL2": True}
    if adapter.ownership_domain == "vpc":
        statuses = {"SERIAL1": True, "SERIAL2": False}
    workflow_plan, context = _deployment_only_plan(resource_type, statuses)

    targets = InterfaceWorkflowCoordinator._pending_deployment_targets(workflow_plan)

    assert targets == (("Ethernet1/40", "SERIAL1"),)
    assert context.sync_status_reads == (["SERIAL1", "SERIAL2"] if adapter.ownership_domain == "vpc" else ["SERIAL1"])


@pytest.mark.parametrize("status", (True, None))
def test_synchronized_or_unknown_switch_status_does_not_trigger_blind_deployment(status):
    workflow_plan, _context = _deployment_only_plan("ethernet_access", {"SERIAL1": status, "SERIAL2": False})

    assert InterfaceWorkflowCoordinator._pending_deployment_targets(workflow_plan) == ()


def test_same_invocation_mutation_target_is_left_to_the_orchestrator_queue():
    workflow_plan, context = _deployment_only_plan("ethernet_access", {"SERIAL1": False}, mutation=True)

    assert InterfaceWorkflowCoordinator._pending_deployment_targets(workflow_plan) == ()
    assert context.sync_status_reads == []


@pytest.mark.parametrize("state", ("merged", "replaced", "deleted"))
def test_explicit_no_mutation_target_is_deployable_for_supported_target_scoped_states(state):
    workflow_plan, _context = _deployment_only_plan("ethernet_access", {"SERIAL1": False}, state=state)

    assert InterfaceWorkflowCoordinator._pending_deployment_targets(workflow_plan) == (("Ethernet1/40", "SERIAL1"),)


def test_check_mode_previews_zero_mutation_deployment_only_action(monkeypatch):
    module = FakeModule(check_mode=True)
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan, _context = _deployment_only_plan("ethernet_access", {"SERIAL1": False})
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)

    result = coordinator.run()

    assert result["changed"] is True
    assert result["planned_changed"] is False
    assert result["mutation_count"] == 0
    assert result["resources"][0]["changed"] is False
    assert result["execution"]["status"] == "check_mode"
    assert result["execution"]["mutations_sent"] == 0
    assert result["execution"]["deployments_sent"] == 0
    assert result["execution"]["deployment"] == {
        "requested": True,
        "status": "would_deploy",
        "targets": [{"interface_name": "Ethernet1/40", "switch_id": "SERIAL1", "status": "would_deploy"}],
    }


def test_normal_zero_mutation_pending_target_executes_one_deployment(monkeypatch):
    calls = []
    module = FakeModule(check_mode=False)
    coordinator = InterfaceWorkflowCoordinator(
        module,
        executor_factory=lambda **kwargs: FakeExecutor(calls, **kwargs),
    )
    workflow_plan, _context = _deployment_only_plan("ethernet_access", {"SERIAL1": False})
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)

    result = coordinator.run()

    assert calls[1][0] == "execute"
    assert calls[1][2] == (("Ethernet1/40", "SERIAL1"),)
    assert result["changed"] is True
    assert result["planned_changed"] is False
    assert result["mutation_count"] == 0
    assert result["resources"][0]["changed"] is False
    assert result["execution"]["status"] == "completed"
    assert result["execution"]["mutations_sent"] == 0
    assert result["execution"]["deployments_sent"] == 1
    assert result["execution"]["deployment"]["status"] == "succeeded"


def test_normal_in_sync_zero_mutation_target_keeps_no_change_short_circuit(monkeypatch):
    calls = []
    coordinator = InterfaceWorkflowCoordinator(
        FakeModule(check_mode=False),
        executor_factory=lambda **kwargs: FakeExecutor(calls, **kwargs),
    )
    workflow_plan, _context = _deployment_only_plan("ethernet_access", {"SERIAL1": True})
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)

    result = coordinator.run()

    assert calls == []
    assert result["changed"] is False
    assert result["execution"]["status"] == "no_change"
    assert result["execution"]["deployments_sent"] == 0


class InverseSerialOrderFabricContext(FakeFabricContext):
    """Map lower management IPs to lexically later vPC-pair serials."""

    switch_ip_by_id = {
        "SERIAL-Z1": "192.0.2.1",
        "SERIAL-Z2": "192.0.2.2",
        "SERIAL-A1": "192.0.2.3",
        "SERIAL-A2": "192.0.2.4",
    }
    switch_id_by_ip = {switch_ip: switch_id for switch_id, switch_ip in switch_ip_by_id.items()}


class ProjectionSnapshot:
    """Cached raw records used by projection tests without network access."""

    def __init__(self, original, current=None):
        self.original = {(switch_id, name.lower()): deepcopy(raw) for switch_id, name, raw in original}
        self.current = dict(self.original)
        if current is not None:
            self.current = {(switch_id, name.lower()): deepcopy(raw) for switch_id, name, raw in current}
        self.lookups = []
        self.request_stats = {"switches": len({key[0] for key in self.current}), "interface_inventory_gets": 0}

    def cached_interface(self, switch_id, interface_name, *, original=False):
        self.lookups.append((switch_id, interface_name.lower(), original))
        source = self.original if original else self.current
        value = source.get((switch_id, interface_name.lower()))
        return deepcopy(value) if value is not None else None

    @property
    def interfaces_by_identity(self):
        return deepcopy(self.current)


def _raw_ethernet(name, policy_type, **policy):
    mode = "access" if policy_type == "accessHost" else "trunk"
    return {
        "interfaceName": name,
        "interfaceType": "ethernet",
        "configData": {
            "mode": mode,
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": policy_type, **policy},
            },
        },
    }


def _raw_loopback(name):
    return {
        "interfaceName": name,
        "interfaceType": "loopback",
        "configData": {
            "mode": "managed",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": "loopback", "description": "requested loopback"},
            },
        },
    }


def _ethernet_config(switch_ip, name, *, access_vlan=None):
    item = {"switch_ip": switch_ip, "interface_names": [name]}
    if access_vlan is not None:
        item["config_data"] = {"network_os": {"policy": {"access_vlan": access_vlan}}}
    return item


def _validated(adapter, config, state):
    if not config:
        return NDConfigCollection(model_class=adapter.model_class)
    return adapter.validate_config(config, state, 0)


def _projection_resource(
    resource_type,
    state,
    proposed_config,
    *,
    family_before=(),
    family_after=(),
    action=None,
    context=None,
):
    adapter = INTERFACE_FAMILY_ADAPTERS[resource_type]
    proposed = _validated(adapter, list(proposed_config), state)
    before = _validated(adapter, list(family_before), "merged")
    after = _validated(adapter, list(family_after), "merged")
    desired = tuple(proposed)
    creates = desired if action == "create" else ()
    updates = desired if action == "update" else ()
    deletes = desired if action == "delete" else ()
    transitions = (FakeTransition(desired[0]),) if action == "transition" else ()
    return SimpleNamespace(
        resource_index=0,
        resource_type=resource_type,
        adapter=adapter,
        state=state,
        changed=action is not None,
        transitions=transitions,
        before=before,
        proposed=proposed,
        operations=SimpleNamespace(
            after=after,
            creates=creates,
            updates=updates,
            deletes=deletes,
        ),
        orchestrator=SimpleNamespace(fabric_context=context or FakeFabricContext()),
    )


def _projection_plan(resource_plan):
    return SimpleNamespace(
        changed=resource_plan.changed,
        fabric_name="FABRIC1",
        mutation_count=1 if resource_plan.changed else 0,
        target_switch_ids=("SERIAL1", "SERIAL2"),
        resources=(resource_plan,),
        request_stats={"switches": 2, "interface_inventory_gets": 0},
    )


def test_target_projection_is_switch_aware_and_debug_retains_full_family():
    proposed = [_ethernet_config("192.0.2.2", "Ethernet1/1", access_vlan=200)]
    family = [
        _ethernet_config("192.0.2.1", "Ethernet1/1", access_vlan=100),
        *proposed,
        _ethernet_config("192.0.2.2", "Ethernet1/5", access_vlan=5),
    ]
    resource_plan = _projection_resource(
        "ethernet_access",
        "merged",
        proposed,
        family_before=family,
        family_after=family,
    )
    snapshot = ProjectionSnapshot(
        [
            ("SERIAL1", "Ethernet1/1", _raw_ethernet("Ethernet1/1", "accessHost", accessVlan=100)),
            ("SERIAL2", "Ethernet1/1", _raw_ethernet("Ethernet1/1", "accessHost", accessVlan=200)),
            ("SERIAL2", "Ethernet1/5", _raw_ethernet("Ethernet1/5", "accessHost", accessVlan=5)),
        ]
    )
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True, output_level="debug"))
    coordinator._snapshot = snapshot

    result = coordinator._format_result(_projection_plan(resource_plan))

    projected = result["resources"][0]
    assert set(result) == COMPACT_RESULT_KEYS
    assert set(projected) == COMPACT_RESOURCE_KEYS | {"proposed", "family_before", "family_after"}
    assert [(item["switch_ip"], item["interface_name"]) for item in projected["before"]] == [("192.0.2.2", "Ethernet1/1")]
    assert projected["before"][0]["config_data"]["network_os"]["policy"]["access_vlan"] == 200
    assert projected["after"] == projected["before"]
    assert len(projected["family_before"]) == 3
    assert len(projected["family_after"]) == 3
    assert "family_diff" not in projected
    assert "diff" not in projected
    assert "before" not in result
    assert "after" not in result
    assert "diff" not in result
    assert "check_mode" not in result
    assert "output_level" not in result


def test_cross_policy_transition_uses_unknown_source_fallback_and_destination_model():
    proposed = [_ethernet_config("192.0.2.1", "Ethernet1/1", access_vlan=3900)]
    resource_plan = _projection_resource(
        "ethernet_access",
        "merged",
        proposed,
        family_after=proposed,
        action="transition",
    )
    raw = _raw_ethernet(
        "Ethernet1/1",
        "dot1qTunnel",
        customerVlanId=[100, 200],
        providerVlanId=3900,
    )
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    coordinator._snapshot = ProjectionSnapshot([("SERIAL1", "Ethernet1/1", raw)])

    result = coordinator._format_result(_projection_plan(resource_plan))
    projected = result["resources"][0]

    assert projected["before"][0]["policy_type"] == "dot1qTunnel"
    source_policy = projected["before"][0]["config_data"]["network_os"]["policy"]
    assert source_policy["customer_vlan_id"] == [100, 200]
    assert source_policy["provider_vlan_id"] == 3900
    assert projected["after"][0]["policy_type"] == "accessHost"
    assert projected["after"][0]["config_data"]["network_os"]["policy"]["access_vlan"] == 3900
    assert projected["operations"][0]["action"] == "transition"
    assert projected["operations"][0]["from_policy_type"] == "routedHost"
    assert projected["operations"][0]["to_policy_type"] == "accessHost"
    assert projected["operations"][0]["status"] == "planned"
    assert projected["operations"][0]["changes"]


@pytest.mark.parametrize(
    ("raw", "action", "expected_changed"),
    [
        (_raw_ethernet("Ethernet1/1", "accessHost", accessVlan=3900), "delete", True),
        (
            {
                **InterfaceDefaultConfig().to_payload(),
                "interfaceName": "Ethernet1/1",
            },
            None,
            False,
        ),
    ],
)
def test_physical_delete_reports_reset_default_or_idempotent_default(raw, action, expected_changed):
    proposed = [_ethernet_config("192.0.2.1", "Ethernet1/1")]
    resource_plan = _projection_resource(
        "ethernet_access",
        "deleted",
        proposed,
        action=action,
    )
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    coordinator._snapshot = ProjectionSnapshot([("SERIAL1", "Ethernet1/1", raw)])

    projected = coordinator._format_result(_projection_plan(resource_plan))["resources"][0]

    assert projected["before"][0]["interface_name"] == "Ethernet1/1"
    assert projected["after"][0]["interface_name"] == "Ethernet1/1"
    assert projected["after"][0]["policy_type"] == "trunkHost"
    assert projected["after"][0]["config_data"]["network_os"]["policy"]["allowed_vlans"] == "none"
    assert projected["changed"] is expected_changed
    assert bool(projected["operations"]) is expected_changed
    if expected_changed:
        assert projected["operations"][0]["action"] == "reset"
        assert {"path": "policy_type", "before": "accessHost", "after": "trunkHost"} in projected["operations"][0]["changes"]


@pytest.mark.parametrize("present", [True, False])
def test_logical_delete_reports_requested_resource_or_clean_absence(present):
    config = [{"switch_ip": "192.0.2.1", "interface_name": "loopback10"}]
    resource_plan = _projection_resource(
        "loopback",
        "deleted",
        config,
        action="delete" if present else None,
    )
    records = [("SERIAL1", "loopback10", _raw_loopback("loopback10"))] if present else []
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    coordinator._snapshot = ProjectionSnapshot(records)

    projected = coordinator._format_result(_projection_plan(resource_plan))["resources"][0]

    assert len(projected["before"]) == int(present)
    assert projected["after"] == []
    assert projected["changed"] is present
    assert bool(projected["operations"]) is present
    if present:
        assert projected["operations"][0]["action"] == "delete"
        assert "changes" not in projected["operations"][0]


def _raw_vpc(name, peer_switch_id, access_vlan=3900):
    return {
        "interfaceName": name,
        "interfaceType": "vpc",
        "configData": {
            "mode": "access",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "accessVpcHost",
                    "accessVlan": access_vlan,
                    "peerSwitchId": peer_switch_id,
                },
            },
        },
    }


def _vpc_access_config(switch_ip, peer_switch_id, access_vlan):
    """Return one reporting-equivalent vPC access model config."""
    return {
        "switch_ip": switch_ip,
        "interface_name": "vpc10",
        "config_data": {
            "network_os": {
                "policy": {
                    "access_vlan": access_vlan,
                    "peer_switch_id": peer_switch_id,
                }
            }
        },
    }


def test_observed_vpc_target_requires_both_consistent_peer_records():
    adapter = INTERFACE_FAMILY_ADAPTERS["vpc_access"]
    desired = SimpleNamespace(switch_ip="192.0.2.1", interface_name="vpc10")
    orchestrator = SimpleNamespace(
        fabric_context=FakeFabricContext(),
        _peer_serial_cache={"SERIAL1": "SERIAL2", "SERIAL2": "SERIAL1"},
    )
    resource_plan = SimpleNamespace(adapter=adapter, orchestrator=orchestrator)
    primary = _raw_vpc("vpc10", "SERIAL2")
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=False))
    coordinator._snapshot = ProjectionSnapshot([("SERIAL1", "vpc10", primary)])

    assert not coordinator._vpc_target_is_pair_consistent(resource_plan, desired, primary)

    coordinator._snapshot = ProjectionSnapshot(
        [
            ("SERIAL1", "vpc10", primary),
            ("SERIAL2", "vpc10", _raw_vpc("vpc10", "SERIAL1")),
        ]
    )
    assert coordinator._vpc_target_is_pair_consistent(resource_plan, desired, primary)


@pytest.mark.parametrize(
    ("primary_peer_id", "peer_peer_id"),
    [
        pytest.param("SERIAL1", "SERIAL2", id="self-references"),
        pytest.param("OUTSIDE-PAIR", "OUTSIDE-PAIR", id="outside-authoritative-pair"),
    ],
)
def test_observed_vpc_target_rejects_wrong_or_self_peer_switch_ids(primary_peer_id, peer_peer_id):
    """Matching policy data cannot hide peer IDs that contradict the authoritative pair."""
    adapter = INTERFACE_FAMILY_ADAPTERS["vpc_access"]
    desired = SimpleNamespace(switch_ip="192.0.2.1", interface_name="vpc10")
    resource_plan = SimpleNamespace(
        adapter=adapter,
        orchestrator=SimpleNamespace(
            fabric_context=FakeFabricContext(),
            _peer_serial_cache={"SERIAL1": "SERIAL2", "SERIAL2": "SERIAL1"},
        ),
    )
    primary = _raw_vpc("vpc10", primary_peer_id)
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=False))
    coordinator._snapshot = ProjectionSnapshot(
        [
            ("SERIAL1", "vpc10", primary),
            ("SERIAL2", "vpc10", _raw_vpc("vpc10", peer_peer_id)),
        ]
    )

    assert not coordinator._vpc_target_is_pair_consistent(resource_plan, desired, primary)


@pytest.mark.parametrize(
    ("primary_peer_id", "peer_peer_id"),
    [
        pytest.param("SERIAL1", "SERIAL2", id="self-references"),
        pytest.param("OUTSIDE-PAIR", "OUTSIDE-PAIR", id="outside-authoritative-pair"),
    ],
)
def test_observed_overridden_vpc_rejects_wrong_or_self_peer_switch_ids(primary_peer_id, peer_peer_id):
    """A full-family observation is unverified when reciprocal records name invalid peers."""
    adapter = INTERFACE_FAMILY_ADAPTERS["vpc_access"]
    resource_plan = SimpleNamespace(
        adapter=adapter,
        proposed=(),
        orchestrator=SimpleNamespace(
            fabric_context=FakeFabricContext(),
            _peer_serial_cache={"SERIAL1": "SERIAL2", "SERIAL2": "SERIAL1"},
        ),
    )
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=False))
    coordinator._snapshot = ProjectionSnapshot(
        [
            ("SERIAL1", "vpc10", _raw_vpc("vpc10", primary_peer_id)),
            ("SERIAL2", "vpc10", _raw_vpc("vpc10", peer_peer_id)),
        ]
    )

    projected, verified = coordinator._observed_overridden_vpc_after(resource_plan, FakeCollection([]))

    assert len(projected) == 1
    assert not verified


def test_observed_overridden_vpc_preserves_equal_names_on_independent_pairs():
    adapter = INTERFACE_FAMILY_ADAPTERS["vpc_access"]
    peer_cache = {
        "SERIAL1": "SERIAL2",
        "SERIAL2": "SERIAL1",
        "SERIAL3": "SERIAL4",
        "SERIAL4": "SERIAL3",
    }
    resource_plan = SimpleNamespace(
        adapter=adapter,
        proposed=(),
        orchestrator=SimpleNamespace(
            fabric_context=FakeFabricContext(),
            _peer_serial_cache=peer_cache,
        ),
    )
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=False))
    coordinator._snapshot = ProjectionSnapshot(
        [
            ("SERIAL1", "vpc10", _raw_vpc("vpc10", "SERIAL2", 100)),
            ("SERIAL2", "vpc10", _raw_vpc("vpc10", "SERIAL1", 100)),
            ("SERIAL3", "vpc10", _raw_vpc("vpc10", "SERIAL4", 200)),
            ("SERIAL4", "vpc10", _raw_vpc("vpc10", "SERIAL3", 200)),
        ]
    )

    projected, verified = coordinator._observed_overridden_vpc_after(resource_plan, FakeCollection([]))

    assert verified
    assert [(item["switch_ip"], item["interface_name"]) for item in projected] == [
        ("192.0.2.1", "vpc10"),
        ("192.0.2.3", "vpc10"),
    ]


def test_overridden_vpc_observation_uses_model_identity_order_without_false_diff():
    """Serial-pair ordering cannot make equal full-scope state appear changed."""
    context = InverseSerialOrderFabricContext()
    family = [
        _vpc_access_config("192.0.2.1", "SERIAL-Z2", 100),
        _vpc_access_config("192.0.2.3", "SERIAL-A2", 200),
    ]
    resource_plan = _projection_resource(
        "vpc_access",
        "overridden",
        family,
        family_before=family,
        family_after=family,
        context=context,
    )
    resource_plan.orchestrator._peer_serial_cache = {
        "SERIAL-Z1": "SERIAL-Z2",
        "SERIAL-Z2": "SERIAL-Z1",
        "SERIAL-A1": "SERIAL-A2",
        "SERIAL-A2": "SERIAL-A1",
    }
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=False, output_level="debug"))
    coordinator._snapshot = ProjectionSnapshot(
        [
            ("SERIAL-Z1", "vpc10", _raw_vpc("vpc10", "SERIAL-Z2", 100)),
            ("SERIAL-Z2", "vpc10", _raw_vpc("vpc10", "SERIAL-Z1", 100)),
            ("SERIAL-A1", "vpc10", _raw_vpc("vpc10", "SERIAL-A2", 200)),
            ("SERIAL-A2", "vpc10", _raw_vpc("vpc10", "SERIAL-A1", 200)),
        ]
    )

    result = coordinator._format_result(_projection_plan(resource_plan))
    projected = result["resources"][0]

    assert result["changed"] is False
    assert projected["changed"] is False
    assert projected["operations"] == []
    assert projected["before"] == projected["after"]
    assert "diff" not in projected
    assert projected["family_before"] == projected["family_after"]
    assert "family_diff" not in projected


def test_vpc_pair_map_is_authoritative_and_bidirectional(monkeypatch):
    module = FakeModule(check_mode=True)
    resources = [{"type": "vpc_access", "config": [{"switch_ip": "192.0.2.2"}]}]
    coordinator = InterfaceWorkflowCoordinator(module)
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: {"vpcPairs": [{"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"}]},
    )
    pair_map = coordinator._vpc_pair_map(resources=resources, fabric_context=FakeFabricContext(), rest_send=object())
    assert pair_map == {"192.0.2.1": "SERIAL2", "192.0.2.2": "SERIAL1"}
    assert coordinator._vpc_pair_gets == 1


def test_vpc_pair_map_accepts_consistent_duplicate_and_inverse_records(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: {
            "vpcPairs": [
                {"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"},
                {"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"},
                {"switchId": "SERIAL2", "peerSwitchId": "SERIAL1"},
            ]
        },
    )

    pair_map = coordinator._vpc_pair_map(resources=[{"type": "vpc_access", "config": []}], fabric_context=FakeFabricContext(), rest_send=object())
    assert pair_map == {"192.0.2.1": "SERIAL2", "192.0.2.2": "SERIAL1"}


def test_vpc_pair_map_paginates_intended_pairs_and_counts_actual_gets(monkeypatch):
    responses = iter(
        [
            {
                "vpcPairs": [{"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"}],
                "meta": {"counts": {"remaining": 1, "total": 2}},
            },
            {
                "vpcPairs": [{"switchId": "SERIAL3", "peerSwitchId": "SERIAL4"}],
                "meta": {"counts": {"remaining": 0, "total": 2}},
            },
        ]
    )
    requested_paths = []

    def request(*_args, **kwargs):
        requested_paths.append(kwargs["path"])
        return next(responses)

    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(coordinator, "_request", request)

    pair_map = coordinator._vpc_pair_map(
        resources=[{"type": "vpc_access", "config": [{"switch_ip": "192.0.2.1"}]}],
        fabric_context=FakeFabricContext(),
        rest_send=object(),
    )

    assert pair_map == {
        "192.0.2.1": "SERIAL2",
        "192.0.2.2": "SERIAL1",
        "192.0.2.3": "SERIAL4",
        "192.0.2.4": "SERIAL3",
    }
    assert len(requested_paths) == 2
    assert all("view=intendedPairs" in path for path in requested_paths)
    assert all("max=500" in path for path in requested_paths)
    assert all("sort=switchId%3Aasc" in path for path in requested_paths)
    assert "offset=0" in requested_paths[0]
    assert "offset=1" in requested_paths[1]
    assert coordinator._vpc_pair_gets == 2


def test_vpc_pair_map_rejects_self_pair(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: {"vpcPairs": [{"switchId": "SERIAL1", "peerSwitchId": "SERIAL1"}]},
    )

    with pytest.raises(InterfaceWorkflowValidationError, match=r"self-pair.*SERIAL1"):
        coordinator._vpc_pair_map(
            resources=[{"type": "vpc_access", "config": []}],
            fabric_context=FakeFabricContext(),
            rest_send=object(),
        )


def test_vpc_pair_map_rejects_conflicting_duplicate_mapping(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: {
            "vpcPairs": [
                {"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"},
                {"switchId": "SERIAL1", "peerSwitchId": "SERIAL3"},
            ]
        },
    )

    with pytest.raises(InterfaceWorkflowValidationError, match=r"conflicting.*SERIAL1.*SERIAL2.*SERIAL3"):
        coordinator._vpc_pair_map(
            resources=[{"type": "vpc_access", "config": []}],
            fabric_context=FakeFabricContext(),
            rest_send=object(),
        )


def test_vpc_pair_map_rejects_inverse_inconsistent_records(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: {
            "vpcPairs": [
                {"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"},
                {"switchId": "SERIAL2", "peerSwitchId": "SERIAL3"},
            ]
        },
    )

    with pytest.raises(InterfaceWorkflowValidationError, match=r"inverse-inconsistent.*SERIAL2.*SERIAL3.*SERIAL1"):
        coordinator._vpc_pair_map(
            resources=[{"type": "vpc_access", "config": []}],
            fabric_context=FakeFabricContext(),
            rest_send=object(),
        )


def test_vpc_group_rejects_switch_missing_from_authoritative_pair_inventory(
    monkeypatch,
):
    module = FakeModule(check_mode=True)
    resources = [{"type": "vpc_trunk_host", "config": [{"switch_ip": "192.0.2.99"}]}]
    coordinator = InterfaceWorkflowCoordinator(module)
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: {"vpcPairs": [{"switchId": "SERIAL1", "peerSwitchId": "SERIAL2"}]},
    )
    with pytest.raises(
        InterfaceWorkflowValidationError,
        match=r"resources\[0\]\.config\[0\].*192\.0\.2\.99",
    ):
        coordinator._vpc_pair_map(resources=resources, fabric_context=FakeFabricContext(), rest_send=object())


def test_non_vpc_workflow_skips_pair_inventory(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(
        coordinator,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("vPC request was not expected"),
    )
    pair_map = coordinator._vpc_pair_map(
        resources=[{"type": "loopback", "config": []}],
        fabric_context=FakeFabricContext(),
        rest_send=object(),
    )
    assert pair_map == {}
    assert coordinator._vpc_pair_gets == 0


def test_vpc_pair_inventory_count_remains_visible_in_request_stats():
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    coordinator._snapshot = SimpleNamespace(request_stats={"switches": 2, "interface_inventory_gets": 2})
    coordinator._vpc_pair_gets = 1

    result = coordinator._format_result(plan())

    assert result["request_stats"]["vpc_pair_gets"] == 1


def test_authoritative_pair_inventory_seeds_one_cache_shared_by_all_vpc_orchestrators():
    rest_send = RestSend({"fabric_name": "FABRIC1", "check_mode": True})
    fabric_context = FabricContext(rest_send=rest_send, fabric_name="FABRIC1")
    fabric_context._fabric_summary = {"local": True, "fabricStatus": "default"}
    fabric_context._switch_map = {"192.0.2.1": "SERIAL1", "192.0.2.2": "SERIAL2"}
    fabric_context._switch_map_by_id = {"SERIAL1": "192.0.2.1", "SERIAL2": "192.0.2.2"}
    requests = []
    snapshot = InterfaceStateSnapshot(
        fabric_name="FABRIC1",
        fabric_context=fabric_context,
        request=lambda **kwargs: requests.append(kwargs) or {"interfaces": []},
    )
    planner = InterfaceWorkflowPlanner(
        snapshot=snapshot,
        vpc_pair_by_switch_ip={
            "192.0.2.1": "SERIAL2",
            "192.0.2.2": "SERIAL1",
        },
    )

    workflow_plan = planner.plan(
        [
            {
                "type": "vpc_access",
                "config": [
                    {
                        "switch_ip": "192.0.2.1",
                        "interface_name": "vpc10",
                        "config_data": {"network_os": {"policy": {"access_vlan": 10}}},
                    }
                ],
            },
            {
                "type": "vpc_trunk_host",
                "config": [
                    {
                        "switch_ip": "192.0.2.2",
                        "interface_name": "vpc20",
                        "config_data": {"network_os": {"policy": {"allowed_vlans": "10-20"}}},
                    }
                ],
            },
        ]
    )

    access_orchestrator, trunk_orchestrator = (resource.orchestrator for resource in workflow_plan.resources)
    assert access_orchestrator._peer_serial_cache is trunk_orchestrator._peer_serial_cache
    assert access_orchestrator._peer_serial_cache == {
        "SERIAL1": "SERIAL2",
        "SERIAL2": "SERIAL1",
    }
    assert access_orchestrator._resolve_peer_switch_id("192.0.2.1", "SERIAL1") == "SERIAL2"
    assert trunk_orchestrator._resolve_peer_switch_id("192.0.2.2", "SERIAL2") == "SERIAL1"
    assert len(requests) == 2
