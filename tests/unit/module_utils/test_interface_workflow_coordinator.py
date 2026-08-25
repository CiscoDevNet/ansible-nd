# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for the Phase 3 public interface workflow coordinator."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import (
    InterfaceWorkflowCoordinator,
    InterfaceWorkflowExecutionFailed,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfaceWorkflowValidationError,
)


class FakeCollection:
    """Small NDConfigCollection-compatible serializer for coordinator output tests."""

    def __init__(self, config):
        self.config = config

    def to_ansible_config(self):
        return self.config

    def get_diff_collection(self, other):
        return self.config != other.config


class FakeModel:
    """Small model serializer for action output."""

    def __init__(self, value):
        self.value = value

    def to_config(self):
        return self.value


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


def resource(index, *, changed=True):
    """Return one InterfaceResourcePlan-shaped object."""
    before_config = [{"interface_name": f"Ethernet1/{index + 1}", "value": "old"}]
    after_config = [{"interface_name": f"Ethernet1/{index + 1}", "value": "new"}] if changed else before_config
    before = FakeCollection(before_config)
    after = FakeCollection(after_config)
    operations = SimpleNamespace(
        after=after,
        creates=((FakeModel({"interface_name": f"Ethernet1/{index + 1}"}),) if changed else ()),
        updates=(),
        deletes=(),
    )
    return SimpleNamespace(
        resource_index=index,
        resource_type="ethernet_access",
        adapter=SimpleNamespace(module_name="cisco.nd.nd_interface_ethernet_access"),
        state="merged",
        changed=changed,
        before=before,
        proposed=FakeCollection(after_config),
        operations=operations,
    )


def plan(*, changed=True):
    """Return one InterfaceWorkflowPlan-shaped object with repeated family types."""
    resources = (resource(0, changed=changed), resource(1, changed=False))
    return SimpleNamespace(
        changed=changed,
        fabric_name="FABRIC1",
        mutation_count=1 if changed else 0,
        target_switch_ids=("SERIAL1", "SERIAL2"),
        resources=resources,
        request_stats={"switches": 2, "interface_inventory_gets": 2},
    )


class FakeExecution:
    """InterfaceWorkflowExecution-compatible result for coordinator wiring tests."""

    def __init__(self, workflow_plan, *, failed=False):
        self.changed = not failed
        self.failed = failed
        self.message = "execution failed" if failed else ""
        self.mutation_requests = 1
        self.deploy_requests = 1 if not failed else 0
        self.actual_after_by_resource = {item.resource_index: item.operations.after if not failed else item.before for item in workflow_plan.resources}

    def to_dict(self):
        return {
            "status": "failed" if self.failed else "completed",
            "mutations_sent": self.mutation_requests,
            "deployments_sent": self.deploy_requests,
            "affected_switch_ids": ["SERIAL1"],
            "items": [],
            "deployment": {
                "requested": True,
                "status": "succeeded" if not self.failed else "not_attempted",
                "targets": [],
            },
            "errors": [self.message] if self.failed else [],
        }


class FakeExecutor:
    """Capture coordinator execution settings and return a configured result."""

    def __init__(self, calls, *, failed=False, **kwargs):
        self.calls = calls
        self.failed = failed
        self.calls.append(("init", kwargs))

    def execute(self, workflow_plan):
        self.calls.append(("execute", workflow_plan))
        return FakeExecution(workflow_plan, failed=self.failed)


def test_check_mode_result_retains_repeated_groups_and_reports_planned_change():
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    result = coordinator._format_result(plan())

    assert result["changed"] is True
    assert result["planned_changed"] is True
    assert result["execution"]["status"] == "check_mode"
    assert result["execution"]["mutations_sent"] == 0
    assert [item["resource_index"] for item in result["resources"]] == [0, 1]
    assert [item["type"] for item in result["resources"]] == [
        "ethernet_access",
        "ethernet_access",
    ]
    assert result["resources"][0]["diff"] == {
        "before": [{"interface_name": "Ethernet1/1", "value": "old"}],
        "after": [{"interface_name": "Ethernet1/1", "value": "new"}],
    }
    assert result["resources"][0]["after_verified"] is False
    assert "proposed" not in result["resources"][0]
    assert result["request_stats"]["interface_inventory_gets"] == 2
    assert result["request_stats"]["mutation_requests"] == 0
    assert result["request_stats"]["deploy_requests"] == 0


def test_info_output_includes_normalized_proposed_config():
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True, output_level="info"))
    result = coordinator._format_result(plan())
    assert result["resources"][0]["proposed"][0]["value"] == "new"


def test_check_mode_run_returns_complete_plan_without_execution(monkeypatch):
    coordinator = InterfaceWorkflowCoordinator(FakeModule(check_mode=True))
    monkeypatch.setattr(coordinator, "_build_plan", lambda: plan())
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

    assert result["config_actions"] == {}
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
    assert result["request_stats"]["mutation_requests"] == 1
    assert result["request_stats"]["deploy_requests"] == 1


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
    monkeypatch.setattr(coordinator, "_build_plan", lambda: plan())

    with pytest.raises(InterfaceWorkflowExecutionFailed) as exc_info:
        coordinator.run()

    assert exc_info.value.result["failed"] is True
    assert exc_info.value.result["execution"]["status"] == "failed"
    assert exc_info.value.result["request_stats"]["mutation_requests"] == 1


class FakeFabricContext:
    fabric_name = "FABRIC1"

    switch_ip_by_id = {"SERIAL1": "192.0.2.1", "SERIAL2": "192.0.2.2"}

    def get_switch_ip(self, switch_id):
        try:
            return self.switch_ip_by_id[switch_id]
        except KeyError as exc:
            raise RuntimeError("unknown switch") from exc


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
