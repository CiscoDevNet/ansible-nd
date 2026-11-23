# Copyright: (c) 2026, Cisco Systems, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Offline integration of explicitly scoped missing-member preparation."""

from dataclasses import replace
from types import ModuleType, SimpleNamespace
import sys

import pytest

from ansible_collections.cisco.nd.plugins.module_utils import interface_workflow_coordinator as coordinator_module
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_coordinator import InterfaceWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import InterfaceWorkflowExecutor
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import InterfaceMemberPreparation, InterfaceWorkflowValidationError
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_workflow_coordinator as coordinator_fakes
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_workflow_executor as executor_fakes
from ansible_collections.cisco.nd.tests.unit.module_utils import test_interface_workflow_planner as planner_fakes

HELPER = "ansible_collections.cisco.nd.plugins.module_utils.interface_missing_member_preparation"


class RejectingParent(executor_fakes.FakeOrchestrator):
    """Return a definitive failed parent result after the auxiliary write."""

    def create_bulk(self, models):
        names = tuple(model.interface_name for model in models)
        self.events.append(("create", self.name, names))
        self.rest_send.record(
            "/interfaces",
            success=False,
            changed=False,
            return_code=207,
            data={"results": [{"name": name, "switchId": "SERIAL1", "status": "failed", "message": "parent rejected"} for name in names]},
        )
        raise RuntimeError("parent rejected")


def _prepared_plan(*, fail_parent=False):
    events = []
    parent_class = RejectingParent if fail_parent else executor_fakes.FakeOrchestrator
    parent = parent_class("parent", events)
    auxiliary = executor_fakes.FakeOrchestrator("missing-ethernet", events)
    parent_model = executor_fakes.FakeModel("port-channel42", policy_type="portChannelTrunkHost")
    parent_resource = executor_fakes.resource(
        0,
        parent,
        creates=[parent_model],
        resource_type="port_channel_trunk_host",
        actual=("before",),
    )
    parent_resource.adapter.safety = SimpleNamespace(guards_child_subinterfaces=False, owns_physical_members=False)
    preparations = tuple(
        InterfaceMemberPreparation(
            resource_index=1,
            resource_type="ethernet_trunk_host",
            source_action="create",
            switch_id="SERIAL1",
            interface_name=name,
            model=executor_fakes.FakeModel(name, policy_type="trunkHost"),
            current={},
            from_policy_type=None,
            to_policy_type="trunkHost",
            parent_resource_index=0,
            parent_action="create",
            parent_switch_id="SERIAL1",
            parent_name="port-channel42",
            parent_policy_type="portChannelTrunkHost",
            kind="missing_inventory",
            orchestrator=auxiliary,
            requires_member_update=False,
            expected_member_policy="poMember",
            parent_port_channel_id=42,
        )
        for name in ("Ethernet1/42", "Ethernet1/43")
    )
    member_resource = executor_fakes.resource(1, auxiliary, resource_type="ethernet_trunk_host", actual=("before",))
    member_resource.adapter.safety = SimpleNamespace(guards_child_subinterfaces=False, owns_physical_members=False)
    planner, _recorder = planner_fakes._planner()
    planner._member_preparations = list(preparations)
    layers = planner._build_execution_layers([parent_resource, member_resource])
    workflow_plan = executor_fakes.plan(
        parent_resource,
        member_resource,
        auxiliary_orchestrators=(),
        execution_layers=layers,
        member_preparations=preparations,
    )
    return workflow_plan, parent, auxiliary, events


def _phase_guard(monkeypatch, events, *, reject_phase=None):
    """Mock the independent fresh-state guard, retaining executor boundaries."""
    helper = ModuleType(HELPER)

    def refresh(preparations, snapshot, *, phase):
        names = tuple(preparation.interface_name for preparation in preparations)
        events.append(("guard", phase, names))
        assert all(preparation.expected_member_policy == "poMember" and preparation.parent_port_channel_id == 42 for preparation in preparations)
        creates = [event for event in events if event[0] == "create"]
        if phase == "absent":
            assert not creates
        elif phase == "prepared":
            assert creates == [("create", "missing-ethernet", ("Ethernet1/42", "Ethernet1/43"))]
        elif phase == "member":
            assert [event[1] for event in creates] == ["missing-ethernet", "parent"]
        else:
            pytest.fail("Unknown preparation observation phase")
        if phase == reject_phase:
            raise RuntimeError("Observed member has the wrong policy or parent owner")

    helper.refresh_missing_preparations = refresh
    helper.scoped_member_expectations = lambda *args, **kwargs: ((), ())
    monkeypatch.setitem(sys.modules, HELPER, helper)


def test_planner_orders_missing_preparation_before_parent_without_final_ethernet_update():
    workflow_plan, _parent, _auxiliary, _events = _prepared_plan()

    assert [[operation.action for operation in layer] for layer in workflow_plan.execution_layers] == [
        ["prepare_member", "prepare_member"],
        ["create"],
    ]
    assert {operation.resource_index for layer in workflow_plan.execution_layers for operation in layer} == {0, 1}
    assert all(not preparation.requires_member_update for preparation in workflow_plan.member_preparations)
    assert not any(operation.action == "update" for layer in workflow_plan.execution_layers for operation in layer)


def test_executor_prepares_auxiliary_then_verifies_real_parent_members_without_deploy(monkeypatch):
    workflow_plan, parent, auxiliary, events = _prepared_plan()
    _phase_guard(monkeypatch, events)

    result = InterfaceWorkflowExecutor(snapshot=executor_fakes.FakeSnapshot(events), deploy=False, verify=True).execute(workflow_plan)

    assert result.failed is False
    assert result.status == "staged"
    assert result.changed is True
    assert result.mutation_requests == 2  # Auxiliary POST and exact parent POST.
    assert result.deploy_requests == 0
    important = [event[:2] for event in events if event[0] in ("guard", "create", "update", "deploy")]
    assert important == [("guard", "absent"), ("create", "missing-ethernet"), ("guard", "prepared"), ("create", "parent"), ("guard", "member")]
    assert parent.deploy is False and auxiliary.deploy is False
    assert all(value["status"] == "succeeded" for value in result.member_preparations)
    assert all(value["verified_before_membership"] and value["verified_after_membership"] for value in result.member_preparations)
    assert all(value["member_update"]["status"] == "not_requested" for value in result.member_preparations)
    assert all(value["parent_operation"]["status"] == "succeeded" for value in result.member_preparations)


def test_accepted_auxiliary_then_rejected_parent_reports_truthful_partial_change(monkeypatch):
    workflow_plan, _parent, _auxiliary, events = _prepared_plan(fail_parent=True)
    _phase_guard(monkeypatch, events)

    result = InterfaceWorkflowExecutor(snapshot=executor_fakes.FakeSnapshot(events), deploy=False, verify=True).execute(workflow_plan)

    assert result.failed is True
    assert result.changed is True
    assert result.status == "partial_failure"
    assert result.mutation_requests == 2
    assert result.deploy_requests == 0
    assert all(value["status"] == "succeeded" for value in result.member_preparations)
    assert all(value["verified_before_membership"] for value in result.member_preparations)
    assert all(value["verified_after_membership"] is False for value in result.member_preparations)
    assert all(value["parent_operation"]["status"] == "failed" for value in result.member_preparations)
    assert not any(event[0] == "deploy" or event[:2] == ("guard", "member") for event in events)


def test_wrong_generated_member_fails_after_accepted_parent_without_claiming_verification(monkeypatch):
    workflow_plan, _parent, _auxiliary, events = _prepared_plan()
    _phase_guard(monkeypatch, events, reject_phase="member")

    result = InterfaceWorkflowExecutor(snapshot=executor_fakes.FakeSnapshot(events), deploy=False, verify=True).execute(workflow_plan)

    assert result.failed is True
    assert result.changed is True
    assert result.status == "partial_failure"
    assert result.deploy_requests == 0
    assert result.mutation_requests == 2
    assert any("wrong policy or parent owner" in error for error in result.errors)
    assert all(value["parent_operation"]["status"] == "succeeded" for value in result.member_preparations)
    assert all(value["verified_after_membership"] is False for value in result.member_preparations)
    assert not any(event[0] in ("update", "deploy") for event in events)


@pytest.mark.parametrize("deploy,verify", [(True, True), (False, False), (None, True)])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("kind", ["missing_inventory", "explicit_host_conversion"])
def test_explicit_missing_preparation_requires_verified_staging_before_executor(monkeypatch, deploy, verify, check_mode, kind):
    module = coordinator_fakes.FakeModule(check_mode=check_mode, verify_enabled=verify)
    module.params["config_actions"] = {"deploy": deploy}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan()
    workflow_plan.member_preparations = (SimpleNamespace(kind=kind),)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)
    coordinator.executor_factory = lambda **kwargs: pytest.fail("Unsafe preparation must not construct an executor")

    with pytest.raises(InterfaceWorkflowValidationError, match="Explicit member preparation requires"):
        coordinator.run()


def test_ordinary_workflow_uses_existing_planner_arguments_without_preparation_option(monkeypatch):
    module = coordinator_fakes.FakeModule(check_mode=True)
    coordinator = InterfaceWorkflowCoordinator(module)
    monkeypatch.setattr(coordinator, "_new_rest_send", lambda **kwargs: executor_fakes.FakeRestSend())
    monkeypatch.setattr(coordinator, "_request", lambda *args, **kwargs: pytest.fail("Empty ordinary planning must not make an API request"))
    captured = []
    sentinel = object()

    def factory(**kwargs):
        captured.append(kwargs)
        return SimpleNamespace(plan=lambda resources: sentinel)

    coordinator.planner_factory = factory

    assert coordinator._build_plan() is sentinel
    assert len(captured) == 1
    assert set(captured[0]) == {"snapshot", "rest_send_factory", "vpc_pair_by_switch_ip", "run_capability_preflight"}


def test_existing_host_conversion_still_requires_preparation_parent_and_final_update():
    workflow_plan, _parent, auxiliary, _events = _prepared_plan()
    parent_resource = workflow_plan.resources[0]
    legacy = replace(
        workflow_plan.member_preparations[0],
        resource_index=1,
        kind="existing_host_conversion",
        orchestrator=None,
        requires_member_update=True,
    )
    planner, _recorder = planner_fakes._planner()
    planner._member_preparations = [legacy]

    with pytest.raises(InterfaceWorkflowValidationError, match="final update"):
        planner._build_execution_layers([parent_resource])

    member_resource = executor_fakes.resource(1, auxiliary, updates=[legacy.model], resource_type="ethernet_trunk_host")
    member_resource.adapter.safety = SimpleNamespace(guards_child_subinterfaces=False, owns_physical_members=False)
    layers = planner._build_execution_layers([parent_resource, member_resource])

    assert [[operation.action for operation in layer] for layer in layers] == [["prepare_member"], ["create"], ["update"]]


def _observed_member_row():
    return {
        "resource_index": 1,
        "type": "ethernet_trunk_host",
        "switch_id": "SERIAL1",
        "switch_ip": "192.0.2.1",
        "interface_name": "Ethernet1/42",
        "parent_resource_index": 0,
        "parent_switch_id": "SERIAL1",
        "parent_interface_name": "port-channel42",
        "parent_policy_type": "trunkPoHost",
        "owner_switch_id": "SERIAL1",
        "configured_port_channel_id": 42,
        "policy_type": "poMember",
        "pair_validated": False,
    }


def test_explicit_member_noop_checks_fresh_ownership_before_output_or_equality(monkeypatch):
    events = []
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=True)
    module.params["config_actions"] = {"deploy": False}
    module.params["execution_options"] = {"desired_equality": True}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan(changed=False)
    proof = SimpleNamespace(switch_id="SERIAL1", interface_name="Ethernet1/42", parent_port_channel_id=42)
    workflow_plan.missing_member_verifications = (proof,)
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)
    coordinator.executor_factory = lambda **kwargs: pytest.fail("A no-op must not construct an executor")
    helper = ModuleType(HELPER)
    reject = {"member": False}

    def verify(preparations, snapshot, *, phase):
        assert preparations == (proof,) and snapshot is coordinator._snapshot and phase == "member"
        events.append("member")
        if reject["member"]:
            raise RuntimeError("Wrong actual member policy or parent")
        return (_observed_member_row(),)

    helper.refresh_missing_preparations = verify
    monkeypatch.setitem(sys.modules, HELPER, helper)
    ordinary_format = coordinator._format_result

    def format_result(*args, **kwargs):
        events.append("format")
        return ordinary_format(*args, **kwargs)

    def equality(**kwargs):
        events.append("equality")
        return {"complete": True, "all_satisfied": True}

    monkeypatch.setattr(coordinator, "_format_result", format_result)
    monkeypatch.setattr(coordinator_module, "desired_equality", equality)

    result = coordinator.run()

    assert events == ["member", "format", "equality"]
    assert result["changed"] is False and result["execution"]["status"] == "no_change"
    assert result["desired_equality"]["complete"] is True
    assert result["member_verifications"] == {
        "version": 1,
        "source": "native_explicit_member_ownership_v1",
        "observed": True,
        "complete": True,
        "request_sha256": result["workflow_contract"]["request_sha256"],
        "members": [_observed_member_row()],
    }
    events.clear()
    reject["member"] = True
    with pytest.raises(RuntimeError, match="Wrong actual member"):
        coordinator.run()
    assert events == ["member"]
    assert coordinator._member_verification_rows is None


def test_retry_with_retained_preparation_still_verifies_members_before_output_and_equality(monkeypatch):
    events, calls = [], []
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=True)
    module.params["config_actions"] = {"deploy": False}
    module.params["execution_options"] = {"desired_equality": True}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan(changed=True)
    assert workflow_plan.member_preparations == ()
    proof = SimpleNamespace(switch_id="SERIAL1", interface_name="Ethernet1/42", parent_port_channel_id=42)
    workflow_plan.missing_member_verifications = (proof,)
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)

    class RecordingExecutor(coordinator_fakes.FakeExecutor):
        def execute(self, workflow_plan, deployment_targets=()):
            events.append("execute")
            return super().execute(workflow_plan, deployment_targets=deployment_targets)

    coordinator.executor_factory = lambda **kwargs: RecordingExecutor(calls, **kwargs)
    helper = ModuleType(HELPER)

    def verify(preparations, snapshot, *, phase):
        assert preparations == (proof,) and snapshot is coordinator._snapshot and phase == "member"
        events.append("member")
        return (_observed_member_row(),)

    helper.refresh_missing_preparations = verify
    monkeypatch.setitem(sys.modules, HELPER, helper)
    ordinary_format = coordinator._format_result

    def format_result(*args, **kwargs):
        events.append("format")
        return ordinary_format(*args, **kwargs)

    def equality(**kwargs):
        events.append("equality")
        return {"complete": True, "all_satisfied": True}

    monkeypatch.setattr(coordinator, "_format_result", format_result)
    monkeypatch.setattr(coordinator_module, "desired_equality", equality)

    result = coordinator.run()

    assert events == ["execute", "member", "format", "equality"]
    assert result["changed"] is True and result["execution"]["status"] == "staged"
    assert result["member_preparations"] == []
    assert result["desired_equality"]["complete"] is True
    assert result["member_verifications"]["members"] == [_observed_member_row()]
    assert result["member_verifications"]["request_sha256"] == result["workflow_contract"]["request_sha256"]


@pytest.mark.parametrize("verify", [False, True])
def test_policy_only_member_noop_verifies_ownership_without_changing_generic_verify_option(monkeypatch, verify):
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=verify)
    module.params["config_actions"] = {"deploy": False}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan(changed=False)
    workflow_plan.missing_member_verifications = (SimpleNamespace(switch_id="SERIAL1"),)
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)
    coordinator.executor_factory = lambda **kwargs: pytest.fail("A no-op must not construct an executor")
    helper = ModuleType(HELPER)
    helper.refresh_missing_preparations = lambda *args, **kwargs: (_observed_member_row(),)
    monkeypatch.setitem(sys.modules, HELPER, helper)

    result = coordinator.run()

    assert result["changed"] is False
    assert result["member_verifications"]["members"] == [_observed_member_row()]
    assert result["member_verifications"]["request_sha256"] == result["workflow_contract"]["request_sha256"]


def test_check_mode_does_not_claim_observed_explicit_member_ownership(monkeypatch):
    module = coordinator_fakes.FakeModule(check_mode=True, verify_enabled=True)
    module.params["config_actions"] = {"deploy": False}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan(changed=False)
    workflow_plan.missing_member_verifications = (SimpleNamespace(switch_id="SERIAL1"),)
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)
    helper = ModuleType(HELPER)
    helper.refresh_missing_preparations = lambda *args, **kwargs: pytest.fail("Check mode cannot claim final observed membership")
    monkeypatch.setitem(sys.modules, HELPER, helper)

    result = coordinator.run()

    assert "member_verifications" not in result


def test_failed_execution_does_not_claim_observed_explicit_member_ownership(monkeypatch):
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=True)
    module.params["config_actions"] = {"deploy": False}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan(changed=True)
    workflow_plan.missing_member_verifications = (SimpleNamespace(switch_id="SERIAL1"),)
    coordinator._snapshot = SimpleNamespace(request_stats=workflow_plan.request_stats)
    monkeypatch.setattr(coordinator, "_build_plan", lambda: workflow_plan)
    coordinator.executor_factory = lambda **kwargs: coordinator_fakes.FakeExecutor([], failed=True, **kwargs)
    helper = ModuleType(HELPER)
    helper.refresh_missing_preparations = lambda *args, **kwargs: pytest.fail("Failed execution cannot claim final observed membership")
    monkeypatch.setitem(sys.modules, HELPER, helper)

    with pytest.raises(coordinator_module.InterfaceWorkflowExecutionFailed) as exc_info:
        coordinator.run()

    assert "member_verifications" not in exc_info.value.result


def test_incomplete_actual_member_readback_cannot_produce_a_complete_receipt(monkeypatch):
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=True)
    module.params["config_actions"] = {"deploy": False}
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan(changed=False)
    workflow_plan.missing_member_verifications = (SimpleNamespace(switch_id="SERIAL1"),)
    helper = ModuleType(HELPER)
    helper.refresh_missing_preparations = lambda *args, **kwargs: ()
    monkeypatch.setitem(sys.modules, HELPER, helper)

    with pytest.raises(RuntimeError, match="complete observed ownership"):
        coordinator._verify_missing_member_success(workflow_plan)

    assert coordinator._member_verification_rows is None


def test_deployed_existing_interface_workflow_skips_stage_only_member_recheck(monkeypatch):
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=True)
    coordinator = InterfaceWorkflowCoordinator(module)
    workflow_plan = coordinator_fakes.plan()
    workflow_plan.missing_member_verifications = (SimpleNamespace(switch_id="SERIAL1"),)
    helper = ModuleType(HELPER)
    helper.refresh_missing_preparations = lambda *args, **kwargs: pytest.fail("Ordinary deployed workflows retain their existing verification path")
    monkeypatch.setitem(sys.modules, HELPER, helper)

    coordinator._verify_missing_member_success(workflow_plan)


def test_ordinary_workflow_without_explicit_member_expectations_skips_recheck(monkeypatch):
    module = coordinator_fakes.FakeModule(check_mode=False, verify_enabled=True)
    module.params["config_actions"] = {"deploy": False}
    coordinator = InterfaceWorkflowCoordinator(module)
    helper = ModuleType(HELPER)
    helper.refresh_missing_preparations = lambda *args, **kwargs: pytest.fail("No explicit aggregate-member request requires no member recheck")
    monkeypatch.setitem(sys.modules, HELPER, helper)

    coordinator._verify_missing_member_success(coordinator_fakes.plan())


def test_real_typed_explicit_ethernet_resource_prepares_then_stages_parent(monkeypatch):
    from copy import deepcopy
    from ansible_collections.cisco.nd.plugins.module_utils import interface_missing_member_preparation as helper
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base import NDBaseOrchestrator
    from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.ethernet_trunk_host_interface import EthernetTrunkHostInterfaceOrchestrator

    planner, _recorder = planner_fakes._planner(switches={"192.0.2.1": "SERIAL1"}, responses=[{"interfaces": []}])
    planner_fakes._set_non_vpc_topology(planner)
    phases, sent, wire = [], [], {}
    monkeypatch.setattr(helper, "refresh_missing_preparations", lambda preparations, snapshot, phase="absent": phases.append(phase))
    resources = [
        {
            "type": "port_channel_trunk_host",
            "state": "merged",
            "config": [planner_fakes._port_channel("192.0.2.1", "port-channel42", members=["Ethernet1/42", "Ethernet1/43"])],
        },
        {
            "type": "ethernet_trunk_host",
            "state": "merged",
            "config": [
                {
                    "switch_ip": "192.0.2.1",
                    "interface_names": ["Ethernet1/42", "Ethernet1/43"],
                    "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "trunkHost"}}},
                }
            ],
        },
    ]

    workflow_plan = planner.plan(resources)

    assert workflow_plan.member_preparations
    assert workflow_plan.auxiliary_orchestrators == ()
    assert isinstance(workflow_plan.resources[1].orchestrator, EthernetTrunkHostInterfaceOrchestrator)
    assert all(item.resource_index == 1 and item.parent_resource_index == 0 for item in workflow_plan.member_preparations)

    def transport(orchestrator, path, verb, data=None, **kwargs):
        method = getattr(verb, "value", str(verb)).upper()
        assert method == "POST" and path.endswith("/interfaces")
        sent.append((type(orchestrator).__name__, deepcopy(data)))
        rows = data["interfaces"]
        wire.update((row["interfaceName"].casefold(), deepcopy(row)) for row in rows)
        body = {"results": [{"name": row["interfaceName"], "switchId": row["switchId"], "status": "success"} for row in rows]}
        response = {"METHOD": method, "REQUEST_PATH": path, "RETURN_CODE": 200, "DATA": body}
        outcome = {"success": True, "changed": True}
        sender = orchestrator.rest_send
        sender.response_current = response
        sender.add_response(response)
        sender.result_current = outcome
        sender.add_result(outcome)
        return body

    monkeypatch.setattr(NDBaseOrchestrator, "_request", transport)
    from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend

    def metadata_probe(sender):
        assert "/capableSwitches?" in sender.path
        response = {
            "METHOD": "GET",
            "REQUEST_PATH": sender.path,
            "RETURN_CODE": 200,
            "DATA": {"switches": [{"switchId": "SERIAL1", "switchName": "switch-1", "model": "N9K-C9300v"}]},
        }
        outcome = {"success": True, "changed": False}
        sender.response_current = response
        sender.add_response(response)
        sender.result_current = outcome
        sender.add_result(outcome)

    monkeypatch.setattr(RestSend, "commit", metadata_probe)
    monkeypatch.setattr(type(planner.fabric_context), "validate_for_mutation", lambda context: None)
    monkeypatch.setattr(
        planner.snapshot, "_request", lambda **kwargs: {"interfaces": list(deepcopy(wire).values()), "meta": {"counts": {"total": len(wire), "remaining": 0}}}
    )
    monkeypatch.setattr(planner.snapshot, "invalidate_topology_evidence", lambda: None)
    result = InterfaceWorkflowExecutor(snapshot=planner.snapshot, deploy=False, verify=True).execute(workflow_plan)

    assert result.failed is False, result.errors
    assert result.mutation_requests == 2 and result.deploy_requests == 0
    assert len(sent) == 2
    assert sent[0][0] == "EthernetTrunkHostInterfaceOrchestrator"
    assert {row["interfaceName"] for row in sent[0][1]["interfaces"]} == {"Ethernet1/42", "Ethernet1/43"}
    assert all(value["verified_before_membership"] and value["verified_after_membership"] for value in result.member_preparations)
    assert all(value["member_update"]["status"] == "not_requested" for value in result.member_preparations)
    assert phases[-3:] == ["absent", "prepared", "member"]
