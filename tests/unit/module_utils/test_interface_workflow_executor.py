# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for aggregate interface mutation execution."""

from __future__ import annotations

from types import SimpleNamespace

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import (
    InterfaceWorkflowExecutor,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_planner import (
    InterfacePolicyTransition,
    InterfaceWorkflowPlanner,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vpc_interface_base import (
    VpcInterfaceBaseOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class FakeModel:
    """Minimal interface model used by the executor."""

    def __init__(self, name, switch_ip="192.0.2.1", policy_type=None):
        self.interface_name = name
        self.switch_ip = switch_ip
        self.policy_type = policy_type

    def get_identifier_value(self):
        return self.switch_ip, self.interface_name


class FakeCollection:
    """Minimal collection used for actual-state reconciliation."""

    def __init__(self, values):
        self.values = list(values)

    def __iter__(self):
        return iter(self.values)

    def get_diff_collection(self, other):
        return self.values != other.values


class FakeRestSend:
    """Record controller request/response history."""

    def __init__(self):
        self.check_mode = True
        self.params = {"check_mode": True}
        self.responses = []
        self.results = []

    def record(self, path, *, success=True, changed=True, data=None, method="POST", return_code=None):
        self.responses.append(
            {
                "METHOD": method,
                "REQUEST_PATH": path,
                "RETURN_CODE": return_code if return_code is not None else (200 if success else 207),
                "DATA": data or {},
            }
        )
        self.results.append({"success": success, "changed": changed})


class FakeFabricContext:
    """Resolve two stable switch identities."""

    switch_ids = {"192.0.2.1": "SERIAL1", "192.0.2.2": "SERIAL2"}

    def get_switch_id(self, switch_ip):
        return self.switch_ids[switch_ip]


class FakeOrchestrator:
    """Develop-orchestrator lifecycle surface used by the executor."""

    supports_bulk_delete = True
    supports_bulk_create = True

    def __init__(
        self,
        name,
        events,
        *,
        fail_preflight=False,
        fail_create=False,
        fail_deploy=False,
        fail_transition=False,
    ):
        self.name = name
        self.events = events
        self.fail_preflight = fail_preflight
        self.fail_create = fail_create
        self.fail_deploy = fail_deploy
        self.rest_send = FakeRestSend()
        self.results = SimpleNamespace(check_mode=True)
        self.fabric_context = FakeFabricContext()
        self.deploy = True
        self._deploys = []
        self._removes = []
        self.fail_transition = fail_transition

    @property
    def pending_deploys(self):
        return tuple(self._deploys)

    @property
    def pending_removes(self):
        return tuple(self._removes)

    def queue_deploy_targets(self, targets):
        for target in targets:
            if target not in self._deploys:
                self._deploys.append(target)

    def queue_remove_targets(self, targets):
        for target in targets:
            if target not in self._removes:
                self._removes.append(target)

    def validate_prerequisites(self):
        self.events.append(("validate", self.name))

    def preflight_create(self, _models):
        self.events.append(("preflight_create", self.name))

    def preflight(self, _models):
        self.events.append(("preflight", self.name))
        if self.fail_preflight:
            raise RuntimeError("switch is not capable")

    def delete_bulk(self, models):
        self.events.append(("delete_bulk", self.name, tuple(model.interface_name for model in models)))
        for model in models:
            target = (
                model.interface_name,
                self.fabric_context.get_switch_id(model.switch_ip),
            )
            self.queue_remove_targets([target])
            self.queue_deploy_targets([target])

    def remove_pending(self):
        self.events.append(("remove", self.name, tuple(self._removes)))
        self.rest_send.record("/interfaceActions/remove")
        self._removes = []

    def update(self, model, existing_data=None):
        target = (
            model.interface_name,
            self.fabric_context.get_switch_id(model.switch_ip),
        )
        action = "transition" if existing_data is not None else "update"
        self.events.append((action, self.name, model.interface_name))
        if action == "transition" and self.fail_transition:
            self.rest_send.record(f"/interfaces/{model.interface_name}", success=False, changed=False, method="PUT")
            raise RuntimeError("policy transition rejected")
        self.rest_send.record(f"/interfaces/{model.interface_name}", method="PUT")
        self.queue_deploy_targets([target])

    def create_bulk(self, models):
        names = tuple(model.interface_name for model in models)
        self.events.append(("create", self.name, names))
        if self.fail_create:
            outcomes = [
                {"name": names[0], "switchId": "SERIAL1", "status": "success"},
                {
                    "name": names[1],
                    "switchId": "SERIAL1",
                    "status": "failed",
                    "message": "invalid policy",
                },
            ]
            self.rest_send.record("/interfaces", success=False, changed=True, data={"results": outcomes})
            raise RuntimeError("mixed create result")
        self.rest_send.record("/interfaces")
        for model in models:
            target = (
                model.interface_name,
                self.fabric_context.get_switch_id(model.switch_ip),
            )
            self.queue_deploy_targets([target])

    def deploy_pending(self):
        targets = tuple(self._deploys)
        self.events.append(("deploy", self.name, targets))
        if self.fail_deploy:
            outcomes = [
                {"name": targets[0][0], "switchId": targets[0][1], "status": "success"},
                {
                    "name": targets[1][0],
                    "switchId": targets[1][1],
                    "status": "failed",
                    "message": "switch rejected deploy",
                },
            ]
            self.rest_send.record(
                "/interfaceActions/deploy",
                success=False,
                changed=True,
                data={"results": outcomes},
            )
            raise RuntimeError("mixed deploy result")
        self.rest_send.record("/interfaceActions/deploy")
        self._deploys = []


class PolicyGroupedFakeOrchestrator(FakeOrchestrator):
    """Model the loopback orchestrator one-request-per-policy create boundary."""

    def create_bulk(self, models):
        names = tuple(model.interface_name for model in models)
        policy_types = {model.policy_type for model in models}
        assert len(policy_types) == 1
        policy_type = next(iter(policy_types))
        self.events.append(("create", self.name, names, policy_type))
        if policy_type == "mplsLoopback":
            self.rest_send.record(
                "/interfaces",
                success=False,
                changed=False,
                data={
                    "results": [
                        {
                            "name": names[0],
                            "switchId": "SERIAL1",
                            "status": "failed",
                            "message": "policy group rejected",
                        }
                    ]
                },
            )
            raise RuntimeError("policy group create failed")
        self.rest_send.record("/interfaces")
        for model in models:
            target = (
                model.interface_name,
                self.fabric_context.get_switch_id(model.switch_ip),
            )
            self.queue_deploy_targets([target])


class NormalReturn207CreateFakeOrchestrator(FakeOrchestrator):
    """Return HTTP 207 without raising, optionally omitting the final requested target."""

    def __init__(self, name, events, *, omit_last):
        super().__init__(name, events)
        self.omit_last = omit_last

    def create_bulk(self, models):
        names = tuple(model.interface_name for model in models)
        self.events.append(("create", self.name, names))
        reported = models[:-1] if self.omit_last else models
        outcomes = [
            {
                "name": model.interface_name,
                "switchId": self.fabric_context.get_switch_id(model.switch_ip),
                "status": "success",
            }
            for model in reported
        ]
        self.rest_send.record(
            "/interfaces",
            success=True,
            changed=True,
            data={"results": outcomes},
            return_code=207,
        )
        for model in models:
            self.queue_deploy_targets(
                [
                    (
                        model.interface_name,
                        self.fabric_context.get_switch_id(model.switch_ip),
                    )
                ]
            )


class NormalReturn207DeployFakeOrchestrator(FakeOrchestrator):
    """Return a superficially successful HTTP 207 that omits one deployed target."""

    def deploy_pending(self):
        targets = tuple(self._deploys)
        self.events.append(("deploy", self.name, targets))
        self.rest_send.record(
            "/interfaceActions/deploy",
            success=True,
            changed=True,
            data={
                "results": [
                    {
                        "name": targets[0][0],
                        "switchId": targets[0][1],
                        "status": "success",
                    }
                ]
            },
            return_code=207,
        )
        self._deploys = []


class MixedSwitch207DeployFakeOrchestrator(FakeOrchestrator):
    """Fail deployment with per-switch outcomes rather than per-interface outcomes."""

    def deploy_pending(self):
        targets = tuple(self._deploys)
        self.events.append(("deploy", self.name, targets))
        self.rest_send.record(
            "/interfaceActions/deploy",
            success=False,
            changed=True,
            data={
                "results": [
                    {
                        "name": "loopback2",
                        "switchId": "SERIAL1",
                        "status": "failed",
                        "message": "interface rejected deploy",
                    }
                ],
                "switchIds": [
                    {"switchId": "SERIAL1", "status": "success"},
                    {
                        "switchId": "SERIAL2",
                        "status": "failed",
                        "message": "switch rejected deploy",
                    },
                ],
            },
        )
        raise RuntimeError("mixed per-switch deploy result")


class NormalReturn207EthernetFakeOrchestrator(FakeOrchestrator):
    """Model Ethernet normalize returning HTTP 207 while omitting one target."""

    def __init__(self, name, events):
        super().__init__(name, events)
        self._normalizes = []
        self._resets = []

    @property
    def pending_normalizes(self):
        return tuple(self._normalizes)

    @property
    def pending_resets(self):
        return tuple(self._resets)

    def queue_normalize_targets(self, targets):
        for target in targets:
            if target not in self._normalizes:
                self._normalizes.append(target)

    def queue_reset_targets(self, targets):
        for target in targets:
            if target not in self._resets:
                self._resets.append(target)

    def delete_bulk(self, models):
        self.events.append(("delete_bulk", self.name, tuple(model.interface_name for model in models)))
        for model in models:
            target = (
                model.interface_name,
                self.fabric_context.get_switch_id(model.switch_ip),
            )
            self.queue_normalize_targets([target])
            self.queue_deploy_targets([target])

    def remove_pending(self):
        targets = tuple(self._normalizes)
        self.events.append(("normalize", self.name, targets))
        self.rest_send.record(
            "/interfaceActions/normalize",
            success=True,
            changed=True,
            data={
                "results": [
                    {
                        "name": targets[0][0],
                        "switchId": targets[0][1],
                        "status": "success",
                    }
                ]
            },
            return_code=207,
        )
        self._normalizes = []
        self._resets = []


class FakeAdapter:
    """Return a preselected actual collection after snapshot refresh."""

    ownership_domain = "loopback"

    def __init__(self, actual):
        self.actual = actual

    def existing_collection(self, _orchestrator):
        return self.actual


class FakeSnapshot:
    """Record dirty/refresh lifecycle calls."""

    def __init__(self, events):
        self.events = events
        self._refreshes = 0
        self._dirty_refetches = 0
        self._interface_inventory_gets = 0

    def mark_dirty(self, switch_ids):
        self.events.append(("dirty", tuple(switch_ids)))

    def refresh(self, switch_ids):
        switch_ids = tuple(dict.fromkeys(switch_ids))
        self.events.append(("refresh", switch_ids))
        self._refreshes += len(switch_ids)
        self._dirty_refetches += len(switch_ids)
        self._interface_inventory_gets += len(switch_ids)

    @property
    def request_stats(self):
        """Return the refresh counters relevant to optional verification tests."""
        return {
            "interface_inventory_gets": self._interface_inventory_gets,
            "interface_inventory_refreshes": self._refreshes,
            "interface_inventory_dirty_refetches": self._dirty_refetches,
        }


def resource(index, orchestrator, *, deletes=(), transitions=(), updates=(), creates=(), actual=("after",)):
    """Build one InterfaceResourcePlan-shaped value."""
    before = FakeCollection(["before"])
    return SimpleNamespace(
        resource_index=index,
        resource_type="loopback",
        state="merged",
        proposed=FakeCollection(["proposed"]),
        before=before,
        transitions=tuple(transitions),
        operations=SimpleNamespace(deletes=tuple(deletes), updates=tuple(updates), creates=tuple(creates)),
        orchestrator=orchestrator,
        adapter=FakeAdapter(FakeCollection(actual)),
    )


def policy_transition(name="Ethernet1/1"):
    """Build one explicit routed-to-access transition."""
    return InterfacePolicyTransition(
        desired=FakeModel(name),
        current={"configData": {"networkOS": {"policy": {"policyType": "routedHost"}}}},
        switch_ip="192.0.2.1",
        switch_id="SERIAL1",
        interface_name=name,
        from_policy_type="routedHost",
        to_policy_type="accessHost",
    )


def plan(*resources):
    """Build one InterfaceWorkflowPlan-shaped value."""
    return SimpleNamespace(resources=tuple(resources), target_switch_ids=("SERIAL1", "SERIAL2"))


def test_executor_orders_phases_consolidates_remove_and_deploy_then_refreshes():
    events = []
    first = FakeOrchestrator("first", events)
    second = FakeOrchestrator("second", events)
    workflow_plan = plan(
        resource(
            0,
            first,
            deletes=[FakeModel("loopback1")],
            updates=[FakeModel("loopback2")],
            creates=[FakeModel("loopback3")],
        ),
        resource(
            1,
            second,
            deletes=[FakeModel("loopback4", "192.0.2.2")],
            creates=[FakeModel("loopback5", "192.0.2.2")],
        ),
    )

    snapshot = FakeSnapshot(events)
    result = InterfaceWorkflowExecutor(snapshot=snapshot, deploy=True, verify=True).execute(workflow_plan)

    phase_names = [event[0] for event in events]
    assert result.failed is False
    assert result.status == "completed"
    assert result.changed is True
    assert result.mutation_requests == 4
    assert result.deploy_requests == 1
    assert phase_names.index("remove") < phase_names.index("update") < phase_names.index("create") < phase_names.index("deploy")
    assert phase_names.count("remove") == 1
    assert phase_names.count("deploy") == 1
    remove_event = next(event for event in events if event[0] == "remove")
    assert set(remove_event[2]) == {("loopback1", "SERIAL1"), ("loopback4", "SERIAL2")}
    deploy_event = next(event for event in events if event[0] == "deploy")
    assert set(deploy_event[2]) == {
        ("loopback1", "SERIAL1"),
        ("loopback2", "SERIAL1"),
        ("loopback3", "SERIAL1"),
        ("loopback4", "SERIAL2"),
        ("loopback5", "SERIAL2"),
    }
    assert events[-2:] == [
        ("dirty", ("SERIAL1", "SERIAL2")),
        ("refresh", ("SERIAL1", "SERIAL2")),
    ]
    assert snapshot.request_stats == {
        "interface_inventory_gets": 2,
        "interface_inventory_refreshes": 2,
        "interface_inventory_dirty_refetches": 2,
    }
    assert set(result.actual_after_by_resource) == {0, 1}
    assert {item.status for item in result.items} == {"succeeded"}


class SuccessfulChangedFalseFakeOrchestrator(FakeOrchestrator):
    """Return exact mutation success while the generic result changed flag is false."""

    def create_bulk(self, models):
        super().create_bulk(models)
        self.rest_send.results[-1]["changed"] = False


def test_executor_defaults_to_no_verification_and_skips_post_mutation_inventory_gets():
    events = []
    orchestrator = SuccessfulChangedFalseFakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1")]))
    snapshot = FakeSnapshot(events)

    result = InterfaceWorkflowExecutor(snapshot=snapshot).execute(workflow_plan)

    assert result.failed is False
    assert result.changed is True
    assert result.status == "staged"
    assert result.actual_after_by_resource == {}
    assert not any(event[0] in {"dirty", "refresh"} for event in events)
    assert snapshot.request_stats == {
        "interface_inventory_gets": 0,
        "interface_inventory_refreshes": 0,
        "interface_inventory_dirty_refetches": 0,
    }


def test_executor_defaults_to_staging_changes_without_deployment():
    events = []
    orchestrator = FakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events)).execute(workflow_plan)

    assert result.failed is False
    assert result.status == "staged"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert result.deployment["requested"] is False
    assert result.deployment["status"] == "disabled"
    assert "deploy" not in [event[0] for event in events]
    assert not any(event[0] in {"dirty", "refresh"} for event in events)
    assert result.actual_after_by_resource == {}


def test_deployment_only_execution_sends_one_exact_target_without_mutation_or_refresh():
    events = []
    orchestrator = FakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, actual=("before",)))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(
        workflow_plan,
        deployment_targets=(("loopback1", "SERIAL1"),),
    )

    assert result.failed is False
    assert result.status == "completed"
    assert result.changed is True
    assert result.mutation_requests == 0
    assert result.deploy_requests == 1
    assert result.affected_switch_ids == ()
    assert result.items == ()
    assert result.actual_after_by_resource[0].values == ["before"]
    assert result.deployment == {
        "requested": True,
        "status": "succeeded",
        "targets": [{"interface_name": "loopback1", "switch_id": "SERIAL1", "status": "succeeded"}],
    }
    assert events == [
        ("validate", "only"),
        ("deploy", "only", (("loopback1", "SERIAL1"),)),
    ]


def test_supplemental_and_mutation_deployment_targets_are_deduplicated_into_one_post():
    events = []
    orchestrator = FakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(
        workflow_plan,
        deployment_targets=(("loopback1", "SERIAL1"), ("loopback2", "SERIAL1")),
    )

    deploy_events = [event for event in events if event[0] == "deploy"]
    assert result.failed is False
    assert result.mutation_requests == 1
    assert result.deploy_requests == 1
    assert len(deploy_events) == 1
    assert set(deploy_events[0][2]) == {
        ("loopback1", "SERIAL1"),
        ("loopback2", "SERIAL1"),
    }


def test_partial_deployment_only_failure_reports_successful_target_as_changed():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_deploy=True)
    workflow_plan = plan(resource(0, orchestrator, actual=("before",)))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(
        workflow_plan,
        deployment_targets=(("loopback1", "SERIAL1"), ("loopback2", "SERIAL1")),
    )

    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.changed is True
    assert result.mutation_requests == 0
    assert result.deploy_requests == 1
    assert result.deployment["status"] == "partial_failure"
    assert {target["interface_name"]: target["status"] for target in result.deployment["targets"]} == {
        "loopback1": "succeeded",
        "loopback2": "failed",
    }


def test_transition_put_precedes_ordinary_updates_and_creates_then_deploys_once():
    events = []
    orchestrator = FakeOrchestrator("only", events)
    workflow_plan = plan(
        resource(
            0,
            orchestrator,
            transitions=[policy_transition("Ethernet1/1")],
            updates=[FakeModel("Ethernet1/2")],
            creates=[FakeModel("Ethernet1/3")],
        )
    )

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    phase_names = [event[0] for event in events]
    assert result.failed is False
    assert result.status == "completed"
    assert result.mutation_requests == 3
    assert result.deploy_requests == 1
    assert phase_names.index("transition") < phase_names.index("update") < phase_names.index("create") < phase_names.index("deploy")
    transition_item = next(item for item in result.items if item.action == "transition")
    assert transition_item.status == "succeeded"
    assert transition_item.to_dict() == {
        "resource_index": 0,
        "type": "loopback",
        "action": "transition",
        "switch_ip": "192.0.2.1",
        "switch_id": "SERIAL1",
        "interface_name": "Ethernet1/1",
        "status": "succeeded",
        "from_policy_type": "routedHost",
        "to_policy_type": "accessHost",
    }
    deploy_event = next(event for event in events if event[0] == "deploy")
    assert set(deploy_event[2]) == {
        ("Ethernet1/1", "SERIAL1"),
        ("Ethernet1/2", "SERIAL1"),
        ("Ethernet1/3", "SERIAL1"),
    }


def test_transition_with_deploy_false_stages_one_put_without_physical_deployment():
    events = []
    orchestrator = FakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, transitions=[policy_transition()]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=False).execute(workflow_plan)

    assert result.failed is False
    assert result.status == "staged"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert result.deployment["requested"] is False
    assert result.deployment["status"] == "disabled"
    assert [event[0] for event in events].count("transition") == 1
    assert "deploy" not in [event[0] for event in events]


def test_transition_failure_stops_updates_creates_and_deployment():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_transition=True)
    workflow_plan = plan(
        resource(
            0,
            orchestrator,
            transitions=[policy_transition("Ethernet1/1")],
            updates=[FakeModel("Ethernet1/2")],
            creates=[FakeModel("Ethernet1/3")],
            actual=("before",),
        )
    )

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    status_by_action = {item.action: item.status for item in result.items}
    assert result.failed is True
    assert result.status == "failed"
    assert result.changed is False
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert status_by_action == {
        "transition": "failed",
        "update": "not_attempted",
        "create": "not_attempted",
    }
    assert result.deployment["status"] == "not_attempted"
    assert not any(event[0] in {"update", "create", "deploy"} for event in events)
    assert events[-2:] == [
        ("dirty", ("SERIAL1", "SERIAL2")),
        ("refresh", ("SERIAL1", "SERIAL2")),
    ]
    assert result.actual_after_by_resource[0].values == ["before"]


def test_preflight_failure_sends_no_writes_and_leaves_every_item_not_attempted():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_preflight=True)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1")], actual=("before",)))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    assert result.failed is True
    assert result.status == "failed"
    assert result.changed is False
    assert result.mutation_requests == 0
    assert result.deploy_requests == 0
    assert result.items[0].status == "not_attempted"
    assert not any(event[0] in {"create", "deploy", "dirty", "refresh"} for event in events)


def test_preflight_failure_reconciles_equal_vpc_names_by_pair_without_false_change(monkeypatch):
    """A read-only failed run keeps independent same-name pairs and reports no controller change."""
    switch_map = {
        "192.0.2.1": "SERIAL1",
        "192.0.2.2": "SERIAL2",
        "192.0.2.3": "SERIAL3",
        "192.0.2.4": "SERIAL4",
    }
    peer_ids = ("SERIAL2", "SERIAL1", "SERIAL4", "SERIAL3")
    responses = iter(
        {
            "interfaces": [
                {
                    "interfaceName": "vpc10",
                    "interfaceType": "vpc",
                    "configData": {
                        "mode": "access",
                        "networkOS": {
                            "networkOSType": "nx-os",
                            "policy": {
                                "policyType": "accessVpcHost",
                                "accessVlan": 10,
                                "peerSwitchId": peer_id,
                            },
                        },
                    },
                }
            ]
        }
        for peer_id in peer_ids
    )
    rest_send = RestSend({"fabric_name": "FABRIC1", "check_mode": True})
    context = FabricContext(rest_send=rest_send, fabric_name="FABRIC1")
    context._fabric_summary = {"local": True, "fabricStatus": "default"}
    context._switch_map = switch_map
    context._switch_map_by_id = {switch_id: switch_ip for switch_ip, switch_id in switch_map.items()}
    snapshot = InterfaceStateSnapshot(
        fabric_name="FABRIC1",
        fabric_context=context,
        request=lambda **_kwargs: next(responses),
    )
    planner = InterfaceWorkflowPlanner(
        snapshot=snapshot,
        vpc_pair_by_switch_ip={
            "192.0.2.1": "SERIAL2",
            "192.0.2.2": "SERIAL1",
            "192.0.2.3": "SERIAL4",
            "192.0.2.4": "SERIAL3",
        },
    )
    workflow_plan = planner.plan(
        [
            {
                "type": "vpc_access",
                "state": "merged",
                "config": [
                    {
                        "switch_ip": switch_ip,
                        "interface_name": "vpc10",
                        "config_data": {"network_os": {"policy": {"access_vlan": 20}}},
                    }
                    for switch_ip in ("192.0.2.1", "192.0.2.3")
                ],
            }
        ]
    )
    resource_plan = workflow_plan.resources[0]

    def reject_preflight(_self, _models):
        raise RuntimeError("switch is not capable")

    monkeypatch.setattr(type(resource_plan.orchestrator), "preflight", reject_preflight)

    result = InterfaceWorkflowExecutor(snapshot=snapshot).execute(workflow_plan)

    actual = result.actual_after_by_resource[0]
    assert result.failed is True
    assert result.mutation_requests == 0
    assert snapshot.request_stats["interface_inventory_gets"] == 4
    assert len(actual) == 2
    assert {item.get_identifier_value() for item in actual} == {
        ("192.0.2.1", "vpc10"),
        ("192.0.2.3", "vpc10"),
    }
    assert result.changed is False
    assert result.status == "failed"


def test_207_exact_success_allowlist_fails_all_identified_non_success_outcomes():
    """HTTP 207 trusts only exact success while retaining target-specific mixed-success evidence."""
    targets = tuple((f"loopback{index}", "SERIAL1") for index in range(1, 7))
    response = {
        "RETURN_CODE": 207,
        "DATA": {
            "results": [
                {"name": "loopback1", "switchId": "SERIAL1", "status": " Success "},
                {"name": "loopback2", "switchId": "SERIAL1", "message": "status omitted"},
                {"name": "loopback3", "switchId": "SERIAL1", "status": None, "message": "status null"},
                {"name": "loopback4", "switchId": "SERIAL1", "status": "warning", "message": "partially applied"},
                {"name": "loopback5", "switchId": "SERIAL1", "status": "notexecuted", "message": "dependency failed"},
                {"name": "loopback6", "switchId": "SERIAL1", "status": "futureStatus", "message": "unknown outcome"},
            ]
        },
    }

    classified = InterfaceWorkflowExecutor._classify_response(
        targets,
        response,
        {"success": False, "changed": True},
        "bulk create failed",
    )

    assert classified == {
        targets[0]: ("succeeded", None),
        targets[1]: ("failed", "status omitted"),
        targets[2]: ("failed", "status null"),
        targets[3]: ("failed", "partially applied"),
        targets[4]: ("failed", "dependency failed"),
        targets[5]: ("failed", "unknown outcome"),
    }


def test_207_unidentified_non_success_fails_unclassified_targets():
    """An unidentified non-success 207 item fails closed without erasing an identified success."""
    targets = (("loopback1", "SERIAL1"), ("loopback2", "SERIAL1"))
    response = {
        "RETURN_CODE": 207,
        "DATA": {
            "results": [
                {"name": "loopback1", "switchId": "SERIAL1", "status": "success"},
                {"status": "warning", "message": "controller omitted target identity"},
            ]
        },
    }

    classified = InterfaceWorkflowExecutor._classify_response(
        targets,
        response,
        {"success": False, "changed": True},
        "bulk create failed",
    )

    assert classified == {
        targets[0]: ("succeeded", None),
        targets[1]: ("failed", "bulk create failed"),
    }


def test_207_success_result_with_missing_target_outcome_fails_without_uncertain_status():
    """A successful top-level 207 cannot substitute for exact-success evidence for every requested target."""
    targets = (("loopback1", "SERIAL1"), ("loopback2", "SERIAL1"), ("loopback3", "SERIAL1"))
    response = {
        "RETURN_CODE": 207,
        "DATA": {
            "results": [
                {"name": "loopback1", "switchId": "SERIAL1", "status": "success"},
                {"name": "loopback2", "switchId": "SERIAL1", "status": "failed", "message": "invalid policy"},
            ]
        },
    }

    classified = InterfaceWorkflowExecutor._classify_response(
        targets,
        response,
        {"success": True, "changed": True},
        "bulk create failed",
    )

    assert classified == {
        targets[0]: ("succeeded", None),
        targets[1]: ("failed", "invalid policy"),
        targets[2]: ("failed", "bulk create failed"),
    }


def test_normal_return_207_create_omitting_target_fails_end_to_end():
    """A non-raising bulk create still fails when its HTTP 207 omits a requested target."""
    events = []
    orchestrator = NormalReturn207CreateFakeOrchestrator("only", events, omit_last=True)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert {item.interface_name: item.status for item in result.items} == {
        "loopback1": "succeeded",
        "loopback2": "failed",
    }
    assert result.deployment["status"] == "not_attempted"
    assert "deploy" not in [event[0] for event in events]
    assert result.errors == (
        "resources[0] loopback bulk create failed on SERIAL1: HTTP 207 response did not report exact success for every requested interface.",
    )


def test_normal_return_207_create_with_exact_success_for_every_target_succeeds():
    """A non-raising HTTP 207 remains successful when every requested target has exact success evidence."""
    events = []
    orchestrator = NormalReturn207CreateFakeOrchestrator("only", events, omit_last=False)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=False).execute(workflow_plan)

    assert result.failed is False
    assert result.status == "staged"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert {item.status for item in result.items} == {"succeeded"}
    assert result.errors == ()


def test_normal_return_207_ethernet_normalize_omitting_target_fails_end_to_end(monkeypatch):
    """A non-raising Ethernet normalize HTTP 207 is classified against every queued delete."""
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor.EthernetBaseOrchestrator",
        NormalReturn207EthernetFakeOrchestrator,
    )
    events = []
    orchestrator = NormalReturn207EthernetFakeOrchestrator("ethernet", events)
    workflow_plan = plan(resource(0, orchestrator, deletes=[FakeModel("Ethernet1/1"), FakeModel("Ethernet1/2")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert {item.interface_name: item.status for item in result.items} == {
        "Ethernet1/1": "succeeded",
        "Ethernet1/2": "failed",
    }
    assert result.deployment["status"] == "not_attempted"
    assert "deploy" not in [event[0] for event in events]


def test_normal_return_207_deploy_omitting_target_fails_end_to_end():
    """A non-raising deployment HTTP 207 cannot mark an omitted requested target successful."""
    events = []
    orchestrator = NormalReturn207DeployFakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 1
    assert {item.status for item in result.items} == {"succeeded"}
    assert result.deployment["status"] == "partial_failure"
    assert {entry["interface_name"]: entry["status"] for entry in result.deployment["targets"]} == {
        "loopback1": "succeeded",
        "loopback2": "failed",
    }
    assert result.errors == ("Consolidated interface deployment failed: HTTP 207 response did not report exact success for every requested interface.",)


def test_deploy_switch_scoped_207_outcomes_fan_out_to_every_requested_interface():
    """Switch outcomes fan out, while an interface-specific failure overrides switch success."""
    events = []
    orchestrator = MixedSwitch207DeployFakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, actual=("before",)))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(
        workflow_plan,
        deployment_targets=(
            ("loopback1", "SERIAL1"),
            ("loopback2", "SERIAL1"),
            ("loopback3", "SERIAL2"),
        ),
    )

    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.mutation_requests == 0
    assert result.deploy_requests == 1
    assert result.deployment["status"] == "partial_failure"
    assert {(entry["interface_name"], entry["switch_id"]): entry["status"] for entry in result.deployment["targets"]} == {
        ("loopback1", "SERIAL1"): "succeeded",
        ("loopback2", "SERIAL1"): "failed",
        ("loopback3", "SERIAL2"): "failed",
    }


def test_bulk_create_matches_loopback_switch_and_policy_request_boundaries():
    """A later loopback policy-group failure does not erase earlier group success evidence."""
    events = []
    orchestrator = PolicyGroupedFakeOrchestrator("only", events)
    workflow_plan = plan(
        resource(
            0,
            orchestrator,
            creates=[
                FakeModel("loopback1", policy_type="loopback"),
                FakeModel("loopback2", policy_type="loopback"),
                FakeModel("loopback3", policy_type="mplsLoopback"),
            ],
        )
    )

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=False).execute(workflow_plan)

    assert [event for event in events if event[0] == "create"] == [
        ("create", "only", ("loopback1", "loopback2"), "loopback"),
        ("create", "only", ("loopback3",), "mplsLoopback"),
    ]
    assert {item.interface_name: item.status for item in result.items} == {
        "loopback1": "succeeded",
        "loopback2": "succeeded",
        "loopback3": "failed",
    }
    assert orchestrator.pending_deploys == (("loopback1", "SERIAL1"), ("loopback2", "SERIAL1"))
    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.changed is True
    assert result.mutation_requests == 2
    assert result.deploy_requests == 0


def test_mixed_create_response_preserves_per_item_partial_success_and_stops_deploy():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_create=True)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    statuses = {item.interface_name: item.status for item in result.items}
    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.changed is True
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert statuses == {"loopback1": "succeeded", "loopback2": "failed"}
    assert result.deployment["status"] == "not_attempted"
    assert "deploy" not in [event[0] for event in events]
    assert events[-2:] == [
        ("dirty", ("SERIAL1", "SERIAL2")),
        ("refresh", ("SERIAL1", "SERIAL2")),
    ]


def test_mixed_deploy_response_reports_target_outcomes_without_erasing_mutation_success():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_deploy=True)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=True).execute(workflow_plan)

    deploy_statuses = {item["interface_name"]: item["status"] for item in result.deployment["targets"]}
    assert result.failed is True
    assert result.status == "partial_failure"
    assert result.changed is True
    assert result.mutation_requests == 1
    assert result.deploy_requests == 1
    assert {item.status for item in result.items} == {"succeeded"}
    assert result.deployment["status"] == "partial_failure"
    assert deploy_statuses == {"loopback1": "succeeded", "loopback2": "failed"}


def test_deploy_false_stages_changes_without_sending_deploy_request():
    events = []
    orchestrator = FakeOrchestrator("only", events)
    workflow_plan = plan(resource(0, orchestrator, creates=[FakeModel("loopback1")]))

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events), deploy=False).execute(workflow_plan)

    assert result.failed is False
    assert result.status == "staged"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert result.deployment["status"] == "disabled"
    assert "deploy" not in [event[0] for event in events]


class CacheAwareFakeVpcOrchestrator(FakeOrchestrator):
    """Exercise the production vPC peer resolver through each executor write phase."""

    fabric_name = "FABRIC1"

    def __init__(self, name, events):
        super().__init__(name, events)
        self._peer_serial_cache = {}

    def _request(self, *, path, verb, not_found_ok=False):
        del verb, not_found_ok
        self.rest_send.record(path, changed=False, method="GET")
        return {"peerSwitchId": "UNSEEDED_PEER"}

    def _resolve_model_peer(self, model):
        switch_id = self.fabric_context.get_switch_id(model.switch_ip)
        return VpcInterfaceBaseOrchestrator._resolve_peer_switch_id(self, model.switch_ip, switch_id)

    def update(self, model, existing_data=None):
        self._resolve_model_peer(model)
        return super().update(model, existing_data=existing_data)

    def create_bulk(self, models):
        for model in models:
            self._resolve_model_peer(model)
        return super().create_bulk(models)


def test_seeded_shared_vpc_cache_avoids_pair_gets_during_transition_update_and_create():
    events = []
    access = CacheAwareFakeVpcOrchestrator("access", events)
    trunk = CacheAwareFakeVpcOrchestrator("trunk", events)
    shared_cache = {
        "SERIAL1": "SERIAL2",
        "SERIAL2": "SERIAL1",
    }
    VpcInterfaceBaseOrchestrator.share_peer_serial_cache(access, shared_cache)
    VpcInterfaceBaseOrchestrator.share_peer_serial_cache(trunk, shared_cache)
    workflow_plan = plan(
        resource(
            0,
            access,
            transitions=[policy_transition("vpc10")],
            updates=[FakeModel("vpc11")],
        ),
        resource(
            1,
            trunk,
            creates=[FakeModel("vpc20", "192.0.2.2")],
        ),
    )

    result = InterfaceWorkflowExecutor(snapshot=FakeSnapshot(events)).execute(workflow_plan)

    responses = [*access.rest_send.responses, *trunk.rest_send.responses]
    assert result.failed is False
    assert result.mutation_requests == 3
    assert access._peer_serial_cache is shared_cache
    assert trunk._peer_serial_cache is shared_cache
    assert all(response["METHOD"] != "GET" for response in responses)
    assert all("/vpcPair" not in response["REQUEST_PATH"] for response in responses)
