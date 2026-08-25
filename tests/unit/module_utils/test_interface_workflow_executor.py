# Copyright: (c) 2026, Mike Wiebe (@mikewiebe) mwiebe@cisco.com

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Unit tests for aggregate interface mutation execution."""

from __future__ import annotations

from types import SimpleNamespace

from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import (
    InterfaceWorkflowExecutor,
)


class FakeModel:
    """Minimal interface model used by the executor."""

    def __init__(self, name, switch_ip="192.0.2.1"):
        self.interface_name = name
        self.switch_ip = switch_ip

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

    def record(self, path, *, success=True, changed=True, data=None, method="POST"):
        self.responses.append(
            {
                "METHOD": method,
                "REQUEST_PATH": path,
                "RETURN_CODE": 200 if success else 207,
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
        self.events.append(
            ("delete_bulk", self.name, tuple(model.interface_name for model in models))
        )
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

    def update(self, model):
        target = (
            model.interface_name,
            self.fabric_context.get_switch_id(model.switch_ip),
        )
        self.events.append(("update", self.name, model.interface_name))
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
            self.rest_send.record(
                "/interfaces", success=False, changed=True, data={"results": outcomes}
            )
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

    def mark_dirty(self, switch_ids):
        self.events.append(("dirty", tuple(switch_ids)))

    def refresh(self, switch_ids):
        self.events.append(("refresh", tuple(switch_ids)))


def resource(
    index, orchestrator, *, deletes=(), updates=(), creates=(), actual=("after",)
):
    """Build one InterfaceResourcePlan-shaped value."""
    before = FakeCollection(["before"])
    return SimpleNamespace(
        resource_index=index,
        resource_type="loopback",
        state="merged",
        proposed=FakeCollection(["proposed"]),
        before=before,
        operations=SimpleNamespace(
            deletes=tuple(deletes), updates=tuple(updates), creates=tuple(creates)
        ),
        orchestrator=orchestrator,
        adapter=FakeAdapter(FakeCollection(actual)),
    )


def plan(*resources):
    """Build one InterfaceWorkflowPlan-shaped value."""
    return SimpleNamespace(
        resources=tuple(resources), target_switch_ids=("SERIAL1", "SERIAL2")
    )


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

    result = InterfaceWorkflowExecutor(
        snapshot=FakeSnapshot(events), deploy=True
    ).execute(workflow_plan)

    phase_names = [event[0] for event in events]
    assert result.failed is False
    assert result.status == "completed"
    assert result.changed is True
    assert result.mutation_requests == 4
    assert result.deploy_requests == 1
    assert (
        phase_names.index("remove")
        < phase_names.index("update")
        < phase_names.index("create")
        < phase_names.index("deploy")
    )
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
    assert {item.status for item in result.items} == {"succeeded"}


def test_preflight_failure_sends_no_writes_and_leaves_every_item_not_attempted():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_preflight=True)
    workflow_plan = plan(
        resource(0, orchestrator, creates=[FakeModel("loopback1")], actual=("before",))
    )

    result = InterfaceWorkflowExecutor(
        snapshot=FakeSnapshot(events), deploy=True
    ).execute(workflow_plan)

    assert result.failed is True
    assert result.status == "failed"
    assert result.changed is False
    assert result.mutation_requests == 0
    assert result.deploy_requests == 0
    assert result.items[0].status == "not_attempted"
    assert not any(
        event[0] in {"create", "deploy", "dirty", "refresh"} for event in events
    )


def test_mixed_create_response_preserves_per_item_partial_success_and_stops_deploy():
    events = []
    orchestrator = FakeOrchestrator("only", events, fail_create=True)
    workflow_plan = plan(
        resource(
            0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]
        )
    )

    result = InterfaceWorkflowExecutor(
        snapshot=FakeSnapshot(events), deploy=True
    ).execute(workflow_plan)

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
    workflow_plan = plan(
        resource(
            0, orchestrator, creates=[FakeModel("loopback1"), FakeModel("loopback2")]
        )
    )

    result = InterfaceWorkflowExecutor(
        snapshot=FakeSnapshot(events), deploy=True
    ).execute(workflow_plan)

    deploy_statuses = {
        item["interface_name"]: item["status"] for item in result.deployment["targets"]
    }
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

    result = InterfaceWorkflowExecutor(
        snapshot=FakeSnapshot(events), deploy=False
    ).execute(workflow_plan)

    assert result.failed is False
    assert result.status == "staged"
    assert result.mutation_requests == 1
    assert result.deploy_requests == 0
    assert result.deployment["status"] == "disabled"
    assert "deploy" not in [event[0] for event in events]
