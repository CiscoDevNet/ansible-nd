# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Definition-only cleanup keeps ordinary discovery read-only in check mode."""

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.overlay_deletion_finalizer import OverlayDeletionFinalizer
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule


class _Sender:
    path = ""
    verb = HttpVerbEnum.GET
    payload = None
    response = {}

    def __init__(self, resource, runtime, *, fail_discovery=False):
        self.resource = resource
        self.runtime = runtime
        self.fail_discovery = fail_discovery
        self.calls = []

    def commit(self):
        self.calls.append((self.verb, self.path, deepcopy(self.payload), self.runtime.check_mode))
        assert self.verb == HttpVerbEnum.GET, "Check-mode finalization must not dispatch a mutation or attachment query"
        assert self.path.split("?", 1)[0].endswith("/" + self.resource + "s")
        if self.fail_discovery:
            raise RuntimeError("discovery transport failed")
        body = {self.resource + "s": [{"fabricName": "fab1", self.resource + "Name": "BLUE", self.resource + "Status": "notApplicable"}]}
        self.response = {"RETURN_CODE": 200, "METHOD": self.verb, "MESSAGE": "OK", "DATA": body}


class _Coordinator:
    def __init__(self, resource, *, fail_discovery=False, fail_guard=False, fail_crud=False):
        self.resource = resource
        self.module = MockAnsibleModule()
        self.module.check_mode = True
        self.module.params = {
            "fabric_name": "fab1",
            "state": "deleted",
            "config": [{"fabric_name": "fab1", resource + "_name": "BLUE"}],
        }
        self.runtime = RestSend(dict(self.module.params, check_mode=True))
        self.runtime.response_handler = ResponseHandler()
        self.sender = _Sender(resource, self.runtime, fail_discovery=fail_discovery)
        self.runtime.sender = self.sender
        self.fail_guard = fail_guard
        self.fail_crud = fail_crud
        self.restored = []
        self.guard_calls = []
        if resource == "network":
            self.strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
            self.orchestrator = NDNetworkOrchestrator(rest_send=self.runtime, strategy=self.strategy)
        else:
            self.strategy = StandaloneVrfStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
            self.orchestrator = NDVrfOrchestrator(rest_send=self.runtime, strategy=self.strategy)

    def _new_state_machine(self, _args, _strategy):
        self.actual_sm = NDStateMachine(module=self.module, model_orchestrator=self.orchestrator)
        if self.fail_crud:

            def fail():
                raise RuntimeError("definition planning failed")

            self.actual_sm.manage_state = fail
        return self.actual_sm, self.module.params["config"], self.module.params["state"]

    def _ensure(self, _args, _strategy, names):
        self.guard_calls.append(names)
        if self.fail_guard:
            raise RuntimeError("referenced definition")

    _ensure_networks_have_no_networks = _ensure
    _ensure_vrfs_have_no_networks = _ensure

    def _restore_state_machine_params(self, config, state):
        self.restored.append((config, state))
        self.module.params["config"] = config
        self.module.params["state"] = state

    @staticmethod
    def _format_state_machine_output(sm):
        return sm.output.format_with_verbosity(0, sm.results)


def _run(coordinator):
    return OverlayDeletionFinalizer(coordinator, coordinator.resource).run(dict(coordinator.module.params, deletion_mode="finalize"), coordinator.strategy)


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_check_mode_uses_only_crud_discovery_and_plans_without_mutation(resource):
    coordinator = _Coordinator(resource)
    before_config = deepcopy(coordinator.module.params["config"])
    result = _run(coordinator)

    assert result["changed"] is True
    receipt = result["deletion_finalization"]
    assert receipt["version"] == 1
    assert receipt["proof"] == "definition_only_overlay_deletion_v1"
    assert receipt["deletion_operations_succeeded"] is None
    assert receipt["detach_attempts"] == receipt["deployment_attempts"] == 0
    assert "definition_absence_verified" not in receipt
    assert "attachments_verified_detached" not in receipt
    assert len(coordinator.sender.calls) == 1
    assert coordinator.sender.calls[0][0] == HttpVerbEnum.GET
    assert coordinator.sender.calls[0][3] is True
    assert coordinator.guard_calls == [["BLUE"]]
    assert coordinator.module.check_mode is coordinator.actual_sm.check_mode is coordinator.runtime.check_mode is True
    assert coordinator.runtime.params["check_mode"] is True
    assert coordinator.module.params["config"] == before_config
    assert len(coordinator.restored) == 1


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_discovery_failure_does_not_override_runtime_check_mode(resource):
    coordinator = _Coordinator(resource, fail_discovery=True)
    with pytest.raises(Exception, match="discovery transport failed"):
        _run(coordinator)
    # Ordinary discovery may retry with its existing broader-query fallback.
    # Every attempted read must retain check mode; finalization adds no POST.
    assert coordinator.sender.calls
    assert all(verb == HttpVerbEnum.GET and flag is True for verb, _path, _payload, flag in coordinator.sender.calls)
    assert coordinator.module.check_mode is coordinator.runtime.check_mode is True
    assert coordinator.runtime.params["check_mode"] is True
    assert coordinator.guard_calls == []


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("failure", ["fail_guard", "fail_crud"])
def test_failure_after_discovery_restores_params_without_additional_queries(resource, failure):
    coordinator = _Coordinator(resource, **{failure: True})
    before = deepcopy(coordinator.module.params)
    message = "referenced definition" if failure == "fail_guard" else "definition planning failed"
    with pytest.raises(RuntimeError, match=message):
        _run(coordinator)
    assert len(coordinator.sender.calls) == 1
    assert coordinator.module.params == before
    assert coordinator.module.check_mode is coordinator.runtime.check_mode is True
    assert coordinator.runtime.params["check_mode"] is True
    assert len(coordinator.restored) == 1
