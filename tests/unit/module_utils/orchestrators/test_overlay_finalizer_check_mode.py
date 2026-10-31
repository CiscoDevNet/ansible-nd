# Copyright: (c) 2026, Mike Wiebe (@mikewiebe)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Known attachment-query POSTs use real reads while CRUD remains in check mode."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.enums import HttpVerbEnum
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import NDStateMachine
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.network_attachment_manager import NetworkAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.networks import NDNetworkOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.overlay_deletion_finalizer import OverlayDeletionFinalizer
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_network import StandaloneNetworkStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_attachment_manager import VrfAttachmentManager
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.response_handler_nd import ResponseHandler
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.tests.unit.module_utils.mock_ansible_module import MockAnsibleModule
from ansible_collections.cisco.nd.tests.unit.module_utils.orchestrators.test_overlay_deletion_finalizer import _Coordinator


class _Sender:
    path = ""
    verb = HttpVerbEnum.GET
    payload = None
    response = {}

    def __init__(self, resource, runtime, *, fail=False):
        self.resource = resource
        self.runtime = runtime
        self.fail = fail
        self.calls = []

    def commit(self):
        self.calls.append((self.verb, self.path, deepcopy(self.payload), self.runtime.check_mode))
        if self.verb == HttpVerbEnum.GET:
            body = {self.resource + "s": [{"fabricName": "fab1", self.resource + "Name": "BLUE", self.resource + "Status": "notApplicable"}]}
        else:
            assert self.verb == HttpVerbEnum.POST
            assert self.path.split("?", 1)[0].endswith(f"/{self.resource}Attachments/query")
            assert self.payload == {self.resource + "Names": ["BLUE"]}
            if self.fail:
                raise RuntimeError("query transport failed")
            body = {"attachments": [{self.resource + "Name": "BLUE", "switchId": "S1", "attach": False, "status": "notApplicable"}]}
        self.response = {"RETURN_CODE": 200, "METHOD": self.verb, "MESSAGE": "OK", "DATA": body}


def _runtime(resource, *, check_mode=True, fail=False):
    coordinator = _Coordinator(resource, check_mode=check_mode)
    module = MockAnsibleModule()
    module.check_mode = check_mode
    module.params = {"fabric_name": "fab1", "state": "deleted", "config": [{"fabric_name": "fab1", resource + "_name": "BLUE"}]}
    coordinator.module = module
    runtime = RestSend(dict(module.params, check_mode=check_mode))
    runtime.response_handler = ResponseHandler()
    sender = _Sender(resource, runtime, fail=fail)
    runtime.sender = sender
    if resource == "network":
        strategy = StandaloneNetworkStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
        orchestrator = NDNetworkOrchestrator(rest_send=runtime, strategy=strategy)
        coordinator.attachments = NetworkAttachmentManager(coordinator)
    else:
        strategy = StandaloneVrfStrategy(fabric_name="fab1", fabric_data={"managementType": "vxlanIbgp"})
        orchestrator = NDVrfOrchestrator(rest_send=runtime, strategy=strategy)
        coordinator.attachments = VrfAttachmentManager(coordinator)
    setattr(coordinator, "_new_" + resource + "_orchestrator", lambda _args, _strategy: (orchestrator, None))

    def state_machine(_args, _strategy):
        coordinator.actual_sm = NDStateMachine(module=module, model_orchestrator=orchestrator)
        return coordinator.actual_sm, module.params["config"], "deleted"

    coordinator._new_state_machine = state_machine
    coordinator._format_state_machine_output = lambda sm: sm.output.format_with_verbosity(0, sm.results)
    return coordinator, strategy, orchestrator, runtime, sender


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_check_mode_queries_actual_attachments_without_dispatching_crud(resource):
    coordinator, strategy, _orchestrator, runtime, sender = _runtime(resource)
    result = OverlayDeletionFinalizer(coordinator, resource).run(dict(coordinator.module.params, deletion_mode="finalize"), strategy)
    assert result["deletion_finalization"]["definition_absence_verified"] is None
    assert coordinator.module.check_mode is True
    assert coordinator.actual_sm.check_mode is True
    assert runtime.check_mode is True
    assert runtime.params["check_mode"] is True
    queries = [row for row in sender.calls if row[0] != HttpVerbEnum.GET]
    assert len(queries) == 1
    assert queries[0][1].split("?", 1)[0].endswith(f"/{resource}Attachments/query")
    assert queries[0][3] is False
    assert not any("remove" in path or "deploy" in path or verb == HttpVerbEnum.DELETE for verb, path, _data, _flag in sender.calls)


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_query_transport_failure_restores_exact_original_flag(resource, check_mode):
    coordinator, strategy, orchestrator, runtime, sender = _runtime(resource, check_mode=check_mode, fail=True)
    with pytest.raises(Exception, match="query transport failed"):
        OverlayDeletionFinalizer(coordinator, resource)._attachments(orchestrator, strategy, ["BLUE"])
    assert runtime.check_mode is check_mode
    assert runtime.params["check_mode"] is check_mode
    assert coordinator.module.check_mode is check_mode
    assert len(sender.calls) == 1
    assert sender.calls[0][3] is False


@pytest.mark.parametrize("resource", ["network", "vrf"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_successful_query_restores_exact_original_transport_flag(resource, check_mode):
    coordinator, strategy, orchestrator, runtime, sender = _runtime(resource, check_mode=check_mode)
    rows = OverlayDeletionFinalizer(coordinator, resource)._attachments(orchestrator, strategy, ["BLUE"])
    assert rows == [{resource + "Name": "BLUE", "switchId": "S1", "attach": False, "status": "notApplicable"}]
    assert len(sender.calls) == 1
    assert sender.calls[0][3] is False
    assert runtime.check_mode is check_mode
    assert coordinator.module.check_mode is check_mode


@pytest.mark.parametrize("resource", ["network", "vrf"])
def test_check_mode_override_refuses_an_unrecognized_endpoint(resource):
    coordinator, strategy, orchestrator, runtime, sender = _runtime(resource)

    class UnknownEndpoint:
        path = "/api/v1/manage/fabrics/fab1/unsafe"
        verb = HttpVerbEnum.POST

        def __init__(self):
            self.endpoint_params = SimpleNamespace()

    coordinator.attachments._attachments_query_endpoint_cls = lambda _strategy: UnknownEndpoint
    with pytest.raises(ValueError, match="recognized.*attachment query"):
        OverlayDeletionFinalizer(coordinator, resource)._attachments(orchestrator, strategy, ["BLUE"])
    assert runtime.check_mode is True
    assert sender.calls == []
