"""Fail-closed tests for the ND 4.3.1 mixed logical-create path."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.interface_workflow_executor import InterfaceWorkflowExecutor
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import NDBaseInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.subinterface_unmanaged_interface import SubinterfaceUnmanagedInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def runtime(version: str = "4.3.1.175"):
    rest = RestSend({"fabric_name": "FABRIC1", "check_mode": False})
    rest.controller_version = version
    context = FabricContext(rest_send=rest, fabric_name="FABRIC1")
    context._switch_map = {"192.0.2.1": "S1"}
    context._switch_map_by_id = {"S1": "192.0.2.1"}
    snapshot = InterfaceStateSnapshot(fabric_name="FABRIC1", fabric_context=context, request=lambda **_kwargs: {})
    snapshot._interfaces_by_switch["S1"] = {"ethernet1/1": {"interfaceType": "ethernet", "configData": {"mode": "routed"}, "operData": {"mode": "routed"}}}
    loopback = LoopbackInterfaceOrchestrator(rest_send=rest, interface_state_snapshot=snapshot)
    subinterface = SubinterfaceUnmanagedInterfaceOrchestrator(rest_send=rest, interface_state_snapshot=snapshot)
    loopback_model = LoopbackInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "loopback100",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "loopback", "ip": "198.18.0.1"}}},
        }
    )
    subinterface_model = SubinterfaceUnmanagedInterfaceModel.from_config({"switch_ip": "192.0.2.1", "interface_name": "Ethernet1/1.100"})
    return loopback, subinterface, loopback_model, subinterface_model, snapshot


def prepared(loopback, subinterface, loopback_model, subinterface_model):
    return [loopback.prepare_bulk_create_modify(loopback_model), subinterface.prepare_bulk_create_modify(subinterface_model)]


def test_mixed_create_queues_exact_accepted_targets_and_dirties_snapshot(monkeypatch) -> None:
    loopback, subinterface, loopback_model, subinterface_model, snapshot = runtime()
    payloads = prepared(loopback, subinterface, loopback_model, subinterface_model)
    assert all(payloads)

    def accepted(self, *, path, verb, data):
        assert path.endswith("/interfaceActions/modify") and verb.value == "POST"
        assert data == {"interfaces": payloads}
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": "S1~loopback100", "status": "success"}, {"name": "S1~Ethernet1/1.100", "status": "success"}]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", accepted)
    loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, subinterface], payload_models=[loopback_model, subinterface_model])
    assert loopback.pending_deploys == (("loopback100", "S1"),)
    assert subinterface.pending_deploys == (("Ethernet1/1.100", "S1"),)
    assert not snapshot.has_switch("S1")


def test_partial_207_retains_only_accepted_create_and_dirties_snapshot(monkeypatch) -> None:
    loopback, subinterface, loopback_model, subinterface_model, snapshot = runtime()
    payloads = prepared(loopback, subinterface, loopback_model, subinterface_model)
    controller_error = RuntimeError("ND rejected Ethernet1/1.100: controller rejection detail")

    def partial(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": "S1~loopback100", "status": "success"}, {"name": "S1:Ethernet1/1.100", "status": "failed"}]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        raise controller_error

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", partial)
    with pytest.raises(RuntimeError, match="accepted 1 of 2") as failure:
        loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, subinterface], payload_models=[loopback_model, subinterface_model])
    assert str(controller_error) in str(failure.value)
    assert failure.value.__cause__ is controller_error
    assert loopback.pending_deploys == (("loopback100", "S1"),)
    assert not subinterface.pending_deploys
    assert not snapshot.has_switch("S1")


def test_absent_create_refuses_unqualified_or_stale_inputs_before_transport(monkeypatch) -> None:
    loopback, subinterface, loopback_model, subinterface_model, snapshot = runtime()
    payloads = prepared(loopback, subinterface, loopback_model, subinterface_model)
    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", lambda *_args, **_kwargs: pytest.fail("must not send"))

    invalid = deepcopy(payloads)
    invalid[0]["interfaceName"] = "loopback1024"
    with pytest.raises(ValueError, match="unqualified identity"):
        loopback.create_bulk_modify_prepared(invalid, payload_orchestrators=[loopback, subinterface], payload_models=[loopback_model, subinterface_model])

    snapshot._interfaces_by_switch["S1"]["loopback100"] = {"interfaceName": "loopback100", "switchId": "S1"}
    with pytest.raises(ValueError, match="requires complete, absent"):
        loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, subinterface], payload_models=[loopback_model, subinterface_model])

    snapshot._interfaces_by_switch["S1"].clear()
    snapshot.invalidate("S1")
    with pytest.raises(ValueError, match="requires complete, absent"):
        loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, subinterface], payload_models=[loopback_model, subinterface_model])


def test_421_and_invalid_names_remain_on_ordinary_create_path() -> None:
    loopback, subinterface, loopback_model, subinterface_model, _snapshot = runtime("4.2.1.10")
    assert prepared(loopback, subinterface, loopback_model, subinterface_model) == [None, None]
    with pytest.raises(RuntimeError, match="requires confirmed ND 4.3.1"):
        loopback.create_bulk_modify_prepared(
            [loopback_model.to_payload(), subinterface_model.to_payload()],
            payload_orchestrators=[loopback, subinterface],
            payload_models=[loopback_model, subinterface_model],
        )

    loopback, _subinterface, loopback_model, _subinterface_model, _snapshot = runtime()
    invalid = LoopbackInterfaceModel.from_config(
        {
            "switch_ip": loopback_model.switch_ip,
            "interface_name": "loopback1024",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "loopback", "ip": "198.18.0.9"}}},
        }
    )
    assert loopback.prepare_bulk_create_modify(invalid) is None


def test_svi_create_stays_on_standard_post_while_other_families_batch(monkeypatch) -> None:
    """ND's modify-create SVI edit guard must not block a same-run mixed create."""
    loopback, subinterface, loopback_model, subinterface_model, snapshot = runtime()
    svi = SviInterfaceOrchestrator(rest_send=loopback.rest_send, interface_state_snapshot=snapshot)
    svi_model = SviInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "Vlan100",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"ip": "198.18.0.5", "prefix": 30}}},
        }
    )
    assert svi.prepare_bulk_create_modify(svi_model) is None
    assert svi.supports_bulk_full_modify is True
    requests = []

    def accepted(self, *, path, verb, data):
        assert verb.value == "POST"
        requests.append((path, data))
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": f"{item['switchId']}~{item['interfaceName']}", "status": "success"} for item in data["interfaces"]]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(NDBaseInterfaceOrchestrator, "_request", accepted)
    resources = tuple(
        SimpleNamespace(
            resource_index=index,
            resource_type=kind,
            orchestrator=orchestrator,
            transitions=(),
            operations=SimpleNamespace(deletes=(), updates=(), creates=(model,)),
        )
        for index, (kind, orchestrator, model) in enumerate(
            (("loopback", loopback, loopback_model), ("subinterface_unmanaged", subinterface, subinterface_model), ("svi", svi, svi_model))
        )
    )
    workflow_plan = SimpleNamespace(resources=resources, member_preparations=())
    executor = InterfaceWorkflowExecutor(snapshot=snapshot, deploy=False)
    executor._build_items(workflow_plan)
    assert executor._execute_creates(workflow_plan) is True
    assert len(requests) == 2
    assert requests[0][0].endswith("/interfaces")
    assert [item["interfaceName"] for item in requests[0][1]["interfaces"]] == ["vlan100"]
    assert requests[1][0].endswith("/interfaceActions/modify")
    assert [item["interfaceName"] for item in requests[1][1]["interfaces"]] == ["loopback100", "Ethernet1/1.100"]
    assert svi.pending_deploys == (("vlan100", "S1"),)
    assert loopback.pending_deploys == (("loopback100", "S1"),)
    assert subinterface.pending_deploys == (("Ethernet1/1.100", "S1"),)
    assert all(item.status == "succeeded" for item in executor._items)
