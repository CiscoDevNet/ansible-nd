"""Fail-closed tests for the ND 4.3.1 mixed logical-create path."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import FabricContext
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import InterfaceStateSnapshot
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import LoopbackInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import SviInterfaceModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.loopback_interface import LoopbackInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import SviInterfaceOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def runtime(version: str = "4.3.1.175"):
    rest = RestSend({"fabric_name": "FABRIC1", "check_mode": False})
    rest.controller_version = version
    context = FabricContext(rest_send=rest, fabric_name="FABRIC1")
    context._switch_map = {"192.0.2.1": "S1"}
    context._switch_map_by_id = {"S1": "192.0.2.1"}
    snapshot = InterfaceStateSnapshot(fabric_name="FABRIC1", fabric_context=context, request=lambda **_kwargs: {})
    snapshot._interfaces_by_switch["S1"] = {}
    loopback = LoopbackInterfaceOrchestrator(rest_send=rest, interface_state_snapshot=snapshot)
    svi = SviInterfaceOrchestrator(rest_send=rest, interface_state_snapshot=snapshot)
    loopback_model = LoopbackInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "loopback100",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "loopback", "ip": "198.18.0.1"}}},
        }
    )
    svi_model = SviInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "Vlan100",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"ip": "198.18.0.5", "prefix": 30}}},
        }
    )
    return loopback, svi, loopback_model, svi_model, snapshot


def prepared(loopback, svi, loopback_model, svi_model):
    return [loopback.prepare_bulk_create_modify(loopback_model), svi.prepare_bulk_create_modify(svi_model)]


def test_mixed_create_queues_exact_accepted_targets_and_dirties_snapshot(monkeypatch) -> None:
    loopback, svi, loopback_model, svi_model, snapshot = runtime()
    payloads = prepared(loopback, svi, loopback_model, svi_model)
    assert all(payloads)

    def accepted(self, *, path, verb, data):
        assert path.endswith("/interfaceActions/modify") and verb.value == "POST"
        assert data == {"interfaces": payloads}
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": "S1~loopback100", "status": "success"}, {"name": "S1~vlan100", "status": "success"}]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", accepted)
    loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, svi], payload_models=[loopback_model, svi_model])
    assert loopback.pending_deploys == (("loopback100", "S1"),)
    assert svi.pending_deploys == (("vlan100", "S1"),)
    assert not snapshot.has_switch("S1")


def test_partial_207_retains_only_accepted_create_and_dirties_snapshot(monkeypatch) -> None:
    loopback, svi, loopback_model, svi_model, snapshot = runtime()
    payloads = prepared(loopback, svi, loopback_model, svi_model)

    def partial(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": "S1~loopback100", "status": "success"}, {"name": "S1:vlan100", "status": "failed"}]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        raise RuntimeError("partial response")

    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", partial)
    with pytest.raises(RuntimeError, match="accepted 1 of 2"):
        loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, svi], payload_models=[loopback_model, svi_model])
    assert loopback.pending_deploys == (("loopback100", "S1"),)
    assert not svi.pending_deploys
    assert not snapshot.has_switch("S1")


def test_absent_create_refuses_unqualified_or_stale_inputs_before_transport(monkeypatch) -> None:
    loopback, svi, loopback_model, svi_model, snapshot = runtime()
    payloads = prepared(loopback, svi, loopback_model, svi_model)
    monkeypatch.setattr(LoopbackInterfaceOrchestrator, "_request", lambda *_args, **_kwargs: pytest.fail("must not send"))

    invalid = deepcopy(payloads)
    invalid[0]["interfaceName"] = "loopback1024"
    with pytest.raises(ValueError, match="unqualified identity"):
        loopback.create_bulk_modify_prepared(invalid, payload_orchestrators=[loopback, svi], payload_models=[loopback_model, svi_model])

    snapshot._interfaces_by_switch["S1"]["loopback100"] = {"interfaceName": "loopback100", "switchId": "S1"}
    with pytest.raises(ValueError, match="requires complete, absent"):
        loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, svi], payload_models=[loopback_model, svi_model])

    snapshot._interfaces_by_switch["S1"].clear()
    snapshot.invalidate("S1")
    with pytest.raises(ValueError, match="requires complete, absent"):
        loopback.create_bulk_modify_prepared(payloads, payload_orchestrators=[loopback, svi], payload_models=[loopback_model, svi_model])


def test_421_and_invalid_names_remain_on_ordinary_create_path() -> None:
    loopback, svi, loopback_model, svi_model, _snapshot = runtime("4.2.1.10")
    assert prepared(loopback, svi, loopback_model, svi_model) == [None, None]
    with pytest.raises(RuntimeError, match="requires confirmed ND 4.3.1"):
        loopback.create_bulk_modify_prepared(
            [loopback_model.to_payload(), svi_model.to_payload()], payload_orchestrators=[loopback, svi], payload_models=[loopback_model, svi_model]
        )

    loopback, _svi, loopback_model, _svi_model, _snapshot = runtime()
    invalid = LoopbackInterfaceModel.from_config(
        {
            "switch_ip": loopback_model.switch_ip,
            "interface_name": "loopback1024",
            "config_data": {"network_os": {"network_os_type": "nx-os", "policy": {"policy_type": "loopback", "ip": "198.18.0.9"}}},
        }
    )
    assert loopback.prepare_bulk_create_modify(invalid) is None
