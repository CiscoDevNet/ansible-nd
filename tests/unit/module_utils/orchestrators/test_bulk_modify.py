"""Fail-closed tests for the production ND 4.3.1 bulk-modify update path."""

from __future__ import annotations

from copy import deepcopy

import pytest

from ansible_collections.cisco.nd.plugins.module_utils.fabric_context import (
    FabricContext,
)
from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_interfaces import (
    EpManageInterfacesDelete,
    EpManageInterfacesGet,
    EpManageInterfacesListGet,
    EpManageInterfacesPost,
    EpManageInterfacesPut,
)
from ansible_collections.cisco.nd.plugins.module_utils.interface_state_snapshot import (
    InterfaceStateSnapshot,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.loopback_interface import (
    LoopbackInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.interfaces.svi_interface import (
    SviInterfaceModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.base_interface import (
    NDBaseInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.svi_interface import (
    SviInterfaceOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


class _ModifyStub(NDBaseInterfaceOrchestrator):
    create_endpoint: type = EpManageInterfacesPost
    update_endpoint: type = EpManageInterfacesPut
    delete_endpoint: type = EpManageInterfacesDelete
    query_one_endpoint: type = EpManageInterfacesGet
    query_all_endpoint: type = EpManageInterfacesListGet


class _DescriptionModel:
    def __init__(
        self,
        name: str,
        *,
        policy_type: str = "loopback",
        interface_type: str = "loopback",
        extra: dict | None = None,
    ) -> None:
        self.switch_ip = "192.0.2.1"
        self.interface_name = name
        self.policy_type = policy_type
        self.interface_type = interface_type
        self.extra = extra or {}

    def to_payload(self) -> dict:
        payload = _payload(
            self.interface_name,
            policy_type=self.policy_type,
            interface_type=self.interface_type,
        )
        payload["configData"]["networkOS"]["policy"].update(self.extra)
        return payload

    def to_reverse_diff_dict(self) -> dict:
        return self.to_payload()


def _orchestrator(version: str = "4.3.1.175") -> _ModifyStub:
    rest_send = RestSend({"fabric_name": "FABRIC1", "check_mode": False})
    rest_send.controller_version = version
    context = FabricContext(rest_send=rest_send, fabric_name="FABRIC1")
    snapshot = InterfaceStateSnapshot(fabric_name="FABRIC1", fabric_context=context, request=lambda **_kwargs: {})
    context._switch_map = {"192.0.2.1": "S1"}
    context._switch_map_by_id = {"S1": "192.0.2.1"}
    snapshot._interfaces_by_switch["S1"] = {
        name.casefold(): {
            "interfaceName": name,
            "switchId": "S1",
            "interfaceType": interface_type,
            "configData": {
                "mode": "managed",
                "networkOS": {
                    "networkOSType": "nx-os",
                    "policy": {"policyType": policy_type},
                },
            },
        }
        for name, interface_type, policy_type in (
            ("loopback1", "loopback", "loopback"),
            ("loopback2", "loopback", "loopback"),
            ("Vlan100", "svi", "intfSvi"),
        )
    }
    return _ModifyStub(rest_send=rest_send, interface_state_snapshot=snapshot)


def _payload(
    name: str,
    *,
    switch_id: str = "S1",
    policy_type: str = "loopback",
    interface_type: str = "loopback",
) -> dict:
    return {
        "interfaceName": name,
        "switchId": switch_id,
        "interfaceType": interface_type,
        "configData": {
            "mode": "managed",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {"policyType": policy_type, "description": "updated"},
            },
        },
    }


def test_description_candidate_is_prepared_only_on_431() -> None:
    current = _DescriptionModel("loopback1")
    eligible = _orchestrator()
    payload = eligible.prepare_bulk_description_update(current, current)
    assert payload is not None
    assert payload["switchId"] == "S1"
    assert payload["configData"]["networkOS"]["policy"]["description"] == "updated"
    assert _orchestrator("4.2.1.10").prepare_bulk_description_update(current, current) is None


def test_description_candidate_preserves_all_other_wire_fields() -> None:
    orchestrator = _orchestrator()
    current_policy = orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"]["configData"]["networkOS"]["policy"]
    current_policy["ip"] = "198.18.0.1"
    current_policy["readOnlyEcho"] = "preserve"
    previous = _DescriptionModel("loopback1", extra={"ip": "198.18.0.1"})
    desired = _DescriptionModel("loopback1", extra={"ip": "198.18.0.1"})
    payload = orchestrator.prepare_bulk_description_update(desired, previous)
    assert payload is not None
    assert payload["configData"]["networkOS"]["policy"]["readOnlyEcho"] == "preserve"
    assert orchestrator.prepare_bulk_description_update(_DescriptionModel("loopback1"), previous) is None


def test_description_candidate_rejects_absent_and_policy_transitions() -> None:
    orchestrator = _orchestrator()
    assert orchestrator.prepare_bulk_description_update(_DescriptionModel("loopback99"), _DescriptionModel("loopback99")) is None
    assert (
        orchestrator.prepare_bulk_description_update(
            _DescriptionModel("loopback1", policy_type="other"),
            _DescriptionModel("loopback1"),
        )
        is None
    )


def test_description_candidate_respects_member_bearing_parent_guard(monkeypatch) -> None:
    orchestrator = _orchestrator()
    monkeypatch.setattr(_ModifyStub, "_bulk_full_modify_guard", lambda self, _model, _current: False)

    assert orchestrator.prepare_bulk_description_update(_DescriptionModel("loopback1"), _DescriptionModel("loopback1")) is None


def test_real_loopback_model_preserves_nd_default_and_read_only_echoes() -> None:
    orchestrator = _orchestrator()
    current = orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"]
    current["switchIp"] = "192.0.2.1"
    current_policy = current["configData"]["networkOS"]["policy"]
    current_policy.update(
        {
            "ip": "198.18.0.1",
            "adminState": True,
            "linkStateRoutingTag": "",
            "ospfAreaId": "",
        }
    )
    previous = LoopbackInterfaceModel.from_response(current)
    desired = LoopbackInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "loopback1",
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {
                        "policy_type": "loopback",
                        "ip": "198.18.0.1",
                        "description": "updated",
                    },
                }
            },
        }
    )

    payload = orchestrator.prepare_bulk_description_update(desired, previous)

    assert payload is not None
    assert payload["configData"]["networkOS"]["policy"]["adminState"] is True
    assert payload["configData"]["networkOS"]["policy"]["linkStateRoutingTag"] == ""
    assert payload["configData"]["networkOS"]["policy"]["ip"] == "198.18.0.1"
    assert current_policy.get("description") is None

    reset_ip = LoopbackInterfaceModel.from_config(
        {
            "switch_ip": "192.0.2.1",
            "interface_name": "loopback1",
            "config_data": {
                "network_os": {
                    "network_os_type": "nx-os",
                    "policy": {"policy_type": "loopback", "description": "updated"},
                }
            },
        }
    )
    assert orchestrator.prepare_bulk_description_update(reset_ip, previous) is None


def test_real_svi_model_normalizes_only_known_hsrp_version_echo(monkeypatch) -> None:
    stub = _orchestrator()
    snapshot = stub.state_snapshot
    rows = snapshot._interfaces_by_switch["S1"]
    rows["vlan100"] = {
        "interfaceName": "vlan100",
        "interfaceType": "svi",
        "switchId": "S1",
        "switchIp": "192.0.2.1",
        "configData": {
            "mode": "managed",
            "networkOS": {
                "networkOSType": "nx-os",
                "policy": {
                    "policyType": "svi",
                    "description": "original",
                    "adminState": True,
                    "hsrpVersion": "1",
                    "ip": "198.18.0.1",
                    "prefix": 30,
                },
            },
        },
    }
    rows["vlan101"] = deepcopy(rows["vlan100"])
    rows["vlan101"]["interfaceName"] = "vlan101"
    rows["vlan101"]["configData"]["networkOS"]["policy"]["ip"] = "198.18.0.5"
    orchestrator = SviInterfaceOrchestrator(rest_send=stub.rest_send, interface_state_snapshot=snapshot)

    payloads = []
    for name in ("vlan100", "vlan101"):
        previous = SviInterfaceModel.from_response(rows[name])
        desired = SviInterfaceModel.from_config(
            {
                "switch_ip": "192.0.2.1",
                "interface_name": name,
                "config_data": {
                    "network_os": {
                        "network_os_type": "nx-os",
                        "policy": {
                            "policy_type": "svi",
                            "description": "updated",
                            "admin_state": True,
                            "ip": rows[name]["configData"]["networkOS"]["policy"]["ip"],
                            "prefix": 30,
                            "hsrp_version": 1,
                        },
                    }
                },
            }
        )
        payload = orchestrator.prepare_bulk_description_update(desired, previous)
        assert payload is not None
        assert payload["configData"]["networkOS"]["policy"]["hsrpVersion"] == 1
        assert rows[name]["configData"]["networkOS"]["policy"]["hsrpVersion"] == "1"
        payloads.append(payload)

    invalid = deepcopy(payloads)
    invalid[0]["configData"]["networkOS"]["policy"]["hsrpVersion"] = "1"
    with pytest.raises(ValueError, match="omit or alter unrelated"):
        orchestrator.modify_bulk_prepared(invalid)

    def accepted(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": f"S1~{name}", "status": "success"} for name in ("vlan100", "vlan101")]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(SviInterfaceOrchestrator, "_request", accepted)
    orchestrator.modify_bulk_prepared(payloads)
    assert orchestrator.pending_deploys == (("vlan100", "S1"), ("vlan101", "S1"))


def test_svi_bulk_candidate_declines_unknown_hsrp_version_echo() -> None:
    stub = _orchestrator()
    row = stub.state_snapshot._interfaces_by_switch["S1"]["vlan100"]
    row["configData"]["networkOS"]["policy"] = {"policyType": "svi", "hsrpVersion": "3"}
    orchestrator = SviInterfaceOrchestrator(rest_send=stub.rest_send, interface_state_snapshot=stub.state_snapshot)
    current = _DescriptionModel("Vlan100", policy_type="svi", interface_type="svi")
    assert orchestrator.prepare_bulk_description_update(current, current) is None


def test_421_stays_on_singular_put(monkeypatch) -> None:
    orchestrator = _orchestrator("4.2.1.10")
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not send bulk modify"),
    )

    with pytest.raises(RuntimeError, match="requires confirmed ND 4.3.1"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])


@pytest.mark.parametrize(
    "payloads, message",
    [
        ([_payload("loopback1"), _payload("LOOPBACK1")], "repeated name"),
        ([_payload("loopback1"), _payload("loopback2", switch_id="S2")], "inventory for every switch"),
        (
            [
                _payload("Ethernet1/1", policy_type="poMember", interface_type="ethernet"),
                _payload("loopback2"),
            ],
            "member-policy",
        ),
    ],
)
def test_unsafe_groups_fail_before_transport(monkeypatch, payloads, message) -> None:
    orchestrator = _orchestrator()
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not send unsafe bulk modify"),
    )

    with pytest.raises(ValueError, match=message):
        orchestrator.modify_bulk_prepared(payloads)


def test_absent_preflight_identity_fails_before_transport(monkeypatch) -> None:
    """ND 4.3.1 modify can create absent identities; never submit one."""
    orchestrator = _orchestrator()
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not upsert"),
    )

    with pytest.raises(ValueError, match="refuses absent or unowned"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback1002")])


@pytest.mark.parametrize("field,value", [("switchId", None), ("interfaceName", "loopback99")])
def test_unowned_cached_row_fails_before_transport(monkeypatch, field, value) -> None:
    orchestrator = _orchestrator()
    orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"][field] = value
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not use unowned cached row"),
    )

    with pytest.raises(ValueError, match="refuses absent or unowned"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])


def test_malformed_nested_policy_fails_before_transport(monkeypatch) -> None:
    orchestrator = _orchestrator()
    payload = _payload("loopback1")
    payload["configData"]["networkOS"] = "invalid"
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not send malformed policy"),
    )

    with pytest.raises(ValueError, match="requires a policyType"):
        orchestrator.modify_bulk_prepared([payload, _payload("loopback2")])


def test_dirty_preflight_inventory_fails_before_transport(monkeypatch) -> None:
    orchestrator = _orchestrator()
    orchestrator.state_snapshot.invalidate("S1")
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not use stale inventory"),
    )

    with pytest.raises(ValueError, match="complete, clean preflighted switch inventory"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])


def test_policy_type_change_fails_before_transport(monkeypatch) -> None:
    orchestrator = _orchestrator()
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must not change policy type"),
    )
    payload = _payload("loopback1", policy_type="otherLoopbackPolicy")

    with pytest.raises(ValueError, match="policyType change"):
        orchestrator.modify_bulk_prepared([payload, _payload("loopback2")])


def test_omitted_current_policy_field_fails_before_transport(monkeypatch) -> None:
    orchestrator = _orchestrator()
    orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"]["configData"]["networkOS"]["policy"]["ip"] = "198.18.0.1"
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must preserve policy"),
    )

    with pytest.raises(ValueError, match="omit or alter unrelated"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])


def test_unrelated_mode_change_fails_before_transport(monkeypatch) -> None:
    orchestrator = _orchestrator()
    payload = _payload("loopback1")
    payload["configData"]["mode"] = "unmanaged"
    monkeypatch.setattr(
        _ModifyStub,
        "_request",
        lambda *_args, **_kwargs: pytest.fail("must preserve mode"),
    )

    with pytest.raises(ValueError, match="omit or alter unrelated"):
        orchestrator.modify_bulk_prepared([payload, _payload("loopback2")])


def test_success_dirties_switch_snapshot(monkeypatch) -> None:
    orchestrator = _orchestrator()

    def accepted(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~loopback2", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)

    orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert not orchestrator.state_snapshot.has_switch("S1")


def test_uncertain_transport_dirties_switch_snapshot(monkeypatch) -> None:
    orchestrator = _orchestrator()

    def disconnected(self, **_kwargs):
        raise RuntimeError("disconnected")

    monkeypatch.setattr(_ModifyStub, "_request", disconnected)

    with pytest.raises(RuntimeError, match="disconnected"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert not orchestrator.state_snapshot.has_switch("S1")


def test_mixed_policy_same_switch_with_exact_207_success(monkeypatch) -> None:
    orchestrator = _orchestrator()
    payloads = [
        _payload("loopback1"),
        _payload("Vlan100", policy_type="intfSvi", interface_type="svi"),
    ]

    def accepted(self, *, path, verb, data):
        assert path.endswith("/interfaceActions/modify")
        assert str(verb.value) == "POST"
        assert data == {"interfaces": payloads}
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~Vlan100", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)

    result = orchestrator.modify_bulk_prepared(payloads)

    assert len(result["results"]) == 2
    assert orchestrator.pending_deploys == (("loopback1", "S1"), ("Vlan100", "S1"))


def test_mixed_policy_uses_each_family_wire_echo_canonicalizer(monkeypatch) -> None:
    """A loopback-owned request must still normalize the SVI GET echo."""
    source = _orchestrator()
    svi_rest_send = RestSend({"fabric_name": "FABRIC1", "check_mode": False})
    svi_rest_send.controller_version = "4.3.1.175"
    svi = SviInterfaceOrchestrator(rest_send=svi_rest_send, interface_state_snapshot=source.state_snapshot)
    current_svi = source.state_snapshot._interfaces_by_switch["S1"]["vlan100"]
    current_svi["configData"]["networkOS"]["policy"] = {"policyType": "svi", "hsrpVersion": "1"}
    payloads = [_payload("loopback1"), _payload("Vlan100", policy_type="svi", interface_type="svi")]
    payloads[1]["configData"]["networkOS"]["policy"]["hsrpVersion"] = 1

    def accepted(self, *, data, **_kwargs):
        assert data == {"interfaces": payloads}
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": "S1~loopback1", "status": "success"}, {"name": "S1~Vlan100", "status": "success"}]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)

    with pytest.raises(ValueError, match="unrelated policy/config fields"):
        source.modify_bulk_prepared(payloads)

    result = source.modify_bulk_prepared(payloads, payload_orchestrators=[source, svi])

    assert len(result["results"]) == 2
    assert source.pending_deploys == (("loopback1", "S1"),)
    assert svi.pending_deploys == (("Vlan100", "S1"),)


def test_full_policy_batch_requires_exact_family_model_payload(monkeypatch) -> None:
    """Full mode permits semantic changes only with the family's PUT body."""
    monkeypatch.setattr(_ModifyStub, "supports_bulk_full_modify", True)
    source = _orchestrator()
    models = [
        _DescriptionModel("loopback1", extra={"ip": "198.18.224.1"}),
        _DescriptionModel("loopback2", extra={"ip": "198.18.224.2"}),
    ]
    payloads = [source.prepare_bulk_full_update(model, _DescriptionModel(model.interface_name)) for model in models]
    assert all(payload is not None for payload in payloads)
    assert [payload["configData"]["networkOS"]["policy"]["ip"] for payload in payloads] == [
        "198.18.224.1",
        "198.18.224.2",
    ]

    def accepted(self, *, data, **_kwargs):
        assert data == {"interfaces": payloads}
        response = {
            "RETURN_CODE": 207,
            "DATA": {"results": [{"name": f"S1~{model.interface_name}", "status": "success"} for model in models]},
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)

    tampered = deepcopy(payloads)
    tampered[0]["configData"]["networkOS"]["policy"]["ip"] = "198.18.224.99"
    with pytest.raises(ValueError, match="unqualified full-policy body"):
        source.modify_bulk_prepared(
            tampered,
            payload_orchestrators=[source, source],
            payload_models=models,
            payload_modes=["full", "full"],
        )

    result = source.modify_bulk_prepared(
        payloads,
        payload_orchestrators=[source, source],
        payload_models=models,
        payload_modes=["full", "full"],
    )
    assert len(result["results"]) == 2


def test_full_policy_candidate_stays_on_put_without_431_or_family_qualification(monkeypatch) -> None:
    desired = _DescriptionModel("loopback1", extra={"ip": "198.18.224.1"})
    previous = _DescriptionModel("loopback1")
    assert _orchestrator().prepare_bulk_full_update(desired, previous) is None

    monkeypatch.setattr(_ModifyStub, "supports_bulk_full_modify", True)
    assert _orchestrator("4.2.1.10").prepare_bulk_full_update(desired, previous) is None


def test_bulk_modify_rejects_unqualified_batch_size_before_transport() -> None:
    orchestrator = _orchestrator()

    with pytest.raises(ValueError, match="2–10000"):
        orchestrator.modify_bulk_prepared([_payload("loopback1")])
    with pytest.raises(ValueError, match="2–10000"):
        orchestrator.modify_bulk_prepared([_payload("loopback1")] * 10001)


def test_partial_207_queues_only_exact_success(monkeypatch) -> None:
    orchestrator = _orchestrator()

    def partial(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1:loopback2", "status": "failed"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        raise RuntimeError("partial failure")

    monkeypatch.setattr(_ModifyStub, "_request", partial)

    with pytest.raises(RuntimeError, match="accepted 1 of 2"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert orchestrator.pending_deploys == (("loopback1", "S1"),)


def test_live_mixed_separator_207_is_exact_but_partial() -> None:
    """4.3.1 names successes with ~ and validation failures with :."""
    orchestrator = _orchestrator()
    orchestrator.rest_send.response_current = {
        "RETURN_CODE": 207,
        "DATA": {
            "results": [
                {"name": "S1~loopback1", "status": "success"},
                {"name": "S1:loopback2", "status": "failed"},
            ]
        },
    }

    accepted, exact = orchestrator._bulk_modify_classify_results({"loopback1": "loopback1", "loopback2": "loopback2"}, "S1")

    assert accepted == {"loopback1"}
    assert exact is True


def test_cross_switch_duplicate_names_require_qualified_207_and_dirty_both(monkeypatch) -> None:
    orchestrator = _orchestrator()
    second = deepcopy(orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"])
    second["switchId"] = "S2"
    orchestrator.state_snapshot._interfaces_by_switch["S2"] = {"loopback1": second}
    payloads = [_payload("loopback1", switch_id="S1"), _payload("loopback1", switch_id="S2")]

    def accepted(self, *, data, **_kwargs):
        assert data == {"interfaces": payloads}
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S2~loopback1", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)
    orchestrator.modify_bulk_prepared(payloads)

    assert orchestrator.pending_deploys == (("loopback1", "S1"), ("loopback1", "S2"))
    assert not orchestrator.state_snapshot.has_switch("S1")
    assert not orchestrator.state_snapshot.has_switch("S2")


def test_cross_switch_bare_result_is_ambiguous_but_exact_success_survives(monkeypatch) -> None:
    orchestrator = _orchestrator()
    second = deepcopy(orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"])
    second["switchId"] = "S2"
    orchestrator.state_snapshot._interfaces_by_switch["S2"] = {"loopback1": second}

    def ambiguous(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "loopback1", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", ambiguous)
    with pytest.raises(RuntimeError, match="1 were accepted"):
        orchestrator.modify_bulk_prepared([_payload("loopback1", switch_id="S1"), _payload("loopback1", switch_id="S2")])
    assert orchestrator.pending_deploys == (("loopback1", "S1"),)


@pytest.mark.parametrize("result_name", ["S1~P1~vpc1", "P1~S1~vpc1"])
def test_vpc_pair_qualified_207_is_exact_and_wrong_peer_fails_closed(monkeypatch, result_name) -> None:
    orchestrator = _orchestrator()
    current = deepcopy(orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"])
    current["interfaceName"] = "vpc1"
    current["interfaceType"] = "vpc"
    current["configData"]["networkOS"]["policy"] = {"policyType": "accessVpcHost", "peerSwitchId": "P1"}
    orchestrator.state_snapshot._interfaces_by_switch["S1"]["vpc1"] = current
    orchestrator.state_snapshot._interfaces_by_switch["P1"] = {}
    vpc = _payload("vpc1", policy_type="accessVpcHost", interface_type="vpc")
    vpc["configData"]["networkOS"]["policy"]["peerSwitchId"] = "P1"
    payloads = [_payload("loopback1"), vpc]

    def accepted(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": result_name, "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)
    orchestrator.modify_bulk_prepared(payloads)
    assert orchestrator.pending_deploys == (("loopback1", "S1"), ("vpc1", "S1"))
    assert not orchestrator.state_snapshot.has_switch("S1")
    assert not orchestrator.state_snapshot.has_switch("P1")

    orchestrator = _orchestrator()
    orchestrator.state_snapshot._interfaces_by_switch["S1"]["vpc1"] = current

    def wrong_peer(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~OTHER~vpc1", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", wrong_peer)
    with pytest.raises(RuntimeError, match="1 were accepted"):
        orchestrator.modify_bulk_prepared(payloads)
    assert orchestrator.pending_deploys == (("loopback1", "S1"),)


def test_vpc_207_peer_first_with_secondary_as_submitted_owner(monkeypatch) -> None:
    """ND's primary-first result must still match a secondary-owned request."""
    orchestrator = _orchestrator()
    current = deepcopy(orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"])
    current["interfaceName"] = "vpc1"
    current["switchId"] = "P1"
    current["interfaceType"] = "vpc"
    current["configData"]["networkOS"]["policy"] = {"policyType": "accessVpcHost", "peerSwitchId": "S1"}
    orchestrator.state_snapshot._interfaces_by_switch["P1"] = {"vpc1": current}
    vpc = _payload("vpc1", switch_id="P1", policy_type="accessVpcHost", interface_type="vpc")
    vpc["configData"]["networkOS"]["policy"]["peerSwitchId"] = "S1"

    def accepted(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~P1~vpc1", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", accepted)
    orchestrator.modify_bulk_prepared([_payload("loopback1"), vpc])
    assert orchestrator.pending_deploys == (("loopback1", "S1"), ("vpc1", "P1"))


@pytest.mark.parametrize(
    ("rows", "requested", "peers", "expected_accepted", "expected_exact"),
    [
        (
            [{"name": "S1~P1~vpc1", "status": "success"}],
            {("s1", "vpc1"): ("S1", "vpc1"), ("p1", "vpc1"): ("P1", "vpc1")},
            {("s1", "vpc1"): "p1", ("p1", "vpc1"): "s1"},
            set(),
            False,
        ),
        (
            [{"name": "S1~P1~vpc1", "status": "success"}, {"name": "P1~S1~vpc1", "status": "success"}],
            {("p1", "vpc1"): ("P1", "vpc1")},
            {("p1", "vpc1"): "s1"},
            set(),
            False,
        ),
        (
            [{"name": "S1~P1~vpc1", "status": "failed"}],
            {("p1", "vpc1"): ("P1", "vpc1")},
            {("p1", "vpc1"): "s1"},
            set(),
            True,
        ),
    ],
)
def test_vpc_207_ambiguous_duplicate_and_failure_rows_fail_closed(rows, requested, peers, expected_accepted, expected_exact) -> None:
    orchestrator = _orchestrator()
    orchestrator.rest_send.response_current = {"DATA": {"results": rows}}
    accepted, exact = orchestrator._bulk_modify_classify_result_pairs(requested, peer_switch_ids=peers)
    assert accepted == expected_accepted
    assert exact is expected_exact


@pytest.mark.parametrize(
    ("name", "interface_type", "policy_type", "member_field"),
    [
        ("port-channel1", "portChannel", "l3Po", "ports"),
        ("vpc1", "vpc", "accessVpcHost", "peer1MemberPorts"),
    ],
)
def test_member_bearing_parent_cannot_bypass_bulk_guard(name, interface_type, policy_type, member_field) -> None:
    orchestrator = _orchestrator()
    current = deepcopy(orchestrator.state_snapshot._interfaces_by_switch["S1"]["loopback1"])
    current["interfaceName"] = name
    current["interfaceType"] = interface_type
    current_policy = current["configData"]["networkOS"]["policy"]
    current_policy["policyType"] = policy_type
    current_policy[member_field] = ["Ethernet1/10"]
    if interface_type == "vpc":
        current_policy["peerSwitchId"] = "P1"
    orchestrator.state_snapshot._interfaces_by_switch["S1"][name.casefold()] = current
    payload = _payload(name, policy_type=policy_type, interface_type=interface_type)
    payload_policy = payload["configData"]["networkOS"]["policy"]
    payload_policy[member_field] = ["Ethernet1/10"]
    if interface_type == "vpc":
        payload_policy["peerSwitchId"] = "P1"

    with pytest.raises(ValueError, match="member-bearing parent"):
        orchestrator.modify_bulk_prepared([_payload("loopback2"), payload])


def test_partial_207_returned_as_success_still_fails_and_queues_only_accepted(
    monkeypatch,
) -> None:
    """The generic transport accepts HTTP 207; the per-item parser must not."""
    orchestrator = _orchestrator()

    def partial(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~loopback2", "status": "failed"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", partial)

    with pytest.raises(RuntimeError, match="1 were accepted"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert orchestrator.pending_deploys == (("loopback1", "S1"),)
    assert not orchestrator.state_snapshot.has_switch("S1")


@pytest.mark.parametrize(
    "name",
    ["S2~loopback1", "S2:loopback1", "S1~S2~loopback1", "S1:loopback1:extra", "S1~unexpected"],
)
def test_unexpected_207_identity_fails_closed(monkeypatch, name) -> None:
    orchestrator = _orchestrator()

    def unexpected(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": name, "status": "success"},
                    {"name": "S1~loopback2", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", unexpected)

    with pytest.raises(RuntimeError, match="1 were accepted"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert orchestrator.pending_deploys == (("loopback2", "S1"),)


def test_duplicate_207_identity_does_not_count_as_proven_success(monkeypatch) -> None:
    orchestrator = _orchestrator()

    def duplicate(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~loopback1", "status": "failed"},
                    {"name": "S1~loopback2", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", duplicate)

    with pytest.raises(RuntimeError, match="1 were accepted"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert orchestrator.pending_deploys == (("loopback2", "S1"),)


def test_unexpected_extra_207_row_keeps_known_successes_queued(monkeypatch) -> None:
    orchestrator = _orchestrator()

    def extra(self, **_kwargs):
        response = {
            "RETURN_CODE": 207,
            "DATA": {
                "results": [
                    {"name": "S1~loopback1", "status": "success"},
                    {"name": "S1~loopback2", "status": "success"},
                    {"name": "S1~unexpected", "status": "success"},
                ]
            },
        }
        self.rest_send.response_current = response
        self.rest_send.add_response(response)
        return response["DATA"]

    monkeypatch.setattr(_ModifyStub, "_request", extra)

    with pytest.raises(RuntimeError, match="did not report exact success"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert orchestrator.pending_deploys == (("loopback1", "S1"), ("loopback2", "S1"))


def test_sender_failure_does_not_reuse_stale_207(monkeypatch) -> None:
    orchestrator = _orchestrator()
    stale = {
        "RETURN_CODE": 207,
        "DATA": {"results": [{"name": "loopback1", "status": "success"}]},
    }
    orchestrator.rest_send.response_current = stale
    orchestrator.rest_send.add_response(stale)

    def sender_failure(self, **_kwargs):
        raise RuntimeError("transport disconnected before response")

    monkeypatch.setattr(_ModifyStub, "_request", sender_failure)

    with pytest.raises(RuntimeError, match="transport disconnected"):
        orchestrator.modify_bulk_prepared([_payload("loopback1"), _payload("loopback2")])

    assert orchestrator.pending_deploys == ()
