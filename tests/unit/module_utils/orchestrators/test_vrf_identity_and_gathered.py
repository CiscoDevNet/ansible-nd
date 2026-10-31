# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Existing VRF identity and topology-correct gathered replay."""

from copy import deepcopy
from types import SimpleNamespace

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import PARENT_CHILD_ONLY_VRF_FIELDS, VrfParentConfigModel
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import VrfDataModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_vrf import ChildVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import MulticlusterParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import MultisiteParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.staged_state_helpers import crud_module_args
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend


def _strategy(topology):
    if topology in ("msd_child", "mcfg_child"):
        return ChildVrfStrategy(fabric_name="FAB", fabric_data={"management": {"type": "vxlanIbgp"}}, cluster_name="C1" if topology == "mcfg_child" else None)
    cls = {"standalone": StandaloneVrfStrategy, "msd": MultisiteParentVrfStrategy, "mcfg": MulticlusterParentVrfStrategy}[topology]
    members = [{"fabricName": "CHILD", "fabricState": "member", **({"clusterName": "C1"} if topology == "mcfg" else {})}] if topology != "standalone" else []
    return cls(fabric_name="FAB", fabric_data={"managementType": "vxlan" if topology == "mcfg" else "vxlanIbgp", "members": members})


def _coordinator(monkeypatch, strategy, state, observed, *, check=False, version=None):
    def fail_json(**kwargs):
        raise AssertionError(kwargs)

    module = SimpleNamespace(
        params={"fabric_name": strategy.fabric_name, "state": state, "config": [], "output_level": "normal"}, check_mode=check, _verbosity=0
    )
    module.fail_json = fail_json
    coordinator = VrfWorkflowCoordinator(module, strategy)
    calls = []

    def request(_self, **kwargs):
        calls.append(kwargs)
        return {"vrfs": deepcopy(observed), "meta": {"counts": {"remaining": 0, "total": len(observed)}}} if kwargs["verb"].value == "GET" else {}

    monkeypatch.setattr(NDVrfOrchestrator, "_request", request)

    def rest_send(params):
        runtime = RestSend(params)
        runtime.controller_version = version
        return runtime

    monkeypatch.setattr(coordinator, "_new_rest_send", rest_send)
    return coordinator, calls


def _readback(strategy):
    orchestrator = NDVrfOrchestrator(rest_send=RestSend({"state": "replaced"}), strategy=strategy)
    config = {"vrf_name": "BLUE", "vrf_id": 50001}
    data = orchestrator.prepare_config_data([config])[0]
    wire = VrfDataModel.from_config(data).to_payload()
    wire["vrfId"] = 50001
    if strategy.is_parent:
        wire.setdefault("coreData", {})["v6VrfRouteMap"] = "FABRIC-RMAP-REDIST-SUBNET"
    return wire


def _manage(coordinator, intent, state):
    if coordinator.strategy.is_child:
        state = "merged"
        child = {"fabric_name": coordinator.strategy.fabric_name, **{key: value for key, value in intent.items() if key != "vrf_name"}}
        parsed = coordinator._parse_config([child], coordinator.strategy.config_model_cls, state)
        parsed[0]["vrf_name"] = intent["vrf_name"]
    else:
        parsed = coordinator._parse_config([intent], coordinator.strategy.config_model_cls, state)
    sm, original_config, original_state = coordinator._new_state_machine(crud_module_args({"state": state, "config": parsed}))
    try:
        sm.manage_state()
        return sm
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)


@pytest.mark.parametrize("topology", ["standalone", "msd_child", "mcfg_child"])
@pytest.mark.parametrize("version", ["4.2.1.10", "4.3.1.175"])
@pytest.mark.parametrize("key_type,number", [("3des", 3), ("type6", 6), ("type7", 7)])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_bgp_pair_and_sparse_updates_converge_through_actual_state_preparation(monkeypatch, topology, version, key_type, number, state):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    observed.setdefault("fabricData", {}).update(bgpPassword="aabbccdd", bgpPasswordKeyType=number if version.startswith("4.2.") else key_type)
    if strategy.is_child:
        observed["vrfType"] = "vxlanIbgp"
    intent = {"vrf_name": "BLUE", "bgp_password": "aabbccdd", "bgp_passwd_encrypt": key_type}
    for change in ({}, {"bgp_password": "11223344"}, {"bgp_passwd_encrypt": "type7"}, {"bgp_log_neighbor_change": True}):
        intent.update(change)
        sparse = state == "merged" or strategy.is_child
        entry = {"vrf_name": "BLUE", **change} if sparse and change else dict(intent)
        changed = bool(change) and not (change == {"bgp_passwd_encrypt": "type7"} and key_type == "type7")
        for check, expected in ((True, changed), (False, changed), (False, False), (True, False)):
            coordinator, calls = _coordinator(monkeypatch, strategy, state, [observed], check=check, version=version)
            sm = _manage(coordinator, entry, state)
            assert sm.output.format()["changed"] is expected
            assert sum(call["verb"].value == "GET" for call in calls) == 1
            writes = [call for call in calls if call["verb"].value != "GET"]
            assert len(writes) == int(expected and not check)
            gathered = sm.existing.get(("BLUE", "FAB")).to_gathered_config()
            assert gathered["bgp_passwd_encrypt"] == intent["bgp_passwd_encrypt"]
            if writes:
                payload = writes[0]["data"]
                wire_key = {"3des": 3, "type6": 6, "type7": 7}[intent["bgp_passwd_encrypt"]] if version.startswith("4.2.") else intent["bgp_passwd_encrypt"]
                assert payload["fabricData"]["bgpPasswordKeyType"] == wire_key
                assert payload["fabricData"]["bgpPassword"] == intent["bgp_password"]
                observed = {**observed, **deepcopy(payload)}
                if version.startswith("4.2.") and intent["bgp_password"].isdigit():
                    observed["fabricData"]["bgpPassword"] = int(intent["bgp_password"])


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg", "msd_child", "mcfg_child"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_existing_id_is_preserved_before_diff_and_update_without_another_read(monkeypatch, topology, state, check):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    child = strategy.is_child
    intent = {"vrf_name": "BLUE", **({"bgp_log_neighbor_change": True} if child else {"vrf_description": "new"})}
    for repeat in (False, True):
        coordinator, calls = _coordinator(monkeypatch, strategy, state, [observed], check=check)
        sm = _manage(coordinator, intent, state)
        proposed = sm.proposed.get(("BLUE", "FAB"))
        assert proposed.vrf_id == 50001
        assert sm.before.get(("BLUE", "FAB")).vrf_id == 50001
        assert sum(call["verb"].value == "GET" for call in calls) == 1
        writes = [call for call in calls if call["verb"].value != "GET"]
        assert len(writes) == (0 if check or repeat else 1)
        assert sm.output.format()["changed"] is (not repeat)
        if writes and not child:
            assert writes[0]["data"]["vrfId"] == 50001
        observed = proposed.to_payload() if state != "merged" else sm.existing.get(("BLUE", "FAB")).to_payload()
        if check and state == "merged":
            observed.setdefault("fabricData" if child else "coreData", {})["bgpLogNeighborChange" if child else "vrfDescription"] = True if child else "new"


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_name_only_existing_vrf_is_not_changed_for_an_omitted_id(monkeypatch, topology, state):
    strategy = _strategy(topology)
    coordinator, calls = _coordinator(monkeypatch, strategy, state, [_readback(strategy)])
    sm = _manage(coordinator, {"vrf_name": "BLUE"}, state)
    assert sm.proposed.get(("BLUE", "FAB")).vrf_id == 50001
    assert not sm.output.format()["changed"]
    assert len(calls) == 1


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("requested_id", [None, 50002])
def test_id_resolution_does_not_invent_new_ids_or_overwrite_explicit_ids(monkeypatch, topology, requested_id):
    strategy = _strategy(topology)
    coordinator, _calls = _coordinator(monkeypatch, strategy, "merged", [])
    intent = {"vrf_name": "BLUE", **({"vrf_id": requested_id} if requested_id is not None else {})}
    sm = _manage(coordinator, intent, "merged")
    assert sm.proposed.get(("BLUE", "FAB")).vrf_id == requested_id
    if requested_id is not None:
        coordinator, calls = _coordinator(monkeypatch, strategy, "replaced", [_readback(strategy)], check=True)
        sm = _manage(coordinator, intent, "replaced")
        assert sm.proposed.get(("BLUE", "FAB")).vrf_id == requested_id
        assert sm.output.format()["changed"]
        assert len(calls) == 1


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
def test_missing_observed_id_is_not_invented(monkeypatch, topology):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    observed.pop("vrfId")
    coordinator, _calls = _coordinator(monkeypatch, strategy, "replaced", [observed])
    sm = _manage(coordinator, {"vrf_name": "BLUE", "vrf_description": "new"}, "replaced")
    assert sm.proposed.get(("BLUE", "FAB")).vrf_id is None


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_omitted_vrf_vlan_survives_comparison_and_unrelated_update(monkeypatch, topology, state, check):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    observed["vlanId"] = 2301
    if topology == "standalone":
        observed.setdefault("fabricData", {})["l3VniWithoutVlan"] = False
    intent = {"vrf_name": "BLUE"}
    for update in (False, True):
        if update:
            intent["vrf_description"] = "NEW"
        for repeat in (False, True):
            coordinator, calls = _coordinator(monkeypatch, strategy, state, [observed], check=check)
            sm = _manage(coordinator, intent, state)
            changed = update and not repeat
            assert sm.output.format()["changed"] is changed
            assert sm.output.format()["after"][0]["vlan_id"] == 2301
            assert sm.before.get(("BLUE", "FAB")).vlan_id == 2301
            assert sum(call["verb"].value == "GET" for call in calls) == 1
            writes = [call for call in calls if call["verb"].value != "GET"]
            assert len(writes) == (1 if changed and not check else 0)
            if changed:
                assert sm.sent.get(("BLUE", "FAB")).vlan_id == 2301
                if writes:
                    assert writes[0]["data"]["vlanId"] == 2301
                observed.setdefault("coreData", {})["vrfDescription"] = "NEW"


@pytest.mark.parametrize("topology", ["standalone", "msd"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_explicit_vrf_vlan_change_is_not_replaced_by_observed_vlan(monkeypatch, topology, state, check):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    observed["vlanId"] = 2301
    if topology == "standalone":
        observed.setdefault("fabricData", {})["l3VniWithoutVlan"] = False
    for repeat in (False, True):
        coordinator, calls = _coordinator(monkeypatch, strategy, state, [observed], check=check)
        sm = _manage(coordinator, {"vrf_name": "BLUE", "vlan_id": 2302}, state)
        assert sm.output.format()["changed"] is (not repeat)
        assert sm.existing.get(("BLUE", "FAB")).vlan_id == 2302
        writes = [call for call in calls if call["verb"].value != "GET"]
        assert len(writes) == (0 if check or repeat else 1)
        if writes:
            assert writes[0]["data"]["vlanId"] == 2302
        observed["vlanId"] = 2302


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("check", [False, True])
def test_explicit_no_vlan_transition_does_not_retain_vrf_vlan(monkeypatch, state, check):
    strategy = _strategy("standalone")
    observed = _readback(strategy)
    observed["vlanId"] = 2301
    observed.setdefault("fabricData", {})["l3VniWithoutVlan"] = False
    for repeat in (False, True):
        coordinator, calls = _coordinator(monkeypatch, strategy, state, [observed], check=check)
        sm = _manage(coordinator, {"vrf_name": "BLUE", "l3vni_wo_vlan": True}, state)
        assert sm.output.format()["changed"] is (not repeat)
        writes = [call for call in calls if call["verb"].value != "GET"]
        assert len(writes) == (0 if check or repeat else 1)
        if writes:
            assert "vlanId" not in writes[0]["data"]
            assert writes[0]["data"]["fabricData"]["l3VniWithoutVlan"] is True
        if state != "merged":
            assert sm.existing.get(("BLUE", "FAB")).vlan_id is None
        observed.pop("vlanId", None)
        observed["fabricData"]["l3VniWithoutVlan"] = True


@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
def test_no_vlan_readback_echo_is_not_inherited_into_proposal(monkeypatch, state):
    strategy = _strategy("standalone")
    observed = _readback(strategy)
    observed.update(vlanId=2301)
    observed.setdefault("fabricData", {})["l3VniWithoutVlan"] = True
    coordinator, calls = _coordinator(monkeypatch, strategy, state, [observed], check=True)
    sm = _manage(coordinator, {"vrf_name": "BLUE"}, state)
    proposed = sm.proposed.get(("BLUE", "FAB"))
    assert proposed.vlan_id is None
    assert "vlanId" not in proposed.to_payload()
    assert not sm.output.format()["changed"]
    assert len(calls) == 1


@pytest.mark.parametrize("topology", ["standalone", "msd", "mcfg"])
@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
@pytest.mark.parametrize("exists", [False, True])
def test_vrf_vlan_retention_does_not_invent_a_missing_vlan(monkeypatch, topology, state, exists):
    strategy = _strategy(topology)
    coordinator, calls = _coordinator(monkeypatch, strategy, state, [_readback(strategy)] if exists else [], check=True)
    sm = _manage(coordinator, {"vrf_name": "BLUE"}, state)
    assert sm.proposed.get(("BLUE", "FAB")).vlan_id is None
    assert sum(call["verb"].value == "GET" for call in calls) == 1
    assert len(calls) == 1


@pytest.mark.parametrize("topology", ["msd", "mcfg"])
def test_explicit_ipv6_route_map_does_not_skip_id_resolution(monkeypatch, topology):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    observed["vlanId"] = 2301
    coordinator, calls = _coordinator(monkeypatch, strategy, "replaced", [observed])
    sm = _manage(coordinator, {"vrf_name": "BLUE", "v6_redist_direct_rmap": "CUSTOM-V6"}, "replaced")
    assert sm.proposed.get(("BLUE", "FAB")).vrf_id == 50001
    assert calls[-1]["data"]["vrfId"] == 50001
    assert calls[-1]["data"]["vlanId"] == 2301
    assert calls[-1]["data"]["coreData"]["v6VrfRouteMap"] == "CUSTOM-V6"


@pytest.mark.parametrize("topology", ["msd", "mcfg"])
@pytest.mark.parametrize("check", [False, True])
def test_parent_gathered_uses_parent_spec_and_replays_without_child_fields(monkeypatch, topology, check):
    strategy = _strategy(topology)
    observed = _readback(strategy)
    observed["fabricData"] = {"advertiseHostRoute": True, "advertiseDefaultRoute": False, "configureStaticDefaultRoute": True, "bgpLogNeighborChange": True}
    coordinator, calls = _coordinator(monkeypatch, strategy, "gathered", [observed], check=check)
    result = coordinator._handle_parent_workflow({"fabric_name": "FAB", "state": "gathered", "config": []}, strategy.fabric_type)
    assert len(calls) == 1
    assert "/oneManage/manage/" in calls[0]["path"] if topology == "mcfg" else "/api/v1/manage/" in calls[0]["path"]
    assert not result["changed"]
    assert len(result["gathered"]) == 1
    entry = result["gathered"][0]
    assert not set(entry).intersection(PARENT_CHILD_ONLY_VRF_FIELDS)
    assert entry["vrf_id"] == 50001
    spec = {"config": {"type": "list", "elements": "dict", "options": strategy.get_argument_spec()}}
    assert not ArgumentSpecValidator(spec).validate({"config": [entry]}).error_messages
    replay = VrfParentConfigModel.from_config(entry, context={"state": "merged"}).to_config(exclude_unset=True)
    coordinator, calls = _coordinator(monkeypatch, strategy, "merged", [observed], check=check)
    sm = _manage(coordinator, replay, "merged")
    assert not sm.output.format()["changed"]
    assert len(calls) == 1
    assert observed["fabricData"]["advertiseHostRoute"] is True


def test_child_gathered_keeps_child_owned_values(monkeypatch):
    strategy = _strategy("mcfg_child")
    observed = _readback(strategy)
    observed["fabricData"] = {"advertiseHostRoute": True, "advertiseDefaultRoute": False, "configureStaticDefaultRoute": True}
    coordinator, calls = _coordinator(monkeypatch, strategy, "gathered", [observed])
    result = coordinator._handle_child_workflow({"fabric_name": "FAB", "state": "gathered", "config": []}, strategy.fabric_type)
    assert result["gathered"][0]["adv_host_routes"] is True
    assert result["gathered"][0]["adv_default_routes"] is False
    assert result["gathered"][0]["static_default_route"] is True
    assert len(calls) == 1
