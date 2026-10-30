# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""VRF sparse intent, authoritative clears, and VXLAN transition regressions."""

from __future__ import annotations

from copy import deepcopy

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import ValidationError
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    VrfChildConfigModel,
    VrfConfigModel,
    VrfParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import VrfDataModel
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.staged_state_helpers import prepare_crud_state
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import vrf_parent_argument_spec, vrf_standalone_argument_spec
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.child_vrf import ChildVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import MulticlusterParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multisite_parent_vrf import MultisiteParentVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import NDVrfOrchestrator


class _Module:
    def __init__(self, params, check_mode):
        self.params = params
        self.check_mode = check_mode
        self._verbosity = 0

    @staticmethod
    def fail_json(**kwargs):
        raise AssertionError(kwargs)


@pytest.fixture
def vrf_controller(monkeypatch):
    """Model standalone replacement, parent retention, and omitted empty lists."""
    controller = {
        "row": {
            "fabricName": "FAB",
            "vrfName": "BLUE",
            "vrfType": "vxlan",
            "vrfId": 50000,
            "vlanId": 2001,
            "coreData": {
                "mtu": 9000,
                "routingTag": 23456,
                "maxBgpPaths": 4,
                "maxIbgpPaths": 8,
                "ipv6LinkLocal": False,
                "disableRtAuto": True,
                "vrfRouteMap": "CUSTOM-V4",
                "v6VrfRouteMap": "CUSTOM-V6",
                "vrfVlanName": "BLUE_VLAN",
                "vrfInterfaceDescription": "BLUE_SVI",
                "vrfDescription": "BLUE_DESCRIPTION",
                "routeTargetImport": ["65000:1"],
                "routeTargetExport": ["65000:2"],
                "evpnRouteTargetImport": ["65000:3"],
                "evpnRouteTargetExport": ["65000:4"],
            },
        },
        "reads": 0,
        "writes": [],
    }

    def query_all(_orchestrator, **_kwargs):
        controller["reads"] += 1
        return [deepcopy(controller["row"])] if controller["row"] is not None else []

    def request(_orchestrator, **kwargs):
        controller["writes"].append(deepcopy(kwargs))
        payload = deepcopy(kwargs["data"])
        if "vrfs" in payload:
            payload = payload["vrfs"][0]
        current = controller["row"] or {}
        core_update = payload.pop("coreData", {})
        if not _orchestrator.strategy.is_parent and not _orchestrator.strategy.is_child:
            core = core_update
        else:
            core = {**current.get("coreData", {}), **core_update}
        current.update(payload)
        current["coreData"] = {key: value for key, value in core.items() if value not in (None, "", [])}
        trm = (current.get("fabricData") or {}).get("trmData")
        if isinstance(trm, dict):
            for key in ("ipv4Trm", "ipv6Trm", "v4RpAbsent", "v4RpExternal", "v6RpAbsent", "v6RpExternal", "trmOnBgw", "mvpnInterAs"):
                trm.setdefault(key, False)
        controller["row"] = current
        return {}

    monkeypatch.setattr(NDVrfOrchestrator, "query_all", query_all)
    monkeypatch.setattr(NDVrfOrchestrator, "_request", request)
    return controller


def _run(strategy, entry, state="merged", check_mode=False):
    spec = {**vrf_parent_argument_spec(), **vrf_standalone_argument_spec()}
    accepted = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": spec}}).validate({"config": [entry]})
    assert not accepted.error_messages
    module = _Module({"fabric_name": "FAB", "state": state, "config": accepted.validated_parameters["config"]}, check_mode)
    coordinator = VrfWorkflowCoordinator(module, strategy)
    model = VrfParentConfigModel if strategy.is_parent else VrfChildConfigModel if strategy.is_child else VrfConfigModel
    if strategy.is_child:
        module.params["config"][0]["fabric_name"] = strategy.fabric_name
    args = {**module.params, "config": coordinator._parse_config(module.params["config"], model, state)}
    if strategy.is_child:
        args["config"][0]["vrf_name"] = entry["vrf_name"]
    sm, original_config, original_state = coordinator._new_state_machine(args, strategy)
    try:
        prepare_crud_state(sm, state)
        sm.manage_state()
        return sm
    finally:
        coordinator._restore_state_machine_params(original_config, original_state)


@pytest.mark.parametrize("strategy_cls", [MultisiteParentVrfStrategy, MulticlusterParentVrfStrategy])
@pytest.mark.parametrize(
    "entry",
    [
        {"vrf_name": "BLUE"},
        {"vrf_name": "BLUE", "v6_redist_direct_rmap": "UPDATED-V6"},
        {"vrf_name": "BLUE", "child_fabric_config": [{"fabric_name": "CHILD", "bgp_log_neighbor_change": True}]},
    ],
)
def test_parent_merged_preserves_unrequested_core_fields(strategy_cls, entry, vrf_controller):
    strategy = strategy_cls(fabric_name="FAB", fabric_data={"managementType": "vxlan"})
    before = deepcopy(vrf_controller["row"])
    expected = deepcopy(before["coreData"])
    if "v6_redist_direct_rmap" in entry:
        expected["v6VrfRouteMap"] = "UPDATED-V6"
    changes = "v6_redist_direct_rmap" in entry
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, entry, check_mode=check_mode)
        assert bool(len(sm.sent)) is (changes and index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (1 if changes and index > 0 else 0)
    assert vrf_controller["row"]["coreData"] == expected
    assert before["coreData"]["mtu"] == 9000


@pytest.mark.parametrize("strategy_cls", [StandaloneVrfStrategy, MultisiteParentVrfStrategy, MulticlusterParentVrfStrategy])
@pytest.mark.parametrize(
    "field,value,wire",
    [
        ("vrf_int_mtu", 9216, "mtu"),
        ("loopback_route_tag", 12345, "routingTag"),
        ("max_bgp_paths", 1, "maxBgpPaths"),
        ("max_ibgp_paths", 2, "maxIbgpPaths"),
        ("ipv6_linklocal_enable", True, "ipv6LinkLocal"),
        ("disable_rt_auto", False, "disableRtAuto"),
        ("redist_direct_rmap", "FABRIC-RMAP-REDIST-SUBNET", "vrfRouteMap"),
        ("v6_redist_direct_rmap", "FABRIC-RMAP-REDIST-SUBNET", "v6VrfRouteMap"),
        ("import_vpn_rt", [], "routeTargetImport"),
        ("export_vpn_rt", [], "routeTargetExport"),
        ("import_evpn_rt", [], "evpnRouteTargetImport"),
        ("export_evpn_rt", [], "evpnRouteTargetExport"),
    ],
)
def test_merged_explicit_defaults_and_clears_remain_managed(strategy_cls, field, value, wire, vrf_controller):
    strategy = strategy_cls(fabric_name="FAB", fabric_data={"managementType": "vxlan" if strategy_cls is not StandaloneVrfStrategy else "vxlanIbgp"})
    vrf_controller["row"]["vrfType"] = "vxlan" if strategy.is_parent else "vxlanIbgp"
    before = deepcopy(vrf_controller["row"]["coreData"])
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, {"vrf_name": "BLUE", field: value}, check_mode=check_mode)
        assert bool(len(sm.sent)) is (index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (0 if index == 0 else 1)
    assert vrf_controller["writes"][0]["data"]["coreData"][wire] == value
    expected = {key: item for key, item in {**before, wire: value}.items() if item not in (None, "", [])}
    assert vrf_controller["row"]["coreData"] == expected


@pytest.mark.parametrize("strategy_cls", [StandaloneVrfStrategy, MultisiteParentVrfStrategy, MulticlusterParentVrfStrategy])
@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
@pytest.mark.parametrize("empty_readback", ["omitted", "empty", "null"])
def test_authoritative_route_target_clear_converges(strategy_cls, state, empty_readback, vrf_controller):
    strategy = strategy_cls(fabric_name="FAB", fabric_data={"managementType": "vxlan" if strategy_cls is not StandaloneVrfStrategy else "vxlanIbgp"})
    vrf_controller["row"]["vrfType"] = "vxlan" if strategy.is_parent else "vxlanIbgp"
    entry = {"vrf_name": "BLUE", "vrf_vlan_name": "BLUE_VLAN", "vrf_intf_desc": "BLUE_SVI", "vrf_description": "UPDATED"}
    fields = {
        "routeTargetImport": [],
        "routeTargetExport": [],
        "evpnRouteTargetImport": [],
        "evpnRouteTargetExport": [],
    }
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, entry, state, check_mode)
        assert bool(len(sm.sent)) is (index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (0 if index == 0 else 1)
        if index == 1:
            payload = vrf_controller["writes"][0]["data"]
            assert all(payload["coreData"][key] == value for key, value in fields.items())
            assert payload["vrfId"] == 50000
            assert all(key not in vrf_controller["row"]["coreData"] for key in fields)
            if empty_readback != "omitted":
                vrf_controller["row"]["coreData"].update({key: None if empty_readback == "null" else value for key, value in fields.items()})
    assert vrf_controller["row"]["coreData"]["vrfDescription"] == "UPDATED"


@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
def test_standalone_authoritative_text_reset_uses_omission(state, vrf_controller):
    strategy = StandaloneVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlanIbgp"})
    vrf_controller["row"]["vrfType"] = "vxlanIbgp"
    text_fields = {"vrfVlanName", "vrfInterfaceDescription", "vrfDescription"}
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, {"vrf_name": "BLUE"}, state, check_mode)
        assert bool(len(sm.sent)) is (index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (0 if index == 0 else 1)
    payload = vrf_controller["writes"][0]["data"]
    assert not text_fields.intersection(payload.get("coreData", {}))
    assert not text_fields.intersection(vrf_controller["row"].get("coreData", {}))


@pytest.mark.parametrize("state", ["replaced", "overridden", "staged"])
def test_parent_retained_text_is_not_hidden_by_comparison(state, vrf_controller):
    strategy = MultisiteParentVrfStrategy(fabric_name="FAB", fabric_data={"managementType": "vxlan"})
    text_fields = {"vrfVlanName", "vrfInterfaceDescription", "vrfDescription"}
    before = {key: vrf_controller["row"]["coreData"][key] for key in text_fields}
    sm = _run(strategy, {"vrf_name": "BLUE"}, state)
    assert len(sm.sent) == 1
    assert not text_fields.intersection(vrf_controller["writes"][0]["data"].get("coreData", {}))
    assert {key: vrf_controller["row"]["coreData"][key] for key in text_fields} == before
    assert len(_run(strategy, {"vrf_name": "BLUE"}, state, check_mode=True).sent) == 1
    assert len(vrf_controller["writes"]) == 1


@pytest.mark.parametrize("vrf_type", ["vxlanIbgp", "vxlanEbgp", "vxlanCampus"])
@pytest.mark.parametrize("change", [{"no_rp": True}, {"trm_enable": False}])
def test_child_trm_transition_prunes_only_inherited_fields(vrf_type, change, vrf_controller):
    strategy = ChildVrfStrategy(fabric_name="FAB", fabric_data={"management": {"type": vrf_type}})
    vrf_controller["row"]["vrfType"] = vrf_type
    vrf_controller["row"]["fabricData"] = {
        "trmData": {
            "ipv4Trm": True,
            "v4RpAbsent": False,
            "v4RpExternal": False,
            "v4RpAddress": "192.0.2.1",
            "loopbackNumber": 17,
            "l3VniMulticastGroup": "239.1.1.1",
        }
    }
    before = deepcopy(vrf_controller["row"])
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, {"vrf_name": "BLUE", **change}, check_mode=check_mode)
        assert bool(len(sm.sent)) is (index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (0 if index == 0 else 1)
    trm = vrf_controller["writes"][0]["data"]["fabricData"]["trmData"]
    assert "v4RpAddress" not in trm
    assert not trm.get("v4RpExternal")
    assert ("l3VniMulticastGroup" in trm) is ("no_rp" in change)
    assert vrf_controller["row"]["coreData"] == before["coreData"]


@pytest.mark.parametrize("vrf_type", ["vxlanIbgp", "vxlanEbgp", "vxlanCampus"])
@pytest.mark.parametrize("change", [{"no_rp": True, "rp_address": "192.0.2.2"}, {"trm_enable": False, "rp_address": "192.0.2.2"}])
def test_child_trm_transition_rejects_explicit_contradictions(vrf_type, change, vrf_controller):
    strategy = ChildVrfStrategy(fabric_name="FAB", fabric_data={"management": {"type": vrf_type}})
    vrf_controller["row"]["vrfType"] = vrf_type
    vrf_controller["row"]["fabricData"] = {"trmData": {"ipv4Trm": True, "v4RpAddress": "192.0.2.1", "loopbackNumber": 17, "l3VniMulticastGroup": "239.1.1.1"}}
    before = deepcopy(vrf_controller["row"])
    with pytest.raises((AssertionError, ValidationError), match="(RP settings|rp_address)"):
        _run(strategy, {"vrf_name": "BLUE", **change})
    assert not vrf_controller["writes"]
    assert vrf_controller["row"] == before


@pytest.mark.parametrize("strategy_cls", [StandaloneVrfStrategy, ChildVrfStrategy])
@pytest.mark.parametrize("vrf_type", ["vxlanIbgp", "vxlanEbgp", "vxlanCampus"])
@pytest.mark.parametrize("family", [4, 6])
def test_trm_disable_preserves_other_family_and_common_settings(strategy_cls, vrf_type, family, vrf_controller):
    strategy = strategy_cls(fabric_name="FAB", fabric_data={"managementType": vrf_type})
    vrf_controller["row"]["vrfType"] = vrf_type
    trm = {
        "ipv4Trm": True,
        "ipv6Trm": True,
        "v4RpAddress": "192.0.2.1",
        "v6RpAddress": "2001:db8::1",
        "loopbackNumber": 17,
        "l3VniMulticastGroup": "239.1.1.1",
        "mvpnRouteTargetImport": ["65000:1"],
    }
    vrf_controller["row"]["fabricData"] = {"trmData": trm}
    field = "trm_enable" if family == 4 else "ipv6_trm"
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, {"vrf_name": "BLUE", field: False}, check_mode=check_mode)
        assert bool(len(sm.sent)) is (index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (0 if index == 0 else 1)
    updated = vrf_controller["row"]["fabricData"]["trmData"]
    assert f"v{family}RpAddress" not in updated
    assert updated[f"v{10 - family}RpAddress"] == trm[f"v{10 - family}RpAddress"]
    for shared in ("loopbackNumber", "l3VniMulticastGroup", "mvpnRouteTargetImport"):
        assert updated[shared] == trm[shared]


def test_comparison_does_not_mutate_readback_or_sparse_clear_intent():
    raw = {"fabricName": "FAB", "vrfName": "BLUE", "vrfType": "vxlan", "coreData": {"vrfVlanName": "VLAN"}}
    current = VrfDataModel.from_response(raw)
    sparse = VrfDataModel.from_config({"fabric_name": "FAB", "vrf_name": "BLUE", "vrf_type": "vxlan"})
    clear = VrfDataModel.from_config({**sparse.to_payload(), "coreData": {"vrfVlanName": ""}})
    before = deepcopy(raw)
    assert current.get_diff(sparse, exclude_unset=True)
    assert not current.get_diff(clear, exclude_unset=True)
    assert current.to_payload() == before
    assert sparse.to_payload() == {"fabricName": "FAB", "vrfName": "BLUE", "vrfType": "vxlan"}
    assert clear.to_payload()["coreData"] == {"vrfVlanName": ""}
    assert raw == before


@pytest.mark.parametrize("field,wire", [("import_mvpn_rt", "mvpnRouteTargetImport"), ("export_mvpn_rt", "mvpnRouteTargetExport")])
@pytest.mark.parametrize("vrf_type", ["vxlanIbgp", "vxlanEbgp", "vxlanCampus"])
def test_child_mvpn_explicit_clear_preserves_intent_and_omitted_readback_converges(field, wire, vrf_type, vrf_controller):
    strategy = ChildVrfStrategy(fabric_name="FAB", fabric_data={"managementType": vrf_type})
    vrf_controller["row"]["vrfType"] = vrf_type
    vrf_controller["row"]["fabricData"] = {"trmData": {"ipv4Trm": True, "v4RpAbsent": True, "l3VniMulticastGroup": "239.1.1.1", wire: ["65000:1"]}}
    for index, check_mode in enumerate((True, False, False, True)):
        sm = _run(strategy, {"vrf_name": "BLUE", field: []}, check_mode=check_mode)
        assert bool(len(sm.sent)) is (index < 2)
        assert vrf_controller["reads"] == index + 1
        assert len(vrf_controller["writes"]) == (0 if index == 0 else 1)
        if index == 1:
            assert vrf_controller["writes"][0]["data"]["fabricData"]["trmData"][wire] == []
            vrf_controller["row"]["fabricData"]["trmData"].pop(wire)
