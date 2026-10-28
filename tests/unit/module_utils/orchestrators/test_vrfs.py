# -*- coding: utf-8 -*-

# Copyright: (c) 2026, Akshayanat C S (@achengam) <achengam@cisco.com>

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Unit tests for VRF orchestrator payload transformation.
"""

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=invalid-name

import json
from types import SimpleNamespace

import pytest
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator

from ansible_collections.cisco.nd.plugins.module_utils.common.pydantic_compat import (
    ValidationError,
)
from ansible_collections.cisco.nd.plugins.module_utils.enums import (
    HttpVerbEnum,
    OperationType,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import (
    PARENT_CHILD_ONLY_VRF_FIELDS,
    VrfChildConfigModel,
    VrfConfigModel,
    VrfParentConfigModel,
)
from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.vrf_data_models import (
    VrfDataModel,
    VxlanFabricInstance,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs import (
    NDVrfOrchestrator,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_workflow_coordinator import VrfWorkflowCoordinator
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_config_utils import (
    vrf_name_filter,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_config_collection import (
    NDConfigCollection,
)
from ansible_collections.cisco.nd.plugins.module_utils.nd_state_machine import (
    NDStateMachine,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrf_argument_specs import (
    _child_fabric_config_element_spec,
    vrf_base_argument_spec,
    vrf_parent_argument_spec,
    vrf_standalone_argument_spec,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.multicluster_parent_vrf import (
    MulticlusterParentVrfStrategy,
)
from ansible_collections.cisco.nd.plugins.module_utils.orchestrators.strategies.standalone_vrf import StandaloneVrfStrategy
from ansible_collections.cisco.nd.plugins.module_utils.rest.rest_send import RestSend
from ansible_collections.cisco.nd.plugins.module_utils.rest.results import (
    Results,
)


class _Strategy:
    def __init__(self, fabric_data=None, is_child=False, is_parent=False, is_multicluster=False):
        self.fabric_name = "AK-VXLAN"
        self.fabric_data = fabric_data or {}
        self.is_child = is_child
        self.is_parent = is_parent
        self.is_multicluster = is_multicluster


def _resolve_standalone(sm, entries, state, l3vni_default=None):
    fabric_data = {"management": {"l3VniNoVlanDefaultOption": l3vni_default}} if l3vni_default is not None else {}
    coordinator = VrfWorkflowCoordinator.__new__(VrfWorkflowCoordinator)
    coordinator._resolve_standalone_vrf_intent(sm, entries, state, _Strategy(fabric_data=fabric_data))


def _effective_vrf(sm, name="BLUE", state="merged"):
    proposed = sm.proposed.get((name, "AK-VXLAN"))
    current = sm.existing.get((name, "AK-VXLAN"))
    return current.model_copy(deep=True).merge(proposed) if state == "merged" and current is not None else proposed


def _validate_child_effective(intent, existing=None, state="merged", vrf_type="vxlanIbgp", *, fabric_default=None, is_multicluster=False):
    entry = {"vrf_name": "BLUE", **intent}
    proposed = VrfDataModel.from_config(_transform(entry, fabric_name="AK-VXLAN", is_child=True))
    proposed.vrf_type = vrf_type
    current = (
        VrfDataModel.from_config({"fabric_name": "AK-VXLAN", "vrf_name": "BLUE", "vrf_type": vrf_type, "fabric_data": existing})
        if existing is not None
        else None
    )
    key = ("BLUE", "AK-VXLAN")
    sm = SimpleNamespace(proposed={key: proposed}, existing={key: current} if current is not None else {})
    fabric_data = {"management": {"l3VniNoVlanDefaultOption": fabric_default}} if fabric_default is not None else {}
    VrfWorkflowCoordinator._validate_child_vrf_intent(sm, [entry], state, _Strategy(fabric_data=fabric_data, is_child=True, is_multicluster=is_multicluster))
    return proposed, current


def test_vrf_gathered_flatteners_preserve_present_values_and_ignore_empty_sections():
    flattened = {}
    VrfDataModel._flatten_core_data(flattened, {})
    VrfDataModel._flatten_fabric_data(flattened, None)
    assert flattened == {}

    VrfDataModel._flatten_core_data(flattened, {"vrfDescription": "tenant VRF"})
    VrfDataModel._flatten_fabric_data(flattened, {"bgpPassword": "secret", "trmData": {"ipv4Trm": True}})
    assert flattened == {
        "vrf_description": "tenant VRF",
        "bgp_password": "secret",
        "trm_enable": True,
    }
    assert VrfDataModel._nested_config(VrfDataModel(fabricName="FAB", vrfName="BLUE"))["vrf_name"] == "BLUE"
    assert VrfDataModel._nested_config(object()) == {}


def test_standalone_vrf_ui_fields_round_trip_through_payload_and_gathered_config():
    config = VrfConfigModel.from_config(
        {
            "vrf_name": "BLUE",
            "bgp_best_path_relax": True,
            "bgp_log_neighbor_change": True,
            "bgp_allow_as_in": True,
            "bgp_allow_as_in_num": 4,
            "bgp_as_override": True,
            "bgp_disable_peer_as_check": True,
            "bgp_soft_reconfig_always": True,
            "ipv6_trm": True,
            "v6_no_rp": True,
            "v6_overlay_mcast_group": "ff1e::/121",
            "underlay_mcast_ip": "239.1.1.1",
            "mvpn_inter_as": True,
        }
    ).to_config()
    payload = VrfDataModel.from_config(_transform(config)).to_payload()
    fabric = payload["fabricData"]
    trm = fabric["trmData"]
    assert {
        key: fabric[key]
        for key in (
            "bgpBestPathRelax",
            "bgpLogNeighborChange",
            "bgpAllowAsIn",
            "bgpAsOverride",
            "bgpDisablePeerAsCheck",
            "bgpSoftReconfigAlways",
        )
    } == dict.fromkeys(
        (
            "bgpBestPathRelax",
            "bgpLogNeighborChange",
            "bgpAllowAsIn",
            "bgpAsOverride",
            "bgpDisablePeerAsCheck",
            "bgpSoftReconfigAlways",
        ),
        True,
    )
    assert fabric["bgpAllowAsInNum"] == 4
    assert trm["ipv6Trm"] is True
    assert trm["v6RpAbsent"] is True
    assert trm["v6MulticastGroup"] == "ff1e::/121"
    assert trm["mvpnInterAs"] is True
    gathered = VrfDataModel.from_response(payload).to_gathered_config()
    for key in (
        "bgp_best_path_relax",
        "bgp_log_neighbor_change",
        "bgp_allow_as_in",
        "bgp_as_override",
        "ipv6_trm",
        "v6_no_rp",
        "mvpn_inter_as",
    ):
        assert gathered[key] is True
    assert gathered["bgp_allow_as_in_num"] == 4
    assert gathered["v6_overlay_mcast_group"] == "ff1e::/121"


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"v6_rp_address": "2001:db8::1"}, "ipv6_trm=True"),
        (
            {"ipv6_trm": True, "v6_no_rp": True, "v6_rp_address": "2001:db8::1"},
            "v6_no_rp=True",
        ),
        ({"trm_bgw_msite": True}, "trm_enable=True or ipv6_trm=True"),
        ({"bgp_password": "not-hex"}, "bgp_password"),
        ({"bgp_password": "aabbccdd"}, "bgp_passwd_encrypt"),
        ({"bgp_passwd_encrypt": "type6"}, "bgp_password"),
        ({"l3vni_wo_vlan": True, "vrf_int_mtu": 9000}, "vrf_int_mtu"),
        ({"l3vni_wo_vlan": True, "vrf_int_mtu": 9216}, "vrf_int_mtu"),
        (
            {"l3vni_wo_vlan": True, "ipv6_linklocal_enable": False},
            "ipv6_linklocal_enable",
        ),
        (
            {"l3vni_wo_vlan": True, "ipv6_linklocal_enable": True},
            "ipv6_linklocal_enable",
        ),
    ],
)
def test_standalone_vrf_ui_dependencies(fields, message):
    with pytest.raises(ValidationError, match=message):
        VrfConfigModel.from_config({"vrf_name": "BLUE", **fields})


def test_standalone_l3vni_without_vlan_omits_svi_defaults():
    config = VrfConfigModel.from_config({"vrf_name": "BLUE", "l3vni_wo_vlan": True}).to_config()
    payload = VrfDataModel.from_config(_transform(config)).to_payload()
    assert "mtu" not in payload["coreData"]
    assert "ipv6LinkLocal" not in payload["coreData"]


def test_standalone_no_vlan_transition_does_not_resend_inherited_svi_fields():
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _Strategy())
    model = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "BLUE",
            "vlan_id": 3001,
            "core_data": {
                "vrfVlanName": "old",
                "vrfInterfaceDescription": "old",
                "mtu": 9216,
                "ipv6LinkLocal": True,
            },
            "fabric_data": {"l3VniWithoutVlan": True},
        }
    )
    payload = orchestrator._create_or_update_payload(model)
    assert "vlanId" not in payload
    assert not {"vrfVlanName", "vrfInterfaceDescription", "mtu", "ipv6LinkLocal"} & payload["coreData"].keys()

    model.fabric_data["l3VniWithoutVlan"] = False
    payload = orchestrator._create_or_update_payload(model)
    assert payload["vlanId"] == 3001
    assert payload["coreData"]["mtu"] == 9216
    assert payload["coreData"]["ipv6LinkLocal"] is True


def test_standalone_ipv6_route_map_falls_back_to_requested_ipv4_map():
    for fields, expected in (
        ({"redist_direct_rmap": "CUSTOM-V4"}, "CUSTOM-V4"),
        (
            {"redist_direct_rmap": "CUSTOM-V4", "v6_redist_direct_rmap": "CUSTOM-V6"},
            "CUSTOM-V6",
        ),
    ):
        config = VrfConfigModel.from_config({"vrf_name": "BLUE", **fields}).to_config(exclude_unset=True)
        proposed = VrfDataModel.from_config(_transform(config))
        sm = SimpleNamespace(
            existing=NDConfigCollection(VrfDataModel),
            proposed=NDConfigCollection(VrfDataModel, [proposed]),
        )
        _resolve_standalone(sm, [config], "merged")
        payload = sm.proposed.get(("BLUE", "AK-VXLAN")).to_payload()
        assert payload["coreData"]["vrfRouteMap"] == "CUSTOM-V4"
        assert payload["coreData"]["v6VrfRouteMap"] == expected


def test_parent_route_map_fallback_uses_ipv4_for_new_vrf():
    config = VrfParentConfigModel.from_config({"vrf_name": "BLUE", "redist_direct_rmap": "CUSTOM-V4"}).to_config(exclude_unset=True)
    proposed = VrfDataModel.from_config(_transform(config, is_parent=True))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    strategy = SimpleNamespace(fabric_name="AK-VXLAN")
    VrfWorkflowCoordinator._resolve_parent_route_map_fallback(sm, [config], "merged", strategy)
    payload = proposed.to_payload()
    assert payload["coreData"]["vrfRouteMap"] == "CUSTOM-V4"
    assert payload["coreData"]["v6VrfRouteMap"] == "CUSTOM-V4"


def test_mcfg_parent_route_map_fallback_uses_ipv4_for_new_vrf():
    config = VrfParentConfigModel.from_config({"vrf_name": "BLUE", "redist_direct_rmap": "CUSTOM-V4"}).to_config(exclude_unset=True)
    proposed = VrfDataModel.from_config(_transform(config, is_parent=True, is_multicluster=True, fabric_data={"managementType": "vxlan"}))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    VrfWorkflowCoordinator._resolve_parent_route_map_fallback(sm, [config], "merged", SimpleNamespace(fabric_name="AK-VXLAN"))
    assert proposed.to_payload()["coreData"]["v6VrfRouteMap"] == "CUSTOM-V4"


@pytest.mark.parametrize("state,expected", [("merged", "OLD-V6"), ("replaced", "NEW-V4"), ("overridden", "NEW-V4")])
def test_parent_route_map_fallback_respects_sparse_and_authoritative_states(state, expected):
    config = {"vrf_name": "BLUE", "redist_direct_rmap": "NEW-V4"}
    proposed = VrfDataModel.from_config(_transform(config, is_parent=True))
    current = VrfDataModel.from_response(
        {"fabricName": "AK-VXLAN", "vrfName": "BLUE", "vrfType": "vxlanIbgp", "coreData": {"vrfRouteMap": "OLD-V4", "v6VrfRouteMap": "OLD-V6"}}
    )
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    VrfWorkflowCoordinator._resolve_parent_route_map_fallback(sm, [config], state, SimpleNamespace(fabric_name="AK-VXLAN"))
    effective = current.model_copy(deep=True).merge(proposed) if state == "merged" else proposed
    assert effective.to_payload()["coreData"]["v6VrfRouteMap"] == expected


def test_parent_rd_id_and_valid_child_values_split_for_msd_and_mcfg():
    for is_multicluster in (False, True):
        config = {
            "vrf_name": "BLUE",
            "vrf_id": 50001,
            "route_distinguisher_id": 73,
            "child_fabric_config": [{"fabric_name": "AK-VXLAN", "adv_host_routes": True, "trm_enable": True}],
        }
        parent = VrfParentConfigModel.from_config(config).to_config(exclude_unset=True)
        assert not set(PARENT_CHILD_ONLY_VRF_FIELDS) & parent.keys()
        assert parent["child_fabric_config"][0]["adv_host_routes"] is True
        assert parent["child_fabric_config"][0]["trm_enable"] is True
        parent.pop("child_fabric_config")
        payload = VrfDataModel.from_config(_transform(parent, is_parent=True, is_multicluster=is_multicluster)).to_payload()
        assert payload["coreData"]["routeDistinguisherId"] == 73
        assert "fabricData" not in payload


@pytest.mark.parametrize("field", PARENT_CHILD_ONLY_VRF_FIELDS)
@pytest.mark.parametrize("wire_keys", [False, True])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged", "gathered", "deleted"])
def test_parent_vrf_validates_child_only_top_level_options(field, wire_keys, state):
    key = VrfChildConfigModel.model_fields.get(field).alias if wire_keys else field
    config = {"vrf_name": "BLUE", key: False}
    if state in ("gathered", "deleted"):
        model = VrfParentConfigModel.from_config(config, context={"state": state})
        assert field not in model.to_config(exclude_unset=True)
    else:
        with pytest.raises(ValidationError, match="must be set under child_fabric_config") as error:
            VrfParentConfigModel.from_config(config, context={"state": state})
        assert field in error.value.errors()[0]["msg"]
    assert config[key] is False


def test_parent_vrf_reports_all_misplaced_fields_and_keeps_nested_false():
    config = {
        "vrfName": "BLUE",
        "trmEnable": True,
        "advHostRoutes": False,
        "l3vniWoVlan": True,
        "childFabricConfig": [{"fabric_name": "AK-VXLAN", "advHostRoutes": False}],
    }
    with pytest.raises(ValidationError, match="must be set under child_fabric_config") as error:
        VrfParentConfigModel.from_config(config, context={"state": "merged"})
    message = error.value.errors()[0]["msg"]
    assert all(field in message for field in ("trm_enable", "adv_host_routes", "l3vni_wo_vlan"))
    for key in ("trmEnable", "advHostRoutes", "l3vniWoVlan"):
        config.pop(key)
    model = VrfParentConfigModel.from_config(config, context={"state": "merged"})
    assert model.to_config(exclude_unset=True)["child_fabric_config"] == [{"fabric_name": "AK-VXLAN", "adv_host_routes": False}]


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
def test_parent_vrf_does_not_reject_argspec_defaults(state):
    spec = {**vrf_parent_argument_spec(), **vrf_standalone_argument_spec()}
    accepted = ArgumentSpecValidator({"config": {"type": "list", "elements": "dict", "options": spec}}).validate({"config": [{"vrf_name": "BLUE"}]})
    assert not accepted.error_messages
    parsed = VrfParentConfigModel.from_config(accepted.validated_parameters["config"][0], context={"state": state}).to_config(exclude_unset=True)
    assert not set(PARENT_CHILD_ONLY_VRF_FIELDS) & parsed.keys()


@pytest.mark.parametrize("field,value", [("import_mvpn_rt", []), ("rp_address", "")])
def test_parent_vrf_rejects_explicit_empty_child_options(field, value):
    with pytest.raises(ValidationError, match="must be set under child_fabric_config"):
        VrfParentConfigModel.from_config({"vrf_name": "BLUE", field: value}, context={"state": "merged"})


@pytest.mark.parametrize("action", ["enforcedPermit", "enforcedDeny"])
def test_standalone_enforced_security_action_allows_controller_generated_tag(action):
    config = VrfConfigModel.from_config({"vrf_name": "BLUE", "default_security_action": action}).to_config(exclude_unset=True)
    payload = VrfDataModel.from_config(_transform(config)).to_payload()
    assert payload["defaultSecurityAction"] == action
    assert "defaultSecurityGroupTag" not in payload


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_standalone_generated_tag_and_no_vlan_readback_repeat_without_diff(state):
    existing = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "vxlanIbgp",
            "defaultSecurityAction": "enforcedPermit",
            "defaultSecurityGroupTag": 11282,
            "fabricData": {
                "l3VniWithoutVlan": True,
                "advertiseDefaultRoute": True,
                "advertiseHostRoute": False,
                "bgpAllowAsIn": False,
                "bgpAllowAsInNum": 3,
                "bgpAsOverride": False,
                "bgpBestPathRelax": False,
                "bgpDisablePeerAsCheck": False,
                "bgpLogNeighborChange": False,
                "bgpSoftReconfigAlways": False,
                "configureStaticDefaultRoute": True,
                "enableVrfVpnRouteLeaking": False,
                "netflow": False,
                "trmData": {
                    "ipv4Trm": False,
                    "ipv6Trm": False,
                    "mvpnInterAs": False,
                    "trmOnBgw": False,
                    "v4RpAbsent": False,
                    "v4RpExternal": False,
                    "v6RpAbsent": False,
                    "v6RpExternal": False,
                },
            },
            "coreData": {
                "disableRtAuto": False,
                "ipv6LinkLocal": True,
                "maxBgpPaths": 1,
                "maxIbgpPaths": 2,
                "mtu": 9216,
                "routingTag": 12345,
            },
        }
    )
    proposed = VrfDataModel.from_config(
        _transform(
            {
                "vrf_name": "BLUE",
                "default_security_action": "enforcedPermit",
                "l3vni_wo_vlan": True,
            }
        )
    )
    collection = NDConfigCollection(VrfDataModel, [existing])
    assert collection.get_diff_config(proposed, exclude_unset=state == "merged") == "no_diff"

    explicit_tag = VrfDataModel.from_config(
        _transform(
            {
                "vrf_name": "BLUE",
                "default_security_action": "enforcedPermit",
                "default_security_group_tag": 11283,
                "l3vni_wo_vlan": True,
            }
        )
    )
    assert collection.get_diff_config(explicit_tag, exclude_unset=state == "merged") == "changed"


def test_standalone_authoritative_reverse_diff_keeps_nondefault_and_explicit_default_edits():
    existing = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "coreData": {"maxBgpPaths": 8},
            "fabricData": {"bgpBestPathRelax": True},
        }
    )
    collection = NDConfigCollection(VrfDataModel, [existing])
    sparse = VrfDataModel.from_config({"fabric_name": "AK-VXLAN", "vrf_name": "BLUE"})
    assert collection.get_diff_config(sparse) == "changed"
    explicit_defaults = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "BLUE",
            "core_data": {"maxBgpPaths": 1},
            "fabric_data": {"bgpBestPathRelax": False},
        }
    )
    assert collection.get_diff_config(explicit_defaults, exclude_unset=True) == "changed"


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_standalone_vrf_state_machine_repeated_sparse_definition_is_noop(state):
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfId": 59694,
            "vrfType": "vxlanIbgp",
            "defaultSecurityAction": "enforcedPermit",
            "defaultSecurityGroupTag": 11282,
            "coreData": {
                "vrfRouteMap": "CUSTOM-V4",
                "v6VrfRouteMap": "CUSTOM-V4",
                "mtu": 9216,
                "ipv6LinkLocal": True,
                "maxBgpPaths": 1,
            },
            "fabricData": {
                "l3VniWithoutVlan": True,
                "advertiseDefaultRoute": True,
                "trmData": {"ipv4Trm": False, "ipv6Trm": False},
            },
        }
    )
    proposed = VrfDataModel.from_config(
        _transform(
            {
                "vrf_name": "BLUE",
                "vrf_id": 59694,
                "default_security_action": "enforcedPermit",
                "l3vni_wo_vlan": True,
                "redist_direct_rmap": "CUSTOM-V4",
            }
        )
    )
    writes = []
    sm = NDStateMachine.__new__(NDStateMachine)
    sm.state = state
    sm.before = NDConfigCollection(VrfDataModel, [current])
    sm.existing = sm.before.copy()
    sm.proposed = NDConfigCollection(VrfDataModel, [proposed])
    sm.sent = NDConfigCollection(VrfDataModel)
    sm.removed = NDConfigCollection(VrfDataModel)
    sm.model_orchestrator = SimpleNamespace(
        preflight_create=lambda _items: None,
        preflight=lambda _items: None,
        update=lambda item: writes.append(("update", item)),
        create_bulk=lambda items: writes.append(("create", items)),
        delete_bulk=lambda items: writes.append(("delete", items)),
    )
    sm.output = SimpleNamespace(assign=lambda **_kwargs: None)
    sm.check_mode = False
    sm.ignore_errors = False
    sm.supports_bulk_delete = True
    intent = {
        "vrf_name": "BLUE",
        "vrf_id": 59694,
        "default_security_action": "enforcedPermit",
        "l3vni_wo_vlan": True,
        "redist_direct_rmap": "CUSTOM-V4",
    }
    _resolve_standalone(sm, [intent], state)
    sm.manage_state()
    assert writes == []
    assert len(sm.sent) == 0


@pytest.mark.parametrize("state", ["replaced", "overridden"])
def test_standalone_authoritative_route_map_fallback_repeat(state):
    proposed = VrfDataModel.from_config(_transform({"vrf_name": "BLUE", "redist_direct_rmap": "CUSTOM-V4"}))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [{"vrf_name": "BLUE", "redist_direct_rmap": "CUSTOM-V4"}], state)
    effective = sm.proposed.get(("BLUE", "AK-VXLAN"))
    assert effective.to_payload()["coreData"]["v6VrfRouteMap"] == "CUSTOM-V4"
    existing = VrfDataModel.from_response(effective.to_payload())
    assert NDConfigCollection(VrfDataModel, [existing]).get_diff_config(effective) == "no_diff"


def test_standalone_sparse_dependencies_use_existing_effective_values():
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "fabricData": {
                "trmData": {"ipv4Trm": True, "v4RpAbsent": False, "l3VniMulticastGroup": "239.1.1.3"},
                "netflow": True,
                "netflowMonitor": "MONITOR-A",
                "bgpPassword": "aabbccdd",
                "bgpPasswordKeyType": "type6",
            },
        }
    )
    intent = {"vrf_name": "BLUE", "rp_address": "192.0.2.9", "bgp_password": "eeff0011"}
    VrfConfigModel.from_config(intent, context={"state": "merged", "defer_dependencies": True})
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [intent], "merged")
    payload = _effective_vrf(sm).to_payload()
    assert payload["fabricData"]["trmData"]["v4RpAddress"] == "192.0.2.9"
    assert payload["fabricData"]["trmData"]["ipv4Trm"] is True
    assert payload["fabricData"]["netflowMonitor"] == "MONITOR-A"
    assert payload["fabricData"]["bgpPasswordKeyType"] == "type6"

    empty = SimpleNamespace(existing=NDConfigCollection(VrfDataModel), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    with pytest.raises(ValidationError, match="require trm_enable=True"):
        _resolve_standalone(empty, [intent], "merged")


@pytest.mark.parametrize(
    ("mode", "address", "api_mode", "api_address", "api_external", "enabled"),
    [
        ("no_rp", "rp_address", "v4RpAbsent", "v4RpAddress", "v4RpExternal", "ipv4Trm"),
        ("v6_no_rp", "v6_rp_address", "v6RpAbsent", "v6RpAddress", "v6RpExternal", "ipv6Trm"),
    ],
)
def test_standalone_sparse_no_rp_clears_inherited_rp(mode, address, api_mode, api_address, api_external, enabled):
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "vxlanIbgp",
            "fabricData": {
                "trmData": {
                    enabled: True,
                    api_mode: False,
                    api_address: "2001:db8::1" if mode == "v6_no_rp" else "192.0.2.9",
                    api_external: True,
                    "l3VniMulticastGroup": "239.1.1.3",
                }
            },
        }
    )
    intent = {"vrf_name": "BLUE", mode: True}
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [intent], "merged")
    payload = _effective_vrf(sm).to_payload()
    trm = payload["fabricData"]["trmData"]
    assert trm[api_mode] is True
    assert api_address not in trm
    assert api_external not in trm
    assert (
        NDConfigCollection(VrfDataModel, [VrfDataModel.from_response(payload)]).get_diff_config(sm.proposed.get(("BLUE", "AK-VXLAN")), exclude_unset=True)
        == "no_diff"
    )

    contradictory = {**intent, address: "2001:db8::2" if mode == "v6_no_rp" else "192.0.2.10"}
    sm.proposed.replace(VrfDataModel.from_config(_transform(contradictory)))
    with pytest.raises(ValidationError, match=address):
        _resolve_standalone(sm, [contradictory], "merged")


def test_standalone_sparse_repeat_clears_stale_rp_when_mode_already_matches():
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "fabricData": {
                "trmData": {
                    "ipv4Trm": True,
                    "v4RpAbsent": True,
                    "v4RpAddress": "192.0.2.9",
                    "v4RpExternal": True,
                    "l3VniMulticastGroup": "239.1.1.3",
                }
            },
        }
    )
    intent = {"vrf_name": "BLUE", "no_rp": True}
    proposed = VrfDataModel.from_config(_transform(intent))
    collection = NDConfigCollection(VrfDataModel, [current])

    assert collection.get_diff_config(proposed, exclude_unset=True) == "changed"
    effective = current.model_copy(deep=True).merge(proposed)
    assert "v4RpAddress" not in effective.fabric_data["trmData"]
    assert "v4RpExternal" not in effective.fabric_data["trmData"]
    readback = NDConfigCollection(VrfDataModel, [VrfDataModel.from_response(effective.to_payload())])
    assert readback.get_diff_config(proposed, exclude_unset=True) == "no_diff"


def test_standalone_sparse_trm_disable_clears_inherited_family_and_common_fields():
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "vxlanIbgp",
            "fabricData": {
                "trmData": {
                    "ipv4Trm": True,
                    "v4RpAddress": "192.0.2.9",
                    "v4MulticastGroup": "239.2.2.2",
                    "loopbackNumber": 1,
                    "l3VniMulticastGroup": "239.1.1.3",
                    "mvpnRouteTargetImport": ["65000:1"],
                }
            },
        }
    )
    intent = {"vrf_name": "BLUE", "trm_enable": False}
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [intent], "merged")
    payload = _effective_vrf(sm).to_payload()
    assert payload["fabricData"]["trmData"] == {"ipv4Trm": False}


@pytest.mark.parametrize(
    ("disabled", "removed", "retained"),
    [
        ("trm_enable", "v4RpAddress", "v6RpAddress"),
        ("ipv6_trm", "v6RpAddress", "v4RpAddress"),
    ],
)
def test_standalone_sparse_trm_disable_preserves_other_family(disabled, removed, retained):
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vrfType": "vxlanIbgp",
            "fabricData": {
                "trmData": {
                    "ipv4Trm": True,
                    "ipv6Trm": True,
                    "v4RpAddress": "192.0.2.9",
                    "v6RpAddress": "2001:db8::1",
                    "loopbackNumber": 1,
                    "l3VniMulticastGroup": "239.1.1.3",
                }
            },
        }
    )
    intent = {"vrf_name": "BLUE", disabled: False}
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [intent], "merged")
    trm = _effective_vrf(sm).to_payload()["fabricData"]["trmData"]
    assert removed not in trm
    assert retained in trm
    assert trm["loopbackNumber"] == 1
    assert trm["l3VniMulticastGroup"] == "239.1.1.3"


@pytest.mark.parametrize("field,value", [("trm_enable", True), ("vrf_description", "dropped")])
@pytest.mark.parametrize("state", ["merged", "replaced"])
def test_user_defined_vrf_rejects_fields_its_payload_cannot_carry(field, value, state):
    intent = {"vrf_name": "BLUE", "vrf_template_name": "CUSTOM", field: value}
    with pytest.raises(ValidationError, match=field):
        VrfConfigModel.from_config(intent, context={"state": state, "defer_dependencies": state == "merged"})


@pytest.mark.parametrize("state", ["gathered", "deleted"])
def test_user_defined_vrf_read_selectors_do_not_enforce_write_field_scope(state):
    intent = {"vrf_name": "BLUE", "vrf_template_name": "CUSTOM", "vrf_description": "readback"}
    assert VrfConfigModel.from_config(intent, context={"state": state}).vrf_type == "userDefined"


def test_standalone_new_password_requires_key_type():
    intent = {"vrf_name": "BLUE", "bgp_password": "aabbccdd"}
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    with pytest.raises(ValidationError, match="bgp_passwd_encrypt is required"):
        _resolve_standalone(sm, [intent], "merged")


def test_standalone_authoritative_omission_resets_nondefaults():
    current = VrfDataModel.from_response(
        {"fabricName": "AK-VXLAN", "vrfName": "BLUE", "coreData": {"maxBgpPaths": 8}, "fabricData": {"bgpBestPathRelax": True}}
    )
    intent = {"vrf_name": "BLUE"}
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [intent], "replaced")
    effective = sm.proposed.get(("BLUE", "AK-VXLAN"))
    assert sm.existing.get_diff_config(effective) == "changed"
    assert "coreData" not in effective.to_payload()
    assert "fabricData" not in effective.to_payload()


def test_standalone_sparse_no_vlan_rejects_explicit_svi_and_drops_readback_echo():
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "vlanId": 200,
            "coreData": {"vrfVlanName": "old", "mtu": 9216, "ipv6LinkLocal": True},
            "fabricData": {"l3VniWithoutVlan": True},
        }
    )
    sm = SimpleNamespace(
        existing=NDConfigCollection(VrfDataModel, [current]),
        proposed=NDConfigCollection(VrfDataModel, [VrfDataModel.from_config(_transform({"vrf_name": "BLUE", "vrf_description": "updated"}))]),
    )
    _resolve_standalone(sm, [{"vrf_name": "BLUE", "vrf_description": "updated"}], "merged")
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _Strategy())
    payload = orchestrator._create_or_update_payload(_effective_vrf(sm))
    assert payload["coreData"] == {"vrfDescription": "updated"}
    assert "vlanId" not in payload

    intent = {"vrf_name": "BLUE", "vrf_int_mtu": 9000}
    sm.proposed.replace(VrfDataModel.from_config(_transform(intent)))
    with pytest.raises(ValidationError, match="vrf_int_mtu"):
        _resolve_standalone(sm, [intent], "merged")


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("existing_mode", [None, False, True])
@pytest.mark.parametrize(
    "field,value,wire",
    [
        ("vlan_id", 2001, "vlanId"),
        ("vrf_vlan_name", "BLUE_VLAN", "vrfVlanName"),
        ("vrf_intf_desc", "BLUE SVI", "vrfInterfaceDescription"),
        ("vrf_vlan_name", "", "vrfVlanName"),
        ("vrf_intf_desc", "", "vrfInterfaceDescription"),
    ],
)
def test_standalone_l3vni_vlan_intent_overrides_creation_default_and_existing_mode(state, existing_mode, field, value, wire):
    """Explicit VLAN/SVI identity selects VLAN-backed mode, including explicit clears."""
    intent = {"vrf_name": "BLUE", field: value}
    current = (
        []
        if existing_mode is None
        else [VrfDataModel.from_response({"fabricName": "AK-VXLAN", "vrfName": "BLUE", "fabricData": {"l3VniWithoutVlan": existing_mode}})]
    )
    sm = SimpleNamespace(
        existing=NDConfigCollection(VrfDataModel, current),
        proposed=NDConfigCollection(VrfDataModel, [VrfDataModel.from_config(_transform(intent))]),
    )
    _resolve_standalone(sm, [intent], state, l3vni_default=True)
    payload = _effective_vrf(sm, state=state).to_payload()
    assert payload["fabricData"]["l3VniWithoutVlan"] is False
    assert (payload if field == "vlan_id" else payload["coreData"])[wire] == value
    assert intent["l3vni_wo_vlan"] is False


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("fabric_default", [None, False, True])
@pytest.mark.parametrize("existing_mode", [None, False, True])
def test_standalone_l3vni_default_is_creation_only(state, fabric_default, existing_mode):
    """Fabric settings choose new modes without migrating existing VRFs."""
    intent = {"vrf_name": "BLUE"}
    current = (
        []
        if existing_mode is None
        else [VrfDataModel.from_response({"fabricName": "AK-VXLAN", "vrfName": "BLUE", "fabricData": {"l3VniWithoutVlan": existing_mode}})]
    )
    sm = SimpleNamespace(
        existing=NDConfigCollection(VrfDataModel, current),
        proposed=NDConfigCollection(VrfDataModel, [VrfDataModel.from_config(_transform(intent))]),
    )
    _resolve_standalone(sm, [intent], state, l3vni_default=fabric_default)
    payload = _effective_vrf(sm, state=state).to_payload()
    expected = existing_mode if existing_mode is not None else fabric_default
    assert (payload.get("fabricData") or {}).get("l3VniWithoutVlan") is expected
    if expected is None:
        assert "l3vni_wo_vlan" not in intent
    else:
        assert intent["l3vni_wo_vlan"] is expected
    if current:
        assert sm.existing.get_diff_config(sm.proposed.get(("BLUE", "AK-VXLAN")), exclude_unset=state == "merged") == "no_diff"


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("selected", [False, True])
def test_standalone_l3vni_explicit_mode_wins_over_creation_default_and_current(state, selected):
    """An explicit mode overrides both cached state and the creation default."""
    intent = {"vrf_name": "BLUE", "l3vni_wo_vlan": selected}
    current = VrfDataModel.from_response({"fabricName": "AK-VXLAN", "vrfName": "BLUE", "fabricData": {"l3VniWithoutVlan": not selected}})
    sm = SimpleNamespace(
        existing=NDConfigCollection(VrfDataModel, [current]),
        proposed=NDConfigCollection(VrfDataModel, [VrfDataModel.from_config(_transform(intent))]),
    )
    _resolve_standalone(sm, [intent], state, l3vni_default=not selected)
    assert _effective_vrf(sm, state=state).fabric_data["l3VniWithoutVlan"] is selected


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("vlan_id", [None, 2001])
def test_standalone_missing_observed_mode_does_not_inherit_creation_default(state, vlan_id):
    """An unknown existing mode is not replaced with a fabric creation default."""
    intent = {"vrf_name": "BLUE"}
    current = VrfDataModel.from_response({"fabricName": "AK-VXLAN", "vrfName": "BLUE", "vlanId": vlan_id})
    sm = SimpleNamespace(
        existing=NDConfigCollection(VrfDataModel, [current]),
        proposed=NDConfigCollection(VrfDataModel, [VrfDataModel.from_config(_transform(intent))]),
    )
    _resolve_standalone(sm, [intent], state, l3vni_default=True)
    assert "l3VniWithoutVlan" not in (sm.proposed.get(("BLUE", "AK-VXLAN")).fabric_data or {})


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_standalone_generated_tag_and_sparse_repeat(state):
    current = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "defaultSecurityAction": "enforcedPermit",
            "defaultSecurityGroupTag": 11282,
            "coreData": {"vrfRouteMap": "OLD-V4", "v6VrfRouteMap": "CUSTOM-V6"},
        }
    )
    intent = {"vrf_name": "BLUE", "default_security_action": "enforcedPermit", "redist_direct_rmap": "NEW-V4"}
    proposed = VrfDataModel.from_config(_transform(intent))
    sm = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [current]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(sm, [intent], state)
    effective = _effective_vrf(sm, state=state)
    assert effective.default_security_group_tag == 11282
    assert effective.core_data["v6VrfRouteMap"] == ("CUSTOM-V6" if state == "merged" else "NEW-V4")
    readback = VrfDataModel.from_response(effective.to_payload())
    repeated = SimpleNamespace(existing=NDConfigCollection(VrfDataModel, [readback]), proposed=NDConfigCollection(VrfDataModel, [proposed]))
    _resolve_standalone(repeated, [intent], state)
    assert repeated.existing.get_diff_config(repeated.proposed.get(("BLUE", "AK-VXLAN")), exclude_unset=state == "merged") == "no_diff"


def test_standalone_sparse_merged_nested_payload_retains_omitted_values():
    existing = VrfDataModel.from_response(
        {
            "fabricName": "AK-VXLAN",
            "vrfName": "BLUE",
            "coreData": {
                "vrfRouteMap": "OLD-V4",
                "v6VrfRouteMap": "CUSTOM-V6",
                "maxBgpPaths": 8,
            },
            "fabricData": {
                "bgpAllowAsIn": True,
                "trmData": {"ipv4Trm": True, "v4RpAbsent": True},
            },
        }
    )
    proposed = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "BLUE",
            "core_data": {"vrfRouteMap": "NEW-V4"},
            "fabric_data": {"trmData": {"ipv6Trm": True}},
        }
    )
    collection = NDConfigCollection(VrfDataModel, [existing])
    assert collection.get_diff_config(proposed, exclude_unset=True) == "changed"
    merged = collection.merge(proposed)
    assert merged.to_payload()["coreData"] == {
        "vrfRouteMap": "NEW-V4",
        "v6VrfRouteMap": "CUSTOM-V6",
        "maxBgpPaths": 8,
    }
    assert merged.to_payload()["fabricData"] == {
        "bgpAllowAsIn": True,
        "trmData": {"ipv4Trm": True, "v4RpAbsent": True, "ipv6Trm": True},
    }
    readback = VrfDataModel.from_response(merged.to_payload())
    assert NDConfigCollection(VrfDataModel, [readback]).get_diff_config(proposed, exclude_unset=True) == "no_diff"


@pytest.mark.parametrize("key_type", [3, 7, "3", "7"])
def test_vrf_numeric_bgp_key_types_are_rejected(key_type):
    with pytest.raises(ValidationError, match="bgp_passwd_encrypt must be 3des, type6, or type7"):
        VrfConfigModel.from_config(
            {
                "vrf_name": "BLUE",
                "bgp_password": "aabbccdd",
                "bgp_passwd_encrypt": key_type,
            }
        )
    with pytest.raises(ValidationError, match="bgp_passwd_encrypt must be 3des, type6, or type7"):
        VxlanFabricInstance(bgpPasswordKeyType=key_type)


def test_vrf_bgp_key_type_argspec_exposes_only_manage_enum():
    choices = ["3des", "type6", "type7"]
    assert vrf_standalone_argument_spec()["bgp_passwd_encrypt"]["choices"] == choices
    assert "bgp_passwd_encrypt" not in vrf_parent_argument_spec()
    assert _child_fabric_config_element_spec()["bgp_passwd_encrypt"]["choices"] == choices


def _transform(
    config,
    fabric_name="AK-VXLAN",
    fabric_data=None,
    is_child=False,
    is_parent=False,
    is_multicluster=False,
):
    """Call the payload transformer without constructing the full orchestrator."""
    instance = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        instance,
        "strategy",
        _Strategy(fabric_data, is_child, is_parent, is_multicluster),
    )
    if is_child:
        return instance._transform_child_config_to_payload_model_data(config, fabric_name)
    return instance._transform_config_to_payload_model_data(config, fabric_name)


class _EndpointStrategy:
    fabric_name = "AK-VXLAN"
    fabric_data = {}
    is_parent = False

    def __init__(self, is_child=False, is_multicluster=False):
        self.is_child = is_child
        self.is_multicluster = is_multicluster

    @staticmethod
    def configure_endpoint(_endpoint):
        return None

    @staticmethod
    def vrfs_get_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
            EpManageFabricsVrfsGet,
        )

        return EpManageFabricsVrfsGet

    @staticmethod
    def vrfs_post_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
            EpManageFabricsVrfsPost,
        )

        return EpManageFabricsVrfsPost

    @staticmethod
    def vrf_actions_remove_post_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrf_actions import (
            EpManageFabricsVrfActionsRemovePost,
        )

        return EpManageFabricsVrfActionsRemovePost

    @staticmethod
    def vrf_put_cls():
        from ansible_collections.cisco.nd.plugins.module_utils.endpoints.v1.manage.manage_fabrics_vrfs import (
            EpManageFabricsVrfsVrfNamePut,
        )

        return EpManageFabricsVrfsVrfNamePut


class _McfgTopDownStrategy:
    fabric_name = "MCFG_FAB"
    is_parent = True
    is_child = False
    is_multicluster = True

    def __init__(self, fabric_data=None):
        self.fabric_data = fabric_data or {"management": {"type": "vxlan"}}


class _RestSend:
    controller_version = "4.3.1.175"

    def __init__(self, params):
        self.params = params
        self.response_current = {}


def _orchestrator_for_request_tests(params, is_child=False, is_multicluster=False):
    instance = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        instance,
        "strategy",
        _EndpointStrategy(is_child=is_child, is_multicluster=is_multicluster),
    )
    object.__setattr__(instance, "rest_send", _RestSend(params))
    return instance


@pytest.fixture(params=["externalConnectivity", "vxlanExternal"])
def external_vrf_inventory(request):
    """Actual AK-EXT stored shape, including an omitted optional description."""
    return [
        {"fabricName": "AK-EXT", "vrfName": "MyVRF_50000", "vrfType": request.param, "vrfStatus": "notApplicable", "description": "VRFDESc"},
        {
            "fabricName": "AK-EXT",
            "vrfName": "ND_EXT_VRF_20261028",
            "vrfType": request.param,
            "vrfStatus": "notApplicable",
            "description": "ND_EXT_INITIAL",
        },
        {"fabricName": "AK-EXT", "vrfName": "ND_EXT_VRF_BARE_20261028", "vrfType": request.param, "vrfStatus": "notApplicable"},
    ]


@pytest.mark.parametrize("state", ["merged", "replaced", "deleted"])
@pytest.mark.parametrize("name_count", [1, 2])
def test_external_vrf_discovery_uses_one_supported_query(external_vrf_inventory, state, name_count):
    requested = external_vrf_inventory[1 : 1 + name_count]
    orchestrator = _orchestrator_for_request_tests({"state": state, "config": [{"vrf_name": item["vrfName"]} for item in requested]})
    orchestrator.strategy.fabric_name = "AK-EXT"
    orchestrator.strategy.fabric_data = {"management": {"type": requested[0]["vrfType"]}}
    paths = []

    def request(**kwargs):
        paths.append(kwargs["path"])
        if "filter=" in kwargs["path"]:
            assert kwargs["path"] == "/api/v1/manage/fabrics/AK-EXT/vrfs?filter=vrfName%3AND_EXT_VRF_20261028"
            return {"meta": {"counts": {"remaining": 0, "total": 1}}, "vrfs": requested}
        return {"meta": {"counts": {"remaining": 0, "total": 3}}, "vrfs": external_vrf_inventory}

    object.__setattr__(orchestrator, "_request", request)
    assert orchestrator.query_all() == requested
    assert len(paths) == 1
    if name_count > 1:
        assert paths == ["/api/v1/manage/fabrics/AK-EXT/vrfs?offset=0&max=10000"]


@pytest.mark.parametrize("state", ["merged", "replaced", "deleted"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_external_vrf_multi_name_repeat_and_delete_use_existing_inventory(external_vrf_inventory, state, check_mode):
    config = [
        {"vrf_name": "ND_EXT_VRF_20261028", "vrf_description": "ND_EXT_INITIAL"},
        {"vrf_name": "ND_EXT_VRF_BARE_20261028"},
    ]
    params = {"state": state, "config": config, "output_level": "normal"}
    orchestrator = NDVrfOrchestrator(
        rest_send=RestSend(params),
        strategy=StandaloneVrfStrategy(fabric_name="AK-EXT", fabric_data={"management": {"type": external_vrf_inventory[0]["vrfType"]}}),
    )
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        if kwargs["verb"] == HttpVerbEnum.GET:
            assert kwargs["path"] == "/api/v1/manage/fabrics/AK-EXT/vrfs?offset=0&max=10000"
            return {"meta": {"counts": {"remaining": 0, "total": 3}}, "vrfs": external_vrf_inventory}
        assert state == "deleted"
        assert kwargs["path"] == "/api/v1/manage/fabrics/AK-EXT/vrfActions/remove"
        assert kwargs["data"] == {"vrfNames": ["ND_EXT_VRF_20261028", "ND_EXT_VRF_BARE_20261028"]}
        return {}

    object.__setattr__(orchestrator, "_request", request)
    parsed = [VrfConfigModel.from_config(entry, context={"state": state}).to_config() for entry in config]
    sm = NDStateMachine(
        module=SimpleNamespace(params=params, check_mode=check_mode),
        model_orchestrator=orchestrator,
        config=orchestrator.prepare_config_data(parsed),
    )
    sm.manage_state()
    assert sm.output.format()["changed"] is (state == "deleted")
    assert len(calls) == (2 if state == "deleted" and not check_mode else 1)
    assert len(sm.before) == 2


@pytest.mark.parametrize("observed_description", [{}, {"description": None}, {"description": ""}])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_external_vrf_explicit_description_clear_converges(external_vrf_inventory, observed_description, state, check_mode):
    current = {**external_vrf_inventory[-1], **observed_description}
    config = [{"vrf_name": current["vrfName"], "vrf_description": ""}]
    params = {"state": state, "config": config, "output_level": "normal"}
    orchestrator = NDVrfOrchestrator(
        rest_send=RestSend(params),
        strategy=StandaloneVrfStrategy(fabric_name="AK-EXT", fabric_data={"management": {"type": current["vrfType"]}}),
    )
    orchestrator.rest_send.controller_version = "4.3.1.175"
    calls = []

    def request(**kwargs):
        calls.append(kwargs)
        assert kwargs["verb"] == HttpVerbEnum.GET, "An already-cleared description must not cause a write"
        return {"meta": {"counts": {"remaining": 0, "total": 1}}, "vrfs": [current]}

    object.__setattr__(orchestrator, "_request", request)
    sm = NDStateMachine(
        module=SimpleNamespace(params=params, check_mode=check_mode), model_orchestrator=orchestrator, config=orchestrator.prepare_config_data(config)
    )
    sm.manage_state()
    assert sm.output.format()["changed"] is False
    assert len(calls) == 1
    proposed = sm.proposed.get((current["vrfName"], "AK-EXT"))
    assert orchestrator._create_or_update_payload(proposed)["description"] == ""
    observed = VrfDataModel.from_response(current)
    assert observed.to_payload().get("description") == observed_description.get("description")
    assert observed.to_gathered_config().get("vrf_description") == observed_description.get("description")


def test_external_vrf_description_comparison_preserves_clear_and_sparse_intent(external_vrf_inventory):
    current = VrfDataModel.from_response(external_vrf_inventory[1])
    sparse = VrfDataModel.from_config({"fabric_name": "AK-EXT", "vrf_name": current.vrf_name, "vrf_type": current.vrf_type})
    clear = VrfDataModel.from_config({**sparse.to_config(), "description": ""})

    assert current.get_diff(sparse, exclude_unset=True)
    assert not current.get_diff(sparse, exclude_unset=False)
    assert "description" not in sparse.to_diff_dict(exclude_unset=True)
    assert "description" not in sparse.to_payload()
    assert current.model_copy(deep=True).merge(sparse).description == "ND_EXT_INITIAL"
    for exclude_unset in (False, True):
        assert not current.get_diff(clear, exclude_unset=exclude_unset)
    assert current.model_copy(deep=True).merge(clear).to_payload()["description"] == ""
    vxlan = VrfDataModel.from_config({"fabric_name": "VXLAN", "vrf_name": "BLUE", "vrf_type": "vxlanIbgp"})
    assert "description" not in vxlan.to_diff_dict()


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
def test_external_vrf_definition_payload_and_readback_are_schema_shaped(vrf_type):
    fabric_data = {"manageFabricDetails": {"management": {"type": vrf_type}}}
    parsed = VrfConfigModel.from_config({"vrf_name": "EXT_BLUE", "vrf_description": "External routing"}).to_config()
    transformed = _transform(parsed, fabric_name="EXT", fabric_data=fabric_data)
    model = VrfDataModel.from_config(transformed)
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _EndpointStrategy())
    object.__setattr__(orchestrator, "rest_send", _RestSend({}))
    raw = {
        "fabricName": "EXT",
        "vrfName": "EXT_BLUE",
        "vrfType": vrf_type,
        "description": "External routing",
    }

    assert orchestrator._create_or_update_payload(model) == raw
    observed = VrfDataModel.from_response({"fabricName": "EXT", **raw})
    assert observed.to_gathered_config() == {
        "vrf_name": "EXT_BLUE",
        "vrf_description": "External routing",
    }
    assert observed.get_diff(model, exclude_unset=True)
    assert observed.get_diff(model, exclude_unset=False)
    minimal = VrfDataModel.from_config(
        _transform(
            VrfConfigModel.from_config({"vrf_name": "EXT_GREEN"}).to_config(),
            fabric_name="EXT",
            fabric_data=fabric_data,
        )
    )
    assert orchestrator._create_or_update_payload(minimal) == {
        "fabricName": "EXT",
        "vrfName": "EXT_GREEN",
        "vrfType": vrf_type,
    }


@pytest.mark.parametrize(
    "option,value",
    [
        ("vrf_id", 50000),
        ("vlan_id", 2000),
        ("trm_enable", True),
        ("attach", [{"ip_address": "192.0.2.10"}]),
    ],
)
def test_external_vrf_rejects_unsupported_options(option, value):
    fabric_data = {"management": {"type": "externalConnectivity"}}
    config = VrfConfigModel.from_config({"vrf_name": "EXT_BLUE", option: value}).to_config()
    with pytest.raises(ValueError, match=f"unsupported options: {option}"):
        _transform(config, fabric_data=fabric_data)


def test_external_vrf_rejects_custom_template_type_and_fills_readback_identity():
    fabric_data = {"management": {"type": "externalConnectivity"}}
    with pytest.raises(ValueError, match="unsupported options: vrf_template_name"):
        _transform(
            {"vrf_name": "EXT_BLUE", "vrf_template_name": "CUSTOM"},
            fabric_data=fabric_data,
        )

    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    strategy = _EndpointStrategy()
    strategy.fabric_data = fabric_data
    strategy.fabric_name = "EXT"
    object.__setattr__(orchestrator, "strategy", strategy)
    assert orchestrator._normalize_query_vrf_item({"vrfName": "EXT_BLUE", "description": "External routing"}) == {
        "vrfName": "EXT_BLUE",
        "vrfType": "externalConnectivity",
        "fabricName": "EXT",
        "description": "External routing",
    }


def test_external_vrf_rejects_explicit_default_valued_vxlan_option(monkeypatch):
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    orchestrator.strategy.fabric_data = {"management": {"type": "externalConnectivity"}}
    monkeypatch.setattr(
        "ansible_collections.cisco.nd.plugins.module_utils.orchestrators.vrfs.get_raw_module_args",
        lambda: {"config": [{"vrf_name": "EXT_BLUE", "trm_enable": False}]},
    )
    parsed = VrfConfigModel.from_config({"vrf_name": "EXT_BLUE", "trm_enable": False}).to_config()

    with pytest.raises(ValueError, match="unsupported options: trm_enable"):
        orchestrator.prepare_config_data([parsed])


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
@pytest.mark.parametrize("description", [{}, {"description": "External routing"}, {"description": ""}])
def test_external_vrf_create_and_update_include_fabric_identity(vrf_type, description):
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    orchestrator.strategy.fabric_name = "AK_EXT"
    model = VrfDataModel.from_config(
        {
            "fabric_name": "AK_EXT",
            "vrf_name": "EXT_BLUE",
            "vrf_type": vrf_type,
            **description,
        }
    )
    calls = []

    def record_request(**kwargs):
        calls.append(kwargs)
        return {"status": "success"}

    object.__setattr__(orchestrator, "_request", record_request)
    orchestrator.create_bulk([model])
    orchestrator.update(model)

    expected = {
        "fabricName": "AK_EXT",
        "vrfName": "EXT_BLUE",
        "vrfType": vrf_type,
        **description,
    }
    assert len(calls) == 2
    assert calls[0]["path"] == "/api/v1/manage/fabrics/AK_EXT/vrfs"
    assert calls[0]["verb"] == HttpVerbEnum.POST
    assert calls[0]["data"] == {"vrfs": [expected]}
    assert calls[1]["path"] == "/api/v1/manage/fabrics/AK_EXT/vrfs/EXT_BLUE"
    assert calls[1]["verb"] == HttpVerbEnum.PUT
    assert calls[1]["data"] == expected


@pytest.mark.parametrize("vrf_type", ["externalConnectivity", "vxlanExternal"])
@pytest.mark.parametrize(
    "version,supported",
    [("4.2.1.10", False), ("4.3.0.9", False), ("4.3.1.0", True), ("4.3.1.175", True), ("4.4.1.1", True), (None, False), ("invalid", False), ("4.3", False)],
)
@pytest.mark.parametrize("description", [{}, {"description": "probe"}, {"description": ""}])
@pytest.mark.parametrize("updating", [False, True])
def test_external_vrf_direct_writes_enforce_release_support(*, vrf_type, version, supported, description, updating):
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    orchestrator.rest_send.controller_version = version
    model = VrfDataModel.from_config({"fabricName": "FAB", "vrfName": "BLUE", "vrfType": vrf_type, **description})
    calls = []
    object.__setattr__(orchestrator, "_request", lambda **kwargs: calls.append(kwargs) or {})
    if not supported and (updating or description):
        with pytest.raises(Exception, match=r"requires ND 4\.3\.1 or later"):
            orchestrator.update(model) if updating else orchestrator.create_bulk([model])
        assert not calls
    else:
        orchestrator.update(model) if updating else orchestrator.create_bulk([model])
        assert len(calls) == 1
        assert calls[0]["verb"] == (HttpVerbEnum.PUT if updating else HttpVerbEnum.POST)


def test_external_vrf_release_check_reuses_cached_version_and_skips_unneeded_lookup():
    rest_send = RestSend({})
    versions = []

    def get_version():
        versions.append("lookup")
        return "4.3.1.175"

    rest_send._sender = SimpleNamespace(get_version=get_version)
    orchestrator = NDVrfOrchestrator(rest_send=rest_send, strategy=StandaloneVrfStrategy(fabric_name="ISN"))
    name_only = VrfDataModel.from_config({"fabricName": "ISN", "vrfName": "BLUE", "vrfType": "externalConnectivity"})
    vxlan = VrfDataModel.from_config({"fabricName": "FAB", "vrfName": "BLUE", "vrfType": "vxlanIbgp"})
    orchestrator.validate_external_vrf_write(name_only)
    orchestrator.validate_external_vrf_write(vxlan, updating=True)
    assert not versions
    for _index in range(3):
        orchestrator.validate_external_vrf_write(name_only, updating=True)
    assert versions == ["lookup"]


def test_vrfs_00010_transform_standalone_config_to_schema_payload():
    """
    # Summary

    Verify playbook-facing VRF config is transformed to the schema-shaped
    payload before VrfDataModel drops unknown config fields.

    ## Test

    - Python config fields are mapped into coreData and fabricData
    - vrfType defaults from resolved fabric details
    - The final VrfDataModel payload contains nested ND API keys

    ## Classes and Methods

    - NDVrfOrchestrator._transform_config_to_payload_model_data()
    - VrfDataModel.to_payload()
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-vrf-int1",
            "vrf_id": 9008011,
            "vlan_id": 600,
            "vrf_int_mtu": 9216,
            "loopback_route_tag": 12345,
            "redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "v6_redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "max_bgp_paths": 1,
            "max_ibgp_paths": 2,
            "ipv6_linklocal_enable": True,
            "disable_rt_auto": False,
            "adv_host_routes": False,
            "adv_default_routes": True,
            "static_default_route": True,
            "netflow_enable": False,
        },
        fabric_data={"vrfType": "vxlanEbgp"},
    )

    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["fabricName"] == "AK-VXLAN"
    assert payload["vrfName"] == "ansible-vrf-int1"
    assert payload["vrfId"] == 9008011
    assert payload["vlanId"] == 600
    assert payload["vrfType"] == "vxlanEbgp"

    assert payload["coreData"]["mtu"] == 9216
    assert payload["coreData"]["routingTag"] == 12345
    assert payload["coreData"]["vrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert payload["coreData"]["v6VrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert "routeTargetImport" not in payload["coreData"]
    assert "evpnRouteTargetExport" not in payload["coreData"]

    assert payload["fabricData"]["advertiseHostRoute"] is False
    assert payload["fabricData"]["advertiseDefaultRoute"] is True
    assert payload["fabricData"]["configureStaticDefaultRoute"] is True
    assert payload["fabricData"]["netflow"] is False
    assert "trmData" not in payload["fabricData"]


def test_vrfs_00020_transform_preserves_minimal_config_intent():
    """
    # Summary

    Verify a minimal VRF config does not manufacture optional field intent.

    ## Classes and Methods

    - NDVrfOrchestrator._transform_config_to_payload_model_data()
    """
    transformed = _transform({"vrf_name": "ansible-vrf-int1"})
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["vrfType"] == "vxlanIbgp"
    assert "coreData" not in payload
    assert "fabricData" not in payload


@pytest.mark.parametrize("selected", [False, True])
def test_vrf_l3vni_without_vlan_explicit_values_reach_payload(selected):
    """Preserve both explicit overrides instead of applying the fabric default."""
    config = VrfConfigModel.from_config({"vrf_name": "BLUE", "l3vni_wo_vlan": selected}).to_config()
    payload = VrfDataModel.from_config(_transform(config)).to_payload()
    assert payload["fabricData"]["l3VniWithoutVlan"] is selected


def test_vrf_sparse_merged_l3vni_omission_does_not_reset_existing_override():
    """A fabric default must not replace an existing VRF's value in merged."""
    existing = VrfDataModel.from_response(VrfDataModel.from_config(_transform({"vrf_name": "BLUE", "l3vni_wo_vlan": False})).to_payload())
    sparse = VrfConfigModel.from_config({"vrf_name": "BLUE"}).to_config(exclude_unset=True)
    proposed = VrfDataModel.from_config(_transform(sparse))
    assert existing.get_diff(proposed, exclude_unset=True) is True


def test_vrf_sparse_description_does_not_reset_trm_or_bgp_options():
    existing = VrfDataModel.from_response(
        VrfDataModel.from_config(
            _transform(
                {
                    "vrf_name": "BLUE",
                    "trm_enable": True,
                    "no_rp": True,
                    "underlay_mcast_ip": "239.1.1.3",
                    "bgp_best_path_relax": True,
                }
            )
        ).to_payload()
    )
    sparse = VrfConfigModel.from_config({"vrf_name": "BLUE", "vrf_description": "new"}).to_config(exclude_unset=True)
    proposed = VrfDataModel.from_config(_transform(sparse))
    assert proposed.to_payload()["coreData"] == {"vrfDescription": "new"}
    assert "fabricData" not in proposed.to_payload()
    merged = existing.merge(proposed)
    assert merged.fabric_data["trmData"]["ipv4Trm"] is True
    assert merged.fabric_data["trmData"]["l3VniMulticastGroup"] == "239.1.1.3"
    assert merged.fabric_data["bgpBestPathRelax"] is True


def test_vrf_rd_id_and_vpn_route_leaking_map_and_gather():
    config = VrfConfigModel.from_config(
        {
            "vrf_name": "BLUE",
            "route_distinguisher_id": 123,
            "enable_vrf_vpn_route_leaking": True,
        }
    ).to_config(exclude_unset=True)
    payload = VrfDataModel.from_config(_transform(config)).to_payload()
    assert payload["coreData"]["routeDistinguisherId"] == 123
    assert payload["fabricData"]["enableVrfVpnRouteLeaking"] is True
    gathered = VrfDataModel.from_response(payload).to_gathered_config()
    assert gathered["route_distinguisher_id"] == 123
    assert gathered["enable_vrf_vpn_route_leaking"] is True


def test_vrfs_00021_transform_mcfg_parent_uses_schema_payload_not_template_payload():
    """
    # Summary

    Verify MCFG parent create/update payloads use the OneManage manage schema,
    not the deprecated template-config/top-down payload shape.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-mcfg-parent",
            "vrf_id": 9008031,
            "vlan_id": 631,
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
        },
        fabric_name="MCFG_FAB",
        fabric_data={"managementType": "vxlan"},
        is_parent=True,
        is_multicluster=True,
    )
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["fabricName"] == "MCFG_FAB"
    assert payload["fabricData"]["advertiseHostRoute"] is True
    assert payload["fabricData"]["advertiseDefaultRoute"] is False
    assert payload["fabricData"]["configureStaticDefaultRoute"] is False

    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())
    mcfg_payload = orchestrator._create_or_update_payload(VrfDataModel.from_config(transformed))

    assert mcfg_payload["fabricName"] == "MCFG_FAB"
    assert mcfg_payload["vrfName"] == "ansible-mcfg-parent"
    assert mcfg_payload["vrfType"] == "vxlan"
    assert mcfg_payload["vrfId"] == 9008031
    assert "vlanId" not in mcfg_payload
    assert "vrfTemplateConfig" not in mcfg_payload
    assert mcfg_payload["fabricData"] == {}
    assert mcfg_payload["coreData"]["vrfVlanName"] == ""
    assert mcfg_payload["coreData"]["vrfInterfaceDescription"] == ""
    assert mcfg_payload["coreData"]["vrfDescription"] == ""
    assert mcfg_payload["coreData"]["routeTargetImport"] == []
    assert mcfg_payload["coreData"]["routeTargetExport"] == []


def test_vrfs_00022_transform_msd_parent_omits_fabric_data():
    """
    # Summary

    Verify non-MCFG parent behavior remains unchanged and does not carry
    parent fabricData into the normal parent payload.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-msd-parent",
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
        },
        is_parent=True,
    )
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert "fabricData" not in payload


def test_vrfs_00023_transform_mcfg_parent_omits_implicit_fabric_defaults():
    """
    # Summary

    Verify MCFG parent configs do not carry implicit fabricData defaults when
    the playbook only intends child_fabric_config to control child options.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-mcfg-parent-child-options",
            "vrf_id": 9008032,
            "vlan_id": 632,
        },
        fabric_name="MCFG_FAB",
        is_parent=True,
        is_multicluster=True,
    )
    payload = VrfDataModel.from_config(transformed).to_payload()

    assert "fabricData" not in payload


def test_vrfs_00025_config_model_accepts_supported_attachment_fields():
    """
    # Summary

    Verify attach/deploy are accepted by standalone and parent config models
    with only the supported attachment-level fields.
    """
    config = {
        "vrf_name": "ansible-vrf-attach",
        "deploy": False,
        "deploy_type": "vrf",
        "attach": [
            {
                "ip_address": "192.168.1.224",
                "freeform_config": "interface loopback10\n description test",
                "attachment_options": {
                    "dpu_secure": True,
                    "dpu_affinity": "dynamic",
                    "loopback_id": 10,
                    "loopback_ipv4_address": "10.10.10.10",
                    "loopback_ipv6_address": "2001:db8::10",
                    "import_vpn_rt": ["65000:10"],
                    "export_vpn_rt": ["65000:11"],
                    "import_evpn_rt": ["65000:12"],
                    "export_evpn_rt": ["65000:13"],
                },
            }
        ],
    }

    standalone = VrfConfigModel.from_config(config).to_config()
    parent = VrfParentConfigModel.from_config(dict(config, child_fabric_config=[{"fabric_name": "AK-VXLAN"}])).to_config()

    for parsed in (standalone, parent):
        assert parsed["deploy"] is False
        assert parsed["deploy_type"] == "vrf"
        attachment = parsed["attach"][0]
        assert attachment["ip_address"] == "192.168.1.224"
        assert attachment["freeform_config"] == "interface loopback10\n description test"
        attachment_options = attachment["attachment_options"]
        assert attachment_options["dpu_secure"] is True
        assert attachment_options["dpu_affinity"] == "dynamic"
        assert attachment_options["loopback_id"] == 10
        assert attachment_options["loopback_ipv4_address"] == "10.10.10.10"
        assert attachment_options["loopback_ipv6_address"] == "2001:db8::10"
        assert attachment_options["import_vpn_rt"] == ["65000:10"]
        assert attachment_options["export_vpn_rt"] == ["65000:11"]
        assert attachment_options["import_evpn_rt"] == ["65000:12"]
        assert attachment_options["export_evpn_rt"] == ["65000:13"]


def test_vrfs_00025a_config_model_rejects_attachment_aliases():
    """
    # Summary

    Verify playbook-facing VRF attachment config accepts snake_case only.
    """
    with pytest.raises(
        ValidationError,
        match="ipAddress|freeformConfig|attachmentOptions|dpuSecure|Extra inputs",
    ):
        VrfConfigModel.from_config(
            {
                "vrf_name": "ansible-vrf-attach-alias",
                "attach": [
                    {
                        "ipAddress": "192.168.1.224",
                        "freeformConfig": "interface loopback10",
                        "attachmentOptions": {
                            "dpuSecure": True,
                        },
                    }
                ],
            }
        )


def test_vrfs_00026_config_models_match_argument_specs():
    """
    # Summary

    Verify playbook-facing config models accept the same field names exposed
    by their corresponding argument specs.
    """
    internal_only_fields = {"vrf_type"}
    assert set(VrfConfigModel.model_fields) - internal_only_fields == set(vrf_standalone_argument_spec())
    from ansible_collections.cisco.nd.plugins.module_utils.models.manage_vrfs.config_models import PARENT_CHILD_ONLY_VRF_FIELDS

    assert set(VrfParentConfigModel.model_fields) - internal_only_fields - set(PARENT_CHILD_ONLY_VRF_FIELDS) == set(vrf_parent_argument_spec())
    attach_spec = vrf_base_argument_spec()["attach"]["options"]
    assert "vrf_type" not in vrf_base_argument_spec()
    assert "vrf_type" not in vrf_parent_argument_spec()
    attachment_options_spec = attach_spec["attachment_options"]["options"]

    assert set(attach_spec) == {"ip_address", "freeform_config", "attachment_options"}
    assert "loopback_id" not in attach_spec
    assert "dpu_secure" not in attach_spec
    assert "dpu_affinity" not in attach_spec
    assert attachment_options_spec["dpu_affinity"]["choices"] == [
        "dynamic",
        "dpu1",
        "dpu2",
        "dpu3",
        "dpu4",
    ]
    assert "dpu_secure" in attachment_options_spec
    assert "loopback_id" in attachment_options_spec
    assert "import_vpn_rt" in attachment_options_spec

    assert set(VrfChildConfigModel.model_fields) == set(_child_fabric_config_element_spec())


def test_vrfs_00027_config_model_accepts_schema_security_fields():
    """
    # Summary

    Verify schema-supported security group fields are accepted and preserved
    by standalone and parent config models.
    """
    config = {
        "vrf_name": "ansible-vrf-security",
        "default_security_action": "enforcedPermit",
        "default_security_group_tag": 101,
    }

    standalone = VrfConfigModel.from_config(config).to_config()
    parent = VrfParentConfigModel.from_config(config).to_config()

    for parsed in (standalone, parent):
        assert parsed["default_security_action"] == "enforcedPermit"
        assert parsed["default_security_group_tag"] == 101


@pytest.mark.parametrize(
    "feature,child_field,value",
    [
        ("trm_enable", "import_mvpn_rt", ["65000:1"]),
        ("trm_enable", "export_mvpn_rt", ["65000:2"]),
        ("trm_enable", "rp_address", "192.0.2.1"),
        ("netflow_enable", "nf_monitor", "CHILD_MON"),
    ],
)
def test_vrf_child_dependencies_do_not_inherit_parent_only_input(feature, child_field, value):
    config = {
        "vrf_name": "BLUE",
        feature: True,
        "child_fabric_config": [{"fabric_name": "site1", child_field: value}],
    }
    if feature == "netflow_enable":
        config["nf_monitor"] = "PARENT_MON"

    with pytest.raises(ValidationError, match="must be set under child_fabric_config"):
        VrfParentConfigModel.from_config(config)
    config.pop(feature)
    config.pop("nf_monitor", None)
    child = VrfParentConfigModel.from_config(config).child_fabric_config[0]
    assert getattr(child, feature) is None
    config["child_fabric_config"][0][feature] = True
    model = VrfParentConfigModel.from_config(config)
    assert feature not in model.to_config(exclude_unset=True)
    child = model.to_config()["child_fabric_config"][0]
    assert child[feature] is True
    assert child[child_field] == value


@pytest.mark.parametrize(
    "feature,child_field,value",
    [
        ("trm_enable", "import_mvpn_rt", ["65000:1"]),
        ("trm_enable", "rp_address", "192.0.2.1"),
        ("netflow_enable", "nf_monitor", "CHILD_MON"),
    ],
)
def test_vrf_child_dependencies_require_enabled_parent_or_child(feature, child_field, value):
    config = {
        "vrf_name": "BLUE",
        "child_fabric_config": [{"fabric_name": "site1", child_field: value}],
    }
    assert getattr(VrfParentConfigModel.from_config(config).child_fabric_config[0], feature) is None

    config["child_fabric_config"][0][feature] = True
    assert getattr(VrfParentConfigModel.from_config(config).child_fabric_config[0], feature) is True

    config["child_fabric_config"][0][feature] = False
    assert getattr(VrfParentConfigModel.from_config(config).child_fabric_config[0], feature) is False


@pytest.mark.parametrize("state", ["gathered", "deleted"])
def test_vrf_read_only_and_deleted_skip_child_feature_prerequisites(state):
    config = {
        "vrf_name": "BLUE",
        "child_fabric_config": [{"fabric_name": "site1", "import_mvpn_rt": ["65000:1"]}],
    }
    model = VrfParentConfigModel.from_config(config, context={"state": state})
    assert model.child_fabric_config[0].trm_enable is None


def test_vrfs_00030_transform_all_standalone_manageable_fields():
    """
    # Summary

    Verify every standalone module config field that can legally coexist is
    either mapped into the VXLAN VRF payload or intentionally excluded because
    the POST schema does not expose it for vxlanIbgp.

    ## Classes and Methods

    - NDVrfOrchestrator._transform_config_to_payload_model_data()
    - VrfDataModel.to_payload()
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-vrf-allprops",
            "vrf_id": 9008012,
            "vlan_id": 651,
            "vrf_vlan_name": "ansible_vrf_allprops_vlan",
            "vrf_intf_desc": "Ansible all properties VRF SVI",
            "vrf_int_mtu": 9216,
            "l3vni_wo_vlan": False,
            "vrf_description": "Ansible all manageable properties test",
            "loopback_route_tag": 12345,
            "redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "v6_redist_direct_rmap": "FABRIC-RMAP-REDIST-SUBNET",
            "max_bgp_paths": 4,
            "max_ibgp_paths": 4,
            "ipv6_linklocal_enable": True,
            "disable_rt_auto": True,
            "import_vpn_rt": ["65000:9008012"],
            "export_vpn_rt": ["65000:9008013"],
            "import_evpn_rt": ["65000:9008014"],
            "export_evpn_rt": ["65000:9008015"],
            "trm_enable": True,
            "no_rp": False,
            "rp_external": False,
            "rp_address": "10.254.254.1",
            "rp_loopback_id": 101,
            "underlay_mcast_ip": "239.1.1.1",
            "overlay_mcast_group": "239.2.2.2",
            "trm_bgw_msite": False,
            "import_mvpn_rt": ["65000:9008016"],
            "export_mvpn_rt": ["65000:9008017"],
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
            "bgp_password": "abcdef12",
            "bgp_passwd_encrypt": "3des",
            "netflow_enable": True,
            "nf_monitor": "MON1",
        }
    )

    payload = VrfDataModel.from_config(transformed).to_payload()
    core = payload["coreData"]
    fabric = payload["fabricData"]
    trm = fabric["trmData"]

    assert payload["fabricName"] == "AK-VXLAN"
    assert payload["vrfName"] == "ansible-vrf-allprops"
    assert payload["vrfId"] == 9008012
    assert payload["vlanId"] == 651
    assert payload["vrfType"] == "vxlanIbgp"
    assert "vrfTemplateName" not in payload
    assert "vrfExtensionTemplateName" not in payload
    assert "serviceVrfTemplateName" not in payload

    assert core["vrfVlanName"] == "ansible_vrf_allprops_vlan"
    assert core["vrfInterfaceDescription"] == "Ansible all properties VRF SVI"
    assert core["vrfDescription"] == "Ansible all manageable properties test"
    assert core["mtu"] == 9216
    assert core["routingTag"] == 12345
    assert core["vrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert core["v6VrfRouteMap"] == "FABRIC-RMAP-REDIST-SUBNET"
    assert core["maxBgpPaths"] == 4
    assert core["maxIbgpPaths"] == 4
    assert core["ipv6LinkLocal"] is True
    assert core["disableRtAuto"] is True
    assert core["routeTargetImport"] == ["65000:9008012"]
    assert core["routeTargetExport"] == ["65000:9008013"]
    assert core["evpnRouteTargetImport"] == ["65000:9008014"]
    assert core["evpnRouteTargetExport"] == ["65000:9008015"]

    assert fabric["l3VniWithoutVlan"] is False
    assert fabric["advertiseHostRoute"] is True
    assert fabric["advertiseDefaultRoute"] is False
    assert fabric["configureStaticDefaultRoute"] is False
    assert fabric["bgpPassword"] == "abcdef12"
    assert fabric["bgpPasswordKeyType"] == "3des"
    assert fabric["netflow"] is True
    assert fabric["netflowMonitor"] == "MON1"

    assert trm["ipv4Trm"] is True
    assert trm["v4RpAbsent"] is False
    assert trm["v4RpExternal"] is False
    assert trm["v4RpAddress"] == "10.254.254.1"
    assert trm["loopbackNumber"] == 101
    assert trm["l3VniMulticastGroup"] == "239.1.1.1"
    assert trm["v4MulticastGroup"] == "239.2.2.2"
    assert trm["trmOnBgw"] is False
    assert trm["mvpnRouteTargetImport"] == ["65000:9008016"]
    assert trm["mvpnRouteTargetExport"] == ["65000:9008017"]


def test_vrfs_00040_transform_user_defined_custom_template_payload():
    """
    Verify custom template fields are emitted only for userDefined VRFs and
    use the schema-supported field names.
    """
    transformed = _transform(
        {
            "vrf_name": "ansible-vrf-custom",
            "vrf_id": 9008020,
            "vlan_id": 652,
            "service_vrf_template_name": "CustomServiceTemplate1",
            "vrf_template_name": "CustomTemplate1",
            "vrf_extension_template_name": "CustomExtTemplate1",
            "vrf_template_config": {
                "param1": "value1",
                "mtu": "9216",
            },
        },
        fabric_data={"vrfType": "vxlanIbgp"},
    )

    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload == {
        "fabricName": "AK-VXLAN",
        "vrfName": "ansible-vrf-custom",
        "vrfId": 9008020,
        "vlanId": 652,
        "vrfType": "userDefined",
        "serviceVrfTemplateName": "CustomServiceTemplate1",
        "vrfTemplateName": "CustomTemplate1",
        "vrfExtensionTemplateName": "CustomExtTemplate1",
        "vrfTemplateConfig": {
            "param1": "value1",
            "mtu": "9216",
        },
    }


def test_vrfs_00050_custom_template_fields_infer_user_defined_type():
    """Custom template fields infer the internal userDefined discriminator."""
    model = VrfConfigModel.from_config(
        {
            "vrf_name": "ansible-vrf-custom",
            "vrf_template_name": "CustomTemplate1",
        }
    )

    assert model.vrf_type == "userDefined"


def test_vrfs_00055_custom_template_fields_reject_explicit_non_user_defined_type():
    """Internal non-userDefined discriminator cannot be combined with templates."""
    with pytest.raises(ValidationError):
        VrfConfigModel.from_config(
            {
                "vrf_name": "ansible-vrf-invalid-custom",
                "vrf_type": "vxlanIbgp",
                "vrf_template_name": "CustomTemplate1",
            }
        )


def test_vrfs_00060_vrf_template_config_values_must_be_strings():
    """Schema requires vrfTemplateConfig to be an object of string values."""
    with pytest.raises(ValidationError):
        VrfConfigModel.from_config(
            {
                "vrf_name": "ansible-vrf-invalid-template-config",
                "vrf_template_name": "CustomTemplate1",
                "vrf_template_config": {"mtu": 9216},
            }
        )


def test_vrfs_00070_transform_child_config_to_fabric_data_only():
    """MSD child overrides must not emit parent-owned VLAN/SVI/core fields."""
    transformed = _transform(
        {
            "vrf_name": "ansible-msd-vrf",
            "l3vni_wo_vlan": False,
            "adv_host_routes": True,
            "adv_default_routes": False,
            "static_default_route": False,
            "netflow_enable": False,
            "trm_enable": False,
        },
        fabric_name="AK-VXLAN",
        is_child=True,
    )

    payload = VrfDataModel.from_config(transformed).to_payload()

    assert payload["fabricName"] == "AK-VXLAN"
    assert payload["vrfName"] == "ansible-msd-vrf"
    assert "vlanId" not in payload
    assert "vrfId" not in payload
    assert "coreData" not in payload
    fabric = payload["fabricData"]
    assert fabric["l3VniWithoutVlan"] is False
    assert fabric["advertiseHostRoute"] is True
    assert fabric["advertiseDefaultRoute"] is False
    assert fabric["configureStaticDefaultRoute"] is False
    assert "bgpPasswordKeyType" not in fabric
    assert fabric["netflow"] is False
    assert fabric["trmData"]["ipv4Trm"] is False
    assert "trmOnBgw" not in fabric["trmData"]


def test_child_vrf_new_fields_map_to_sparse_fabric_payload():
    child = {
        "vrf_name": "BLUE",
        "bgp_best_path_relax": True,
        "enable_vrf_vpn_route_leaking": True,
        "bgp_log_neighbor_change": True,
        "ipv6_trm": True,
        "v6_no_rp": True,
        "v6_rp_external": False,
        "v6_overlay_mcast_group": "ff3e::/16",
        "mvpn_inter_as": True,
        "bgp_allow_as_in": True,
        "bgp_allow_as_in_num": 4,
        "bgp_as_override": True,
        "bgp_disable_peer_as_check": True,
        "bgp_soft_reconfig_always": True,
    }
    payload = VrfDataModel.from_config(_transform(child, fabric_name="AK-VXLAN", is_child=True)).to_payload()
    assert "coreData" not in payload
    assert "vlanId" not in payload
    fabric = payload["fabricData"]
    for key in (
        "bgpBestPathRelax",
        "enableVrfVpnRouteLeaking",
        "bgpLogNeighborChange",
        "bgpAllowAsIn",
        "bgpAsOverride",
        "bgpDisablePeerAsCheck",
        "bgpSoftReconfigAlways",
    ):
        assert fabric[key] is True
    assert fabric["bgpAllowAsInNum"] == 4
    assert fabric["trmData"] == {
        "ipv6Trm": True,
        "v6RpAbsent": True,
        "v6RpExternal": False,
        "v6MulticastGroup": "ff3e::/16",
        "mvpnInterAs": True,
    }
    assert "advertiseDefaultRoute" not in fabric
    assert "bgpPasswordKeyType" not in fabric
    assert "netflow" not in fabric


@pytest.mark.parametrize("state", ["merged", "replaced", "overridden"])
def test_child_vrf_sparse_defaults_and_repeat_comparison(state):
    intent = {"adv_host_routes": False, "bgp_log_neighbor_change": True}
    proposed, current = _validate_child_effective(intent, {"advertiseHostRoute": False, "bgpLogNeighborChange": True}, state)
    assert proposed.fabric_data == {"advertiseHostRoute": False, "bgpLogNeighborChange": True}
    assert current.get_diff(proposed, exclude_unset=state == "merged") is True


@pytest.mark.parametrize("is_multicluster", [False, True], ids=["msd", "mcfg"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("fabric_default", [None, False, True])
@pytest.mark.parametrize("existing_mode", [None, False, True])
def test_child_vrf_l3vni_creation_default_preserves_existing_mode(is_multicluster, state, fabric_default, existing_mode):
    """Both child topologies use only their own creation defaults for new VRFs."""
    existing = None if existing_mode is None else {"l3VniWithoutVlan": existing_mode, "bgpLogNeighborChange": False}
    proposed, current = _validate_child_effective(
        {"bgp_log_neighbor_change": False}, existing, state, fabric_default=fabric_default, is_multicluster=is_multicluster
    )
    expected = fabric_default if current is None else existing_mode
    assert proposed.fabric_data.get("l3VniWithoutVlan") is expected
    if current is not None:
        assert current.get_diff(proposed, exclude_unset=state == "merged") is True
    if expected is None:
        assert "l3VniWithoutVlan" not in proposed.fabric_data


@pytest.mark.parametrize("is_multicluster", [False, True], ids=["msd", "mcfg"])
@pytest.mark.parametrize("state", ["merged", "replaced", "overridden", "staged"])
@pytest.mark.parametrize("selected", [False, True])
def test_child_vrf_explicit_l3vni_mode_overrides_existing_and_fabric(is_multicluster, state, selected):
    """Both explicit child modes remain authoritative across parent states."""
    proposed, _current = _validate_child_effective(
        {"l3vni_wo_vlan": selected},
        {"l3VniWithoutVlan": not selected},
        state,
        fabric_default=not selected,
        is_multicluster=is_multicluster,
    )
    assert proposed.fabric_data["l3VniWithoutVlan"] is selected


@pytest.mark.parametrize(
    "intent,existing,valid",
    [
        ({"import_mvpn_rt": ["65000:1"]}, {"trmData": {"ipv4Trm": True, "v4RpAbsent": True, "l3VniMulticastGroup": "239.1.1.1"}}, True),
        ({"import_mvpn_rt": ["65000:1"]}, {"trmData": {"ipv4Trm": False}}, False),
        ({"v6_overlay_mcast_group": "ff3e::/16"}, {"trmData": {"ipv6Trm": True, "v6RpAbsent": True, "l3VniMulticastGroup": "239.1.1.1"}}, True),
        ({"trm_enable": True, "no_rp": True, "underlay_mcast_ip": "239.1.1.1"}, None, True),
        ({"trm_enable": True, "underlay_mcast_ip": "239.1.1.1"}, None, False),
        ({"trm_enable": True, "rp_external": True, "rp_address": "192.0.2.1", "underlay_mcast_ip": "239.1.1.1"}, None, True),
        ({"nf_monitor": "NEW"}, {"netflow": True, "netflowMonitor": "OLD"}, True),
        ({"nf_monitor": "NEW"}, {"netflow": False}, False),
        ({"bgp_password": "aabbccdd", "bgp_passwd_encrypt": "type6"}, None, True),
        ({"bgp_password": "aabbccdd"}, None, False),
        ({"bgp_allow_as_in_num": 4}, {"bgpAllowAsIn": False}, False),
    ],
)
def test_child_vrf_dependencies_use_effective_state(intent, existing, valid):
    if valid:
        _validate_child_effective(intent, existing)
    else:
        with pytest.raises(ValidationError):
            _validate_child_effective(intent, existing)


def test_child_vrf_password_requires_hex_input():
    with pytest.raises(ValidationError):
        VrfChildConfigModel.from_config({"fabric_name": "AK-VXLAN", "bgp_password": "not-hex"})


@pytest.mark.parametrize("vrf_type", ["vxlanIbgp", "vxlan"])
def test_child_vrf_disabling_netflow_clears_inherited_monitor(vrf_type):
    proposed, current = _validate_child_effective(
        {"netflow_enable": False},
        {"netflow": True, "netflowMonitor": "OLD"},
        vrf_type=vrf_type,
    )
    assert current.get_diff(proposed, exclude_unset=True) is False
    effective = current.model_copy(deep=True).merge(proposed)
    assert effective.fabric_data["netflow"] is False
    assert "netflowMonitor" not in effective.fabric_data
    assert effective.get_diff(proposed, exclude_unset=True) is True


@pytest.mark.parametrize("vrf_type", ["vxlanIbgp", "vxlan"])
def test_child_vrf_disabling_ipv6_trm_clears_inherited_rp(vrf_type):
    proposed, current = _validate_child_effective(
        {"ipv6_trm": False},
        {"trmData": {"ipv6Trm": True, "v6RpAddress": "2001:db8::1", "loopbackNumber": 5, "l3VniMulticastGroup": "239.1.1.1"}},
        vrf_type=vrf_type,
    )
    assert current.get_diff(proposed, exclude_unset=True) is False
    effective = current.model_copy(deep=True).merge(proposed)
    assert effective.fabric_data["trmData"] == {"ipv6Trm": False}
    assert effective.get_diff(proposed, exclude_unset=True) is True


@pytest.mark.parametrize("state", ["merged", "replaced", "deleted"])
def test_vrfs_00080_query_all_scopes_targeted_state_reads(state):
    """
    # Summary

    Verify targeted multi-name reads select only requested VRFs from one
    inventory read, without using the controller's broken OR filter.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": state,
            "config": [
                {"vrf_name": "ansible-vrf-b"},
                {"vrf_name": "ansible-vrf-a"},
                {"vrf_name": "ansible-vrf-a"},
            ],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {"vrfName": "ansible-vrf-b"},
                {"vrfName": "ansible-vrf-a"},
                {"vrfName": "ansible-vrf-other"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"vrfName": "ansible-vrf-b"},
        {"vrfName": "ansible-vrf-a"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=10000",
    ]


def test_vrfs_00081_query_all_scoped_single_name_uses_fielded_filter():
    """
    # Summary

    Verify single-name scoped reads use the VRF name filter form supported by
    the controller.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [{"vrf_name": "ansible-vrf-a"}],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": [{"vrfName": "ansible-vrf-a"}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": "ansible-vrf-a"}]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3Aansible-vrf-a",
    ]


def test_vrf_filter_builders_return_raw_expressions_for_endpoint_encoding():
    names = ["VRF/SECOND", "VRF PRIMARY&50%"]
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)

    assert vrf_name_filter(names) == "(vrfName:VRF PRIMARY&50% OR vrfName:VRF/SECOND)"
    assert orchestrator._vrf_name_filter(names) == "(vrfName:VRF PRIMARY&50% OR vrfName:VRF/SECOND)"


def test_vrf_query_all_encodes_reserved_filter_characters_once():
    vrf_name = "VRF PRIMARY&50%"
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [{"vrf_name": vrf_name}],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": [{"vrfName": vrf_name}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": vrf_name}]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3AVRF%20PRIMARY%2650%25",
    ]


@pytest.mark.parametrize("paginated", [False, True])
def test_vrfs_00081a_query_all_scoped_multi_name_uses_unfiltered_local_filter(paginated):
    """
    # Summary

    Verify multi-name VRF reads exact-filter one unfiltered inventory response.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "replaced",
            "config": [
                {"vrf_name": "ansible-vrf-b"},
                {"vrf_name": "ansible-vrf-a"},
            ],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        if paginated and "offset=0" in kwargs["path"]:
            return {"vrfs": [{"vrfName": "ansible-vrf-other"}], "meta": {"counts": {"remaining": 2, "total": 3}}}
        return {
            "vrfs": [
                {"vrfName": "ansible-vrf-b"},
                {"vrfName": "ansible-vrf-a"},
            ]
            + ([] if paginated else [{"vrfName": "ansible-vrf-other"}]),
            "meta": {"counts": {"remaining": 0, "total": 3}},
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [
        {"vrfName": "ansible-vrf-b"},
        {"vrfName": "ansible-vrf-a"},
    ]
    assert requested_paths == [
        "/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=10000",
    ] + (["/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=1&max=10000"] if paginated else [])


def test_vrfs_00081b_mcfg_parent_scoped_query_uses_unfiltered_read_and_local_filter():
    """
    # Summary

    Verify MCFG parent scoped reads avoid Lucene filters on the OneManage
    parent surface and exact-filter the paginated read in module code.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        orchestrator,
        "strategy",
        MulticlusterParentVrfStrategy(
            fabric_name="MCFG_FAB",
            fabric_data={"management": {"type": "vxlan"}, "members": []},
        ),
    )
    object.__setattr__(
        orchestrator,
        "rest_send",
        _RestSend(
            {
                "state": "replaced",
                "config": [{"vrf_name": "ansible-vrf-a"}],
            }
        ),
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {"vrfName": "ansible-vrf-a", "fabricName": "MCFG_FAB"},
                {"vrfName": "ansible-vrf-other", "fabricName": "MCFG_FAB"},
            ],
            "meta": {"counts": {"remaining": 0, "total": 2}},
        }

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": "ansible-vrf-a", "fabricName": "MCFG_FAB", "vrfType": "vxlan"}]
    assert requested_paths == ["/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfs?offset=0&max=10000"]


def test_vrfs_00082_query_all_uses_one_inventory_for_larger_name_sets():
    """
    # Summary

    Verify large targeted VRF configs avoid a large Lucene filter and use the
    normal fabric GET instead.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": f"ansible-vrf-{index}"} for index in range(5)],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": [{"vrfName": "ansible-vrf-0"}]}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == [{"vrfName": "ansible-vrf-0"}]
    assert requested_paths == ["/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max=10000"]


@pytest.mark.parametrize("metadata_key,requested_page_size", [("metadata", 200), ("meta", 10000)])
def test_vrfs_00083_query_all_unfiltered_walks_paginated_results(metadata_key, requested_page_size):
    """
    # Summary

    Verify unfiltered reads follow max/offset pagination instead of relying on
    the controller default page size.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "gathered",
            "config": [],
        }
    )
    original_page_size = NDVrfOrchestrator.unfiltered_query_page_size
    NDVrfOrchestrator.unfiltered_query_page_size = requested_page_size
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        if "offset=0" in kwargs["path"]:
            return {
                "vrfs": [{"vrfName": f"ansible-vrf-{index:03d}"} for index in range(200)],
                metadata_key: {"counts": {"total": 500, "remaining": 300}},
            }
        if "offset=200" in kwargs["path"]:
            return {
                "vrfs": [{"vrfName": f"ansible-vrf-{index:03d}"} for index in range(200, 400)],
                metadata_key: {"counts": {"total": 500, "remaining": 100}},
            }
        return {
            "vrfs": [{"vrfName": f"ansible-vrf-{index:03d}"} for index in range(400, 500)],
            metadata_key: {"counts": {"total": 500, "remaining": 0}},
        }

    object.__setattr__(orchestrator, "_request", request)

    try:
        result = orchestrator.query_all()
    finally:
        NDVrfOrchestrator.unfiltered_query_page_size = original_page_size

    assert len(result) == 500
    assert requested_paths == [
        f"/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=0&max={requested_page_size}",
        f"/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=200&max={requested_page_size}",
        f"/api/v1/manage/fabrics/AK-VXLAN/vrfs?offset=400&max={requested_page_size}",
    ]


def test_vrfs_00085_query_all_does_not_scope_overridden_reads():
    """
    # Summary

    Verify overridden keeps a full current-state read because it must compare
    desired config against all existing VRFs.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "overridden",
            "config": [{"vrf_name": "ansible-vrf-a"}],
        }
    )
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {"vrfs": []}

    object.__setattr__(orchestrator, "_request", request)

    assert orchestrator.query_all() == []
    assert len(requested_paths) == 1
    assert "filter=" not in requested_paths[0]


def test_vrfs_00087_mcfg_parent_normalizes_vrf_template_config():
    """
    # Summary

    Verify MCFG parent template-config data is converted back into the normal VRF
    schema shape used by validation and module output.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())

    normalized = orchestrator._normalize_query_vrf_item(
        {
            "fabric": "MCFG_FAB",
            "vrfName": "ansible-nd-vrf-mcfg-a",
            "vrfId": 9008860,
            "vrfStatus": "NA",
            "vrfTemplateConfig": json.dumps(
                {
                    "vrfVlanId": "2860",
                    "vrfDescription": "Ansible ND VRF MCFG sanity merged",
                    "maxBgpPaths": "2",
                    "maxIbgpPaths": "2",
                    "disableRtAuto": "true",
                    "routeTargetImport": "65000:50660",
                    "routeTargetExport": "65000:50661",
                    "routeTargetImportEvpn": "65000:50662",
                    "routeTargetExportEvpn": "65000:50663",
                    "advertiseHostRouteFlag": "true",
                    "advertiseDefaultRouteFlag": "false",
                    "configureStaticDefaultRouteFlag": "false",
                }
            ),
        }
    )

    assert normalized["fabricName"] == "MCFG_FAB"
    assert normalized["vrfType"] == "vxlan"
    assert normalized["vrfStatus"] == "notApplicable"
    assert normalized["vlanId"] == 2860
    assert normalized["coreData"]["vrfDescription"] == "Ansible ND VRF MCFG sanity merged"
    assert normalized["coreData"]["maxBgpPaths"] == 2
    assert normalized["coreData"]["maxIbgpPaths"] == 2
    assert normalized["coreData"]["disableRtAuto"] is True
    assert normalized["coreData"]["routeTargetImport"] == ["65000:50660"]
    assert normalized["coreData"]["routeTargetExport"] == ["65000:50661"]
    assert normalized["coreData"]["evpnRouteTargetImport"] == ["65000:50662"]
    assert normalized["coreData"]["evpnRouteTargetExport"] == ["65000:50663"]
    assert normalized["fabricData"]["l3VniWithoutVlan"] is False
    assert normalized["fabricData"]["advertiseHostRoute"] is True
    assert normalized["fabricData"]["advertiseDefaultRoute"] is False
    assert normalized["fabricData"]["configureStaticDefaultRoute"] is False


def test_vrfs_00088_mcfg_parent_infers_l3vni_without_vlan_from_top_down_empty_vlan():
    """Template-config readback omits the explicit L3VNI flag on some releases but returns an empty VLAN."""
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())

    normalized = orchestrator._normalize_query_vrf_item(
        {
            "fabric": "MCFG_FAB",
            "vrfName": "ansible-nd-vrf-mcfg-b",
            "vrfStatus": "NA",
            "vrfTemplateConfig": json.dumps(
                {
                    "vrfVlanId": "",
                    "vrfDescription": "Ansible ND VRF MCFG L3VNI without VLAN",
                    "advertiseDefaultRouteFlag": "true",
                    "configureStaticDefaultRouteFlag": "true",
                }
            ),
        }
    )

    assert "vlanId" not in normalized
    assert normalized["coreData"]["vrfDescription"] == "Ansible ND VRF MCFG L3VNI without VLAN"
    assert normalized["fabricData"]["l3VniWithoutVlan"] is True
    assert normalized["fabricData"]["advertiseDefaultRoute"] is True
    assert normalized["fabricData"]["configureStaticDefaultRoute"] is True


def test_vrfs_00089_mcfg_parent_enriches_missing_fabric_fields_from_child_vrfs():
    """
    MCFG parent template-config records may omit fabric-instance booleans; child
    fabric records remain the source of truth for those fields.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        orchestrator,
        "strategy",
        _McfgTopDownStrategy(
            {
                "members": [
                    {
                        "fabricName": "nac-msd-fabric1",
                        "fabricState": "member",
                        "clusterName": "ND42-REL",
                    }
                ]
            }
        ),
    )
    object.__setattr__(orchestrator, "enrich_mcfg_parent_from_children", True)
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {
                    "vrfName": "ansible-nd-vrf-mcfg-a",
                    "fabricData": {
                        "advertiseHostRoute": True,
                        "advertiseDefaultRoute": False,
                        "configureStaticDefaultRoute": False,
                    },
                }
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    enriched = orchestrator._enrich_mcfg_parent_vrfs_from_children(
        [
            {
                "fabricName": "MCFG_FAB",
                "vrfName": "ansible-nd-vrf-mcfg-a",
                "fabricData": {
                    "l3VniWithoutVlan": False,
                },
            }
        ]
    )

    assert requested_paths == ["/api/v1/manage/fabrics/nac-msd-fabric1/vrfs?clusterName=ND42-REL"]
    assert enriched[0]["fabricData"] == {
        "l3VniWithoutVlan": False,
        "advertiseHostRoute": True,
        "advertiseDefaultRoute": False,
        "configureStaticDefaultRoute": False,
    }


def test_vrfs_00089a_mcfg_parent_does_not_enrich_child_fields_unless_requested():
    """
    MCFG child-read enrichment is a gathered-output concern. Write-state query
    normalization must not pull child-only fields into parent diff input.
    """
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(
        orchestrator,
        "strategy",
        _McfgTopDownStrategy(
            {
                "members": [
                    {
                        "fabricName": "nac-msd-fabric1",
                        "fabricState": "member",
                        "clusterName": "ND42-REL",
                    }
                ]
            }
        ),
    )
    object.__setattr__(orchestrator, "enrich_mcfg_parent_from_children", False)
    requested_paths = []

    def request(**kwargs):
        requested_paths.append(kwargs["path"])
        return {
            "vrfs": [
                {
                    "vrfName": "ansible-nd-vrf-mcfg-a",
                    "fabricData": {
                        "advertiseHostRoute": True,
                    },
                }
            ]
        }

    object.__setattr__(orchestrator, "_request", request)

    item = {
        "fabricName": "MCFG_FAB",
        "vrfName": "ansible-nd-vrf-mcfg-a",
        "fabricData": {
            "l3VniWithoutVlan": False,
        },
    }

    enriched = orchestrator._enrich_mcfg_parent_vrfs_from_children([item])

    assert requested_paths == []
    assert enriched == [item]


def test_vrfs_00090_bulk_delete_retries_only_sync_failed_vrfs():
    """
    # Summary

    Verify bulk delete retries fabric re-sync failures and only sends the VRFs
    that failed with retryable controller sync errors on the next attempt.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "deleted",
            "config": [
                {"vrf_name": "ansible-vrf-a"},
                {"vrf_name": "ansible-vrf-b"},
            ],
        }
    )
    requested_payloads = []

    def request(**kwargs):
        requested_payloads.append(list(kwargs["data"]["vrfNames"]))
        if len(requested_payloads) == 1:
            orchestrator.rest_send.response_current = {
                "DATA": {
                    "results": [
                        {"vrfName": "ansible-vrf-a", "status": "success"},
                        {
                            "vrfName": "ansible-vrf-b",
                            "status": "failed",
                            "message": "Fabric re-sync is in progress. Retry after sync completes.",
                        },
                    ]
                }
            }
            raise Exception("partial delete failure")
        return {"results": [{"vrfName": "ansible-vrf-b", "status": "success"}]}

    object.__setattr__(orchestrator, "delete_retry_delay", 0)
    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator._delete_bulk_with_retry(["ansible-vrf-a", "ansible-vrf-b"])

    assert requested_payloads == [
        ["ansible-vrf-a", "ansible-vrf-b"],
        ["ansible-vrf-b"],
    ]
    assert result["results"] == [
        {"vrfName": "ansible-vrf-b", "status": "success"},
        {"vrfName": "ansible-vrf-a", "status": "success"},
    ]


def test_vrfs_00091_mcfg_parent_delete_uses_remove_action_body():
    """
    # Summary

    Verify multicluster parent VRF delete uses the OneManage remove action
    with a body payload, not the deprecated top-down bulk-delete query path.
    """
    strategy = MulticlusterParentVrfStrategy(
        fabric_name="MCFG_FAB",
        fabric_data={
            "managementType": "vxlan",
            "onemanageProxyPath": "/onemanage",
        },
    )
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", strategy)
    object.__setattr__(orchestrator, "rest_send", _RestSend({"state": "deleted", "config": []}))
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"vrfName": name, "status": "success"} for name in kwargs["data"]["vrfNames"]]}

    object.__setattr__(orchestrator, "delete_retry_delay", 0)
    object.__setattr__(orchestrator, "_request", request)

    result = orchestrator._delete_bulk_with_retry(["ansible-vrf-a", "ansible-vrf-b"])

    assert requests == [
        {
            "path": "/api/v1/oneManage/manage/fabrics/MCFG_FAB/vrfActions/remove",
            "verb": HttpVerbEnum.POST,
            "data": {"vrfNames": ["ansible-vrf-a", "ansible-vrf-b"]},
            "operation_type": OperationType.DELETE,
        }
    ]
    assert result["results"] == [
        {"vrfName": "ansible-vrf-a", "status": "success"},
        {"vrfName": "ansible-vrf-b", "status": "success"},
    ]


def test_vrfs_00095_bulk_create_uses_single_vrfs_payload():
    """
    # Summary

    Verify standalone/parent VRF creates are batched into one POST request with
    the API's list wrapper.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [
                {"vrf_name": "ansible-vrf-a"},
                {"vrf_name": "ansible-vrf-b"},
            ],
        }
    )
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {
            "results": [
                {"vrfName": "ansible-vrf-a", "status": "success"},
                {"vrfName": "ansible-vrf-b", "status": "success"},
            ]
        }

    object.__setattr__(orchestrator, "_request", request)
    models = [
        VrfDataModel.from_config(
            {
                "fabric_name": "AK-VXLAN",
                "vrf_name": "ansible-vrf-a",
                "vrf_type": "vxlanIbgp",
            }
        ),
        VrfDataModel.from_config(
            {
                "fabric_name": "AK-VXLAN",
                "vrf_name": "ansible-vrf-b",
                "vrf_type": "vxlanIbgp",
            }
        ),
    ]

    result = orchestrator.create_bulk(models)

    assert result["results"][0]["vrfName"] == "ansible-vrf-a"
    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/manage/fabrics/AK-VXLAN/vrfs"
    assert requests[0]["verb"].value == "POST"
    assert [item["vrfName"] for item in requests[0]["data"]["vrfs"]] == [
        "ansible-vrf-a",
        "ansible-vrf-b",
    ]


def test_vrfs_00096_mcfg_parent_bulk_create_uses_onemanage_schema_payload():
    """
    # Summary

    Verify MCFG parent VRF create uses the OneManage manage schema payload
    accepted by ND 4.2: ``{"vrfs": [{fabricName, vrfName, vrfType, coreData,
    fabricData, vrfId}]}``.
    """
    strategy = MulticlusterParentVrfStrategy(
        fabric_name="MCFG_C",
        fabric_data={
            "managementType": "vxlan",
            "manageFabricDetails": {"management": {"type": "vxlan"}},
        },
    )
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", strategy)
    object.__setattr__(orchestrator, "rest_send", _RestSend({"state": "merged", "config": []}))
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"results": [{"vrfName": "MyVRF_50000", "status": "success"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = VrfDataModel.from_config(
        {
            "fabric_name": "MCFG_C",
            "vrf_name": "MyVRF_50000",
            "vrf_type": "vxlan",
            "vrf_id": 50000,
            "vlan_id": 3123,
            "core_data": {
                "mtu": 9216,
                "routingTag": 12345,
                "vrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                "v6VrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                "maxBgpPaths": 1,
                "maxIbgpPaths": 2,
                "ipv6LinkLocal": True,
                "disableRtAuto": False,
            },
            "fabric_data": {
                "advertiseHostRoute": True,
                "advertiseDefaultRoute": False,
            },
        }
    )

    orchestrator.create_bulk([model])

    assert len(requests) == 1
    assert requests[0]["path"] == "/api/v1/oneManage/manage/fabrics/MCFG_C/vrfs"
    assert requests[0]["verb"] == HttpVerbEnum.POST
    assert requests[0]["operation_type"] == OperationType.CREATE
    assert requests[0]["data"] == {
        "vrfs": [
            {
                "fabricName": "MCFG_C",
                "vrfName": "MyVRF_50000",
                "vrfType": "vxlan",
                "coreData": {
                    "vrfVlanName": "",
                    "vrfInterfaceDescription": "",
                    "vrfDescription": "",
                    "mtu": 9216,
                    "routingTag": 12345,
                    "vrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                    "v6VrfRouteMap": "FABRIC-RMAP-REDIST-SUBNET",
                    "maxBgpPaths": 1,
                    "maxIbgpPaths": 2,
                    "ipv6LinkLocal": True,
                    "disableRtAuto": False,
                    "routeTargetImport": [],
                    "routeTargetExport": [],
                    "evpnRouteTargetImport": [],
                    "evpnRouteTargetExport": [],
                },
                "fabricData": {},
                "vrfId": 50000,
            }
        ]
    }


def test_vrfs_00100_child_create_bulk_uses_update_endpoint():
    """
    # Summary

    Verify parent-driven child fabric work never POST-creates VRFs on member
    fabrics.  ND requires VRF creation at the parent/group level; child fabric
    overrides are applied with PUT.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": "ansible-msd-vrf"}],
        },
        is_child=True,
    )
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        return {"status": "success"}

    object.__setattr__(orchestrator, "_request", request)
    model = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "ansible-msd-vrf",
            "fabric_data": {
                "advertiseDefaultRoute": False,
                "advertiseHostRoute": True,
            },
        }
    )

    result = orchestrator.create_bulk([model])

    assert result == [{"status": "success"}]
    assert len(requests) == 1
    assert requests[0]["verb"].value == "PUT"
    assert requests[0]["path"] == "/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-msd-vrf"
    assert requests[0]["data"] == {
        "fabricName": "AK-VXLAN",
        "vrfName": "ansible-msd-vrf",
        "vrfType": "vxlanIbgp",
        "fabricData": {
            "advertiseHostRoute": True,
            "advertiseDefaultRoute": False,
        },
    }


def test_vrfs_00105_remote_mcfg_child_update_falls_back_to_list_visibility():
    """
    # Summary

    Verify a remote MCFG child VRF update rejection does not fail the parent
    workflow when the VRF is visible through the child list endpoint.
    """
    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": "ansible-mcfg-vrf"}],
        },
        is_child=True,
        is_multicluster=True,
    )
    requests = []

    def request(**kwargs):
        requests.append(kwargs)
        if kwargs["verb"].value == "PUT":
            raise Exception("Request failed (400): Fabric 'AK-VXLAN' does not exist")
        return {"vrfs": [{"fabricName": "AK-VXLAN", "vrfName": "ansible-mcfg-vrf"}]}

    object.__setattr__(orchestrator, "_request", request)
    model = VrfDataModel.from_config(
        {
            "fabric_name": "AK-VXLAN",
            "vrf_name": "ansible-mcfg-vrf",
            "fabric_data": {
                "advertiseDefaultRoute": False,
                "advertiseHostRoute": True,
            },
        }
    )

    result = orchestrator.update(model)

    assert result["status"] == "skipped"
    assert result["fabricName"] == "AK-VXLAN"
    assert result["vrfName"] == "ansible-mcfg-vrf"
    assert [request["verb"].value for request in requests] == ["PUT", "GET"]
    assert requests[1]["path"] == "/api/v1/manage/fabrics/AK-VXLAN/vrfs?filter=vrfName%3Aansible-mcfg-vrf"


def test_vrfs_00106_handled_remote_mcfg_child_update_clears_failed_trace():
    """
    # Summary

    Verify the accepted remote-child PUT rejection remains visible in debug
    traces but no longer marks the task failed after list visibility is proven.
    """
    results = Results()
    results.action = OperationType.UPDATE.value
    results.operation_type = OperationType.UPDATE
    results.path_current = "/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-mcfg-vrf"
    results.verb_current = HttpVerbEnum.PUT
    results.payload_current = {"vrfName": "ansible-mcfg-vrf"}
    results.response_current = {
        "RETURN_CODE": 400,
        "DATA": {"message": "Fabric 'AK-VXLAN' does not exist"},
    }
    results.result_current = {"success": False, "changed": False}
    results.diff_current = {}
    results.verbosity_level_current = 2
    results.register_api_call()

    orchestrator = _orchestrator_for_request_tests(
        {
            "state": "merged",
            "config": [{"vrf_name": "ansible-mcfg-vrf"}],
        },
        is_child=True,
        is_multicluster=True,
    )
    object.__setattr__(orchestrator, "results", results)

    orchestrator._mark_child_update_rejection_handled("/api/v1/manage/fabrics/AK-VXLAN/vrfs/ansible-mcfg-vrf")

    results.build_final_result()
    final = results.final_result
    assert final["failed"] is False
    assert final["result"][0]["success"] is True
    assert final["result"][0]["handled"] is True
    assert final["response"][0]["handled"] is True


def test_vrfs_00107_vrf_status_accepts_uppercase_controller_values():
    """
    # Summary

    Verify live controller status casing is normalized by the API data model.
    """
    model = VrfDataModel.from_response(
        {
            "fabricName": "MCFG_C",
            "vrfName": "ansible-nd-vrf-mcfg-merged",
            "vrfStatus": "PENDING",
        }
    )

    assert model.to_config()["vrf_status"] == "pending"


@pytest.mark.parametrize("scope,raise_scoped", [([], False), (["BLUE"], False), (["BLUE"], True)])
def test_vrf_query_all_uses_unfiltered_fallback_only_for_scoped_errors(scope, raise_scoped):
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    calls = []
    object.__setattr__(orchestrator, "_query_scope_vrf_names", lambda: scope)
    object.__setattr__(
        orchestrator,
        "_query_all_unfiltered",
        lambda: calls.append("unfiltered") or [{"vrfName": "BLUE"}],
    )

    def query_by_names(_names):
        calls.append("scoped")
        if raise_scoped:
            raise RuntimeError("filter unavailable")
        return [{"vrfName": "BLUE"}]

    object.__setattr__(orchestrator, "query_by_names", query_by_names)
    assert orchestrator.query_all() == [{"vrfName": "BLUE"}]
    assert calls == (["unfiltered"] if not scope else ["scoped", "unfiltered"] if raise_scoped else ["scoped"])


def test_vrf_query_all_preserves_unfiltered_failure_cause():
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    object.__setattr__(orchestrator, "_query_scope_vrf_names", lambda: [])

    def fail():
        raise RuntimeError("controller unavailable")

    object.__setattr__(orchestrator, "_query_all_unfiltered", fail)
    with pytest.raises(Exception, match="Query all VRFs failed: controller unavailable"):
        orchestrator.query_all()


def test_vrf_empty_scoped_name_list_needs_no_controller_query():
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    assert orchestrator.query_by_names([]) == []


def test_mcfg_parent_normalizes_core_defaults_from_query_response():
    orchestrator = NDVrfOrchestrator.__new__(NDVrfOrchestrator)
    object.__setattr__(orchestrator, "strategy", _McfgTopDownStrategy())
    normalized = orchestrator._normalize_query_vrf_item({"vrfName": "BLUE", "coreData": {"vrfDescription": "tenant"}})
    assert normalized["coreData"] == {
        "vrfDescription": "tenant",
        "vrfVlanName": "",
        "vrfInterfaceDescription": "",
    }


def test_vrf_single_name_query_falls_back_after_filtered_request_failure():
    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})

    def fail(**_kwargs):
        raise RuntimeError("filter unavailable")

    object.__setattr__(orchestrator, "_request", fail)
    object.__setattr__(
        orchestrator,
        "_query_all_unfiltered",
        lambda: [{"vrfName": "BLUE"}, {"vrfName": "GREEN"}],
    )
    assert orchestrator.query_by_names(["BLUE"]) == [{"vrfName": "BLUE"}]


def test_vrf_single_name_query_accepts_endpoint_without_filter_parameters():
    from types import SimpleNamespace

    orchestrator = _orchestrator_for_request_tests({"state": "merged", "config": []})
    object.__setattr__(
        orchestrator,
        "_make_endpoint",
        lambda _cls: SimpleNamespace(path="/vrfs", verb=HttpVerbEnum.GET),
    )
    object.__setattr__(orchestrator, "_request", lambda **_kwargs: {"vrfs": [{"vrfName": "BLUE"}]})
    assert orchestrator.query_by_names(["BLUE"]) == [{"vrfName": "BLUE"}]
