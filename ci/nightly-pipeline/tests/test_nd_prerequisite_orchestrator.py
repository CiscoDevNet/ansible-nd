import copy
import json
import pathlib
import sys

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from nd_prerequisite_orchestrator import (
    SWITCH_TOPOLOGY_MUTATION_PROFILES,
    UNAVAILABLE_EXIT_CODE,
    ApiErrorTracker,
    OrchestrationError,
    UnavailableError,
    build_phase_schedule,
    build_snapshot,
    evaluate_restore,
    main,
    plan_topology_delta,
    quarantine,
    resolve_execution,
    runtime_vars_for_execution,
    snapshot_path,
    validate_api_status,
    validate_snapshot_lineage,
    write_restricted_json,
    write_restricted_yaml,
)
from validate_nd_prerequisites import load_registry


@pytest.fixture
def registry():
    return load_registry(ROOT / "tests/nd_prerequisite_profiles.yaml")


@pytest.fixture
def valid_state():
    return yaml.safe_load((ROOT / "tests/fixtures/nd_prerequisite/valid_state.yaml").read_text())


def confirm(registry, profile_id):
    result = copy.deepcopy(registry)
    result["profiles"][profile_id]["confirmation"] = {
        "status": "confirmed", "owner": "fixture-owner", "evidence": "fixture-contract", "reasons": [],
    }
    return result


def interface_state_for_profile(registry, valid_state, profile_id):
    state = copy.deepcopy(valid_state)
    state.setdefault("logical_interfaces", {})
    state.setdefault("interface_details", {})
    state.setdefault("physical_links", [])
    for resource in registry["profiles"][profile_id]["resources"]:
        switch_ref = resource.get("switch_ref")
        if not switch_ref:
            continue
        physical = []
        if resource.get("kind") == "verify_free_interfaces":
            physical = resource["interfaces"]
        elif resource.get("kind") == "ensure_routed_parent":
            physical = [resource["interface"]]
            if resource.get("existing_link"):
                peer = registry["lab"]["switches"][resource["existing_link"]["peer_switch_ref"]]
                cable = {
                    "srcSwitchId": registry["lab"]["switches"][switch_ref]["serial"],
                    "srcInterfaceName": resource["interface"],
                    "dstSwitchId": peer["serial"],
                    "dstInterfaceName": resource["existing_link"]["peer_interface"],
                    "linkType": "ethisl",
                }
                if cable not in state["physical_links"]:
                    state["physical_links"].append(cable)
        for interface in physical:
            state.setdefault("interfaces", {}).setdefault(switch_ref, {})[interface] = {
                "exists": True,
                "configured": False,
                "policy": "",
                "policy_type": "",
                "nv_pairs": {},
                "admin_state": False,
                "operational_state": None,
            }
            state["interface_details"].setdefault(switch_ref, []).append({
                "ifName": interface,
                "underlayPolicies": [],
            })
        logical = []
        if resource.get("kind") == "verify_logical_interface_namespace":
            logical = resource["interfaces"]
        elif resource.get("kind") == "ensure_routed_port_channel":
            logical = [resource["interface"]]
        for interface in logical:
            state["logical_interfaces"].setdefault(switch_ref, {})[interface] = {
                "exists": False,
                "policy": "",
                "nv_pairs": {},
            }
    return state


# Peer-links the lab owner records once leaf_1<->leaf_2 / edge_1<->edge_2 are physically cabled
# (see nd_prerequisite_profiles.yaml integration.nd_vpc_pair executions). Virtual peering is
# unsupported on these switches, so a physical pair is only concrete once these are present.
LEAF_PEER_LINKS = [{
    "local": "vxlan_leaf_1", "local_interfaces": ["Ethernet1/3", "Ethernet1/4"],
    "remote": "vxlan_leaf_2", "remote_interfaces": ["Ethernet1/3", "Ethernet1/4"],
}]
EDGE_PEER_LINKS = [{
    "local": "external_edge_1", "local_interfaces": ["Ethernet1/2", "Ethernet1/3"],
    "remote": "external_edge_2", "remote_interfaces": ["Ethernet1/2", "Ethernet1/3"],
}]


def confirm_vpc_executions(registry):
    result = confirm(registry, "integration.nd_vpc_pair")
    executions = result["profile_executions"]["integration.nd_vpc_pair"]
    executions[0].update(pair_mode="physical", physical_peer_links=copy.deepcopy(LEAF_PEER_LINKS))
    executions[1].update(
        switch_refs=["external_edge_1", "external_edge_2"],
        desired_roles=["edge_router", "edge_router"],
        pair_mode="physical",
        physical_peer_links=copy.deepcopy(EDGE_PEER_LINKS),
    )
    for execution in executions:
        execution["confirmation"] = {
            "status": "confirmed", "owner": "fixture-owner", "evidence": "fixture-contract", "reasons": [],
        }
    return result


def test_pending_profile_and_implicit_multi_execution_are_rejected(registry):
    with pytest.raises(OrchestrationError, match="owner confirmation is pending"):
        resolve_execution(registry, "integration.nd_manage_policy")
    confirmed = confirm_vpc_executions(registry)
    with pytest.raises(OrchestrationError, match="explicit execution ID"):
        resolve_execution(confirmed, "integration.nd_vpc_pair")


def test_allow_auto_confirm_resolves_concrete_pending_execution(registry):
    resolved = resolve_execution(registry, "integration.nd_manage_policy", allow_auto_confirm=True)
    assert resolved["profile_id"] == "integration.nd_manage_policy"

    # Both vpc_pair executions are physical with no peer-links cabled yet -> auto-confirm refuses
    # them until the lab owner records physical_peer_links (virtual peering is unsupported here).
    for execution_id in ("integration.nd_vpc_pair.advanced", "integration.nd_vpc_pair.external"):
        with pytest.raises(OrchestrationError, match="physical pair requires peer-link interfaces"):
            resolve_execution(registry, execution_id, allow_auto_confirm=True)

    # Once the leaf_1<->leaf_2 peer-links are cabled and recorded, the concrete physical execution
    # auto-confirms and schedules alongside the concrete policy profile.
    cabled = copy.deepcopy(registry)
    cabled["profile_executions"]["integration.nd_vpc_pair"][0]["physical_peer_links"] = copy.deepcopy(LEAF_PEER_LINKS)
    advanced = resolve_execution(cabled, "integration.nd_vpc_pair.advanced", allow_auto_confirm=True)
    assert advanced["execution_id"] == "integration.nd_vpc_pair.advanced"
    assert advanced["execution"]["pair_mode"] == "physical"

    schedule = build_phase_schedule(
        cabled,
        ["integration.nd_manage_policy", "integration.nd_vpc_pair.advanced"],
        allow_auto_confirm=True,
    )
    assert [phase["phase_id"] for phase in schedule] == ["advanced_leaf", "vpc_pair_isolated"]


def test_phase_schedule_is_registry_ordered_and_expands_vpc(registry):
    confirmed = confirm_vpc_executions(registry)
    for profile_id in (
        "smoke.nd_manage_prefix_list",
        "integration.nd_manage_policy",
        "integration.nd_manage_switches",
    ):
        confirmed = confirm(confirmed, profile_id)
    schedule = build_phase_schedule(
        confirmed,
        [
            "integration.nd_manage_switches",
            "integration.nd_vpc_pair",
            "integration.nd_manage_policy",
            "smoke.nd_manage_prefix_list",
        ],
    )
    assert [phase["phase_id"] for phase in schedule] == [
        "retained_no_switch", "advanced_leaf", "vpc_pair_isolated",
    ]
    vpc_ids = next(item["execution_ids"] for item in schedule if item["phase_id"] == "vpc_pair_isolated")
    assert vpc_ids == ["integration.nd_vpc_pair.advanced", "integration.nd_vpc_pair.external"]


def test_ordinary_profiles_refuse_switch_topology_mutation(registry, valid_state):
    policy_registry = confirm(registry, "integration.nd_manage_policy")
    drifted = copy.deepcopy(valid_state)
    drifted["switches"]["vxlan_leaf_1"]["role"] = "border"
    policy = resolve_execution(policy_registry, "integration.nd_manage_policy")
    with pytest.raises(OrchestrationError, match="verify-only.*refusing role change"):
        plan_topology_delta(policy_registry, policy, drifted)

    moved = copy.deepcopy(valid_state)
    moved["switches"]["vxlan_leaf_1"]["fabric_ref"] = "external"
    with pytest.raises(OrchestrationError, match="verify-only.*refusing membership change"):
        plan_topology_delta(policy_registry, policy, moved)

    missing = copy.deepcopy(valid_state)
    missing["switches"].pop("vxlan_leaf_1")
    assert plan_topology_delta(policy_registry, policy, missing) == [{
        "operation": "ensure_switch_membership",
        "switch_ref": "vxlan_leaf_1",
        "serial": "SERIAL00001",
        "fabric_ref": "advanced",
        "desired_role": "leaf",
    }]


def test_switch_topology_mutation_allowlist_is_integration_only():
    assert SWITCH_TOPOLOGY_MUTATION_PROFILES == {
        "integration.nd_manage_fabric",
        "integration.nd_manage_switches",
        "integration.nd_resource_manager",
    }
    assert all(profile_id.startswith("integration.") for profile_id in SWITCH_TOPOLOGY_MUTATION_PROFILES)


def test_smoke_profiles_refuse_switch_topology_mutation(registry, valid_state):
    resource_registry = confirm(registry, "smoke.nd_manage_resource_manager")
    resource = resolve_execution(resource_registry, "smoke.nd_manage_resource_manager")
    drifted = copy.deepcopy(valid_state)
    drifted["switches"]["vxlan_leaf_1"]["role"] = "border"
    with pytest.raises(OrchestrationError, match="verify-only.*refusing role change"):
        plan_topology_delta(resource_registry, resource, drifted)


def test_permitted_switch_profile_can_reconcile_role_drift(registry, valid_state):
    switch_registry = confirm(registry, "integration.nd_manage_switches")
    drifted = copy.deepcopy(valid_state)
    drifted["switches"]["vxlan_spine_1"]["role"] = "leaf"
    resolved = resolve_execution(switch_registry, "integration.nd_manage_switches")
    operations = plan_topology_delta(switch_registry, resolved, drifted)
    assert operations == [{
        "operation": "change_role",
        "switch_ref": "vxlan_spine_1",
        "serial": "SERIAL00003",
        "fabric_ref": "advanced",
        "current_role": "leaf",
        "desired_role": "spine",
    }]


def test_non_topology_prerequisites_remain_available(registry, valid_state):

    group_registry = confirm(registry, "integration.nd_manage_policy_group")
    group = resolve_execution(group_registry, "integration.nd_manage_policy_group")
    operations = plan_topology_delta(group_registry, group, valid_state)
    assert operations == []

    bfd_missing = copy.deepcopy(valid_state)
    bfd_missing["fabrics"]["advanced"]["bfd_enabled"] = False
    l3out_registry = confirm(registry, "integration.nd_manage_l3out")
    l3out = resolve_execution(l3out_registry, "integration.nd_manage_l3out")
    assert plan_topology_delta(l3out_registry, l3out, bfd_missing) == [
        {"operation": "ensure_bfd", "fabric_ref": "advanced"},
    ]


def test_typed_interface_verification_operations_are_planned(registry, valid_state):
    for profile_id, expected_operations in {
        "integration.nd_interface_loopback": ["verify_logical_interface_namespace"],
        "integration.nd_interface_svi": ["verify_logical_interface_namespace"],
        "integration.nd_interface_ethernet_access": ["verify_free_interfaces"],
        "integration.nd_interface_ethernet_trunk_host": ["verify_free_interfaces"],
        "integration.nd_interface_ethernet_routed": ["verify_free_interfaces"],
        "integration.nd_interface_port_channel_access": [
            "verify_free_interfaces", "verify_logical_interface_namespace",
        ],
        "integration.nd_interface_port_channel_trunk_host": [
            "verify_free_interfaces", "verify_logical_interface_namespace",
        ],
    }.items():
        confirmed = confirm(registry, profile_id)
        resolved = resolve_execution(confirmed, profile_id)
        state = interface_state_for_profile(confirmed, valid_state, profile_id)
        operations = plan_topology_delta(confirmed, resolved, state)
        assert [item["operation"] for item in operations] == expected_operations


def test_interface_checks_reject_fabric_links_memberships_and_namespace_collisions(registry, valid_state):
    profile_id = "integration.nd_interface_port_channel_access"
    confirmed = confirm(registry, profile_id)
    resolved = resolve_execution(confirmed, profile_id)

    fabric_link = interface_state_for_profile(confirmed, valid_state, profile_id)
    fabric_link["physical_links"].append({
        "link-type": "ethisl",
        "sw1-info": {
            "sw-serial-number": "SERIAL00001",
            "if-name": "Ethernet1/10",
        },
        "sw2-info": {
            "sw-serial-number": "peer-serial",
            "if-name": "Ethernet1/1",
        },
    })
    with pytest.raises(OrchestrationError, match="reserved interface is a fabric link"):
        plan_topology_delta(confirmed, resolved, fabric_link)

    member = interface_state_for_profile(confirmed, valid_state, profile_id)
    detail = next(
        item
        for item in member["interface_details"]["vxlan_leaf_1"]
        if item["ifName"] == "Ethernet1/10"
    )
    detail["underlayPolicies"] = [{"templateName": "int_port_channel_access_member_11_1"}]
    with pytest.raises(OrchestrationError, match="reserved interface is a port-channel member"):
        plan_topology_delta(confirmed, resolved, member)

    collision = interface_state_for_profile(confirmed, valid_state, profile_id)
    collision["logical_interfaces"]["vxlan_leaf_1"]["Port-channel501"]["exists"] = True
    with pytest.raises(OrchestrationError, match="logical interface namespace is in use"):
        plan_topology_delta(confirmed, resolved, collision)


def test_subinterface_parents_are_created_only_from_safe_empty_state(registry, valid_state):
    profile_id = "integration.nd_interface_subinterface_managed"
    confirmed = confirm(registry, profile_id)
    resolved = resolve_execution(confirmed, profile_id)
    empty = interface_state_for_profile(confirmed, valid_state, profile_id)

    operations = plan_topology_delta(confirmed, resolved, empty)
    assert [item["operation"] for item in operations] == [
        "ensure_routed_parent",
        "ensure_routed_port_channel",
        "verify_logical_interface_namespace",
    ]
    assert operations[0]["interface"] == "Ethernet1/1"
    assert operations[1]["interface"] == "Port-channel10"
    assert operations[1]["member_interfaces"] == []

    prepared = copy.deepcopy(empty)
    prepared["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"].update({
        "configured": True,
        "policy": "int_routed_host_11_1",
        "policy_type": "routedHost",
    })
    prepared["logical_interfaces"]["vxlan_leaf_1"]["Port-channel10"].update({
        "exists": True,
        "policy": "int_l3_port_channel",
        "nv_pairs": {"MEMBER_INTERFACES": ""},
    })
    assert [
        item["operation"]
        for item in plan_topology_delta(confirmed, resolved, prepared)
    ] == ["verify_logical_interface_namespace"]

    occupied_parent = copy.deepcopy(empty)
    occupied_parent["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"].update({
        "configured": True,
        "policy": "int_access_host_11_1",
    })
    with pytest.raises(OrchestrationError, match="refusing to replace existing non-routed interface"):
        plan_topology_delta(confirmed, resolved, occupied_parent)

    occupied_pc = copy.deepcopy(empty)
    occupied_pc["logical_interfaces"]["vxlan_leaf_1"]["Port-channel10"].update({
        "exists": True,
        "policy": "int_port_channel_access_host_11_1",
        "nv_pairs": {"MEMBER_INTERFACES": "Ethernet1/36"},
    })
    with pytest.raises(OrchestrationError, match="refusing to replace existing non-routed port-channel"):
        plan_topology_delta(confirmed, resolved, occupied_pc)


ND_DEFAULT_PORT_NV = {
    "ADMIN_STATE": "true", "ALLOWED_VLANS": "none", "BPDUGUARD_ENABLED": "no", "ENABLE_NETFLOW": "false",
    "INTF_NAME": "Ethernet1/1", "MTU": "jumbo", "POLICY_ID": "POLICY-1566130",
    "PORTTYPE_FAST_ENABLED": "true", "PRIORITY": "450", "PTP": "false", "SERIAL_NUMBER": "SERIAL00001",
    "SPEED": "Auto",
}


def test_nd_default_trunk_host_port_is_a_free_routed_parent(registry, valid_state):
    # Live ND 4.3 reports this exact intent on every untouched port (Eth1/1, 1/35, 1/36, 1/41, ...).
    profile_id = "integration.nd_interface_subinterface_managed"
    confirmed = confirm(registry, profile_id)
    resolved = resolve_execution(confirmed, profile_id)
    state = interface_state_for_profile(confirmed, valid_state, profile_id)
    state["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"].update({
        "configured": True, "policy": "int_trunk_host", "policy_type": "trunkHost",
        "nv_pairs": copy.deepcopy(ND_DEFAULT_PORT_NV), "admin_state": True,
    })
    operations = plan_topology_delta(confirmed, resolved, state)
    assert operations[0]["operation"] == "ensure_routed_parent"
    assert operations[0]["interface"] == "Ethernet1/1"

    for override in (
        {"DESC": "customer uplink"},
        {"ALLOWED_VLANS": "10,20"},
        {"ADMIN_STATE": "false"},
        {"CONF": "spanning-tree port type edge"},
    ):
        customised = copy.deepcopy(state)
        customised["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"]["nv_pairs"].update(override)
        with pytest.raises(OrchestrationError, match="refusing to replace existing non-routed interface"):
            plan_topology_delta(confirmed, resolved, customised)

    unknown_details = copy.deepcopy(state)
    unknown_details["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"]["nv_pairs"] = {}
    with pytest.raises(OrchestrationError, match="refusing to replace existing non-routed interface"):
        plan_topology_delta(confirmed, resolved, unknown_details)


# What ND 4.3 reports for a port after the prerequisite restore reset it (per-interface PUT replace + deploy):
# the same free intent with the whole int_trunk_host template persisted at its defaults.
ND_RESET_PORT_NV = {
    **ND_DEFAULT_PORT_NV,
    "BPDUFILTER_ENABLED": "no", "CDP_ENABLE": "true", "ENABLE_ERRDISABLE_ACL": "true", "ENABLE_MONITOR": "false",
    "ENABLE_ORPHAN_PORT": "false", "ENABLE_PFC": "false", "ENABLE_QOS": "false", "ENABLE_STORM_CONTROL": "false",
    "FEC": "auto", "LINK_TYPE": "auto", "NEGOTIATE_AUTO": "true", "PORT_DUPLEX_MODE": "auto",
    "STORM_CONTROL_ACTION": "no", "enableVlanMapping": "false",
    "BANDWIDTH": "", "DESC": "", "CONF": "", "NATIVE_VLAN": "", "QOS_POLICY": "", "vlanMappingEntries": "",
}


def test_reset_trunk_host_port_is_still_a_free_routed_parent(registry, valid_state):
    profile_id = "integration.nd_interface_subinterface_managed"
    confirmed = confirm(registry, profile_id)
    resolved = resolve_execution(confirmed, profile_id)
    state = interface_state_for_profile(confirmed, valid_state, profile_id)
    state["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"].update({
        "configured": True, "policy": "int_trunk_host", "policy_type": "trunkHost",
        "nv_pairs": copy.deepcopy(ND_RESET_PORT_NV), "admin_state": True,
    })
    operations = plan_topology_delta(confirmed, resolved, state)
    assert operations[0]["operation"] == "ensure_routed_parent"
    assert operations[0]["interface"] == "Ethernet1/1"

    # A stamped key that no longer holds its default is user intent and must still be refused.
    for override in ({"CDP_ENABLE": "false"}, {"FEC": "rs-fec"}, {"ENABLE_STORM_CONTROL": "true"}, {"enableVlanMapping": "true"}):
        customised = copy.deepcopy(state)
        customised["interfaces"]["vxlan_leaf_1"]["Ethernet1/1"]["nv_pairs"].update(override)
        with pytest.raises(OrchestrationError, match="refusing to replace existing non-routed interface"):
            plan_topology_delta(confirmed, resolved, customised)


def test_subinterface_parent_must_ride_the_declared_existing_link(registry, valid_state):
    profile_id = "integration.nd_interface_subinterface_managed"
    confirmed = confirm(registry, profile_id)
    resolved = resolve_execution(confirmed, profile_id)
    state = interface_state_for_profile(confirmed, valid_state, profile_id)
    assert plan_topology_delta(confirmed, resolved, state)[0]["interface"] == "Ethernet1/1"

    # Either capture shape (legacy control/links or manage/links) proves the cable.
    legacy = copy.deepcopy(state)
    legacy["physical_links"] = [{
        "link-type": "ethisl",
        "sw1-info": {"sw-serial-number": "SERIAL00001", "if-name": "Ethernet1/1"},
        "sw2-info": {"sw-serial-number": "SERIAL00005", "if-name": "Ethernet1/1"},
    }]
    assert plan_topology_delta(confirmed, resolved, legacy)[0]["operation"] == "ensure_routed_parent"

    # No cable in ND: the substrate is unavailable -> skip with the exact ports, never provision.
    uncabled = copy.deepcopy(state)
    uncabled["physical_links"] = []
    with pytest.raises(
        UnavailableError,
        match=r"required existing link is absent in ND: vxlan_leaf_1/Ethernet1/1 <-> external_edge_1/Ethernet1/1",
    ):
        plan_topology_delta(confirmed, resolved, uncabled)

    # The same port also carrying another (underlay) link is never converted.
    shared = copy.deepcopy(state)
    shared["physical_links"].append({
        "srcSwitchId": "SERIAL00003", "srcInterfaceName": "Ethernet1/1",
        "dstSwitchId": "SERIAL00001", "dstInterfaceName": "Ethernet1/1", "linkType": "ethisl",
    })
    with pytest.raises(UnavailableError, match="carries another link"):
        plan_topology_delta(confirmed, resolved, shared)

    # A profile can never declare an intra-fabric peer: that would be an underlay link.
    underlay = copy.deepcopy(confirmed)
    parent = next(
        item for item in underlay["profiles"][profile_id]["resources"] if item["kind"] == "ensure_routed_parent"
    )
    parent["existing_link"] = {"peer_switch_ref": "vxlan_leaf_2", "peer_interface": "Ethernet1/1"}
    with pytest.raises(OrchestrationError, match="existing link must join two"):
        plan_topology_delta(underlay, resolve_execution(underlay, profile_id), state)


def test_links_profile_verifies_free_ports_on_both_switches(registry, valid_state):
    profile_id = "integration.nd_manage_links"
    confirmed = confirm(registry, profile_id)
    resolved = resolve_execution(confirmed, profile_id)
    state = interface_state_for_profile(confirmed, valid_state, profile_id)
    operations = plan_topology_delta(confirmed, resolved, state)
    assert [(item["operation"], item["switch_ref"]) for item in operations] == [
        ("verify_free_interfaces", "vxlan_leaf_2"),
        ("verify_free_interfaces", "vxlan_border_1"),
    ]
    assert all(item["interfaces"] == ["Ethernet1/30", "Ethernet1/31", "Ethernet1/32"] for item in operations)
    runtime = runtime_vars_for_execution(resolved, "run-1", "phase-1")
    assert (runtime["nd_test_fabric_numbered"], runtime["nd_test_switch_a"], runtime["nd_test_switch_b"]) == (
        "VXLAN_EVPN_Fabric", "vxlan_leaf_2", "vxlan_border_1",
    )

    # A link already using a reserved port means the substrate is not available: skip, do not fail.
    linked = copy.deepcopy(state)
    linked["physical_links"].append({
        "srcSwitchId": "SERIAL00002", "srcInterfaceName": "Ethernet1/30",
        "dstSwitchId": "SERIAL00004", "dstInterfaceName": "Ethernet1/30",
    })
    with pytest.raises(UnavailableError, match="reserved interface is a fabric link"):
        plan_topology_delta(confirmed, resolved, linked)

    missing = copy.deepcopy(state)
    missing["interfaces"]["vxlan_border_1"]["Ethernet1/31"]["exists"] = False
    with pytest.raises(UnavailableError, match="required physical interface is missing"):
        plan_topology_delta(confirmed, resolved, missing)


def test_absent_required_vpc_pair_is_unavailable_and_cli_exits_with_skip_code(tmp_path, capsys):
    registry_path = ROOT / "tests/nd_prerequisite_profiles.yaml"
    state = yaml.safe_load((ROOT / "tests/fixtures/nd_prerequisite/valid_state.yaml").read_text())
    # The real lab: virtual vPC peering is unsupported on the 9300v switches, and with no leaf_1<->leaf_2
    # peer-link ND listed the physical pair cannot form either.
    state["vpc_pairs"] = []
    state["links"] = [
        item for item in state["links"]
        if not (item["srcSwitchId"] == "SERIAL00001" and item["dstSwitchId"] == "SERIAL00002")
    ]
    state_path = tmp_path / "state.yaml"
    state_path.write_text(yaml.safe_dump(state))
    registry = load_registry(registry_path)
    resolved = resolve_execution(registry, "integration.nd_resource_manager", allow_auto_confirm=True)
    with pytest.raises(UnavailableError, match=r"required physical vPC peer-link is missing: vxlan_leaf_1/Ethernet1/2 <-> vxlan_leaf_2/Ethernet1/1"):
        plan_topology_delta(registry, resolved, state)
    assert issubclass(UnavailableError, OrchestrationError)
    assert main([
        "plan", "--registry", str(registry_path),
        "--execution-id", "integration.nd_resource_manager",
        "--state", str(state_path), "--allow-auto-confirm",
    ]) == UNAVAILABLE_EXIT_CODE == 3
    assert "substrate unavailable" in capsys.readouterr().err


def test_resource_manager_runs_on_a_cabled_physical_peer_link_and_recovers_shut_ports(registry, valid_state):
    confirmed = confirm(registry, "integration.nd_resource_manager")
    resolved = resolve_execution(confirmed, "integration.nd_resource_manager")
    no_pair = copy.deepcopy(valid_state)
    no_pair["vpc_pairs"] = []
    # The target creates the pair itself, so a cabled peer-link means there is nothing to apply.
    assert plan_topology_delta(confirmed, resolved, no_pair) == []

    # Both peer-link ports administratively shut (ND lists the link as not present): admin-up them first.
    shut = copy.deepcopy(no_pair)
    for switch_ref, interface in (("vxlan_leaf_1", "Ethernet1/2"), ("vxlan_leaf_2", "Ethernet1/1")):
        shut["interfaces"][switch_ref][interface] = {"admin_state": False, "operational_state": "down"}
    for item in shut["links"]:
        if item["srcSwitchId"] == "SERIAL00001" and item["dstSwitchId"] == "SERIAL00002":
            item["linkPresent"] = False
    operations = plan_topology_delta(confirmed, resolved, shut)
    assert [(op["operation"], op["switch_ref"], op["interface"]) for op in operations] == [
        ("ensure_interface", "vxlan_leaf_1", "Ethernet1/2"),
        ("ensure_interface", "vxlan_leaf_2", "Ethernet1/1"),
    ]

    # A planned link has no cable behind it, so it never satisfies the peer-link prerequisite.
    planned = copy.deepcopy(no_pair)
    for item in planned["links"]:
        if item["srcSwitchId"] == "SERIAL00001" and item["dstSwitchId"] == "SERIAL00002":
            item.update(linkType="lan_planned_link", linkPlanned=True, linkPresent=False)
    with pytest.raises(UnavailableError, match="required physical vPC peer-link is missing"):
        plan_topology_delta(confirmed, resolved, planned)

    # An already formed pair (either peer-link mode) needs nothing from the planner.
    physical_pair = copy.deepcopy(planned)
    physical_pair["vpc_pairs"] = [{"fabric_ref": "advanced", "peer_refs": ["vxlan_leaf_1", "vxlan_leaf_2"], "mode": "physical"}]
    assert plan_topology_delta(confirmed, resolved, physical_pair) == []


def test_l3out_needs_one_cable_and_plans_config_only_links_for_the_other_types(registry, valid_state):
    confirmed = confirm(registry, "integration.nd_manage_l3out")
    resolved = resolve_execution(confirmed, "integration.nd_manage_l3out")
    assert plan_topology_delta(confirmed, resolved, valid_state) == []

    # Right after the switches are re-added ND only holds the discovered cable, with no template on it.
    cable = {
        "srcSwitchId": "SERIAL00004", "srcInterfaceName": "Ethernet1/1",
        "dstSwitchId": "SERIAL00005", "dstInterfaceName": "Ethernet1/3",
        "templateName": "", "linkType": "ethisl", "policyType": "", "linkPlanned": False, "linkPresent": True,
    }
    fresh = copy.deepcopy(valid_state)
    fresh["links"] = [copy.deepcopy(cable)]
    operations = plan_topology_delta(confirmed, resolved, fresh)
    assert [(op["template"], op["policy_type"], op["provisioning"], op["requires_physical"], op["config_only"]) for op in operations] == [
        ("ext_l3_dci_link", "layer3DciVrfLite", "nd_manage_links", True, False),
        ("ext_fabric_setup", "ebgpVrfLite", "nd_manage_links", False, True),
        ("ext_l2_dci_link", "layer2Dci", "nd_manage_links", False, True),
    ]
    assert operations[1]["template_inputs"]["src_ebgp_asn"] == "1234"
    assert operations[2]["template_inputs"]["bpdu_guard"] == "default"
    assert (operations[1]["src"]["interface"], operations[1]["dst"]["interface"]) == ("Ethernet1/2", "Ethernet1/2")

    # The one real cable is the only physical blocker; the SKIP names the exact ports.
    no_cable = copy.deepcopy(fresh)
    no_cable["links"] = []
    with pytest.raises(UnavailableError, match=r"required physical link is missing: vxlan_border_1/Ethernet1/1 <-> external_edge_1/Ethernet1/3"):
        plan_topology_delta(confirmed, resolved, no_cable)

    # A planned link is not a cable, even one that already carries the right policy.
    planned_only = copy.deepcopy(fresh)
    planned_only["links"] = [dict(cable, linkType="lan_planned_link", linkPlanned=True, linkPresent=False, policyType="layer3DciVrfLite")]
    with pytest.raises(UnavailableError, match="required physical link is missing"):
        plan_topology_delta(confirmed, resolved, planned_only)

    # If the sub-interface pair is genuinely cabled, ND updates that link in place and the restore never deletes it.
    cabled = copy.deepcopy(fresh)
    cabled["links"].append(dict(cable, srcInterfaceName="Ethernet1/2", dstInterfaceName="Ethernet1/2"))
    operations = plan_topology_delta(confirmed, resolved, cabled)
    assert [(op["template"], op["config_only"]) for op in operations] == [
        ("ext_l3_dci_link", False), ("ext_fabric_setup", False), ("ext_l2_dci_link", True),
    ]


def test_nd_manage_links_provisioning_is_pinned_to_the_template_policy(registry, valid_state):
    broken = confirm(registry, "integration.nd_manage_l3out")
    resolved = resolve_execution(broken, "integration.nd_manage_l3out")
    resolved["profile"]["interfabric_links"][1]["policy_type"] = "layer3DciVrfLite"
    fresh = copy.deepcopy(valid_state)
    fresh["links"] = [item for item in fresh["links"] if item["dstInterfaceName"] == "Ethernet1/3"]
    with pytest.raises(OrchestrationError, match="must use nd_manage_links policy ebgpVrfLite"):
        plan_topology_delta(broken, resolved, fresh)

    resolved = resolve_execution(broken, "integration.nd_manage_l3out")
    resolved["profile"]["interfabric_links"][2]["template_inputs"] = {"trunk_allowed_vlans": [100, 200]}
    with pytest.raises(OrchestrationError, match="template_inputs must be a flat map of scalar values"):
        plan_topology_delta(broken, resolved, valid_state)


def test_delta_creates_only_namespaced_disposable_fabric(registry, valid_state):
    confirmed = confirm(registry, "smoke.nd_manage_fabric_ibgp_vxlan")
    state = copy.deepcopy(valid_state)
    state["fabrics"].pop("disposable_ibgp", None)
    resolved = resolve_execution(confirmed, "smoke.nd_manage_fabric_ibgp_vxlan")
    assert plan_topology_delta(confirmed, resolved, state) == [{
        "operation": "create_disposable_fabric",
        "fabric_ref": "disposable_ibgp",
        "name": "ANSIBLE_NIGHTLY_IBGP",
        "fabric_type": "vxlanIbgp",
    }]

    retained_missing = copy.deepcopy(valid_state)
    retained_missing["fabrics"].pop("advanced")
    policy_registry = confirm(registry, "integration.nd_manage_policy")
    with pytest.raises(OrchestrationError, match="retained fabric advanced is missing"):
        plan_topology_delta(
            policy_registry,
            resolve_execution(policy_registry, "integration.nd_manage_policy"),
            retained_missing,
        )


def test_delta_enforces_link_allowlist_virtual_vpc_and_resources(registry, valid_state):
    confirmed = confirm(registry, "integration.nd_interface_vpc_access")
    state = copy.deepcopy(valid_state)
    state["interfaces"]["vxlan_leaf_1"]["Ethernet1/3"]["admin_state"] = False
    state["vpc_pairs"] = []
    resolved = resolve_execution(confirmed, "integration.nd_interface_vpc_access")
    operations = plan_topology_delta(confirmed, resolved, state)
    assert any(item["operation"] == "ensure_interface" and item["switch_ref"] == "vxlan_leaf_1" for item in operations)
    vpc = [item for item in operations if item["operation"] == "ensure_virtual_vpc"]
    assert vpc == [{
        "operation": "ensure_virtual_vpc", "fabric_ref": "advanced",
        "peer_refs": ["vxlan_leaf_1", "vxlan_leaf_2"], "physical_peer_links": [],
    }]

    broken = copy.deepcopy(state)
    broken["interfaces"]["vxlan_leaf_1"].pop("Ethernet1/3")
    with pytest.raises(OrchestrationError, match="required physical interface is missing"):
        plan_topology_delta(confirmed, resolved, broken)

    resource_registry = confirm(registry, "smoke.nd_manage_resource_manager")
    resource = resolve_execution(resource_registry, "smoke.nd_manage_resource_manager")
    resource_ops = plan_topology_delta(resource_registry, resource, valid_state)
    assert resource_ops == [{
        "operation": "verify_resource",
        "resource": {"kind": "pool", "name": "L3_VNI", "type": "ID", "state": "existing"},
    }]

    entity_registry = confirm(registry, "integration.nd_resource_manager")
    entity_resource = resolve_execution(entity_registry, "integration.nd_resource_manager")
    entity_ops = plan_topology_delta(entity_registry, entity_resource, valid_state)
    assert not any(item["operation"] == "verify_resource" for item in entity_ops)

    fabric_registry = confirm(registry, "integration.nd_manage_fabric")
    fabric_profile = resolve_execution(fabric_registry, "integration.nd_manage_fabric")
    assert plan_topology_delta(fabric_registry, fabric_profile, valid_state) == []

    missing_pair_state = copy.deepcopy(valid_state)
    missing_pair_state["vpc_pairs"] = []
    # nd_resource_manager no longer forbids creation: its target forms the physical pair itself.
    assert not any(
        item["operation"] == "ensure_virtual_vpc"
        for item in plan_topology_delta(entity_registry, entity_resource, missing_pair_state)
    )


def test_snapshots_have_strict_lineage_and_restricted_writes(tmp_path, valid_state):
    l0 = build_snapshot("L0", "run-1", valid_state)
    l1 = build_snapshot(
        "L1", "run-1", valid_state, phase_id="advanced_leaf", parent_snapshot_id=l0["snapshot_id"],
    )
    l2 = build_snapshot(
        "L2", "run-1", valid_state, phase_id="advanced_leaf",
        profile_id="integration.nd_manage_policy", execution_id="integration.nd_manage_policy",
        parent_snapshot_id=l1["snapshot_id"],
    )
    assert validate_snapshot_lineage(l0, l1, l2) == []
    stale = copy.deepcopy(l2)
    stale["parent_snapshot_id"] = "wrong"
    assert "L2 parent does not match L1" in validate_snapshot_lineage(l0, l1, stale)

    state_dir = tmp_path / ".nd-prerequisite-recovery" / "run-1"
    yaml_path = snapshot_path(state_dir, "L0")
    json_path = snapshot_path(state_dir, "L1", phase_id="advanced_leaf").with_suffix(".json")
    assert yaml_path == state_dir / "L0" / "job.yaml"
    assert snapshot_path(
        state_dir, "L2", phase_id="advanced_leaf", execution_id="integration.nd_manage_policy",
    ) == state_dir / "L2" / "advanced_leaf" / "integration.nd_manage_policy.yaml"
    write_restricted_yaml(yaml_path, l0)
    write_restricted_json(json_path, l1)
    assert state_dir.stat().st_mode & 0o777 == 0o700
    assert yaml_path.stat().st_mode & 0o777 == 0o600
    assert json_path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(OrchestrationError, match="already exists"):
        write_restricted_yaml(yaml_path, l0)


def test_runtime_vars_are_fresh_and_execution_specific(registry):
    confirmed = confirm(registry, "integration.nd_manage_policy")
    resolved = resolve_execution(confirmed, "integration.nd_manage_policy")
    runtime = runtime_vars_for_execution(resolved, "run-22", "phase-baseline-3")
    assert runtime["fabric_name"] == "VXLAN_EVPN_Fabric"
    assert [item["name"] for item in runtime["nd_test_fabric_switches"]["VXLAN_EVPN_Fabric"]] == [
        "vxlan_leaf_1", "vxlan_leaf_2", "vxlan_spine_1", "vxlan_border_1",
    ]
    assert [item["name"] for item in runtime["nd_test_fabric_switches"]["External_Connectivity_Fabric"]] == [
        "external_edge_1", "external_edge_2",
    ]
    assert runtime["nd_prerequisite_prepared"] is True
    assert runtime["nd_prerequisite_run_id"] == "run-22"
    assert runtime["nd_prerequisite_profile"] == "integration.nd_manage_policy"
    assert runtime["nd_prerequisite_execution_id"] == "integration.nd_manage_policy"
    assert runtime["nd_prerequisite_phase_baseline_id"] == "phase-baseline-3"

    vpc_registry = confirm_vpc_executions(registry)
    vpc = resolve_execution(vpc_registry, "integration.nd_vpc_pair.advanced")
    vpc_runtime = runtime_vars_for_execution(vpc, "run-23", "phase-baseline-4")
    assert vpc_runtime["fabric_name"] == "VXLAN_EVPN_Fabric"
    assert vpc_runtime["fabric_type"] == "vxlanIbgp"
    assert vpc_runtime["switch1_serial"] == "SERIAL00001"
    assert vpc_runtime["switch2_serial"] == "SERIAL00002"

    resolved["profile"]["runtime_vars"]["nd_test_fabric_switches"] = {}
    with pytest.raises(OrchestrationError, match="collide with canonical topology"):
        runtime_vars_for_execution(resolved, "run-24", "phase-baseline-5")


def test_snapshot_and_quarantine_reject_credentials_and_symlinked_state(tmp_path, valid_state):
    secret_state = copy.deepcopy(valid_state)
    secret_state["switch_password"] = "must-not-serialize"
    with pytest.raises(OrchestrationError, match="credential-like"):
        build_snapshot("L0", "run-1", secret_state)

    real = tmp_path / ".nd-prerequisite-recovery" / "real"
    real.mkdir(parents=True)
    linked = tmp_path / ".nd-prerequisite-recovery" / "linked"
    linked.symlink_to(real, target_is_directory=True)
    with pytest.raises(OrchestrationError, match="symlink"):
        quarantine(linked, "run-1", "integration.nd_manage_policy", ["switches"])


def test_http_207_and_three_consecutive_api_errors_fail_closed():
    with pytest.raises(OrchestrationError, match="HTTP 207"):
        validate_api_status(207, [{"switchId": "x", "message": "partial"}])
    tracker = ApiErrorTracker(max_consecutive_errors=3)
    assert tracker.observe(success=False) == 1
    assert tracker.observe(success=False) == 2
    with pytest.raises(OrchestrationError, match="3 consecutive API errors"):
        tracker.observe(success=False)
    assert tracker.observe(success=True) == 0


def test_restore_mismatch_quarantines_and_keeps_recovery_material(tmp_path, valid_state):
    after = copy.deepcopy(valid_state)
    after["switches"]["vxlan_leaf_1"]["role"] = "border"
    mismatches = evaluate_restore(valid_state, after, ["switches", "fabrics"])
    assert mismatches == ["switches"]
    state_dir = tmp_path / ".nd-prerequisite-recovery" / "run-1"
    state_dir.mkdir(parents=True)
    marker = quarantine(state_dir, "run-1", "integration.nd_manage_policy", mismatches)
    assert marker.name == "QUARANTINED"
    assert marker.stat().st_mode & 0o777 == 0o600
    report = json.loads((state_dir / "recovery-report.json").read_text())
    assert report["mismatched_domains"] == ["switches"]


def test_cli_plan_and_schedule_emit_json(capsys):
    registry_path = ROOT / "tests/nd_prerequisite_profiles.yaml"
    state_path = ROOT / "tests/fixtures/nd_prerequisite/valid_state.yaml"
    assert main([
        "plan", "--registry", str(registry_path),
        "--execution-id", "integration.nd_manage_policy",
        "--state", str(state_path), "--allow-auto-confirm",
        "--run-id", "run-9", "--phase-baseline-id", "phase-9",
    ]) == 0
    plan_output = json.loads(capsys.readouterr().out)
    assert plan_output["resolved"]["execution_id"] == "integration.nd_manage_policy"
    assert isinstance(plan_output["operations"], list)
    assert plan_output["runtime_vars"]["nd_prerequisite_run_id"] == "run-9"

    assert main([
        "schedule", "--registry", str(registry_path),
        "--selected", "integration.nd_manage_policy",
        "--allow-auto-confirm",
    ]) == 0
    schedule_output = json.loads(capsys.readouterr().out)
    assert [phase["phase_id"] for phase in schedule_output] == ["advanced_leaf"]

    # vpc_pair executions are physical with no peer-links cabled yet -> the CLI fails closed on a
    # schedule or plan that selects them, matching the profile's documented "not met" state.
    assert main([
        "schedule", "--registry", str(registry_path),
        "--selected", "integration.nd_manage_policy,integration.nd_vpc_pair.advanced",
        "--allow-auto-confirm",
    ]) == 1

    assert main([
        "plan", "--registry", str(registry_path),
        "--execution-id", "integration.nd_vpc_pair.external", "--allow-auto-confirm",
    ]) == 1
